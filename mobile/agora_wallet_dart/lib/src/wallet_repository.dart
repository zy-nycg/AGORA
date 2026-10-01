/// AGORA 钱包 · 数据仓库（缓存 + 轮询 + 失败降级）
///
/// 移动端取数的三个现实约束
/// ------------------------
/// 1. **流量与电量**：不要每个界面各自去拉一遍。这里集中缓存，多个界面共享一份数据；
/// 2. **网络不稳定**：手机切网/进电梯是常态。因此所有 `watch*` 在**出错时不会结束流**，
///    而是发出一个错误事件后继续按退避重试 —— 否则界面会永久停在"加载失败"；
/// 3. **数据新鲜度必须可判断**：每条缓存都带 `fetchedAt` 与当时的链 `height`，
///    界面可以据此显示"数据来自高度 N（3 秒前）"，而不是含糊的"最新"。
library;

import 'dart:async';

import 'agora_api.dart';
import 'amount.dart';
import 'errors.dart';
import 'models.dart';

/// 带元数据的缓存条目。
class Cached<T> {
  Cached(this.value, this.fetchedAt, this.height);

  final T value;
  final DateTime fetchedAt;

  /// 取这份数据时链的高度（用于判断"是不是同一高度上的同一份数据"）。
  final int height;

  Duration age([DateTime? now]) => (now ?? DateTime.now()).difference(fetchedAt);

  bool isFresh(Duration maxAge, [DateTime? now]) => age(now) <= maxAge;
}

/// 轮询配置。
class PollConfig {
  const PollConfig({
    this.interval = const Duration(seconds: 5),
    this.errorBackoff = const Duration(seconds: 10),
    this.maxBackoff = const Duration(minutes: 2),
  });

  /// 正常情况下的轮询间隔（AGORA 每槽 5 秒出块，5 秒足够"接近实时"）。
  final Duration interval;

  /// 出错后的重试间隔（指数退避的起点）。
  final Duration errorBackoff;
  final Duration maxBackoff;
}

/// 钱包数据仓库：面向界面的取数入口。
class WalletRepository {
  WalletRepository({
    required this.api,
    this.poll = const PollConfig(),
  });

  final AgoraApi api;
  final PollConfig poll;

  // ── 缓存 ──
  Cached<ChainStatus>? _status;
  final Map<String, Cached<AccountState>> _accounts = {};
  final Map<String, Cached<AirdropStatus>> _airdrops = {};
  Cached<ValidatorSet>? _validators;
  ChainParams? _params;

  ChainStatus? get cachedStatus => _status?.value;
  AccountState? cachedAccount(String address) =>
      _accounts[normalizeAddress(address)]?.value;
  AirdropStatus? cachedAirdrop(String address) =>
      _airdrops[normalizeAddress(address)]?.value;

  /// 协议参数（进程内缓存一次即可：它们由创世冻结）。
  Future<ChainParams> params({bool refresh = false}) async {
    final p = _params;
    if (p != null && !refresh) return p;
    final fetched = await api.params();
    _params = fetched;
    return fetched;
  }

  /// 读链状态（默认优先用缓存，除非过期）。
  Future<ChainStatus> status({
    Duration maxAge = const Duration(seconds: 3),
    bool refresh = false,
  }) async {
    final c = _status;
    if (!refresh && c != null && c.isFresh(maxAge)) return c.value;
    final v = await api.status();
    _status = Cached(v, DateTime.now(), v.envelope.height);
    return v;
  }

  /// 读账户（余额 + nonce）。**转账前必须 `refresh: true`**：
  /// nonce 与余额是"写操作的前置条件"，用缓存值会导致交易被拒。
  Future<AccountState> account(String address,
      {Duration maxAge = const Duration(seconds: 3), bool refresh = false}) async {
    final key = normalizeAddress(address);
    final c = _accounts[key];
    if (!refresh && c != null && c.isFresh(maxAge)) return c.value;
    final v = await api.account(key);
    _accounts[key] = Cached(v, DateTime.now(), v.envelope.height);
    return v;
  }

  Future<AirdropStatus> airdrop(String address,
      {Duration maxAge = const Duration(seconds: 30), bool refresh = false}) async {
    final key = normalizeAddress(address);
    final c = _airdrops[key];
    if (!refresh && c != null && c.isFresh(maxAge)) return c.value;
    final v = await api.airdrop(key);
    _airdrops[key] = Cached(v, DateTime.now(), v.envelope.height);
    return v;
  }

  Future<ValidatorSet> validators(
      {Duration maxAge = const Duration(seconds: 30), bool refresh = false}) async {
    final c = _validators;
    if (!refresh && c != null && c.isFresh(maxAge)) return c.value;
    final v = await api.validators();
    _validators = Cached(v, DateTime.now(), v.envelope.height);
    return v;
  }

  // ── 轮询流（给界面用）──

  /// 持续推送链状态。**出错时发一个错误事件后继续重试**，流不会因网络抖动而结束。
  Stream<ChainStatus> watchStatus() =>
      _watch(() => status(refresh: true), (v) => v.envelope.height);

  /// 持续推送账户状态（余额/nonce）。
  Stream<AccountState> watchAccount(String address) =>
      _watch(() => account(address, refresh: true), (v) => v.envelope.height);

  /// 持续推送空投状态（变化频率低，因此间隔更长）。
  Stream<AirdropStatus> watchAirdrop(String address) => _watch(
        () => airdrop(address, refresh: true),
        (v) => v.envelope.height,
        interval: const Duration(seconds: 30),
      );

  Stream<T> _watch<T>(
    Future<T> Function() fetch,
    int Function(T) heightOf, {
    Duration? interval,
  }) {
    final controller = StreamController<T>();
    var backoff = poll.errorBackoff;
    Timer? timer;
    var closed = false;
    var lastHeight = -1;

    Future<void> tick() async {
      if (closed) return;
      try {
        final v = await fetch();
        final h = heightOf(v);
        // 同一高度不重复推送（省电、也避免界面无谓重建）
        if (h != lastHeight) {
          lastHeight = h;
          if (!controller.isClosed) controller.add(v);
        }
        backoff = poll.errorBackoff;                 // 成功即重置退避
        timer = Timer(interval ?? poll.interval, tick);
      } on AgoraException catch (e, st) {
        // 错误**不结束流**：界面显示"离线/重试中"，网络恢复后自动继续。
        if (!controller.isClosed) controller.addError(e, st);
        backoff = backoff * 2 > poll.maxBackoff ? poll.maxBackoff : backoff * 2;
        timer = Timer(backoff, tick);
      }
    }

    controller.onListen = () => tick();
    controller.onCancel = () {
      closed = true;
      timer?.cancel();
    };
    return controller.stream;
  }

  void dispose() {
    _status = null;
    _accounts.clear();
    _airdrops.clear();
    _validators = null;
  }
}

/// 面向界面的格式化助手（与 [formatAgora] 一致，集中一处以免各处写法不一）。
String displayBalance(BigInt atom, {int decimals = 4}) =>
    formatAgora(atom, decimals: decimals, withUnit: true);
