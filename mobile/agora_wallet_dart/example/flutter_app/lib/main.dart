// AGORA 钱包 · Flutter 示例 App（可直接抄进你的项目）
//
// 设计原则：**链上逻辑一行都不写在这里**。
// 所有"取数 / 校验 / 构造 / 签名 / 提交 / 查回执"都在 `agora_wallet` 包里
// （那部分有 70+ 项自检与向量对齐），本文件只负责：把状态渲染出来、
// 把用户输入交给包、把错误分类翻译成人话。
//
// 这样做的理由很实际：Flutter 的 widget 层**没法在 CI 里对着真链跑**，
// 而链上逻辑必须能被反复验证。把逻辑逼到包里，UI 就只剩"显示与转发"。
//
// 运行前：
//   cd example/flutter_app && flutter pub get
//   flutter run            # 记得按 docs/FLUTTER_INTEGRATION.md 配好
//                          # Android 的 INTERNET/明文 HTTP 与 iOS 的 ATS
//
// ⚠ 本文件**没有**在本仓库的沙箱里通过 `flutter analyze`（该环境里 Flutter SDK
//   目录只读、工具链起不来）。纯 Dart 的部分（示例 CLI、自检）已全部验证通过；
//   请在你的机器上跑一次 `flutter analyze` 与 `dart run tool/selftest.dart`。

import 'dart:async';
import 'dart:convert';

import 'package:agora_wallet/agora_wallet.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// 你的节点列表与链身份。**创世哈希必须从创世文件抄**，不要猜：
/// 它是"连到哪条链"的最后一道防线（字符串比对，不是密码学证明）。
const _nodes = [
  AgoraNode('http://192.168.1.10:8645', label: '主节点'),
  AgoraNode('http://192.168.1.11:8645', label: '备用节点'),
];
const _expectedChainId = 'agora-testnet-1';
const _expectedGenesisHash =
    '0x56c6819fe377e54e142cf15add68fa600c322e976ca27f3d973c31f95d2060bc';

void main() => runApp(const AgoraWalletApp());

class AgoraWalletApp extends StatelessWidget {
  const AgoraWalletApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'AGORA 钱包',
        theme: ThemeData(colorSchemeSeed: Colors.teal, useMaterial3: true),
        home: const WalletHomePage(),
      );
}

/// 全 App **只创建一份** client 与 repository（连接池、缓存、轮询都在里面）。
class WalletScope extends InheritedWidget {
  WalletScope({super.key, required this.repo, required super.child});

  final WalletRepository repo;

  static WalletRepository of(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<WalletScope>()!.repo;

  @override
  bool updateShouldNotify(WalletScope oldWidget) => repo != oldWidget.repo;
}

class WalletHomePage extends StatefulWidget {
  const WalletHomePage({super.key});

  @override
  State<WalletHomePage> createState() => _WalletHomePageState();
}

class _WalletHomePageState extends State<WalletHomePage>
    with WidgetsBindingObserver {
  late final AgoraHttpClient _client;
  late final WalletRepository _repo;

  // 私钥在真实 App 里必须来自安全存储（flutter_secure_storage / Keychain / Keystore）。
  // 示例里为可运行起见用内存中的种子，并**明确标注这是反面示例**。
  Uint8List? _seed;
  String? _address;

  StreamSubscription<AccountState>? _sub;
  AccountState? _account;
  Object? _error;
  bool _sending = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _client = AgoraHttpClient(_nodes,
        config: const AgoraClientConfig(
          expectedChainId: _expectedChainId,
          expectedGenesisHash: _expectedGenesisHash,
          timeout: Duration(seconds: 8),
        ));
    _repo = WalletRepository(api: AgoraApi(_client));
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _sub?.cancel();
    _repo.dispose();
    _client.close();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // 退到后台就停止轮询（省电）；回前台立刻重新拉一次。
    if (state == AppLifecycleState.resumed) {
      _subscribe();
    } else {
      _sub?.cancel();
      _sub = null;
    }
  }

  Future<void> _importSeed(String hex) async {
    final seed = hexToBytes(hex.trim());
    final pubkey = await ed25519PublicKey(seed);
    final addr = bytesToHex0x(keccak256(pubkey).sublist(12));
    setState(() {
      _seed = seed;
      _address = addr;
      _error = null;
    });
    _subscribe();
  }

  void _subscribe() {
    final addr = _address;
    if (addr == null) return;
    _sub?.cancel();
    _sub = _repo.watchAccount(addr).listen(
          (a) => setState(() {
            _account = a;
            _error = null;
          }),
          // **错误不结束流**：这里只记下来并让界面显示"离线/重试中"，
          // 网络恢复后会自动继续（包里有测试钉住这一性质）。
          onError: (Object e) => setState(() => _error = e),
        );
  }

  Future<void> _send(String to, String amountAgora) async {
    final seed = _seed;
    final acc = _account;
    if (seed == null || acc == null) return;
    setState(() => _sending = true);
    try {
      // ① 先确认链身份：它参与签名载荷，签错链会被节点按第 5 项拒收
      final st = await _repo.status(refresh: true);
      final chainId = utf8.encode(st.envelope.chainId);
      final pubkey = await ed25519PublicKey(seed);

      // ② nonce 与余额必须是**刚取到的**（写操作的前置条件，不能吃缓存）
      final fresh = await _repo.account(_address!, refresh: true);

      var tx = AgoraTransaction.transfer(
        nonce: fresh.nonce,
        to: normalizeAddress(to),
        value: parseAgoraToAtom(amountAgora),
        pubkey: pubkey,
        gasLimit: 100000,
        maxFeePerGas:
            ((st.baseFeePerGas ?? BigInt.from(1000000000)) * BigInt.two)
                .toInt(),
      );
      tx = await tx.sign(seed, chainId);
      if (!await tx.verifySignature(chainId)) {
        throw StateError('本地验签失败，已放弃提交');
      }

      // ③ 提交（202 = 已受理，**不是**上链）
      final r = await _repo.api.submitRawTx(tx.toHexEnvelope());
      if (!mounted) return;
      if (!r.isPending) throw StateError('节点未受理：${r.note}');
      _snack('已提交，等待上链…');

      // ④ 权威判定：查到所在区块才算成功
      for (var i = 0; i < 60; i++) {
        final look = await _repo.api.tx(tx.txHashHex);
        if (look.found) {
          _snack('已上链：高度 ${look.blockHeight}');
          return;
        }
        await Future<void>.delayed(const Duration(milliseconds: 500));
      }
      _snack('已提交但暂未上链，稍后可在交易记录里查看');
    } on AgoraChainMismatchException catch (e) {
      _snack('连到了别的链，已拒绝使用：${e.reason}');
    } on AgoraApiException catch (e) {
      // 交易被拒时服务端会带 §16.4.2 的项号，直接展示即可
      _snack(e.isNotFound ? '没有这笔记录' : '节点拒绝：${e.message}');
    } on AgoraTransportException {
      _snack('网络异常，请稍后重试');
    } on AgoraParseException catch (e) {
      _snack('节点数据异常：$e');
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  void _snack(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
  }

  @override
  Widget build(BuildContext context) {
    return WalletScope(
      repo: _repo,
      child: Scaffold(
        appBar: AppBar(title: const Text('AGORA 钱包')),
        body: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            if (_address == null)
              _SeedImportCard(onImport: _importSeed)
            else ...[
              _BalanceCard(
                address: _address!,
                account: _account,
                error: _error,
              ),
              const SizedBox(height: 16),
              _SendCard(enabled: !_sending, onSend: _send),
              const SizedBox(height: 16),
              _AirdropCard(address: _address!, seed: _seed!),
              const SizedBox(height: 16),
              _RepoSelfCheckCard(repo: _repo),
            ],
          ],
        ),
      ),
    );
  }
}

class _SeedImportCard extends StatefulWidget {
  const _SeedImportCard({required this.onImport});
  final Future<void> Function(String hex) onImport;

  @override
  State<_SeedImportCard> createState() => _SeedImportCardState();
}

class _SeedImportCardState extends State<_SeedImportCard> {
  final _ctrl = TextEditingController();

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('导入私钥（示例）',
                  style: TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              const Text(
                '⚠ 示例把种子放在内存里。真实 App 必须用安全存储'
                '（Keychain / Keystore），并且不要把助记词当种子直接使用'
                '（应先经 KDF 派生 32 字节）。',
                style: TextStyle(fontSize: 12, color: Colors.redAccent),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _ctrl,
                decoration:
                    const InputDecoration(labelText: '32 字节种子（64 位十六进制）'),
                inputFormatters: [
                  FilteringTextInputFormatter.allow(RegExp(r'[0-9a-fA-F]')),
                  LengthLimitingTextInputFormatter(64),
                ],
              ),
              const SizedBox(height: 8),
              FilledButton(
                onPressed: () => widget.onImport(_ctrl.text),
                child: const Text('导入并开始取数'),
              ),
            ],
          ),
        ),
      );
}

class _BalanceCard extends StatelessWidget {
  const _BalanceCard(
      {required this.address, required this.account, required this.error});

  final String address;
  final AccountState? account;
  final Object? error;

  @override
  Widget build(BuildContext context) {
    final acc = account;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(address, style: const TextStyle(fontSize: 12)),
            const SizedBox(height: 8),
            if (acc != null) ...[
              Text(displayBalance(acc.balanceAtom),
                  style: Theme.of(context).textTheme.headlineMedium),
              Text('高度 ${acc.envelope.height} · next nonce ${acc.nonce}',
                  style: Theme.of(context).textTheme.bodySmall),
            ] else if (error != null)
              Text(_explain(error!),
                  style: const TextStyle(color: Colors.orange))
            else
              const LinearProgressIndicator(),
            // 有旧数据时也把错误显示出来（"正在重试"而不是"空白"）
            if (acc != null && error != null) ...[
              const SizedBox(height: 4),
              Text(_explain(error!),
                  style: const TextStyle(fontSize: 12, color: Colors.orange)),
            ],
          ],
        ),
      ),
    );
  }

  static String _explain(Object e) {
    if (e is AgoraChainMismatchException) return '当前节点不是目标链：${e.reason}';
    if (e is AgoraTransportException) return '网络异常，正在自动重试…';
    return '数据异常：$e';
  }
}

class _SendCard extends StatefulWidget {
  const _SendCard({required this.enabled, required this.onSend});
  final bool enabled;
  final Future<void> Function(String to, String amount) onSend;

  @override
  State<_SendCard> createState() => _SendCardState();
}

class _SendCardState extends State<_SendCard> {
  final _to = TextEditingController();
  final _amt = TextEditingController(text: '1');

  @override
  void dispose() {
    _to.dispose();
    _amt.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('转账', style: TextStyle(fontWeight: FontWeight.bold)),
              TextField(
                controller: _to,
                decoration: const InputDecoration(labelText: '收款地址 0x…'),
              ),
              TextField(
                controller: _amt,
                decoration: const InputDecoration(labelText: '金额（AGORA）'),
                keyboardType:
                    const TextInputType.numberWithOptions(decimal: true),
              ),
              const SizedBox(height: 8),
              FilledButton(
                onPressed: widget.enabled
                    ? () => widget.onSend(_to.text, _amt.text)
                    : null,
                child: const Text('签名并提交'),
              ),
            ],
          ),
        ),
      );
}

class _AirdropCard extends StatefulWidget {
  const _AirdropCard({required this.address, required this.seed});
  final String address;
  final Uint8List seed;

  @override
  State<_AirdropCard> createState() => _AirdropCardState();
}

class _AirdropCardState extends State<_AirdropCard> {
  AirdropStatus? _ad;
  bool _busy = false;

  Future<void> _load() async {
    final repo = WalletScope.of(context);
    setState(() => _busy = true);
    try {
      final ad = await repo.airdrop(widget.address, refresh: true);
      if (mounted) setState(() => _ad = ad);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('空投查询失败：$e')));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _claim() async {
    final ad = _ad;
    final repo = WalletScope.of(context);
    if (ad == null) return;
    final missing = ad.missingForClaim();
    if (missing.isNotEmpty) {
      // 「本节点未加载分配表」与「你不在分配表里」是两件完全不同的事，
      // 原因由接口原样给出，这里直接展示。
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('暂不能领取：${missing.join("；")}')));
      return;
    }
    setState(() => _busy = true);
    try {
      final st = await repo.status(refresh: true);
      final chainId = utf8.encode(st.envelope.chainId);
      final pubkey = await ed25519PublicKey(widget.seed);
      final acc = await repo.account(widget.address, refresh: true);

      // 空投领取要**两处签名**：载荷里的绑定签名 + 交易签名
      var claim = AirdropClaim(
        index: ad.index!,
        amount: ad.amountAtom!,
        gasAllowance: ad.gasAllowanceAtom ?? BigInt.zero,
        pubkey: pubkey,
        merkleProof: ad.merkleProof,
      );
      claim =
          await claim.bind(widget.seed, chainId, hexToBytes(widget.address));
      var tx = AgoraTransaction.airdropClaim(
        nonce: acc.nonce,
        claim: claim,
        pubkey: pubkey,
        gasLimit: 100000,
        maxFeePerGas:
            ((st.baseFeePerGas ?? BigInt.from(1000000000)) * BigInt.two)
                .toInt(),
      );
      tx = await tx.sign(widget.seed, chainId);
      final r = await repo.api.submitRawTx(tx.toHexEnvelope());
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text(r.isPending ? '领取已提交，等待上链…' : '未受理：${r.note}')));
      await _load();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('领取失败：$e')));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final ad = _ad;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('空投', style: TextStyle(fontWeight: FontWeight.bold)),
            if (ad == null)
              const Text('尚未查询（空投证明由节点提供，链上只存 airdrop_root）')
            else ...[
              Text(
                  '可领取：${ad.eligible}  已领取：${ad.claimed}  证明可用：${ad.proofAvailable}'),
              if (ad.amountAtom != null)
                Text('条目 index=${ad.index} 金额=${formatAgora(ad.amountAtom!)}'),
              if (ad.reason.isNotEmpty)
                Text(ad.reason,
                    style: const TextStyle(fontSize: 12, color: Colors.orange)),
            ],
            const SizedBox(height: 8),
            Row(
              children: [
                OutlinedButton(
                    onPressed: _busy ? null : _load, child: const Text('查询')),
                const SizedBox(width: 8),
                FilledButton(
                    onPressed: _busy ? null : _claim, child: const Text('领取')),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

/// 把包自带的"取数纪律"也搬进界面：参数、验证者、链身份一目了然。
class _RepoSelfCheckCard extends StatelessWidget {
  const _RepoSelfCheckCard({required this.repo});
  final WalletRepository repo;

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: FutureBuilder<ChainParams>(
            future: repo.params(),
            builder: (context, snap) {
              final p = snap.data;
              if (p == null) return const Text('读取协议参数…');
              return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('链参数（**不要**在 App 里硬编码）',
                      style: TextStyle(fontWeight: FontWeight.bold)),
                  Text('chain_id : ${p.chainId}'),
                  Text(
                      '槽长 / 纪元 : ${p.slotTimeSeconds}s / ${p.epochLengthSlots} 槽'),
                  Text('空投窗口 : 槽 ${p.airdropStartSlot} .. ${p.airdropEndSlot}'),
                  Text('解绑期 : ${p.unbondingPeriodSlots} 槽'),
                ],
              );
            },
          ),
        ),
      );
}
