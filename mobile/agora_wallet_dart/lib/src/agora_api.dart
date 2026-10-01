/// AGORA 钱包 · 数据接口（把 HTTP 端点映射成类型化方法）
///
/// 这一层只做一件事：**端点 → 模型**，不含缓存、不含轮询（那些在
/// `wallet_repository.dart`）。这样"取数"与"怎么用数"分开，便于各自测试。
library;

import 'amount.dart';
import 'errors.dart';
import 'http_client.dart';
import 'models.dart';

class AgoraApi {
  AgoraApi(this.client);

  final AgoraHttpClient client;

  /// 存活探测（**不走链身份校验**：它本来就不返回链信息）。
  Future<bool> health() async {
    try {
      final res = await client.getJson('/healthz');
      return res.json['ok'] == true;
    } on AgoraException {
      return false;
    }
  }

  /// 协议参数：钱包**不应**硬编码槽长、原子精度、空投窗口等常量。
  Future<ChainParams> params() async {
    final res = await client.getJson('/v1/params');
    return ChainParams.fromJson(res.json, path: '/v1/params');
  }

  /// 链状态：高度、链头、状态根、当前槽、空投窗口与可用性。
  Future<ChainStatus> status() async {
    final res = await client.getJson('/v1/status');
    return ChainStatus.fromJson(res.json, path: '/v1/status');
  }

  /// 账户：余额（atom）、nonce（下一笔交易就用它）、验证者信息。
  Future<AccountState> account(String address) async {
    final a = normalizeAddress(address);
    final res = await client.getJson('/v1/account/$a');
    return AccountState.fromJson(res.json, path: '/v1/account/$a');
  }

  /// 区块：按高度（`latest`/数字）或按哈希。
  Future<BlockView> block(String heightOrHash) async {
    final path = '/v1/block/$heightOrHash';
    final res = await client.getJson(path);
    final b = res.json['block'];
    if (b is! Map<String, dynamic>) {
      throw AgoraParseException('响应缺少 "block" 对象', path: path);
    }
    return BlockView.fromJson(b, res.json, path: path);
  }

  Future<BlockView> latestBlock() => block('latest');

  /// 交易：所在区块、块内位置、确认数、回执。
  Future<TxLookup> tx(String txHash) async {
    final h = normalizeHash(txHash, field: 'tx_hash');
    final res = await client.getJson('/v1/tx/$h');
    return TxLookup.fromJson(res.json, path: '/v1/tx/$h');
  }

  /// 空投：资格、金额、`index`、Merkle 证明、领取状态、窗口。
  Future<AirdropStatus> airdrop(String address) async {
    final a = normalizeAddress(address);
    final res = await client.getJson('/v1/airdrop/$a');
    return AirdropStatus.fromJson(res.json, path: '/v1/airdrop/$a');
  }

  /// 验证者列表（含法定数阈值）。
  Future<ValidatorSet> validators() async {
    final res = await client.getJson('/v1/validators');
    return ValidatorSet.fromJson(res.json, path: '/v1/validators');
  }

  /// 单个验证者；不是验证者时返回 `null`（404 不是故障）。
  Future<ValidatorInfo?> validator(String address) async {
    final a = normalizeAddress(address);
    try {
      final res = await client.getJson('/v1/validator/$a');
      final v = res.json['validator'];
      if (v is! Map<String, dynamic>) {
        throw AgoraParseException('响应缺少 "validator" 对象',
            path: '/v1/validator/$a');
      }
      return ValidatorInfo.fromJson(v, path: '/v1/validator/$a');
    } on AgoraApiException catch (e) {
      if (e.isNotFound) return null;
      rethrow;
    }
  }

  /// 提交**已签名**交易（RLP 十六进制）。
  ///
  /// 语义（务必按这个写界面）：
  /// * 成功 ⇒ HTTP 202 + `accepted=true`/`status=queued`，**只表示节点已受理并转发**，
  ///   **不表示一定上链**；要用 [tx] 查询到所在区块才算数；
  /// * `status=duplicate` ⇒ 该交易已在池中（重复提交是安全的）；
  /// * 交易不合法 ⇒ 抛 [AgoraApiException]（HTTP 400，`code=tx_rejected`，
  ///   `message` 里带 §16.4.2 的项号，例如"第 9 项失败：nonce 不匹配"）。
  Future<TxSubmitResult> submitRawTx(String txRlpHex) async {
    final res = await client.postJson('/v1/tx', {'tx_rlp': txRlpHex});
    return TxSubmitResult.fromJson(res.json);
  }
}

/// 交易提交结果（**受理 ≠ 上链**）。
class TxSubmitResult {
  const TxSubmitResult({
    required this.accepted,
    required this.status,
    this.txHash,
    this.poolSize = 0,
    this.note = '',
  });

  /// 是否已被本节点受理（并转发）。
  final bool accepted;

  /// `queued`（新受理）或 `duplicate`（已在池中）——两者都可以继续等上链。
  final String status;
  final String? txHash;
  final int poolSize;
  final String note;

  /// 是否"已受理或本来就在池中"（界面据此显示"等待上链"）。
  bool get isPending => accepted || status == 'duplicate';

  static TxSubmitResult fromJson(Map<String, dynamic> json) => TxSubmitResult(
        accepted: json['accepted'] == true,
        status: (json['status'] as String?) ?? 'unknown',
        txHash: json['tx_hash'] as String?,
        poolSize: (json['pool_size'] as int?) ?? 0,
        note: (json['note'] as String?) ?? '',
      );
}
