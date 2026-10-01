/// AGORA 钱包 · 交易构造与签名（规范 §16.1 / §20.2 / §20.3）
///
/// 字节级契约（**必须与链上逐一一致**，否则节点按 §16.4.2 第 1/5 项拒绝）：
///
/// ```text
/// TxContent = RLP([ tx_type, protocol_version_hash, nonce,
///                   max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
///                   to, value, payload, pubkey ])            # 10 项
/// TxEnvelope = RLP([ ...TxContent, signature ])              # 11 项
///
/// 签名载荷 = "AGORA/TX/v0.2.2" ‖ CHAIN(chain_id, TxContent)   # 标签在 CHAIN 之外
/// tx_hash  = Keccak(TxEnvelope)                              # 含签名
/// ```
///
/// 三个容易写错的地方（本模块都用测试钉住了）：
///
/// 1. **`protocol_version_hash` 是 `Keccak("AGORA/v0.2.2")`**，不是 `Keccak(chain_id)`；
///    后者是 `chain_id_hash`，它**不在**交易里（链身份通过签名载荷里的
///    `chain_id` 参与，见 §20.3）。
/// 2. **签名载荷不含签名字段**，且标签前置在 `CHAIN` **之外**
///    （早期实现在两处各写一份、写法不同，导致签名互相验不过 —— BUG-67）。
/// 3. **整数一律用最小字节串编码**（无前导零），`0` 编成空字节串 `0x80`。
library;

import 'dart:typed_data';

import '../crypto/ed25519.dart';
import '../crypto/keccak.dart';
import '../crypto/rlp.dart';
import 'payloads.dart';

/// 协议版本（与链上 `PROTOCOL_VERSION` 一致）。
const String agoraProtocolVersion = 'AGORA/v0.2.2';

/// 交易签名载荷的域标签（ASCII，前置在 CHAIN 之外；规范 §20.1/§20.3）。
const String tagTx = 'AGORA/TX/v0.2.2';

/// 交易类型码（规范 §16.2）。
class AgoraTxType {
  static const int transfer = 0x01;
  static const int bond = 0x02;
  static const int unbond = 0x03;
  static const int rebond = 0x04;
  static const int withdraw = 0x05;
  static const int evidence = 0x06;
  static const int airdropClaim = 0x07;

  static const Map<int, String> names = {
    transfer: 'TRANSFER',
    bond: 'BOND',
    unbond: 'UNBOND',
    rebond: 'REBOND',
    withdraw: 'WITHDRAW',
    evidence: 'EVIDENCE',
    airdropClaim: 'AIRDROP_CLAIM',
  };
}

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// 一条 AGORA 交易（不可变）。
class AgoraTransaction {
  AgoraTransaction({
    required this.txType,
    required this.nonce,
    required this.maxPriorityFeePerGas,
    required this.maxFeePerGas,
    required this.gasLimit,
    required List<int> to,
    required this.value,
    List<int> payload = const [],
    required List<int> pubkey,
    List<int> signature = const [],
    List<int>? protocolVersionHash,
  })  : to = Uint8List.fromList(to),
        payload = Uint8List.fromList(payload),
        pubkey = Uint8List.fromList(pubkey),
        signature = signature.isEmpty
            ? Uint8List(0)
            : Uint8List.fromList(signature),
        protocolVersionHash = Uint8List.fromList(
            protocolVersionHash ?? keccak256(agoraProtocolVersion.codeUnits)) {
    if (this.pubkey.length != 32) {
      throw ArgumentError('pubkey 必须为 32 字节，实际 ${this.pubkey.length}');
    }
    if (this.to.isNotEmpty && this.to.length != 20) {
      throw ArgumentError('to 必须为 20 字节或空（空 = 创建账户，本版本未使用）');
    }
    if (this.value.isNegative) throw ArgumentError('value 不能为负');
    if (this.signature.isNotEmpty && this.signature.length != 64) {
      throw ArgumentError('签名必须为 64 字节');
    }
  }

  final int txType;
  final int nonce;
  final int maxPriorityFeePerGas;
  final int maxFeePerGas;
  final int gasLimit;
  final Uint8List to;
  final BigInt value;
  final Uint8List payload;
  final Uint8List pubkey;
  final Uint8List signature;
  final Uint8List protocolVersionHash;

  /// 是否已签名。
  bool get isSigned => signature.length == 64;

  /// 构造 `BOND`（把自己注册为验证者 / 追加质押）。
  ///
  /// `validatorPubkey` 是**被质押账户自己的公钥**（规范 §16.2：BOND 的载荷是公钥）。
  factory AgoraTransaction.bond({
    required int nonce,
    required List<int> validatorPubkey,
    required BigInt value,
    required List<int> pubkey,
    required int gasLimit,
    required int maxFeePerGas,
    int maxPriorityFeePerGas = 0,
  }) =>
      AgoraTransaction(
        txType: AgoraTxType.bond,
        nonce: nonce,
        maxPriorityFeePerGas: maxPriorityFeePerGas,
        maxFeePerGas: maxFeePerGas,
        gasLimit: gasLimit,
        to: const [],
        value: value,
        payload: AgoraPayloads.bond(validatorPubkey),
        pubkey: pubkey,
      );

  /// 构造 `UNBOND`（解绑；资金进入 21 天解绑期，期间仍可被罚没）。
  factory AgoraTransaction.unbond({
    required int nonce,
    required BigInt amount,
    required List<int> pubkey,
    required int gasLimit,
    required int maxFeePerGas,
    int maxPriorityFeePerGas = 0,
  }) =>
      AgoraTransaction(
        txType: AgoraTxType.unbond,
        nonce: nonce,
        maxPriorityFeePerGas: maxPriorityFeePerGas,
        maxFeePerGas: maxFeePerGas,
        gasLimit: gasLimit,
        to: const [],
        value: BigInt.zero,
        payload: AgoraPayloads.amount(amount),
        pubkey: pubkey,
      );

  /// 构造 `REBOND`（把解绑中的资金重新质押回去）。
  factory AgoraTransaction.rebond({
    required int nonce,
    required BigInt amount,
    required List<int> pubkey,
    required int gasLimit,
    required int maxFeePerGas,
    int maxPriorityFeePerGas = 0,
  }) =>
      AgoraTransaction(
        txType: AgoraTxType.rebond,
        nonce: nonce,
        maxPriorityFeePerGas: maxPriorityFeePerGas,
        maxFeePerGas: maxFeePerGas,
        gasLimit: gasLimit,
        to: const [],
        value: BigInt.zero,
        payload: AgoraPayloads.amount(amount),
        pubkey: pubkey,
      );

  /// 构造 `WITHDRAW`（解绑期满后提取；未到期会被 §16.4.2 第 13 项拒绝）。
  factory AgoraTransaction.withdraw({
    required int nonce,
    required List<int> pubkey,
    required int gasLimit,
    required int maxFeePerGas,
    int maxPriorityFeePerGas = 0,
  }) =>
      AgoraTransaction(
        txType: AgoraTxType.withdraw,
        nonce: nonce,
        maxPriorityFeePerGas: maxPriorityFeePerGas,
        maxFeePerGas: maxFeePerGas,
        gasLimit: gasLimit,
        to: const [],
        value: BigInt.zero,
        payload: AgoraPayloads.withdraw(),
        pubkey: pubkey,
      );

  /// 构造 `AIRDROP_CLAIM`（§32.6）。
  ///
  /// `claim` **必须**已经用 [AirdropClaim.bind] 绑定过签名（`isBound == true`），
  /// 否则节点会在第 16 项拒绝（"绑定签名无效"）—— 这里提前拦下，省一次往返。
  factory AgoraTransaction.airdropClaim({
    required int nonce,
    required AirdropClaim claim,
    required List<int> pubkey,
    required int gasLimit,
    required int maxFeePerGas,
    int maxPriorityFeePerGas = 0,
    bool allowUnbound = false,
  }) {
    if (!claim.isBound && !allowUnbound) {
      throw ArgumentError('空投领取载荷尚未绑定签名：请先调用 AirdropClaim.bind()');
    }
    if (!_sameBytes(claim.pubkey, pubkey)) {
      throw ArgumentError('载荷里的 pubkey 必须与交易签名公钥一致（§32.6 第 ② 项）');
    }
    return AgoraTransaction(
      txType: AgoraTxType.airdropClaim,
      nonce: nonce,
      maxPriorityFeePerGas: maxPriorityFeePerGas,
      maxFeePerGas: maxFeePerGas,
      gasLimit: gasLimit,
      to: const [],
      value: BigInt.zero,
      payload: AgoraPayloads.airdropClaim(claim),
      pubkey: pubkey,
    );
  }

  /// 构造一笔**转账**（钱包最常用的那一种）。
  factory AgoraTransaction.transfer({
    required int nonce,
    required String to,
    required BigInt value,
    required List<int> pubkey,
    required int gasLimit,
    required int maxFeePerGas,
    int maxPriorityFeePerGas = 0,
  }) =>
      AgoraTransaction(
        txType: AgoraTxType.transfer,
        nonce: nonce,
        maxPriorityFeePerGas: maxPriorityFeePerGas,
        maxFeePerGas: maxFeePerGas,
        gasLimit: gasLimit,
        to: hexToBytes(to),
        value: value,
        payload: const [],
        pubkey: pubkey,
      );

  /// §16.1 的 `TxContent`（10 项，**不含签名**）。
  List<Object?> get contentFields => [
        txType,
        protocolVersionHash,
        nonce,
        maxPriorityFeePerGas,
        maxFeePerGas,
        gasLimit,
        to,
        value,
        payload,
        pubkey,
      ];

  /// `RLP(TxContent)`。
  Uint8List toContentRlp() => rlpEncode(contentFields);

  /// `RLP(TxEnvelope)` = 内容 + 签名（11 项）。
  Uint8List toEnvelopeRlp() =>
      rlpEncode([...contentFields, signature]);

  /// 签名载荷 = `TAG ‖ CHAIN(chain_id, TxContent)`。
  ///
  /// **绝不包含签名字段**；标签在 `CHAIN` 之外。
  Uint8List signingPayload(List<int> chainId) {
    final tag = Uint8List.fromList(tagTx.codeUnits);
    final chained = chain([
      ChainField.bytes(Uint8List.fromList(chainId)),
      ChainField.bytes(toContentRlp()),
    ]);
    return Uint8List.fromList([...tag, ...chained]);
  }

  /// `tx_hash = Keccak(TxEnvelope)`（含签名）。
  Uint8List txHash() => keccak256(toEnvelopeRlp());

  /// 用种子签名，返回**已签名**的新交易（不可变对象，不改自身）。
  Future<AgoraTransaction> sign(List<int> seed32, List<int> chainId) async {
    final sig = await ed25519Sign(seed32, signingPayload(chainId));
    return AgoraTransaction(
      txType: txType,
      nonce: nonce,
      maxPriorityFeePerGas: maxPriorityFeePerGas,
      maxFeePerGas: maxFeePerGas,
      gasLimit: gasLimit,
      to: to,
      value: value,
      payload: payload,
      pubkey: pubkey,
      signature: sig,
      protocolVersionHash: protocolVersionHash,
    );
  }

  /// 校验自身签名（不需要节点）。
  Future<bool> verifySignature(List<int> chainId) async {
    if (!isSigned) return false;
    return ed25519Verify(pubkey, signingPayload(chainId), signature);
  }

  /// 提交给节点的十六进制串（`0x` 前缀）。
  String toHexEnvelope() => bytesToHex0x(toEnvelopeRlp());

  String get txHashHex => bytesToHex0x(txHash());

  @override
  String toString() => 'AgoraTransaction(${AgoraTxType.names[txType] ?? txType} '
      'nonce=$nonce value=$value to=${bytesToHex0x(to)} '
      'hash=${txHashHex.substring(0, 12)}… signed=$isSigned)';
}
