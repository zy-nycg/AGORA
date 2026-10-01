/// AGORA 钱包 · Ed25519 签名（RFC 8032，规范 §2.1）
///
/// **为什么用依赖而不自己实现**
/// --------------------------
/// 钱包里手写椭圆曲线运算不可接受：一个进位错误就可能让私钥泄露或签名可伪造，
/// 而且这类错误**不会在测试里"看起来不对"**（签名照样能自洽验证）。
/// 因此这里用 `cryptography`（纯 Dart、被广泛使用的实现），并把它与链上实现做
/// **双向**验证：
///
/// * Dart 签出的交易 → 提交给节点 → 节点按 §16.4.2 第 5 项验签通过（端到端）；
/// * Python（C 后端）签出的签名 → Dart 验签通过（见 `tool/selftest.dart`）。
///
/// 实测：同一 seed 与消息，Dart 与 Python 产出的**签名逐字节相同**
/// （RFC 8032 是确定性签名，签名值不应有随机性）。
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// 由 32 字节种子推导 Ed25519 公钥。
Future<Uint8List> ed25519PublicKey(List<int> seed32) async {
  _checkSeed(seed32);
  final kp = await Ed25519().newKeyPairFromSeed(
      seed32 is Uint8List ? seed32 : Uint8List.fromList(seed32));
  final pub = await kp.extractPublicKey();
  return Uint8List.fromList(pub.bytes);
}

/// 用 32 字节种子对消息签名（返回 64 字节签名）。
///
/// 确定性：同一 (seed, message) **必须**给出同一签名 —— 如果实现引入了随机性，
/// 同一笔交易重签会得到不同 `tx_hash`，钱包的重试逻辑就会重复扣费。
Future<Uint8List> ed25519Sign(List<int> seed32, List<int> message) async {
  _checkSeed(seed32);
  final algo = Ed25519();
  final kp = await algo.newKeyPairFromSeed(
      seed32 is Uint8List ? seed32 : Uint8List.fromList(seed32));
  final sig = await algo.sign(
      message is Uint8List ? message : Uint8List.fromList(message),
      keyPair: kp);
  return Uint8List.fromList(sig.bytes);
}

/// 校验 Ed25519 签名（严格长度检查；任何异常都算验签失败）。
Future<bool> ed25519Verify(List<int> pubkey32, List<int> message,
    List<int> signature) async {
  if (pubkey32.length != 32 || signature.length != 64) return false;
  try {
    final algo = Ed25519();
    final pub = SimplePublicKey(
        pubkey32 is Uint8List ? pubkey32 : Uint8List.fromList(pubkey32),
        type: KeyPairType.ed25519);
    final sig = Signature(
        signature is Uint8List ? signature : Uint8List.fromList(signature),
        publicKey: pub);
    return await algo.verify(
        message is Uint8List ? message : Uint8List.fromList(message),
        signature: sig);
  } catch (_) {
    return false;
  }
}

void _checkSeed(List<int> seed) {
  if (seed.length != 32) {
    throw ArgumentError('Ed25519 种子必须为 32 字节，实际 ${seed.length} —— '
        '不要用手写口令/助记词直接当种子（应先经 KDF 派生 32 字节）');
  }
}
