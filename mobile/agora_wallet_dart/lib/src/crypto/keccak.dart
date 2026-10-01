/// AGORA 钱包 · Keccak-256 与 `CHAIN()` 定宽连接（规范 §20.1 / §20.3）
///
/// Keccak-256 用 `pointycastle` 的 `KeccakDigest(256)`：
/// 它是**原始 Keccak**（填充字节 `0x01`），不是 NIST 的 SHA3-256（`0x06`）——
/// 两者输出的第一个字节就不同，用错会让 `tx_hash` 完全对不上。
/// 本仓库用黄金向量把它钉住（`tool/selftest.dart` 的"向量对齐"一节）。
///
/// `CHAIN()` 是**哈希原像与签名载荷的唯一连接函数**（§20.1），与 RLP 无关：
///
/// * 定宽整数：按声明宽度大端写出（`u8`/`u16`/`u32`/`u64`/`u256`）；
/// * 字节串：**20 或 32 字节原样**，其余长度加 `u32(len)` 前缀；
/// * 域标签：**前置在 CHAIN 之外**（ASCII，不加长度前缀）。
///
/// 为什么要显式声明宽度：早期实现让整数取"最小宽度"，同一个值在不同调用点
/// 得到不同字节（`index=1` 编成 1 字节，而链上按 `u64` 编成 8 字节），
/// 独立实现之间永远对不上 —— 这就是 BUG-64 与空投工具链那两次事故的根因。
library;

import 'dart:typed_data';

import 'package:pointycastle/digests/keccak.dart';

/// Keccak-256（Ethereum / AGORA 口径）。
Uint8List keccak256(List<int> input) {
  final digest = KeccakDigest(256);
  final data = input is Uint8List ? input : Uint8List.fromList(input);
  digest.update(data, 0, data.length);
  final out = Uint8List(32);
  digest.doFinal(out, 0);
  return out;
}

/// CHAIN 的字段宽度（单位：字节）。
const Map<String, int> chainWidths = {
  'u8': 1,
  'u16': 2,
  'u32': 4,
  'u64': 8,
  'u256': 32,
};

/// 一个 CHAIN 字段：定宽整数（[ChainField.u]）或字节串（[ChainField.bytes]）。
class ChainField {
  const ChainField.u(this.width, this.intValue) : bytes = null;
  const ChainField.bytes(this.bytes)
      : width = null,
        intValue = null;

  final String? width;
  final BigInt? intValue;
  final Uint8List? bytes;

  /// 便捷构造：`ChainField.uint64(7)`。
  factory ChainField.uint64(int v) => ChainField.u('u64', BigInt.from(v));
  factory ChainField.uint32(int v) => ChainField.u('u32', BigInt.from(v));
  factory ChainField.uint8(int v) => ChainField.u('u8', BigInt.from(v));
  factory ChainField.uint256(BigInt v) => ChainField.u('u256', v);
}

/// 规范 §20.1 的 `CHAIN(...)`：把字段按顺序连接成哈希原像。
///
/// **所有签名载荷与哈希原像都 MUST 用 [ChainField.u] 显式声明宽度。**
Uint8List chain(List<ChainField> fields) {
  final out = BytesBuilder(copy: false);
  for (final f in fields) {
    if (f.bytes != null) {
      final b = f.bytes!;
      if (b.length == 20 || b.length == 32) {
        out.add(b); // 地址 / 哈希：原样
      } else {
        out.add(_u32(b.length)); // 其余：u32 长度前缀
        out.add(b);
      }
      continue;
    }
    final w = f.width!;
    final width = chainWidths[w];
    if (width == null) {
      throw ArgumentError('未知 CHAIN 宽度名：$w（应为 u8/u16/u32/u64/u256）');
    }
    final v = f.intValue!;
    if (v.isNegative) throw ArgumentError('CHAIN 只接受无符号整数');
    if (v >= (BigInt.one << (8 * width))) {
      throw ArgumentError('$w 溢出：$v');
    }
    final buf = Uint8List(width);
    var x = v;
    for (var i = width - 1; i >= 0; i--) {
      buf[i] = (x & BigInt.from(0xff)).toInt();
      x = x >> 8;
    }
    out.add(buf);
  }
  return out.toBytes();
}

Uint8List _u32(int v) => Uint8List.fromList(
    [(v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);
