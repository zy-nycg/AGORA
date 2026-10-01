/// AGORA 钱包 · RLP 编码（规范 §20.2）
///
/// 为什么自己实现而不用现成包
/// --------------------------
/// 交易封装是**共识对象**：字节错一个，节点就会以 §16.4.2 第 1 项拒绝，
/// 或者（更糟）算出不同的 `tx_hash` 让回执查不到。因此这里按规范字面实现，
/// 并用仓库里的 `TXBLOCK` 黄金向量**逐字节**比对（见 `tool/selftest.dart`）。
///
/// 规范要点（§20.2）
/// ----------------
/// * **整数必须是"最小字节串"编码**：`0` → `0x80`（空字节串），
///   `1` → `0x01`，`0x80` → `0x8180`；**不允许前导零**（`0x00 0x01` 非法）。
///   节点侧用 `require_canonical_int` 严格校验，编码端写错会被直接拒绝
///   （BUG-49 就是这条）。
/// * 单字节且 < 0x80 的字节串**原样写出**（不再加前缀）。
/// * 列表用 0xc0/0xf7（短）或 0xf8/0xf9…（长）前缀。
library;

import 'dart:typed_data';

/// RLP 编码失败（非规范输入）。
class RlpException implements Exception {
  RlpException(this.message);
  final String message;
  @override
  String toString() => 'RlpException: $message';
}

/// 把一个 [BigInt] 编码成"最小字节串"（无前导零；0 编码为空）。
Uint8List _intToMinimalBytes(BigInt v) {
  if (v.isNegative) {
    throw RlpException('RLP 只接受无符号整数，收到 $v');
  }
  if (v == BigInt.zero) return Uint8List(0);
  final len = (v.bitLength + 7) ~/ 8;
  final out = Uint8List(len);
  var x = v;
  for (var i = len - 1; i >= 0; i--) {
    out[i] = (x & BigInt.from(0xff)).toInt();
    x = x >> 8;
  }
  return out;
}

/// 长串（长度前缀 > 55 字节）时的长度前缀。
Uint8List _lengthPrefix(int offset, int len) {
  if (len <= 55) {
    return Uint8List.fromList([offset + len]);
  }
  final lenBytes = _intToMinimalBytes(BigInt.from(len));
  final out = Uint8List(1 + lenBytes.length);
  out[0] = offset + 55 + lenBytes.length;
  out.setRange(1, out.length, lenBytes);
  return out;
}

Uint8List _concatBytes(List<Uint8List> parts) {
  var total = 0;
  for (final p in parts) {
    total += p.length;
  }
  final out = Uint8List(total);
  var off = 0;
  for (final p in parts) {
    out.setRange(off, off + p.length, p);
    off += p.length;
  }
  return out;
}

/// 按规范 §20.2 编码任意值。
///
/// 支持：`int`/`BigInt`（最小字节串）、`Uint8List`/`List<int>`（字节串）、
/// `List`（嵌套列表）、`null`（编码为空字节串，等价于 0）。
Uint8List rlpEncode(Object? value) {
  if (value == null) {
    return Uint8List.fromList(const [0x80]);
  }
  if (value is BigInt) {
    final b = _intToMinimalBytes(value);
    if (b.isEmpty) return Uint8List.fromList(const [0x80]);
    if (b.length == 1 && b[0] < 0x80) return b;         // 单字节 <0x80 原样
    return _concatBytes([_lengthPrefix(0x80, b.length), b]);
  }
  if (value is int) {
    return rlpEncode(BigInt.from(value));
  }
  if (value is Uint8List) {
    if (value.length == 1 && value[0] < 0x80) return value;
    return _concatBytes([_lengthPrefix(0x80, value.length), value]);
  }
  if (value is List<int>) {
    return rlpEncode(Uint8List.fromList(value));
  }
  if (value is List) {
    final parts = value.map(rlpEncode).toList(growable: false);
    final body = _concatBytes(parts);
    return _concatBytes([_lengthPrefix(0xc0, body.length), body]);
  }
  throw RlpException('RLP 不支持的字段类型：${value.runtimeType}');
}

/// 十六进制字符串 → 字节（接受可选的 `0x` 前缀）。
Uint8List hexToBytes(String hex) {
  var s = hex.trim();
  if (s.startsWith('0x') || s.startsWith('0X')) s = s.substring(2);
  if (s.length.isOdd) {
    throw RlpException('十六进制串长度必须为偶数：$hex');
  }
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    final byte = int.tryParse(s.substring(i * 2, i * 2 + 2), radix: 16);
    if (byte == null) throw RlpException('非法的十六进制字符：$hex');
    out[i] = byte;
  }
  return out;
}

/// 字节 → 小写十六进制（不带前缀）。
String bytesToHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// 字节 → `0x` + 小写十六进制。
String bytesToHex0x(List<int> bytes) => '0x${bytesToHex(bytes)}';
