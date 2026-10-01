/// AGORA 钱包 · 金额与地址的**唯一**处理入口
///
/// 为什么单独一个文件、为什么这么啰嗦
/// ----------------------------------
/// 1 AGORA = 10^18 atom，初始供应约 2.048×10^25 atom。这个量级**超出**
/// IEEE-754 双精度能精确表示的范围（安全整数上限 2^53 ≈ 9.0×10^15），
/// 也超出 Dart 的 `int`（64 位，上限约 9.2×10^18）。
///
/// 因此钱包里**只有两种合法做法**：
///
/// * 金额一律用 [BigInt]；
/// * 服务端返回的 `*_atom` 字段一律是**十进制字符串**，绝不解析成 `double`。
///
/// 曾经见过的事故模式：`balance as num` → 静默丢精度 → 界面显示"余额正常"，
/// 但转账金额算错、或 gas 费少算一位。这类错误**不会抛异常**，只会把钱算错，
/// 所以本文件把金额解析收敛到一处，并在解析失败时**抛异常而不是用 0 兜底**
/// （用 0 兜底会让界面显示"余额 0"，用户以为钱没了）。
library;

/// 1 AGORA = 10^18 atom（规范 A9）。
final BigInt atomPerAgora = BigInt.from(10).pow(18);

/// 地址字节长度（规范 §19.2）。
const int addressBytes = 20;

/// 交易哈希 / 区块哈希 / 状态根长度。
const int hashBytes = 32;

/// 把 `*_atom` 字段（十进制字符串）解析为 [BigInt]。
///
/// 接受 `"0"`、`"123"`、可选前导 `+`；**拒绝**小数、科学计数法、千分位逗号、
/// 空串 —— 这些都属于"服务端契约被破坏"，必须显式暴露而不是猜一个值。
BigInt parseAtom(Object? raw, {required String field}) {
  if (raw is String) {
    final s = raw.trim();
    if (s.isEmpty) {
      throw FormatException('$field 是空字符串，无法解析为 atom 金额');
    }
    final ok = RegExp(r'^\+?\d+$').hasMatch(s);
    if (!ok) {
      throw FormatException(
          '$field 必须是十进制整数字符串（atom），实际为 "$s" —— '
          '不要用 double/num 解析金额：1 AGORA = 10^18 atom，超出双精度安全范围');
    }
    return BigInt.parse(s);
  }
  if (raw is int) {
    // 允许小整数（例如 0），但仍然拒绝用 double 传金额
    return BigInt.from(raw);
  }
  throw FormatException(
      '$field 的类型是 ${raw.runtimeType}，但金额字段必须是十进制字符串 '
      '（服务端契约：所有 *_atom 字段为 string）');
}

/// atom → 人类可读的 AGORA 字符串，例如 `114687999999999999636` → `"114.6879"`。
///
/// [decimals] 为显示小数位（默认 4）；**只用于显示**，任何计算都必须用 atom 的 [BigInt]。
String formatAgora(BigInt atom, {int decimals = 4, bool withUnit = false}) {
  if (decimals < 0 || decimals > 18) {
    throw ArgumentError('decimals 必须在 0..18 之间，实际 $decimals');
  }
  final negative = atom.isNegative;
  final v = atom.abs();
  final whole = v ~/ atomPerAgora;
  var frac = (v % atomPerAgora).toString().padLeft(18, '0');
  if (decimals == 0) {
    return '${negative ? '-' : ''}$whole${withUnit ? ' AGORA' : ''}';
  }
  frac = frac.substring(0, decimals);
  final trimmed = frac.replaceFirst(RegExp(r'0+$'), '');
  final body = trimmed.isEmpty ? '$whole' : '$whole.$trimmed';
  return '${negative ? '-' : ''}$body${withUnit ? ' AGORA' : ''}';
}

/// 用户输入的 AGORA 字符串（如 `"1.5"`）→ atom 的 [BigInt]。
///
/// 严格解析：不接受空串、负号（转账金额必须为正）、超过 18 位小数、
/// 非数字字符。付款金额一旦解析错就是**不可逆**的，所以这里宁可报错。
BigInt parseAgoraToAtom(String text) {
  final s = text.trim().replaceAll('_', '');
  if (s.isEmpty) throw FormatException('金额为空');
  if (s.startsWith('-')) throw FormatException('金额不能为负：$text');
  final m = RegExp(r'^(\d+)(?:\.(\d*))?$').firstMatch(s);
  if (m == null) throw FormatException('金额格式非法：$text');
  final whole = BigInt.parse(m.group(1)!);
  final fracRaw = m.group(2) ?? '';
  if (fracRaw.length > 18) {
    throw FormatException('金额小数位超过 18 位（1 atom 是最小单位）：$text');
  }
  final frac = fracRaw.isEmpty
      ? BigInt.zero
      : BigInt.parse(fracRaw.padRight(18, '0'));
  return whole * atomPerAgora + frac;
}

/// 规范化地址：`0x` + 40 位小写十六进制。
///
/// 前端展示与小写比较都应使用本函数的结果；**不要**在别处手写 substring 逻辑。
String normalizeAddress(String address) {
  var s = address.trim();
  if (s.startsWith('0x') || s.startsWith('0X')) s = s.substring(2);
  s = s.toLowerCase();
  if (!RegExp(r'^[0-9a-f]{40}$').hasMatch(s)) {
    throw FormatException(
        '地址必须是 20 字节（40 位十六进制），实际 ${s.length} 位：$address');
  }
  return '0x$s';
}

/// 校验并规范化 32 字节哈希（区块/交易/状态根）。
String normalizeHash(String value, {String field = 'hash'}) {
  var s = value.trim();
  if (s.startsWith('0x') || s.startsWith('0X')) s = s.substring(2);
  s = s.toLowerCase();
  if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(s)) {
    throw FormatException('$field 必须是 32 字节（64 位十六进制），实际 ${s.length} 位');
  }
  return '0x$s';
}

/// 简易地址校验（不抛异常），供输入框实时反馈使用。
bool isPlausibleAddress(String address) {
  var s = address.trim();
  if (s.startsWith('0x') || s.startsWith('0X')) s = s.substring(2);
  return RegExp(r'^[0-9a-fA-F]{40}$').hasMatch(s);
}
