/// AGORA 钱包 · 错误类型
///
/// 为什么要把错误分类（而不是 everywhere `catch (e)`)
/// ------------------------------------------------
/// 钱包界面必须能区分三类完全不同的状况，否则用户看到的提示会误导人：
///
/// | 状况 | 类型 | 界面应该说什么 |
/// |---|---|---|
/// | 网络不通/超时 | [AgoraTransportException] | "网络异常，请稍后重试"（可重试） |
/// | 连错了链 | [AgoraChainMismatchException] | "当前节点不是目标链，已拒绝使用其数据"（**不可重试，必须换节点**） |
/// | 服务端说查不到 | [AgoraApiException] (404) | "该地址无记录"（不是错误） |
/// | 服务端返回了坏数据 | [AgoraParseException] | "节点返回的数据无法解析"（可疑，记录日志） |
/// | 接口不支持 | [AgoraApiException] (501) | "该功能尚不可用"（诚实告知，不要假装成功） |
///
/// 尤其是**链身份不匹配**：如果钱包不加检查地使用任意节点的数据，
/// 用户在测试网上充值的地址可能在主网上被显示成"余额 0"或"有余额"，
/// 而转账签名会因 chain_id 不同而失败。因此本客户端把链身份检查做成**强制**的。
library;

/// 所有 AGORA 客户端异常的基类。
abstract class AgoraException implements Exception {
  AgoraException(this.message);
  final String message;
  @override
  String toString() => '$runtimeType: $message';
}

/// 网络层失败：连不上、超时、连接被重置。
///
/// **可重试**（换节点或稍后重试）。
class AgoraTransportException extends AgoraException {
  AgoraTransportException(super.message, {this.baseUrl, this.cause});
  final String? baseUrl;
  final Object? cause;
  @override
  String toString() =>
      'AgoraTransportException($baseUrl): $message${cause == null ? '' : ' ← $cause'}';
}

/// 服务端返回了非 2xx（且不是 404 这种"业务性不存在"）。
class AgoraApiException extends AgoraException {
  AgoraApiException({
    required this.statusCode,
    required this.code,
    required String message,
    this.detail = '',
    this.path = '',
  }) : super(message);

  /// HTTP 状态码。
  final int statusCode;

  /// 服务端错误码（`not_found` / `bad_request` / `not_implemented` / …）。
  final String code;

  /// 服务端给出的补充说明（例如"缺哪三件事"）。
  final String detail;

  /// 请求路径（便于日志）。
  final String path;

  /// 是否是"这一版还没有的能力"（例如交易提交）。
  bool get isNotImplemented => statusCode == 501;

  /// 是否是"查询对象不存在"（不是故障）。
  bool get isNotFound => statusCode == 404;

  @override
  String toString() =>
      'AgoraApiException($statusCode $code @ $path): $message'
      '${detail.isEmpty ? '' : ' — $detail'}';
}

/// 响应体不符合契约（缺字段、类型不对、金额不是字符串……）。
///
/// **绝不用默认值兜底**：把"解析失败"伪装成"余额 0"是钱包里最危险的行为。
class AgoraParseException extends AgoraException {
  AgoraParseException(super.message, {this.path = '', this.snippet = ''});
  final String path;
  final String snippet;
  @override
  String toString() =>
      'AgoraParseException(@ $path): $message${snippet.isEmpty ? '' : ' | $snippet'}';
}

/// 连接到了**别的链**（或别的创世）：`chain_id` / `genesis_hash` 与预期不符。
///
/// 这是安全性检查，不是可用性问题；**必须**让用户看到并切回正确节点。
class AgoraChainMismatchException extends AgoraException {
  AgoraChainMismatchException({
    required this.expectedChainId,
    required this.actualChainId,
    required this.expectedGenesisHash,
    required this.actualGenesisHash,
    this.baseUrl = '',
  }) : super('节点返回的链身份与钱包预期不一致');

  final String expectedChainId;
  final String actualChainId;
  final String? expectedGenesisHash;
  final String? actualGenesisHash;
  final String baseUrl;

  /// 具体是哪一项不符（便于日志与界面提示）。
  String get reason {
    final parts = <String>[];
    if (expectedChainId != actualChainId) {
      parts.add('chain_id: 期望 $expectedChainId，实际 $actualChainId');
    }
    if (expectedGenesisHash != null &&
        actualGenesisHash != null &&
        expectedGenesisHash!.toLowerCase() != actualGenesisHash!.toLowerCase()) {
      parts.add('genesis_hash: 期望 $expectedGenesisHash，实际 $actualGenesisHash');
    }
    return parts.join('；');
  }

  @override
  String toString() => 'AgoraChainMismatchException($baseUrl): $reason';
}

/// 节点高度落后于钱包要求（例如提交交易前要求"已追平"）。
class AgoraStaleDataException extends AgoraException {
  AgoraStaleDataException(super.message, {this.height, this.requiredHeight});
  final int? height;
  final int? requiredHeight;
}
