/// AGORA 钱包 · HTTP 传输层（零第三方依赖，只用 `dart:io`）
///
/// 为什么不用 http/dio
/// -------------------
/// * 钱包是最需要"少依赖"的一类应用：少一个包就少一处供应链风险；
/// * `dart:io` 的 `HttpClient` 足够用（连接池、超时、TLS 都由它管）；
/// * Flutter 移动端与桌面都支持 `dart:io`（仅 Web 不支持，Web 端需要换成
///   `package:http` 或 `dart:html` 的适配层，见 README 的"Web 平台"一节）。
///
/// 这个类负责四件事：
/// 1. **多节点故障转移**：一个节点连不上就换下一个（钱包不能因为"我连的那台挂了"就不能用）；
/// 2. **超时与重试**：GET 幂等，可安全重试；POST 不自动重试（避免重复提交交易）；
/// 3. **链身份强制校验**：`chain_id` / `genesis_hash` 不符立刻抛异常（见 [errors]）；
/// 4. **JSON 契约校验**：非 JSON、非对象、缺信封 → 抛 [AgoraParseException]，
///    绝不把坏数据当正常数据返回。
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'errors.dart';

/// 一个节点的地址（`baseUrl` 形如 `http://192.168.1.10:8645`）。
class AgoraNode {
  const AgoraNode(this.baseUrl, {this.label});

  final String baseUrl;
  final String? label;

  @override
  String toString() => label == null ? baseUrl : '$label($baseUrl)';
}

/// 客户端配置。
class AgoraClientConfig {
  const AgoraClientConfig({
    this.expectedChainId,
    this.expectedGenesisHash,
    this.timeout = const Duration(seconds: 8),
    this.maxRetries = 2,
    this.userAgent = 'agora-wallet-dart/0.1',
  });

  /// 预期链身份。**强烈建议设置**：不设就等于接受"任意节点说它是什么链就是什么链"。
  final String? expectedChainId;

  /// 预期创世哈希（比 `chain_id` 更强：链身份字符串相同也可能是另一条链）。
  final String? expectedGenesisHash;

  final Duration timeout;

  /// 单个节点的 GET 重试次数（换节点不计入）。
  final int maxRetries;

  final String userAgent;
}

/// 一次 HTTP 调用的结果。
class AgoraResponse {
  AgoraResponse(this.statusCode, this.json, this.node, {this.rawBody = ''});

  final int statusCode;
  final Map<String, dynamic> json;
  final AgoraNode node;
  final String rawBody;

  String get chainId => json['chain_id'] as String? ?? '';
}

/// 传输层：负责"把请求送到某个节点并拿回一个**已校验信封**的 JSON 对象"。
class AgoraHttpClient {
  AgoraHttpClient(List<AgoraNode> nodes, {AgoraClientConfig? config})
      : nodes = List.unmodifiable(nodes),
        config = config ?? const AgoraClientConfig() {
    if (nodes.isEmpty) {
      throw ArgumentError('至少要给一个节点地址（AgoraNode）');
    }
  }

  final List<AgoraNode> nodes;
  final AgoraClientConfig config;

  HttpClient? _client;
  int _roundRobin = 0;

  /// 最近一次成功使用的节点（界面可显示"当前节点"）。
  AgoraNode? lastGoodNode;

  HttpClient get _http => _client ??= HttpClient()
    ..connectionTimeout = config.timeout
    ..userAgent = config.userAgent;

  void close() {
    _client?.close(force: true);
    _client = null;
  }

  /// 按"上次成功的节点优先 + 轮询"的顺序返回候选节点。
  List<AgoraNode> _candidates() {
    final list = <AgoraNode>[];
    final last = lastGoodNode;
    if (last != null) list.add(last);
    for (var i = 0; i < nodes.length; i++) {
      final n = nodes[(_roundRobin + i) % nodes.length];
      if (last == null || n.baseUrl != last.baseUrl) list.add(n);
    }
    _roundRobin = (_roundRobin + 1) % nodes.length;
    return list;
  }

  /// GET 一个 JSON 端点。失败时按候选顺序换节点，全部失败才抛异常。
  Future<AgoraResponse> getJson(String path, {Map<String, String>? query}) async {
    final errors = <Object>[];
    for (final node in _candidates()) {
      for (var attempt = 0; attempt <= config.maxRetries; attempt++) {
        try {
          final res = await _request('GET', node, path, query: query);
          lastGoodNode = node;
          return res;
        } on AgoraApiException {
          // 服务端**明确**回答了（4xx/5xx）：这是权威结论，不要换节点重试 ——
          // 换一个节点可能得到不同答案，那会让"查不到"变成"随机结果"。
          rethrow;
        } on AgoraTransportException catch (e) {
          errors.add(e);
          if (attempt < config.maxRetries) {
            await Future<void>.delayed(Duration(milliseconds: 150 * (attempt + 1)));
          }
        }
      }
    }
    throw AgoraTransportException(
      '所有节点都不可达（${nodes.map((n) => n.baseUrl).join(", ")}）：${errors.isEmpty ? "未知原因" : errors.last}',
    );
  }

  /// POST（**不自动重试**：交易提交重复执行可能造成重复扣费/重复领取）。
  Future<AgoraResponse> postJson(String path, Map<String, dynamic> body) async {
    Object? lastError;
    for (final node in _candidates()) {
      try {
        final res = await _request('POST', node, path, body: body);
        lastGoodNode = node;
        return res;
      } on AgoraApiException {
        rethrow;                       // 服务端的明确回答：直接交给调用方
      } on AgoraTransportException catch (e) {
        lastError = e;                 // 换节点重试一次是安全的：请求可能根本没到
      }
    }
    throw AgoraTransportException('所有节点都不可达：$lastError');
  }

  Future<AgoraResponse> _request(
    String method,
    AgoraNode node,
    String path, {
    Map<String, String>? query,
    Map<String, dynamic>? body,
  }) async {
    final uri = Uri.parse('${node.baseUrl}$path').replace(queryParameters: query);
    HttpClientRequest req;
    try {
      req = await _http.openUrl(method, uri).timeout(config.timeout);
    } on TimeoutException catch (e) {
      throw AgoraTransportException('连接超时（${config.timeout.inSeconds}s）',
          baseUrl: node.baseUrl, cause: e);
    } on SocketException catch (e) {
      throw AgoraTransportException('无法连接（${e.osError?.message ?? e.message}）',
          baseUrl: node.baseUrl, cause: e);
    } on HttpException catch (e) {
      throw AgoraTransportException('HTTP 层错误：${e.message}',
          baseUrl: node.baseUrl, cause: e);
    }

    if (body != null) {
      final payload = utf8.encode(jsonEncode(body));
      req.headers.contentType = ContentType.json;
      req.headers.contentLength = payload.length;
      req.add(payload);
    }

    HttpClientResponse res;
    try {
      res = await req.close().timeout(config.timeout);
    } on TimeoutException catch (e) {
      throw AgoraTransportException('读取响应超时', baseUrl: node.baseUrl, cause: e);
    } on SocketException catch (e) {
      throw AgoraTransportException('连接中断：${e.osError?.message ?? e.message}',
          baseUrl: node.baseUrl, cause: e);
    }

    final raw = await utf8.decoder.bind(res).join();
    Map<String, dynamic> decoded;
    try {
      final obj = raw.isEmpty ? <String, dynamic>{} : jsonDecode(raw);
      if (obj is! Map<String, dynamic>) {
        throw const FormatException('响应顶层不是 JSON 对象');
      }
      decoded = obj;
    } on FormatException catch (e) {
      throw AgoraParseException('响应不是合法 JSON：${e.message}',
          path: path, snippet: raw.length > 120 ? '${raw.substring(0, 120)}…' : raw);
    }

    if (res.statusCode >= 200 && res.statusCode < 300) {
      _checkChainIdentity(decoded, node, path);
      return AgoraResponse(res.statusCode, decoded, node, rawBody: raw);
    }

    // 错误响应：`{"error": {"code", "message", "detail"}}`
    final err = decoded['error'];
    if (err is Map<String, dynamic>) {
      throw AgoraApiException(
        statusCode: res.statusCode,
        code: (err['code'] as String?) ?? 'unknown',
        message: (err['message'] as String?) ?? '服务端返回错误',
        detail: (err['detail'] as String?) ?? '',
        path: path,
      );
    }
    throw AgoraApiException(
      statusCode: res.statusCode,
      code: 'http_${res.statusCode}',
      message: '服务端返回 ${res.statusCode}，响应体不是标准错误结构',
      detail: raw.length > 200 ? raw.substring(0, 200) : raw,
      path: path,
    );
  }

  /// **链身份强制校验**（`/healthz` 之外的所有端点都会走这里）。
  ///
  /// 只做字符串比对：它不是密码学证明，但能挡住最常见、也最危险的一类错误 ——
  /// 手机连到了另一个网络（测试网/主网/自建的开发链）却浑然不觉。
  void _checkChainIdentity(Map<String, dynamic> json, AgoraNode node, String path) {
    final wantChain = config.expectedChainId;
    final wantGenesis = config.expectedGenesisHash;
    if (wantChain == null && wantGenesis == null) return;

    final gotChain = json['chain_id'] as String? ?? '';
    final hasGenesis = json.containsKey('genesis_hash');
    final gotGenesis = json['genesis_hash'] as String? ?? '';
    // 响应里**没有** genesis_hash 字段：这是契约缺失，不是"连错链"。
    // 两者必须分开报，否则会把人引到错误的排查方向（实测：/v1/params 曾漏回该字段，
    // 客户端报出「链身份不符（期望 … 实际 空）」，看起来像节点指向了别的网络）。
    if (wantGenesis != null && !hasGenesis && (wantChain == null || gotChain == wantChain)) {
      throw AgoraParseException(
          '响应缺少 genesis_hash 字段，无法核对链身份（该端点必须带齐信封）',
          path: path,
          snippet: json.keys.take(8).join(','));
    }
    if ((wantChain != null && gotChain != wantChain) ||
        (wantGenesis != null &&
            gotGenesis.toLowerCase() != wantGenesis.toLowerCase())) {
      throw AgoraChainMismatchException(
        expectedChainId: wantChain ?? '（未指定）',
        actualChainId: gotChain,
        expectedGenesisHash: wantGenesis,
        actualGenesisHash: gotGenesis,
        baseUrl: '${node.baseUrl}$path',
      );
    }
  }
}
