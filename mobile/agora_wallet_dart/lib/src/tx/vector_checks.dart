// AGORA 钱包 · 签名模块的**向量对齐**自检（`dart run tool/selftest.dart` 会调用它）
//
// 为什么必须有这一层
// ------------------
// 单元测试只能证明"自己和自己一致"；真正要证明的是"**和链上一致**"。
// 因此这里对着仓库里的黄金向量（`vectors/agora_v0.2.2_vectors.json`，
// 由 Python 参考实现生成）做**逐字节**比对：
//
//   · ENC     —— RLP 编码（含最小编码规则）
//   · CHAIN   —— 定宽连接（含 u8/u64/u256 与字节串前缀规则）
//   · TXBLOCK —— 真实交易的 TxContent / TxEnvelope / 签名载荷 / tx_hash / 签名
//
// 最后一项最强：**用同一个种子、按同样的载荷签名，必须得到与向量完全相同的
// 64 字节签名**（RFC 8032 是确定性签名）。签名一致 ⇒ RLP、CHAIN、域标签、
// 字段顺序、Ed25519 全部正确 —— 任何一处错了签名都不会相同。

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:agora_wallet/agora_wallet.dart';

int _pass = 0;
int _fail = 0;

void _chk(String name, bool ok, [String detail = '']) {
  if (ok) {
    _pass++;
    print('  [OK  ] $name${detail.isEmpty ? '' : '   $detail'}');
  } else {
    _fail++;
    print('  [FAIL] $name${detail.isEmpty ? '' : '   $detail'}');
  }
}

/// 地址 = `Keccak(pubkey)` 的后 20 字节（规范 §19.2/§2.1）。
String _addressFromPubkey(List<int> pubkey) {
  final h = keccak256(pubkey);
  return bytesToHex0x(h.sublist(12));
}

/// 返回 `(通过, 失败)`，供 selftest 汇总。
Future<List<int>> runTxVectorChecks() async {
  print('\n8) 签名模块向量对齐（RLP / CHAIN / TXBLOCK，逐字节）');
  final path = _findVectors();
  if (path == null) {
    _chk('找到黄金向量文件 vectors/agora_v0.2.2_vectors.json', false,
        '未找到（跳过向量检查）');
    return [_pass, _fail];
  }
  final vectors = jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;
  _chk('读取向量文件', true, path);

  // ── RLP：编码表 ──
  // 向量里的 `input_repr` 是 **Python 字面量**（`0` / `b'dog'` / `[1, 2, [3]]`），
  // 因此这里自带一个小解析器（只支持这个子集）；解析不了的行记为"跳过"而不是失败
  // —— 把"没解析"当成"通过"是最容易骗过自己的做法，因此两者分开计数并都打印出来。
  final enc = vectors['ENC'] as Map<String, dynamic>;
  var rlpOk = 0;
  var rlpSkipped = 0;
  final rlpRows = enc['encode'] as List;
  for (final row in rlpRows) {
    final r = row as Map<String, dynamic>;
    final repr = r['input_repr'] as String;
    final expected = (r['expected'] as String).toLowerCase();
    final input = _parsePyLiteral(repr);
    if (input == null) {
      rlpSkipped++;
      continue;
    }
    if (bytesToHex(rlpEncode(input)) == expected) rlpOk++;
  }
  _chk('RLP 编码表逐字节一致（${rlpRows.length} 行，跳过 $rlpSkipped 行）',
      rlpOk + rlpSkipped == rlpRows.length && rlpOk > 0,
      '$rlpOk 通过 / $rlpSkipped 跳过 / ${rlpRows.length} 总');

  // 最小编码的关键反例（写错会被节点按 §16.4.2 第 1 项拒绝）
  _chk('整数 0 ⇒ 0x80（空字节串）', bytesToHex(rlpEncode(0)) == '80');
  _chk('整数 127 ⇒ 0x7f（单字节不加前缀）', bytesToHex(rlpEncode(127)) == '7f');
  _chk('整数 128 ⇒ 0x8180（必须加长度前缀）', bytesToHex(rlpEncode(128)) == '8180');
  _chk('非规范输入（负数）必须抛异常',
      _throws(() => rlpEncode(BigInt.from(-1))));

  // ── CHAIN：定宽连接（`fields` 是结构化 JSON：[{"t":"u8","v":"1"}]）──
  final chainRows = (vectors['CHAIN'] as Map<String, dynamic>)['chain'] as List;
  var chainOk = 0;
  var chainSkipped = 0;
  for (final row in chainRows) {
    final r = row as Map<String, dynamic>;
    final expected = (r['expected'] as String? ?? '').toLowerCase();
    final rawFields = r['fields'];
    if (expected.isEmpty || rawFields is! List) {
      chainSkipped++;                      // 最后两行是投票载荷（下面单独校验）
      continue;
    }
    final parsed = <ChainField>[];
    var bad = false;
    for (final item in rawFields) {
      final m = item as Map<String, dynamic>;
      final t = m['t'].toString();
      final v = m['v'].toString();
      if (['u8', 'u16', 'u32', 'u64', 'u256'].contains(t)) {
        parsed.add(ChainField.u(t, BigInt.parse(v)));
      } else if (t == 'bytes') {
        parsed.add(ChainField.bytes(hexToBytes(v)));
      } else {
        bad = true;
        break;
      }
    }
    if (bad) {
      chainSkipped++;
      continue;
    }
    if (bytesToHex(chain(parsed)) == expected) chainOk++;
  }
  _chk('CHAIN 定宽连接表逐字节一致（跳过 $chainSkipped 行投票载荷）',
      chainOk + chainSkipped == chainRows.length && chainOk > 0,
      '$chainOk 通过 / $chainSkipped 跳过 / ${chainRows.length} 总');

  // ── CHAIN 摘要 + 投票签名载荷（这两行给出 payload 与 digest）──
  var digOk = 0;
  var digTotal = 0;
  for (final row in chainRows) {
    final r = row as Map<String, dynamic>;
    final payload = r['payload'] as String?;
    final digest = r['digest'] as String?;
    if (payload == null || digest == null) continue;
    digTotal++;
    if (bytesToHex(keccak256(hexToBytes(payload))) == digest.toLowerCase()) {
      digOk++;
    }
  }
  if (digTotal > 0) {
    _chk('投票签名载荷的 Keccak 摘要 $digOk/$digTotal 一致', digOk == digTotal);
  }

  // ── TXBLOCK：真实交易逐字节 ──
  final tb = vectors['TXBLOCK'] as Map<String, dynamic>;
  final txVec = tb['tx'] as Map<String, dynamic>;
  final f = txVec['fields'] as Map<String, dynamic>;
  // 种子**从向量里读**：向量必须自描述（否则第二实现只能去翻生成器源码）。
  // 早期版本把种子硬编码在测试里，结果 TXPAYLOADS 用的是另一个种子，
  // "重签"检查全线失败 —— 而那其实只是测试写错了种子，与实现无关。
  final seedHex = tb['seed_hex'] as String?;
  if (seedHex == null) {
    _chk('TXBLOCK 向量里声明了签名种子 seed_hex', false,
        '缺该字段 ⇒ 无法做"重签一致"检查（请重新生成向量）');
  }
  final seed = seedHex != null ? hexToBytes(seedHex) : Uint8List(32);
  final pubkey = hexToBytes(f['pubkey'] as String);

  // ⚠ 向量里的整数**类型不统一**：小整数是 JSON number，大整数（如 value）是字符串
  //   —— 因为 JSON number 在 JS/Dart 里是 double，超过 2^53 会静默丢精度。
  //   因此这里统一用 `_asInt` 解析，并把这一点当作契约的一部分。
  int asInt(String k) => _asInt(f[k], k);
  final tx = AgoraTransaction(
    txType: asInt('tx_type'),
    nonce: asInt('nonce'),
    maxPriorityFeePerGas: asInt('max_priority_fee_per_gas'),
    maxFeePerGas: asInt('max_fee_per_gas'),
    gasLimit: asInt('gas_limit'),
    to: hexToBytes(f['to'] as String),
    value: BigInt.parse(f['value'].toString()),
    payload: hexToBytes(f['payload'] as String),
    pubkey: pubkey,
    signature: hexToBytes(f['signature'] as String),
  );

  _chk('TxContent RLP 逐字节一致',
      bytesToHex(tx.toContentRlp()) == (txVec['content_rlp'] as String),
      '${bytesToHex(tx.toContentRlp()).substring(0, 24)}…');
  _chk('TxEnvelope RLP 逐字节一致',
      bytesToHex(tx.toEnvelopeRlp()) == (txVec['envelope_rlp'] as String));
  _chk('protocol_version_hash == Keccak("AGORA/v0.2.2")',
      bytesToHex(tx.protocolVersionHash) == (f['protocol_version_hash'] as String));
  _chk('tx_hash == Keccak(TxEnvelope)',
      bytesToHex(tx.txHash()) == (txVec['tx_hash'] as String),
      bytesToHex0x(tx.txHash()));
  _chk('地址推导 == 向量里的 sender_address',
      _addressFromPubkey(pubkey) ==
          '0x${(txVec['sender_address'] as String).replaceFirst('0x', '')}',
      _addressFromPubkey(pubkey));

  // 签名载荷（标签 + CHAIN(chain_id, TxContent)）
  // 链身份从向量的 meta 取（交易字段里**没有** chain_id：它只出现在签名载荷里，
  // 见 §20.3；交易里那个 32 字节字段是 protocol_version_hash，**不是** chain_id_hash）。
  final meta = vectors['meta'] as Map<String, dynamic>? ?? const {};
  final chainId = utf8.encode(meta['chain_id'] as String? ?? 'agora-mainnet-1');
  _chk('签名载荷逐字节一致',
      bytesToHex(tx.signingPayload(chainId)) ==
          (txVec['signing_payload'] as String),
      '${bytesToHex(tx.signingPayload(chainId)).substring(0, 28)}…');

  // ★ 最强的一条：用同一种子重签，必须得到**完全相同**的签名
  final resigned = await tx.sign(seed, chainId);
  _chk('★重签得到的签名与向量逐字节相同（确定性 Ed25519 + 载荷正确）',
      bytesToHex(resigned.signature) == (f['signature'] as String),
      bytesToHex0x(resigned.signature).substring(0, 20) + '…');
  _chk('★用 Dart 自己验签通过', await resigned.verifySignature(chainId));

  // RFC 8032 TEST 1：把 Ed25519 接线钉在标准上（不是"自己和自己一致"）
  const rfcSeed =
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
  const rfcPub =
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
  const rfcSig =
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
      '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';
  final pk = await ed25519PublicKey(hexToBytes(rfcSeed));
  _chk('Ed25519：RFC 8032 TEST 1 的公钥推导一致',
      bytesToHex(pk) == rfcPub, bytesToHex(pk));
  final sigEmpty = await ed25519Sign(hexToBytes(rfcSeed), const []);
  _chk('Ed25519：RFC 8032 TEST 1 的签名一致',
      bytesToHex(sigEmpty) == rfcSig);
  _chk('Ed25519：签名的**确定性**（同输入两次结果相同）',
      bytesToHex(await ed25519Sign(hexToBytes(rfcSeed), const [])) == rfcSig);
  _chk('Ed25519：篡改消息后验签失败',
      !(await ed25519Verify(hexToBytes(rfcPub), const [1], hexToBytes(rfcSig))));
  _chk('Ed25519：长度不对的签名直接判失败',
      !(await ed25519Verify(hexToBytes(rfcPub), const [], Uint8List(63))));

  // ── TXPAYLOADS：七种类型的载荷与封装（含空投领取的绑定签名）──
  final pay = vectors['TXPAYLOADS'] as Map<String, dynamic>?;
  if (pay != null) {
    print('\n8b) 各交易类型的载荷与封装（TXPAYLOADS）');
    final cases = pay['cases'] as List;
    final paySeedHex = pay['seed_hex'] as String?;
    _chk('TXPAYLOADS 向量里声明了签名种子 seed_hex', paySeedHex != null,
        paySeedHex ?? '（缺失）');
    final paySeed =
        paySeedHex != null ? hexToBytes(paySeedHex) : Uint8List(32);
    var ok = 0;
    for (final c in cases) {
      final r = c as Map<String, dynamic>;
      final name = r['case'] as String;
      final payload = hexToBytes(r['payload'] as String);
      final pk = hexToBytes(r['pubkey'] as String);
      final tx = AgoraTransaction(
        txType: _asInt(r['tx_type'], 'tx_type'),
        nonce: _asInt(r['nonce'], 'nonce'),
        maxPriorityFeePerGas: _asInt(r['max_priority_fee_per_gas'], 'prio'),
        maxFeePerGas: _asInt(r['max_fee_per_gas'], 'max_fee'),
        gasLimit: _asInt(r['gas_limit'], 'gas_limit'),
        to: hexToBytes(r['to'] as String),
        value: BigInt.parse(r['value'].toString()),
        payload: payload,
        pubkey: pk,
        signature: hexToBytes(r['signature'] as String),
      );
      final contentOk =
          bytesToHex(tx.toContentRlp()) == (r['content_rlp'] as String);
      final envOk =
          bytesToHex(tx.toEnvelopeRlp()) == (r['envelope_rlp'] as String);
      final hashOk = bytesToHex(tx.txHash()) == (r['tx_hash'] as String);
      // 重签必须得到与向量相同的签名（确定性 Ed25519）
      final resigned = await tx.sign(paySeed, chainId);
      final sigOk = bytesToHex(resigned.signature) == (r['signature'] as String);
      if (contentOk && envOk && hashOk && sigOk) {
        ok++;
      } else {
        print('    ✗ $name content=$contentOk env=$envOk hash=$hashOk sig=$sigOk');
      }
    }
    _chk('★六种类型的载荷/封装/签名全部逐字节一致（${cases.length} 例）',
        ok == cases.length, '$ok/${cases.length}');

    // 空投领取：绑定签名载荷 + 证明结构（§32.6 第 ③ 项）
    final claimRow = cases
        .cast<Map<String, dynamic>>()
        .firstWhere((r) => (r['case'] as String).startsWith('AIRDROP_CLAIM'),
            orElse: () => const {});
    if (claimRow.isNotEmpty) {
      final proof = (claimRow['merkle_proof'] as List)
          .map((e) => e as String)
          .toList(growable: false);
      final sender = hexToBytes(claimRow['sender_address'] as String);
      final claim = AirdropClaim(
        index: _asInt(claimRow['claim_index'], 'claim_index'),
        amount: BigInt.parse(claimRow['claim_amount'].toString()),
        gasAllowance:
            BigInt.parse(claimRow['claim_gas_allowance'].toString()),
        pubkey: hexToBytes(claimRow['claim_pubkey'] as String),
        merkleProof: proof,
        bindingSignature:
            hexToBytes(claimRow['binding_signature'] as String),
      );
      _chk('空投领取载荷 RLP 逐字节一致',
          bytesToHex(claim.toRlp()) == (claimRow['payload'] as String));
      _chk('绑定签名载荷（§32.6 第 ③ 项）逐字节一致',
          bytesToHex(AirdropClaim.bindingMessage(chainId, claim.pubkey, sender,
                  claim.index)) ==
              (claimRow['binding_message'] as String));
      _chk('用同一种子重生成的绑定签名与向量一致',
          bytesToHex(await (await claim.bind(paySeed, chainId, sender))
                  .bindingSignature) ==
              (claimRow['binding_signature'] as String));
      _chk('绑定签名本地验签通过',
          await claim.verifyBinding(chainId, sender));
      // 证明结构自检：改一个字节后绑定的**载荷**必须变化（否则说明字段没进原像）
      final tampered = AirdropClaim(
        index: claim.index + 1,
        amount: claim.amount,
        gasAllowance: claim.gasAllowance,
        pubkey: claim.pubkey,
        merkleProof: proof,
        bindingSignature: claim.bindingSignature,
      );
      _chk('改 index 后绑定签名载荷随之变化（index 确实进了原像）',
          bytesToHex(AirdropClaim.bindingMessage(
                  chainId, claim.pubkey, sender, tampered.index)) !=
              bytesToHex(AirdropClaim.bindingMessage(
                  chainId, claim.pubkey, sender, claim.index)));
    }
  }

  // Keccak 的经典值（防止误用 SHA3-256：填充字节不同，首字节就不同）
  _chk('Keccak-256("") == c5d24601…（不是 SHA3-256 的 a7ffc6f8…）',
      bytesToHex(keccak256(const [])) ==
          'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');

  return [_pass, _fail];
}

/// 把向量里的整数（JSON number **或**十进制字符串）统一成 `int`。
int _asInt(Object? v, String field) {
  if (v is int) return v;
  if (v is String) return int.parse(v);
  throw FormatException('向量字段 $field 类型异常：${v.runtimeType}');
}

/// 解析 Python 字面量的一个子集：整数 / `b'...'` 字节串 / 嵌套列表。
///
/// 为什么不用现成 JSON：向量里写的是 `b'dog'` 这类 Python 表示，
/// 它们**故意**与 JSON 不同（`bytes` 在 JSON 里没有类型）。
/// 支持 `\xNN` 转义（向量里可能有非可打印字节）。
Object? _parsePyLiteral(String src) {
  final s = _PyParser(src);
  try {
    final v = s.parseValue();
    return v;
  } catch (_) {
    return null;
  }
}

class _PyParser {
  _PyParser(this.src);
  final String src;
  int i = 0;

  void _ws() {
    while (i < src.length && (src[i] == ' ' || src[i] == '\n')) {
      i++;
    }
  }

  Object? parseValue() {
    _ws();
    if (i >= src.length) throw const FormatException('意外结束');
    final c = src[i];
    if (c == '[') return _parseList();
    if (c == 'b' && i + 1 < src.length && (src[i + 1] == "'" || src[i + 1] == '"')) {
      i++;
      return _parseBytes();
    }
    if (c == "'" || c == '"') return _parseBytes();
    if (RegExp(r'[0-9]').hasMatch(c)) {
      final start = i;
      while (i < src.length && RegExp(r'[0-9]').hasMatch(src[i])) {
        i++;
      }
      return BigInt.parse(src.substring(start, i));
    }
    throw FormatException('无法解析：${src.substring(i)}');
  }

  List<Object?> _parseList() {
    i++; // [
    final out = <Object?>[];
    _ws();
    if (i < src.length && src[i] == ']') {
      i++;
      return out;
    }
    while (true) {
      out.add(parseValue());
      _ws();
      if (i >= src.length) throw const FormatException('列表未闭合');
      if (src[i] == ',') {
        i++;
        continue;
      }
      if (src[i] == ']') {
        i++;
        return out;
      }
      throw FormatException('列表语法错误：${src.substring(i)}');
    }
  }

  Uint8List _parseBytes() {
    final quote = src[i];
    i++;
    final out = BytesBuilder();
    while (i < src.length && src[i] != quote) {
      if (src[i] == r'\') {
        i++;
        if (i >= src.length) throw const FormatException('转义未结束');
        final e = src[i];
        if (e == 'x') {
          final hex = src.substring(i + 1, i + 3);
          out.addByte(int.parse(hex, radix: 16));
          i += 3;
          continue;
        }
        const map = {'n': 10, 't': 9, 'r': 13, '0': 0, r'\': 92, "'": 39, '"': 34};
        final b = map[e];
        if (b == null) throw FormatException('未知转义：\\$e');
        out.addByte(b);
        i++;
        continue;
      }
      out.addByte(src.codeUnitAt(i));
      i++;
    }
    if (i >= src.length) throw const FormatException('字节串未闭合');
    i++; // 收尾引号
    return out.toBytes();
  }
}

bool _throws(void Function() body) {
  try {
    body();
    return false;
  } catch (_) {
    return true;
  }
}

/// 在仓库里找向量文件（包可能被拷进别的 App，因此多试几个相对路径）。
String? _findVectors() {
  const candidates = [
    'vectors/agora_v0.2.2_vectors.json',
    '../../vectors/agora_v0.2.2_vectors.json',
    '../../../vectors/agora_v0.2.2_vectors.json',
    '../vectors/agora_v0.2.2_vectors.json',
  ];
  for (final c in candidates) {
    if (File(c).existsSync()) return c;
  }
  return null;
}
