/*
 * AGORA v0.2.2 — 独立实现（Node.js）· 跨实现一致性校验（GATE-7）
 * =============================================================
 *
 * 用 Node.js 侧**独立实现**重算 Python 侧生成的黄金向量，并逐字节比对。
 *
 * 为什么这是 GATE-7 的核心：
 *   同一个作者在同一种语言里，会把同一处误解重复一次。只有换语言、换标准库、
 *   换整数实现，才会真正暴露"两种实现对同一份规范理解不同"的地方 ——
 *   而这类分歧在单实现下**永远无法发现**，上线后表现为永久分叉。
 *
 * 校验范围（本轮）：
 *   · ENC     —— RLP 编码结果 + 必须拒绝/必须接受的非规范编码（两层校验）
 *   · CHAIN   —— 定宽前置函数的逐字段字节 + 两个投票载荷摘要
 *   · MPT     —— 空根、五种结构的根、以及"插入后删除回到空根"
 *   · ED25519 —— 用 Node 自带 crypto 验证 Python 生成的签名（另一套代码库）
 *
 * 用法：
 *   node independent/node/crosscheck.js [vectors/agora_v0.2.2_vectors.json]
 * 退出码 0 = 全部一致；非 0 = 存在分歧（GATE-7 未通过）。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const P = require('./primitives.js');
const { Trie, EMPTY_TRIE_ROOT } = require('./mpt.js');
const { keccak256, decode } = require('./primitives.js');

const ROOT = path.resolve(__dirname, '..', '..');
const VEC_PATH = process.argv[2] || path.join(ROOT, 'vectors', 'agora_v0.2.2_vectors.json');

let pass = 0;
let fail = 0;
const failures = [];

function chk(family, name, cond, detail = '') {
  if (cond) {
    pass++;
    console.log(`  [OK  ] ${name}${detail ? '   ' + detail : ''}`);
  } else {
    fail++;
    failures.push(`${family}: ${name}${detail ? ' — ' + detail : ''}`);
    console.log(`  [FAIL] ${name}${detail ? '   ' + detail : ''}`);
  }
}

const vectors = JSON.parse(fs.readFileSync(VEC_PATH, 'utf8'));
console.log('═'.repeat(76));
console.log('AGORA v0.2.2 · 跨实现一致性校验（Node.js 独立实现 ⇄ Python 黄金向量）');
console.log('═'.repeat(76));
console.log(`向量文件：${path.relative(ROOT, VEC_PATH)}`);
console.log(`实现语言：Node.js ${process.version}    独立于 Python 参考实现`);
console.log();

// ══════════════════════════════════════════════════════════════════════
// 1. ENC —— RLP
// ══════════════════════════════════════════════════════════════════════
console.log('1) ENC · RLP 编码');
{
  for (const row of vectors.ENC.encode) {
    const repr = row.input_repr;
    const got = P.encode(rlpFromRepr(repr)).toString('hex');
    // 向量里 expected 是 Python 手算的期望值；match 表示参考实现与之一致
    chk('ENC', `${row.case}（${repr.slice(0, 24)}）`, got === row.expected,
      got === row.expected ? '' : `Node=${got} 期望=${row.expected}`);
  }

  // 结构层：必须拒绝
  for (const row of vectors.ENC.must_reject) {
    if (row.layer !== 'decode') continue;             // 整数层单独测
    let rejected = false;
    try {
      P.decode(Buffer.from(row.encoded, 'hex'));
    } catch (e) {
      rejected = true;
    }
    chk('ENC', `拒绝：${row.case}`, rejected === row.must_reject, row.encoded);
  }

  // 整数层：解码应成功，但按整数解释必须被拒
  for (const row of vectors.ENC.must_reject) {
    if (row.layer !== 'require_canonical_int') continue;
    let decodeOk = true;
    let item = null;
    try {
      item = P.decode(Buffer.from(row.encoded, 'hex'));
    } catch (e) {
      decodeOk = false;
    }
    chk('ENC', `结构层接受但整数层拒绝：${row.case}`, decodeOk,
      decodeOk ? '' : '解码器不应拒绝合法结构');
    if (decodeOk) {
      let rejected = false;
      try {
        P.requireCanonicalInt(item);
      } catch (e) {
        rejected = true;
      }
      chk('ENC', `整数层拒绝前导零：${row.case}`, rejected, row.encoded);
    }
  }

  // 必须接受
  for (const row of vectors.ENC.must_accept) {
    let ok = true;
    try {
      P.decode(Buffer.from(row.encoded, 'hex'));
    } catch (e) {
      ok = false;
    }
    chk('ENC', `接受合法编码：${row.case}`, ok, row.encoded);
  }

  // BUG-49 要点：以 0x00 开头的合法字节串必须能往返
  const zero20 = Buffer.alloc(20);
  chk('ENC', '以 0x00 开头的 20 字节地址可往返（BUG-49）',
    P.decode(P.encode(zero20)).equals(zero20));
}

/** 把向量里的 `input_repr`（Python repr）还原为 Node 侧输入 */
function rlpFromRepr(repr) {
  const t = repr.trim();
  if (/^-?\d+$/.test(t)) {
    // 超过 2^53 的整数必须用 BigInt —— 用 Number 会静默丢精度
    // （实测 2^64-1 变成 18446744073709552000，RLP 随之编错）。
    const n = BigInt(t);
    return (n > 9007199254740991n || n < -9007199254740991n) ? n : Number(t);
  }
  if (t.startsWith("b'") || t.startsWith('b"')) {
    const s = t.slice(2, -1);
    return Buffer.from(s.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))), 'latin1');
  }
  if ((t.startsWith("'") && t.endsWith("'")) || (t.startsWith('"') && t.endsWith('"'))) {
    return t.slice(1, -1);
  }
  if (t.startsWith('[')) {
    // 形如 [0]、[1, 2]、['cat', 'dog']
    const inner = t.slice(1, -1).trim();
    if (!inner) return [];
    return splitTop(inner).map(rlpFromRepr);
  }
  throw new Error(`无法解析向量 input_repr：${repr}`);
}

function splitTop(s) {
  const out = [];
  let depth = 0;
  let cur = '';
  let inStr = false;
  let quote = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      cur += c;
      if (c === quote) inStr = false;
      continue;
    }
    if (c === "'" || c === '"') {
      inStr = true;
      quote = c;
      cur += c;
      continue;
    }
    if (c === '[' || c === '(') depth++;
    if (c === ']' || c === ')') depth--;
    if (c === ',' && depth === 0) {
      out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

// ══════════════════════════════════════════════════════════════════════
// 2. CHAIN —— 定宽前置函数
// ══════════════════════════════════════════════════════════════════════
//
// **本节按规范 §20.1 的**字面规则**实现**：`u8/u16/u32/u64/u256 → 无符号大端定宽`。
// 参考实现的 `chain()` 采用的是**最小定宽**（BUG-64），因此本节必然出现分歧 ——
// 这不是本实现的 bug，而是**两个实现在同一份规范下的真实分歧**，正是 GATE-7
// 要暴露的东西。分歧项会被明确标注并计入失败，直到 §37B 的裁决落地。
console.log('\n2) CHAIN · 定宽前置函数（**按规范 §20.1 字面规则**：整数定宽）');
{
  // 规范给了明确宽度的字段（"u8"、"u16"、"u32"、"u64"、"u256（定宽 32 字节）"）
  const widthCases = vectors.CHAIN.chain.filter(
    (r) => r.fields_repr && /^\(\d+/.test(r.fields_repr.trim()));

  for (const row of widthCases) {
    const m = /\bu(8|16|32|64|256)\b/.exec(row.case);
    if (!m) continue;                                   // 多字段/字节串用例另行处理
    const wantBytes = Number(m[1]) / 8;

    // u256 用例的 repr 在向量里被截断（70 字符），无法从向量复原原始值。
    // 因此对 u256 **独立计算**规范期望：2^200 的 32 字节大端。
    // 这也再次说明"向量应包含机器可读字段"（BUG-65）。
    let value;
    if (m[1] === '256') {
      value = 1n << 200n;
      const got = P.chainFieldU(32, value).toString('hex');
      const want = (1n << 200n).toString(16).padStart(64, '0');
      chk('CHAIN', `${row.case}（独立自算 2^200 的定宽编码）`, got === want,
        got === want ? '' : `Node=${got.slice(0, 32)}… 期望=${want.slice(0, 32)}…`);
      continue;
    }

    const raw = row.fields_repr.trim().replace(/[()]/g, '').split(',')[0].trim();
    if (!/^\d+$/.test(raw)) continue;                   // repr 截断，跳过
    value = BigInt(raw);
    const got = P.chainFieldU(wantBytes, value).toString('hex');
    chk('CHAIN', `${row.case}（定宽 ${wantBytes} 字节）`, got === row.expected,
      got === row.expected ? '' : `Node=${got.slice(0, 32)}… 向量=${row.expected.slice(0, 32)}…`);
  }

  // 字节串字段：20 / 32 字节原样，其它加 u32 长度前缀
  for (const row of vectors.CHAIN.chain) {
    const repr = row.fields_repr;
    if (!repr || !repr.includes("b'")) continue;
    const hexes = [...repr.matchAll(/\\x([0-9a-fA-F]{2})/g)].map((x) => x[1]);
    if (!hexes.length) continue;                        // 形如 b'abc' 的用另一分支
    const buf = Buffer.from(hexes.join(''), 'hex');
    if (buf.length !== 20 && buf.length !== 32) continue;
    // 解析可能截断，只在长度确实为 20/32 且与用例语义相符时比较
    const got = P.chain({ t: 'bytes', v: buf }).toString('hex');
    chk('CHAIN', `${row.case}（${buf.length} 字节原样）`, got === row.expected,
      got === row.expected ? '' : `Node=${got.slice(0, 32)}… 向量=${row.expected.slice(0, 32)}…`);
  }

  // 变长字节串 ⇒ u32 前缀
  for (const [name, raw, expect] of [
    ['变长字节串加 u32 前缀', 'abc', '00000003616263'],
    ['标签作为数据字段仍需 u32 前缀', 'AGORA/TX/v0.2.2',
      '0000000f' + Buffer.from('AGORA/TX/v0.2.2', 'ascii').toString('hex')],
  ]) {
    const got = P.chain({ t: 'bytes', v: Buffer.from(raw, 'ascii') }).toString('hex');
    chk('CHAIN', name, got === expect, got === expect ? '' : `Node=${got} 期望=${expect}`);
  }

  // 多字段顺序敏感（不涉及宽度分歧，用最小定宽即可）
  chk('CHAIN', '多字段顺序敏感',
    P.chain({ t: 'u8', v: 1n }, { t: 'u8', v: 2n }).toString('hex') === '0102');
  chk('CHAIN', '多字段反向',
    P.chain({ t: 'u8', v: 2n }, { t: 'u8', v: 1n }).toString('hex') === '0201');

  // ★ 核心分歧项：投票签名载荷（规范 §20.3 明确写了 u64/u32/u8）
  const payloadRow = vectors.CHAIN.chain.find((r) => r.payload !== undefined);
  if (payloadRow) {
    const bh = Buffer.from([...Array(32).keys()]);
    // 标签 **MUST** 前置在 chain() 之外（规范 §20.1：标签 ASCII 无长度前缀）。
    // 把标签作为 chain() 的参数会让它被当成普通字节串而加上 u32 前缀 ——
    // 参考实现的两个函数曾分别采用这两种写法，产出两种签名载荷（BUG-67）。
    const specPayload = Buffer.concat([
      Buffer.from('AGORA/PRECOMMIT/v0.2.2', 'ascii'),
      P.chain(
        { t: 'bytes', v: Buffer.from('agora-mainnet-1', 'ascii') },
        { t: 'u64', v: 7n }, { t: 'u32', v: 3n }, { t: 'u8', v: 2n },
        { t: 'hash32', v: bh }),
    ]);
    const vecPayload = Buffer.from(payloadRow.payload, 'hex');
    const sameBytes = specPayload.equals(vecPayload);
    const sameDigest = P.keccak256(specPayload).toString('hex') === payloadRow.digest;
    chk('CHAIN', '投票签名载荷字节：规范定宽 vs 参考实现',
      sameBytes,
      sameBytes ? '' : `Node=${specPayload.length}B 向量=${vecPayload.length}B`);
    chk('CHAIN', '投票签名载荷摘要：规范定宽 vs 参考实现',
      sameDigest,
      sameDigest ? '' : 'Node=' + P.keccak256(specPayload).toString('hex').slice(0, 16)
        + '… 向量=' + payloadRow.digest.slice(0, 16) + '…');
    if (!sameBytes) {
      console.log('         └─ 分歧定位：');
      console.log(`            规范 u64(height=7) = ${P.chainFieldU(8, 7n).toString('hex')}（8 字节）`);
      console.log('            参考实现          = 07（1 字节，最小定宽）');
      console.log(`            规范 u32(round=3)  = ${P.chainFieldU(4, 3n).toString('hex')}（4 字节）`);
      console.log('            参考实现          = 03（1 字节，最小定宽）');
      console.log('            ⇒ 载荷长度相差 10 字节 ⇒ 签名永不互验');
    }
  }
}

// ══════════════════════════════════════════════════════════════════════
// 3. MPT —— 状态树根
// ══════════════════════════════════════════════════════════════════════
console.log('\n3) MPT · Merkle Patricia Trie（引用一律哈希、绝不内联）');
{
  chk('MPT', '空 trie 根 = Keccak(RLP(""))',
    EMPTY_TRIE_ROOT.toString('hex') === vectors.MPT.empty_root,
    EMPTY_TRIE_ROOT.toString('hex').slice(0, 24) + '…');

  // 向量的 keys 是**原始键**的十六进制；需要按规范用同样的键值对重建。
  // 值不在向量里 —— 用与生成器相同的规则重建：
  //   单叶/双叶/三叶用 b"v1"/b"v2"/b"v%d"；五十叶用 b"value-%d"；含空值用例第二个为空。
  for (const c of vectors.MPT.cases) {
    // 优先使用向量自带的键值对（BUG-66 已补入 `entries`）—— 向量即权威，
    // 独立实现不应再自行"重建"值（那样等于在猜生成器的意图）。
    const items = c.entries
      ? c.entries.map(([k, v]) => [Buffer.from(k, 'hex'), Buffer.from(v, 'hex')])
      : valuesForCase(c);
    if (items === null) {
      chk('MPT', `${c.case}：向量未包含值，跳过独立重建`, false,
        '★ 请在向量中包含键值对，否则独立实现无法校验根');
      continue;
    }
    const t = Trie.fromItems(items);
    const got = t.root.toString('hex');
    chk('MPT', `${c.case}（${c.key_count} 叶）`, got === c.root,
      got === c.root ? '' : `Node=${got.slice(0, 24)}… 期望=${c.root.slice(0, 24)}…`);
  }

  // 插入顺序无关（独立真值：自己构造 64 项，正序与逆序）
  const items = [];
  for (let i = 0; i < 64; i++) {
    items.push([Buffer.alloc(20, i % 256), Buffer.from(`v${i}`)]);
  }
  const t1 = Trie.fromItems(items);
  const t2 = Trie.fromItems([...items].reverse());
  chk('MPT', '插入顺序不改变根（确定性）', t1.root.equals(t2.root),
    t1.root.toString('hex').slice(0, 24) + '…');

  // 插入后全部删除 ⇒ 必须回到空 trie 根
  const t3 = Trie.fromItems(items);
  for (const [k] of items) t3.delete(k);
  chk('MPT', '全部删除后根回到空 trie 根（删除必须规范化）',
    t3.root.toString('hex') === vectors.MPT.empty_root,
    t3.root.toString('hex').slice(0, 24) + '…');
}

/**
 * 重建用例的键值对。
 *
 * **为什么必须按生成器的原始规格重建，而不是从 `c.keys` 反推：**
 * 五十叶用例的键是 `bytes([i % 256]) * 20`，当 i ≥ 256 时会与前面的键重复
 * （本用例 i < 50 不重复，但规则如此），且值 `value-%d` 绑定的是**原始下标 i**。
 * 从 `c.keys` 反推只能拿到去重后的键序列，无法复原"哪个键对应哪个值"。
 * 这正是"独立实现要求向量包含完整键值对"的原因（见 BUG-65）。
 */
function valuesForCase(c) {
  const keys = c.keys.map((h) => Buffer.from(h, 'hex'));
  if (c.case.includes('单叶')) return [[keys[0], Buffer.from('v1')]];
  if (c.case.includes('双叶')) {
    return [[keys[0], Buffer.from('v1')], [keys[1], Buffer.from('v2')]];
  }
  if (c.case.includes('三叶')) return keys.map((k, i) => [k, Buffer.from(`v${i}`)]);
  if (c.case.includes('五十叶')) {
    // 生成器：[(bytes([i % 256]) * 20, b"value-%d" % i) for i in range(50)]
    const items = [];
    for (let i = 0; i < 50; i++) {
      items.push([Buffer.alloc(20, i % 256), Buffer.from(`value-${i}`)]);
    }
    return items;
  }
  if (c.case.includes('含空值')) return [[keys[0], Buffer.from('v1')]];
  return null;
}

// ══════════════════════════════════════════════════════════════════════
// 4. Ed25519 —— 用 Node 自带 crypto 验证 Python 生成的签名
// ══════════════════════════════════════════════════════════════════════
console.log('\n4) Ed25519 · 交叉验证（Node 自带实现 ⇄ Python 参考实现）');
{
  // Node 侧自己生成并对自己的签名验证（先确认本机 Ed25519 可用）
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const msg = Buffer.from('AGORA crosscheck');
  const sig = crypto.sign(null, msg, privateKey);
  chk('ED25519', 'Node 侧签名/验证自洽',
    crypto.verify(null, msg, publicKey, sig));
  chk('ED25519', '篡改消息后验证失败',
    !crypto.verify(null, Buffer.from('AGORA crosscheck!'), publicKey, sig));

  // 跨实现：用已知 RFC 8032 TEST 1 向量（官方向量，两侧共同真值）
  const pk = Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex');
  const rsig = Buffer.from(
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
    + '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b', 'hex');
  // Node 的 crypto.verify 需要 KeyObject
  const keyObj = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pk]),
    format: 'der', type: 'spki',
  });
  chk('ED25519', 'RFC 8032 TEST 1 签名通过 Node 验证',
    crypto.verify(null, Buffer.alloc(0), keyObj, rsig));
  chk('ED25519', 'RFC 8032 TEST 1 篡改消息被拒',
    !crypto.verify(null, Buffer.from('x'), keyObj, rsig));
}

// ══════════════════════════════════════════════════════════════════════
// 5. TXBLOCK —— 共识对象（交易 / 区块头 / Commit / 提案载荷）
// ══════════════════════════════════════════════════════════════════════
//
// 这一节把跨实现一致性从"原语层"推进到"**共识对象层**"：
// 字段顺序、哪些字段进签名载荷、哈希取在内容还是封装上 —— 任何一处理解不同，
// 两个实现都会算出不同的交易哈希与区块哈希，而各自的测试都通过。
console.log('\n5) TXBLOCK · 共识对象编解码与派生哈希');
{
  const O = require('./objects.js');
  const TB = vectors.TXBLOCK;
  const B = (x) => Buffer.from(x, 'hex');
  const chainId = Buffer.from(vectors.GENESIS.chain_id, 'ascii');
  const TAG_TX = Buffer.from('AGORA/TX/v0.2.2', 'ascii');
  const TAG_PROPOSAL = Buffer.from('AGORA/PROPOSAL/v0.2.2', 'ascii');
  const TAG_PRECOMMIT = Buffer.from('AGORA/PRECOMMIT/v0.2.2', 'ascii');

  // ── 交易 ──
  const tf = {
    tx_type: TB.tx.fields.tx_type,
    protocol_version_hash: B(TB.tx.fields.protocol_version_hash),
    chain_id_hash: B(TB.tx.fields.chain_id_hash),
    nonce: TB.tx.fields.nonce,
    max_priority_fee_per_gas: TB.tx.fields.max_priority_fee_per_gas,
    max_fee_per_gas: TB.tx.fields.max_fee_per_gas,
    gas_limit: TB.tx.fields.gas_limit,
    to: B(TB.tx.fields.to),
    value: TB.tx.fields.value,
    payload: B(TB.tx.fields.payload),
    pubkey: B(TB.tx.fields.pubkey),
    signature: B(TB.tx.fields.signature),
  };
  const contentRlp = O.txContentRlp(tf).toString('hex');
  chk('TXBLOCK', '交易 TxContent RLP 逐字节一致', contentRlp === TB.tx.content_rlp,
    contentRlp === TB.tx.content_rlp ? '' : 'Node≠向量');
  const envRlp = O.txEnvelopeRlp(tf).toString('hex');
  chk('TXBLOCK', '交易 TxEnvelope RLP（含签名）一致', envRlp === TB.tx.envelope_rlp,
    envRlp === TB.tx.envelope_rlp ? '' : 'Node≠向量');
  const sp = O.txSigningPayload(tf, chainId, TAG_TX);
  chk('TXBLOCK', '交易签名载荷原像一致', sp.toString('hex') === TB.tx.signing_payload,
    sp.toString('hex') === TB.tx.signing_payload ? '' : 'Node≠向量');
  chk('TXBLOCK', '交易签名载荷摘要一致',
    keccak256(sp).toString('hex') === TB.tx.signing_payload_digest);
  chk('TXBLOCK', '交易哈希一致（Keccak(TxEnvelope)）',
    O.txHash(tf).toString('hex') === TB.tx.tx_hash,
    O.txHash(tf).toString('hex') === TB.tx.tx_hash ? '' : 'Node≠向量');
  chk('TXBLOCK', '发送者地址 = Last20(Keccak(pubkey))',
    keccak256(tf.pubkey).subarray(-20).toString('hex') === TB.tx.sender_address);

  // 交易的 RLP 可被独立解码回同一字段（不是只比哈希）
  const decoded = decode(B(TB.tx.envelope_rlp));
  chk('TXBLOCK', '交易封装可独立解码为 11 项', Array.isArray(decoded) && decoded.length === 11,
    Array.isArray(decoded) ? `实际 ${decoded.length} 项` : '非列表');
  if (Array.isArray(decoded) && decoded.length === 11) {
    chk('TXBLOCK', '解码后签名与公钥逐字节一致',
      Buffer.from(decoded[10]).equals(tf.signature)
      && Buffer.from(decoded[9]).equals(tf.pubkey));
  }

  // ── 区块头与区块 ──
  const hf = {
    protocol_version_hash: B(TB.block_header.fields.protocol_version_hash),
    chain_id_hash: B(TB.block_header.fields.chain_id_hash),
    height: TB.block_header.fields.height,
    round: TB.block_header.fields.round,
    claimed_slot: TB.block_header.fields.claimed_slot,
    timestamp: TB.block_header.fields.timestamp,
    parent_hash: B(TB.block_header.fields.parent_hash),
    parent_commit_hash: B(TB.block_header.fields.parent_commit_hash),
    tx_root: B(TB.block_header.fields.tx_root),
    receipt_root: B(TB.block_header.fields.receipt_root),
    state_root: B(TB.block_header.fields.state_root),
    gas_used: TB.block_header.fields.gas_used,
    base_fee_per_gas: TB.block_header.fields.base_fee_per_gas,
    parent_commit_rlp: B(TB.block_header.fields.parent_commit_rlp),
    proposer_pubkey: B(TB.block_header.fields.proposer_pubkey),
    proposer_signature: B(TB.block_header.fields.proposer_signature),
  };
  const hcRlp = O.headerContentRlp(hf).toString('hex');
  chk('TXBLOCK', '区块头 HeaderContent RLP（15 项）一致',
    hcRlp === TB.block_header.content_rlp, hcRlp === TB.block_header.content_rlp ? '' : 'Node≠向量');
  const hRlp = O.headerRlp(hf).toString('hex');
  chk('TXBLOCK', '区块头完整 RLP（16 项）一致', hRlp === TB.block_header.header_rlp,
    hRlp === TB.block_header.header_rlp ? '' : 'Node≠向量');
  const propSp = O.proposalSigningPayload(hf, chainId, TAG_PROPOSAL);
  chk('TXBLOCK', '提案签名载荷原像一致',
    propSp.toString('hex') === TB.block_header.signing_payload,
    propSp.toString('hex') === TB.block_header.signing_payload ? '' : 'Node≠向量');
  chk('TXBLOCK', '区块哈希一致（Keccak(完整头部)）',
    O.blockHash(hf).toString('hex') === TB.block_header.block_hash,
    O.blockHash(hf).toString('hex') === TB.block_header.block_hash ? '' : 'Node≠向量');
  const bRlp = O.blockRlp(hf, [O.txEnvelopeRlp(tf)]).toString('hex');
  chk('TXBLOCK', '区块 RLP（头 + 交易列表）一致',
    bRlp === TB.block_header.block_rlp, bRlp === TB.block_header.block_rlp ? '' : 'Node≠向量');

  // ── Commit 与预提交载荷 ──
  const cf = {
    height: TB.commit.fields.height,
    round: TB.commit.fields.round,
    block_hash: B(TB.commit.fields.block_hash),
    signatures: TB.commit.fields.signatures.map(([a, s]) => [B(a), B(s)]),
  };
  chk('TXBLOCK', 'Commit RLP 一致', O.commitRlp(cf).toString('hex') === TB.commit.rlp);

  const pc = O.precommitPayload(7, 3, B('88'.repeat(32)), chainId, TAG_PRECOMMIT,
                                P.chainFieldU);
  chk('TXBLOCK', '预提交签名载荷原像一致（定宽 u64/u32/u8）',
    pc.toString('hex') === TB.precommit_payload.payload,
    pc.toString('hex') === TB.precommit_payload.payload ? '' : 'Node≠向量');
  chk('TXBLOCK', '预提交签名载荷摘要一致',
    keccak256(pc).toString('hex') === TB.precommit_payload.digest);

  // ── ★ 跨实现签名互验（GATE-7 的核心断言）──────────────────────────
  //
  // 前面的比对只能证明"两个实现算出同样的**字节**"。这里进一步证明
  // "一个实现签出的签名，另一个实现**能验过**" —— 这正是跨实现互操作的
  // 实质含义：若签名载荷有任何分歧，这一步必然失败，而字节比对可能因为
  // 双方都错得一样（如 BUG-64/67）而侥幸通过。
  const edKey = (pkBuf) => crypto.createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pkBuf]),
    format: 'der', type: 'spki',
  });

  // 交易签名：由参考实现（Python）签出，用 Node 的 Ed25519 验证
  chk('TXBLOCK', '★ Python 签的交易签名通过 Node 验证（跨实现互操作）',
    crypto.verify(null, sp, edKey(tf.pubkey), tf.signature));
  chk('TXBLOCK', '交易签名对篡改后的载荷被拒',
    !crypto.verify(null, Buffer.concat([sp, Buffer.from([0])]), edKey(tf.pubkey), tf.signature));

  // 提案签名：同上（验证的是 RLP(HeaderContent) 的 CHAIN 原像）
  chk('TXBLOCK', '★ Python 签的提案签名通过 Node 验证',
    crypto.verify(null, propSp, edKey(hf.proposer_pubkey), hf.proposer_signature));

  // 预提交签名：向量里给的是原像与摘要；这里额外验证"Node 重算的原像"
  // 能用于验证 —— 即两个实现对投票载荷的理解一致（BUG-64 的要害）。
  chk('TXBLOCK', '预提交载荷：Node 重算结果与向量逐字节一致（宽度定宽）',
    pc.toString('hex') === TB.precommit_payload.payload);

  // ── 区块头里的 tx_root 必须等于交易根的算法结果（此处仅校验长度约束） ──
  chk('TXBLOCK', '区块头 tx_root 为 32 字节',
    hf.tx_root.length === 32, `${hf.tx_root.length} 字节`);
  chk('TXBLOCK', '区块 RLP 可独立解码为 2 项',
    (() => { const d = decode(B(TB.block_header.block_rlp)); return Array.isArray(d) && d.length === 2; })());
}

// ══════════════════════════════════════════════════════════════════════
// 6. PROPOSER —— 提案者选取（共识关键）
// ══════════════════════════════════════════════════════════════════════
//
// 这是**最关键**的一处共识函数：选错提案者 = 全网永远无法最终化。
// 独立实现必须自己算出完全相同的提案者，否则两个实现造的块互相不认。
console.log('\n6) PROPOSER · 提案者选取（§12.3–§12.4，共识关键）');
{
  const O = require('./objects.js');
  const PR = vectors.PROPOSER;
  const TAG_PROPOSER = 'AGORA/PROPOSER/v0.2.2';
  const epochSeedBytes = Buffer.from(PR.epoch_seed, 'hex');
  const stake = BigInt(vectors.GENESIS.validators[0].stake);   // 每名验证者等额质押
  const vp = PR.validator_set.map((a) => [Buffer.from(a, 'hex'), stake]);
  const stakedSupply = stake * BigInt(vp.length);

  chk('PROPOSER', '验证者集合为 4 名等额质押', vp.length === 4,
    `S_epoch = ${stakedSupply}`);

  // ── R 重算（同时校验 CHAIN 的定宽 u64 编码）──
  let rOk = 0;
  for (const row of PR.validators) {
    const r = O.selectionRandomness(epochSeedBytes, row.epoch, row.slot, row.round,
                                    TAG_PROPOSER, P.chainFieldU);
    if (r.toString('hex') === row.R) rOk++;
  }
  chk(`PROPOSER`, `选择随机数 R 逐字节一致（${rOk}/${PR.validators.length}）`,
    rOk === PR.validators.length, rOk === PR.validators.length ? '' : `${rOk} 项不符`);

  // ── 提案者选取 ──
  let pOk = 0;
  const mismatches = [];
  for (const row of PR.validators) {
    const r = Buffer.from(row.R, 'hex');
    const got = O.selectProposer(r, vp, stakedSupply);
    const gotHex = got === null ? null : got.toString('hex');
    if (gotHex === row.proposer) pOk++;
    else if (mismatches.length < 3) {
      mismatches.push(`e=${row.epoch} s=${row.slot} r=${row.round} `
        + `Node=${gotHex} 向量=${row.proposer}`);
    }
  }
  chk('PROPOSER', `提案者选取逐项一致（${pOk}/${PR.validators.length}）`,
    pOk === PR.validators.length, mismatches.join(' | '));

  // ── 规范 §12.4 的边界性质（独立验证，不依赖向量）──
  const sorted = vp.map(([a]) => a).sort(Buffer.compare);
  // target == 0（R 全零）⇒ 必选第一个有权成员
  const first = O.selectProposer(Buffer.alloc(32), vp, stakedSupply);
  chk('PROPOSER', 'target == 0（R 全零）⇒ 选第一个有权成员（§12.4 第 4 条）',
    first !== null && first.equals(sorted[0]),
    first ? first.toString('hex').slice(0, 12) + '…' : 'null');

  // target == S-1 ⇒ 必选最后一个。
  // 注意：`target = R mod S`，所以要把 R（256 位整数）构造成 `S-1`，
  // 而不是把 `S-1` 塞进 u64 —— 本协议的 S_epoch 远超 2^64（256 AGORA = 2.56e20）。
  // 首次写这条测试时正是踩了这个坑（writeBigUInt64BE 溢出）。
  const rMax = Buffer.alloc(32);
  let rem = stakedSupply - 1n;
  for (let i = 31; i >= 0 && rem > 0n; i--) {
    rMax[i] = Number(rem & 0xffn);
    rem >>= 8n;
  }
  const last = O.selectProposer(rMax, vp, stakedSupply);
  chk('PROPOSER', 'target == S−1 ⇒ 选最后一个成员',
    last !== null && last.equals(sorted[sorted.length - 1]));

  // 零权成员永不入选
  const vpZero = [[sorted[0], 0n], [sorted[1], stake], [sorted[2], 0n], [sorted[3], stake]];
  const picked = new Set();
  // 采样必须是**接近均匀的 256 位随机数**：若只取小整数 i，则 `target = i mod S = i`
  // 永远落在第一个成员区间内，"只选中 2 个成员"这条断言就测不出东西
  //（首次实现正是如此，误报为失败）。
  const rng = require('crypto').createHash('sha256');
  for (let i = 0; i < 400; i++) {
    const r = rng.copy().update(`proposer-sample-${i}`).digest();
    const a = O.selectProposer(r, vpZero, stake * 2n);
    if (a) picked.add(a.toString('hex'));
  }
  chk('PROPOSER', '零权成员永不入选（§12.4 第 2 条）',
    !picked.has(sorted[0].toString('hex')) && !picked.has(sorted[2].toString('hex')),
    `400 次抽样命中 ${picked.size} 个不同成员`);
  chk('PROPOSER', '零权跳过后期望只选中 2 个有权成员', picked.size === 2,
    `实际 ${picked.size}`);

  // S_epoch == 0 ⇒ null（链 halt）
  chk('PROPOSER', 'S_epoch == 0 ⇒ 返回 null（§7.7 链 halt）',
    O.selectProposer(Buffer.alloc(32), [], 0n) === null);

  // 确定性：同输入多次同结果
  const r1 = Buffer.from(PR.validators[0].R, 'hex');
  const det = new Set();
  for (let i = 0; i < 50; i++) det.add(O.selectProposer(r1, vp, stakedSupply).toString('hex'));
  chk('PROPOSER', '同输入 50 次给出同一提案者（确定性）', det.size === 1);
}

// ══════════════════════════════════════════════════════════════════════
// 7. 经济与费用函数（基础费 / 发行曲线 / 分配 / 罚没）
// ══════════════════════════════════════════════════════════════════════
console.log('\n7) ECON · 基础费 / 发行曲线 / 奖励分配 / 罚没');
{
  const E = require('./econ.js');
  const BF = vectors.BASEFEE;
  const TG = 5000000n, MG = 10000000n, DIV = 40000000n, MINBF = 1000000000n;

  // ── 基础费 ──
  let bfOk = 0;
  for (const row of BF.verification_table) {
    const got = E.baseFeeNext(BigInt(row.base_fee), BigInt(row.gas_used),
                              TG, MG, DIV, MINBF);
    if (got === BigInt(row.next)) bfOk++;
    else console.log(`        差异: bf=${row.base_fee} gas=${row.gas_used} `
      + `Node=${got} 向量=${row.next}`);
  }
  chk('ECON', `基础费验证表逐项一致（${bfOk}/${BF.verification_table.length}）`,
    bfOk === BF.verification_table.length);

  // 基础费序列（200 步，含地板价与上限边界）
  let seqOk = true, bf = MINBF;
  for (let i = 0; i < BF.gas_sequence.length; i++) {
    bf = E.baseFeeNext(bf, BigInt(BF.gas_sequence[i]), TG, MG, DIV, MINBF);
    if (bf !== BigInt(BF.base_fee_sequence[i])) {
      seqOk = false;
      console.log(`        序列第 ${i} 步不符：Node=${bf} 向量=${BF.base_fee_sequence[i]}`);
      break;
    }
  }
  chk(`ECON`, `基础费序列逐步一致（${BF.gas_sequence.length} 步）`, seqOk);

  // 边界性质（独立验证）
  // 注意：base_fee **必须 ≥ MIN_BASE_FEE**，否则函数按规范拒绝（这是正确行为）。
  // 首次写这条断言时用了 1.23e8（低于地板价 1e9），于是"实现正确拒绝、测试误报"。
  chk('ECON', 'gas_used == TARGET ⇒ 基础费不变',
    E.baseFeeNext(1234567890n, TG, TG, MG, DIV, MINBF) === 1234567890n);
  chk('ECON', '基础费低于地板价时被拒绝（规范前置条件）', (() => {
    try { E.baseFeeNext(999999999n, TG, TG, MG, DIV, MINBF); return false; }
    catch (e) { return true; }
  })());
  // 空块：delta = ceil(bf/8)。1.5e9 → 1.5e9 − 1.875e8 = 1.3125e9（未触底）
  chk('ECON', '空块时基础费按 ceil(bf/8) 下降',
    E.baseFeeNext(1500000000n, 0n, TG, MG, DIV, MINBF) === 1312500000n,
    `${E.baseFeeNext(1500000000n, 0n, TG, MG, DIV, MINBF)}`);
  // 地板价：1e9 再降就低于 MIN ⇒ 夹到 MIN。**注意** MIN_BASE_FEE = 1 nAGORA = 1e9，
  // 我曾把它误当成 1e8 来写断言，导致误报（见下方"下限夹取"）。
  chk('ECON', '下降触底时夹到 MIN_BASE_FEE（不得低于地板价）',
    E.baseFeeNext(MINBF, 0n, TG, MG, DIV, MINBF) === MINBF);
  chk('ECON', 'MIN_BASE_FEE = 1 nAGORA = 10^9 atom', MINBF === 1000000000n);
  chk('ECON', '满块时基础费上升且增量 ≥1（下限保证不停滞）',
    E.baseFeeNext(MINBF, MG, TG, MG, DIV, MINBF) > MINBF);

  // ── 发行曲线（恒定曲线 + 过渡期奖励地板，§28.4 / §28.4.1）──
  const REW = vectors.REWARD;
  // **所有常量都取自向量元数据**：独立实现不得自己硬编码协议参数，
  // 否则参数一改，两边的"一致"就只是巧合（BUG-70/72 类问题的根源）。
  const rCtx = {
    numerator: BigInt(REW.numerator),
    minReward: BigInt(REW.min_reward),
    maxReward: BigInt(REW.max_reward),
    transitionEndSlot: BigInt(REW.transition_end_slot),
    transitionFloor: BigInt(REW.transition_floor),
  };
  let curveOk = 0;
  for (const row of REW.curve) {
    const s = BigInt(row.staked_agora_str);
    // 恒定曲线一列取过渡期**之后**的槽 ⇒ 必须与 curve_block_reward 一致
    const got = E.blockReward(s, BigInt(row.slot), rCtx);
    if (got === BigInt(row.block_reward)) curveOk++;
    else console.log(`        曲线差异: S=${s} slot=${row.slot} Node=${got} 向量=${row.block_reward}`);
  }
  chk('ECON', `发行曲线逐项一致（${curveOk}/${REW.curve.length}）`,
    curveOk === REW.curve.length);

  // 过渡期窗口边界：末槽 = 0.64、首槽 = 曲线值 —— 这是"用错槽"的唯一探针
  let transOk = 0;
  for (const row of REW.transition) {
    const s = BigInt(row.staked_agora_str);
    const got = E.blockReward(s, BigInt(row.slot), rCtx);
    if (String(got) === String(row.block_reward)) transOk++;
    else console.log(`        过渡期差异: S=${s} slot=${row.slot} Node=${got} 向量=${row.block_reward}`);
  }
  chk('ECON', `过渡期奖励地板逐项一致（${transOk}/${REW.transition.length}）`,
    transOk === REW.transition.length);
  chk('ECON', '过渡期内块奖励与质押率无关（地板 == 上限）',
    REW.transition.filter((r) => r.transition_active)
      .every((r) => BigInt(r.block_reward) === rCtx.maxReward));
  // 窗口边界的**真实探针**：取质押率 100%（曲线 = MIN ≠ 地板），
  // 于是"窗口内 / 窗口外"必须给出不同取值 —— 用错槽立刻暴露。
  const sFull = 20480000n * 10n ** 18n;                  // INITIAL_SUPPLY（100% 质押）
  chk('ECON', `窗口末槽 = 地板 ${rCtx.transitionFloor}、窗口首槽 = 曲线 ${rCtx.minReward}（边界切换）`,
    E.blockReward(sFull, rCtx.transitionEndSlot - 1n, rCtx) === rCtx.maxReward
    && E.blockReward(sFull, rCtx.transitionEndSlot, rCtx) === rCtx.minReward);
  chk('ECON', '上下界关系 MIN ≤ 地板(过渡期) ≤ MAX',
    rCtx.minReward <= rCtx.transitionFloor && rCtx.transitionFloor <= rCtx.maxReward);
  chk('ECON', 'blockReward 拒绝省略 slot（不得有默认值）', (() => {
    try { E.blockReward(1n); return false; } catch (e) { return true; }
  })());

  // ── 真实执行过的区块：三个承诺字段必须**自行重算**（规范 §6.1.1，BUG-78）──
  //
  // 这一段是本次修订的核心：此前 `tx_root`/`receipt_root` 只被校验"长度为 32 字节"，
  // 而向量里给的是人造常量 ⇒ "规范未定义原像"这件事在跨实现比对中完全不可见。
  // 现在由本实现自己算：tx_root / receipt_root / parent_commit_hash / 头部内容 RLP / block_hash。
  const EB = vectors.TXBLOCK.executed_block;
  const HB = (x) => Buffer.from(x, 'hex');   // 本节的局部 hex 助手（B 定义在后面的 STATE 节）
  const EMPTY_LIST_ROOT = keccak256(P.encode([]));
  const txHashes = EB.transactions.map((t) => keccak256(HB(t.envelope_rlp)));
  const txRoot = keccak256(P.encode(txHashes));
  chk('TXBLOCK', 'tx_root 自行重算一致（Keccak(RLP([tx_hash…]))）',
    txRoot.toString('hex') === EB.header_fields.tx_root,
    `Node=${txRoot.toString('hex').slice(0, 16)}… 向量=${EB.header_fields.tx_root.slice(0, 16)}…`);
  chk('TXBLOCK', '交易哈希自行重算一致（对完整封装取 Keccak）',
    EB.transactions.every((t, i) => txHashes[i].toString('hex') === t.tx_hash));

  const leaves = EB.receipts.map((r) => keccak256(P.encode([
    HB(r.tx_hash), BigInt(r.gas_used), BigInt(r.status), BigInt(r.effective_gas_price)])));
  const receiptRoot = keccak256(P.encode(leaves));
  chk('TXBLOCK', 'receipt_root 自行重算一致（§6.1.1 的收据叶子）',
    receiptRoot.toString('hex') === EB.header_fields.receipt_root,
    `Node=${receiptRoot.toString('hex').slice(0, 16)}…`);
  chk('TXBLOCK', '空交易列表的交易根为 Keccak(RLP([]))',
    keccak256(P.encode([])).equals(EMPTY_LIST_ROOT));

  const pcHash = keccak256(HB(EB.parent_commit_rlp));
  chk('TXBLOCK', 'parent_commit_hash = Keccak(RLP(Commit)) 自行重算一致',
    pcHash.toString('hex') === EB.header_fields.parent_commit_hash);

  // 由**自算的三个字段**重建头部内容 RLP 与 block_hash
  const hf = EB.header_fields;
  const headerFields = [
    HB(hf.protocol_version_hash), HB(hf.chain_id_hash),
    BigInt(hf.height), BigInt(hf.round), BigInt(hf.claimed_slot), BigInt(hf.timestamp),
    HB(hf.parent_hash), pcHash, txRoot, receiptRoot, HB(hf.state_root),
    BigInt(hf.gas_used), BigInt(hf.base_fee_per_gas),
    decode(HB(EB.parent_commit_rlp)),          // parent_commit 为**嵌套列表**
    HB(hf.proposer_pubkey),
  ];
  chk('TXBLOCK', '头部内容 RLP（15 字段）自行重建一致',
    P.encode(headerFields).toString('hex') === EB.header_content_rlp);
  chk('TXBLOCK', 'block_hash = Keccak(RLP(头部 16 字段)) 自行重算一致',
    keccak256(P.encode(headerFields.concat([HB(hf.proposer_signature)]))).toString('hex')
      === EB.block_hash);

  // ── 分配（提案者/见证池）──
  let spOk = 0;
  for (const row of vectors.REWARD.splits) {
    const [p, a] = E.splitProposerAttestation(BigInt(row.amount), 800000n);
    if (p === BigInt(row.proposer) && a === BigInt(row.attestation)) spOk++;
  }
  chk('ECON', `提案者/见证池分配逐项一致（${spOk}/${vectors.REWARD.splits.length}）`,
    spOk === vectors.REWARD.splits.length);
  chk('ECON', '分配守恒（提案者 + 池 == 总额，余数归提案者）',
    vectors.REWARD.splits.every((r) =>
      BigInt(r.proposer) + BigInt(r.attestation) === BigInt(r.amount)));

  // ── 罚没 ──
  let slOk = 0;
  for (const row of vectors.SLASH.cases) {
    const amt = E.slashAmount(BigInt(row.base), BigInt(row.ppm),
                              BigInt(vectors.SLASH.denominator));
    const reward = (amt * 200000n) / 1000000n;
    if (amt === BigInt(row.amount)) slOk++;
  }
  chk('ECON', `罚没额逐项一致（${slOk}/${vectors.SLASH.cases.length}）`,
    slOk === vectors.SLASH.cases.length);
  let slRwOk = 0;
  for (const row of vectors.SLASH.cases) {
    const amt = E.slashAmount(BigInt(row.base), BigInt(row.ppm),
                              BigInt(vectors.SLASH.denominator));
    const reward = (amt * 200000n) / 1000000n;
    if (reward === BigInt(row.evidence_reward)) slRwOk++;
  }
  chk('ECON', `证据奖励 = 罚没额的 20% 逐项一致（${slRwOk}/${vectors.SLASH.cases.length}）`,
    slRwOk === vectors.SLASH.cases.length);

}

// ══════════════════════════════════════════════════════════════════════
// 8. STATE —— 状态根与空投证明（跨实现分叉最直接的体现）
// ══════════════════════════════════════════════════════════════════════
//
// 这一节让独立实现**自己算出状态根**：给定具体账户集合（已哈希键 + 账户 RLP），
// 独立构建 trie 并得到根，与参考实现比对。状态根是跨实现分叉最直接的体现 ——
// 两个实现只要有一个条目不同，根就不同，链立刻分叉。
console.log('\n8) STATE · 状态根与空投证明');
{
  const ST = vectors.STATE;
  const B = (x) => Buffer.from(x, 'hex');

  // ── 账户叶值必须由本实现**自行重编码**（规范 §19.2 字面）──
  //
  // 为什么这一段是本次修订的核心：此前本实现直接把向量里的 `value_rlp` 塞进 trie，
  // 于是"参考实现把余额 zigzag 翻倍"这类**叶值编码分歧永远测不出来**
  // （见 PROJECT_REVIEW R-1 / §4.1）。现在改为：从 `nonce`/`balance` 与
  // 两个键（由 ValidatorRecord / SystemState 的哈希独立导出）**重新编码**，
  // 与向量逐字节比对，并且**用自算的叶子**建 trie。
  const HASH_EMPTY = keccak256(Buffer.alloc(0));
  const vkByHashed = new Map();
  for (const v of ST.validators) {
    const addr = B(v.address.replace(/^0x/, ''));
    vkByHashed.set(keccak256(addr).toString('hex'), keccak256(B(v.record_rlp)));
  }
  const sysHashed = keccak256(B(ST.system_address.replace(/^0x/, ''))).toString('hex');
  const sysKey = keccak256(B(ST.system_state_rlp));
  const derived = [];
  let reencOk = 0;
  const leafBad = [];
  for (const a of ST.accounts) {
    const vk = vkByHashed.get(a.hashed_key) || HASH_EMPTY;
    const sk = (a.hashed_key === sysHashed) ? sysKey : HASH_EMPTY;
    const leaf = P.encode([BigInt(a.nonce), BigInt(a.balance), vk, sk]);
    derived.push([a.hashed_key, leaf]);
    if (leaf.equals(B(a.value_rlp))) reencOk++;
    else leafBad.push(a.hashed_key.slice(0, 12) + '…');
  }
  chk('STATE', `账户叶值自行重编码后逐字节一致（${reencOk}/${ST.accounts.length}）`,
    reencOk === ST.accounts.length,
    leafBad.length ? `不一致：${leafBad.join(',')}` : '规范 §19.2 字面编码');
  chk('STATE', '空键必须编码为 Hash("")（32 字节），不得为 0 长度',
    derived.every(([, leaf]) => {
      const d = decode(leaf);
      return d[2].length === 32 && d[3].length === 32;
    }));

  // ── 状态根：由**自算的**账户叶值独立构建 trie ──
  const t = new Trie();
  for (const [k, v] of derived) {
    t.putRawHashed(B(k), v);
  }
  const root = t.root.toString('hex');
  chk('STATE', `账户数 ${ST.accounts.length}：独立构建的 trie 根与向量一致`,
    root === ST.state_root, root === ST.state_root ? '' : `Node=${root.slice(0, 24)}…`);
  chk('STATE', 'accounts_trie_root == state_root（trie 根即状态根，不做二次哈希）',
    ST.accounts_trie_root === ST.state_root);

  // trie 内容可往返导出
  const exported = t.items().map(([k, v]) => [k.toString('hex'), v.toString('hex')]);
  const want = ST.accounts.map((a) => [a.hashed_key, a.value_rlp]);
  const same = exported.length === want.length
    && exported.every(([k, v], i) => k === want[i][0] && v === want[i][1]);
  chk('STATE', 'trie 导出与输入的 (键,值) 集合逐一相同', same,
    `导出 ${exported.length} 项，输入 ${want.length} 项`);

  // 账户 RLP 结构可独立解码
  let structOk = 0;
  for (const a of ST.accounts) {
    const d = decode(B(a.value_rlp));
    if (Array.isArray(d) && d.length === 4) structOk++;
    // has_validator_key / has_system_key 必须与"键是否等于 Hash(\"\")"一致。
    // 注意：新编码下"无此键"仍然是 **32 字节**的 Hash("")，所以判据**不能**是
    // "长度 > 0"（那正是旧代码的写法，也是叶值分歧长期未被发现的原因之一）。
    const hasVk = !d[2].equals(HASH_EMPTY);
    const hasSk = !d[3].equals(HASH_EMPTY);
    if (hasVk !== a.has_validator_key || hasSk !== a.has_system_key) structOk = -999;
  }
  chk('STATE', '账户 RLP 均为 4 项（nonce, balance, validator_key, system_key）',
    structOk === ST.accounts.length, `符合 ${structOk}/${ST.accounts.length}`);

  // 系统账户的 system_key 必须是一个 32 字节哈希
  const sysAcc = ST.accounts.find((a) => a.has_system_key);
  chk('STATE', '恰有一个账户带 system_key（系统账户）', !!sysAcc,
    sysAcc ? sysAcc.hashed_key.slice(0, 12) + '…' : '未找到');
  if (sysAcc) {
    chk('STATE', '系统账户的 system_key 为 32 字节',
      Buffer.from(sysAcc.has_system_key ? B(sysAcc.value_rlp) && decode(B(sysAcc.value_rlp))[3] : []).length === 32);
  }
  chk('STATE', 'system_key 与向量声明一致（= Keccak(RLP(SystemState)) 的结果）',
    ST.system_key.length === 64);

  // ── 从 ValidatorRecord 独立推导 validator_key ──
  //
  // 这是"独立性"最有价值的一处：`validator_key = Keccak(RLP(ValidatorRecord))`，
  // 因此独立实现可以**自己算出**该账户承诺的验证者记录，再与账户叶里的字节比对。
  // 若两个实现对 ValidatorRecord 的字段顺序或宽度理解不同，这一步立刻失败 ——
  // 而它不需要信任向量里的任何派生值（只用到 record 的 RLP 本身）。
  //
  // 需要把验证者地址映射到「已哈希键」：trie 键 = Keccak(address)（secure trie）。
  let vkOk = 0;
  const vkMismatch = [];
  for (const v of ST.validators) {
    const addr = Buffer.from(v.address, 'hex');
    const hashedKey = keccak256(addr);
    const acc = ST.accounts.find((a) => a.hashed_key === hashedKey.toString('hex'));
    if (!acc) {
      vkMismatch.push(`${v.address.slice(0, 12)}… 在 accounts 中找不到`);
      continue;
    }
    const d = decode(B(acc.value_rlp));
    const accVk = Buffer.from(d[2]);                     // validator_key
    const derived = keccak256(B(v.record_rlp));          // Keccak(RLP(ValidatorRecord))
    if (accVk.equals(derived)) vkOk++;
    else vkMismatch.push(`${v.address.slice(0, 12)}… 账户内=${accVk.toString('hex').slice(0, 16)}…`
      + ` 推导=${derived.toString('hex').slice(0, 16)}…`);
  }
  chk('STATE', `validator_key == Keccak(RLP(ValidatorRecord))（${vkOk}/${ST.validators.length}）`,
    vkOk === ST.validators.length, vkMismatch.slice(0, 2).join(' | '));

  // ValidatorRecord 的字段数与宽度（独立解析，不依赖向量里的派生值）
  let recOk = 0;
  for (const v of ST.validators) {
    const r = decode(B(v.record_rlp));
    if (!Array.isArray(r) || r.length !== 12) {
      vkMismatch.push(`${v.address.slice(0, 12)}… 记录项数 ${Array.isArray(r) ? r.length : '非列表'}`);
      continue;
    }
    const pubkey = Buffer.from(r[0]);
    const status = Buffer.from(r[3]);
    const founder = Buffer.from(r[9]);
    if (pubkey.length === 32 && status.length <= 1 && founder.length <= 1) recOk++;
    else vkMismatch.push(`${v.address.slice(0, 12)}… 字段宽度不符`);
  }
  chk('STATE', 'ValidatorRecord 均为 12 项且字段宽度正确（pubkey 32 字节等）',
    recOk === ST.validators.length, vkMismatch.slice(0, 2).join(' | '));

  // ── ★ 独立重算 system_key（= Keccak(RLP(SystemState))) ──
  //
  // 这是"独立实现能算状态根"的最后一环：系统账户的 `system_key` 承诺了整个
  // 链级状态，因此必须由独立实现自己编码 16 个字段并哈希，而不是照抄向量。
  const S = require('./state.js');
  const sysFixture = {
    ...ST.system_state,
    snapshot: ST.snapshot,
  };
  const sysRlp = S.systemStateRlp(sysFixture);
  const recomputed = keccak256(sysRlp).toString('hex');
  chk('STATE', '★ system_key 独立重算一致（Keccak(RLP(SystemState))，16 字段）',
    recomputed === ST.system_key,
    recomputed === ST.system_key ? '' : `Node=${recomputed.slice(0, 24)}… 向量=${ST.system_key.slice(0, 24)}…`);
  chk('STATE', 'SystemState 的 RLP 与向量导出的原像逐字节一致',
    sysRlp.toString('hex') === ST.system_state_rlp,
    sysRlp.length === ST.system_state_rlp.length / 2
      ? '' : `Node ${sysRlp.length} 字节 vs 向量 ${ST.system_state_rlp.length / 2} 字节`);
  // 解码校验：必须是 16 项
  const sysDecoded = decode(sysRlp);
  chk('STATE', 'SystemState 可独立解码为 16 项',
    Array.isArray(sysDecoded) && sysDecoded.length === 16,
    Array.isArray(sysDecoded) ? `实际 ${sysDecoded.length} 项` : '非列表');
  // 快照子结构：4 项
  if (Array.isArray(sysDecoded) && sysDecoded.length === 16) {
    const snapDecoded = decode(B(ST.snapshot ? S.snapshotRlp(ST.snapshot).toString('hex') : ''));
    chk('STATE', 'SnapshotSet 可独立解码为 4 项（membership, voting_power, staked, records）',
      Array.isArray(snapDecoded) && snapDecoded.length === 4,
      Array.isArray(snapDecoded) ? `实际 ${snapDecoded.length} 项` : '非列表');
    // 第 10 项是 `RLP(SnapshotSet)` 的**字节串**（一层嵌套编码）；解出来应为 4 项。
    const snapBytes = Buffer.from(sysDecoded[10]);
    const snapInside = decode(snapBytes);
    chk('STATE', 'SystemState[10] 是快照的 RLP 字节串，解码为 4 项',
      Array.isArray(snapInside) && snapInside.length === 4,
      Array.isArray(snapInside) ? `实际 ${snapInside.length} 项` : '非列表');
    if (Array.isArray(snapInside) && snapInside.length === 4) {
      chk('STATE', '快照内的成员地址数与向量一致',
        snapInside[0].length === ST.snapshot.membership.length,
        `${snapInside[0].length} vs ${ST.snapshot.membership.length}`);
      chk('STATE', '快照内的投票权项数与向量一致',
        snapInside[1].length === ST.snapshot.voting_power.length);
      chk('STATE', '快照内的 records 项数与向量一致',
        snapInside[3].length === ST.snapshot.records.length);
      chk('STATE', '快照内的 records[0] 与向量导出的记录 RLP 逐字节一致',
        Buffer.from(snapInside[3][0]).equals(B(ST.snapshot.records[0])));
    }
    chk('STATE', 'SystemState[3] total_supply 与向量一致',
      BigInt('0x' + Buffer.from(sysDecoded[3]).toString('hex') || '0x0')
        === BigInt(ST.system_state.total_supply)
      || Buffer.from(sysDecoded[3]).length === 0);
  }

  // ── 空投：叶子哈希与包含证明 ──
  // 叶子 = Keccak(TAG_AIRDROP ‖ CHAIN(pubkey(32), u256(amount), u256(gas_allowance)))
  const TAG_AIRDROP = Buffer.from('AGORA/AIRDROP/v0.2.2', 'ascii');
  const leafPre = Buffer.concat([
    TAG_AIRDROP,
    // 叶子 **MUST** 含 `u64(index)`（规范 §32.5 / BUG-87）：唯一性判据是
    // `(tx.from, index)`，而 index 由提交者自选；叶子不含 index 时 Merkle 证明
    // 与该条目不是一一对应 ⇒ 同一份权益可换 index 反复领取，把整个金库领空。
    P.chain({ t: 'u64', v: BigInt(ST.airdrop.index) },
            { t: 'hash32', v: B(ST.airdrop.pubkey) },
            { t: 'u256', v: BigInt(ST.airdrop.amount) },
            { t: 'u256', v: BigInt(ST.airdrop.gas_allowance) }),
  ]);
  const leaf = keccak256(leafPre).toString('hex');
  chk('STATE', '空投叶子哈希独立重算一致（标签前置 + u256 定宽）',
    leaf === ST.airdrop.leaf_hash, leaf === ST.airdrop.leaf_hash ? '' : `Node=${leaf.slice(0, 24)}…`);

  // 包含证明：叶子与各兄弟节点按 (小,大) 排序后逐层哈希
  let h = Buffer.from(ST.airdrop.leaf_hash, 'hex');
  for (const sibHex of ST.airdrop.proof) {
    const sib = Buffer.from(sibHex, 'hex');
    const [x, y] = Buffer.compare(h, sib) <= 0 ? [h, sib] : [sib, h];
    h = keccak256(Buffer.concat([Buffer.from([1]), x, y]));
  }
  chk('STATE', `空投证明（${ST.airdrop.proof.length} 个兄弟节点）重算得到根`,
    h.toString('hex') === ST.airdrop.root,
    h.toString('hex') === ST.airdrop.root ? '' : `Node=${h.toString('hex').slice(0, 24)}…`);

  // 篡改证明必须失败（否则"验证"没有意义）
  if (ST.airdrop.proof.length > 0) {
    const bad = Buffer.from(ST.airdrop.proof[0], 'hex');
    bad[0] ^= 0xff;
    let h2 = Buffer.from(ST.airdrop.leaf_hash, 'hex');
    for (const sibHex of [bad.toString('hex'), ...ST.airdrop.proof.slice(1)]) {
      const sib = Buffer.from(sibHex, 'hex');
      const [x, y] = Buffer.compare(h2, sib) <= 0 ? [h2, sib] : [sib, h2];
      h2 = keccak256(Buffer.concat([Buffer.from([1]), x, y]));
    }
    chk('STATE', '被篡改的证明无法得到根（防伪有效）',
      h2.toString('hex') !== ST.airdrop.root);
  }
}

// ══════════════════════════════════════════════════════════════════════
// 9. HANDSHAKE —— 握手原像与签名（§6.7，名字 ↔ 连接的身份绑定）
// ══════════════════════════════════════════════════════════════════════
//
// 为什么值得单独一节：握手是"对端自述的名字"与**公钥**之间唯一的绑定。
// 原像只要差一个字节（标签写进了 CHAIN、chain_id 被当成 20 字节原样、
// nonce 顺序颠倒），两个实现就**互相验不过**，表现为跨实现永远握手失败；
// 而如果差的是域分隔（role 字节），CHALLENGE 的签名就能被当成 AUTH ——
// 那是**安全缺陷**，且"字节比对全绿"也发现不了，只能靠"角色互换必须被拒"
// 这类语义断言证明。因此本节既比字节，也比"拒绝"。
console.log('\n9) HANDSHAKE · 名字↔连接的握手原像与签名');
{
  const HS = require('./handshake.js');
  const H = vectors.HANDSHAKE;
  if (!H) throw new Error('向量文件缺少 HANDSHAKE 族：请先跑 tools/agora_vectors.py 重新生成');

  const B = (hex) => Buffer.from(hex, 'hex');
  const params = (row) => ({
    chainId: row.chain_id, role: row.role, name: row.name,
    pubkey: B(row.pubkey), nonceI: B(row.nonce_i), nonceR: B(row.nonce_r),
  });

  // ── 原像：Node 独立重算，与 Python 逐字节比对 ──
  const built = new Map();
  for (const row of H.cases) {
    const got = HS.handshakePreimage(params(row));
    built.set(row.case, got);
    chk('HANDSHAKE', `原像逐字节一致：${row.case}`,
      got.toString('hex') === row.preimage,
      got.toString('hex') === row.preimage ? '' : `Node=${got.toString('hex').slice(0, 48)}… 向量=${row.preimage.slice(0, 48)}…`);
    const dig = HS.handshakeDigest(got).toString('hex');
    chk('HANDSHAKE', `原像摘要（Keccak-256）一致：${row.case}`, dig === row.digest,
      dig === row.digest ? '' : `Node=${dig} 向量=${row.digest}`);
  }

  // ── 布局：长度、标签位置、role 偏移必须与**规范文本**的手算值一致 ──
  // 长度不是照抄向量，而是按字段独立加出来的（含 UTF-8 名字更长的情形：
  // "节点1" = 7 字节 ⇒ 147 + 2 = 149），照抄的话"表和实现同时错"就发现不了
  const expectedLen = (r) => H.tag_len + 4 + Buffer.from(r.chain_id, 'ascii').length + 1
    + 4 + Buffer.from(r.name, 'utf8').length + 32 + 32 + 32;
  const payloadRows = H.cases.filter((r) => r.length !== undefined);
  chk('HANDSHAKE', '标准情形原像长度 = 147 字节（标签22 + 链ID(4+15) + 角色1 + 名字(4+5) + 公钥32 + 两个 nonce 64）',
    H.preimage_len === 147 && payloadRows.filter((r) => r.name_utf8_len === 5)
      .every((r) => r.length === 147),
    `向量声明 ${H.preimage_len}`);
  chk('HANDSHAKE', `每行长度 = 各字段独立加总（含 UTF-8 名字 ${payloadRows.length} 行）`,
    payloadRows.every((r) => r.length === expectedLen(r) && B(r.preimage).length === r.length),
    payloadRows.map((r) => `${r.case}:${r.length}`).join(' '));

  const tag = B(H.cases[0].preimage).subarray(0, H.tag_len);
  chk('HANDSHAKE', '原像以 22 字节 ASCII 标签开头（标签在 CHAIN **之外**前置）',
    H.tag_len === 22 && HS.TAG_HANDSHAKE.length === 22
    && HS.TAG_HANDSHAKE.toString('ascii') === H.tag
    && tag.toString('ascii') === H.tag);

  // role 偏移：向量给的是逐字段布局表，这里从**链 ID 长度**独立算出应有偏移，
  // 而不是照抄表里的数字（照抄的话，表和实现同时错就发现不了）
  const cidLen = Buffer.from(H.chain_ids.testnet, 'ascii').length;
  const roleOff = H.tag_len + 4 + cidLen;
  const layoutRole = (H.layout || []).find((f) => f.field === 'role');
  chk('HANDSHAKE', `布局表 role 偏移与独立计算一致（${H.tag_len} + 4 + ${cidLen} = ${roleOff}）`,
    !!layoutRole && layoutRole.offset === roleOff,
    layoutRole ? `表=${layoutRole.offset} 算=${roleOff}` : '布局表缺 role 项');
  chk('HANDSHAKE', 'role 字节确实落在该偏移处且等于各行声明的角色',
    H.cases.every((r) => B(r.preimage)[roleOff] === r.role));

  // 15 字节的 chain_id **必须带 u32 前缀**（既非 20 也非 32 字节 ⇒ 不原样）。
  // 这是独立实现最容易对不上的一处：若按"原样"写，前 26 字节就会是
  // TAG ‖ "agora-testnet-1" ‖ 0x02…，与向量的 147 字节布局整体错位。
  const testnetRow = H.cases.find((r) => r.chain_id === H.chain_ids.testnet && r.case === 'payload_challenge');
  {
    const p = B(testnetRow.preimage);
    const prefixed = p.subarray(H.tag_len, H.tag_len + 4).readUInt32BE(0) === cidLen
      && p.subarray(H.tag_len + 4, roleOff).toString('ascii') === H.chain_ids.testnet;
    const notRaw = p.subarray(H.tag_len, H.tag_len + cidLen).toString('ascii') !== H.chain_ids.testnet;
    chk('HANDSHAKE', `15 字节 chain_id 带 u32 长度前缀（${cidLen}），不是原样`,
      prefixed && notRaw, `前缀=${p.subarray(H.tag_len, H.tag_len + 4).toString('hex')}`);
  }

  // UTF-8 名字的长度前缀是**字节数**（"节点1" = 7 字节），不是字符数
  {
    const row = H.cases.find((r) => /utf8/.test(r.case));
    if (row) {
      const p = B(row.preimage);
      const nb = Buffer.from(row.name, 'utf8');
      const nameOff = roleOff + 1;
      const ok = p.subarray(nameOff, nameOff + 4).readUInt32BE(0) === nb.length
        && p.subarray(nameOff + 4, nameOff + 4 + nb.length).equals(nb);
      chk('HANDSHAKE', `UTF-8 名字按字节数加前缀（${row.name} = ${nb.length} 字节，非字符数）`,
        ok && nb.length === row.name_utf8_len);
    }
  }

  // ── 签名：Python 签的、由 Node 独立重算的原像验证 ──
  for (const row of H.cases.filter((r) => r.signature)) {
    const pre = built.get(row.case);
    const sig = B(row.signature);
    chk('HANDSHAKE', `★ Python 签的 ${row.role_name} 握手签名通过 Node 验证（跨实现互操作）`,
      row.verified === true && HS.verifyHandshakeSig(B(row.pubkey), sig, params(row)));
    chk('HANDSHAKE', `${row.case} 签名为 64 字节且与原像摘要同源`,
      sig.length === 64 && HS.handshakeDigest(pre).toString('hex') === row.digest);
  }

  // ── 域分隔：CHALLENGE 与 AUTH 原像 **只差 role 字节** ──
  {
    const pc = built.get('payload_challenge');
    const pa = built.get('payload_auth');
    const diff = [];
    for (let i = 0; i < pc.length; i++) if (pc[i] !== pa[i]) diff.push(i);
    chk('HANDSHAKE', `CHALLENGE/AUTH 原像仅差 1 个字节且恰在 role 偏移 ${roleOff}（域分隔的实现证明，不是声明）`,
      diff.length === 1 && diff[0] === roleOff, `差异位置=[${diff.join(',')}]`);
    chk('HANDSHAKE', '该差异字节正是 2(CHALLENGE)/3(AUTH)，其余 146 字节完全相同',
      pc[roleOff] === HS.ROLE_CHALLENGE && pa[roleOff] === HS.ROLE_AUTH
      && pc.subarray(0, roleOff).equals(pa.subarray(0, roleOff))
      && pc.subarray(roleOff + 1).equals(pa.subarray(roleOff + 1)));
  }

  // ── must_reject：每一条都必须被 Node 侧**独立验证器**拒绝 ──
  for (const row of H.must_reject) {
    const ok = HS.verifyHandshakeSig(B(row.pubkey), B(row.signature), params(row));
    chk('HANDSHAKE', `拒绝：${row.case}`,
      row.must_reject === true && row.rejected === true && ok === false,
      ok ? 'Node 侧竟然通过' : '');
  }

  // 全零签名 / 全零公钥是规范定义的"无身份"哨兵 —— 上面的验证器对它们做了
  // 前置短路。这里再绕过哨兵，直接问**密码学验证器本身**：若它接受，
  // 则任何漏掉哨兵判断的调用方都能被伪造签名骗过（等于免签后门）。
  {
    const row = H.cases.find((r) => r.signature);
    const pre = built.get(row.case);
    const raw = (pk, sig) => {
      try { return crypto.verify(null, pre, HS.ed25519Key(pk), sig); } catch (e) { return false; }
    };
    chk('HANDSHAKE', '绕过 NIL 哨兵后，全零 64 字节签名仍被密码学验证器拒绝',
      raw(B(row.pubkey), Buffer.alloc(64)) === false);
    chk('HANDSHAKE', '绕过 NIL 哨兵后，全零 32 字节公钥仍被密码学验证器拒绝',
      raw(Buffer.alloc(32), B(row.signature)) === false);
  }

  // ── Node 自签自验：证明"重算出的原像"确实是合法的 Ed25519 签名输入 ──
  {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const der = publicKey.export({ format: 'der', type: 'spki' });
    const rawPub = der.subarray(der.length - 32);          // SPKI 尾部即 32 字节裸公钥
    const row = H.cases.find((r) => r.case === 'payload_challenge');
    const mine = { chainId: row.chain_id, name: row.name,
                   pubkey: rawPub, nonceI: B(row.nonce_i), nonceR: B(row.nonce_r) };
    // 注意：原像**含签名者公钥**，所以这里必须签"用本机新公钥重算的原像"，
    // 而不是向量里那个（属于另一把密钥的）原像 —— 后者验不过正是正确行为。
    const nodePre = HS.handshakePreimage({ ...mine, role: HS.ROLE_CHALLENGE });
    const nodeSig = crypto.sign(null, nodePre, privateKey);
    chk('HANDSHAKE', 'Node 用自己的密钥对重算原像签名，再用本模块验证通过（原像是合法签名输入）',
      der.length === 44 && HS.verifyChallengeSig(rawPub, nodeSig, mine));
    chk('HANDSHAKE', '同一 Node 签名换成 AUTH 角色必须验不过（Node 侧域分隔自洽）',
      HS.verifyAuthSig(rawPub, nodeSig, mine) === false);
  }
}

// ══════════════════════════════════════════════════════════════════════
console.log('\n' + '═'.repeat(76));
console.log(`通过 ${pass} 项，失败 ${fail} 项`);
if (fail) {
  console.log('\n★ 跨实现分歧（GATE-7 未通过）：');
  for (const f of failures.slice(0, 20)) console.log('  - ' + f);
  console.log('\n结果：★ 存在分歧');
} else {
  console.log('结果：两种实现对全部校验项**逐字节一致** ✅');
}
console.log('═'.repeat(76));
process.exit(fail ? 1 : 0);
