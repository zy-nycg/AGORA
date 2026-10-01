/*
 * AGORA v0.2.2 — 独立实现（Node.js）· 共识对象（交易 / 区块头 / Commit）
 * ====================================================================
 *
 * 依据规范 §16.1、§6.1、§6.2、§20.3 独立编写。
 *
 * 为什么需要这一层：原语（RLP / CHAIN / MPT）一致**不代表**共识对象一致 ——
 * 字段顺序、哪些字段进签名载荷、哈希取在"内容"还是"封装"上，任何一处理解不同，
 * 都会让两个实现算出不同的交易哈希与区块哈希，而**各自的测试都通过**。
 * 实测已发生过的同类问题：投票签名载荷在参考实现里有两份写法（BUG-67）。
 *
 * 关键规则（逐条照做，不参照参考实现的行为）：
 *
 *   交易（§16.1）：
 *     TxContent  = RLP([type, chain_id_hash(32), nonce, max_prio, max_fee,
 *                       gas_limit, to(20)|empty, value, payload, pubkey])
 *     TxEnvelope = TxContent + [signature]        ← **签名在封装内但不参与签名载荷**
 *     tx_signing_payload = TAG_TX ‖ CHAIN(chain_id, RLP(TxContent))
 *     tx_hash            = Keccak(RLP(TxEnvelope))  ← 含签名
 *
 *   区块头（§6.1，16 项）：
 *     HeaderContent = 前 15 项（不含 proposer_signature）
 *     BlockHash     = Keccak(RLP(16 项))            ← 含签名
 *     proposal_signing_payload = TAG_PROPOSAL ‖ CHAIN(chain_id, RLP(HeaderContent))
 *
 *   Commit（§6.2）：
 *     Commit = RLP([height, round, block_hash(32), [[address(20), sig(64)], ...]])
 *
 *   **链 ID 在签名载荷里按 CHAIN 的字节串规则处理**：15 字节（既非 20 也非 32）
 *   ⇒ 加 u32 长度前缀。而它的**哈希**（`chain_id_hash`）是一个 32 字节哈希，
 *   在 RLP 里按普通字节串编码。
 */

'use strict';

const { keccak256, encode, decode, bytesToInt } = require('./primitives.js');

/** `CHAIN` 的字节串规则：20/32 字节原样，其它加 u32 长度前缀。 */
function chainBytes(buf) {
  if (buf.length === 20 || buf.length === 32) return buf;
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length, 0);
  return Buffer.concat([len, buf]);
}

// ══════════════════════════════════════════════════════════════════════
// 交易（§16.1）
// ══════════════════════════════════════════════════════════════════════

/**
 * @param {object} f 字段（与向量 `TXBLOCK.tx.fields` 同名）
 * @param f.protocol_version_hash {Buffer} 32 字节
 * @param f.chain_id_hash {Buffer} 32 字节
 */
function txContentFields(f) {
  return [
    f.tx_type,
    f.protocol_version_hash,
    f.nonce,
    BigInt(f.max_priority_fee_per_gas),
    BigInt(f.max_fee_per_gas),
    f.gas_limit,
    f.to,
    BigInt(f.value),
    f.payload,
    f.pubkey,
  ];
}

function txContentRlp(f) {
  return encode(txContentFields(f));
}

function txEnvelopeRlp(f) {
  return encode(txContentFields(f).concat([f.signature]));
}

function txSigningPayload(f, chainId, tagTx) {
  // `RLP(TxContent)` 是一个**变长字节串**，因此 CHAIN 对它加 u32 长度前缀
  // （129 字节 ⇒ `00000081`）。链 ID 同为字节串（15 字节 ⇒ `0000000f`）。
  // 我曾漏掉 RLP 那一层前缀，导致载荷短 4 字节 —— 而**总长差 4 字节**
  // 正是这类错误唯一的表征，必须靠逐字节比对才能发现。
  return Buffer.concat([
    tagTx,
    chainBytes(chainId),
    chainBytes(txContentRlp(f)),
  ]);
}

function txHash(f) {
  return keccak256(txEnvelopeRlp(f));
}

// ══════════════════════════════════════════════════════════════════════
// 区块头与区块（§6.1）
// ══════════════════════════════════════════════════════════════════════

function headerContentFields(f) {
  return [
    f.protocol_version_hash,
    f.chain_id_hash,
    f.height,
    f.round,
    f.claimed_slot,
    f.timestamp,
    f.parent_hash,
    f.parent_commit_hash,
    f.tx_root,
    f.receipt_root,
    f.state_root,
    f.gas_used,
    BigInt(f.base_fee_per_gas),
    // `parent_commit` 是**嵌套列表**（规范 §6.1 写的是对象类型 `parent_commit:Commit`；
    // 本规范对需要预序列化的字段一律显式写 `bytes`，如 §19.5 的 `snapshot:bytes`）。
    // 曾写成 `f.parent_commit_rlp`（字节串）⇒ 头部 RLP 与区块哈希都不对。
    decode(f.parent_commit_rlp),
    f.proposer_pubkey,
  ];
}

function headerContentRlp(f) {
  return encode(headerContentFields(f));
}

function headerRlp(f) {
  return encode(headerContentFields(f).concat([f.proposer_signature]));
}

function blockHash(f) {
  return keccak256(headerRlp(f));
}

function proposalSigningPayload(f, chainId, tagProposal) {
  // 同交易：`RLP(HeaderContent)` 也是变长字节串，需 u32 长度前缀。
  return Buffer.concat([
    tagProposal,
    chainBytes(chainId),
    chainBytes(headerContentRlp(f)),
  ]);
}

function blockRlp(f, txRlps) {
  // 规范 §6.1.2：`Block = RLP([BlockHeader, [Transaction, …]])` —— **嵌套对象**，
  // 头部与每笔交易都不得写成"它们各自的 RLP 字节串"（BUG-81）。
  return encode([
    headerContentFields(f).concat([f.proposer_signature]),
    txRlps.map((e) => decode(e)),
  ]);
}

// ══════════════════════════════════════════════════════════════════════
// Commit（§6.2）与预提交签名载荷（§20.3）
// ══════════════════════════════════════════════════════════════════════

function commitRlp(c) {
  // 规范 §6.2：`signatures` 是 **[[address, signature], …] 的嵌套列表**，
  // 不是"每个签名的 RLP 字节串"。二者前缀不同（列表 c… vs 字节串 b8…），
  // 而 Commit 经 parent_commit_hash 进入**每一个区块哈希**（BUG-79）。
  return encode([
    c.height,
    c.round,
    c.block_hash,
    c.signatures.map(([addr, sig]) => [addr, sig]),
  ]);
}

/**
 * 预提交签名载荷（§20.3）：
 *     TAG_PRECOMMIT ‖ CHAIN(chain_id, u64(height), u32(round), u8(PRE_COMMIT), block_hash)
 *
 * **宽度必须与规范 §20.3 一致（定宽）**：这是 BUG-64 的要害 ——
 * 用最小定宽会让载荷长度差 10 字节、摘要完全不同。
 */
function precommitPayload(height, round, blockHashBytes, chainId, tagPrecommit,
                          chainFieldU) {
  return Buffer.concat([
    tagPrecommit,
    chainFieldU(4, BigInt(chainId.length)), chainId,
    chainFieldU(8, BigInt(height)),
    chainFieldU(4, BigInt(round)),
    chainFieldU(1, 2n),
    blockHashBytes,
  ]);
}

module.exports = {
  chainBytes, txContentFields, txContentRlp, txEnvelopeRlp, txSigningPayload,
  txHash, headerContentFields, headerContentRlp, headerRlp, blockHash,
  proposalSigningPayload, blockRlp, commitRlp, precommitPayload,
};

// ══════════════════════════════════════════════════════════════════════
// 提案者选取（§12.2–§12.4）—— 共识关键
// ══════════════════════════════════════════════════════════════════════
//
// 为什么这是最关键的一处：**选错提案者 = 全网永远无法最终化**。
// 每个节点独立算出同一个提案者才能达成共识；排序规则、累计边界（`>` 还是 `≥`）、
// 零权成员是否跳过，任何一处理解不同都会让部分节点拒绝正确提案，
// 而各自的单元测试都通过（因为各自自洽）。

/** §12.3：`R(E, slot, round) = Keccak(TAG_PROPOSER ‖ CHAIN(EpochSeed, u64(E), u64(slot), u64(round)))` */
function selectionRandomness(epochSeed, epoch, slot, round, tagProposer,
                             chainFieldU) {
  const payload = Buffer.concat([
    Buffer.from(tagProposer, 'ascii'),
    epochSeed,
    chainFieldU(8, BigInt(epoch)),
    chainFieldU(8, BigInt(slot)),
    chainFieldU(8, BigInt(round)),
  ]);
  return keccak256(payload);
}

/**
 * §12.4：按**地址 20 字节升序**累计投票权，取累计值**严格大于** `target` 的第一个成员；
 * **零权成员跳过**（因此 `target == 0` 时也能唯一确定）。
 *
 * @param {Buffer} r 32 字节随机数
 * @param {Array<[Buffer, bigint]>} votingPower `(address, vp)`
 * @param {bigint} stakedSupply `S_epoch`
 * @returns {Buffer|null} 提案者地址；`S_epoch == 0` 时返回 `null`（§7.7 链 halt）
 */
function selectProposer(r, votingPower, stakedSupply) {
  if (stakedSupply <= 0n) return null;
  const sorted = votingPower
    .filter(([, vp]) => vp > 0n)
    .sort((a, b) => Buffer.compare(a[0], b[0]));
  if (sorted.length === 0) return null;
  const target = bytesToInt(r) % stakedSupply;
  let cum = 0n;
  for (const [addr, vp] of sorted) {
    cum += vp;
    if (cum > target) return addr;      // **严格大于**：`>=` 会让 target==0 时选错
  }
  return sorted[sorted.length - 1][0];
}

/**
 * §12.2：`EpochSeed = Keccak(TAG_EPOCH_SEED ‖ CHAIN(prev_block_hash(32), prev_state_root(32),
 *          prev_tx_root(32), prev_proposer(20), u64(prev_slot), u64(prev_round)))`
 */
function epochSeed(prev, tagEpochSeed, chainFieldU) {
  const payload = Buffer.concat([
    Buffer.from(tagEpochSeed, 'ascii'),
    prev.block_hash, prev.state_root, prev.tx_root, prev.proposer,
    chainFieldU(8, BigInt(prev.slot)),
    chainFieldU(8, BigInt(prev.round)),
  ]);
  return keccak256(payload);
}


module.exports.selectionRandomness = selectionRandomness;
module.exports.selectProposer = selectProposer;
module.exports.epochSeed = epochSeed;
