/*
 * AGORA v0.2.2 — 独立实现（Node.js）· 握手原像与签名（§6.7 身份绑定）
 * ==================================================================
 *
 * 依据规范文本独立编写（**不参照 `agora/handshake.py` 的行为**）：
 *
 *   原像 = TAG ‖ CHAIN( chain_id, u8(role), utf8(name), pubkey, nonce_i, nonce_r )
 *
 *   TAG          = "AGORA/HANDSHAKE/v0.2.2"（22 字节 ASCII，**在 CHAIN 之外前置**，§20.1）
 *   u8(role)     = 2 = CHALLENGE（响应方签）/ 3 = AUTH（发起方签）—— 域分隔
 *   chain_id     = 15 字节（既非 20 也非 32）⇒ **带 u32 长度前缀**（最容易对不上的一处）
 *   utf8(name)   = 普通字节串 ⇒ 带 u32 长度前缀；长度是**字节数**，不是字符数
 *   pubkey       = 32 字节 Ed25519 公钥，CHAIN 规则下原样
 *   nonce_i/nonce_r = 各 32 字节原样，**顺序恒为（发起方, 响应方）**：两种角色签同一
 *                     顺序，唯一区别就是 role 字节
 *
 * 标准情形总长 = 22 + (4+15) + 1 + (4+5) + 32 + 32 + 32 = **147 字节**。
 *
 * 为什么这一层必须独立重算：握手是"名字 ↔ 连接"的唯一绑定手段。若两个实现
 * 对原像的理解差一个字节（前缀、字段顺序、role 位置），签名就**互相验不过**，
 * 表现为节点间永远握手失败；若差的是 role 字节之外的域分隔，CHALLENGE 的签名
 * 就能当 AUTH 用 —— 中间人可以把一次挑战重放成"对端已认证"，这是安全缺陷而不是
 * 可用性缺陷，且**字节比对通过、只有语义检查能发现**（故本模块的调用方必须同时
 * 做"角色互换必须被拒"的断言）。
 */

'use strict';

const crypto = require('crypto');
const { chain, keccak256 } = require('./primitives.js');

/** 域标签：ASCII，22 字节，**在 CHAIN 之外**前置（§20.1）。 */
const TAG_HANDSHAKE = Buffer.from('AGORA/HANDSHAKE/v0.2.2', 'ascii');

const ROLE_CHALLENGE = 2;
const ROLE_AUTH = 3;

const NONCE_LEN = 32;
const PUBKEY_LEN = 32;
const SIG_LEN = 64;

/**
 * Ed25519 裸公钥 ⇒ Node `KeyObject` 所需的 DER/SPKI 包装。
 *
 * 与 `crosscheck.js` 的 ED25519 / TXBLOCK 两段用的是**同一个**前缀
 * （`302a300506032b6570032100` = SPKI 头 + 0x03/0x21 + BIT STRING 长度 32），
 * 不另造一套：跨实现互验的前提就是"两边都把 32 字节裸公钥当同一个东西"。
 *
 * @param {Buffer} pubkey 32 字节裸公钥
 * @returns {crypto.KeyObject}
 */
function ed25519Key(pubkey) {
  return crypto.createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pubkey]),
    format: 'der', type: 'spki',
  });
}

/** `CHAIN` 的字节串规则（§20.1）：20/32 字节原样，其余加 u32 长度前缀。 */
function chainBytes(buf) {
  if (buf.length === 20 || buf.length === 32) return buf;
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length, 0);
  return Buffer.concat([len, buf]);
}

/**
 * 握手签名原像（规范文本的唯一实现）。
 *
 * @param {object} f
 * @param {string} f.chainId 链身份（ASCII，如 `agora-testnet-1`）
 * @param {number} f.role    2 = CHALLENGE，3 = AUTH
 * @param {string} f.name    节点名（UTF-8）
 * @param {Buffer} f.pubkey  32 字节签名者公钥
 * @param {Buffer} f.nonceI  32 字节，**恒为第一个**
 * @param {Buffer} f.nonceR  32 字节，**恒为第二个**
 * @returns {Buffer} 147 字节（标准情形）
 */
function handshakePreimage({ chainId, role, name, pubkey, nonceI, nonceR }) {
  // 角色只允许 2/3：多一个取值就等于多一个可被重放的域（规范里只定义了两个）
  if (role !== ROLE_CHALLENGE && role !== ROLE_AUTH) {
    throw new Error(`未知握手角色：${role}（应为 ${ROLE_CHALLENGE} 或 ${ROLE_AUTH}）`);
  }
  if (pubkey.length !== PUBKEY_LEN) {
    throw new Error(`pubkey 必须为 ${PUBKEY_LEN} 字节，实际 ${pubkey.length}`);
  }
  if (nonceI.length !== NONCE_LEN || nonceR.length !== NONCE_LEN) {
    throw new Error('nonce 必须各为 32 字节');
  }
  // 标签**在 CHAIN 之外**：写成 CHAIN 的参数会多出 4 字节 u32 长度前缀
  // （22 字节既非 20 也非 32），原像随之整体变化。
  return Buffer.concat([
    TAG_HANDSHAKE,
    // 宽度显式声明（§20.1 / BUG-64 的教训：裸整数语义为"最小定宽"，不可用于签名载荷）
    chain(Buffer.from(chainId, 'ascii'), { t: 'u8', v: role },
          // 名字按**普通字节串**处理 ⇒ u32(字节数) ‖ UTF-8 字节
          Buffer.from(name, 'utf8'), pubkey, nonceI, nonceR),
  ]);
}

/** 原像摘要（Keccak-256，§2.2）：仅用于日志与向量比对，签名签的是原像本身。 */
function handshakeDigest(preimage) {
  return keccak256(preimage);
}

/**
 * 用 Node 自带 Ed25519 校验握手签名。
 *
 * **任何**非"通过"的结果都返回 `false`（包括格式非法：长度不对、公钥不可解码、
 * 全零哨兵）。理由：调用方的输入来自网络，是不可信数据；抛异常会让"不可信输入"
 * 以难以定位的方式炸在上层，而根据异常类型决定否决/接受是经典的认证绕过来源。
 * 全零签名与全零公钥是规范定义的"无身份"哨兵 —— 它们**不是**通过，而是失败。
 *
 * @param {Buffer} pubkey    32 字节
 * @param {Buffer} signature 64 字节
 * @param {object} f         同 `handshakePreimage` 的字段
 * @returns {boolean}
 */
function verifyHandshakeSig(pubkey, signature, f) {
  try {
    if (!Buffer.isBuffer(pubkey) || !Buffer.isBuffer(signature)) return false;
    if (pubkey.length !== PUBKEY_LEN || signature.length !== SIG_LEN) return false;
    if (signature.equals(Buffer.alloc(SIG_LEN))) return false;   // NIL_SIG：无身份 ≠ 通过
    if (pubkey.equals(Buffer.alloc(PUBKEY_LEN))) return false;   // NIL_PUBKEY：无身份 ≠ 通过
    return crypto.verify(null, handshakePreimage({ ...f, pubkey }), ed25519Key(pubkey),
                         signature);
  } catch (e) {
    return false;
  }
}

/** 校验响应方的挑战签名（发起方用）。 */
function verifyChallengeSig(pubkey, signature, f) {
  return verifyHandshakeSig(pubkey, signature, { ...f, role: ROLE_CHALLENGE });
}

/** 校验发起方的确认签名（响应方用）。 */
function verifyAuthSig(pubkey, signature, f) {
  return verifyHandshakeSig(pubkey, signature, { ...f, role: ROLE_AUTH });
}

module.exports = {
  TAG_HANDSHAKE, ROLE_CHALLENGE, ROLE_AUTH, NONCE_LEN, PUBKEY_LEN, SIG_LEN,
  chainBytes, ed25519Key, handshakePreimage, handshakeDigest,
  verifyHandshakeSig, verifyChallengeSig, verifyAuthSig,
};
