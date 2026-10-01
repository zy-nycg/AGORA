/*
 * AGORA v0.2.2 — 独立实现（Node.js）· 基础原语与 RLP
 * ==================================================
 *
 * 本文件是 GATE-7 要求的**独立实现**的一部分。
 *
 * 「独立」的含义（这条纪律决定了整个文件怎么写）
 * ------------------------------------------------
 * 1. **只依据规范文本（`AGORA_v0.2.2_SPEC.md`）与公开标准（RFC 8032、
 *    Keccak 参考定义）编写**，不复制、不翻译 `agora/` 下的 Python 代码；
 * 2. 语言与运行时必须与参考实现不同（此处为 Node.js，另一套 bigint/
 *    Buffer/编码语义）；
 * 3. 校验方式是与 Python 生成的**黄金向量逐字节比对** —— 一致才算通过。
 *
 * 为什么这一步不能用"再写一遍 Python"替代：同一个作者在同一种语言里，
 * 会把同一处误解重复一次（例如"RLP 整数是否需要最小字节串"这种细节）。
 * 换语言、换标准库、换整数实现，才会真正暴露分歧。
 *
 * 已实现的独立部分：Keccak-f[1600] 置换与 Keccak-256 填充、RLP 编解码、
 * `CHAIN` 定宽前置函数。Ed25519 走 Node 自带的 RFC 8032 实现（另一套代码库）。
 */

'use strict';

// ══════════════════════════════════════════════════════════════════════
// 1. Keccak-256（规范 §2.2）
// ══════════════════════════════════════════════════════════════════════
//
// **关键区别：Keccak-256 ≠ SHA-3-256。** 二者置换完全相同，仅域分隔字节不同：
//   Keccak-256（本协议）：0x01
//   SHA-3-256（NIST）    ：0x06
// 所以**不能**用 node:crypto 的 sha3-256 代替（实测 node 也没有 keccak）。
//
// 本实现按 Keccak 参考定义独立写出，使用 BigInt 做 64 位无符号运算
// （Python 侧是原生 int，Node 侧是 BigInt —— 另一套溢出与移位语义）。

const MASK64 = (1n << 64n) - 1n;

/** 轮常数 RC[0..23]：由 LFSR 生成（规范 §2.2 未固定写法，此处独立推导）。 */
function roundConstants() {
  const rc = [];
  let lfsr = 1;
  for (let round = 0; round < 24; round++) {
    let c = 0n;
    for (let j = 0; j < 7; j++) {
      const bit = lfsr & 1;
      lfsr = ((lfsr << 1) ^ (lfsr & 0x80 ? 0x71 : 0)) & 0xff;
      if (bit) c ^= 1n << BigInt((1 << j) - 1);
    }
    rc.push(c);
  }
  return rc;
}

const RC = roundConstants();

/** ρ 步的旋转偏移：offset[x + 5y]，由 (x,y) 的游走规则生成。 */
function rhoOffsets() {
  const offs = new Array(25).fill(0);
  let x = 1, y = 0;
  for (let t = 0; t < 24; t++) {
    offs[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;
    const nx = y, ny = (2 * x + 3 * y) % 5;
    x = nx; y = ny;
  }
  return offs;
}

const RHO = rhoOffsets();

function rotl64(v, n) {
  if (n === 0) return v & MASK64;
  const s = BigInt(n);
  return ((v << s) | (v >> (64n - s))) & MASK64;
}

/** Keccak-f[1600]：24 轮 θ ρ π χ ι。 */
function keccakF1600(st) {
  for (let round = 0; round < 24; round++) {
    const C = new Array(5);
    for (let x = 0; x < 5; x++) {
      C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
    }
    const D = new Array(5);
    for (let x = 0; x < 5; x++) {
      D[x] = (C[(x + 4) % 5] ^ ((C[(x + 1) % 5] << 1n) | (C[(x + 1) % 5] >> 63n))) & MASK64;
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) st[x + 5 * y] = (st[x + 5 * y] ^ D[x]) & MASK64;
    }

    const B = new Array(25).fill(0n);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        // π 步：B[y][2x+3y] = rot(A[x][y], rho[x+5y])
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(st[x + 5 * y], RHO[x + 5 * y]);
      }
    }

    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        st[x + 5 * y] = (B[x + 5 * y] ^
          (((~B[(x + 1) % 5 + 5 * y]) & MASK64) & B[(x + 2) % 5 + 5 * y])) & MASK64;
      }
    }

    st[0] = (st[0] ^ RC[round]) & MASK64;
  }
}

/**
 * Keccak-256。rate = 1088 bit = 136 字节，域分隔字节 0x01。
 * @param {Buffer} data
 * @returns {Buffer} 32 字节
 */
function keccak256(data) {
  const rate = 136;
  const st = new Array(25).fill(0n);

  // 吸收完整分组
  let off = 0;
  while (data.length - off >= rate) {
    for (let i = 0; i < rate / 8; i++) {
      st[i] = (st[i] ^ data.readBigUInt64LE(off + i * 8)) & MASK64;
    }
    keccakF1600(st);
    off += rate;
  }

  // 末块 + 填充
  const blk = Buffer.alloc(rate);
  data.copy(blk, 0, off);
  const rem = data.length - off;
  blk[rem] = 0x01;
  blk[rate - 1] |= 0x80;
  for (let i = 0; i < rate / 8; i++) {
    st[i] = (st[i] ^ blk.readBigUInt64LE(i * 8)) & MASK64;
  }
  keccakF1600(st);

  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(st[i], i * 8);
  return out;
}

// ══════════════════════════════════════════════════════════════════════
// 2. RLP（规范 §20.2）
// ══════════════════════════════════════════════════════════════════════
//
// 规范要点（此处严格照做，不参考 Python 实现）：
//   · 单字节且 < 0x80      → 原样
//   · 0..55 字节的串       → 0x80+len ‖ payload
//   · >55 字节的串         → 0xb7+lenOfLen ‖ len ‖ payload
//   · 列表                 → 0xc0+len 或 0xf7+lenOfLen ‖ concat(items)
//   · **整数 = 无符号大端最小字节串，0 编码为空串**
//
// 校验分两层（规范 §20.2，BUG-49）：
//   ① 结构层（解码时）：长度前缀必须最小、长度声明必须自洽、不得有尾随字节；
//   ② 整数层（解释为整数时）：拒绝前导零。
// 解码器**不掌握 schema**，因此**不得**在解码时一律拒绝以 0x00 开头的字节串
// —— 地址、32 字节哈希都可能以 0x00 开头，一律拒绝会让"同一笔交易是否合法"
// 在实现间产生分歧（一种拒绝、一种接受）。

function encodeLength(len, offset) {
  if (len < 56) return Buffer.from([offset + len]);
  const lenBytes = intToBytes(len);
  return Buffer.concat([Buffer.from([offset + 55 + lenBytes.length]), lenBytes]);
}

/** 整数 → 最小大端字节串（0 → 空） */
function intToBytes(n) {
  if (typeof n === 'bigint') {
    if (n < 0n) throw new Error('RLP 只支持非负整数');
    if (n === 0n) return Buffer.alloc(0);
    let hex = n.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    return Buffer.from(hex, 'hex');
  }
  if (!Number.isInteger(n) || n < 0) throw new Error('RLP 只支持非负整数');
  if (n === 0) return Buffer.alloc(0);
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

function encodeBytes(buf) {
  if (buf.length === 1 && buf[0] < 0x80) return Buffer.from(buf);
  return Buffer.concat([encodeLength(buf.length, 0x80), buf]);
}

/**
 * 统一入口：接受 number / bigint / Buffer / string(UTF-8) / 数组（列表）。
 * 规范里的"整数"一律用 number 或 bigint 传入，字符串按字节串处理。
 */
function encode(item) {
  if (Array.isArray(item)) {
    const parts = item.map(encode);
    const body = Buffer.concat(parts);
    return Buffer.concat([encodeLength(body.length, 0xc0), body]);
  }
  if (Buffer.isBuffer(item)) return encodeBytes(item);
  if (typeof item === 'string') return encodeBytes(Buffer.from(item, 'utf8'));
  if (typeof item === 'number' || typeof item === 'bigint') {
    return encodeBytes(intToBytes(item));
  }
  throw new Error(`RLP 不支持的输入类型：${typeof item}`);
}

/** 解码为"字节串或数组"的树；整数语义由调用方解释。 */
function decode(data) {
  const [obj, pos] = decodeOne(data, 0);
  if (pos !== data.length) {
    throw new Error(`RLP 存在尾随字节：已解 ${pos}，总长 ${data.length}`);
  }
  return obj;
}

function decodeOne(data, pos) {
  if (pos >= data.length) throw new Error('RLP 输入不足');
  const b0 = data[pos];

  if (b0 < 0x80) return [Buffer.from([b0]), pos + 1];

  if (b0 < 0xb8) {
    const len = b0 - 0x80;
    if (pos + 1 + len > data.length) throw new Error('RLP 字符串长度超出输入');
    // 注意：此处**不**检查前导零（见文件头"校验分两层"）
    return [data.subarray(pos + 1, pos + 1 + len), pos + 1 + len];
  }

  if (b0 < 0xc0) {
    const ll = b0 - 0xb7;
    if (pos + 1 + ll > data.length) throw new Error('RLP 长度前缀超出输入');
    if (data[pos + 1] === 0) throw new Error('RLP 长度前缀非最小（非规范编码）');
    const len = Number(bytesToInt(data.subarray(pos + 1, pos + 1 + ll)));
    if (len <= 55) throw new Error('RLP 长度 < 56 必须用短形式（非规范编码）');
    const start = pos + 1 + ll;
    if (start + len > data.length) throw new Error('RLP 字符串长度超出输入');
    return [data.subarray(start, start + len), start + len];
  }

  let len, start;
  if (b0 < 0xf8) {
    len = b0 - 0xc0;
    start = pos + 1;
  } else {
    const ll = b0 - 0xf7;
    if (pos + 1 + ll > data.length) throw new Error('RLP 长度前缀超出输入');
    if (data[pos + 1] === 0) throw new Error('RLP 长度前缀非最小（非规范编码）');
    len = Number(bytesToInt(data.subarray(pos + 1, pos + 1 + ll)));
    if (len <= 55) throw new Error('RLP 列表长度 < 56 必须用短形式');
    start = pos + 1 + ll;
  }
  if (start + len > data.length) throw new Error('RLP 列表长度超出输入');

  const items = [];
  let p = start;
  const end = start + len;
  while (p < end) {
    const [item, np] = decodeOne(data, p);
    items.push(item);
    p = np;
  }
  if (p !== end) throw new Error('RLP 列表内容不足声明长度');
  return [items, end];
}

function bytesToInt(buf) {
  if (buf.length === 0) return 0n;
  return BigInt('0x' + buf.toString('hex'));
}

/** 整数层校验：把 RLP 字节串解释为整数，拒绝非最小编码。 */
function requireCanonicalInt(buf, field = '') {
  if (!Buffer.isBuffer(buf)) throw new Error(`${field || '字段'} 期望字节串`);
  if (buf.length && buf[0] === 0) {
    throw new Error(`${field || '整数'}存在前导零（非规范编码）：${buf.toString('hex')}`);
  }
  return bytesToInt(buf);
}

// ══════════════════════════════════════════════════════════════════════
// 3. CHAIN 定宽前置函数（规范 §20.1）
// ══════════════════════════════════════════════════════════════════════
//
// 规则（规范 §20.1）：
//   · u8/u32/u64/u256（整数）→ **定宽大端**（不是最小字节串！）
//   · 字节串长度 20 或 32     → 原样拼接，**不加长度前缀**
//   · 其它长度的字节串        → 加 u32 长度前缀
//
// 这是最容易出错的一处：**RLP 用最小字节串，CHAIN 用定宽**。两者混用会让
// 所有签名载荷在不改变任何"看起来正确"的代码的前提下全部改变。
//
// `fields_repr` 里用到的描述符（与向量生成器约定一致）：
//   ("u8", n) ("u32", n) ("u64", n) ("u256", n) ("bytes", hex) ("hash32", hex)

function chainFieldU(width, value) {
  const b = BigInt(value);
  if (b < 0n) throw new Error('CHAIN 只支持无符号整数');
  const max = 1n << BigInt(width * 8);
  if (b >= max) throw new Error(`${width * 8} 位整数溢出：${value}`);
  const out = Buffer.alloc(width);
  let v = b;
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function chainFieldBytes(buf) {
  if (buf.length === 20 || buf.length === 32) return buf;
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length, 0);
  return Buffer.concat([len, buf]);
}

function chain(...fields) {
  const parts = fields.map((f) => {
    if (typeof f === 'object' && f !== null && !Buffer.isBuffer(f) && f.t) {
      const { t, v } = f;
      if (t === 'u8') return chainFieldU(1, v);
      if (t === 'u32') return chainFieldU(4, v);
      if (t === 'u64') return chainFieldU(8, v);
      if (t === 'u256') return chainFieldU(32, v);
      if (t === 'bytes' || t === 'hash32' || t === 'address') {
        return chainFieldBytes(Buffer.isBuffer(v) ? v : Buffer.from(v, 'hex'));
      }
      throw new Error(`未知的 CHAIN 字段类型：${t}`);
    }
    if (Buffer.isBuffer(f)) return chainFieldBytes(f);
    if (typeof f === 'string') return chainFieldBytes(Buffer.from(f, 'utf8'));
    throw new Error('CHAIN 字段必须是 Buffer 或描述符对象');
  });
  return Buffer.concat(parts);
}

module.exports = {
  keccak256, rc: RC, rho: RHO, keccakF1600,
  encode, decode, intToBytes, bytesToInt, requireCanonicalInt,
  chain, chainFieldU, chainFieldBytes,
};
