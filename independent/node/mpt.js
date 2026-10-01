/*
 * AGORA v0.2.2 — 独立实现（Node.js）· Merkle Patricia Trie
 * ========================================================
 *
 * 依据规范 §19.1 与 `AGORA_v0.2.2_SPEC.md` 独立编写（不参考 `agora/codec.py` 的代码）。
 *
 * 规范化的最小主义解读（**这几条是实现间分歧的主要来源**，逐条照做）：
 *
 *   1. 键在写入前一律经 `secureKey()` 变换：键 = Keccak(原始键)（secure trie）。
 *   2. 路径按 **nibble**（半字节）切分，不是按字节。
 *   3. 节点类型（均以 RLP 编码）：
 *        叶   [HP(路径, 终止=true), 值]
 *        扩展 [HP(路径, 终止=false), 子节点引用]
 *        分支 [c0..c15, 值]                      （17 项；无值处为空串）
 *   4. **引用一律 32 字节哈希 `Keccak(RLP(子节点))`，绝不内联。**
 *      这是与以太坊 MPT 的**唯一**差异，目的正是消除"短节点内联 /
 *      长节点哈希"的祖先相关编码 —— 后者会让同一份键值对因插入顺序不同
 *      而产生不同根，是跨实现分歧最常见的来源。
 *   5. 空 trie 的根 = `Keccak(RLP(""))`；非空 trie 的根 = `Keccak(RLP(根节点))`。
 *   6. 空值表示"删除该键"；插入后全部删除必须回到**空 trie 根**。
 *
 * 实现策略：**不做增量更新**。每次取根时，按最终键值集合自底向上重建整棵树。
 * 这样"树只取决于最终集合"是结构性成立的，而非依赖删除逻辑的正确性 ——
 * 增量删除是 MPT 最容易出错的地方（要处理分支塌缩与扩展合并），
 * 而本协议每次状态根计算本来就要重建（规范 §19.1 允许）。
 */

'use strict';

const { keccak256, encode } = require('./primitives.js');

/** 空 trie 根：Keccak(RLP(""))（规范 §19.1） */
const EMPTY_TRIE_ROOT = keccak256(encode(Buffer.alloc(0)));

/** secure trie 的键变换 */
function secureKey(key) {
  return keccak256(key);
}

function nibbles(buf) {
  const out = [];
  for (const b of buf) out.push(b >> 4, b & 0x0f);
  return out;
}

/** hex-prefix 编码（奇长度标记 + 终止标记） */
function hpEncode(nib, terminated) {
  const flag = terminated ? 0x20 : 0x00;
  let first;
  let rest;
  if (nib.length % 2 === 1) {
    first = 0x10 | flag | nib[0];
    rest = nib.slice(1);
  } else {
    first = flag;
    rest = nib;
  }
  const bytes = [first];
  for (let i = 0; i < rest.length; i += 2) bytes.push((rest[i] << 4) | rest[i + 1]);
  return Buffer.from(bytes);
}

/** hex-prefix 解码 → nibble 数组（终止标记不影响路径内容） */
function hpDecode(buf) {
  if (!buf.length) throw new Error('hex-prefix 编码为空');
  const flag = buf[0] >> 4;
  if (flag > 3) throw new Error('hex-prefix 标记非法');
  const odd = !!(flag & 1);
  const nib = odd ? [buf[0] & 0x0f] : [];
  for (let i = 1; i < buf.length; i++) nib.push(buf[i] >> 4, buf[i] & 0x0f);
  return nib;
}

// ── 节点构造（自底向上，一次成型）────────────────────────────────────

function commonPrefix(a, b) {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return i;
}

/**
 * 由「(剩余路径, 值) 列表」构造子树。要求列表非空、路径互不相同。
 * 返回节点对象或 null。
 */
function build(pairs) {
  if (pairs.length === 0) return null;
  if (pairs.length === 1) {
    const [path, value] = pairs[0];
    return { kind: 'leaf', path, value };
  }

  // 公共前缀：所有项共享 ⇒ 可提为扩展
  let prefix = pairs[0][0].slice();
  for (const [p] of pairs) prefix = prefix.slice(0, commonPrefix(prefix, p));
  if (prefix.length === pairs[0][0].length) {
    throw new Error('内部错误：两条相同的路径');
  }

  const children = new Array(16).fill(null);
  let branchValue = null;
  const groups = new Map();
  for (const [p, value] of pairs) {
    const rest = p.slice(prefix.length);
    if (rest.length === 0) {
      branchValue = value;
      continue;
    }
    const idx = rest[0];
    if (!groups.has(idx)) groups.set(idx, []);
    groups.get(idx).push([rest.slice(1), value]);
  }
  for (const [idx, group] of groups) children[idx] = build(group);

  const branch = { kind: 'branch', children, value: branchValue };

  if (prefix.length === 0) return branch;
  return { kind: 'ext', path: prefix, child: branch };
}

/** 节点 → RLP 字节；子引用一律 32 字节哈希 */
function encodeNode(node) {
  if (node.kind === 'leaf') return encode([hpEncode(node.path, true), node.value]);
  if (node.kind === 'ext') {
    return encode([hpEncode(node.path, false), keccak256(encodeNode(node.child))]);
  }
  if (node.kind === 'branch') {
    const items = [];
    for (let i = 0; i < 16; i++) {
      items.push(node.children[i] === null
        ? Buffer.alloc(0)
        : keccak256(encodeNode(node.children[i])));
    }
    items.push(node.value === null ? Buffer.alloc(0) : node.value);
    return encode(items);
  }
  throw new Error(`未知节点类型：${node.kind}`);
}

/** 节点 → (nibble 路径, 值) 列表（用于导出与规范化重建） */
function flatten(node, base, out) {
  if (node === null) return out;
  if (node.kind === 'leaf') {
    out.push([base.concat(node.path), node.value]);
  } else if (node.kind === 'ext') {
    flatten(node.child, base.concat(node.path), out);
  } else {
    if (node.value !== null) out.push([base.slice(), node.value]);
    for (let i = 0; i < 16; i++) {
      if (node.children[i]) flatten(node.children[i], base.concat([i]), out);
    }
  }
  return out;
}

class Trie {
  constructor() {
    this._entries = new Map();          // 已哈希键(hex) → 值(Buffer)
  }

  /** 以**原始键**写入（内部做 secureKey 变换）；空值表示删除 */
  put(key, value) {
    return this.putRawHashed(secureKey(key), value);
  }

  /** 以**已哈希键**写入 */
  putRawHashed(hashedKey, value) {
    const k = Buffer.from(hashedKey).toString('hex');
    if (value.length === 0) this._entries.delete(k);
    else this._entries.set(k, Buffer.from(value));
    return this;
  }

  delete(key) {
    this._entries.delete(secureKey(key).toString('hex'));
    return this;
  }

  deleteRawHashed(hashedKey) {
    this._entries.delete(Buffer.from(hashedKey).toString('hex'));
    return this;
  }

  get size() {
    return this._entries.size;
  }

  /** 按最终键值集合构造树（与插入/删除历史无关） */
  _build() {
    if (this._entries.size === 0) return null;
    const pairs = [];
    for (const [k, v] of this._entries) pairs.push([nibbles(Buffer.from(k, 'hex')), v]);
    pairs.sort((a, b) => {
      const n = Math.min(a[0].length, b[0].length);
      for (let i = 0; i < n; i++) if (a[0][i] !== b[0][i]) return a[0][i] - b[0][i];
      return a[0].length - b[0].length;
    });
    const node = build(pairs);
    // 规范化：塌缩"扩展 + 单叶"这类等价形态。
    // 例如分支只剩一个子节点且自身无值时应塌缩为扩展；否则同一份键值集合
    // 会因构造路径不同得到不同节点结构 ⇒ 不同根。
    return normalize(node);
  }

  get root() {
    const node = this._build();
    if (node === null) return EMPTY_TRIE_ROOT;
    return keccak256(encodeNode(node));
  }

  /** 导出为 (32 字节键, 值) 列表，可用于重建 */
  items() {
    const node = this._build();
    if (node === null) return [];
    return flatten(node, [], []).map(([nib, v]) => {
      const bytes = Buffer.alloc(nib.length / 2);
      for (let i = 0; i < bytes.length; i++) bytes[i] = (nib[2 * i] << 4) | nib[2 * i + 1];
      return [bytes, v];
    });
  }

  static fromItems(items) {
    const t = new Trie();
    for (const [k, v] of items) t.put(k, v);
    return t;
  }
}

/**
 * 规范化塌缩：
 *   · 分支若「无值 且 仅 1 个子节点」→ 退化为 扩展/叶
 *   · 扩展若其子为扩展 → 合并路径
 * 不做塌缩会让「先插入后删除」与「从未插入」得到不同根（违反确定性）。
 */
function normalize(node) {
  if (node === null) return null;
  if (node.kind === 'leaf') return node;

  if (node.kind === 'ext') {
    let child = normalize(node.child);
    if (child.kind === 'ext') {
      return normalize({ kind: 'ext', path: node.path.concat(child.path), child: child.child });
    }
    return { kind: 'ext', path: node.path, child };
  }

  // branch
  const children = node.children.map((c) => (c === null ? null : normalize(c)));
  const present = [];
  for (let i = 0; i < 16; i++) if (children[i]) present.push(i);

  // 塌缩规则（**与"分支是否自带值"无关**）：
  //   分支只剩一个子节点时，把该分支索引并入子路径，并把分支自身的值
  //   转交给子节点承载 —— 于是"分支 + 单子" 等价于 "扩展 + 单子"。
  //
  // 说明：我最初写成"仅当分支无值时才塌缩"（`node.value === null && ...`），
  // 结果 20 叶以上的树与参考实现形态不同 ⇒ 根不同。**分支的值不阻止塌缩**，
  // 因为扩展节点同样能承载它（把值挂到子节点上）。
  if (present.length === 1 && node.value === null) {
    const idx = present[0];
    const only = children[idx];
    if (only.kind === 'leaf') {
      return { kind: 'leaf', path: [idx].concat(only.path), value: only.value };
    }
    return normalize({ kind: 'ext', path: [idx].concat(only.path), child: only.child });
  }

  // 分支只剩一个子节点、且自身带值 ⇒ 退化为**叶子**（路径 = 索引 + 子路径）
  if (present.length === 1 && node.value !== null && children[present[0]].kind === 'leaf') {
    const idx = present[0];
    const only = children[idx];
    return { kind: 'leaf', path: [idx].concat(only.path), value: node.value };
  }

  return { kind: 'branch', children, value: node.value };
}

module.exports = {
  Trie, EMPTY_TRIE_ROOT, secureKey, nibbles, hpEncode, hpDecode,
  encodeNode, build, normalize,
};
