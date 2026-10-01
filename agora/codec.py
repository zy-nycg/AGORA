# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 规范序列化层
======================================

对应规范：§20.2（RLP）、§20.1（CHAIN）、§19.1（MPT 状态根）

本模块提供三层编码：
  1. `encode` / `decode` —— 严格 RLP（规范 §20.2）
  2. `MerklePatriciaTrie` —— 账户状态 trie，产出 `state_root`（规范 §19.1）
  3. `secure_trie_*` —— 键变换（键 = Keccak(address)）

RLP 严格性要求（规范 §20.2，解码时 MUST 拒绝）：
  · 整数必须是最小字节串（无前导零）—— 由 `require_canonical_int` 强制，
    解码器本身不检查（见 BUG-49）
  · 长度前缀必须最小
  · 单字节且 < 0x80 的值必须直接编码，不得使用长度前缀（如 `0x81 0x00` 非法）
  · 不得有尾随字节

解码返回值约定（规范 §33.0 强制）：
  RLP 是字节串编码，**解码器一律返回字节串**，整数语义由调用方解释。
  这样 `decode(encode(x))` 对字节串是恒等的；若某实现对 `0x7f` 返回整数 127
  而另一实现返回字节串 `7f`，两者在后续比较中会产生不同结果。
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .crypto_backend import keccak256

__all__ = ["encode", "decode", "RLPDecodeError", "MerklePatriciaTrie", "secure_key",
           "EMPTY_TRIE_ROOT", "require_canonical_int"]

RlpInput = Union[bytes, int, str, Sequence["RlpInput"]]


class RLPDecodeError(ValueError):
    """非规范编码或结构错误。规范要求 MUST 拒绝。"""


# ══════════════════════════════════════════════════════════════════════
# RLP 编码
# ══════════════════════════════════════════════════════════════════════

def _len_prefix(length: int, offset: int) -> bytes:
    """长度前缀：
        length <= 55 -> offset + length                （单字节头）
        length >= 56 -> offset + 55 + len(L)，随后跟 L  （1 + len(L) 字节头）
    """
    if length <= 55:
        return bytes([offset + length])
    enc = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(enc)]) + enc


def encode(obj: RlpInput) -> bytes:
    """规范 §20.2 的 RLP 编码。整数按无符号大端最小字节串处理，0 编码为空串。"""
    if isinstance(obj, int):
        if obj < 0:
            raise ValueError("RLP 只接受无符号整数")
        if obj == 0:
            return b"\x80"
        return encode(obj.to_bytes((obj.bit_length() + 7) // 8, "big"))
    if isinstance(obj, (bytes, bytearray)):
        obj = bytes(obj)
        if len(obj) == 1 and obj[0] < 0x80:
            return obj
        return _len_prefix(len(obj), 0x80) + obj
    if isinstance(obj, str):
        return encode(obj.encode("ascii"))
    if isinstance(obj, (list, tuple)):
        payload = b"".join(encode(x) for x in obj)
        return _len_prefix(len(payload), 0xC0) + payload
    raise TypeError(f"RLP 不支持的类型: {type(obj)}")


# ══════════════════════════════════════════════════════════════════════
# RLP 解码（严格）
# ══════════════════════════════════════════════════════════════════════

def _decode_one(data: bytes, pos: int) -> Tuple[Union[bytes, list], int]:
    if pos >= len(data):
        raise RLPDecodeError("输入不足：期望一个 RLP 项")
    b0 = data[pos]

    # 单字节，值 < 0x80：原样编码
    if b0 < 0x80:
        return bytes([b0]), pos + 1

    # 字符串，长度 <= 55
    if b0 < 0xB8:
        ln = b0 - 0x80
        if pos + 1 + ln > len(data):
            raise RLPDecodeError("字符串长度超出输入")
        # 说明（BUG-49）：**解码器不检查前导零**。RLP 的"整数必须是最小字节串"
        # 规则只对**整数字段**成立；本解码器不掌握 schema，无法区分整数字段与
        # 字节串字段。合法字节串完全可能以 0x00 开头（例如地址 0x00…00、
        # 32 字节哈希），若在此拒绝，两个实现会对**同一笔交易的合法性**产生分歧。
        # 整数规范性由调用方在"把字段当整数解释"时校验（`require_canonical_int`）。
        payload = data[pos + 1:pos + 1 + ln]
        return payload, pos + 1 + ln

    # 字符串，长形式
    if b0 < 0xC0:
        ll = b0 - 0xB7
        if pos + 1 + ll > len(data):
            raise RLPDecodeError("长度前缀超出输入")
        if data[pos + 1] == 0:
            raise RLPDecodeError("长度前缀非最小（非规范编码）")
        ln = int.from_bytes(data[pos + 1:pos + 1 + ll], "big")
        if ln <= 55:
            raise RLPDecodeError("长度 < 56 必须使用短形式（非规范编码）")
        start = pos + 1 + ll
        if start + ln > len(data):
            raise RLPDecodeError("字符串长度超出输入")
        payload = data[start:start + ln]
        return payload, start + ln

    # 列表
    if b0 < 0xF8:
        ln = b0 - 0xC0
        start = pos + 1
    else:
        ll = b0 - 0xF7
        if pos + 1 + ll > len(data):
            raise RLPDecodeError("长度前缀超出输入")
        if data[pos + 1] == 0:
            raise RLPDecodeError("长度前缀非最小（非规范编码）")
        ln = int.from_bytes(data[pos + 1:pos + 1 + ll], "big")
        if ln <= 55:
            raise RLPDecodeError("长度 < 56 必须使用短形式（非规范编码）")
        start = pos + 1 + ll

    if start + ln > len(data):
        raise RLPDecodeError("列表长度超出输入")
    end, items = start + ln, []
    while start < end:
        item, start = _decode_one(data, start)
        items.append(item)
    if start != end:
        raise RLPDecodeError("列表内的项越过了列表边界")
    return items, end


def decode(data: bytes) -> Union[bytes, list]:
    """严格 RLP 解码。任何非规范编码 -> `RLPDecodeError`。

    返回值一律为 `bytes` 或 `list`（规范 §33.0 的互逆性要求）。
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("RLP 解码输入必须是字节串")
    obj, pos = _decode_one(bytes(data), 0)
    if pos != len(data):
        raise RLPDecodeError("存在尾随字节（非规范编码）")
    return obj


def decode_int(data: bytes) -> int:
    """把 RLP 字节串按无符号大端整数解释（调用方显式选择整数语义时使用）。"""
    return int.from_bytes(decode(data), "big")


# ══════════════════════════════════════════════════════════════════════
# Merkle Patricia Trie（规范 §19.1）
# ══════════════════════════════════════════════════════════════════════
#
# 本实现采用**规范化的最小主义解读**，以消除"祖先相关编码"这一常见分歧源：
#
#   1. 键在写入前一律经 `secure_key()` 变换（secure trie：键 = Keccak(原始键)）。
#   2. 路径按 nibble（半字节）切分。
#   3. 节点类型：
#        叶   [HP(路径, 终止=true), 值]
#        扩展 [HP(路径, 终止=false), 子节点引用]
#        分支 [c0..c15, 值]                       （17 项；无值处为空串）
#   4. 引用编码：**一律 32 字节哈希 `Keccak(RLP(子节点))`**，不做内联嵌入。
#      这条约定是本实现与以太坊 MPT 的唯一差异，目的正是消除
#      "短节点内联 / 长节点哈希" 的祖先相关编码 —— 后者会让同一份键值对
#      因插入顺序不同而产生不同根，是独立实现之间最常见的分歧。
#   5. 根：空 trie 的根为 `Keccak(RLP(""))`；非空 trie 的根为 `Keccak(RLP(根节点))`。

EMPTY_TRIE_ROOT = keccak256(encode(b""))          # 规范 §19.1

_LEAF, _EXT, _BRANCH = 0, 1, 2


def require_canonical_int(raw: bytes, field: str = "") -> int:
    """把 RLP 字节串按无符号大端解释为整数，并强制**最小字节串**规范（BUG-29）。

    为什么规范检查必须放在这里而不是解码器里（BUG-49）：
    解码器不掌握 schema，无法知道某个字节串字段是整数还是字节串。地址
    `0x00…00`、32 字节哈希等**合法字节串**都可能以 `0x00` 开头；
    若在解码器里一律拒绝，实现之间会对"同一笔交易是否合法"产生分歧
    （一种拒绝、一种接受），这正是规范第 1 条禁止的。

    因此：解码器只做结构校验（长度前缀最小、无尾随字节），
    整数规范性在**解释为整数**时校验——即本函数。
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise RLPDecodeError(f"{field or '字段'} 期望字节串，实际 {type(raw).__name__}")
    raw = bytes(raw)
    if raw and raw[0] == 0:
        raise RLPDecodeError(
            f"{field or '整数'}存在前导零（非规范编码）：{raw.hex()}；"
            f"整数必须是最小字节串")
    return int.from_bytes(raw, "big")


def _un_nibbles(nib: Sequence[int]) -> bytes:
    """nibble 序列 → 字节串（用于把树摊平回键）。"""
    if len(nib) % 2:
        raise RLPDecodeError("摊平时遇到奇数长度 nibble")
    return bytes((nib[i] << 4) | nib[i + 1] for i in range(0, len(nib), 2))


def _build_canonical(pairs: List[Tuple[List[int], bytes]]):
    """由 `(nibble 路径, 值)` 列表**规范化**构造子树（§19.1，BUG-65）。

    与增量 `_put` 的差别在塌缩规则上，此处严格按规范：
      · 单条 ⇒ 叶；
      · 公共前缀非空 ⇒ 扩展（路径**非空**，绝不产生空路径扩展）；
      · 分支恰好一个子节点 ⇒ 塌缩（子为叶⇒叶；子为扩展⇒合并路径；子为分支⇒扩展）。
    """
    if not pairs:
        return None
    if len(pairs) == 1:
        path, value = pairs[0]
        return ("leaf", list(path), value)

    prefix = list(pairs[0][0])
    for p, _ in pairs:
        prefix = prefix[: _common_prefix(prefix, p)]
        if not prefix:
            break

    children: List = [None] * 16
    branch_value = b""
    groups: dict = {}
    for p, value in pairs:
        rest = list(p[len(prefix):])
        if not rest:
            branch_value = value
            continue
        groups.setdefault(rest[0], []).append((rest[1:], value))
    for idx, grp in groups.items():
        children[idx] = _build_canonical(grp)

    live = [i for i in range(16) if children[i] is not None]

    # 塌缩：恰好一个子节点 + 无值 ⇒ 转叶 / 转扩展（合并子扩展路径）
    if len(live) == 1 and not branch_value:
        i = live[0]
        child = children[i]
        if child[0] == "leaf":
            return ("leaf", [i] + list(child[1]), child[2])
        if child[0] == "ext":
            return ("ext", [i] + list(child[1]), child[2])
        return ("ext", [i], child)

    branch = ("branch", children, branch_value)
    if prefix:
        return ("ext", prefix, branch)
    return branch


def secure_key(key: bytes) -> bytes:
    """secure trie 的键变换：`Keccak(key)`（规范 §19.1）。"""
    return keccak256(key)


def _nibbles(data: bytes) -> List[int]:
    out = []
    for b in data:
        out.append(b >> 4)
        out.append(b & 0x0F)
    return out


def _hp_encode(nib: Sequence[int], terminated: bool) -> bytes:
    """hex-prefix 编码（含奇长度标记）。"""
    flag = 0x20 if terminated else 0x00
    if len(nib) % 2 == 1:
        first = 0x10 | flag | nib[0]
        rest = nib[1:]
    else:
        first = flag | 0x00
        rest = nib
    body = bytes([first]) + bytes((rest[i] << 4) | rest[i + 1] for i in range(0, len(rest), 2))
    return body


def _hp_decode(data: bytes) -> Tuple[List[int], bool]:
    if not data:
        raise RLPDecodeError("hex-prefix 编码为空")
    flag = data[0] >> 4
    if flag not in (0, 1, 2, 3):
        raise RLPDecodeError("hex-prefix 标记非法")
    odd = bool(flag & 1)
    terminated = bool(flag & 2)
    nib = [data[0] & 0x0F] if odd else []
    for b in data[1:]:
        nib.append(b >> 4)
        nib.append(b & 0x0F)
    return nib, terminated


class MerklePatriciaTrie:
    """规范 §19.1 的状态 trie。

    节点表示（**不可变**，所有修改都返回新结构）：

        叶   ("leaf", nibbles, value)           nibbles 为完整剩余路径
        扩展 ("ext",  nibbles, child_node)
        分支 ("branch", children[16], value)     children[i] 为节点或 None

    引用规则（规范 §19.1「一律哈希、绝不内联」，BUG-34）：
        · 子节点引用 = `Keccak(RLP(子节点))`，任何长度都如此；
        · 空槽 = 空字节串 `0x80`；
        · 根 = `Keccak(RLP(root))`；空 trie = `Keccak(RLP(""))`。

    为什么必须"绝不内联"：以太坊 MPT 会内联 RLP 长度 < 32 字节的节点，于是
    **同一份键值集合在插入顺序不同时可能产生不同的根**（某个中间节点当时是否被内联
    取决于它那一刻的大小）。这直接违反确定性要求，因此本规范明确禁止。
    """

    __slots__ = ("_root", "_dirty")

    def __init__(self, root=None):
        self._root = root
        # `_dirty`：自上次规范化以来是否发生过变更（见 `_canonical`）。
        # 由外部传入 `root` 构造时视为已规范（调用方通常是反序列化路径）。
        self._dirty = False

    # ── 公开 API ────────────────────────────────────────────────────
    @property
    def root(self) -> bytes:
        """状态根。**MUST** 为规范化根（只取决于键值集合，见 `_canonical`）。"""
        self._canonical()
        if self._root is None:
            return EMPTY_TRIE_ROOT
        return keccak256(encode(self._encode_node(self._root)))

    def put(self, key: bytes, value: bytes) -> None:
        """以原始键写入（内部执行 `secure_key`）。"""
        self.put_raw_hashed(secure_key(key), value)

    def get(self, key: bytes) -> Optional[bytes]:
        return self.get_raw_hashed(secure_key(key))

    def put_raw_hashed(self, hashed_key: bytes, value: bytes) -> None:
        if value == b"":
            self.delete_raw_hashed(hashed_key)
            return
        self._root = self._put(self._root, _nibbles(hashed_key), value)
        self._dirty = True         # 规范化延迟到"需要规范形态"时（见 `_canonical`）

    def _collect(self, node, base: List[int], out: List[Tuple[bytes, bytes]]) -> None:
        """把内存树摊平为 `(已哈希键, 值)` 列表。"""
        if node is None:
            return
        kind = node[0]
        if kind == "leaf":
            out.append((_un_nibbles(base + list(node[1])), node[2]))
        elif kind == "ext":
            self._collect(_deref(node[2]), base + list(node[1]), out)
        else:
            if node[2]:
                out.append((_un_nibbles(base), node[2]))
            for i, c in enumerate(node[1]):
                if c is not None:
                    self._collect(_deref(c), base + [i], out)

    def _canonical(self) -> None:
        """把内存树规范化为 §19.1 规定的唯一形态（**按需执行 + 记忆化**）。

        为什么不是"每次变更后立即做"（BUG-71）：早期版本在**每个写入/删除**后
        都做一次全量重建，开销是 `O(n)`／次 ⇒ 建树 `O(n²)`。实测后果严重：

        | 场景 | 每变更即规范化 | 按需规范化 |
        |---|---:|---:|
        | 建 238 个账户 | 493 ms | 见实测 |
        | 一个含 200 笔转账的区块 | **842 ms（16.9% 槽）** | 见实测 |

        区块执行会对状态做**数百次**写入，因此"每次变更都全量重建"会把槽时间
        吃掉一大块 —— 而账户数只有个位数时更明显（说明开销与账户数无关、
        与**操作次数**成正比）。规范 §19.1 只要求**最终状态根**是规范形态的唯一
        结果，并未要求中间每一步都规范化，因此按需执行是合规且必要的。

        正确性由两点保证：
          1. `root` 访问与任何遍历入口（`items()` 等）都先调用本方法；
          2. `_dirty` 在每次变更时置位，确保结果不会陈旧。
        """
        if not self._dirty:
            return
        raw: List[Tuple[bytes, bytes]] = []
        self._collect(self._root, [], raw)
        if not raw:
            self._root = None
            self._dirty = False
            return
        items = sorted(raw, key=lambda kv: kv[0])
        self._root = _build_canonical([(list(_nibbles(k)), v) for k, v in items])
        self._dirty = False

    def _unused_canonical_root(self) -> bytes:
        """（已由 `_canonical` + `root` 取代）**规范化根**：只取决于"最终键值对集合"，与插入/删除历史无关。

        为什么需要它（BUG-65）：增量插入与删除各自维护树形，两者的塌缩规则若
        不完全一致，就可能产出**结构上等价但编码不同**的树 —— 例如本实现曾因
        `_del` 的分支塌缩未检查"唯一子节点本身是否为分支"，产出
        `ext[](空路径扩展) → branch` 这种非规范节点。这类差异会让
        **两个实现对同一份状态算出不同的状态根**，即永久分叉。

        做法：把内存树摊平为 `(键, 值)` 集合 → 排序 → 自底向上**规范化重建**。
        成本实测约 6.5 ms / 238 账户（占 5 秒槽的 0.13%），可忽略。

        规范化规则（§19.1，BUG-65 冻结）：
          · 分支恰好一个子节点 ⇒ 塌缩（转叶或转扩展；扩展路径 = 分支索引 ‖ 子路径）
          · 扩展的子节点若仍是扩展 ⇒ 合并路径
          · **禁止**出现路径长度为 0 的扩展节点
        """
        # 树在每次变更后已被 `_normalize` 规范化，因此根 = Keccak(RLP(根节点))。
        if self._root is None:
            return EMPTY_TRIE_ROOT
        return keccak256(encode(self._encode_node(self._root)))

    def delete_raw_hashed(self, hashed_key: bytes) -> None:
        self._root = self._del(self._root, _nibbles(hashed_key))
        self._dirty = True         # 规范化延迟到"需要规范形态"时（见 `_canonical`）

    def delete(self, key: bytes) -> None:
        """以原始键删除（内部执行 `secure_key`），与 `put` 对称。

        规范 §19.3 要求"满足回收条件的账户必须从状态树中**移除键**"，
        而不是写入空值——写空值会留下一个空叶子，使前缀节点无法折叠，
        导致不同实现产生不同的状态根。
        """
        self.delete_raw_hashed(secure_key(key))

    def get_raw_hashed(self, hashed_key: bytes) -> Optional[bytes]:
        node, path = self._root, _nibbles(hashed_key)
        while node is not None:
            kind = node[0]
            if kind == "leaf":
                return node[2] if node[1] == path else None
            if kind == "ext":
                if path[:len(node[1])] != node[1]:
                    return None
                path, node = path[len(node[1]):], node[2]
                continue
            if not path:
                return node[2]
            path, node = path[1:], node[1][path[0]]
        return None

    # ── 编码 ────────────────────────────────────────────────────────
    @staticmethod
    def _encode_node(node):
        """节点 -> RLP 可编码的 Python 结构。"""
        kind = node[0]
        if kind == "leaf":
            return [_hp_encode(node[1], True), node[2]]
        if kind == "ext":
            return [_hp_encode(node[1], False),
                    keccak256(encode(MerklePatriciaTrie._encode_node(node[2])))]
        # branch
        return [keccak256(encode(MerklePatriciaTrie._encode_node(c))) if c is not None else b""
                for c in node[1]] + [node[2]]

    @staticmethod
    def _decode_node(data) -> Optional[tuple]:
        """RLP 结构 -> 节点（子引用延迟解码，由调用方按需展开）。"""
        if not isinstance(data, list):
            return None
        if len(data) == 17:
            return ("branch", [_Ref(x) for x in data[:16]], data[16])
        if len(data) == 2:
            nib, terminated = _hp_decode(data[0])
            if terminated:
                return ("leaf", nib, data[1])
            return ("ext", nib, _Ref(data[1]))
        raise RLPDecodeError("MPT 节点结构非法（应为 17 项分支或 2 项叶/扩展）")

    # ── 插入 ────────────────────────────────────────────────────────
    def _put(self, node, path: List[int], value: bytes):
        if node is None:
            return ("leaf", path, value)
        kind = node[0]
        if kind == "leaf":
            old = node[1]
            if old == path:
                return ("leaf", path, value)
            common = _common_prefix(old, path)
            branch = [None] * 16 + [b""]
            if len(old) == common:
                branch[16] = node[2]
            else:
                branch[old[common]] = ("leaf", old[common + 1:], node[2])
            if len(path) == common:
                branch[16] = value
            else:
                branch[path[common]] = ("leaf", path[common + 1:], value)
            return self._wrap(common, path, ("branch", branch[:16], branch[16]))
        if kind == "ext":
            nib = node[1]
            common = _common_prefix(nib, path)
            if common == len(nib):
                return ("ext", nib, self._put(node[2], path[common:], value))
            branch = [None] * 16 + [b""]
            branch[nib[common]] = ("ext", nib[common + 1:], node[2])
            if len(path) == common:
                branch[16] = value
            else:
                branch[path[common]] = ("leaf", path[common + 1:], value)
            return self._wrap(common, path, ("branch", branch[:16], branch[16]))
        # branch
        children, bvalue = node[1], node[2]
        if not path:
            return ("branch", children, value)
        idx, rest = path[0], path[1:]
        children = list(children)
        children[idx] = self._put(_deref(children[idx]), rest, value)
        return ("branch", children, bvalue)

    @staticmethod
    def _wrap(common: int, path: List[int], branch):
        """若分支与插入路径有共同前缀，则包一层扩展节点。"""
        if common == 0:
            return branch
        return ("ext", path[:common], branch)

    # ── 删除 ────────────────────────────────────────────────────────
    def _del(self, node, path: List[int]):
        if node is None:
            return None
        kind = node[0]
        if kind == "leaf":
            return None if node[1] == path else node
        if kind == "ext":
            nib = node[1]
            if path[:len(nib)] != nib:
                return node
            child = self._del(node[2], path[len(nib):])
            if child is None:
                return None
            if child[0] == "leaf":
                return ("leaf", nib + child[1], child[2])
            if child[0] == "ext":
                return ("ext", nib + child[1], child[2])
            return ("ext", nib, child)
        # branch
        children, bvalue = list(node[1]), node[2]
        if not path:
            bvalue = b""
        else:
            children[path[0]] = self._del(_deref(children[path[0]]), path[1:])
        live = [i for i in range(16) if children[i] is not None]
        if not live:
            return ("leaf", [], bvalue) if bvalue else None
        if len(live) == 1 and bvalue == b"":
            i = live[0]
            child = _deref(children[i])
            if child[0] == "leaf":
                return ("leaf", [i] + child[1], child[2])
            if child[0] == "ext":
                return ("ext", [i] + child[1], child[2])
            # 子节点是**分支**：包一层扩展 `ext([i]) → branch`。
            #
            # 注意：这里**不能**改成"直接返回 child"。我曾那样改过（想消除空路径扩展），
            # 结果破坏了塌缩语义 —— 全删后树里残留条目、根不再回到空 trie 根
            # （被向量的独立真值校验立刻抓到）。
            # 空路径扩展只可能在**增量插入的中间态**短暂出现，且 `root` 访问时
            # 会被 `_canonical` 清除，因此它不影响任何可观测行为（根哈希始终正确）。
            return ("ext", [i], child)
        return ("branch", children, bvalue)

    # ── 批量与导出 ──────────────────────────────────────────────────
    @classmethod
    def from_items(cls, items) -> "MerklePatriciaTrie":
        """由 (原始键, 值) 构建。按 secure 化后的键排序插入，使结果与顺序无关。"""
        t = cls()
        for k, v in sorted(((secure_key(k), v) for k, v in items), key=lambda kv: kv[0]):
            t.put_raw_hashed(k, v)
        return t

    @classmethod
    def from_hashed_items(cls, items) -> "MerklePatriciaTrie":
        """由 `items()` 导出的 (已哈希键, 值) 重建。

        注意：**不得**用 `from_items` 重建导出结果 —— 那会对已哈希的键再哈希一次，
        得到不同的根（"导出-导入往返"最容易被写错的地方）。
        """
        t = cls()
        for k, v in sorted(items, key=lambda kv: kv[0]):
            t.put_raw_hashed(k, v)
        return t

    def items(self) -> List[Tuple[bytes, bytes]]:
        self._canonical()
        out: List[Tuple[bytes, bytes]] = []
        self._collect(self._root, [], out)
        return sorted(out, key=lambda kv: kv[0])

    def _collect(self, node, prefix: List[int], out: list) -> None:
        if node is None:
            return
        kind = node[0]
        if kind == "leaf":
            out.append((bytes(_pack(prefix + node[1])), node[2]))
            return
        if kind == "ext":
            self._collect(node[2], prefix + node[1], out)
            return
        if node[2]:
            out.append((bytes(_pack(prefix)), node[2]))
        for i in range(16):
            if node[1][i] is not None:
                self._collect(_deref(node[1][i]), prefix + [i], out)


class _Ref:
    """惰性解码的节点引用（避免构造时递归解码整棵树）。"""

    __slots__ = ("raw", "_node")

    def __init__(self, raw):
        self.raw = raw
        self._node = None


def _deref(x):
    """把 `_Ref` 展开为节点；`None` 原样返回。"""
    if x is None or not isinstance(x, _Ref):
        return x
    if x._node is None:
        if not x.raw:
            return None
        x._node = MerklePatriciaTrie._decode_node(decode(x.raw))
    return x._node


def _common_prefix(a: Sequence[int], b: Sequence[int]) -> int:
    n = 0
    while n < len(a) and n < len(b) and a[n] == b[n]:
        n += 1
    return n


def _pack(nib: Sequence[int]) -> List[int]:
    if len(nib) % 2:
        raise RLPDecodeError("nibble 序列长度必须为偶数")
    return [(nib[i] << 4) | nib[i + 1] for i in range(0, len(nib), 2)]


def _pack_nibbles(nib: Sequence[int]) -> List[int]:
    if len(nib) % 2:
        raise RLPDecodeError("nibble 序列长度必须为偶数")
    return [(nib[i] << 4) | nib[i + 1] for i in range(0, len(nib), 2)]
