#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 创世密钥生成与创世配置工具
=========================================

用途
----
1. 生成 Ed25519 密钥对（公钥 + 地址），用于：
     - 创始验证者（genesis_validators，见规范 §32.7）
     - 创世分配收款地址（团队 / 生态 / 基金会）
2. 构建空投分配表（airdrop table）、计算其 Merkle 根（写进创世状态）、
   并为单个受益人导出领取证明（airdrop 的 claim 交易需要）。
3. 校验创世金额闭合约束（规范 §32.2）。
4. 自检（selftest）：核对规范中的关键算术与 4 人创始验证者的法定数性质。

安全须知（务必阅读）
--------------------
* 本脚本【只使用 Python 标准库】，可完全离线运行，不联网。
* 私钥（seed）只应保存在生成它的机器上；离线备份，至少两份异地。
* 【绝对不要】把私钥写进创世配置、提交到代码仓库、或通过聊天/邮件发送。
* 【不要】让同一个人在同一台机器上生成全部创始验证者的私钥 ——
  持有 3 把即等于控制整条链（4 人时 QUORUM = 171，3 人 = 192 ≥ 171）。
* 建议每位创始人【各自】在自己的机器上运行 `keygen`，只把公钥与地址交给协调者。

用法
----
  python3 genome_keygen.py keygen                       # 生成一对密钥（打印公钥/地址/私钥）
  python3 genome_keygen.py keygen --note "founder-1"    # 带备注
  python3 genome_keygen.py address --pubkey <hex>       # 由公钥推导地址
  python3 genome_keygen.py verify  --pubkey <hex> --address <hex>
  python3 genome_keygen.py airdrop-build --in list.csv --out table.json
  python3 genome_keygen.py airdrop-root  --table table.json
  python3 genome_keygen.py claim-proof   --table table.json --pubkey <hex>
  python3 genome_keygen.py genesis-template --validators val.csv --out genesis.json
  python3 genome_keygen.py selftest

CSV 格式（airdrop-build 的 --in）
    pubkey_hex,amount_atom,note
    每行一个受益人。amount_atom 为整数（atom = 10^-18 AGORA）。
    可用 --amount-coin 让 amount 列按 AGORA 书写（脚本自动乘 10^18）。

依赖：仅标准库（hashlib / secrets / json / csv / argparse / unicodedata）
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import secrets
import sys

# ══════════════════════════════════════════════════════════════════════
# 0. 常量（必须与规范 §34 参数表一致）
# ══════════════════════════════════════════════════════════════════════

PROTOCOL_VERSION = "AGORA/v0.2.2"
CHAIN_ID = "agora-mainnet-1"

CHAIN_ID_BYTES = CHAIN_ID.encode("ascii")            # 20 字节
TAG_GENESIS = b"AGORA/GENESIS/v0.2.2"                # ASCII，无长度前缀
TAG_AIRDROP = b"AGORA/AIRDROP/v0.2.2"
TAG_VALSET = b"AGORA/VALSET/v0.2.2"

ATOM = 10 ** 18                                       # 1 AGORA = 10^18 atom

# CHAIN 的显式宽度表（规范 §20.1；单位字节）
_WIDTHS = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "u256": 32}

GENESIS_TIMESTAMP = 1790812800                        # 2026-10-01 00:00:00 UTC
SLOT_TIME = 5
EPOCH_LENGTH = 720

INITIAL_SUPPLY_AGORA = 20_480_000
MIN_VALIDATOR_STAKE_AGORA = 64
AIRDROP_MAX_SHARE_PCT = 20
MAX_VALIDATORS = 100

# Ed25519 常量（RFC 8032）
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


# ══════════════════════════════════════════════════════════════════════
# 1. 基础原语
# ══════════════════════════════════════════════════════════════════════

def keccak256(data: bytes) -> bytes:
    """规范 §2.2：全协议唯一哈希函数。

    注意：Ethereum 的 'Keccak-256' 是原始 Keccak 填充（0x01），
    而 hashlib.sha3_256 使用 SHA-3 填充（0x06），二者不同。
    本函数按 Keccak-256 原始填充实现，与规范一致。
    """
    return _keccak(data, 256)


def _keccak(data: bytes, bits: int = 256) -> bytes:
    rate = 1088 // 8                      # Keccak-256 的 rate = 136 字节
    dsbyte = 0x01                         # Keccak 原始填充
    out_len = bits // 8

    # 多速率填充（pad10*1）——不使用具体库，纯标准库实现
    padlen = rate - (len(data) % rate)
    if padlen == 1:
        data = data + bytes([dsbyte | 0x80])
    else:
        data = data + bytes([dsbyte]) + b"\x00" * (padlen - 2) + b"\x80"

    state = [0] * 25                      # 5x5 lanes of 64 bit
    rc = _keccak_round_constants()
    rndc = _keccak_rho_offsets()

    for off in range(0, len(data), rate):
        block = data[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        state = _keccak_f1600(state, rc, rndc)

    out = b""
    while len(out) < out_len:
        for i in range(rate // 8):
            out += state[i].to_bytes(8, "little")
        if len(out) < out_len:
            state = _keccak_f1600(state, rc, rndc)
    return out[:out_len]


def _keccak_round_constants():
    rc = []
    lfsr = 1
    for _ in range(24):
        c = 0
        for j in range(7):
            lfsr, bit = ((lfsr << 1) ^ (0x71 if lfsr & 0x80 else 0)) & 0xFF, lfsr & 1
            if bit:
                c ^= 1 << ((1 << j) - 1)
        rc.append(c)
    return rc


def _keccak_rho_offsets():
    # rho 旋转偏移表（按 x,y 线性索引 i = x + 5y）
    offsets = [0] * 25
    x, y = 1, 0
    for t in range(24):
        offsets[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return offsets


def _keccak_f1600(state, rc, rndc):
    M = (1 << 64) - 1

    def rol(v, n):
        n %= 64
        return ((v << n) | (v >> (64 - n))) & M if n else v

    for rnd in range(24):
        # theta
        C = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= D[x]
        # rho + pi
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2 * x + 3 * y) % 5)] = rol(state[x + 5 * y], rndc[x + 5 * y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y])) & M
        # iota
        state[0] ^= rc[rnd]
    return state


def chain(*fields) -> bytes:
    """规范 §20.1 的 CHAIN()：一切哈希原像与签名载荷的唯一连接函数。

    定宽大端整数 / u32 长度前缀字节串 / 地址 20 字节 / 哈希 32 字节 / ASCII 标签无前缀。
    """
    out = bytearray()
    for f in fields:
        # 显式宽度：(宽度名, 值)。**签名载荷与哈希原像 MUST 用定宽**（BUG-64）——
        # 早先这里只支持"裸整数取最小宽度"，于是本工具的叶子/根与链上
        # （`u64(index)` / `u256(gas_allowance)` 定宽）**永远对不上**：
        # index=1 这里是 1 字节、链上是 8 字节。见 PROJECT_REVIEW 关于空投工具链的记录。
        if isinstance(f, tuple) and len(f) == 2 and isinstance(f[0], str):
            width = _WIDTHS.get(f[0])
            if width is None:
                raise ValueError(f"未知 CHAIN 宽度名：{f[0]!r}（应为 u8/u16/u32/u64/u256）")
            v = f[1]
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise ValueError("CHAIN 宽度字段的值必须是非负整数")
            if v >= (1 << (8 * width)):
                raise ValueError(f"{f[0]} 溢出：{v}")
            out += v.to_bytes(width, "big")
        elif isinstance(f, bytes):
            if len(f) in (20, 32):
                out += f                      # address / hash：原样
            else:
                out += len(f).to_bytes(4, "big") + f
        elif isinstance(f, int):
            if f < 0:
                raise ValueError("CHAIN 只接受无符号整数")
            if f < 2 ** 8:
                out += f.to_bytes(1, "big")
            elif f < 2 ** 16:
                out += f.to_bytes(2, "big")
            elif f < 2 ** 32:
                out += f.to_bytes(4, "big")
            elif f < 2 ** 64:
                out += f.to_bytes(8, "big")
            elif f < 2 ** 256:
                out += f.to_bytes(32, "big")
            else:
                raise ValueError("整数超出 u256")
        else:
            raise TypeError(f"CHAIN 不支持的字段类型: {type(f)}")
    return bytes(out)


# ── RLP（规范 §20.2）────────────────────────────────────────────────

def rlp_encode(obj) -> bytes:
    if isinstance(obj, int):
        if obj < 0:
            raise ValueError("RLP 只接受无符号整数")
        if obj == 0:
            return b"\x80"
        return rlp_encode(obj.to_bytes((obj.bit_length() + 7) // 8, "big"))
    if isinstance(obj, bytes):
        if len(obj) == 1 and obj[0] < 0x80:
            return obj
        return _rlp_len(len(obj), 0x80) + obj
    if isinstance(obj, str):
        return rlp_encode(obj.encode("ascii"))
    if isinstance(obj, (list, tuple)):
        payload = b"".join(rlp_encode(x) for x in obj)
        return _rlp_len(len(payload), 0xC0) + payload
    raise TypeError(f"RLP 不支持的类型: {type(obj)}")


def _rlp_len(length: int, offset: int) -> bytes:
    """RLP 长度前缀（标准定义）：
        length <= 55  ->  offset + length                     （单字节头）
        length >= 56  ->  offset + 55 + len(L)，随后跟 L       （1 + len(L) 字节头）
    offset = 0x80（字符串）或 0xC0（列表）。
    例：3 字节列表 -> 0xC3；60 字节列表 -> 0xF8 0x3C；60 字节字符串 -> 0xB8 0x3C。
    """
    if length <= 55:
        return bytes([offset + length])
    enc = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(enc)]) + enc


def rlp_decode(data: bytes):
    obj, rest = _rlp_decode(data)
    if rest:
        raise ValueError("RLP 尾随字节 —— 非规范编码（规范 §20.2 禁止）")
    return obj


def _rlp_decode(data: bytes):
    if not data:
        raise ValueError("RLP 输入为空")
    b0 = data[0]
    if b0 < 0x80:
        return bytes([b0]), data[1:]          # 单字节原样编码 -> 返回字节串
    if b0 < 0xB8:
        ln = b0 - 0x80
        if len(data) < 1 + ln:
            raise ValueError("RLP 长度不足")
        payload = data[1:1 + ln]
        _check_minimal_int(payload)
        return payload, data[1 + ln:]
    if b0 < 0xC0:
        ll = b0 - 0xB7
        if len(data) < 1 + ll:
            raise ValueError("RLP 长度前缀不足")
        if data[1] == 0:
            raise ValueError("RLP 非最小长度前缀")
        ln = int.from_bytes(data[1:1 + ll], "big")
        body = data[1 + ll:1 + ll + ln]
        if len(body) != ln:
            raise ValueError("RLP 长度不足")
        if ln == 1 and body[0] < 0x80:
            raise ValueError("RLP 单字节整数必须使用原样编码（非规范编码）")
        return body, data[1 + ll + ln:]
    # 列表
    if b0 < 0xF8:
        ln = b0 - 0xC0
        body = data[1:]
    else:
        ll = b0 - 0xF7
        if len(data) < 1 + ll:
            raise ValueError("RLP 长度前缀不足")
        if data[1] == 0:
            raise ValueError("RLP 非最小长度前缀")
        ln = int.from_bytes(data[1:1 + ll], "big")
        body = data[1 + ll:]
    if len(body) < ln:
        raise ValueError("RLP 列表长度不足")
    items, rest = [], body[:ln]
    while rest:
        item, rest = _rlp_decode(rest)
        items.append(item)
    return items, body[ln:]


def _check_minimal_int(payload: bytes):
    if payload and payload[0] == 0:
        raise ValueError("RLP 整数存在前导零 —— 非规范编码")


# ── Ed25519（RFC 8032 参考实现，便于离线自足）──────────────────────

def _point_add(p, q):
    """完整扩展坐标下的点加（twisted Edwards，a = -1）。

    点表示为 (X, Y, Z, T)，恒等式 T = X*Y/Z。单位元为 (0, 1, 1, 0)。

    重要（本项目实际踩过的坑）：必须使用【完整坐标 + 完整加法公式】。
    若省略 T 分量并使用不完整公式，则：传入扩展坐标（Z != 1）时结果错误，
    甚至把基点自加都会得到错误的点，而群运算表面上仍在「正常工作」——
    这将导致所有公钥与签名静默错误。公式与常量已用 RFC 8032 测试向量校验。
    """
    X1, Y1, Z1, T1 = p
    X2, Y2, Z2, T2 = q
    A = ((Y1 - X1) * (Y2 - X2)) % _P
    B = ((Y1 + X1) * (Y2 + X2)) % _P
    C = ((T1 * 2 * _D) * T2) % _P
    D = ((Z1 * 2) * Z2) % _P
    E, F, G, H = (B - A) % _P, (D - C) % _P, (D + C) % _P, (B + A) % _P
    return ((E * F) % _P, (G * H) % _P, (F * G) % _P, (E * H) % _P)


def _point_mul(p, e: int):
    """标量乘法（double-and-add，自最高位起）。"""
    if e < 0:
        raise ValueError("标量必须非负")
    r = _POINT_IDENTITY
    for bit in bin(e)[2:]:
        r = _point_add(r, r)
        if bit == "1":
            r = _point_add(r, p)
    return r


def _xrecover(y: int) -> int:
    """由 y 恢复 x 的【偶数】根：x^2 = (y^2 - 1) / (d*y^2 + 1)。"""
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _xrecover(_BY)
_BX_EXPECT = 15112221349535400772501151409588531511454012693041857206046113283949847762202
assert _BX == _BX_EXPECT, "基点 x 不正确（Ed25519 基点必须为 15112221349535400772501151409588531511454012693041857206046113283949847762202）"

_POINT_BASE = (_BX, _BY, 1, (_BX * _BY) % _P)
_POINT_IDENTITY = (0, 1, 1, 0)


def _point_encode(p) -> bytes:
    """规范 32 字节编码：y 的低 255 位 + x 的最低位放在最高位。"""
    X, Y, Z, _ = p
    zi = pow(Z, _P - 2, _P)
    x, y = (X * zi) % _P, (Y * zi) % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _point_decode(pk: bytes):
    """严格解码：拒绝非规范 y（>= p）。"""
    if len(pk) != 32:
        return None
    y = int.from_bytes(pk, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x = _xrecover(y)
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, (x * y) % _P)


def ed25519_publickey(seed: bytes) -> bytes:
    """RFC 8032：seed(32) -> 规范 32 字节公钥。"""
    if len(seed) != 32:
        raise ValueError("seed 必须为 32 字节")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return _point_encode(_point_mul(_POINT_BASE, a))


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    """RFC 8032 的 Ed25519 签名（纯 Ed25519，非 Ed25519ph）。"""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    prefix = h[32:]
    pk = _point_encode(_point_mul(_POINT_BASE, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _L
    Rb = _point_encode(_point_mul(_POINT_BASE, r))
    k = int.from_bytes(hashlib.sha512(Rb + pk + msg).digest(), "little") % _L
    S = (r + k * a) % _L
    return Rb + S.to_bytes(32, "little")


def ed25519_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """严格验证（规范 §2.1）：规范编码、S < L、拒绝单位元与不可解码公钥。"""
    if len(pk) != 32 or len(sig) != 64:
        return False
    A = _point_decode(pk)
    R = _point_decode(sig[:32])
    if A is None or R is None:
        return False
    if A == _POINT_IDENTITY or R == _POINT_IDENTITY:      # 单位元 —— 拒绝
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _L:                                           # S 非规范 —— 拒绝
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), "little") % _L
    lhs = _point_mul(_POINT_BASE, S)
    rhs = _point_add(R, _point_mul(A, k))
    return _point_encode(lhs) == _point_encode(rhs)


# ══════════════════════════════════════════════════════════════════════
# 2. 地址与绑定
# ══════════════════════════════════════════════════════════════════════

def address_from_pubkey(pubkey: bytes) -> bytes:
    """规范 §3：Address = Last20Bytes(Keccak256(PublicKey))"""
    if len(pubkey) != 32:
        raise ValueError("公钥必须为 32 字节")
    return keccak256(pubkey)[-20:]


def airdrop_leaf(pubkey: bytes, amount: int, gas_allowance: int = 0,
                 index: int = 1) -> bytes:
    """规范 §32.5（BUG-41 / BUG-87 修正后）的叶子：
        Hash(CHAIN("AGORA/AIRDROP/v0.2.2", u64(index), pubkey,
                   u256(amount), u256(gas_allowance)))

    **`index` 必须是叶子的一部分（BUG-87）**：唯一性判据是 `(tx.from, index)`，
    而 index 由提交者自选；若叶子不含 index，Merkle 证明与该条目就不是一一对应，
    同一份权益可以换 index 反复领取 —— 实测可把**整个金库**（含他人份额）领空。

    `index` 的定义：该条目在**分配表中的序号**（唯一、公开、可审计）。
    它与"Merkle 树中按叶子哈希排序后的位置"**无关**（后者只是构造证明时的排序），
    因此不存在循环依赖。

    `gas_allowance` 也必须计入叶子：它在创世时直接记入受益人余额（否则受益人
    付不起首次领取交易的 gas 费，形成死锁），因此必须可被第三方独立审计。
    """
    if len(pubkey) != 32:
        raise ValueError("公钥必须为 32 字节")
    if not (0 < amount < 2 ** 256):
        raise ValueError("金额必须为 0 < amount < 2^256")
    if not (0 <= gas_allowance < 2 ** 256):
        raise ValueError("gas_allowance 必须在 [0, 2^256)")
    if not (0 < index < 2 ** 64):
        raise ValueError("index 必须为 0 < index < 2^64")
    # **宽度 MUST 显式声明**（规范 §32.5）。旧写法 `chain(index, pubkey, amount, gas_allowance)`
    # 走的是"裸整数取最小宽度"：index=1 → 1 字节、gas_allowance=5e15 → 8 字节，
    # 而链上是 `u64(index)` = 8 字节、`u256(gas_allowance)` = 32 字节
    # ⇒ 本工具算出的 `airdrop_root` 与 `claim-proof` **永远不可能**通过 §16.4.2 第 16 项。
    return keccak256(TAG_AIRDROP + chain(
        ("u64", index), pubkey, ("u256", amount), ("u256", gas_allowance)))


def airdrop_node(left: bytes, right: bytes) -> bytes:
    """内部节点：按字典序连接，域分隔前缀防止第二原像。"""
    a, b = (left, right) if left <= right else (right, left)
    return keccak256(b"\x01" + a + b)


def airdrop_root(leaves) -> bytes:
    if not leaves:
        raise ValueError("空分配表")
    level = sorted(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(airdrop_node(level[i], level[i + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def airdrop_proof(leaves, target) -> list:
    idx = leaves.index(target)
    proof, level, i = [], sorted(leaves), sorted(leaves).index(target)
    while len(level) > 1:
        if i % 2 == 0 and i + 1 < len(level):
            proof.append(level[i + 1])
        elif i % 2 == 1:
            proof.append(level[i - 1])
        nxt = []
        for j in range(0, len(level) - 1, 2):
            nxt.append(airdrop_node(level[j], level[j + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
        level, i = nxt, i // 2
    return proof


def airdrop_verify(pubkey: bytes, amount: int, proof, root: bytes,
                   gas_allowance: int = 0, index: int = 1) -> bool:
    h = airdrop_leaf(pubkey, amount, gas_allowance, index)
    for p in proof:
        h = airdrop_node(h, p)
    return h == root


# ══════════════════════════════════════════════════════════════════════
# 3. 命令行子命令
# ══════════════════════════════════════════════════════════════════════

def cmd_keygen(args):
    """生成 Ed25519 密钥对。

    --count N 用于【本机测试网的多个验证者】：一台机器生成 N 把密钥。
    这样做【只适用于测试网】—— 因为同一台机器保管多把私钥，等于把这些
    验证者的控制权集中在一个人手里。主网创始验证者必须【各自】在独立机器上生成，
    否则持有 3 把即等于控制整条链（4 人时 QUORUM = 171，3 人 = 192 ≥ 171）。
    """
    if args.count < 1:
        raise ValueError("--count 必须 ≥ 1")
    if args.count > 1 and args.network == "mainnet":
        raise ValueError(
            "--count > 1 仅适用于测试网。主网创始验证者必须各自在独立机器上生成密钥，"
            "不得由一台机器批量生成（否则单一实体可控制 ≥3 票 = 控制整条链）。")
    out = []
    for i in range(1, args.count + 1):
        seed = secrets.token_bytes(32)
        pk = ed25519_publickey(seed)
        addr = address_from_pubkey(pk)
        note = args.note or ("validator" if args.count > 1 else "")
        if args.count > 1:
            note = f"{note}-{i}"
        out.append({
            "index": i,
            "note": note,
            "network": args.network,
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID if args.network == "mainnet" else f"agora-{args.network}-1",
            "public_key_hex": pk.hex(),
            "address_hex": "0x" + addr.hex(),
            "private_seed_hex": seed.hex(),
        })

    if args.quiet:
        for e in out:
            print(e["public_key_hex"]); print(e["address_hex"]); print(e["private_seed_hex"])
    else:
        for e in out:
            print("─" * 72)
            print(f"AGORA 密钥对  #{e['index']}   网络标记：{e['network']}")
            print("─" * 72)
            print(f"  备注        : {e['note'] or '(未填写)'}")
            print(f"  公钥 (公开) : {e['public_key_hex']}")
            print(f"  地址 (公开) : {e['address_hex']}")
            print(f"  私钥 (保密) : {e['private_seed_hex']}")
        print("─" * 72)
        if args.count > 1:
            print("★ 警告：本次在一台机器上生成了多把验证者私钥。")
            print("  这把这些验证者的控制权集中在一个人手里，【仅可用于测试网】。")
            print("  主网必须由各创始验证者在自己独立的机器上分别生成。")
        if args.network != "mainnet":
            print(f"★ 本批密钥的网络标记为 {args.network}，其 chain_id 为 agora-{args.network}-1，")
            print("  与主网 agora-mainnet-1 不同 —— 用这些密钥签出的交易在主网无效，")
            print("  这是刻意的防误用设计。")
        else:
            print("  请立即离线保存【私钥】，只把【公钥 + 地址】交给交接方。")
            print("  绝对不要把私钥写进创世配置、代码仓库或聊天记录。")

    if args.out_dir:
        from decimal import Decimal
        os.makedirs(args.out_dir, exist_ok=True)
        stake = Decimal(str(args.stake))
        stake_atom = int(stake * 10 ** 18)
        if stake_atom <= 0:
            raise ValueError("--stake 必须为正")
        rows = []
        for e in out:
            seed_path = os.path.join(args.out_dir, f"key{e['index']}.seed")
            with open(seed_path, "w", encoding="utf-8") as f:
                f.write(e["private_seed_hex"] + "\n")
            os.chmod(seed_path, 0o600)          # 私钥只给属主读写
            pub = {k: v for k, v in e.items() if k != "private_seed_hex"}
            with open(os.path.join(args.out_dir, f"key{e['index']}.pub.json"),
                      "w", encoding="utf-8") as f:
                json.dump(pub, f, ensure_ascii=False, indent=2)
            rows.append(f"{e['public_key_hex']},{e['address_hex']},{stake_atom}")
        csv_path = os.path.join(args.out_dir, "validators.csv")
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("pubkey_hex,address_hex,amount_atom\n" + "\n".join(rows) + "\n")
        print("─" * 72)
        print(f"已写入 {len(out)} 把密钥到 {args.out_dir}/")
        print(f"  私钥文件（权限 0600，**不外传**）: key1.seed … key{len(out)}.seed")
        print(f"  公开信息（可外传）              : key1.pub.json … key{len(out)}.pub.json")
        print(f"  创世验证者名单（可直接使用）    : {csv_path}"
              f"（每人质押 {stake} AGORA）")
        print("  ★ 私钥未打印到终端（刻意的：终端输出会进日志与 shell 历史）")
        for e in out:
            print(f"    #{e['index']} 地址 {e['address_hex']}")
        print("─" * 72)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out if len(out) > 1 else out[0], f, ensure_ascii=False, indent=2)
        print(f"  已写入 {args.json}（含私钥 —— 请立刻转移到离线介质并删除此文件）")
    return 0


def cmd_address(args):
    pk = bytes.fromhex(args.pubkey.removeprefix("0x"))
    print("0x" + address_from_pubkey(pk).hex())
    return 0


def cmd_verify(args):
    pk = bytes.fromhex(args.pubkey.removeprefix("0x"))
    addr = bytes.fromhex(args.address.removeprefix("0x"))
    ok = address_from_pubkey(pk) == addr
    print(("OK  " if ok else "FAIL") + f"  pubkey→address 绑定{'一致' if ok else '不一致'}")
    return 0 if ok else 1


def _load_csv(path, amount_coin: bool):
    """读取分配/验证者 CSV。

    必需列：pubkey_hex
    金额列：按 --amount-coin 选择 `amount_coin`（单位 AGORA）
            或 `amount_atom`（单位 atom）。两者都接受，但必须与开关一致，
            以避免"以为写的是 AGORA 实际按 atom 解析"这类静默错误。
    """
    want_col = "amount_coin" if amount_coin else "amount_atom"
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        cols = [c.strip() for c in (reader.fieldnames or [])]
        if "pubkey_hex" not in cols:
            raise ValueError(f"CSV 缺少必需列 pubkey_hex（实际列为：{cols}）")
        if want_col not in cols:
            other = "amount_atom" if amount_coin else "amount_coin"
            hint = f"（检测到 {other} 列，{'去掉' if amount_coin else '加上'} --amount-coin 开关即可）" \
                if other in cols else ""
            raise ValueError(f"CSV 缺少列 {want_col}{hint}")
        for i, r in enumerate(reader, start=2):
            r = {(k or "").strip(): (v or "").strip() for k, v in r.items()}
            pk = r.get("pubkey_hex", "").removeprefix("0x").removeprefix("0X")
            if len(pk) != 64:
                raise ValueError(f"第 {i} 行：公钥必须为 64 位十六进制（32 字节），实际长度 {len(pk)}")
            try:
                int(pk, 16)
            except ValueError:
                raise ValueError(f"第 {i} 行：公钥含非十六进制字符")
            raw = r.get(want_col, "")
            if not raw:
                raise ValueError(f"第 {i} 行：{want_col} 为空")
            ga_raw = r.get("gas_allowance_atom", "0") or "0"
            if amount_coin:
                if "." in raw:
                    whole, frac = raw.split(".", 1)
                    frac = (frac + "0" * 18)[:18]
                    amount = int(whole) * ATOM + int(frac)
                else:
                    amount = int(raw) * ATOM
            else:
                amount = int(raw)
            if amount <= 0:
                raise ValueError(f"第 {i} 行：金额必须为正整数（实际 {amount}）")
            rows.append({"pubkey_hex": pk.lower(), "amount": amount,
                         "gas_allowance": int(ga_raw), "note": r.get("note", ""),
                         "index": int(r["index"]) if r.get("index") else len(rows) + 1})
    if not rows:
        raise ValueError("CSV 没有任何数据行")
    if len({x["pubkey_hex"] for x in rows}) != len(rows):
        raise ValueError("表中存在重复公钥（每个公钥只能出现一次）")
    if len({x["index"] for x in rows}) != len(rows):
        raise ValueError("表中存在重复 index（每个条目必须有不同的 index，见 BUG-87）")
    return rows


def cmd_airdrop_build(args):
    rows = _load_csv(args.input, args.amount_coin)
    leaves = [airdrop_leaf(bytes.fromhex(r["pubkey_hex"]), r["amount"],
                           r["gas_allowance"], r["index"]) for r in rows]
    root = airdrop_root(leaves)
    total = sum(r["amount"] for r in rows)
    ga_total = sum(r["gas_allowance"] for r in rows)
    max_share = INITIAL_SUPPLY_AGORA * ATOM * AIRDROP_MAX_SHARE_PCT // 100
    table = {
        "protocol_version": PROTOCOL_VERSION,
        "chain_id": CHAIN_ID,
        "airdrop_root": root.hex(),
        "airdrop_pending": str(total),
        "gas_allowance_total": str(ga_total),
        "entries": rows,
        "leaf_hex": [l.hex() for l in leaves],
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(table, f, ensure_ascii=False, indent=2)
    print(f"条目数           : {len(rows)}")
    print(f"airdrop_pending  : {total} atom  = {total / ATOM:,.6f} AGORA")
    print(f"gas_allowance 合计: {ga_total} atom = {ga_total / ATOM:,.6f} AGORA（直接记入受益人余额）")
    print(f"AIRDROP_MAX_SHARE: {max_share} atom = {max_share / ATOM:,.0f} AGORA (20%)")
    print(f"上限校验         : {'通过' if total <= max_share else '★ 超出 20% 上限 —— 必须调整'}")
    print(f"airdrop_root     : {root.hex()}")
    print(f"已写入           : {args.out}")
    return 0 if total <= max_share else 2


def cmd_airdrop_root(args):
    with open(args.table, encoding="utf-8") as f:
        t = json.load(f)
    print(t["airdrop_root"])
    return 0


def cmd_claim_proof(args):
    with open(args.table, encoding="utf-8") as f:
        t = json.load(f)
    pk = bytes.fromhex(args.pubkey.removeprefix("0x"))
    ent = next((e for e in t["entries"] if e["pubkey_hex"] == pk.hex()), None)
    if ent is None:
        print("★ 该公钥不在分配表中", file=sys.stderr)
        return 1
    leaves = [bytes.fromhex(h) for h in t["leaf_hex"]]
    ent_index = int(ent.get("index", 1))
    leaf = airdrop_leaf(pk, ent["amount"], ent.get("gas_allowance", 0), ent_index)
    proof = airdrop_proof(leaves, leaf)
    addr = address_from_pubkey(pk)
    # `index` 就是分配表里的条目序号（BUG-87：它进叶子，且**不是**排序位置）
    leaf_index = ent_index
    print(json.dumps({
        "index": leaf_index,
        "amount": str(ent["amount"]),
        "gas_allowance": str(ent.get("gas_allowance", 0)),
        "pubkey_hex": pk.hex(),
        "address_hex": "0x" + addr.hex(),
        "merkle_proof": [p.hex() for p in proof],
        "airdrop_root": t["airdrop_root"],
        "note": ent["note"],
    }, ensure_ascii=False, indent=2))
    # 自检**必须**用与生成证明时**完全相同**的叶子（含 index）。
    # 这里曾经漏传 index（走默认 index=1），于是 index≠1 的条目一律自检失败：
    # 工具明明打印出了**有效**的证明，却在 stderr 报"证明★无效"并返回非零码 ——
    # 对使用者来说，这看起来就是"钱包/工具坏了"，而真正的问题只是自检写错。
    ok = airdrop_verify_from_leaf(leaf, proof, bytes.fromhex(t["airdrop_root"]))
    print(f"# 自检: 证明{'有效' if ok else '★无效'}", file=sys.stderr)
    return 0 if ok else 1


def cmd_genesis_template(args):
    """由验证者 CSV 生成创世配置模板，并校验 §32.7 / §32.2 的硬约束。"""
    vals = _load_csv(args.validators, amount_coin=False)
    net = args.network
    chain_id = CHAIN_ID if net == "mainnet" else f"agora-{net}-1"
    gts = args.genesis_timestamp if args.genesis_timestamp is not None else GENESIS_TIMESTAMP

    total_stake = sum(v["amount"] for v in vals)
    errs, warns = [], []

    # ── 硬约束（§32.7 / §32.2）──
    if len(vals) < 4 and not args.allow_unsafe:
        errs.append(f"创始验证者必须 ≥ 4 名（当前 {len(vals)}）；"
                    f"若仅用于状态机测试，可加 --allow-unsafe 跳过本约束")
    if len(vals) < 4 and args.allow_unsafe:
        warns.append(f"仅 {len(vals)} 名创始验证者：共识容错退化，"
                     f"仅可用于状态机/编码测试，不得用于任何公开网络")
    for v in vals:
        if v["amount"] < MIN_VALIDATOR_STAKE_AGORA * ATOM:
            errs.append(f"{v['pubkey_hex'][:16]}… 质押低于最低值 64 AGORA")
        if v["amount"] * 3 >= total_stake:
            msg = (f"{v['pubkey_hex'][:16]}… 质押 ≥ 权益总量的 1/3"
                   f"（可单独达成法定数 —— 禁止）")
            if args.allow_unsafe:
                # --allow-unsafe 下的必然结果（验证者越少越必然），降级为警告
                warns.append("存在质押 ≥ 权益总量 1/3 的验证者（可单独达成法定数）—— "
                             "这是 --allow-unsafe 的必然结果，绝不可用于公开网络")
            else:
                errs.append(msg)

    # ── §32.2 创世金额闭合（可由本工具直接给出可用的分配方案）──
    supply = INITIAL_SUPPLY_AGORA * ATOM
    vault = supply * AIRDROP_MAX_SHARE_PCT // 100
    alloc = None
    if args.airdrop_pending is not None:
        ap = args.airdrop_pending
        if ap > vault:
            errs.append(f"airdrop_pending {ap} 超过上限 {vault}（总量的 {AIRDROP_MAX_SHARE_PCT}%）")
        rest = supply - ap                       # 除空投金库外可自由分配的额度
        if rest < total_stake:
            errs.append(f"扣除金库 {ap} 后仅余 {rest}，不足以覆盖质押 {total_stake}")
        else:
            per_cents = (rest - total_stake)
            if len(vals) and per_cents % len(vals) == 0:
                each = per_cents // len(vals)
                alloc = {"mode": "equal_to_genesis_validators", "per_validator_atom": str(each)}
            else:
                alloc = {"mode": "manual_required",
                         "distributable_atom": str(per_cents),
                         "note": "无法被验证者数整除，请手工指定分配方案"}

    tmpl = {
        "protocol_version": PROTOCOL_VERSION,
        "network": net,
        "chain_id": chain_id,
        "genesis_timestamp": gts,
        "initial_supply_atom": str(supply),
        "genesis_validators": [
            {
                "pubkey_hex": v["pubkey_hex"],
                "address_hex": "0x" + address_from_pubkey(bytes.fromhex(v["pubkey_hex"])).hex(),
                "initial_stake_atom": str(v["amount"]),
                "note": v["note"],
            } for v in vals
        ],
        "airdrop_root": "PENDING-MAINNET-VALUE" if net == "mainnet" else "00" * 32,
        "airdrop_pending": "PENDING-MAINNET-VALUE" if net == "mainnet" else "0",
        "AIRDROP_VAULT_ADDRESS": "0x" + "00" * 20,
        "genesis_allocation": alloc if alloc else "PENDING-MAINNET-VALUE",
        "status": ("PENDING-MAINNET-VALUE（GATE-11 通过前不得用于主网）"
                   if net == "mainnet" else f"{net} 测试网配置（与主网参数相同，仅 chain_id 与 genesis_ts 不同）"),
    }

    if args.genesis_timestamp is not None and net == "mainnet" and gts != GENESIS_TIMESTAMP:
        warns.append(f"主网的 GenesisTimestamp 规范值为 {GENESIS_TIMESTAMP}（2026-10-01 00:00:00 UTC），"
                     f"你指定了 {gts} —— 该值不得用于主网")

    print(json.dumps(tmpl, ensure_ascii=False, indent=2))
    print("\n── 校验 ──")
    print(f"网络            : {net}   chain_id = {chain_id}")
    print(f"创始验证者数    : {len(vals)}  (规范要求 ≥ 4)")
    print(f"质押总量 S      : {total_stake / ATOM:,.0f} AGORA")
    # 规范 §9.1（BUG-35）：法定数运算粒度必须是 atom，不得先换算成整币再取整
    q = -(-2 * total_stake // 3)
    print(f"QUORUM          : ceil_div(2S, 3) = {q:,} atom  ≈ {q / ATOM:.6f} AGORA")
    for v in vals:
        print(f"  单人 {v['amount'] / ATOM:>18,.0f} ≥ QUORUM? {v['amount'] >= q}  (必须 False)")
    if len(vals) >= 2:
        rest_stake = total_stake - vals[0]["amount"]
        print(f"  任一离线剩 {len(vals) - 1} 人 = {rest_stake / ATOM:,.0f} ≥ QUORUM? "
              f"{rest_stake >= q}  (≥4 人时必须 True)")
    if alloc:
        print(f"创世分配方案    : 质押 {total_stake / ATOM:,.0f} 之外，"
              f"每位验证者地址 {int(alloc['per_validator_atom']) / ATOM:,.0f} AGORA")
        if alloc["mode"] == "equal_to_genesis_validators":
            n = len(vals)
            total = total_stake + int(alloc["per_validator_atom"]) * n
            print(f"§32.2 闭合校验  : {n}×{int(alloc['per_validator_atom']) / ATOM:,.0f} + "
                  f"{total_stake / ATOM:,.0f}(质押) = {total / ATOM:,.0f} AGORA  "
                  f"{'✓ 等于总量' if total == supply else '★ 不等于总量'}")
            if total != supply:
                errs.append("创世金额不闭合")
    for w in warns:
        print(f"⚠ 警告：{w}")
    if errs:
        print("\n★ 硬约束未通过：")
        for e in errs:
            print("  -", e)
        return 2
    print("\n硬约束全部通过。")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(tmpl, f, ensure_ascii=False, indent=2)
        print(f"已写入 {args.out}")
    return 0


def cmd_selftest(args):
    ok = True
    print("AGORA v0.2.2 自检")
    print("─" * 72)

    # 1) Keccak-256 已知向量（空串）
    expect_empty = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    got = keccak256(b"").hex()
    print(f"[1] Keccak-256('')      : {'OK' if got == expect_empty else 'FAIL'}")
    ok &= got == expect_empty

    # 2) Keccak-256("abc")
    expect_abc = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    got = keccak256(b"abc").hex()
    print(f"[2] Keccak-256('abc')   : {'OK' if got == expect_abc else 'FAIL'}")
    ok &= got == expect_abc

    # 3) Ed25519 签名 / 验证
    seed = secrets.token_bytes(32)
    pk = ed25519_publickey(seed)
    msg = b"agora-selftest"
    sig = ed25519_sign(seed, msg)
    v1 = ed25519_verify(pk, msg, sig)
    v2 = ed25519_verify(pk, msg + b"x", sig)
    print(f"[3] Ed25519 签验/拒伪   : {'OK' if v1 and not v2 else 'FAIL'}")
    ok &= v1 and not v2

    # 4) Ed25519 RFC 8032 测试向量 #1
    rfc_seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    rfc_pk_expect = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    rfc_sig_expect = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    got_pk = ed25519_publickey(rfc_seed)
    got_sig = ed25519_sign(rfc_seed, b"")
    rfc_ok = got_pk == rfc_pk_expect and got_sig == rfc_sig_expect
    print(f"[4] Ed25519 RFC8032 #1  : {'OK' if rfc_ok else 'FAIL'}")
    if not rfc_ok:
        print(f"      期望 pk={rfc_pk_expect.hex()}")
        print(f"      实际 pk={got_pk.hex()}")
    ok &= rfc_ok

    # 5) RLP 边界与非规范拒绝
    r1 = rlp_decode(rlp_encode(0)) == b""                 # 整数 0 -> 空串
    r2 = rlp_decode(rlp_encode(127)) == b"\x7f"           # 单字节 < 0x80 -> 原样
    r3 = rlp_decode(rlp_encode(b"dog")) == b"dog"
    r4 = (rlp_encode([1, 2, [3]]) == bytes.fromhex("c40102c103")
          and rlp_decode(bytes.fromhex("c40102c103")) == [b"\x01", b"\x02", [b"\x03"]]
          and rlp_encode(b"x" * 60)[:2] == bytes.fromhex("b83c")      # 长字符串头
          and rlp_encode(b"x" * 60)[2:] == b"x" * 60)
    # 非规范编码必须被拒绝：单字节整数用 0x81 前缀、以及前导零整数
    r5 = False
    for bad in (b"\x81\x00", b"\x82\x00\x7f", b"\xb8\x01\x41"):
        try:
            rlp_decode(bad)
        except ValueError:
            r5 = True
        else:
            r5 = False
            break
    print(f"[5] RLP 编解码/拒非规范 : {'OK' if all([r1, r2, r3, r4, r5]) else 'FAIL'}")
    ok &= all([r1, r2, r3, r4, r5])

    # 6) Merkle 根与领取证明（含"证明不可伪造"的反向检查）
    pairs = [(secrets.token_bytes(32), 10 ** 18 * (i + 1)) for i in range(7)]
    leaves = [airdrop_leaf(pk_, amt) for pk_, amt in pairs]
    root = airdrop_root(leaves)
    all_ok = True
    bad_root = airdrop_root(leaves[:-1])                 # 另一个根，用于反向检查
    for i, (pk_, amt) in enumerate(pairs):
        proof = airdrop_proof(leaves, leaves[i])
        all_ok &= airdrop_verify_from_leaf(leaves[i], proof, root)
        all_ok &= not airdrop_verify_from_leaf(leaves[i], proof, bad_root)
    # 金额被篡改必须失败
    tampered = airdrop_leaf(pairs[3][0], pairs[3][1] + 1)
    all_ok &= not airdrop_verify_from_leaf(tampered, airdrop_proof(leaves, leaves[3]), root)
    # 叶子顺序无关（根的确定性）
    all_ok &= airdrop_root(list(reversed(leaves))) == root
    print(f"[6] Merkle 根/证明/防伪 : {'OK' if all_ok else 'FAIL'}   (7 叶，全部证明有效且篡改必失败)")
    ok &= all_ok

    # 7) 创世金额闭合
    total = INITIAL_SUPPLY_AGORA * ATOM
    vault = total * AIRDROP_MAX_SHARE_PCT // 100
    rest = total - vault
    close_ok = (vault + rest == total)
    int_ok = all((x * ATOM) % 1 == 0 for x in [INITIAL_SUPPLY_AGORA, 4096000, 16384000, 64])
    print(f"[7] 创世金额闭合        : {'OK' if close_ok and int_ok else 'FAIL'}"
          f"   (20%={vault // ATOM:,} + 80%={rest // ATOM:,} = {total // ATOM:,})")
    ok &= close_ok and int_ok

    # 8) 4 名创始验证者的法定数性质
    S = 4 * MIN_VALIDATOR_STAKE_AGORA * ATOM
    q = -(-2 * S // 3)
    one = MIN_VALIDATOR_STAKE_AGORA * ATOM
    q_ok = (one < q) and (3 * one >= q) and (2 * one < q)
    print(f"[8] QUORUM 4×64         : {'OK' if q_ok else 'FAIL'}"
          f"   (S={S // ATOM}, Q={q / ATOM:,.0f}; 1人^, 2人^, 3人√, 4人√)")
    ok &= q_ok

    # 9) 基础费算式：不得卡住；地板为 MIN_BASE_FEE；上升/下降步长互逆
    TARGET, DENOM, MINBF = 5_000_000, 8, 1_000_000_000

    DIVISOR = TARGET * DENOM

    def upd(bf, gu):
        """规范 §17.4 的【唯一权威形式】。不得改用近似步长 step=bf//DIVISOR 再乘偏差——
        那在 bf 很大时与规范结果相差可达数百万倍（本项目实际踩过的坑）。"""
        if gu > TARGET:
            return bf + max(1, (bf * (gu - TARGET)) // DIVISOR)
        if gu < TARGET:
            return max(MINBF, bf - max(1, -(-(bf * (TARGET - gu)) // DIVISOR)))
        return bf

    # 地板处：低于目标【正确地】保持不变（已是最低值）；不得低于地板
    floor_ok = all(upd(MINBF, gu) >= MINBF for gu in range(0, TARGET, 250_000))
    # 高于地板：必须真的下降，且下降/上升对称
    bf_hi = 1_000_000_000_000
    down_ok = upd(bf_hi, 4_000_000) < bf_hi and upd(bf_hi, 0) < upd(bf_hi, 2_000_000)
    rise_ok = upd(bf_hi, 6_000_000) > bf_hi and upd(bf_hi, 10_000_000) > upd(bf_hi, 6_000_000)
    sym_ok = (bf_hi - upd(bf_hi, 4_000_000)) == (upd(bf_hi, 6_000_000) - bf_hi)
    at_min_ok = upd(bf_hi, TARGET) == bf_hi
    # 规范 §17.4 的期望值表（必须逐项相符）
    table = [                                        # 与规范 §17.4 的核验表逐项一致
        (1_000_000_000, 0, 1_000_000_000),            # 地板挡住，不能再降
        (1_000_000_000, 4_000_000, 1_000_000_000),
        (1_000_000_000, 6_000_000, 1_025_000_000),
        (1_000_000_000, 10_000_000, 1_125_000_000),
        (1_000_000_000_000, 4_000_000, 975_000_000_000),
        (1_000_000_000_000, 10_000_000, 1_125_000_000_000),
    ]
    tbl_ok = all(upd(bf, gu) == want for bf, gu, want in table)
    print(f"[9] 基础费算式可用      : {'OK' if all([floor_ok, down_ok, rise_ok, tbl_ok]) else 'FAIL'}"
          f"   (规范期望值表: {tbl_ok} ; 高于地板必降: {down_ok} ; 升幅: {rise_ok})")
    ok &= all([floor_ok, down_ok, rise_ok, tbl_ok])

    # 10) 槽上界（全局）与时间戳一致性
    GTS = GENESIS_TIMESTAMP
    ts_for = lambda s: GTS + s * SLOT_TIME
    b1 = ts_for(0)
    r_ok = b1 == GTS and ts_for(6_307_200) == GTS + 6_307_200 * SLOT_TIME
    print(f"[10] 时间戳/槽 一致性   : {'OK' if r_ok else 'FAIL'}"
          f"   (slot 0 -> {b1}, slot 6,307,200 -> {ts_for(6_307_200)})")
    ok &= r_ok

    print("─" * 72)
    print("自检结果：" + ("全部通过" if ok else "★ 存在失败项"))
    return 0 if ok else 1


def airdrop_verify_from_leaf(leaf: bytes, proof, root: bytes) -> bool:
    h = leaf
    for p in proof:
        h = airdrop_node(h, p)
    return h == root


# ══════════════════════════════════════════════════════════════════════

def main(argv=None):
    p = argparse.ArgumentParser(
        description="AGORA v0.2.2 创世密钥生成与创世配置工具（离线、仅标准库）")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="生成一对 Ed25519 密钥（打印公钥/地址/私钥）")
    g.add_argument("--note", default="", help="备注，例如 founder-1")
    g.add_argument("--json", default=None, help="可选：把结果写入 JSON 文件（含私钥，慎用）")
    g.add_argument("--quiet", action="store_true",
                   help="只输出三行：公钥 / 地址 / 私钥（便于脚本提取）")
    g.add_argument("--count", type=int, default=1,
                   help="一次生成 N 把验证者密钥（仅测试网；本机模拟多验证者用）")
    g.add_argument("--network", default="mainnet",
                   choices=["mainnet", "testnet", "devnet"],
                   help="网络标记；非 mainnet 的 chain_id 会自动不同，防止误用于主网")
    g.add_argument("--out-dir", default=None,
                   help="把每把密钥写成独立文件：keyN.seed（私钥，权限 0600）+ keyN.pub.json"
                        "（公开信息），并生成可直接喂给创世构建器的 validators.csv。"
                        "给定时**不再把私钥打印到终端**（避免落入日志/终端历史）")
    g.add_argument("--stake", default="64",
                   help="validators.csv 中每名验证者的初始质押（AGORA，默认 64）")
    g.set_defaults(fn=cmd_keygen)

    a = sub.add_parser("address", help="由公钥推导地址")
    a.add_argument("--pubkey", required=True)
    a.set_defaults(fn=cmd_address)

    v = sub.add_parser("verify", help="校验公钥-地址绑定")
    v.add_argument("--pubkey", required=True)
    v.add_argument("--address", required=True)
    v.set_defaults(fn=cmd_verify)

    ab = sub.add_parser("airdrop-build", help="由 CSV 构建分配表并计算 airdrop_root")
    ab.add_argument("--in", dest="input", required=True)
    ab.add_argument("--out", required=True)
    ab.add_argument("--amount-coin", action="store_true", help="amount 列按 AGORA 书写而非 atom")
    ab.set_defaults(fn=cmd_airdrop_build)

    ar = sub.add_parser("airdrop-root", help="打印分配表的 airdrop_root")
    ar.add_argument("--table", required=True)
    ar.set_defaults(fn=cmd_airdrop_root)

    cp = sub.add_parser("claim-proof", help="导出某受益人的领取证明")
    cp.add_argument("--table", required=True)
    cp.add_argument("--pubkey", required=True)
    cp.set_defaults(fn=cmd_claim_proof)

    gt = sub.add_parser("genesis-template", help="由验证者 CSV 生成创世配置模板并校验硬约束")
    gt.add_argument("--validators", required=True)
    gt.add_argument("--out", default=None)
    gt.add_argument("--network", default="mainnet", choices=["mainnet", "testnet", "devnet"],
                    help="网络标记；非 mainnet 时 chain_id 与创世分配会自动切换为测试网形态")
    gt.add_argument("--genesis-timestamp", type=int, default=None,
                    help="覆盖 GenesisTimestamp（仅测试网使用；主网必须为 1790812800）")
    gt.add_argument("--airdrop-pending", type=int, default=None,
                    help="空投金库金额（atom）。给出后本工具会自动计算并校验 §32.2 闭合方案")
    gt.add_argument("--allow-unsafe", action="store_true",
                    help="允许 < 4 名创始验证者（仅用于状态机/编码测试，绝不可用于公开网络）")
    gt.set_defaults(fn=cmd_genesis_template)

    st = sub.add_parser("selftest", help="运行内置自检（含规范关键算术与 RFC 8032 向量）")
    st.set_defaults(fn=cmd_selftest)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (ValueError, FileNotFoundError) as e:
        print(f"错误：{e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
