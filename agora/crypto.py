# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 密码学层
==================================

对应规范：§2（签名/哈希）、§3（地址）、§20.1（CHAIN）

本模块只依赖 Python 标准库，可完全离线构建与验证。

实现要点（每条都对应一次真实踩过的坑，见规范 §33.0）：
  1. Keccak-256 使用【原始 Keccak 填充 0x01】，不是 SHA-3 的 0x06。
     `hashlib.sha3_256` 与 `hashlib.new("sha3_256")` 都是 SHA-3，不能用于本协议。
  2. Ed25519 群运算使用【完整扩展坐标 (X, Y, Z, T)】与完整加法公式。
     使用不完整坐标 (X, Y, Z) + 简化公式时，传入非平凡投影坐标会得到错误结果，
     而代码不会报错 —— 表现为公钥与签名静默错误。
  3. 基点 x 必须取曲线 -x^2 + y^2 = 1 + d*x^2*y^2 对应的正确根。
     取错根会让整条链的密钥与签名全部错误，且同样不报错。
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

__all__ = [
    "keccak256",
    "chain",
    "address_from_pubkey",
    "publickey_from_seed",
    "sign",
    "verify",
    "CURVE_P", "CURVE_L", "BASE_POINT",
    "KEKA_CHAIN_ID_BYTES",
]

# ══════════════════════════════════════════════════════════════════════
# Keccak-256（原始 Keccak 填充）
# ══════════════════════════════════════════════════════════════════════

_KECCAK_ROUND_CONSTANTS = None
_KECCAK_RHO_OFFSETS = None
_KECCAK_PI_MAP = None


def _rc() -> list:
    global _KECCAK_ROUND_CONSTANTS
    if _KECCAK_ROUND_CONSTANTS is None:
        rc, lfsr = [], 1
        for _ in range(24):
            c = 0
            for j in range(7):
                lfsr, bit = ((lfsr << 1) ^ (0x71 if lfsr & 0x80 else 0)) & 0xFF, lfsr & 1
                if bit:
                    c ^= 1 << ((1 << j) - 1)
            rc.append(c)
        _KECCAK_ROUND_CONSTANTS = rc
    return _KECCAK_ROUND_CONSTANTS


def _rho() -> list:
    """ρ 步骤的旋转偏移表：offset[x + 5y]。"""
    global _KECCAK_RHO_OFFSETS
    if _KECCAK_RHO_OFFSETS is None:
        offs, x, y = [0] * 25, 1, 0
        for t in range(24):
            offs[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
            x, y = y, (2 * x + 3 * y) % 5
        _KECCAK_RHO_OFFSETS = offs
    return _KECCAK_RHO_OFFSETS




def _f1600(state: list, rounds: int = 24) -> list:
    """Keccak-f[1600] 置换。

    状态为 25 个 64 位 lane 的扁平列表，约定 `index = x + 5y`。

    本函数**刻意采用最朴素的逐行写法**：θ / ρ / π / χ / ι 各自按 Keccak 规范
    的定义式直接写出，不预计算任何"下标表"。原因是本实现曾在两处因**约定歧义**
    而静默出错（π 的目标坐标写反、手抄的标准表坐标轴方向不同）——这类错误不会
    报错，只是让摘要全错。朴素写法的 `%` 与取模索引开销换来的是可读性与正确性，
    实测它只比展开版慢约 1.5 倍，而正确性优先。

    正确性由两条**独立**真值保证：
      · `tests/test_codec.py`：Keccak-256 官方向量（填充 0x01）
      · `tests/test_keccak_permutation.py`：与 `hashlib.sha3_256` 交叉验证
        （同一置换、仅填充首字节不同），覆盖多种长度与多块输入
    """
    M = (1 << 64) - 1
    A = list(state)
    rc, rho = _rc(), _rho()

    for rnd in range(rounds):
        # θ
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        D = [C[(x - 1) % 5] ^ (((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63)) & M)
             for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x + 5 * y] ^= D[x]

        # ρ + π：B[y][(2x + 3y) mod 5] = rot(A[x][y], r[x][y])
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                n = rho[x + 5 * y]
                v = A[x + 5 * y]
                nx, ny = y, (2 * x + 3 * y) % 5
                B[nx + 5 * ny] = ((v << n) | (v >> (64 - n))) & M if n else v

        # χ：A[x][y] = B[x][y] ^ ((~B[x+1][y]) & B[x+2][y])
        for x in range(5):
            for y in range(5):
                A[x + 5 * y] = B[x + 5 * y] ^ (
                    (~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]) & M

        # ι
        A[0] ^= rc[rnd]

    return A


def keccak256(data: bytes) -> bytes:
    """规范 §2.2：全协议唯一哈希函数。返回 32 字节。"""
    rate, dsbyte = 136, 0x01          # Keccak-256：rate = 1088/8，填充首字节 0x01
    padlen = rate - (len(data) % rate)
    if padlen == 1:
        data = data + bytes([dsbyte | 0x80])
    else:
        data = data + bytes([dsbyte]) + b"\x00" * (padlen - 2) + b"\x80"

    state = [0] * 25
    for off in range(0, len(data), rate):
        blk = data[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(blk[i * 8:(i + 1) * 8], "little")
        state = _f1600(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(rate // 8))[:32]


# ══════════════════════════════════════════════════════════════════════
# CHAIN：哈希原像与签名载荷的唯一连接函数（规范 §20.1）
# ══════════════════════════════════════════════════════════════════════

_WIDTH_BYTES = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "u256": 32}


def chain(*fields) -> bytes:
    """`CHAIN(f1, ..., fn) = f1 ‖ f2 ‖ ... ‖ fn`

    编码规则（规范 §20.1，与 RLP 无关，禁止混用）：
        定宽整数 u8/u16/u32/u64/u256 → 无符号大端定宽
        bytes b                      → u32(len(b)) ‖ b…… 除非恰为 20 或 32 字节（地址/哈希，原样）

    **宽度如何指定（BUG-64 修复）：** 规范 §20.1 要求整数**定宽**，因此调用方
    **MUST** 用 `(宽度, 值)` 二元组显式声明宽度，例如 `("u64", height)`、
    `("u8", vote_type)`。`(宽度, 值)` 里的宽度是 1/2/4/8/32 之一。

    裸整数（`chain(1, 2)`）仍受支持，语义为**最小定宽**，但**仅限**非签名/非哈希
    载荷使用（如单元测试）。**一切签名载荷与哈希原像 MUST 使用显式宽度** ——
    否则会与规范 §20.1 的定宽要求不符（这正是 BUG-64）。
    （域标签 **MUST** 在调用方以 `TAG_XXX + chain(...)` 的形式显式前置，
      不得作为 CHAIN 的参数 —— 见下方 str 分支的说明。）
    """
    out = bytearray()
    for f in fields:
        # 显式宽度：(宽度名, 值)
        if isinstance(f, tuple) and len(f) == 2 and isinstance(f[0], str):
            width = _WIDTH_BYTES.get(f[0])
            if width is None:
                raise ValueError(
                    f"未知的 CHAIN 宽度名：{f[0]!r}（应为 u8/u16/u32/u64/u256）")
            value = f[1]
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"CHAIN 宽度字段的值必须是整数，实际 {type(value).__name__}")
            if value < 0:
                raise ValueError("CHAIN 只接受无符号整数")
            if value >= (1 << (8 * width)):
                raise ValueError(f"{f[0]} 溢出：{value} 需要超过 {width} 字节")
            out += value.to_bytes(width, "big")
        elif isinstance(f, bytes):
            out += f if len(f) in (20, 32) else (len(f).to_bytes(4, "big") + f)
        elif isinstance(f, int):
            if f < 0:
                raise ValueError("CHAIN 只接受无符号整数")
            for width in (1, 2, 4, 8, 32):
                if f < (1 << (8 * width)):
                    out += f.to_bytes(width, "big")
                    break
            else:
                raise ValueError("整数超出 u256")
        elif isinstance(f, str):
            raise TypeError(
                "CHAIN 不再接受字符串参数：域标签必须用 `TAG_XXX + chain(...)` 显式前置。\n"
                "原因：早期实现让 CHAIN 对 str 不加长度前缀、对 bytes 加 u32 前缀，\n"
                "于是同一个标签在不同调用点得到不同的字节串，独立实现必然对不上。")
        else:
            raise TypeError(f"CHAIN 不支持的字段类型: {type(f)}")
    return bytes(out)


# ══════════════════════════════════════════════════════════════════════
# Ed25519（RFC 8032，完整扩展坐标）
# ══════════════════════════════════════════════════════════════════════

CURVE_P = 2 ** 255 - 19
CURVE_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, CURVE_P - 2, CURVE_P)) % CURVE_P
_I = pow(2, (CURVE_P - 1) // 4, CURVE_P)

Point = Tuple[int, int, int, int]          # (X, Y, Z, T)，T = X*Y/Z
IDENTITY: Point = (0, 1, 1, 0)


def _point_add(p: Point, q: Point) -> Point:
    """完整扩展坐标下的点加（twisted Edwards，a = -1）。"""
    X1, Y1, Z1, T1 = p
    X2, Y2, Z2, T2 = q
    A = ((Y1 - X1) * (Y2 - X2)) % CURVE_P
    B = ((Y1 + X1) * (Y2 + X2)) % CURVE_P
    C = ((T1 * 2 * _D) * T2) % CURVE_P
    D = ((Z1 * 2) * Z2) % CURVE_P
    E, F, G, H = (B - A) % CURVE_P, (D - C) % CURVE_P, (D + C) % CURVE_P, (B + A) % CURVE_P
    return ((E * F) % CURVE_P, (G * H) % CURVE_P, (F * G) % CURVE_P, (E * H) % CURVE_P)


def _point_mul(p: Point, e: int) -> Point:
    if e < 0:
        raise ValueError("标量必须非负")
    r = IDENTITY
    for bit in bin(e)[2:]:
        r = _point_add(r, r)
        if bit == "1":
            r = _point_add(r, p)
    return r


def _xrecover(y: int) -> int:
    """由 y 恢复 x 的偶根：x^2 = (y^2 - 1) / (d*y^2 + 1)。"""
    xx = (y * y - 1) * pow(_D * y * y + 1, CURVE_P - 2, CURVE_P)
    x = pow(xx, (CURVE_P + 3) // 8, CURVE_P)
    if (x * x - xx) % CURVE_P != 0:
        x = x * _I % CURVE_P
    if x % 2 != 0:
        x = CURVE_P - x
    return x


_BY = 4 * pow(5, CURVE_P - 2, CURVE_P) % CURVE_P
_BX = _xrecover(_BY)
BASE_POINT: Point = (_BX, _BY, 1, (_BX * _BY) % CURVE_P)

# 规范 §33.0 要求：实现 MUST 在启动时断言基点正确
BASEPOINT_X_EXPECTED = 15112221349535400772501151409588531511454012693041857206046113283949847762202
assert _BX == BASEPOINT_X_EXPECTED, (
    "Ed25519 基点 x 不正确，实际 %d，期望 %d" % (_BX, BASEPOINT_X_EXPECTED))


def _point_encode(p: Point) -> bytes:
    X, Y, Z, _ = p
    zi = pow(Z, CURVE_P - 2, CURVE_P)
    x, y = (X * zi) % CURVE_P, (Y * zi) % CURVE_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _point_decode(pk: bytes) -> Optional[Point]:
    """严格解码：拒绝非规范 y（>= p）。"""
    if len(pk) != 32:
        return None
    y = int.from_bytes(pk, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= CURVE_P:
        return None
    x = _xrecover(y)
    if (x & 1) != sign:
        x = CURVE_P - x
    return (x, y, 1, (x * y) % CURVE_P)


def publickey_from_seed(seed: bytes) -> bytes:
    """RFC 8032：32 字节 seed → 规范 32 字节公钥。"""
    if len(seed) != 32:
        raise ValueError("seed 必须为 32 字节")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return _point_encode(_point_mul(BASE_POINT, a))


def sign(seed: bytes, msg: bytes) -> bytes:
    """RFC 8032 纯 Ed25519 签名（非 ph 变体）。"""
    if len(seed) != 32:
        raise ValueError("seed 必须为 32 字节")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    pk = _point_encode(_point_mul(BASE_POINT, a))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % CURVE_L
    Rb = _point_encode(_point_mul(BASE_POINT, r))
    k = int.from_bytes(hashlib.sha512(Rb + pk + msg).digest(), "little") % CURVE_L
    return Rb + ((r + k * a) % CURVE_L).to_bytes(32, "little")


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """严格验证（规范 §2.1）：规范编码、S < L、拒绝单位元与不可解码公钥。"""
    if len(pk) != 32 or len(sig) != 64:
        return False
    A, R = _point_decode(pk), _point_decode(sig[:32])
    if A is None or R is None or A == IDENTITY or R == IDENTITY:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= CURVE_L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), "little") % CURVE_L
    return _point_encode(_point_mul(BASE_POINT, S)) == _point_encode(
        _point_add(R, _point_mul(A, k)))


# ══════════════════════════════════════════════════════════════════════
# 地址（规范 §3）
# ══════════════════════════════════════════════════════════════════════

# **已废弃，勿使用（BUG-62 清理）。** 本模块是纯 Python 参考实现，不应持有链身份：
# 该常量无人引用，且在测试网下会**误导**（它永远写着主网值）。
# 链身份的唯一来源是 `params.CHAIN_ID_BYTES`（经 `params.set_network` 切换）。
# 保留名字仅为兼容可能的外部引用，值不再被任何代码读取。
KEKA_CHAIN_ID_BYTES = b"agora-mainnet-1"          # DEPRECATED：见上方说明


def address_from_pubkey(pubkey: bytes) -> bytes:
    """`Address = Last20Bytes(Keccak256(PublicKey))`"""
    if len(pubkey) != 32:
        raise ValueError("公钥必须为 32 字节")
    return keccak256(pubkey)[-20:]


def pubkey_matches_address(pubkey: bytes, address: bytes) -> bool:
    """公钥-地址绑定校验（规范 §32.6 第 ② 项）。"""
    return len(address) == 20 and address_from_pubkey(pubkey) == address
