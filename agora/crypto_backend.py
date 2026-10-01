# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 可插拔密码学后端
==========================================

设计目标
--------
1. **正确性基准**：纯 Python 实现（`crypto.py`）是唯一权威，已通过 RFC 8032 与
   Keccak 官方向量。任何 C 后端都必须与它逐字节一致，否则拒绝启用。

**接线纪律（BUG-61）：** 生产路径（`agora/codec.py`、`state.py`、`tx.py`、
`consensus.py`、`node.py`）**MUST** 从本模块导入密码学函数，而**不得**直接
从 `agora/crypto.py` 导入 —— 后者是纯 Python 参考实现（正确性基准）。
此前生产路径全部直接导入 `crypto.py`，导致本模块的 C 后端**从未被使用**，
`backend_info()` 却报告 "active = nacl"，形成"性能看似达标、实则纯 Python"的
假象（实测 Ed25519 4600 µs 而非 108 µs）。`tests/test_crypto_backend.py`
现在有一条断言专门防止该接线再次断开。
2. **性能**：纯 Python 的 Ed25519 验证约 4,539 µs/次，238 笔交易的区块需
   3.64 秒（占 5 秒槽的 72.8%，不可接受）。C 后端把这一步降到 ~108 µs。
3. **严格验证不可妥协**（规范 §2.1）：C 库的默认行为**不满足**规范要求，必须补包装。

实测得到的 C 库行为（本机 PyNaCl 1.5 / cryptography 41）：
    ┌──────────────────────────────┬──────────┬──────────┐
    │ 严格性要求                    │ libsodium│ OpenSSL  │
    ├──────────────────────────────┼──────────┼──────────┤
    │ 拒绝 S >= L（非规范标量）      │    ✓     │    ✓     │
    │ 拒绝单位元公钥                 │    ✓     │ 未测     │
    │ 拒绝非规范 y（y >= p）         │    ✗     │ 未测     │
    └──────────────────────────────┴──────────┴──────────┘
    ⇒ "拒绝非规范 y" 必须由本模块自行补上（`_reject_noncanonical_pubkey`）。

后端选择
--------
    AGORA_CRYPTO_BACKEND = pure | auto | nacl | cryptography | crosscheck
  · pure        —— 只用纯 Python（离线环境、向量核对、无依赖部署）
  · auto（默认）—— 优先 C 后端，不可用时回退纯 Python
  · crosscheck  —— C 后端 + 每次调用都与纯 Python 比对（测试与 CI 用，慢）

香橙派等无第三方库的环境无需安装任何东西即可运行（自动回退）。
"""

from __future__ import annotations

import hashlib
import os
from typing import Callable, Optional, Tuple

from . import crypto as _pure
from . import params as P
from .crypto import CURVE_L, CURVE_P, BASEPOINT_X_EXPECTED

__all__ = [
    "keccak256", "verify", "sign", "publickey_from_seed", "address_from_pubkey",
    "chain", "backend_info", "set_backend", "crosscheck_enabled",
    "keccak_backend", "keccak_is_c_backed", "startup_self_check", "pure_backend",
]

_MODE = os.environ.get("AGORA_CRYPTO_BACKEND", "auto").strip().lower()

# RFC 8032 §7.1 TEST 1 —— 任何后端启用前必须通过
_VEC_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
_VEC_PK = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
_VEC_SIG = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")


# ══════════════════════════════════════════════════════════════════════
# 严格性补充检查（C 库不做的部分）
# ══════════════════════════════════════════════════════════════════════

def _is_canonical_point_encoding(enc: bytes) -> bool:
    """规范 §2.1 第 2 项：公钥/点的编码必须规范，即 y 分量 < p。

    libsodium 与 OpenSSL 都会接受 y ∈ [p, 2^255-1] 的编码，而这类编码
    对应的是同一个群元素、却在字节层面非规范 —— 必须拒绝，否则两个实现
    会对同一笔交易得出不同结论。
    """
    if len(enc) != 32:
        return False
    return (int.from_bytes(enc, "little") & ((1 << 255) - 1)) < CURVE_P


def _reject_noncanonical_pubkey(pk: bytes) -> bool:
    return _is_canonical_point_encoding(pk)


def _signature_strict_fields_ok(sig: bytes) -> bool:
    """规范 §2.1 第 1 项：签名必须为规范 64 字节（R 规范点编码，S < L）。"""
    if len(sig) != 64:
        return False
    if int.from_bytes(sig[32:], "little") >= CURVE_L:      # S >= L
        return False
    return _is_canonical_point_encoding(sig[:32])          # R 必须规范


# ══════════════════════════════════════════════════════════════════════
# 后端探测
# ══════════════════════════════════════════════════════════════════════

class _Backend:
    def __init__(self, name: str, verify: Optional[Callable], sign: Optional[Callable],
                 pubkey: Optional[Callable], note: str = ""):
        self.name = name
        self.verify = verify
        self.sign = sign
        self.pubkey = pubkey
        self.note = note


def _probe_nacl() -> Optional[_Backend]:
    try:
        import nacl.signing

        vk_cls, sk_cls = nacl.signing.VerifyKey, nacl.signing.SigningKey

        def _v(pk: bytes, msg: bytes, sig: bytes) -> bool:
            # 自行补上 C 库缺失的规范编码检查
            if not _signature_strict_fields_ok(sig) or not _reject_noncanonical_pubkey(pk):
                return False
            try:
                vk_cls(pk).verify(msg, sig)
                return True
            except Exception:
                return False

        def _s(seed: bytes, msg: bytes) -> bytes:
            return bytes(sk_cls(seed).sign(msg).signature)

        def _p(seed: bytes) -> bytes:
            return bytes(sk_cls(seed).verify_key)

        return _Backend("nacl", _v, _s, _p, "PyNaCl / libsodium")
    except Exception:
        return None


def _probe_cryptography() -> Optional[_Backend]:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey,
        )
        from cryptography.exceptions import InvalidSignature

        def _v(pk: bytes, msg: bytes, sig: bytes) -> bool:
            if not _signature_strict_fields_ok(sig) or not _reject_noncanonical_pubkey(pk):
                return False
            try:
                Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
                return True
            except (InvalidSignature, Exception):
                return False

        def _s(seed: bytes, msg: bytes) -> bytes:
            return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)

        def _p(seed: bytes) -> bytes:
            from cryptography.hazmat.primitives import serialization
            return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        return _Backend("cryptography", _v, _s, _p, "cryptography / OpenSSL")
    except Exception:
        return None


def _backend_self_test(b: _Backend) -> Tuple[bool, str]:
    """后端启用前必须通过 RFC 8032 向量，否则拒绝。"""
    try:
        if b.pubkey(_VEC_SEED).hex() != _VEC_PK:
            return False, "RFC 8032 公钥向量不符"
        if b.sign(_VEC_SEED, b"").hex() != _VEC_SIG:
            return False, "RFC 8032 签名向量不符"
        if not b.verify(bytes.fromhex(_VEC_PK), b"", bytes.fromhex(_VEC_SIG)):
            return False, "RFC 8032 验证失败"
        if b.verify(bytes.fromhex(_VEC_PK), b"x", bytes.fromhex(_VEC_SIG)):
            return False, "篡改消息竟然通过验证"
        return True, "RFC 8032 向量通过"
    except Exception as e:                                  # pragma: no cover
        return False, f"自检异常：{e}"


_PURE_BACKEND = _Backend("pure", _pure.verify, _pure.sign, _pure.publickey_from_seed,
                         "纯 Python（正确性基准）")

_ACTIVE: _Backend = _PURE_BACKEND
_CROSSCHECK = (_MODE == "crosscheck")
_CANDIDATES: dict = {}


def _init() -> None:
    global _ACTIVE, _CANDIDATES
    for probe in (_probe_nacl, _probe_cryptography):
        b = probe()
        if b is None:
            continue
        ok, why = _backend_self_test(b)
        if ok:
            _CANDIDATES[b.name] = b
        else:                                              # pragma: no cover
            _CANDIDATES[b.name] = None

    if _MODE == "pure":
        _ACTIVE = _PURE_BACKEND
    elif _MODE in _CANDIDATES and _CANDIDATES[_MODE] is not None:
        _ACTIVE = _CANDIDATES[_MODE]
    elif _MODE in ("auto", "crosscheck"):
        _ACTIVE = next((v for v in _CANDIDATES.values() if v is not None), _PURE_BACKEND)
    else:
        _ACTIVE = _PURE_BACKEND


_init()


# ══════════════════════════════════════════════════════════════════════
# 公开 API
# ══════════════════════════════════════════════════════════════════════

def set_backend(name: str) -> None:
    """运行时切换后端（测试用）。name ∈ {pure, auto, crosscheck, nacl, cryptography}"""
    global _ACTIVE, _CROSSCHECK, _MODE
    _MODE = name
    _CROSSCHECK = (name == "crosscheck")
    _init()


def crosscheck_enabled() -> bool:
    return _CROSSCHECK


def backend_info() -> dict:
    return {
        "mode": _MODE,
        "active": _ACTIVE.name,
        "description": _ACTIVE.note,
        "available": {k: (v is not None) for k, v in _CANDIDATES.items()},
        "crosscheck": _CROSSCHECK,
        "keccak": _KECCAK_NOTE,
    }


# ── Keccak-256 ───────────────────────────────────────────────────────
#
# 候选后端按优先级：① 自带 C 共享库（ctypes）→ ② pycryptodome → ③ 纯 Python。
# **不得**使用 hashlib.sha3_256 —— 它是 SHA-3 填充（0x06），与 Keccak（0x01）不同。
#
# 自带 C 源（`native/keccak256.c`）而不是依赖 pip 包，原因见
# `tools/agora_build_native.py`：目标环境可能完全离线、依赖越少越安全，
# 且正确性由**逐字节比对**保证而非信任第三方。

_NATIVE_LIB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "native", "libagora_keccak.so")


def _probe_native_keccak():
    """加载自带 C 共享库，并**先逐字节比对**再启用（不符即拒绝）。"""
    if not os.path.exists(_NATIVE_LIB_PATH):
        return None
    try:
        import ctypes
        lib = ctypes.CDLL(_NATIVE_LIB_PATH)
        lib.agora_keccak256.restype = None
        lib.agora_keccak256.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                                        ctypes.c_char_p]

        def _k(data: bytes) -> bytes:
            out = ctypes.create_string_buffer(32)
            lib.agora_keccak256(data, len(data), out)
            return out.raw
    except Exception:
        return None

    # 启用前必须通过：官方向量 + 分组边界 + 随机交叉校验
    if _k(b"").hex() != ("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b"
                         "7bfad8045d85a470"):
        return None
    if _k(b"abc").hex() != ("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036"
                            "ec44f58fa12d6c45"):
        return None
    import random as _rnd
    _rng = _rnd.Random(20261001)                 # 固定种子 ⇒ 校验本身可复现
    for _ in range(64):
        _n = _rng.randrange(0, 400)
        _d = bytes(_rng.randrange(256) for _ in range(_n))
        if _k(_d) != _pure.keccak256(_d):
            return None                              # 静默不符 ⇒ 拒绝启用
    return _k


_NATIVE_KECCAK = _probe_native_keccak()

try:
    from Crypto.Hash import keccak as _pyc_keccak       # type: ignore

    def _c_keccak(data: bytes) -> bytes:
        h = _pyc_keccak.new(digest_bits=256)
        h.update(data)
        return h.digest()

    if _c_keccak(b"").hex() == _pure.keccak256(b"").hex() and \
       _c_keccak(b"abc").hex() == _pure.keccak256(b"abc").hex():
        _PYC_KECCAK = _c_keccak
    else:                                                # pragma: no cover
        _PYC_KECCAK = None
except Exception:
    _PYC_KECCAK = None

# 选择顺序：自带 C 库 → pycryptodome → 纯 Python
if _NATIVE_KECCAK is not None:
    keccak256 = _NATIVE_KECCAK
    _KECCAK_NOTE = "自带 C 库（native/libagora_keccak.so）"
elif _PYC_KECCAK is not None:
    keccak256 = _PYC_KECCAK
    _KECCAK_NOTE = "pycryptodome (C)"
else:
    keccak256 = _pure.keccak256
    _KECCAK_NOTE = "纯 Python（**未达 GATE-10b**：请先运行 tools/agora_build_native.py）"


def keccak_backend() -> str:
    return _KECCAK_NOTE


def keccak_is_c_backed() -> bool:
    """当前 Keccak 是否由 C 实现提供（GATE-10b 的硬要求）。

    供启动自检使用：主网节点 **MUST** 在启动时确认其为 True，
    否则拒绝以主网参数启动 —— 纯 Python 的 Keccak 会让峰值区块的开销
    上升一个数量级，属于"性能不达标却静默运行"的危险状态。
    """
    return any(x in _KECCAK_NOTE for x in ("pycryptodome", "eth", "自带 C 库"))


def startup_self_check(mainnet: bool = False) -> tuple:
    """节点启动自检：返回 `(ok, 消息列表)`。

    `mainnet=True` 时要求 C 后端 Keccak 与 C 后端 Ed25519 **同时**可用；
    任一缺失即判定不可启动（GATE-10b 方案 (a) 的验收口径）。
    """
    msgs = []
    info = backend_info()
    ed_c = _ACTIVE.name != "pure"
    k_c = keccak_is_c_backed()
    msgs.append(f"Ed25519 后端 = {_ACTIVE.name}（{_ACTIVE.note}）"
                + ("  ✅" if ed_c else "  ⚠ 纯 Python，约 4,600 µs/次"))
    msgs.append(f"Keccak-256 后端 = {_KECCAK_NOTE}"
                + ("  ✅" if k_c else "  ⚠ 纯 Python，约 800 µs/次"))
    if not k_c:
        msgs.append("  提示：运行 `python3 tools/agora_build_native.py` 编译自带 C 库")
    ok = (ed_c and k_c) if mainnet else True
    return ok, msgs


# ── Ed25519 ──────────────────────────────────────────────────────────

def publickey_from_seed(seed: bytes) -> bytes:
    if _ACTIVE.pubkey is None:
        return _pure.publickey_from_seed(seed)
    out = _ACTIVE.pubkey(seed)
    if _CROSSCHECK:
        ref = _pure.publickey_from_seed(seed)
        if out != ref:                                   # pragma: no cover
            raise AssertionError(f"后端 {_ACTIVE.name} 的公钥与纯 Python 基准不一致")
    return out


def _on_first_sign() -> None:
    """在**首次**签名/验签时冻结链身份（规范 §4）。

    为什么在这里而不是在构建创世时：构建创世只是计算，一个进程里可能为
    多个网络分别试算；而签名一旦产生，`chain_id` 就进入了不可撤销的字节，
    此后切换必然产出"签名者与验签者用不同链身份"的垃圾数据。
    """
    if not P.network_frozen():
        P.freeze_network("首次签名")


def sign(seed: bytes, msg: bytes) -> bytes:
    _on_first_sign()
    if _ACTIVE.sign is None:
        return _pure.sign(seed, msg)
    out = _ACTIVE.sign(seed, msg)
    if _CROSSCHECK:
        ref = _pure.sign(seed, msg)
        if out != ref:                                   # pragma: no cover
            raise AssertionError(f"后端 {_ACTIVE.name} 的签名与纯 Python 基准不一致")
    return out


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    _on_first_sign()
    out = _ACTIVE.verify(pk, msg, sig)
    if _CROSSCHECK:
        ref = _pure.verify(pk, msg, sig)
        if out != ref:                                   # pragma: no cover
            raise AssertionError(
                f"后端 {_ACTIVE.name} 的验证结论与纯 Python 基准不一致："
                f"backend={out} pure={ref} pk={pk.hex()} sig={sig.hex()}")
    return out


def address_from_pubkey(pubkey: bytes) -> bytes:
    """`Address = Last20Bytes(Keccak256(PublicKey))`（规范 §3）。

    **必须走本模块的 `keccak256`（即 C 后端）**，不能委托给 `_pure`：
    `_pure.address_from_pubkey` 内部调用的是**纯 Python** 的 Keccak，
    而地址推导在区块执行里出现频率极高（每笔交易的发送者、每个收款人、
    每次验证者集合查询）。实测后果：一个 200 笔转账的区块里，802 次
    纯 Python Keccak 占掉 **79% 的执行时间**（0.83 s / 1.04 s）——
    而 C 后端明明就在手边，只是这一条路径没接上。

    这正是 BUG-61「后端未接线」的**残留盲点**：当时扫的是
    `from .crypto import …` 形式的导入，而这里是**函数内部委托**，
    静态扫描抓不到，只有 profiler 能发现。
    """
    if len(pubkey) != 32:
        raise ValueError("公钥必须为 32 字节")
    return keccak256(pubkey)[-20:]


def chain(*fields) -> bytes:
    """规范 §20.1 的定宽前置函数。

    它只在**构造待哈希载荷**时调用一次，本身不做群运算或置换，
    不构成性能热点，因此直接使用纯实现（无后端差异）。
    """
    return _pure.chain(*fields)


def pure_backend():
    """返回纯 Python 参考实现模块，供交叉校验与向量生成使用。

    测试与 `crosscheck` 模式 **MUST** 用它作为真值来源 —— 若用它替换生产
    路径，就等于把"待验证对象"当成"验证基准"，交叉验证将失去意义。
    """
    return _pure
