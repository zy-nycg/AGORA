# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 编译 C 后端（GATE-10b）
=====================================

把 `native/keccak256.c` 编译为共享库，供 `agora/crypto_backend.py` 通过 ctypes 加载。

为什么需要它（规范 GATE-10b）：纯 Python 的 Keccak 约 800 µs/次，而协议每笔交易
约 12 次、峰值满载 476 笔/块 ⇒ 仅哈希一项就占掉大量槽时间。GATE-10b 要求主网
"峰值区块的密码学与状态根开销 ≤ 5 秒槽的 45%"，因此必须用 C 后端。

为什么自带 C 源码而不是依赖 pip 包：
  · 目标环境可能**完全离线**（本机即无网络，pip 不可用）；
  · 依赖越少，部署面越小（香橙派上无需装任何第三方库）；
  · 正确性由**逐字节比对**保证，而不是靠信任第三方包（见 `crypto_backend`）。

用法：
    python3 tools/agora_build_native.py            # 编译
    python3 tools/agora_build_native.py --check    # 仅校验已编译产物是否可用

产物：`native/libagora_keccak.so`（与架构相关，**不**纳入版本管理）
"""

from __future__ import annotations

import argparse
import ctypes
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "native", "keccak256.c")
LIB = os.path.join(ROOT, "native", "libagora_keccak.so")

# 独立真值：Keccak-256（0x01 填充），**不是** SHA-3-256
TRUTH = {
    b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    b"x" * 32: None,          # 用纯 Python 实现填充（下方运行时计算）
    b"y" * 135: None,
    b"z" * 136: None,
    b"w" * 137: None,
    b"v" * 272: None,
}


def _load(path: str):
    lib = ctypes.CDLL(path)
    lib.agora_keccak256.restype = None
    lib.agora_keccak256.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                                    ctypes.c_char_p]
    return lib

def _call(lib, data: bytes) -> bytes:
    out = ctypes.create_string_buffer(32)
    lib.agora_keccak256(data, len(data), out)
    return out.raw


def verify_lib(path: str = LIB, quiet: bool = False) -> bool:
    """独立校验：官方向量 + 与纯 Python 实现的逐字节比对（含分组边界）。"""
    sys.path.insert(0, ROOT)
    from agora.crypto import keccak256 as pure_keccak

    if not os.path.exists(path):
        if not quiet:
            print(f"✗ 产物不存在：{path}")
        return False
    try:
        lib = _load(path)
    except OSError as e:
        if not quiet:
            print(f"✗ 加载失败：{e}")
        return False

    if not quiet:
        print(f"校验 {os.path.relpath(path, ROOT)}")
    ok = True
    for data, expect in TRUTH.items():
        want = expect if expect is not None else pure_keccak(data).hex()
        got = _call(lib, data).hex()
        good = got == want
        ok &= good
        if not quiet or not good:
            label = repr(data[:12]) + (f"...(len={len(data)})" if len(data) > 12 else "")
            print(f"  [{'OK  ' if good else 'FAIL'}] len={len(data):4d} "
                  f"{'官方向量' if expect else '与纯 Python 比对'}  {label}")
            if not good:
                print(f"         C    = {got}\n         期望 = {want}")

    # 随机化交叉校验（覆盖填充边界与多分组路径）
    import random
    rng = random.Random(20261001)
    for _ in range(200):
        n = rng.randrange(0, 500)
        data = bytes(rng.randrange(256) for _ in range(n))
        if _call(lib, data) != pure_keccak(data):
            ok = False
            print(f"  [FAIL] 随机交叉校验不一致：len={n}")
            break
    if ok and not quiet:
        print("  [OK  ] 200 组随机长度交叉校验一致")
    return ok


def build() -> int:
    if not os.path.exists(SRC):
        print(f"✗ 缺少源文件：{SRC}")
        return 2
    cmd = ["cc", "-O3", "-fPIC", "-shared", "-o", LIB, SRC]
    print("编译：", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("✗ 编译失败：")
        print(r.stderr.strip())
        return r.returncode
    print(f"✓ 已生成 {os.path.relpath(LIB, ROOT)}")
    return 0 if verify_lib() else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="编译 AGORA 的 C 后端 Keccak-256")
    ap.add_argument("--check", action="store_true", help="仅校验已编译产物")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    if a.check:
        return 0 if verify_lib(quiet=a.quiet) else 1
    return build()


if __name__ == "__main__":
    sys.exit(main())
