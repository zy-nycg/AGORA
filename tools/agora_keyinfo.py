# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 节点身份信息（离线，只读私钥文件的**公钥部分**）
==============================================================

用途
----
跨机部署时，每台机器都要把自己验证者的**公钥**交给其他机器，写进它们的
`--peer name@host:port@<pubkey-hex>`（名字↔连接的签名握手，规范 §6.7）。
本工具就是那条命令：**只读私钥文件、只输出公钥与地址**，
私钥本身不会出现在输出里，也不会被写进任何文件。

用法
----
    # 打印本节点的名字/公钥/地址（供别人写进 --peer）
    python3 tools/agora_keyinfo.py --seed-file keys/key1.seed

    # 只输出公钥十六进制（便于脚本拼接 --peer）
    python3 tools/agora_keyinfo.py --seed-file keys/key1.seed --pubkey-only

    # 目录里有一整套 keyN.seed 时，一次性列出（本机多进程联调用）
    python3 tools/agora_keyinfo.py --key-dir wallet/runs/devkeys --count 4

安全纪律
--------
* **只读**；不打印私钥，不落盘任何材料；
* 输出里的"指纹"是 `Keccak(pubkey)` 前 16 个十六进制字符，用于人工比对
  （防止把两把密钥的公钥搞混 —— 那会让握手永远失败且难以定位）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agora.crypto_backend import address_from_pubkey, publickey_from_seed
from agora.crypto import keccak256


def _load_seed(path: str) -> bytes:
    raw = open(path, encoding="utf-8").read().strip()
    if raw.startswith("{"):                      # keygen 工具写出的 JSON 形式
        raw = json.loads(raw).get("seed") or json.loads(raw)["private_key_hex"]
    seed = bytes.fromhex(raw.removeprefix("0x"))
    if len(seed) != 32:
        raise SystemExit(f"{path}: 私钥种子必须为 32 字节（64 位十六进制）")
    return seed


def _line(path: str, name: str = "") -> str:
    seed = _load_seed(path)
    pk = publickey_from_seed(seed)
    addr = address_from_pubkey(pk)
    fp = keccak256(pk).hex()[:16]
    who = name or os.path.basename(path).split(".")[0]
    return f"{who}\t{pk.hex()}\t0x{addr.hex()}\t{fp}…"


def main() -> int:
    ap = argparse.ArgumentParser(description="打印节点公钥/地址（供 --peer name@host:port@pubkey 使用）")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--seed-file", help="单个私钥种子文件")
    g.add_argument("--key-dir", help="含 keyN.seed 的目录")
    ap.add_argument("--count", type=int, default=4, help="--key-dir 时的节点数")
    ap.add_argument("--pubkey-only", action="store_true", help="只输出公钥十六进制")
    a = ap.parse_args()

    if a.seed_file:
        if not os.path.exists(a.seed_file):
            raise SystemExit(f"文件不存在：{a.seed_file}")
        line = _line(a.seed_file)
        print(line.split("\t")[1] if a.pubkey_only else line)
        return 0

    print("name\tpubkey_hex\taddress\tfingerprint")
    rows = []
    for i in range(1, a.count + 1):
        p = os.path.join(a.key_dir, f"key{i}.seed")
        if not os.path.exists(p):
            break
        rows.append(_line(p, f"node{i}"))
    if not rows:
        raise SystemExit(f"{a.key_dir} 下没有找到 keyN.seed")
    for r in rows:
        print(r)
    print()
    print("拼装示例（把下面每一行放进**其它机器**的启动命令）：")
    for r in rows:
        who, pkhex = r.split("\t")[0], r.split("\t")[1]
        print(f"  # 在别的节点上：--peer {who}@<本机IP>:{26656 + (int(who[4:]) - 1) * 10}@{pkhex}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
