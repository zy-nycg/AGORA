# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 创世配置的**唯一读写实现**（配置 ↔ `GenesisAllocation`）
======================================================================

**为什么必须只有一个实现**
--------------------------
"创世配置文件"由构建器写、由节点读。这两端一旦各写一份解析逻辑，就会出现
**只有端到端跑起来才会暴露**的错配 —— 而且症状指向别处。实测过的形态：

* 构建器写下了 `airdrop_root` / `airdrop_pending_atom`，却**没有写空投条目本身**；
* 节点读配置时只重建了验证者与余额，**没有重建空投** ⇒ 金库余额为 0 ⇒
  节点自检报"创世金额不闭合（差额恰好等于空投总额）" ⇒ **节点拒绝启动**；
* 而构建器那边打印的却是"金额闭合 ✓" —— 它只校验了**内存里的对象**，
  没有校验**序列化往返**。

修法不是"补一个字段"，而是把 `(配置) ↔ (分配)` 的转换收敛到本模块：
构建器写完必须用**同一个函数**读回来校验，节点启动也走**同一个函数**。
于是"写出来读不回去"这类缺陷结构性地不可能再出现。

职责：
    `dump_allocation(cfg_path)` —— 构建器写完配置后，用节点的方式重新读一遍
    `load_genesis_config(path)`  —— 节点与构建器共用的加载 + 校验（含空投根对账）
"""

from __future__ import annotations

import json
from typing import List, Optional, Tuple

from . import params as P
from .crypto_backend import address_from_pubkey
from .state import (AirdropEntry, GenesisAllocation, State, airdrop_merkle_root,
                    build_genesis_state)

__all__ = ["load_genesis_config", "GenesisConfigError", "airdrop_entries_to_json"]


class GenesisConfigError(Exception):
    """创世配置不合法（或与声明不符）。调用方**必须**拒绝启动/拒绝写出。"""


def airdrop_entries_to_json(entries: List[AirdropEntry]) -> list:
    """把空投条目序列化成配置里的 `genesis_airdrop`。

    `index` **必须**写进去：它是叶子的组成部分（BUG-87），丢了它就会算出
    另一个 `airdrop_root` —— 表现为"钱包的领取证明通不过第 16 项"。
    """
    return [{"pubkey_hex": e.pubkey.hex(),
             "address_hex": "0x" + address_from_pubkey(e.pubkey).hex(),
             "amount_atom": str(e.amount),
             "gas_allowance_atom": str(e.gas_allowance),
             "index": int(e.index),
             "note": e.note} for e in entries]


def load_genesis_config(path: str, strict_airdrop_root: bool = True
                        ) -> Tuple[dict, GenesisAllocation, State]:
    """读取创世配置并重建 `(cfg, alloc, state)`。

    节点的启动路径与构建器的自检路径**都调用它** —— 这是"写出来必须读得回去"
    的落地方式。
    """
    try:
        cfg = json.load(open(path, encoding="utf-8"))
    except Exception as e:                               # noqa: BLE001
        raise GenesisConfigError(f"创世配置无法读取：{e}")
    if "network" not in cfg:
        raise GenesisConfigError("创世配置缺少 network 字段")
    P.set_network(cfg["network"])

    vals = [(bytes.fromhex(v["pubkey_hex"]), int(v["initial_stake_atom"]))
            for v in cfg["genesis_validators"]]
    addr2pk = {address_from_pubkey(pk): pk for pk, _ in vals}

    bals = []
    for b in cfg.get("genesis_balances", []):
        amt = int(b["balance_atom"])
        if not amt:
            continue
        pkh = b.get("pubkey_hex")
        if pkh:
            bals.append((bytes.fromhex(pkh.removeprefix("0x")), amt))
            continue
        addr = bytes.fromhex(b["address_hex"].removeprefix("0x"))
        if addr not in addr2pk:
            raise GenesisConfigError(
                f"创世余额地址 {addr.hex()} 不属于任何创始验证者，且该条目没有 "
                f"pubkey_hex —— 无法重建创世（旧格式限制）")
        bals.append((addr2pk[addr], amt))

    # ── 空投：**必须**从配置读回条目（缺失 ⇒ 金库为 0 ⇒ 金额不闭合）──
    airdrop: List[AirdropEntry] = []
    for e in cfg.get("genesis_airdrop", []) or []:
        pk = bytes.fromhex(str(e["pubkey_hex"]).removeprefix("0x"))
        amt = e.get("amount_atom", e.get("amount"))
        if amt is None:
            raise GenesisConfigError(f"空投条目缺少金额：{e}")
        ga = e.get("gas_allowance_atom", e.get("gas_allowance", 0)) or 0
        airdrop.append(AirdropEntry(pubkey=pk, amount=int(amt),
                                    gas_allowance=int(ga),
                                    index=int(e.get("index", 0) or 0),
                                    note=str(e.get("note", ""))))

    alloc = GenesisAllocation(validators=vals, balances=bals, airdrop=airdrop,
                              genesis_timestamp=cfg["genesis_timestamp"])
    unsafe = len(vals) < P.GENESIS_VALIDATOR_COUNT
    st, errs = build_genesis_state(alloc, strict=False, allow_unsafe=unsafe)
    real_errs = [e for e in errs if "已豁免" not in e]
    if real_errs:
        raise GenesisConfigError("创世配置不合法：\n  - " + "\n  - ".join(real_errs))

    # ── 与配置里声明的空投根对账 ──
    # 这是**唯一**能自动发现"条目丢失 / index 丢失 / 宽度写错"的地方：
    # 没有它，上述任何一类错误都会让节点在启动时才炸，且报错指向"金额不闭合"。
    declared = str(cfg.get("airdrop_root", "") or "")
    if declared:
        want = bytes.fromhex(declared.removeprefix("0x"))
        got = airdrop_merkle_root(airdrop) if airdrop else st.system.airdrop_root
        if got != want:
            msg = ("创世配置里的 airdrop_root 与按条目重算的结果不符：\n"
                   f"    配置声明 = {declared}\n"
                   f"    条目重算 = 0x{got.hex()}\n"
                   f"    条目数   = {len(airdrop)}")
            if strict_airdrop_root:
                raise GenesisConfigError(msg)
    if st.system.airdrop_root.hex() != (declared.removeprefix("0x") or
                                        st.system.airdrop_root.hex()):
        raise GenesisConfigError(
            "重建的创世状态里的 airdrop_root 与配置声明不符 —— "
            "这说明配置与状态不是同一份（拒绝启动）")
    return cfg, alloc, st
