# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 测试网 / 开发网创世构建器
========================================

输入：创始验证者名单（CSV：pubkey_hex, amount_atom）
输出：**完整且闭合**的创世配置 JSON —— 含创世状态根、创世哈希、以及逐地址的
      最终余额分配，使任何第三方都能仅凭该文件复现出同一创世。

为什么需要这个工具
------------------
`agora_genesis_keygen.py genesis-template` 产出的是**模板**：它不含创世状态根、
不含创世哈希，分配方案也可能是 `PENDING-MAINNET-VALUE`（即创世金额不闭合）。
而一个可启动的测试网必须给出**确定的创世哈希**，否则各节点算出的创世不同，
连第一条共识消息都对不上。

本工具与模板工具的分工：
  · 模板工具  —— 人读的、用于讨论与治理确认的配置草案；
  · 本工具    —— 机器读的、可直接喂给节点启动的**冻结产物**。

与主网的差异（DEPLOYMENT_PLAN.md §6，**只允许这两处不同**）
----------------------------------------------------------
    参数            主网                     测试网/开发网
    chain_id        agora-mainnet-1          agora-testnet-1 / agora-devnet-1
    GenesisTimestamp 1790812800（冻结）       自定（默认取当前整点，便于立刻启动）

其余参数一律相同（SLOT_TIME、EPOCH_LENGTH、QUORUM 公式、gas 表、罚没比例、
发行曲线……）。若测试网用了不同参数，测试结论**不能**用于主网。

用法
----
    # 生成 4 把测试网密钥（允许本机批量；主网密钥必须单把生成）
    python3 tools/agora_genesis_keygen.py keygen --count 4 --network testnet --out-dir tn-keys

    # 由 keygen 产出的 CSV 构建创世
    python3 tools/agora_genesis_build.py --network testnet --validators tn-keys/pubkeys.csv \\
        --out testnet-genesis.json

    # 校验已生成的创世（任何节点启动前都应跑一遍）
    python3 tools/agora_genesis_build.py --check testnet-genesis.json
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agora import params as P


def _load_validators(path: str):
    """读取 `pubkey_hex, amount_atom` CSV；返回 `[(pubkey, amount_atom), ...]`。"""
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        rd = csv.DictReader(f)
        cols = [c.strip() for c in (rd.fieldnames or [])]
        if "pubkey_hex" not in cols:
            raise SystemExit(f"CSV 缺少必需列 pubkey_hex（实际：{cols}）")
        amt_col = "amount_atom" if "amount_atom" in cols else (
            "initial_stake_atom" if "initial_stake_atom" in cols else None)
        if amt_col is None:
            raise SystemExit(f"CSV 缺少金额列 amount_atom（实际：{cols}）")
        for i, r in enumerate(rd, start=2):
            r = {(k or "").strip(): (v or "").strip() for k, v in r.items()}
            pk_hex = r["pubkey_hex"].removeprefix("0x").removeprefix("0X")
            if len(pk_hex) != 64:
                raise SystemExit(f"第 {i} 行：公钥必须为 64 位十六进制，实际 {len(pk_hex)}")
            try:
                pk = bytes.fromhex(pk_hex)
            except ValueError:
                raise SystemExit(f"第 {i} 行：公钥含非十六进制字符")
            raw = r[amt_col]
            if not raw:
                raise SystemExit(f"第 {i} 行：{amt_col} 为空")
            try:
                amt = int(raw)
            except ValueError:
                raise SystemExit(f"第 {i} 行：{amt_col} 不是整数（实际 {raw!r}）")
            rows.append((pk, amt))
    if not rows:
        raise SystemExit("CSV 中没有验证者行")
    if len({pk for pk, _ in rows}) != len(rows):
        raise SystemExit("CSV 中存在重复公钥")
    return rows


def _load_balances(path: str):
    """载入创世余额表：`pubkey_hex,amount_atom`（可带注释行与表头）。

    为什么这里**只接受公钥**而不是地址：`GenesisAllocation.balances` 的输入是公钥，
    地址只是它的哈希，无法反推。若允许写地址，构建器就只能靠"地址属于某个验证者"
    来猜公钥 —— 那正是旧版 `--check` 无法复核非验证者余额的原因。
    """
    rows = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [x.strip() for x in line.split(",")]
            if parts[0].lower().startswith("pubkey"):
                continue
            if len(parts) < 2:
                raise SystemExit(f"{path}:{lineno}: 需要 pubkey_hex,amount_atom")
            key = parts[0].removeprefix("0x")
            if len(key) != 64:
                raise SystemExit(
                    f"{path}:{lineno}: 必须是 32 字节公钥（64 位十六进制）；"
                    f"长度 {len(key)}。地址无法反推公钥，请改用公钥。")
            amt = int(parts[1])
            if amt <= 0:
                raise SystemExit(f"{path}:{lineno}: 余额必须为正")
            rows.append((bytes.fromhex(key), amt))
    seen = {}
    for pk, amt in rows:
        seen[pk] = seen.get(pk, 0) + amt
    if len(seen) != len(rows):
        raise SystemExit(f"{path}: 存在重复公钥（已合并，请检查分配表）")
    return rows


def st_expected_root(cfg: dict) -> str:
    """配置里声明的创世状态根（`0x…`）。"""
    return str(cfg.get("genesis_state_root", "")).removeprefix("0x").lower()


def build(network: str, validators_path: str, genesis_ts: int | None,
          airdrop_pending: int, extra_balances: int,
          balances_path: str | None = None,
          reserve_pubkey: str | None = None,
          dev_mainnet_unsafe: bool = False,
          airdrop_table: str | None = None) -> dict:
    """构建完整的创世配置。"""
    from agora.crypto_backend import address_from_pubkey
    from agora.state import (GenesisAllocation, build_genesis_state,
                             genesis_hash, validate_genesis_closure)
    from agora.state import AirdropEntry as AirdropEntryFor
    from agora.genesis_cfg import airdrop_entries_to_json

    validators = _load_validators(validators_path)

    # ① 链身份必须在**任何**签名/状态构建之前确定（规范 §4）
    P.set_network(network)
    if network == "mainnet" and not dev_mainnet_unsafe:
        raise SystemExit(
            "本工具默认拒绝构建主网创世：主网需填充 F2 空投表与 F7 创始公钥，"
            "并满足 GATE-11（见规范 §37 / DEPLOYMENT_PLAN.md §6）。\n"
            "若你确实要用**主网参数**做本机演练，请显式加上 --dev-mainnet-unsafe，"
            "产物会被标记为 DEV-UNSAFE 且不得对外分发。")
    if network == "mainnet":
        print("!" * 72)
        print("★ 警告：正在构建**主网参数**的创世（--dev-mainnet-unsafe）")
        print("  这**不是**主网发布：它只是用 agora-mainnet-1 参数在本机跑的演练链。")
        print("  主网发布的前置条件（GATE-8/9/11）并未满足；产物带 DEV-UNSAFE 标记。")
        print("!" * 72)

    gts = genesis_ts if genesis_ts is not None else (int(time.time()) // 3600) * 3600

    # ② 分配闭合（规范 §32.2）：
    #    Σ 验证者质押 + Σ 普通余额 + 空投金库 == INITIAL_SUPPLY
    total_stake = sum(a for _, a in validators)

    # 空投金库（§32.5）：金库余额**只能**来自分配表的条目
    # （`build_genesis_state` 按 `sum(e.amount)` 给金库记账，并写入 Merkle 根）。
    # 旧版只接受一个金额、却不建条目，于是统计总额永远比 INITIAL_SUPPLY 少
    # `airdrop_pending` ⇒ 该参数**从未成功过**（一用就报"创世金额不闭合"）。
    # 现改为：要么给表，要么显式拒绝 —— 绝不静默产出一个不闭合的创世。
    airdrop_entries = []
    if airdrop_table:
        from agora.state import airdrop_merkle_root
        _data = json.load(open(airdrop_table, encoding="utf-8"))
        _rows = _data.get("entries", _data if isinstance(_data, list) else [])
        for _e in _rows:
            # **键名必须两种都认**：`agora_genesis_keygen.py airdrop-build` 写的是
            # `amount` / `gas_allowance`，而本工具此前只读 `amount_atom` /
            # `gas_allowance_atom` ⇒ 拿该工具的合法产物直接 `KeyError` 崩溃
            # （连一句可读的错误都没有）。这两个工具是**唯一的**空投表来源，
            # 必须彼此兼容。
            def _pick(*names, default=None):
                for nm in names:
                    if nm in _e and _e[nm] not in (None, ""):
                        return _e[nm]
                return default
            _amt = _pick("amount_atom", "amount")
            if _amt is None:
                raise SystemExit(
                    f"空投表条目缺少金额字段（应有 amount_atom 或 amount）：{_e}")
            _ga = _pick("gas_allowance_atom", "gas_allowance", default=0) or 0
            _idx = int(_pick("index", default=0) or 0)
            airdrop_entries.append(AirdropEntryFor(
                pubkey=bytes.fromhex(str(_e["pubkey_hex"]).removeprefix("0x")),
                amount=int(_amt),
                gas_allowance=int(_ga),
                index=_idx))          # **必须带上 index**（BUG-87）：它是叶子的一部分，
                                      # 丢了它 ⇒ 每条目 index 都为 0 ⇒ 算出的根与分配表
                                      # 声明的根不同 ⇒ 钱包的领取证明永远通不过第 16 项。
        # ③ **与分配表声明的根对账**：这是唯一能自动发现"键名/宽度/index 不一致"的守卫。
        #    没有它，上述任何一类错误都会**静默地**产出一条根不对的链，
        #    等到用户领取时才发现（而且看起来像"钱包有 bug"）。
        _declared = str(_data.get("airdrop_root", "") if isinstance(_data, dict) else "")
        if _declared:
            _want = bytes.fromhex(_declared.removeprefix("0x"))
            _got = airdrop_merkle_root(airdrop_entries)
            if _got != _want:
                raise SystemExit(
                    "空投表与创世构建结果不一致 —— 拒绝构建（否则会产出一条"
                    "任何人都领不到空投的链）：\n"
                    f"    分配表声明的 airdrop_root = {_declared}\n"
                    f"    按条目重算   airdrop_root = 0x{_got.hex()}\n"
                    "  常见原因：① 条目的 index 缺失/被改写；② 叶子使用「最小宽度」整数"
                    "而非定宽（规范要求 u64(index)/u256(gas_allowance)）；\n"
                    "           ③ 分配表不是用 tools/agora_genesis_keygen.py airdrop-build 生成的。")
        _total = sum(_e.amount for _e in airdrop_entries)
        if airdrop_pending and airdrop_pending != _total:
            raise SystemExit(f"--airdrop-pending {airdrop_pending:,} 与分配表合计 "
                             f"{_total:,} 不一致")
        airdrop_pending = _total
    elif airdrop_pending:
        raise SystemExit(
            "--airdrop-pending 必须与 --airdrop-table 一起使用：金库余额由分配表条目求和"
            "得出（规范 §32.5）。只给金额会得到不闭合的创世 —— 这是旧版本的缺陷，"
            "现已改为显式拒绝。")

    # **空投的 `gas_allowance` 也必须从余量里扣掉**（规范 §32.5）：
    # 它在创世时**直接记入各受益人余额**（否则受益人付不起首次领取的 gas 费），
    # 因此它和空投本金一样占用初始供应。此前这里只扣了 `airdrop_pending`，
    # 于是任何带 gas_allowance 的分配表都**无法闭合** —— 报错"创世金额不闭合"
    # 却不指出是 gas_allowance 造成的（实测：3 条各 0.005 AGORA 的表就触发）。
    from agora.state import airdrop_gas_allowance_total as _ga_total
    gas_allowance_total = _ga_total(airdrop_entries)
    rest = P.INITIAL_SUPPLY - total_stake - airdrop_pending - gas_allowance_total
    if extra_balances < 0:
        raise SystemExit("--extra-balances 不得为负")
    if rest < extra_balances:
        raise SystemExit(
            f"创世金额无法闭合：质押 {total_stake:,} + 空投本金 {airdrop_pending:,} "
            f"+ 空投 gas_allowance {gas_allowance_total:,} "
            f"已超过初始供应 {P.INITIAL_SUPPLY:,}\n"
            "  （gas_allowance 会直接记入受益人余额，因此与空投本金一样占用初始供应）")

    balances = []
    if balances_path:
        balances = _load_balances(balances_path)
        if airdrop_pending:
            raise SystemExit("--balances-csv 与 --airdrop-pending 不能同时使用"
                             "（空投金库需 F2 分配表，见 §32.5）")
        if extra_balances:
            raise SystemExit("--balances-csv 与 --extra-balances 不能同时使用")
        assigned = total_stake + sum(a for _, a in balances)
        remainder = P.INITIAL_SUPPLY - assigned
        if remainder < 0:
            raise SystemExit(
                f"创世金额无法闭合：质押 {total_stake:,} + 余额 {assigned - total_stake:,} "
                f"已超过初始供应 {P.INITIAL_SUPPLY:,}")
        if remainder > 0:
            if not reserve_pubkey:
                raise SystemExit(
                    f"创世还差 {remainder:,} atom（≈{remainder / 10**18:,.0f} AGORA）"
                    f"没有归属。请用 --reserve-pubkey <64位十六进制公钥> 显式指定"
                    f"（建议用你的国库/创始人密钥；未指定时**不猜**，避免把巨额余额"
                    f"静默塞给某个账户）。")
            key = reserve_pubkey.removeprefix("0x")
            if len(key) != 64:
                raise SystemExit("--reserve-pubkey 必须是 32 字节公钥")
            balances.append((bytes.fromhex(key), remainder))
        per_extra = 0
    else:
        # 兼容旧行为：余量分配给第一个验证者（仅测试网；主网需治理确认）
        per_extra = rest - extra_balances
        if per_extra:
            balances.append((validators[0][0], per_extra))

    alloc = GenesisAllocation(
        validators=validators,
        balances=balances,
        airdrop=airdrop_entries,
        genesis_timestamp=gts)

    errs = validate_genesis_closure(alloc)
    if errs:
        raise SystemExit("创世配置不合法：\n  - " + "\n  - ".join(errs))

    st, _ = build_genesis_state(alloc)          # 会自动冻结链身份

    # ③ 产出**可复现**的产物：状态根、创世哈希、逐地址余额
    # 列出**全部**持币账户（验证者 + 创世余额）：只列验证者会让 `--check`
    # 复现不出创世（余额漏掉 ⇒ 金额不闭合），实测踩过一次。
    # 去重：同一个公钥既可能是验证者又持有余额，重复列两次会让
    # `--check` / 节点重建时把余额算两遍（实测：金额翻倍、闭合成 2 倍供应量）
    _seen_pk, _all_pk = set(), []
    for pk, _ in list(validators) + list(balances):
        if pk not in _seen_pk:
            _seen_pk.add(pk)
            _all_pk.append(pk)
    accounts = sorted(
        ((address_from_pubkey(pk), st.account_or_empty(address_from_pubkey(pk)).balance, pk)
         for pk in _all_pk),
        key=lambda kv: kv[0])

    gh = genesis_hash(st, alloc)
    return {
        "protocol_version": P.PROTOCOL_VERSION,
        "network": network,
        "chain_id": P.CHAIN_ID,
        "genesis_timestamp": gts,
        "initial_supply_atom": str(P.INITIAL_SUPPLY),
        "genesis_state_root": "0x" + st.state_root.hex(),
        "genesis_hash": "0x" + gh.hex(),
        "validator_set_commitment": "0x" + st.validator_set_commitment().hex(),
        "genesis_validators": [
            {"pubkey_hex": pk.hex(),
             "address_hex": "0x" + address_from_pubkey(pk).hex(),
             "initial_stake_atom": str(amt),
             "voting_power_atom": str(amt)}
            for pk, amt in sorted(validators, key=lambda x: address_from_pubkey(x[0]))
        ],
        "genesis_balances": [{"pubkey_hex": pk.hex(), "address_hex": "0x" + a.hex(),
                              "balance_atom": str(b),
                              "role": ("validator" if pk in {p for p, _ in validators}
                                       else "balance")}
                             for a, b, pk in accounts if b],
        "airdrop_root": "0x" + st.system.airdrop_root.hex(),
        "airdrop_pending_atom": str(st.system.airdrop_pending),
        # **空投条目本身必须写进配置**（不只是根）：
        # 链上只存根，但节点重建创世状态时需要**条目**（金库余额、各受益人的
        # gas_allowance 都来自条目）。此前只写了根与总额 ⇒ 节点重建出的金库为 0
        # ⇒ 自检"金额不闭合"⇒ 拒绝启动；而构建器打印的却是"金额闭合 ✓"。
        "genesis_airdrop": airdrop_entries_to_json(airdrop_entries),
        "airdropped": False,
        "consensus_params": {
            "slot_time_seconds": P.SLOT_TIME,
            "epoch_length_slots": P.EPOCH_LENGTH,
            "quorum_formula": "ceil_div(2 * S_epoch, 3)（atom 粒度，规范 §9.1）",
            "quorum_atom": str(-(-2 * total_stake // 3)),
            "total_stake_atom": str(total_stake),
            "base_timeout_ms": P.BASE_TIMEOUT_MS,
            "round_timeout_increment_ms": P.ROUND_TIMEOUT_INCREMENT_MS,
            "phase_timeouts_ms": {"proposal": P.PROPOSAL_TIMEOUT_MS,
                                  "prevote": P.PREVOTE_TIMEOUT_MS,
                                  "precommit": P.PRECOMMIT_TIMEOUT_MS},
        },
        # 闭合口径**必须**与 `validate_genesis_closure` 完全一致：
        # 初始供应 = 质押 + 普通余额 + 空投本金 + 空投 gas_allowance。
        # 漏掉最后一项会让"其实已闭合"的产物被标成 `balanced: false`，
        # 并让构建器以非零码退出（实测：3 条各 0.005 AGORA 的 gas_allowance 即触发）。
        "closure": {
            "sum_validator_stake_atom": str(total_stake),
            "sum_balances_atom": str(sum(x for _, x in balances)),
            "sum_airdrop_pending_atom": str(airdrop_pending),
            "sum_airdrop_gas_allowance_atom": str(gas_allowance_total),
            "total_atom": str(total_stake + sum(x for _, x in balances)
                              + airdrop_pending + gas_allowance_total),
            "balanced": (total_stake + sum(a for _, a in balances)
                         + airdrop_pending + gas_allowance_total) == P.INITIAL_SUPPLY,
        },
        "status": (f"{network} 冻结产物（可由本工具 --check 独立复核）"
                   + ("  ★ DEV-UNSAFE：主网参数的本机演练链，不得对外分发"
                      if network == "mainnet" else "")),
    }


def check(path: str) -> int:
    """**独立复核**：从产物重建创世，比对状态根与创世哈希是否一致。

    这是启动前的必要步骤：若某台机器用不同参数（或不同代码版本）构建创世，
    其创世哈希会不同，节点之间连第一条共识消息都对不上——
    而症状通常表现为"投票永远凑不齐"，极难排查。
    """
    from agora.state import (GenesisAllocation, build_genesis_state,
                             genesis_hash, AirdropEntry, airdrop_merkle_root)

    cfg = json.load(open(path, encoding="utf-8"))
    P.set_network(cfg["network"])
    vals = [(bytes.fromhex(v["pubkey_hex"]), int(v["initial_stake_atom"]))
            for v in cfg["genesis_validators"]]
    bals = [(bytes.fromhex(b["address_hex"].removeprefix("0x")), int(b["balance_atom"]))
            for b in cfg.get("genesis_balances", [])]

    # 余额在创世里按**地址**给出，而创世构建接口按**公钥**给出；测试网创世把
    # 余量放在第一个验证者地址上，因此这里按地址回填到对应公钥。
    from agora.crypto_backend import address_from_pubkey
    addr2pk = {address_from_pubkey(pk): pk for pk, _ in vals}
    pubkeys = {pk.hex(): pk for pk, _ in vals}
    pk_balances = []
    for entry in cfg.get("genesis_balances", []):
        addr = bytes.fromhex(entry["address_hex"].removeprefix("0x"))
        amt = int(entry["balance_atom"])
        if not amt:
            continue
        pkh = entry.get("pubkey_hex")
        if pkh:                       # 新格式：直接给公钥 ⇒ 任何账户都可复核
            pk_balances.append((bytes.fromhex(pkh), amt))
        elif addr in addr2pk:         # 旧格式：只能复核验证者自己的余额
            pk_balances.append((addr2pk[addr], amt))
        else:
            print(f"✗ 余额 {addr.hex()} 既无 pubkey_hex 也不属于任何创始验证者，"
                  f"无法复核（旧格式限制）")
            return 1

    alloc = GenesisAllocation(validators=vals, balances=pk_balances,
                              airdrop=[], genesis_timestamp=cfg["genesis_timestamp"])
    st, errs = build_genesis_state(alloc, strict=False)
    if errs:
        print("✗ 复核失败：创世配置不合法")
        for e in errs:
            print(f"   - {e}")
        return 1

    got_root = "0x" + st.state_root.hex()
    got_hash = "0x" + genesis_hash(st, alloc).hex()
    ok = True
    for label, got, want in (("创世状态根", got_root, cfg["genesis_state_root"]),
                             ("创世哈希", got_hash, cfg["genesis_hash"]),
                             ("链身份", P.CHAIN_ID, cfg["chain_id"])):
        good = got == want
        ok &= good
        print(f"  [{'OK  ' if good else 'FAIL'}] {label}：{got}"
              + ("" if good else f"（期望 {want}）"))

    # 闭合复核：**gas_allowance 也占用初始供应**（它在创世时直接记入受益人余额，
    # 规范 §32.5）。此前这里漏了它，于是任何带 gas_allowance 的分配表都会被
    # 误报为"未闭合"并让 `--check` 返回失败 —— 与 `validate_genesis_closure`
    # 的口径不一致（后者是算进去的）。
    from agora.state import airdrop_gas_allowance_total as _ga
    _ga_total = _ga(alloc.airdrop)
    tot = (sum(a for _, a in vals) + sum(a for _, a in pk_balances)
           + st.system.airdrop_pending + _ga_total)
    print(f"  [{'OK  ' if tot == P.INITIAL_SUPPLY else 'FAIL'}] 金额闭合："
          f"{tot:,} == {P.INITIAL_SUPPLY:,}")
    ok &= (tot == P.INITIAL_SUPPLY)
    print("结果：" + ("✅ 创世可复现，全节点可安全启动" if ok else "★ 产物不可复现"))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="构建 / 复核 AGORA 测试网创世")
    ap.add_argument("--check", metavar="GENESIS_JSON",
                    help="复核已生成的创世文件（不重新构建）")
    ap.add_argument("--network", default="testnet",
                    choices=["mainnet", "testnet", "devnet"],
                    help="网络（本工具拒绝主网，理由见脚本头部说明）")
    ap.add_argument("--validators", help="验证者 CSV（pubkey_hex, amount_atom）")
    ap.add_argument("--genesis-timestamp", type=int, default=None,
                    help="创世时间戳（默认取当前整点，便于立刻启动）")
    ap.add_argument("--airdrop-pending", type=int, default=0,
                    help="空投金库金额（atom）；**必须**与 --airdrop-table 一起给出"
                         "（金库余额只能由 §32.5 分配表的条目求和得出）")
    ap.add_argument("--airdrop-table",
                    help="F2 空投分配表 JSON（agora_genesis_keygen.py airdrop-build 产物）")
    ap.add_argument("--extra-balances", type=int, default=0,
                    help="额外划出的普通余额（atom）")
    ap.add_argument("--balances-csv",
                    help="创世余额表 CSV：pubkey_hex,amount_atom（可多行，带注释）")
    ap.add_argument("--reserve-pubkey",
                    help="创世余量的归属公钥（未指定且有余量时报错，不静默塞给某账户）")
    ap.add_argument("--dev-mainnet-unsafe", action="store_true",
                    help="允许用主网参数构建创世（仅本机演练，产物标记 DEV-UNSAFE）")
    ap.add_argument("--out", help="输出 JSON 路径")
    a = ap.parse_args()

    if a.check:
        return check(a.check)
    if not a.validators:
        ap.error("构建模式需要 --validators")

    cfg = build(a.network, a.validators, a.genesis_timestamp,
                a.airdrop_pending, a.extra_balances,
                balances_path=a.balances_csv,
                reserve_pubkey=a.reserve_pubkey,
                dev_mainnet_unsafe=a.dev_mainnet_unsafe,
                airdrop_table=a.airdrop_table)
    text = json.dumps(cfg, ensure_ascii=False, indent=2)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        # ── **回写保护：用节点的方式把刚写下的配置读回来** ──────────────
        # 只校验内存对象是不够的。实测缺陷正是"内存里闭合、写出去的配置读不回来"：
        # 空投条目漏写 ⇒ 节点重建出的金库为 0 ⇒ 自检"金额不闭合"⇒ **节点拒绝启动**，
        # 而构建器这边打印的却是"金额闭合 ✓"。因此必须走**同一个**加载函数，
        # 不一致就删掉产物并以非零码退出（宁可不出产物，也不要留下一个起不来的创世）。
        from agora.genesis_cfg import GenesisConfigError, load_genesis_config
        try:
            _cfg2, _alloc2, _st2 = load_genesis_config(a.out)
        except GenesisConfigError as e:
            print(f"★ 写出的创世配置**读不回来**，已删除 {a.out}：\n  {e}")
            os.remove(a.out)
            return 1
        if _st2.state_root.hex().lower() != st_expected_root(cfg):
            print(f"★ 回读得到的状态根与构建时不一致，已删除 {a.out}")
            os.remove(a.out)
            return 1
        print(f"✓ 已写入 {a.out}（并已用节点的方式回读复核）")
    else:
        print(text)

    print("\n── 摘要 ──")
    print(f"网络 / chain_id     : {cfg['network']} / {cfg['chain_id']}")
    print(f"创世时间戳          : {cfg['genesis_timestamp']}")
    print(f"创始验证者          : {len(cfg['genesis_validators'])} 名")
    print(f"质押总量 S          : {int(cfg['consensus_params']['total_stake_atom']) / P.ATOM_PER_AGORA:,.0f} AGORA")
    print(f"QUORUM              : {cfg['consensus_params']['quorum_atom']} atom")
    print(f"创世状态根          : {cfg['genesis_state_root']}")
    print(f"创世哈希            : {cfg['genesis_hash']}")
    print(f"金额闭合            : {'✓' if cfg['closure']['balanced'] else '★ 未闭合'}")
    return 0 if cfg["closure"]["balanced"] else 1


if __name__ == "__main__":
    sys.exit(main())
