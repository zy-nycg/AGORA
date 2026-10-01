#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGORA — 创世开发者奖励钱包生成器（离线，仅标准库 + 本仓库参考实现）
====================================================================

用途
----
生成 N 个 Ed25519 钱包，并把一个**固定池子**按**可复现的随机权重**分配到这些账户，
作为创世（测试网 / 主网演练）的开发者奖励。

设计约束（每一条都有理由，改动前请先读）
----------------------------------------
1. **私钥绝不打印到终端。** 终端输出会进入 shell 历史、CI 日志、录屏与他人视线。
   私钥只写进 `keys/dev_wallets_keys.json`（权限 0600），并提示立刻转移到离线介质。
2. **分配必须可复现。** 随机性来自一个**显式记录的种子**（`--seed-hex` 或自动生成并写入
   报告）。任何人拿到种子都能重算出完全相同的分配表 —— 否则"随机分配"无法审计，
   而这正是治理上最容易出问题的地方。
3. **不产生创世文件。** 本工具只产出「钱包 + 分配表 + 余额 CSV」；
   创世由 `tools/agora_genesis_build.py` 构建（它做 §32.2 的闭合校验）。
   职责分开，是为了让"谁拿了多少"与"链怎么启动"能被分别复核。
4. **权重分布是显式参数**（`--weight-max`），不是"感觉随机"。默认 1..999 的均匀权重，
   即最高/最低分配比约 1000:1，让奖励看起来像真实的贡献差异而非平均主义。

⚠️ 治理提醒（必须与产物一起读）：把创世供应的一部分分给一批"自己控制的钱包"，
在主网上**必须公开披露**（谁、多少、为什么），这是 GATE-11 的要求。
本工具不会也不能替代那份披露 —— 它只保证分配过程**可复现、可核对**。

用法
----
    # 生成 100 个钱包，把初始供应的 10% 随机分配（种子自动生成并记录）
    python3 tools/agora_dev_wallet.py gen --count 100 --pool-pct 10 --out-dir wallet

    # 用指定种子复现同一份分配（审计用）
    python3 tools/agora_dev_wallet.py gen --count 100 --pool-pct 10 \
        --out-dir wallet --seed-hex <64位十六进制>

    # 只根据已有的 keys JSON 重算分配表（校验用）
    python3 tools/agora_dev_wallet.py verify --keys wallet/keys/dev_wallets_keys.json
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agora import params as P                      # noqa: E402
from agora.crypto import address_from_pubkey, publickey_from_seed   # noqa: E402

A = P.ATOM_PER_AGORA


def _derived_seed(master: bytes, index: int) -> bytes:
    """从主种子派生出第 index 个钱包的 Ed25519 种子（HMAC-SHA256，域分离）。"""
    return hmac.new(master, f"agora-dev-wallet-seed:{index}".encode(), hashlib.sha256).digest()


def _weight(master: bytes, index: int, weight_max: int) -> int:
    """派生第 index 个钱包的分配权重（1..weight_max，均匀）。"""
    h = hmac.new(master, f"agora-dev-wallet-weight:{index}".encode(), hashlib.sha256).digest()
    return 1 + int.from_bytes(h[:8], "big") % weight_max


def allocate(pool_atom: int, weights: list) -> list:
    """按权重分配池子，**整数运算、总额精确**。

    取整规则：`floor(pool × w_i / Σw)`，余下的 R 个 atom 按索引顺序**每个钱包补 1**。
    规则刻意选得"笨"且显式：任何取整规则都会有人不满意，但**总额必须精确等于池子**，
    而且必须能被第三方一眼复算。
    """
    total_w = sum(weights)
    if total_w <= 0:
        raise ValueError("权重之和必须为正")
    out = [pool_atom * w // total_w for w in weights]
    remainder = pool_atom - sum(out)
    for i in range(remainder):
        out[i % len(out)] += 1
    assert sum(out) == pool_atom, "分配总额必须精确等于池子"
    return out


def cmd_gen(args) -> int:
    if args.count < 1:
        raise SystemExit("--count 必须 ≥ 1")
    # **禁止浮点**：2.048e25 用 float 表示会丢精度（实测会得到
    # 2,047,999,999,999,999,731,564,544 而不是 2,048,000×10^18）。
    # 规范 §17.4 明确禁止在记账算式里用浮点，这里同罪。
    from fractions import Fraction
    frac = Fraction(str(args.pool_pct)) / 100
    pool_atom = P.INITIAL_SUPPLY * frac.numerator // frac.denominator
    if pool_atom <= 0 or pool_atom >= P.INITIAL_SUPPLY:
        raise SystemExit("--pool-pct 必须位于 (0, 100)")
    if P.INITIAL_SUPPLY * frac.numerator % frac.denominator:
        raise SystemExit(f"--pool-pct={args.pool_pct} 不能整除到 atom（请用更规整的比例）")

    master = (bytes.fromhex(args.seed_hex.removeprefix("0x"))
              if args.seed_hex else secrets.token_bytes(32))
    if len(master) != 32:
        raise SystemExit("--seed-hex 必须为 32 字节（64 位十六进制）")

    weights = [_weight(master, i, args.weight_max) for i in range(1, args.count + 1)]
    amounts = allocate(pool_atom, weights)

    wallets = []
    for i in range(1, args.count + 1):
        seed = _derived_seed(master, i)
        pk = publickey_from_seed(seed)
        wallets.append({
            "index": i,
            "pubkey_hex": pk.hex(),
            "address_hex": "0x" + address_from_pubkey(pk).hex(),
            "private_seed_hex": seed.hex(),
            "weight": weights[i - 1],
            "allocation_atom": str(amounts[i - 1]),
        })
    assert len({w["address_hex"] for w in wallets}) == len(wallets), "地址必须互不相同"

    os.makedirs(args.out_dir, exist_ok=True)
    keys_dir = os.path.join(args.out_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)

    # ① 公开分配表（可随意分发、可供第三方核对）
    csv_path = os.path.join(args.out_dir, "dev_wallets.csv")
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("# AGORA 创世开发者奖励分配表（公开；不含私钥）\n")
        f.write(f"# 池子 = {pool_atom} atom = {pool_atom / A:,.0f} AGORA "
                f"= 初始供应的 {frac.numerator * 100 / frac.denominator:g}%\n")
        f.write(f"# 随机种子（用于复现本表） = {master.hex()}\n")
        f.write(f"# 权重范围 = 1..{args.weight_max}；取整余数按索引顺序每钱包补 1 atom\n")
        f.write("index,address_hex,pubkey_hex,allocation_atom,allocation_agora,weight\n")
        for w in wallets:
            f.write(f"{w['index']},{w['address_hex']},{w['pubkey_hex']},"
                    f"{w['allocation_atom']},{int(w['allocation_atom']) / A:.4f},{w['weight']}\n")

    # ② 创世余额 CSV（公钥 + atom，直接喂给 agora_genesis_build.py --balances-csv）
    bal_path = os.path.join(args.out_dir, "dev_balances.csv")
    with open(bal_path, "w", encoding="utf-8") as f:
        f.write("pubkey_hex,amount_atom\n")
        for w in wallets:
            f.write(f"{w['pubkey_hex']},{w['allocation_atom']}\n")

    # ③ 私钥（0600；只写文件，不打印）
    keys_path = os.path.join(keys_dir, "dev_wallets_keys.json")
    payload = {
        "WARNING": ("这是**私钥**文件。永远不要提交到任何仓库、云盘、聊天工具或截图。"
                    "请立刻转移到离线介质（纸质/U盘/硬件钱包）并从本机删除。"),
        "purpose": "创世开发者奖励钱包（非验证者密钥：不参与共识投票）",
        "network_marker": args.network,
        "chain_id": P.CHAIN_ID if args.network == "mainnet" else f"agora-{args.network}-1",
        "protocol_version": P.PROTOCOL_VERSION,
        "pool_atom": str(pool_atom),
        "rng": {
            "seed_hex": master.hex(),
            "seed_derivation": "seed_i = HMAC_SHA256(master, 'agora-dev-wallet-seed:i')",
            "weight_derivation": ("w_i = 1 + int(HMAC_SHA256(master, "
                                  f"'agora-dev-wallet-weight:i')[:8]) % {args.weight_max}"),
            "allocation": "floor(pool * w_i / Σw) + 余数按索引顺序每钱包 +1 atom",
        },
        "wallets": wallets,
    }
    with open(keys_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.chmod(keys_path, 0o600)

    # ④ 汇总（人看的）
    amounts_agora = sorted(int(w["allocation_atom"]) / A for w in wallets)
    top10 = sum(amounts_agora[-10:]) / (pool_atom / A) * 100
    print("─" * 72)
    print(f"已生成 {args.count} 个开发者奖励钱包 → {args.out_dir}/")
    print(f"  公开分配表      : {csv_path}（不含私钥，可公开）")
    print(f"  创世余额 CSV    : {bal_path}（供 agora_genesis_build.py 使用）")
    print(f"  私钥（权限 0600）: {keys_path}")
    print("─" * 72)
    print(f"  池子            : {pool_atom / A:,.0f} AGORA（初始供应的 {args.pool_pct}%）")
    print(f"  分配            : 最小 {amounts_agora[0]:,.2f} / 中位 "
          f"{amounts_agora[len(amounts_agora) // 2]:,.2f} / 最大 {amounts_agora[-1]:,.2f} AGORA")
    print(f"  最高 10 个钱包合计占比 : {top10:.2f}% 的池子")
    print(f"  合计核对        : {sum(int(w['allocation_atom']) for w in wallets):,} atom "
          f"== 池子 {pool_atom:,} ✅")
    print(f"  随机种子        : {master.hex()}")
    print("   ⇒ 任何人用该种子 + 本工具可复算出完全相同的分配表（可审计）")
    print("─" * 72)
    print("★ 私钥**没有**打印到终端（刻意的）。请把 keys/ 目录转移到离线介质后删除本机副本。")
    return 0


def cmd_verify(args) -> int:
    """用 keys JSON 里的种子与规则**独立重算**分配表，与表中数字比对。"""
    cfg = json.load(open(args.keys, encoding="utf-8"))
    master = bytes.fromhex(cfg["rng"]["seed_hex"])
    pool = int(cfg["pool_atom"])
    wmax = int(cfg["rng"]["weight_derivation"].rsplit("%", 1)[1].strip())
    n = len(cfg["wallets"])
    weights = [_weight(master, i, wmax) for i in range(1, n + 1)]
    amounts = allocate(pool, weights)
    bad = []
    for i, w in enumerate(cfg["wallets"]):
        if w["weight"] != weights[i] or int(w["allocation_atom"]) != amounts[i]:
            bad.append(w["index"])
        pk = publickey_from_seed(bytes.fromhex(w["private_seed_hex"]))
        if pk.hex() != w["pubkey_hex"] or address_from_pubkey(pk).hex() \
                != w["address_hex"].removeprefix("0x"):
            bad.append(f"{w['index']}(公钥/地址不匹配)")
    print(f"钱包数 {n}；重算总额 {sum(amounts):,} == 池子 {pool:,} "
          f"{'✅' if sum(amounts) == pool else '★'}")
    print("逐项一致 ✅" if not bad else f"★ 不一致项：{bad[:10]}")
    return 0 if not bad else 1


def cmd_check_genesis(args) -> int:
    """把创世 JSON 与分配表对照：**逐一验证链上余额**（不是只信 CSV）。"""
    import csv
    from agora.state import GenesisAllocation, build_genesis_state
    cfg = json.load(open(args.genesis, encoding="utf-8"))
    P.set_network(cfg["network"])
    vals = [(bytes.fromhex(v["pubkey_hex"]), int(v["initial_stake_atom"]))
            for v in cfg["genesis_validators"]]
    bals = [(bytes.fromhex(b["pubkey_hex"]), int(b["balance_atom"]))
            for b in cfg.get("genesis_balances", []) if b.get("pubkey_hex")]
    alloc = GenesisAllocation(validators=vals, balances=bals,
                              genesis_timestamp=cfg["genesis_timestamp"])
    st, errs = build_genesis_state(alloc, strict=False)
    if errs:
        print("★ 创世不合法：" + "；".join(errs))
        return 1

    want = {}
    with open(args.table, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or line.startswith("index"):
                continue
            if not line.strip():
                continue
            parts = line.strip().split(",")
            want[parts[2]] = int(parts[3])          # pubkey_hex -> atom

    bad = []
    for pkh, amt in want.items():
        got = st.account_or_empty(address_from_pubkey(bytes.fromhex(pkh))).balance
        if got != amt:
            bad.append((pkh[:12], got, amt))
    total = sum(want.values())
    print(f"分配表条目        : {len(want)}")
    print(f"分配表合计        : {total:,} atom = {total / A:,.4f} AGORA")
    print(f"链上余额逐一核对  : {len(want) - len(bad)}/{len(want)} 一致"
          f"  {'✅' if not bad else '★'}")
    if bad:
        for b in bad[:5]:
            print(f"   {b[0]}… 链上 {b[1]:,} vs 表 {b[2]:,}")
    okc, counted, recorded = st.check_supply_conservation()
    print(f"供应量守恒        : {'✅' if okc else '★'}"
          f"（统计 {counted:,} == 记录 {recorded:,}）")
    print(f"创世哈希          : {cfg['genesis_hash']}")
    return 0 if not bad and okc else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AGORA 创世开发者奖励钱包生成器")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="生成钱包并分配奖励")
    g.add_argument("--count", type=int, default=100)
    g.add_argument("--pool-pct", type=float, default=10.0,
                   help="奖励池占初始供应的百分比（默认 10）")
    g.add_argument("--weight-max", type=int, default=999,
                   help="随机权重上限（默认 999 ⇒ 最高/最低约 1000:1）")
    g.add_argument("--seed-hex", default=None, help="复现用的 32 字节种子（默认随机生成）")
    g.add_argument("--out-dir", default="wallet")
    g.add_argument("--network", default="testnet",
                   choices=["mainnet", "testnet", "devnet"],
                   help="仅作标记用；钱包本身与网络无关")
    g.set_defaults(fn=cmd_gen)

    v = sub.add_parser("verify", help="用种子独立重算并核对分配表")
    v.add_argument("--keys", required=True)
    v.set_defaults(fn=cmd_verify)

    c = sub.add_parser("check-genesis",
                       help="把创世 JSON 与分配表对照，逐一验证链上余额")
    c.add_argument("--genesis", required=True)
    c.add_argument("--table", required=True, help="dev_wallets.csv")
    c.set_defaults(fn=cmd_check_genesis)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
