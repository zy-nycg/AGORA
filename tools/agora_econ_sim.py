# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 经济模拟（GATE-6）
=================================

规范 §30 要求：

> **经济模拟 MUST 覆盖：** 利用率 0 / 10 / 25 / 50 / 75 / 100 / >100%；
> 质押率 10 / 30 / 45 / 56.5 / 75 / 90 / 100%；验证者数 1 / 7 / 50 / 100；
> 丢槽率 0 / 10 / 50%。
> **验收标准（所有者决策 D-5）：** 在**声明运行包线**（丢槽率 ≤ 10%）内
`NetValidatorRevenue ≥ +0.5` 个百分点；包线外（丢槽 50%）不属于验收范围，
但 **MUST** 原样输出并登记为已知残余风险。`--strict` 可恢复"任一点 ≤0 即失败"的旧口径。

本工具按规范定义**逐项计算**并输出模拟结果，不写死任何期望值。

口径说明（口径已锁定，逐点验证见报告首节）
--------------------------------------------
**`NetValidatorRevenue` 的权威定义**（与规范 §28.4 的验收表逐点吻合，残差 0.00）：

    gross_yield = (年发行 + 年优先费) / 质押总量 × 100          [%]
    NetValidatorRevenue = gross_yield − 年销毁率(5)

即：**质押总量层面的年化收益率**，而非单个验证者的绝对收入。
`n_validators` 只影响收入的分配，不影响该收益率。

其他必须知道的几条：

1. **运营成本不参与验收。** §31 明确"协议 **MUST NOT** 假定每个验证者都盈利"，
   因此把硬件/带宽/电力/运维混入会与 §31 直接矛盾。运营成本另以
   "盈亏平衡所需 AGORA 价格"给出，仅供决策参考。

2. **`>100%` 利用率没有稳态。** 基础费在 `gas_used > TARGET` 时每块上调（§17.4），
   不存在恒定不动点，故对该档做**时间序列模拟**。实测：利用率 ≤100% 时基础费
   停留在 `MIN_BASE_FEE`（1 nAGORA）—— 因为 `TARGET` 处不动、低于 `TARGET` 时
   每块下调 12.5% 会立刻触底；因此稳态下基础费销毁恒为 `gas × 1 nAGORA`。

3. **丢槽率**按比例减少有效块数（发行与优先费同步减少）。

4. 基础费 **100% 销毁**，优先费 **100% 归验证者**。

用法：
    python3 tools/agora_econ_sim.py                 # 跑 §30 全矩阵
    python3 tools/agora_econ_sim.py --csv out.csv   # 同时导出逐行结果
    python3 tools/agora_econ_sim.py --quick         # 快速模式（矩阵缩减，用于 CI）
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import sys
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agora import params as P

A = P.ATOM_PER_AGORA

# §30 的矩阵（ppm / 整数，避免浮点）
UTILIZATIONS = [0, 10, 25, 50, 75, 100, 150]          # 百分比（>100% 表示持续满块）
STAKE_RATIOS = [10, 30, 45, 56.5, 75, 90, 100]        # 百分比
VALIDATOR_COUNTS = [1, 7, 50, 100]
SLOT_LOSS = [0, 10, 50]                                # 百分比

BLOCKS_PER_YEAR = P.PROTOCOL_YEAR_SLOTS                 # 6,307,200（= SLOTS_PER_DAY × 365）

# GATE-6 的声明包线（与规范 §30 / §37C.3 一致；参数值取自实现，避免两处各写一遍）
ENVELOPE_SLOT_LOSS = P.ENVELOPE_SLOT_LOSS_PCT          # 10（%）
ENVELOPE_MIN_NET = P.ENVELOPE_MIN_NET_PCT              # +0.5（百分点）

# 模拟用的块数：一年太多（6.3M × 588 组），用"前 N 块外推 + 解析稳态"混合口径。
# 对于有不动点的利用率（≤100%），基础费在若干块内收敛，后续按稳态外推；
# 对于 >100%，报告**一年内**的累计量（按模拟得到的平均速率外推）。
SIM_BLOCKS = 4096


def _fee_dynamics(util_pct: float, blocks: int) -> Tuple[int, List[int]]:
    """在恒定利用率下推进基础费，返回 `(收敛后的基础费, 每块销毁序列)`。"""
    gas = min(int(P.TARGET_GAS_PER_BLOCK * util_pct / 100), P.MAX_GAS_PER_BLOCK * 3)
    bf = P.INITIAL_BASE_FEE
    fees = []
    for _ in range(blocks):
        fees.append(bf * gas)                      # 该块销毁的基础费（atom）
        bf = P.base_fee_next(bf, min(gas, P.MAX_GAS_PER_BLOCK))
    return bf, fees


def _reward_at(stake_ratio_pct: float, slot: int = None) -> int:
    """给定质押率（与槽）下的块奖励。

    · `slot is None`（默认）→ 取**过渡期之后**的槽，即 §28.4 恒定曲线的稳态口径；
    · 传 `slot=0` → 过渡期（§28.4.1）口径，地板生效。
    """
    staked = int(P.INITIAL_SUPPLY * stake_ratio_pct / 100)
    if slot is None:
        slot = P.TRANSITION_END_SLOT
    return P.block_reward(staked, slot)


# 两个口径：稳态（曲线）与过渡期（地板）。矩阵验收**必须**分别做。
REGIMES = {
    "steady": P.TRANSITION_END_SLOT,        # 窗口之后：纯曲线
    "transition": 0,                        # 窗口之内：max(曲线, 地板)
}


def simulate(util_pct: float, stake_pct: float, n_validators: int,
             slot_loss_pct: float, blocks: int = SIM_BLOCKS,
             regime: str = "steady") -> Dict:
    """单一矩阵点的年度经济模拟。

    **口径（已由规范 §28.4 的验收表反推并逐点验证，残差 0.00）：**

        gross_yield = (年发行 + 年优先费) / 质押总量 × 100          [%]
        NetValidatorRevenue = gross_yield − 年销毁率(5)

    即：这是**质押总量层面的年化收益率**，不是单个验证者的绝对收入。
    `n_validators` 只影响收入的**分配**，不影响该收益率（等额质押时）。

    `regime`：
      · `"steady"`     —— 过渡期结束后的稳态，块奖励取 §28.4 恒定曲线；
      · `"transition"` —— 过渡期内，块奖励取 §28.4.1 的 `max(曲线, 地板)`。
    两者对同一个质押率可以给出**不同**发行量，因此不能混在一张表里验收。

    各矩阵参数的作用路径：
      · 质押率     → 决定发行曲线取值 `BLOCK_REWARD(S)`，也决定分母 `S`
      · 利用率     → 决定年优先费与年基础费销毁（基础费全销毁）
      · 丢槽率     → 按比例减少有效块数（发行与优先费同步减少）
      · 验证者数   → 只影响每人的份额
    """
    gas = min(int(P.TARGET_GAS_PER_BLOCK * util_pct / 100), P.MAX_GAS_PER_BLOCK)
    live_blocks = BLOCKS_PER_YEAR * (100 - slot_loss_pct) / 100.0

    staked_total = int(P.INITIAL_SUPPLY * stake_pct / 100)
    staked_agora = staked_total / A
    reward = P.block_reward(staked_total, REGIMES[regime])

    # ── 年发行（AGORA）──
    annual_issuance_agora = reward * live_blocks / A

    # ── 年优先费（AGORA）──
    # §30 的经济基线假设："优先费 0.2 nAGORA/gas"，目标利用率下年优先费 = 6,307.2 AGORA。
    # 该常量是**基线**的一部分，规范 §28.4 的验收表用的就是它；本模拟按基线常量计算，
    # 以保证可复现那张表（残差 0.00）。利用率变化对优先费的影响只在 §5 的敏感性中说明。
    PRIO_FEE_PER_YEAR_AGORA = 6307.2
    annual_prio_agora = PRIO_FEE_PER_YEAR_AGORA * (gas / P.TARGET_GAS_PER_BLOCK) \
        * (live_blocks / BLOCKS_PER_YEAR)

    # ── 基础费销毁（§17.4；全部销毁）──
    # 利用率 ≤100% 时基础费停留在 MIN_BASE_FEE（TARGET 处不动、低于 TARGET 时
    # 每块下调 12.5% 会立刻触底），因此可**直接**取 `gas × MIN_BASE_FEE`，
    # 无需逐块模拟；仅 >100% 时因无稳态而必须逐块推进。
    if util_pct <= 100:
        bf_end = P.MIN_BASE_FEE
        avg_fee_atom = float(P.MIN_BASE_FEE * gas)
    else:
        bf_end, fee_seq = _fee_dynamics(util_pct, blocks)
        avg_fee_atom = (sum(fee_seq) / len(fee_seq)) if fee_seq else 0.0
    annual_basefee_burn_agora = avg_fee_atom * live_blocks / A

    # ── 年度计划销毁（§28.5）──
    annual_plan_burn_agora = P.INITIAL_SUPPLY * P.ANNUAL_BURN_RATE_PPM / 1_000_000 / A

    # ── 核心指标 ──
    gross_yield = ((annual_issuance_agora + annual_prio_agora) / staked_agora) * 100
    net = gross_yield - P.ANNUAL_BURN_RATE_PPM / 10_000

    # ── 每个验证者的年度收入（展示用）──
    revenue_each_agora = (annual_issuance_agora + annual_prio_agora) / n_validators
    stake_each_agora = staked_agora / n_validators

    return {
        "regime": regime,
        "utilization_pct": util_pct,
        "stake_pct": stake_pct,
        "validators": n_validators,
        "slot_loss_pct": slot_loss_pct,
        "gas_per_block": gas,
        "base_fee_end_nagora": bf_end / P.NAGORA_PER_AGORA,
        "staked_total_agora": staked_agora,
        "reward_per_block_agora": reward / A,
        "annual_issuance_agora": annual_issuance_agora,
        "annual_priority_agora": annual_prio_agora,
        "annual_basefee_burn_agora": annual_basefee_burn_agora,
        "annual_plan_burn_agora": annual_plan_burn_agora,
        "gross_yield_pct": gross_yield,
        "net_revenue_pct": net,
        "stake_each_agora": stake_each_agora,
        "annual_revenue_each_agora": revenue_each_agora,
        # 该验证者的绝对净收入（AGORA/年）：收入 − 其质押对应的销毁摊派
        "net_agora_each": revenue_each_agora
                          - annual_plan_burn_agora * (stake_each_agora / (P.INITIAL_SUPPLY / A)),
        "net_positive": net > 0 and revenue_each_agora > 0,
    }


def _breakeven_price(net_atom: float, stake_agora: float,
                     cost_per_year_agora: float = 100.0) -> Optional[float]:
    """若运营成本为 `cost_per_year_agora` AGORA/年，盈亏平衡所需的 AGORA 价格（USD）。

    仅在**报告**中给出，不参与 §30 的验收（§31 明确不假定各验证者都盈利）。
    """
    if net_atom <= 0:
        return None
    net_agora = net_atom / A
    return cost_per_year_agora / net_agora if net_agora else None


def run_matrix(quick: bool = False, regime: str = "steady") -> List[Dict]:
    utils = [0, 50, 100, 150] if quick else UTILIZATIONS
    stakes = [10, 56.5, 100] if quick else STAKE_RATIOS
    counts = [1, 100] if quick else VALIDATOR_COUNTS
    losses = [0, 50] if quick else SLOT_LOSS
    rows: List[Dict] = []
    for u in utils:
        for s in stakes:
            for n in counts:
                for l in losses:
                    rows.append(simulate(u, s, n, l,
                                         blocks=512 if quick else SIM_BLOCKS,
                                         regime=regime))
    return rows


def transition_summary() -> None:
    """过渡期窗口（§28.4.1）的实测数字 —— 规范 §30.1 的表由本函数输出。"""
    A_ = A
    r = P.TRANSITION_REWARD_FLOOR
    ann = r * BLOCKS_PER_YEAR / A_
    print("── 8. 过渡期窗口（§28.4.1；所有者决策 D-3）──")
    print(f"  窗口：纪元 0 – {P.TRANSITION_EPOCHS - 1:,}"
          f"（{P.TRANSITION_EPOCHS:,} 个纪元 = {P.TRANSITION_END_SLOT:,} 槽 "
          f"= {P.TRANSITION_END_SLOT * P.SLOT_TIME / 86400 / 365:.2f} 年）")
    print(f"  地板：{r / A_:.4f} AGORA/块（= MAX_BLOCK_REWARD，故窗口内发行量与质押率无关）")
    print(f"  窗口内年发行：{ann:,.0f} AGORA = 初始供应的 {ann / (P.INITIAL_SUPPLY / A_) * 100:.4f}%")
    print(f"  年度销毁 5% ⇒ 年净供应变化 ≈ {ann / (P.INITIAL_SUPPLY / A_) * 100 - 5:+.4f}%"
          f"（销毁在窗口内发生一次，故实际净增略低于此值）")
    print(f"{'质押率':>9} {'窗口内块奖励':>12} {'窗口内毛收益率':>14} {'窗口内净收益率':>14} "
          f"{'窗口后块奖励':>12} {'窗口后净收益率':>14}")
    for pct in (0.00125, 1, 5, 10, 15, 30, 45, 56.5, 60, 75, 90, 100):
        tr = simulate(50, pct, 100, 0, regime="transition")
        st = simulate(50, pct, 100, 0, regime="steady")
        print(f"{pct:>8.5f}% {tr['reward_per_block_agora']:>12.4f} "
              f"{tr['gross_yield_pct']:>13.2f}% {tr['net_revenue_pct']:>+13.2f}% "
              f"{st['reward_per_block_agora']:>12.4f} {st['net_revenue_pct']:>+13.2f}%")
    # 窗口内最差点（用于 §30.1 的验收陈述）
    worst = min((simulate(u, s, n, l, regime="transition")
                 for u in UTILIZATIONS for s in STAKE_RATIOS
                 for n in VALIDATOR_COUNTS for l in SLOT_LOSS),
                key=lambda x: x["net_revenue_pct"])
    print(f"  窗口内全矩阵最差点：{worst['net_revenue_pct']:+.4f}%"
          f"（利用率 {worst['utilization_pct']}% 质押率 {worst['stake_pct']}% "
          f"丢槽 {worst['slot_loss_pct']}%）")
    print()


def _parse_spec_table(spec_path: Optional[str] = None) -> List[Tuple[float, float, float, float, float]]:
    """从规范 §28.4 解析验收表，返回 `(质押率%, 块奖励, 年发行, 毛收益率, 净收益率)`。

    为什么必须解析而不是硬编码：BUG-70 的根因就是表内数字曾由**人工填写**，
    与实现各自漂移而无人发现。解析 + 复算让"表"与"实现"必须同时正确。
    """
    import re
    path = spec_path or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "AGORA_v0.2.2_SPEC.md")
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return []
    sec = text.split("## 28.4 发行曲线", 1)
    if len(sec) < 2:
        return []
    body = sec[1].split("## 28.4.1", 1)[0]
    out = []
    for m in re.finditer(
            r"^\|\s*([\d.]+)%\s*\|\s*([\d.]+)\s*\|\s*([\d,]+)\s*\|\s*"
            r"([\d.]+)%\s*\|\s*\*\*([+-][\d.]+)%\*\*\s*\|", body, re.M):
        out.append((float(m.group(1)), float(m.group(2)),
                    float(m.group(3).replace(",", "")), float(m.group(4)),
                    float(m.group(5))))
    return out


def report(rows: List[Dict], quick: bool = False) -> int:
    A_ = A
    print("═" * 80)
    print("AGORA v0.2.2 · 经济模拟（GATE-6 · 规范 §30 全矩阵）")
    print("═" * 80)
    print(f"初始供应 {P.INITIAL_SUPPLY / A_:,.0f} AGORA    年块数 {BLOCKS_PER_YEAR:,}    "
          f"目标 gas/块 {P.TARGET_GAS_PER_BLOCK:,}")
    print(f"发行曲线 clamp(floor(NUM/S), {P.MIN_BLOCK_REWARD / A_:.2f}, "
          f"{P.MAX_BLOCK_REWARD / A_:.2f}) AGORA    年度销毁 {P.ANNUAL_BURN_RATE_PPM / 10_000:.1f}%")
    print("口径 NetValidatorRevenue = (年发行+年优先费)/质押总量×100 − 5")
    print()
    rc = 0

    # ── 1. 直接复算**规范 §28.4 的表**（BUG-70 的修法：表必须程序生成、可程序复算）──
    print("── 1. 复算规范 §28.4 的表（残差必须为 0；表内数字由本工具生成）──")
    spec_rows = _parse_spec_table()
    print(f"{'质押率':>8} {'块奖励':>8} {'年发行':>13} {'毛收益率':>10} {'净收益率':>10} "
          f"{'表内净收益':>11} {'残差(pp)':>9}")
    ok_tbl, worst_res = True, 0.0
    for pct, t_rw, t_iss, t_gross, t_net in spec_rows:
        r = simulate(50, pct, 100, 0, blocks=256)
        d = r["net_revenue_pct"] - t_net
        worst_res = max(worst_res, abs(d))
        ok_tbl &= (abs(d) <= 0.011
                   and abs(r["reward_per_block_agora"] - t_rw) <= 1e-4
                   and abs(r["annual_issuance_agora"] - t_iss) <= 1.0
                   and abs(r["gross_yield_pct"] - t_gross) <= 0.011)
        print(f"{pct:>7.2f}% {r['reward_per_block_agora']:>8.4f} "
              f"{r['annual_issuance_agora']:>13,.0f} {r['gross_yield_pct']:>9.2f}% "
              f"{r['net_revenue_pct']:>+9.2f}% {t_net:>+10.2f}% {d:>+9.3f}")
    if not spec_rows:
        ok_tbl = False
        print("  ★ 未能在规范中解析到表格")
    print(f"  ⇒ 规范 §28.4 表与实现{'逐行一致（最大残差 %.3f pp）✅' % worst_res if ok_tbl else '★ 不一致'}"
          f"　共 {len(spec_rows)} 行")
    if not ok_tbl:
        rc = 1
    print()

    # ── 2. 全矩阵验收（按声明包线分开：包线内是验收，包线外是残余风险）──
    regime = rows[0]["regime"] if rows else "steady"
    inside = [r for r in rows if r["slot_loss_pct"] <= ENVELOPE_SLOT_LOSS]
    outside = [r for r in rows if r["slot_loss_pct"] > ENVELOPE_SLOT_LOSS]
    bad = [r for r in inside if r["net_revenue_pct"] < ENVELOPE_MIN_NET]
    risks = [r for r in outside if not r["net_positive"]]
    _note = ("稳态（过渡期之后，§28.4 曲线）" if regime == "steady"
             else "过渡期内（§28.4.1 地板生效）")
    print(f"── 2. §30 全矩阵验收（{len(rows)} 个点）· 发行口径：{_note} ──")
    print(f"   包线：丢槽率 ≤ {ENVELOPE_SLOT_LOSS}%（{len(inside)} 点）要求 "
          f"NetValidatorRevenue ≥ {ENVELOPE_MIN_NET:+} 个百分点；"
          f"包线外 {len(outside)} 点登记为残余风险")
    worst_in = min(inside, key=lambda r: r["net_revenue_pct"])
    print(f"  包线内达标：{len(inside) - len(bad)}/{len(inside)}"
          f"    最差点 {worst_in['net_revenue_pct']:+.4f}%"
          f"（质押率 {worst_in['stake_pct']}% 丢槽 {worst_in['slot_loss_pct']}%）")
    if bad:
        rc = 1
        print(f"  ★ 包线内验收未通过：{len(bad)} 个点 < {ENVELOPE_MIN_NET:+}pp")
        for r in bad[:8]:
            print(f"     - 利用率 {r['utilization_pct']}% 质押率 {r['stake_pct']}% "
                  f"验证者 {r['validators']} 丢槽 {r['slot_loss_pct']}% → "
                  f"{r['net_revenue_pct']:+.4f}%")
    else:
        print(f"  ✅ 包线内验收通过：全部点 NetValidatorRevenue ≥ {ENVELOPE_MIN_NET:+}pp")
    if risks:
        worst_out = min(outside, key=lambda r: r["net_revenue_pct"])
        print(f"  ⚠ 包线外（丢槽 > {ENVELOPE_SLOT_LOSS}%）残余风险：{len(risks)}/{len(outside)} 点为负，"
              f"最差 {worst_out['net_revenue_pct']:+.4f}%"
              f"（质押率 {worst_out['stake_pct']}% 丢槽 {worst_out['slot_loss_pct']}%）")
        print(f"     ⇒ 已登记为已知残余风险（规范 §37C.3），**不是**隐藏项："
              f"本工具每次都原样打印这些点")
        if getattr(report, "_strict", False):
            rc = 1
            print("     --strict：按旧口径（任一点 ≤0 即失败）判定 ⇒ 本次退出码为 1")
    else:
        print("  包线外：无非负点")
    print()

    # ── 3. 分参数敏感性 ──
    print("── 3. 质押率截面（利用率 50%，丢槽 0%）──")
    print(f"{'质押率':>7} {'块奖励':>8} {'年发行/AGORA':>14} {'毛收益率':>10} "
          f"{'净收益率':>10} {'每人年收入':>13}")
    for r in rows:
        if (r["utilization_pct"] == 50 and r["slot_loss_pct"] == 0
                and r["validators"] == 100):
            print(f"{r['stake_pct']:>6.1f}% {r['reward_per_block_agora']:>8.4f} "
                  f"{r['annual_issuance_agora']:>14,.0f} {r['gross_yield_pct']:>9.2f}% "
                  f"{r['net_revenue_pct']:>+9.2f}% "
                  f"{r['annual_revenue_each_agora']:>12,.1f}")
    print()

    print("── 4. 利用率 → 基础费与销毁（丢槽 0%）──")
    print(f"{'利用率':>8} {'gas/块':>10} {'期末基础费':>14} {'年基础费销毁':>14} "
          f"{'年优先费':>12} {'稳态':>16}")
    seen = set()
    for r in rows:
        if r["slot_loss_pct"] == 0 and r["validators"] == 100:
            if r["utilization_pct"] in seen:
                continue
            seen.add(r["utilization_pct"])
            note = "是（地板价）" if r["utilization_pct"] <= 100 else "否，逐块涨费"
            print(f"{r['utilization_pct']:>7}% {r['gas_per_block']:>10,} "
                  f"{r['base_fee_end_nagora']:>13,.3f}n "
                  f"{r['annual_basefee_burn_agora']:>13,.0f} "
                  f"{r['annual_priority_agora']:>11,.1f} {note:>16}")
    print()

    print("── 5. 丢槽率的影响（利用率 50%，质押率 60%，7 验证者）──")
    ref = None
    # 可选验证者数因矩阵（快速/完整）而异，自动选一个存在的
    _vcount = 7 if any(x["validators"] == 7 for x in rows) else 100
    print(f"  （验证者数取 {_vcount}）")
    for loss in (0, 10, 50):
        r = next((x for x in rows if x["utilization_pct"] == 50
                  and x["slot_loss_pct"] == loss and x["validators"] == _vcount
                  and x["stake_pct"] == 56.5), None)
        if r:
            if ref is None:
                ref = r["annual_revenue_each_agora"]
            print(f"  丢槽 {loss:>2}%: 每人年收入 {r['annual_revenue_each_agora']:>12,.1f} AGORA"
                  f"   净收益率 {r['net_revenue_pct']:>+7.2f}%"
                  f"   （相对 0% 丢槽损失 {100 * (1 - r['annual_revenue_each_agora'] / ref):.1f}%）")
    print()

    print("── 6. 验证者数的影响（收益率不变，只影响分配）──")
    for n in (1, 7, 50, 100):
        r = next((x for x in rows if x["utilization_pct"] == 50
                  and x["validators"] == n and x["slot_loss_pct"] == 0
                  and x["stake_pct"] == 56.5), None)
        if r:
            print(f"  {n:>3} 名: 每人年收入 {r['annual_revenue_each_agora']:>12,.1f} AGORA"
                  f"   净收益率 {r['net_revenue_pct']:>+7.2f}%  "
                  f"（收益率与人数无关，总收益固定）")
    print()

    # ── 7. 运营成本参考（不参与验收）──
    print("── 7. 运营成本参考（§31：不假定各验证者都盈利，故**不计入验收**）──")
    print(f"{'质押率':>7} {'每人年收入':>13} {'若年成本 100 AGORA 的盈亏平衡价格':>34}")
    for r in rows:
        if (r["utilization_pct"] == 50 and r["slot_loss_pct"] == 0
                and r["validators"] == 100):
            inc = r["annual_revenue_each_agora"]
            be = 100.0 / inc if inc else None
            be_s = f"{be:,.3f} USD/AGORA" if be else "—"
            print(f"{r['stake_pct']:>6.1f}% {inc:>13,.1f} {be_s:>34}")
    print()
    print("说明：上表为'若运营成本 100 AGORA/年'时的盈亏平衡币价，仅供决策参考；")
    print("      协议不假定每个验证者都盈利（§31），故该项不参与 §30 的验收。")
    print()
    if regime == "steady":
        transition_summary()
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="AGORA 经济模拟（GATE-6）")
    ap.add_argument("--quick", action="store_true", help="快速模式（缩减矩阵）")
    ap.add_argument("--csv", help="导出逐行结果为 CSV")
    ap.add_argument("--regime", choices=["steady", "transition", "both"],
                    default="both",
                    help="稳态（过渡期之后）/ 过渡期内 / 两者都跑（默认）")
    ap.add_argument("--strict", action="store_true",
                    help="旧口径：任一点 ≤0 即失败（含包线外的残余风险点）")
    a = ap.parse_args()

    report._strict = a.strict
    regimes = ["steady", "transition"] if a.regime == "both" else [a.regime]
    rc = 0
    all_rows: List[Dict] = []
    for name in regimes:
        rows = run_matrix(quick=a.quick, regime=name)
        all_rows.extend(rows)
        rc |= report(rows, quick=a.quick)
    # 两个口径都必须单独通过：混在一起会掩盖"窗口内好看、窗口外为负"的情形
    if a.regime == "both":
        print("═" * 80)
        print("总结：两个口径**分别**验收")
        for name in regimes:
            sub = [r for r in all_rows if r["regime"] == name]
            ins = [r for r in sub if r["slot_loss_pct"] <= ENVELOPE_SLOT_LOSS]
            out = [r for r in sub if r["slot_loss_pct"] > ENVELOPE_SLOT_LOSS]
            n_bad = sum(1 for r in ins if r["net_revenue_pct"] < ENVELOPE_MIN_NET)
            w_in = min(ins, key=lambda r: r["net_revenue_pct"])
            w_out = min(out, key=lambda r: r["net_revenue_pct"])
            label = "稳态（§28.4 曲线）" if name == "steady" else "过渡期（§28.4.1 地板）"
            print(f"  {label:<22} 包线内 {len(ins) - n_bad}/{len(ins)} 达标"
                  f"（最差 {w_in['net_revenue_pct']:+.4f}%）；"
                  f"包线外最差 {w_out['net_revenue_pct']:+.4f}%（残余风险）")
        print("═" * 80)
    if a.csv:
        with open(a.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
            w.writeheader()
            w.writerows(all_rows)
        print(f"\n已写入 {a.csv}（{len(all_rows)} 行）")
    return rc


if __name__ == "__main__":
    sys.exit(main())
