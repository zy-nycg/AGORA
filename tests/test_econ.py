# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 参考实现 · 经济模拟测试（GATE-6）
==============================================

覆盖目标（规范 §28.4 / §30 / §31）：

1. **发行曲线**：上下界截断、触底点、与 §28.4 验收表一致；
2. **口径可复现**：`NetValidatorRevenue` 的公式能复现 §28.4 的表（残差 ≤0.2 个百分点）；
3. **全矩阵可运行**：§30 要求的 588 点矩阵能被完整计算并给出失败清单；
4. **失败点结构**：失败与丢槽率、质押率的相关性符合已知结论（防回归）。

**关于"是否通过"（D-5 裁决后）：** 验收按**声明包线**进行 —— 丢槽率 ≤ 10% 的
392 点 **MUST** 满足 `NetValidatorRevenue ≥ +0.5pp`（实测全部达标，最差 +0.5434%）；
丢槽率 50% 的 196 点不属于验收范围，其中 84 点为负，**MUST** 作为**已知残余风险**原样登记
（最差 −1.9203%，§37C.3）。本测试**同时**断言两件事：
① 包线内全部达标；② 包线外的失败结构与最差值**没有变**（否则新数据就是被藏起来了）。

运行：python3 tests/test_econ.py
"""

from __future__ import annotations

import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agora import params as P

_pass = 0
_fail = 0


def chk(name, cond, detail=""):
    global _fail, _pass
    if cond:
        _pass += 1
        print(f"  [OK  ] {name}" + (f"   {detail}" if detail else ""))
    else:
        _fail += 1
        print(f"  [FAIL] {name}" + (f"   {detail}" if detail else ""))


def _load_sim():
    """按路径加载 `tools/agora_econ_sim.py`（tools 不是包）。"""
    path = os.path.join(ROOT, "tools", "agora_econ_sim.py")
    spec = importlib.util.spec_from_file_location("agora_econ_sim", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = P.ATOM_PER_AGORA


# ── 1. 发行曲线 ──────────────────────────────────────────────────────

def test_reward_curve():
    print("\n1) 发行曲线（规范 §28.4，恒定部分）")
    # 上下界
    chk("质押总量=1 时触上限 0.64",
        P.curve_block_reward(1) == P.MAX_BLOCK_REWARD,
        f"{P.curve_block_reward(1) / A:.4f} AGORA")
    chk("质押总量=100% 供应时触下限 0.17",
        P.curve_block_reward(P.INITIAL_SUPPLY) == P.MIN_BLOCK_REWARD,
        f"{P.curve_block_reward(P.INITIAL_SUPPLY) / A:.4f} AGORA")
    chk("质押总量=0 时返回上限（链此时应已 halt，§7.7）",
        P.curve_block_reward(0) == P.MAX_BLOCK_REWARD)

    # 单调不增（质押越多，单块发行越少）
    prev = None
    mono = True
    for pct in range(1, 101):
        r = P.curve_block_reward(int(P.INITIAL_SUPPLY * pct / 100))
        if prev is not None and r > prev:
            mono = False
            break
        prev = r
    chk("发行量随质押率单调不增", mono)

    # 触底点 48.00%（D-5 后的解析值）
    star = P.BLOCK_REWARD_NUMERATOR / P.MIN_BLOCK_REWARD / P.INITIAL_SUPPLY
    chk("曲线触底点 = 48.00%", star == 0.48, f"{star:.4%}")

    # 上限截断点 15%（过渡期地板取值的算术依据）
    cap = P.BLOCK_REWARD_NUMERATOR // P.MAX_BLOCK_REWARD
    chk("曲线上限截断点 = 质押率 15.0000%",
        cap == P.INITIAL_SUPPLY * 15 // 100,
        f"{cap / P.INITIAL_SUPPLY:.4%}")

    # 质押率 60% 恰好是 0.16（BASE_BLOCK_REWARD）
    raw60 = P.BLOCK_REWARD_NUMERATOR // int(P.INITIAL_SUPPLY * 0.6)
    chk("质押率 60% 处曲线值 = 0.16 AGORA",
        raw60 == P.BASE_BLOCK_REWARD, f"{raw60 / A:.4f} AGORA")

    # 分子常量必须等于因子化写法（BUG-33 曾两次写错）
    expect = P.BASE_BLOCK_REWARD * P.TARGET_STAKED_PPM * P.INITIAL_SUPPLY // 1_000_000
    chk("NUMERATOR 等于因子化写法（防手算误差）",
        P.BLOCK_REWARD_NUMERATOR == expect,
        f"{P.BLOCK_REWARD_NUMERATOR}")


# ── 1b. 过渡期奖励地板（规范 §28.4.1）────────────────────────────────

def test_transition_floor():
    print("\n1b) 过渡期奖励地板（规范 §28.4.1，所有者决策 D-3）")
    end = P.TRANSITION_END_SLOT
    chk("窗口长度 = TRANSITION_EPOCHS × EPOCH_LENGTH",
        end == P.TRANSITION_EPOCHS * P.EPOCH_LENGTH, f"{end:,} 槽")
    chk("窗口 = 2 年（与空投窗口同期）", end == P.AIRDROP_END_SLOT
        and end * P.SLOT_TIME == 2 * 365 * 86400,
        f"{end * P.SLOT_TIME / 86400 / 365:.2f} 年")
    chk("地板落在 [MIN, MAX] 内（否则 clamp 语义自相矛盾）",
        P.MIN_BLOCK_REWARD <= P.TRANSITION_REWARD_FLOOR <= P.MAX_BLOCK_REWARD,
        f"{P.TRANSITION_REWARD_FLOOR / A:.4f} AGORA")

    # 槽参数是**唯一**判定输入：窗口末槽生效、首槽失效
    chk("transition_active(0) 与 (END−1) 为真", P.transition_active(0)
        and P.transition_active(end - 1))
    chk("transition_active(END) 与 (END+1) 为假", not P.transition_active(end)
        and not P.transition_active(end + 1))

    # 边界切换：以质押率 100%（曲线 = 0.17 ≠ 地板）为探针
    chk("窗口末槽 = 地板、窗口首槽 = 曲线（边界切换正确）",
        P.block_reward(P.INITIAL_SUPPLY, end - 1) == P.TRANSITION_REWARD_FLOOR
        and P.block_reward(P.INITIAL_SUPPLY, end) == P.MIN_BLOCK_REWARD,
        f"{P.block_reward(P.INITIAL_SUPPLY, end - 1) / A:.4f} → "
        f"{P.block_reward(P.INITIAL_SUPPLY, end) / A:.4f} AGORA")

    # 当前取值（地板 == 上限）⇒ 窗口内发行量与质押率无关
    vals = {P.block_reward(s, 0) for s in (1, 256 * A, P.INITIAL_SUPPLY * 15 // 100,
                                           P.INITIAL_SUPPLY)}
    chk("窗口内块奖励与质押率无关（地板 == 上限）",
        vals == {P.MAX_BLOCK_REWARD}, str([v / A for v in vals]))

    # 窗口内绝不越界（发行量不得超过曲线上限）
    ok = all(P.MIN_BLOCK_REWARD <= P.block_reward(int(P.INITIAL_SUPPLY * p / 100), 0)
             <= P.MAX_BLOCK_REWARD for p in range(1, 101))
    chk("窗口内发行量恒在 [MIN, MAX] 内", ok)

    # 槽参数不可省略（漏传必须报错，而不是静默按曲线算）
    try:
        P.block_reward(1)                                    # type: ignore[call-arg]
        missing_ok = False
    except TypeError:
        missing_ok = True
    chk("省略 slot 参数时抛 TypeError（不存在默认值）", missing_ok)

    # 独立真值：窗口内年发行 = 0.64 × 6,307,200 = 4,036,608 AGORA = 19.71% 初始供应
    ann = P.TRANSITION_REWARD_FLOOR * P.PROTOCOL_YEAR_SLOTS / A
    chk("窗口内年发行 = 4,036,608 AGORA（= 初始供应的 19.7100%）",
        abs(ann - 4_036_608) < 1e-6
        and abs(ann / (P.INITIAL_SUPPLY / A) * 100 - 19.71) < 0.001,
        f"{ann:,.0f} AGORA / {ann / (P.INITIAL_SUPPLY / A) * 100:.4f}%")


# ── 2. 口径可复现规范表 ──────────────────────────────────────────────

def test_reproduces_spec_table():
    """**从规范文本解析** §28.4 的表并逐行复算。

    为什么不再硬编码期望值：BUG-70 的根因就是表内数字曾被人工填写、
    与实现各自漂移。硬编码期望值等于把那份手算噪声抄进测试里
    （本次 D-5 调参时，硬编码版本立刻给出 +1.61pp 的"残差"，而实际上
    是实现与表的**口径都正确**、只是表没跟着改）。
    """
    print("\n2) 逐行复算规范 §28.4 的验收表（BUG-70 修法：不硬编码）")
    sim = _load_sim()
    rows = sim._parse_spec_table()
    chk("能从规范 §28.4 解析到表格", len(rows) >= 8, f"{len(rows)} 行")
    worst, bad = 0.0, []
    for pct, t_rw, t_iss, t_gross, t_net in rows:
        r = sim.simulate(50, pct, 100, 0, blocks=256)
        d = abs(r["net_revenue_pct"] - t_net)
        worst = max(worst, d)
        if (d > 0.011 or abs(r["reward_per_block_agora"] - t_rw) > 1e-4
                or abs(r["annual_issuance_agora"] - t_iss) > 1.0
                or abs(r["gross_yield_pct"] - t_gross) > 0.011):
            bad.append(f"{pct}%")
    chk(f"{len(rows)} 行全部与实现一致（最大残差 {worst:.3f} pp）", not bad,
        "；".join(bad) if bad else "表 == 实现")
    chk("残差 ≤ 0.011 个百分点（表已程序生成，无手算噪声）", worst <= 0.011,
        f"{worst:.4f}")


# ── 3. 全矩阵与失败结构 ──────────────────────────────────────────────

def test_matrix_and_failure_structure():
    """包线内验收 + 包线外残余风险结构（D-5）。"""
    print("\n3) §30 全矩阵（588 点）· 稳态口径 · 按包线分开验收")
    sim = _load_sim()
    rows = sim.run_matrix(quick=False, regime="steady")
    chk("矩阵点为 §30 要求的 588 个", len(rows) == 588, f"实际 {len(rows)}")
    chk("稳态口径的块奖励取曲线（非地板）",
        all(r["regime"] == "steady" for r in rows))

    ins = [r for r in rows if r["slot_loss_pct"] <= P.ENVELOPE_SLOT_LOSS_PCT]
    out = [r for r in rows if r["slot_loss_pct"] > P.ENVELOPE_SLOT_LOSS_PCT]
    chk("包线内 392 点 / 包线外 196 点",
        (len(ins), len(out)) == (392, 196), f"{len(ins)}/{len(out)}")

    # ① 包线内必须全部达标
    worst_in = min(ins, key=lambda r: r["net_revenue_pct"])
    chk(f"包线内全部点 ≥ +{P.ENVELOPE_MIN_NET_PCT}pp（实际 {len(ins)}/{len(ins)}）",
        all(r["net_revenue_pct"] >= P.ENVELOPE_MIN_NET_PCT for r in ins),
        f"最差 {worst_in['net_revenue_pct']:+.4f}%"
        f"（质押率 {worst_in['stake_pct']}% 丢槽 {worst_in['slot_loss_pct']}%）")
    chk("包线内最差点 = 丢槽 10% + 质押率 100%（与规范 §30 一致）",
        worst_in["slot_loss_pct"] == 10 and worst_in["stake_pct"] == 100,
        f"{worst_in['slot_loss_pct']}% / {worst_in['stake_pct']}% → "
        f"{worst_in['net_revenue_pct']:+.4f}%")

    # ② 包线外：失败结构必须如实保留（不许因为"不在验收范围"就被抹掉）
    bad_out = [r for r in out if not r["net_positive"]]
    worst_out = min(out, key=lambda r: r["net_revenue_pct"])
    chk("包线外仍记录 84 个负值点（残余风险未被隐藏）",
        len(bad_out) == 84, f"{len(bad_out)} 个")
    chk("包线外最差 = −1.9203%（质押率 100% + 丢槽 50%）",
        abs(worst_out["net_revenue_pct"] + 1.9203) < 0.001
        and worst_out["stake_pct"] == 100 and worst_out["slot_loss_pct"] == 50,
        f"{worst_out['net_revenue_pct']:+.4f}%")
    chk("包线外失败点只出现在质押率 ≥75%",
        all(r["stake_pct"] >= 75 for r in bad_out),
        "质押率集合：" + str(sorted({r["stake_pct"] for r in bad_out})))

    # ③ 分档结构（与 §30 的表逐格对应）
    by_loss = {}
    for r in rows:
        by_loss.setdefault(r["slot_loss_pct"], []).append(r)
    for loss in (0, 10, 50):
        sub = by_loss[loss]
        n_bad = sum(1 for r in sub if not r["net_positive"])
        print(f"        丢槽 {loss:>2}%: {len(sub) - n_bad}/{len(sub)} 非负"
              f"（{n_bad} 个 ≤0）")
    chk("丢槽 0% 与 10% 档全部非负", all(r["net_positive"] for r in by_loss[0] + by_loss[10]))
    chk("丢槽 50% 档 112/196 非负（= 规范 §30 表）",
        sum(1 for r in by_loss[50] if r["net_positive"]) == 112)

    # ④ 验证者数只影响分配
    same = {round(r["net_revenue_pct"], 6) for r in rows
            if r["stake_pct"] == 56.5 and r["slot_loss_pct"] == 50
            and r["utilization_pct"] == 50}
    chk("验证者数不影响净收益率（只影响分配）", len(same) == 1, str(sorted(same)))
    inc = {round(r["annual_revenue_each_agora"], 3) for r in rows
           if r["stake_pct"] == 56.5 and r["slot_loss_pct"] == 0
           and r["utilization_pct"] == 50}
    chk("但每人年收入随验证者数变化", len(inc) == 4, f"{len(inc)} 种")

    # ⑤ 工具如实报告：默认退出码只看包线内；--strict 才因包线外失败
    chk("工具默认口径：包线内全过 ⇒ 不因包线外负值而失败",
        all(r["net_revenue_pct"] >= P.ENVELOPE_MIN_NET_PCT for r in ins))
    print("        注：`python3 tools/agora_econ_sim.py --strict` 会因包线外残余风险返回 1；"
          "默认返回 0。")


def test_transition_regime_matrix():
    """过渡期口径必须**单独**验收：混入稳态会掩盖窗口内/窗口外的差别。"""
    print("\n3b) §30 全矩阵 · 过渡期口径（§28.4.1 地板生效）")
    sim = _load_sim()
    rows = sim.run_matrix(quick=False, regime="transition")
    chk("矩阵点为 588 个", len(rows) == 588, f"实际 {len(rows)}")
    chk("过渡期口径全矩阵非负（588/588，含包线外）",
        all(r["net_positive"] for r in rows),
        f"{sum(1 for r in rows if r['net_positive'])}/{len(rows)}")
    worst = min(rows, key=lambda r: r["net_revenue_pct"])
    chk("过渡期最差点 = +4.8550%（质押率 100% + 丢槽 50%）",
        abs(worst["net_revenue_pct"] - 4.8550) < 0.01
        and worst["stake_pct"] == 100 and worst["slot_loss_pct"] == 50,
        f"{worst['net_revenue_pct']:+.4f}%")
    ins = [r for r in rows if r["slot_loss_pct"] <= P.ENVELOPE_SLOT_LOSS_PCT]
    chk("过渡期包线内最差点 = +12.7390%（丢槽 10% + 质押率 100%）",
        abs(min(ins, key=lambda r: r["net_revenue_pct"])["net_revenue_pct"] - 12.7390) < 0.01)
    # 窗口内发行量恒为 0.64 ⇒ 与质押率无关
    chk("窗口内块奖励与质押率无关（全部 = 0.64 AGORA）",
        {round(r["reward_per_block_agora"], 6) for r in rows} == {0.64},
        str(sorted({round(r["reward_per_block_agora"], 4) for r in rows})))
    # 两口径在最差点的差 = 曲线触底带来的差异，必须被显式记录
    st = sim.run_matrix(quick=False, regime="steady")
    worst_st = min(st, key=lambda r: r["net_revenue_pct"])
    chk("稳态最差点仍为负（BUG-69 未被过渡期掩盖）",
        worst_st["net_revenue_pct"] < 0,
        f"{worst_st['net_revenue_pct']:+.4f}% @ 质押率 {worst_st['stake_pct']}%")


# ── 4. 利用率与销毁 ──────────────────────────────────────────────────

def test_utilization_effects():
    print("\n4) 利用率 → 基础费销毁与优先费")
    sim = _load_sim()
    # 利用率 ≤100% 时基础费停在地板价
    for u in (0, 50, 100):
        r = sim.simulate(u, 50, 100, 0, blocks=256)
        chk(f"利用率 {u}% 时基础费 = MIN_BASE_FEE（地板价）",
            abs(r["base_fee_end_nagora"] - P.MIN_BASE_FEE / P.NAGORA_PER_AGORA) < 1e-9,
            f"{r['base_fee_end_nagora']:.3f} nAGORA")
    r100 = sim.simulate(100, 50, 100, 0, blocks=256)
    chk("目标利用率下年基础费销毁 = 31,536 AGORA（§30 基线）",
        abs(r100["annual_basefee_burn_agora"] - 31_536) < 1.0,
        f"{r100['annual_basefee_burn_agora']:,.1f} AGORA")
    chk("目标利用率下年优先费 = 6,307.2 AGORA（§30 基线）",
        abs(r100["annual_priority_agora"] - 6_307.2) < 0.1,
        f"{r100['annual_priority_agora']:,.1f} AGORA")

    # >100% 无稳态：基础费必须显著上升
    r150 = sim.simulate(150, 50, 100, 0, blocks=512)
    chk("利用率 150% 时基础费远高于地板价（无稳态，逐块涨费）",
        r150["base_fee_end_nagora"] > P.MIN_BASE_FEE / P.NAGORA_PER_AGORA * 10,
        f"{r150['base_fee_end_nagora']:,.0f} nAGORA")


def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 经济模拟（GATE-6）")
    print("═" * 76)
    test_reward_curve()
    test_transition_floor()
    test_reproduces_spec_table()
    test_matrix_and_failure_structure()
    test_transition_regime_matrix()
    test_utilization_effects()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    print("说明（D-5 裁决后）：验收按**声明包线**进行 —— 丢槽率 ≤10% 的 392 点在两个发行口径下"
          "均 ≥ +0.5pp ✅；丢槽率 50% 档的 84 个负值点**原样登记**为已知残余风险"
          "（最差 −1.9203%，规范 §37C.3），不因'不在验收范围'而被抹去。")
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
