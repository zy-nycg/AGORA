# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 参数一致性测试
========================================

本文件回答一个必须被自动化的问题：**`agora/params.py` 是否与规范 §34 参数表一致？**

它做**三向**校验：
    ① 代码常量  ==  规范文本中的值（从 `AGORA_v0.2.2_SPEC.md` 抽取）
    ② 代码常量  ==  本文件中的硬编码期望值（防止"代码与规范一起漂移"）
    ③ 派生算式  ==  规范给出的核验表

第 ② 项很关键：如果只比对"代码 vs 规范"，那么当两者同时被改错时测试不会失败。
规范的参数值是**冻结**的，所以期望值必须独立写在测试里。

运行：python3 -m tests.test_params
"""

from __future__ import annotations

import os
import re
import sys

from agora import params as P

_fail = 0
_pass = 0
SPEC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "AGORA_v0.2.2_SPEC.md")


def chk(name, cond, detail=""):
    global _fail, _pass
    if cond:
        _pass += 1
        print(f"  [OK  ] {name}" + (f"   {detail}" if detail else ""))
    else:
        _fail += 1
        print(f"  [FAIL] {name}" + (f"   {detail}" if detail else ""))


def load_spec() -> str:
    with open(SPEC, encoding="utf-8") as f:
        return f.read()


# ② 硬编码期望值（规范 §34 冻结值；由人类审查，不由代码推导）
EXPECTED = {
    "PROTOCOL_VERSION": "AGORA/v0.2.2",
    "CHAIN_ID": "agora-mainnet-1",
    "GENESIS_TIMESTAMP": 1790812800,
    "SLOT_TIME": 5,
    "EPOCH_LENGTH": 720,
    "CLOCK_TOLERANCE": 4,
    "SUBJECTIVITY_PERIOD_SLOTS": 241920,
    "UNBONDING_PERIOD_SLOTS": 362880,
    "SLASH_WINDOW_SLOTS": 362880,
    "PROTOCOL_YEAR_SLOTS": 6307200,
    "PROPOSAL_TIMEOUT_MS": 3000,
    "PREVOTE_TIMEOUT_MS": 2000,
    "PRECOMMIT_TIMEOUT_MS": 2000,
    "BASE_TIMEOUT_MS": 7000,
    "ROUND_TIMEOUT_INCREMENT_MS": 500,
    "MAX_ROUND_WINDOW": 64,
    "MAX_VALIDATORS": 100,
    "MIN_ACTIVE_VALIDATORS": 3,
    "FOUNDER_PERIOD_EPOCHS": 8760,
    "GENESIS_VALIDATOR_COUNT": 4,
    "GAS_TX_BASE": 21000,
    "GAS_PER_NONZERO_BYTE": 16,
    "GAS_PER_ZERO_BYTE": 4,
    "GAS_ACCOUNT_CREATION": 25000,
    "GAS_BOND": 50000,
    "GAS_UNBOND": 5000,
    "GAS_REBOND": 5000,
    "GAS_EVIDENCE_BASE": 50000,
    "GAS_EVIDENCE_PER_SIG": 3000,
    "GAS_WITHDRAW": 5000,
    "GAS_AIRDROP_CLAIM": 5000,
    "TARGET_GAS_PER_BLOCK": 5_000_000,
    "MAX_GAS_PER_BLOCK": 10_000_000,
    "INITIAL_BASE_FEE": 1_000_000_000,
    "MIN_BASE_FEE": 1_000_000_000,
    "BASE_FEE_CHANGE_DENOMINATOR": 8,
    "BASE_FEE_DIVISOR": 40_000_000,
    "INITIAL_SUPPLY": 20_480_000 * 10 ** 18,
    "BASE_BLOCK_REWARD": 16 * 10 ** 16,
    "TARGET_STAKED_PPM": 600_000,
    "MIN_BLOCK_REWARD": 20 * 10 ** 16,   # D-5：由 0.17 上调，见规范 §37C.3
    "MAX_BLOCK_REWARD": 64 * 10 ** 16,
    "TRANSITION_EPOCHS": 17_520,
    "TRANSITION_REWARD_FLOOR": 64 * 10 ** 16,
    "TRANSITION_END_SLOT": 12_614_400,
    "BLOCK_REWARD_NUMERATOR": 1966080000000000000000000000000000000000000,
    "PROPOSER_REWARD_PPM": 200_000,
    "ATTESTATION_POOL_PPM": 800_000,
    "ANNUAL_BURN_RATE_PPM": 50_000,
    "MAX_YEAR_BURNS_PER_BLOCK": 1,
    "AIRDROP_MAX_SHARE_PPM": 200_000,
    "AIRDROP_MAX_SHARE": 4_096_000 * 10 ** 18,
    "AIRDROP_END_SLOT": 12_614_400,
    "MIN_VALIDATOR_STAKE": 64 * 10 ** 18,
    "SLASH_PPM_DENOMINATOR": 6_000_000,
    "SLASH_MAX_DEDUCTION_PPM": 1_000_000,
    "EVIDENCE_REWARD_PPM": 200_000,
    "EVIDENCE_BURN_PPM": 800_000,
    "INACTIVITY_WINDOW": 100,
    "INACTIVITY_PENALTY_BASE_PPM": 1,
    "INACTIVITY_PENALTY_CAP": 64,
    "MAX_EVIDENCE_PER_BLOCK": 64,
    "JAIL_ENABLED": False,
    "UNBOND_COMPLETION_EPSILON_SLOTS": 720,
    "SETTLED_SLASH_RETENTION_SLOTS": 725_760,
}


def test_expected_values():
    print("\n1) 代码常量 == 硬编码期望值（规范 §34 冻结值）")
    bad = []
    for name, want in EXPECTED.items():
        got = getattr(P, name, "<缺失>")
        if got != want:
            bad.append(f"{name}: 代码={got!r} 期望={want!r}")
    chk(f"{len(EXPECTED)} 项冻结参数全部一致", not bad,
        "；".join(bad) if bad else "")
    bad2 = [n for n, v in P.SLASH_RATE_PPM.items() if v not in (300_000, 600_000, 60_000)]
    chk("罚没比例取值合法", not bad2, str(bad2))
    chk("DOUBLE_PREVOTE/PRECOMMIT = 5%",
        P.SLASH_RATE_PPM["DOUBLE_PREVOTE"] == 300_000 == P.SLASH_RATE_PPM["DOUBLE_PRECOMMIT"])
    chk("SEVERE = 10%", P.SLASH_RATE_PPM["SEVERE"] == 600_000)
    chk("INVALID_PROPOSAL = 1%", P.SLASH_RATE_PPM["INVALID_PROPOSAL"] == 60_000)


def test_spec_text_agreement():
    print("\n2) 代码常量 == 规范文本（防止代码与规范一起漂移）")
    text = load_spec()
    pairs = [
        ("GenesisTimestamp", r"GenesisTimestamp\s*=\s*(\d{9,})", str(P.GENESIS_TIMESTAMP)),
        ("协议年槽数", r"PROTOCOL_YEAR_SLOTS\s*=\s*([\d,]+)", f"{P.PROTOCOL_YEAR_SLOTS:,}"),
        ("解绑期槽数", r"UNBONDING_PERIOD_SLOTS = ([\d,]+)", f"{P.UNBONDING_PERIOD_SLOTS:,}"),
        ("最大验证者数", r"MAX_VALIDATORS = (\d+)", str(P.MAX_VALIDATORS)),
        ("最低质押", r"MIN_VALIDATOR_STAKE = (\d+) AGORA",
         str(P.MIN_VALIDATOR_STAKE // P.ATOM_PER_AGORA)),
        ("空投上限", r"AIRDROP_MAX_SHARE\s*=\s*20%\s*=\s*([\d,]+) AGORA",
         f"{P.AIRDROP_MAX_SHARE // P.ATOM_PER_AGORA:,}"),
        ("初始供应", r"INITIAL_SUPPLY = ([\d,]+) AGORA",
         f"{P.INITIAL_SUPPLY // P.ATOM_PER_AGORA:,}"),
        ("目标 gas", r"TARGET_GAS_PER_BLOCK = ([\d,]+)", f"{P.TARGET_GAS_PER_BLOCK:,}"),
        ("最小基础费", r"INITIAL_BASE_FEE = MIN_BASE_FEE = 1 nAGORA / gas = ([\d,]+)",
         f"{P.MIN_BASE_FEE:,}"),
        ("基础费分母", r"BASE_FEE_CHANGE_DENOMINATOR = (\d+)",
         str(P.BASE_FEE_CHANGE_DENOMINATOR)),
        ("年度销毁率", r"ANNUAL_BURN_RATE\s*=\s*(\d+)%",
         str(P.ANNUAL_BURN_RATE_PPM // 10_000)),
        ("创始期纪元数", r"FOUNDER_PERIOD_EPOCHS = ([\d,]+)", f"{P.FOUNDER_PERIOD_EPOCHS:,}"),
        ("轮次增量", r"ROUND_INCREMENT\s*=\s*(\d+)\s*毫秒",
         str(P.ROUND_TIMEOUT_INCREMENT_MS)),
        ("过渡期纪元数", r"TRANSITION_EPOCHS\s*=\s*([\d,]+)",
         f"{P.TRANSITION_EPOCHS:,}"),
        ("过渡期窗口末槽", r"TRANSITION_END_SLOT\s*=\s*([\d,]+)",
         f"{P.TRANSITION_END_SLOT:,}"),
    ]
    bad = []
    for label, pat, want in pairs:
        m = re.search(pat, text)
        if not m:
            bad.append(f"{label}(规范中未找到)")
        elif m.group(1).replace(",", "") != want.replace(",", ""):
            bad.append(f"{label}(规范={m.group(1)} 代码={want})")
    chk(f"{len(pairs)} 项与规范文本一致", not bad, "；".join(bad) if bad else "")
    # 发行曲线分子必须在规范文本中出现
    chk("发行曲线分子出现在规范中",
        f"{P.BLOCK_REWARD_NUMERATOR}" in text.replace(",", ""),
        f"{P.BLOCK_REWARD_NUMERATOR}")


def test_derived_formulas():
    print("\n3) 派生算式 == 规范核验表")
    # 时间换算
    chk("SlotsPerDay = 86400/5", P.SLOTS_PER_DAY == 17280)
    chk("14 天 / 21 天 / 365 天 的槽数换算精确",
        P.SUBJECTIVITY_PERIOD_SLOTS * 5 == 14 * 86400
        and P.UNBONDING_PERIOD_SLOTS * 5 == 21 * 86400
        and P.PROTOCOL_YEAR_SLOTS * 5 == 365 * 86400)
    # 时间戳
    chk("block_timestamp(0) = GenesisTimestamp", P.block_timestamp(0) == P.GENESIS_TIMESTAMP)
    chk("block_timestamp(6,307,200) 正确",
        P.block_timestamp(P.PROTOCOL_YEAR_SLOTS)
        == P.GENESIS_TIMESTAMP + P.PROTOCOL_YEAR_SLOTS * 5)
    # 轮次超时
    chk("ROUND_TIMEOUT(0..3) = 7 / 7.5 / 8 / 8.5 秒",
        [P.round_timeout_ms(r) for r in range(4)] == [7000, 7500, 8000, 8500])
    # 法定数：atom 粒度（BUG-35）
    S = 4 * P.MIN_VALIDATOR_STAKE
    chk("QUORUM(4×64 AGORA) = 170,666,666,666,666,666,667 atom",
        P.quorum(S) == 170666666666666666667, f"{P.quorum(S)}")
    chk("QUORUM 运算在 atom 粒度（非整币）",
        P.quorum(S) != 171 * P.ATOM_PER_AGORA,
        "整币粒度会得到 171 AGORA，相差 3.3e17 atom")
    chk("3 人可达法定数", 3 * P.MIN_VALIDATOR_STAKE >= P.quorum(S))
    chk("2 人不可达法定数", 2 * P.MIN_VALIDATOR_STAKE < P.quorum(S))
    chk("1 人不可达法定数", P.MIN_VALIDATOR_STAKE < P.quorum(S))
    # 发行曲线
    # 恒定曲线（§28.4）：用过渡期之后的槽取值
    _after = P.TRANSITION_END_SLOT
    chk("曲线 60% 处 = MIN_BLOCK_REWARD（因 0.17 > 0.16）",
        P.curve_block_reward(P.INITIAL_SUPPLY * 60 // 100) == P.MIN_BLOCK_REWARD)
    chk("曲线 10% 处 = MAX_BLOCK_REWARD",
        P.curve_block_reward(P.INITIAL_SUPPLY * 10 // 100) == P.MAX_BLOCK_REWARD)
    chk("曲线 100% 处 = MIN_BLOCK_REWARD",
        P.curve_block_reward(P.INITIAL_SUPPLY) == P.MIN_BLOCK_REWARD)
    star = P.BLOCK_REWARD_NUMERATOR / P.MIN_BLOCK_REWARD / P.INITIAL_SUPPLY
    chk("曲线触底点 = 48.00%（D-5 后的解析值）", star == 0.48, f"{star:.4%}")
    chk("质押量为 0 时返回 MAX（链此时应 halt）",
        P.curve_block_reward(0) == P.MAX_BLOCK_REWARD)
    chk("block_reward 在窗口后与曲线一致",
        P.block_reward(P.INITIAL_SUPPLY, _after) == P.MIN_BLOCK_REWARD)
    # 过渡期地板（§28.4.1）：窗口内 = max(曲线, 地板)，当前取值下恒为 0.64
    chk("窗口内 100% 质押也发 0.64（地板生效）",
        P.block_reward(P.INITIAL_SUPPLY, 0) == P.MAX_BLOCK_REWARD)
    chk("窗口末槽仍生效、首槽回到曲线",
        P.block_reward(P.INITIAL_SUPPLY, _after - 1) == P.MAX_BLOCK_REWARD
        and P.block_reward(P.INITIAL_SUPPLY, _after) == P.MIN_BLOCK_REWARD)
    chk("地板落在 [MIN, MAX] 内",
        P.MIN_BLOCK_REWARD <= P.TRANSITION_REWARD_FLOOR <= P.MAX_BLOCK_REWARD)
    # GATE-6 包线不变量（D-5）：包线内最差点（丢槽 10% + 质押率 100%）≥ +0.5pp
    _ann = P.MIN_BLOCK_REWARD * P.PROTOCOL_YEAR_SLOTS / P.ATOM_PER_AGORA
    _worst = _ann / (P.INITIAL_SUPPLY / P.ATOM_PER_AGORA) * 100 \
        * (1 - P.ENVELOPE_SLOT_LOSS_PCT / 100) - P.ANNUAL_BURN_RATE_PPM / 10_000
    chk(f"包线内最差点 = {_worst:+.4f}pp ≥ 包线下限 +{P.ENVELOPE_MIN_NET_PCT}pp",
        _worst >= P.ENVELOPE_MIN_NET_PCT, f"{_worst:+.4f}pp")
    chk("包线 = 丢槽 ≤ 10%、下限 +0.5pp（与规范 §30 一致）",
        (P.ENVELOPE_SLOT_LOSS_PCT, P.ENVELOPE_MIN_NET_PCT) == (10, 0.5))
    chk("过渡期 = 2 年且与空投窗口同期",
        P.TRANSITION_END_SLOT == P.AIRDROP_END_SLOT
        == P.TRANSITION_EPOCHS * P.EPOCH_LENGTH)
    # 基础费核验表（规范 §17.4）
    tbl = [(1_000_000_000, 0, 1_000_000_000),
           (1_000_000_000, 4_000_000, 1_000_000_000),
           (1_000_000_000, 6_000_000, 1_025_000_000),
           (1_000_000_000, 10_000_000, 1_125_000_000),
           (1_000_000_000_000, 4_000_000, 975_000_000_000),
           (1_000_000_000_000, 10_000_000, 1_125_000_000_000)]
    bad = [(bf, gu, P.base_fee_next(bf, gu), want)
           for bf, gu, want in tbl if P.base_fee_next(bf, gu) != want]
    chk("基础费核验表 6 行全部相符", not bad, str(bad) if bad else "")
    chk("基础费永不低于 MIN_BASE_FEE",
        all(P.base_fee_next(P.MIN_BASE_FEE, g) >= P.MIN_BASE_FEE
            for g in range(0, P.MAX_GAS_PER_BLOCK + 1, 500_000)))
    chk("gas 等于目标时基础费不变",
        P.base_fee_next(10 ** 12, P.TARGET_GAS_PER_BLOCK) == 10 ** 12)
    # 罚没
    base = 64 * P.ATOM_PER_AGORA
    chk("5% 罚没 = 3.2 AGORA", P.slash_amount(base, "DOUBLE_PREVOTE") == 3_200_000_000_000_000_000)
    chk("10% 罚没 = 6.4 AGORA", P.slash_amount(base, "SEVERE") == 6_400_000_000_000_000_000)
    chk("1% 罚没 = 0.64 AGORA", P.slash_amount(base, "INVALID_PROPOSAL") == 640_000_000_000_000_000)
    # 分配劈分
    prop, pool = P.split_proposer_attestation(100)
    chk("20/80 劈分且余数归提案者", prop + pool == 100 and pool == 80)
    # 不活跃惩罚
    # 规范 §13.2（BUG-36 修正后）：k=100 时为 6,079 ppm = 0.6079%（**不是** 1.402%）
    chk("不活跃 k=1 → 1 ppm", P.inactivity_penalty_ppm(1) == 1)
    chk("不活跃 k=64 → 3,775 ppm", P.inactivity_penalty_ppm(64) == 3775)
    chk("不活跃 k=100 → 6,079 ppm（0.6079%）", P.inactivity_penalty_ppm(100) == 6079,
        f"{P.inactivity_penalty_ppm(100) / 10_000:.4f}%")
    chk("不活跃 k≥64 后每槽 +64 ppm 线性增长",
        all(P.inactivity_penalty_ppm(k + 1) - P.inactivity_penalty_ppm(k) == 64
            for k in range(64, 90)))
    chk("不活跃扣除额：64 AGORA 质押、k=100 → 0.389056 AGORA",
        P.inactivity_deduction(64 * P.ATOM_PER_AGORA, 100) == 389_056_000_000_000_000,
        f"{P.inactivity_deduction(64 * P.ATOM_PER_AGORA, 100) / P.ATOM_PER_AGORA:.6f} AGORA")
    chk("不活跃惩罚随 k 单调递增",
        all(P.inactivity_penalty_ppm(k) < P.inactivity_penalty_ppm(k + 1)
            for k in range(1, 120)))


def test_self_check_runs():
    print("\n4) params 模块的启动自检")
    chk("导入即执行自检且无异常", True, "（导入成功即通过）")
    chk("三阶段超时与轮次超时为不同层级（数值相等属巧合）",
        P.BASE_TIMEOUT_MS == P.PROPOSAL_TIMEOUT_MS + P.PREVOTE_TIMEOUT_MS
        + P.PRECOMMIT_TIMEOUT_MS,
        "规范明文说明这是巧合，禁止据此推导")
    text = load_spec()
    chk("规范已写明该巧合，防止实现误改数值",
        "属巧合" in text and "禁止据此推导" in text)


def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 参数一致性测试")
    print("═" * 76)
    test_expected_values()
    test_spec_text_agreement()
    test_derived_formulas()
    test_self_check_runs()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
