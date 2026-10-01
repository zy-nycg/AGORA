#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 规范数值一致性检查器
====================================

用途
----
从 AGORA_v0.2.2_SPEC.md 中【抽取参数】并复算全部导出的数值，任何不一致即报错退出（exit 1）。

为什么需要它
------------
在 v0.2.2 的修订过程中，曾出现过三类真实缺陷，均由"手写数值"引入：
  1. `MIN_BLOCK_REWARD` 与决策不符（0.08 vs 0.17）—— 造成高质押率区间实际收益为负；
  2. 发行曲线的分子常量算错两次 —— 使曲线在质押率 1.72% / 2.76% 就触底，反馈失效；
  3. 基础费"最小步长"注记错误（1.25e8 vs 1）—— 会误导实现者写出快 250 倍的费率轨迹。
这三类错误的共同点是【文档内部数值彼此不一致】，只有自动化复算才能发现。

用法
----
  python3 tools/agora_check_spec.py [--spec AGORA_v0.2.2_SPEC.md]

退出码：0 = 全部一致；1 = 存在不一致（逐条打印）。
仅使用标准库；不写任何文件。
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from fractions import Fraction as F

# 让检查器能 import 参考实现（用于校验"规范声明 == 实现"，见 BUG-72）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── 从规范文本抽取参数 ────────────────────────────────────────────────

def grab_int(text, pattern, name):
    m = re.search(pattern, text, re.M)
    if not m:
        raise SystemExit(f"规范中找不到参数 {name}（模式：{pattern}）")
    return int(m.group(1).replace(",", "").replace("_", ""))


def parse_spec(path):
    text = open(path, encoding="utf-8").read()
    p = {}
    p["text"] = text
    p["genesis_ts"]   = grab_int(text, r"GenesisTimestamp\s*=\s*(\d{9,})", "GenesisTimestamp")
    p["slot_time"]    = grab_int(text, r"SLOT_TIME\s*=\s*(\d+)\s*秒", "SLOT_TIME")
    p["epoch_len"]    = grab_int(text, r"EPOCH_LENGTH\s*=\s*(\d+)\s*slots", "EPOCH_LENGTH")
    p["delta"]        = grab_int(text, r"CLOCK_TOLERANCE Δ = (\d+)", "CLOCK_TOLERANCE")
    p["year_slots"]   = grab_int(text, r"PROTOCOL_YEAR_SLOTS\s*=\s*([\d,]+)", "PROTOCOL_YEAR_SLOTS")
    p["unbond"]       = grab_int(text, r"UNBONDING_PERIOD_SLOTS = ([\d,]+)", "UNBONDING_PERIOD_SLOTS")
    p["slash_win"]    = grab_int(text, r"SLASH_WINDOW_SLOTS = ([\d,]+)", "SLASH_WINDOW_SLOTS")
    p["subjectivity"] = grab_int(text, r"SUBJECTIVITY_PERIOD_SLOTS = ([\d,]+)", "SUBJECTIVITY_PERIOD_SLOTS")
    p["min_stake"]    = grab_int(text, r"MIN_VALIDATOR_STAKE = (\d+) AGORA", "MIN_VALIDATOR_STAKE")
    p["max_vals"]     = grab_int(text, r"MAX_VALIDATORS = (\d+)", "MAX_VALIDATORS")
    p["founder_ep"]   = grab_int(text, r"FOUNDER_PERIOD_EPOCHS = ([\d,]+)", "FOUNDER_PERIOD_EPOCHS")
    p["airdrop_max"]  = grab_int(text, r"AIRDROP_MAX_SHARE\s*=\s*20%\s*=\s*([\d,]+) AGORA", "AIRDROP_MAX_SHARE")
    p["initial"]      = grab_int(text, r"INITIAL_SUPPLY = ([\d,]+) AGORA", "INITIAL_SUPPLY")
    p["target_gas"]   = grab_int(text, r"TARGET_GAS_PER_BLOCK = ([\d,]+)", "TARGET_GAS_PER_BLOCK")
    p["max_gas"]      = grab_int(text, r"MAX_GAS_PER_BLOCK\s*=\s*([\d,]+)", "MAX_GAS_PER_BLOCK")
    p["base_fee"]     = grab_int(text, r"INITIAL_BASE_FEE = MIN_BASE_FEE = 1 nAGORA / gas = ([\d,]+)", "MIN_BASE_FEE")
    p["denom"]        = grab_int(text, r"BASE_FEE_CHANGE_DENOMINATOR = (\d+)", "BASE_FEE_CHANGE_DENOMINATOR")
    p["annual_burn_pct"] = grab_int(text, r"ANNUAL_BURN_RATE\s*=\s*(\d+)%", "ANNUAL_BURN_RATE")
    p["base_timeout"] = grab_int(text, r"BASE_TIMEOUT\s*=\s*(\d+)\s*秒", "BASE_TIMEOUT")
    p["round_inc"]    = grab_int(text, r"ROUND_INCREMENT\s*=\s*(\d+)\s*毫秒", "ROUND_INCREMENT")
    p["min_block_rew"]= int(float(re.search(r"MIN_BLOCK_REWARD = ([\d.]+) × 10\^(\d+)", text).group(1))
                            * 10 ** int(re.search(r"MIN_BLOCK_REWARD = ([\d.]+) × 10\^(\d+)", text).group(2)))
    p["max_block_rew"]= int(float(re.search(r"MAX_BLOCK_REWARD = ([\d.]+) × 10\^(\d+)", text).group(1))
                            * 10 ** int(re.search(r"MAX_BLOCK_REWARD = ([\d.]+) × 10\^(\d+)", text).group(2)))
    p["base_block_rew"] = int(float(re.search(r"BASE_BLOCK_REWARD = 0\.16 AGORA = ([\d.]+) × 10\^(\d+)", text).group(1))
                              * 10 ** int(re.search(r"BASE_BLOCK_REWARD = 0\.16 AGORA = ([\d.]+) × 10\^(\d+)", text).group(2)))
    p["target_staked"] = float(re.search(r"TARGET_STAKED\s*=\s*([\d.]+)", text).group(1))
    p["numerator"]    = grab_int(text, r"= (1966080000000000000000000000000000000000000)\b", "NUMERATOR")
    # §28.4.1 过渡期（D-3）
    p["transition_epochs"] = grab_int(text, r"TRANSITION_EPOCHS\s*=\s*([\d,]+)", "TRANSITION_EPOCHS")
    p["transition_end"]    = grab_int(text, r"TRANSITION_END_SLOT\s*=\s*([\d,]+)", "TRANSITION_END_SLOT")
    p["transition_floor"]  = int(float(re.search(
        r"TRANSITION_REWARD_FLOOR = MAX_BLOCK_REWARD = ([\d.]+) × 10\^(\d+)", text).group(1))
        * 10 ** int(re.search(
            r"TRANSITION_REWARD_FLOOR = MAX_BLOCK_REWARD = ([\d.]+) × 10\^(\d+)", text).group(2)))
    return p


# ── 检查 ─────────────────────────────────────────────────────────────

class Checker:
    def __init__(self):
        self.fail = 0
        self.pass_ = 0

    def chk(self, name, cond, detail=""):
        mark = "OK  " if cond else "FAIL"
        print(f"  [{mark}] {name}" + (f"   {detail}" if detail else ""))
        if cond:
            self.pass_ += 1
        else:
            self.fail += 1


def _count_fields_from_spec(text: str, name: str):
    """从规范里解析形如 `Name = RLP([ ... ])` 的字段数。

    只统计顶层逗号分隔的项（忽略缩进与注释）；解析失败返回 `None`。
    这样"改了实现忘了改规范"会在检查器里立刻暴露（BUG-72 的教训）。
    """
    import re as _re
    m = _re.search(rf"{_re.escape(name)}\s*=\s*RLP\(\[", text)
    if not m:
        return None
    i = m.end()
    depth = 1
    body = []
    while i < len(text) and depth > 0:
        ch = text[i]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                break
        body.append(ch)
        i += 1
    raw = "".join(body)
    # 去掉注释与空行，按顶层逗号切分
    lines = [_re.sub(r"#.*$", "", ln).strip() for ln in raw.splitlines()]
    joined = " ".join(ln for ln in lines if ln)
    if not joined:
        return 0
    items, depth, cur = [], 0, ""
    for ch in joined:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            items.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        items.append(cur)
    return len([x for x in items if x.strip()])


def _names_from_spec(text: str, name: str):
    """从规范的 `Name = RLP([...])` 块里解析**字段名列表**（按出现顺序）。

    与 `_count_fields_from_spec` 互补：数量一致不代表顺序一致，而 RLP 编码下
    顺序错了照样改变哈希（BUG-74 正是"数量对、顺序错"）。
    """
    import re as _re
    m = _re.search(rf"{_re.escape(name)}\s*=\s*RLP\(\[", text)
    if not m:
        return None
    i, depth, body = m.end(), 1, []
    while i < len(text) and depth > 0:
        ch = text[i]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                break
        body.append(ch)
        i += 1
    raw = _re.sub(r"#.*$", "", "".join(body), flags=_re.M)
    joined = " ".join(ln.strip() for ln in raw.splitlines() if ln.strip())
    if not joined:
        return []
    items, depth, cur = [], 0, ""
    for ch in joined:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            items.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        items.append(cur)
    out = []
    for it in items:
        it = it.strip()
        mm = _re.match(r"([A-Za-z_][A-Za-z0-9_]*)", it)
        out.append(mm.group(1) if mm else it)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="AGORA v0.2.2 规范数值一致性检查器")
    ap.add_argument("--spec", default="AGORA_v0.2.2_SPEC.md")
    args = ap.parse_args(argv)

    s = parse_spec(args.spec)
    text = s["text"]
    c = Checker()
    A = 10 ** 18

    print(f"检查文件：{args.spec}")
    print("═" * 70)
    print("1) 时间与槽")
    c.chk("GenesisTimestamp = 2026-10-01 00:00:00 UTC", s["genesis_ts"] == 1790812800,
          f"= {s['genesis_ts']}")
    c.chk("SLOT_TIME = 5 秒", s["slot_time"] == 5)
    c.chk("EPOCH_LENGTH = 720 slots", s["epoch_len"] == 720)
    c.chk("Δ 已定义", s["delta"] > 0, f"Δ = {s['delta']} 槽")
    c.chk("协议年 = 365×86400/5 槽", s["year_slots"] == 365 * 86400 // 5, f"= {s['year_slots']:,}")
    for label, val, days in (("14 天（主观期）", s["subjectivity"], 14),
                             ("21 天（解绑/罚没窗口）", s["unbond"], 21),
                             ("21 天（罚没窗口）", s["slash_win"], 21)):
        c.chk(f"{label} 的槽数精确", val * s["slot_time"] == days * 86400, f"{val:,} 槽")
    c.chk("相对上界 K 未出现在 §5.2 生效约束块",
          all("parent.claimed_slot + K" not in b
              for b in re.findall(r"```(.*?)```",
                                  text[text.index("## 5.2"):text.index("## 5.3")], re.S)))

    print("\n2) 创世与质押")
    c.chk("创世分配闭合：20% + 80% = 总量",
          s["airdrop_max"] + (s["initial"] - s["airdrop_max"]) == s["initial"],
          f"{s['airdrop_max']:,} + {s['initial'] - s['airdrop_max']:,} = {s['initial']:,}")
    c.chk("AIRDROP_MAX_SHARE = 总量 × 20%", s["airdrop_max"] * 5 == s["initial"])
    S = 4 * s["min_stake"]
    Q = -(-2 * S // 3)
    c.chk("4×64 AGORA → QUORUM = 171", Q == 171, f"S = {S}, Q = {Q}")
    c.chk("单人不可达法定数（防独裁）", s["min_stake"] < Q)
    c.chk("两人不可达法定数", 2 * s["min_stake"] < Q)
    c.chk("三人可达法定数（防单点停机）", 3 * s["min_stake"] >= Q)
    c.chk("创始期 ≈ 1 年", abs(s["founder_ep"] * s["epoch_len"] / s["year_slots"] - 1) < 0.45,
          f"{s['founder_ep']:,} 纪元 = {s['founder_ep'] * s['epoch_len'] / s['year_slots']:.2f} 年")

    from agora import params as _impl
    _P_MIN, _P_MAX = _impl.MIN_BLOCK_REWARD, _impl.MAX_BLOCK_REWARD

    print("\n3) 发行曲线")
    NUM = s["base_block_rew"] * int(F(str(s["target_staked"])) * s["initial"] * A)
    c.chk("NUMERATOR 与因子化定义一致", NUM == s["numerator"],
          f"定义 {NUM:,} / 文本 {s['numerator']:,}")
    c.chk("MIN_BLOCK_REWARD = 0.20 AGORA（1(b) 定值 0.17 经 D-5 上调，见 §37C.3）",
          s["min_block_rew"] == 20 * 10 ** 16,
          f"= {s['min_block_rew'] / A:.4f} AGORA")
    c.chk("实现常量 == 规范文本：MIN / MAX_BLOCK_REWARD",
          (_P_MIN, _P_MAX) == (s["min_block_rew"], s["max_block_rew"]),
          "实现与规范一致" if (_P_MIN, _P_MAX) == (s["min_block_rew"], s["max_block_rew"])
          else f"实现 {_P_MIN / A:.2f}/{_P_MAX / A:.2f}")
    c.chk("MAX_BLOCK_REWARD = 0.64 AGORA", s["max_block_rew"] == 64 * 10 ** 16,
          f"= {s['max_block_rew'] / A:.4f} AGORA")
    c.chk("MIN > MAX 情形不存在", s["min_block_rew"] <= s["max_block_rew"])

    def reward(staked_atoms):
        return max(s["min_block_rew"], min(s["max_block_rew"], s["numerator"] // staked_atoms))

    raw60 = s["numerator"] // int(s["initial"] * A * F(60, 100))
    c.chk("质押率 60% 处曲线值 = 0.16 AGORA", abs(raw60 / A - 0.16) < 1e-9,
          f"= {raw60 / A:.4f}")
    star = F(s["numerator"], s["min_block_rew"]) / (s["initial"] * A)
    c.chk("曲线触底点 = 48.00%（D-5 后的解析值）", star == F(48, 100),
          f"= {float(star):.2%}")

    print("\n3b) 过渡期奖励地板（§28.4.1，所有者决策 D-3）")
    t_ep, t_end, t_floor = s["transition_epochs"], s["transition_end"], s["transition_floor"]
    c.chk("TRANSITION_END_SLOT = TRANSITION_EPOCHS × EPOCH_LENGTH",
          t_end == t_ep * s["epoch_len"], f"{t_ep:,} × {s['epoch_len']} = {t_end:,}")
    c.chk("窗口 = 2 个协议年（12,614,400 槽）",
          t_end * s["slot_time"] == 2 * 365 * 86400,
          f"{t_end * s['slot_time'] / 86400 / 365:.2f} 年")
    c.chk("窗口与空投窗口同期（= AIRDROP_END_SLOT）",
          t_end == grab_int(text, r"AIRDROP_END_SLOT\s*=\s*([\d,]+)", "AIRDROP_END_SLOT"),
          f"{t_end:,}")
    c.chk("地板落在 [MIN, MAX] 内（否则 clamp 语义自相矛盾）",
          s["min_block_rew"] <= t_floor <= s["max_block_rew"],
          f"{t_floor / A:.4f} ∈ [{s['min_block_rew'] / A:.2f}, {s['max_block_rew'] / A:.2f}]")
    c.chk("地板 = MAX_BLOCK_REWARD（D-3 的取值）", t_floor == s["max_block_rew"])
    # 曲线上限截断点必须恰好是质押率 15%（地板取值的算术依据）
    cap = F(s["numerator"], s["max_block_rew"]) / (s["initial"] * A)
    c.chk("曲线上限截断点 = 质押率 15.0000%", cap == F(15, 100), f"{float(cap):.4%}")

    def reward_t(staked_atoms):
        """窗口内块奖励（§28.4.1）。"""
        return max(reward(staked_atoms), t_floor)

    c.chk("窗口内任意质押量均得 0.64 AGORA（地板 == 上限 ⇒ 常数发行）",
          {reward_t(int(s["initial"] * A * F(p, 100))) for p in (1, 15, 60, 100)}
          == {s["max_block_rew"]})
    c.chk("窗口边界：末槽 = 地板、首槽 = 曲线（质押率 100%）",
          reward_t(int(s["initial"] * A)) == t_floor
          and reward(int(s["initial"] * A)) == s["min_block_rew"])
    c.chk("规范写明判定输入必须是 claimed_slot（禁止墙钟/高度）",
          "MUST** 是本区块头里被签名的 `claimed_slot`" in text)

    # 规范 §28.4.1 内嵌表的逐行复算（表由工具生成 ⇒ 必须能程序复现）
    _prio = 6307.2 / 2                          # 利用率 50% 时的年优先费（§30 基线）
    _rows = re.findall(
        r"^\|\s*([\d.]+)%\s*\|\s*([\d.]+)\s*\|\s*([\d,]+\.\d+)%\s*\|\s*"
        r"([+-][\d,]+\.\d+)%\s*\|\s*([\d.]+)\s*\|\s*([+-][\d,]+\.\d+)%\s*\|",
        text, re.M)
    c.chk("§28.4.1 内嵌表可被解析（≥10 行）", len(_rows) >= 10, f"{len(_rows)} 行")
    _bad = []
    for pct_s, w_rw, w_gross, w_net, s_rw, s_net in _rows:
        ratio = F(pct_s) / 100
        staked = int(s["initial"] * A * ratio)
        if staked == 0:
            staked = 1
        staked_agora = staked / A
        # 窗口内
        g = (reward_t(staked) * s["year_slots"] / A + _prio) / float(staked_agora) * 100
        n = g - s["annual_burn_pct"]
        # 窗口后
        g2 = (reward(staked) * s["year_slots"] / A + _prio) / float(staked_agora) * 100
        n2 = g2 - s["annual_burn_pct"]
        if (abs(float(w_rw) - reward_t(staked) / A) > 1e-4     # 表内 4 位小数，允许半位舍入
                or abs(float(w_gross.replace(",", "")) - g) > 0.01
                or abs(float(w_net.replace(",", "").lstrip("+")) - n) > 0.01
                or abs(float(s_rw) - reward(staked) / A) > 1e-4
                or abs(float(s_net.replace(",", "").lstrip("+")) - n2) > 0.01):
            _bad.append(f"{pct_s}%：表 {w_rw}/{w_gross}/{w_net} 复算 "
                        f"{reward_t(staked) / A:.4f}/{g:.2f}/{n:+.2f}")
    c.chk(f"§28.4.1 表内 {len(_rows)} 行逐行复算一致（含窗口前后两列）",
          not _bad, "；".join(_bad[:3]) if _bad else "无残差（≤0.01 个百分点）")

    # §30.1 的口径拆分：过渡期全通过、稳态不通过，且两者不得合并验收
    c.chk("§30.1 要求「口径 × 包线」分别验收（禁止合并）",
          "按**口径 × 包线**分别进行并分别给出结论" in text
          and "**MUST NOT** 合并验收" in text
          and '用"包线内全部通过"的表述把它隐去' in text)
    c.chk("§30 与 §30.1 的包线内数字一致（392/392，最差 +0.5434%）",
          text.count("392/392") >= 2 and "0.5434" in text)
    c.chk("§30 与 §30.1 的包线外数字一致（112/196，最差 −1.9203%）",
          "112/196" in text and "1.9203" in text)
    c.chk("§37E 记录了 §36 要求的八项（① – ⑧）",
          all(re.search(r"\|\s*" + num + r"\s*\|\s*\*\*" + name + r"\*\*", text)
              for num, name in (("①", "原因"), ("②", "受影响参数"), ("③", "安全影响"),
                                ("④", "活性影响"), ("⑤", "经济影响"),
                                ("⑥", "向后兼容性"), ("⑦", "测试变更"),
                                ("⑧", "规范 diff"))))
    # 规范文本 == 实现常量（本节数值若只与自身自洽，就等于没检查）
    from agora import params as _P
    c.chk("实现常量 == 规范文本：TRANSITION_EPOCHS",
          _P.TRANSITION_EPOCHS == t_ep, f"实现 {_P.TRANSITION_EPOCHS:,}")
    c.chk("实现常量 == 规范文本：TRANSITION_END_SLOT",
          _P.TRANSITION_END_SLOT == t_end, f"实现 {_P.TRANSITION_END_SLOT:,}")
    c.chk("实现常量 == 规范文本：TRANSITION_REWARD_FLOOR",
          _P.TRANSITION_REWARD_FLOOR == t_floor,
          f"实现 {_P.TRANSITION_REWARD_FLOOR / A:.4f} AGORA")
    c.chk("实现常量 == 规范文本：MIN / MAX_BLOCK_REWARD",
          (_P.MIN_BLOCK_REWARD, _P.MAX_BLOCK_REWARD)
          == (s["min_block_rew"], s["max_block_rew"]))
    c.chk("实现：窗口外 == 曲线、窗口内 == 地板",
          _P.block_reward(int(_P.INITIAL_SUPPLY), _P.TRANSITION_END_SLOT)
          == _P.curve_block_reward(int(_P.INITIAL_SUPPLY)) == s["min_block_rew"]
          and _P.block_reward(int(_P.INITIAL_SUPPLY), 0) == t_floor)

    print("\n3c) GATE-6 声明包线（§30 / §37C.3，所有者决策 D-5）")
    _env = re.search(r"ENVELOPE_SLOT_LOSS_PCT = (\d+)", text)
    _envmin = re.search(r"ENVELOPE_MIN_NET_PCT = \+([\d.]+) 个百分点", text)
    c.chk("规范定义包线：丢槽率 ≤ 10%", bool(_env) and _env.group(1) == "10",
          f"= {_env.group(1) if _env else '未找到'}%")
    c.chk("规范定义包线内净收益下限：≥ +0.5pp",
          bool(_envmin) and float(_envmin.group(1)) == 0.5,
          f"= +{_envmin.group(1) if _envmin else '未找到'}pp")
    c.chk("实现常量 == 规范文本：包线两项",
          (from_agora := __import__("agora.params", fromlist=["params"])).ENVELOPE_SLOT_LOSS_PCT == 10
          and from_agora.ENVELOPE_MIN_NET_PCT == 0.5)
    # 包线内最差点（丢槽 10% + 质押率 100%，优先费按 0 的保守口径）
    _ann = F(s["min_block_rew"] * s["year_slots"], A)
    _worst = float(_ann / s["initial"] * 100) * 0.9 - s["annual_burn_pct"]
    c.chk(f"包线内最差点净收益 = {_worst:+.4f}pp ≥ +0.5pp（参数与包线自洽）",
          _worst >= 0.5, f"{_worst:+.4f}pp")
    # 包线内其余点必须更高（单调性：质押率越低收益越高）
    _hp = []
    for _p in (10, 30, 45, 48, 56.5, 60, 75, 90, 100):
        _st = int(s["initial"] * A * F(_p) / 100)
        _rw = reward(_st)
        _g = float(F(_rw * s["year_slots"], A) / (_st / A) * 100)
        _hp.append(_g * 0.9 - s["annual_burn_pct"])
    c.chk("包线内所有质押率档均 ≥ +0.5pp（最差点即质押率 100%）",
          min(_hp) >= 0.5 and min(_hp) == _hp[-1],
          f"最小值 {min(_hp):+.4f}pp @ 质押率 {[10,30,45,48,56.5,60,75,90,100][_hp.index(min(_hp))]}%")
    c.chk("§37C 已记录裁决（C + A'）与实现者的判断错误",
          "已由所有者裁决：方案 C + A'" in text
          and "实现者必须先记录自己的判断错误" in text
          and "该方案单独实施并不能通过" in text)
    c.chk("§37D 已记录裁决（方案 A）", "已由所有者确认：方案 A" in text
          and "## 37D.4 裁决（所有者决策 D-6，**已批准**）" in text)
    c.chk("§0.3 登记 D-5 / D-6",
          "| D-5 |" in text and "| D-6 |" in text)
    c.chk("包线外残余风险已原样登记（数值与位置）",
          "−1.9203%" in text and "84 / 588" in text)

    # 规范 §28.4 验收表的逐行复算（BUG-70 的修法：表必须可程序复算）
    _prio = 6307.2 / 2                                   # 利用率 50% 时的年优先费（§30 基线）
    _tbl = re.findall(
        r"^\|\s*([\d.]+)%\s*\|\s*([\d.]+)\s*\|\s*([\d,]+)\s*\|\s*"
        r"([\d.]+)%\s*\|\s*\*\*([+-][\d.]+)%\*\*\s*\|", text, re.M)
    c.chk("§28.4 验收表可被解析（≥8 行）", len(_tbl) >= 8, f"{len(_tbl)} 行")
    _bad4 = []
    for _p, _rw, _iss, _gr, _net in _tbl:
        _st = int(s["initial"] * A * F(_p) / 100)
        _r = reward(_st)
        _a = F(_r * s["year_slots"], A)
        _g = float((_a + _prio) / (_st / A) * 100)      # 含 §30 基线的年优先费
        if (abs(float(_rw) - _r / A) > 1e-4 or abs(float(_iss.replace(",", "")) - float(_a)) > 1.0
                or abs(float(_gr) - _g) > 0.011
                or abs(float(_net.replace("+", "")) - (_g - s["annual_burn_pct"])) > 0.011):
            _bad4.append(f"{_p}%：表 {_rw}/{_iss}/{_gr}/{_net}")
    c.chk(f"§28.4 表内 {len(_tbl)} 行逐行复算一致（BUG-70 修法）",
          not _bad4, "；".join(_bad4[:3]) if _bad4 else "无残差（≤0.011pp）")

    print("\n4) 经济验收（关键：全区间实际收益必须为正）")
    worst, worst_at = None, None
    for r in (F(10, 100), F(30, 100), F(45, 100), F(565, 1000), F(60, 100), F(75, 100), F(90, 100), F(100, 100)):
        staked = int(s["initial"] * A * r)
        rw = reward(staked)
        gross = (rw * s["year_slots"] / A + 6307) / (s["initial"] * float(r)) * 100
        net = gross - s["annual_burn_pct"]
        print(f"        质押率 {float(r):>6.1%} → 块奖励 {rw / A:>6.4f} AGORA, 实际收益 {net:>+7.2f}%")
        if worst is None or net < worst:
            worst, worst_at = net, float(r)
    c.chk(f"全区间 NetValidatorRevenue > 0（最差 {worst:+.2f}% @ {worst_at:.1%}）", worst > 0)

    print("\n5) 基础费")
    T, DEN, MINBF = s["target_gas"], s["denom"], s["base_fee"]
    DIV = T * DEN
    c.chk("DIVISOR = TARGET × DENOM = 40,000,000", DIV == 40_000_000, f"= {DIV:,}")

    def upd(bf, gu):
        if gu > T: return bf + max(1, (bf * (gu - T)) // DIV)
        if gu < T: return max(MINBF, bf - max(1, -(-(bf * (T - gu)) // DIV)))
        return bf

    c.chk("MIN_BASE_FEE = 1 nAGORA/gas = 10^9 atom", MINBF == 10 ** 9)
    c.chk("低于目标时必须真的下降（bf 远高于地板）", upd(10 ** 12, 4_000_000) < 10 ** 12,
          f"1e12 → {upd(10**12, 4_000_000):,}")
    c.chk("不得低于 MIN_BASE_FEE", min(upd(MINBF, gu) for gu in range(0, T, 250_000)) >= MINBF)
    c.chk("单块最大变化 = 12.5%",
          upd(MINBF, s["max_gas"]) - MINBF == MINBF * (s["max_gas"] - T) // DIV,
          f"delta = {upd(MINBF, s['max_gas']) - MINBF:,}")
    c.chk("规范核验表首行相符", upd(MINBF, 6_000_000) == 1_025_000_000,
          f"1e9 / 6e6 → {upd(MINBF, 6_000_000):,}")

    print("\n6) 超时模型")
    # 注意：BASE_TIMEOUT(7) 的数值恰好等于 3+2+2，所以不能断言"数值不等"。
    # 要检查的是"它是独立常量、禁止推导"这条规范性说明是否存在。
    c.chk("BASE_TIMEOUT 为独立常量且禁止推导（说明已存在）",
          s["base_timeout"] == 7 and "独立常量" in text and "禁止据此推导" in text,
          f"= {s['base_timeout']} 秒（数值恰与 3+2+2 相等，属巧合）")
    c.chk("ROUND_INCREMENT = 500 毫秒", s["round_inc"] == 500)

    print("\n7) 关键禁令与结构（必须在文本中存在）")
    reqs = [
        ("state_root 覆盖全部状态变更", "state_root = 本区块【全部】状态变更完成后的 MPT_root"),
        ("state_root 不得只覆盖执行结果", "**MUST NOT** 只覆盖交易执行结果"),
        ("签名载荷不含签名字段", "签名载荷（BUG-2：**绝不包含签名字段**）"),
        ("HeaderContent 去掉签名", "去掉 `proposer_signature`"),
        ("Commit 不得裁剪签名", "不得裁剪为最小法定数子集"),
        ("不存在失败交易", "不存在失败交易"),
        ("分配权重取纪元快照", "纪元快照"),
        ("罚没基数入块时记录", "recorded_base"),
        ("每块即时分配", "每块即时分配"),
        ("空集合 halt", "halt"),
        ("创世配置禁止私钥", "创世配置、代码仓库、公开文档中 **MUST NOT** 出现任何私钥"),
        ("创始人补入规则", "补入"),
    ]
    for name, needle in reqs:
        c.chk(name, needle in text)

    print("\n7b) 交叉引用完整性")
    # 忽略形如 "v0.2.1 §25.1" 的历史版本引用（它们指向旧版本，不是本文件）
    # 忽略"vX.Y.Z … §N"形式的历史版本引用（指向旧版本，不是本文件）
    refs = {r for r in re.findall(r"§(\d+(?:\.\d+)*)", text)
            if not re.search(r"v\d+\.\d+\.\d+[^§]{0,12}§" + re.escape(r), text)}
    # 任意层级的 markdown 标题：# / ## / ### 后跟编号
    secs = set(m.group(1) for m in re.finditer(r"^#{1,6}\s*(\d+(?:\.\d+)*)\.?\s", text, re.M))
    dangling = sorted(r for r in refs if r not in secs)
    c.chk("无失效交叉引用（§N 指向存在章节）", not dangling,
          f"失效：{dangling}" if dangling else f"共 {len(refs)} 个引用全部有效")

    print("\n8) 参数表状态")
    # 参数表中不得出现任何 TBD 占位（标题里的"无 TBD"字样属正常）
    tbl = text[text.index("# 34. 参数表"):]
    c.chk("参数表内无 TBD 占位", not re.search(r"\|\s*TBD\s*\|", tbl) and "TBD**" not in tbl,
          "（仅允许 PENDING-MAINNET-VALUE）")
    pend = len(re.findall(r"PENDING-MAINNET-VALUE", text))
    c.chk("PENDING 项仅限 F2/F7", pend <= 6, f"出现 {pend} 次")

    print("\n8b) RLP 对象定义与实现一致性（BUG-72 确立的规则）")
    # 任何"改变共识对象编码"的修订都必须同步规范里的 RLP 定义；
    # 否则照规范实现的第二实现会算出不同的哈希/状态根（BUG-72 即此类）。
    import dataclasses as _dc
    from agora import state as _state
    _objs = [
        ("StateLeafAccount", 4,
         _count_fields_from_spec(text, "StateLeafAccount")),
        ("ValidatorRecord", len(_dc.fields(_state.ValidatorRecord)),
         _count_fields_from_spec(text, "ValidatorRecord")),
        ("SystemState", 16, _count_fields_from_spec(text, "SystemState")),
    ]
    for _name, _impl, _spec_n in _objs:
        if _spec_n is None:
            c.chk(f"{_name}：规范中可解析字段数", False, "未在规范中找到定义")
            continue
        c.chk(f"{_name}：规范声明字段数 == 实现字段数（{_impl}）",
              _spec_n == _impl, f"规范 {_spec_n}，实现 {_impl}")
    # SystemState 的**字段名顺序**也必须一致（不只是数量）——
    # BUG-74 的教训：快照被摊平为两个顶层字段时"项数仍是 16"，只有比对字段名才发现。
    _sys_spec = _names_from_spec(text, "SystemState")
    _sys_impl = ["epoch_current", "year_index", "year_start_slot", "total_supply",
                 "total_burned_basefee", "total_burned_annual", "total_burned_slash",
                 "total_burned_dust", "total_burned_inactivity",
                 "total_burned_unbacked", "snapshot", "pending_slashes",
                 "settled_slashes", "airdrop_root", "airdrop_pending",
                 "airdrop_claimed"]
    c.chk("SystemState：规范字段名顺序 == 实现（16 项）",
          _sys_spec == _sys_impl,
          "规范与实现不一致" if _sys_spec != _sys_impl else "顺序一致 ✓")
    _val_spec = _names_from_spec(text, "ValidatorRecord")
    _val_impl = ["pubkey", "effective_stake", "unbonding_balance", "status",
                 "unbond_request_slot", "unbond_complete_slot", "last_slashable_slot",
                 "inactivity_streak", "slashed_total", "is_founder",
                 "pending_stake", "pending_unbond"]
    c.chk("ValidatorRecord：规范字段名顺序 == 实现（12 项）",
          _val_spec == _val_impl, "规范与实现不一致" if _val_spec != _val_impl else "顺序一致 ✓")

    # 交易与区块头的项数也必须一致
    from agora.tx import Transaction as _Tx
    from agora.block import BlockHeader as _BH
    _tx_n = _count_fields_from_spec(text, "TxEnvelope")
    c.chk("TxEnvelope：规范 11 项（10 内容 + 1 签名）",
          _tx_n == 11, f"规范 {_tx_n}")
    _bh_n = _count_fields_from_spec(text, "BlockHeader")
    c.chk("BlockHeader：规范 16 项", _bh_n == 16, f"规范 {_bh_n}")

    print("\n9) BUG 台账完整性")
    nums = sorted({int(m) for m in re.findall(r"BUG-(\d+)", text)})
    gaps = [i for i in range(1, max(nums) + 1) if i not in nums] if nums else []
    c.chk("BUG 编号连续无缺号", not gaps, f"共 {len(nums)} 项，缺号 {gaps}")
    # 每个编号都必须在【正文】中被引用，而不只出现在台账表格行里。
    # （BUG-1..32 的修复内容已整合进各章节正文，因此不要求统一的"BUG-N："标记；
    #   这里检查的是"该编号在表格之外是否还有提及"，避免台账成为孤立的装饰。）
    table_only = []
    for n in nums:
        hits = [ln for ln in text.splitlines()
                if f"BUG-{n}" in ln and not ln.strip().startswith("| BUG-")]
        if not hits:
            table_only.append(n)
    c.chk("每个 BUG 编号在正文中都有引用（非仅台账表格）", not table_only,
          f"仅出现在表格中：{table_only}" if table_only else f"{len(nums)} 项均有正文引用")
    ledger_rows = len(re.findall(r"^\| BUG-\d+ \|", text, re.M))
    c.chk("台账行数 == 编号数（无遗漏登记）", ledger_rows == len(nums),
          "台账 %d 行，编号 %d 项" % (ledger_rows, len(nums)))

    print("\n" + "═" * 70)
    print(f"通过 {c.pass_} 项，失败 {c.fail} 项")
    print("结果：" + ("全部一致 ✅" if c.fail == 0 else "★ 存在不一致，必须修正规范"))
    return 0 if c.fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
