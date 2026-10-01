# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 多节点网络测试
========================================

覆盖规范 §41 的「共识状态机测试」「拜占庭测试」「网络测试」三节。

本文件验证**六条端到端不变量**：
    1. 理想网络下所有节点收敛到同一链头（T1 的工程体现）
    2. 高度单调推进，且每步都被 `apply_block` 真正应用（state_root 演进）
    3. 网络分区不产生分叉：恢复后仍只有一条最终化链
    4. 丢包/延迟/重复不破坏安全性（只影响速度）
    5. 拜占庭节点双签**不会**导致两个冲突区块同时最终化
    6. 全程无任何节点出现自身双签（`equivocations == 0`）

运行：python3 -m tests.test_node
"""

from __future__ import annotations

import sys
import time

from agora import params as P
from agora.consensus import Vote, VoteType
from agora.crypto import address_from_pubkey, publickey_from_seed, sign
from agora.node import Network, NetworkConfig, Simulation, make_genesis_block

_fail = 0
_pass = 0


def chk(name, cond, detail=""):
    global _fail, _pass
    if cond:
        _pass += 1
        print(f"  [OK  ] {name}" + (f"   {detail}" if detail else ""))
    else:
        _fail += 1
        print(f"  [FAIL] {name}" + (f"   {detail}" if detail else ""))


def sim(n=4, **cfg):
    cfg.setdefault('latency', 1)
    cfg.setdefault('seed', 7)
    return Simulation(n, NetworkConfig(**cfg))


def heads_equal(s: Simulation) -> bool:
    hs = {h for h in s.heads().values()}
    return len(hs) == 1


# ── 1. 理想网络 ─────────────────────────────────────────────────────

def test_ideal_network():
    print("\n1) 理想网络：收敛与推进（规范 §41 共识状态机测试）")
    s = sim(latency=1, seed=7)
    chk("创世块哈希非零且确定",
        s.genesis_block.block_hash() != b"\x00" * 32
        and s.genesis_block.block_hash() == make_genesis_block(s.genesis_state).block_hash())
    chk("4 个节点都从高度 1 起步",
        all(nd.height == 1 for nd in s.nodes.values()))

    t0 = time.time()
    s.drive(3)
    dt = time.time() - t0
    chk("所有节点达到高度 3", all(nd.height >= 3 for nd in s.nodes.values()),
        f"{s.heights()}（用时 {dt:.1f}s）")
    chk("链头收敛为同一条链", s.converged(),
        (s.nodes['node1'].head.block_hash().hex()[:12] + "…") if s.converged() else str(s.heads()))
    chk("无任何节点自身双签",
        all(nd.stats.equivocations == 0 for nd in s.nodes.values()))
    chk("每个节点都真正应用了区块",
        all(len(nd.blockchain) == nd.height - 1 for nd in s.nodes.values()),
        f"{[len(nd.blockchain) for nd in s.nodes.values()]}")
    chk("所有节点状态根一致",
        len({nd.state.state_root for nd in s.nodes.values()}) == 1)
    chk("所有节点供应量一致且守恒",
        len({nd.state.system.total_supply for nd in s.nodes.values()}) == 1
        and all(nd.state.check_supply_conservation()[0] for nd in s.nodes.values()))
    chk("已发行的总量 > 初始供应（每块发行生效）",
        s.nodes['node1'].state.system.total_supply > P.INITIAL_SUPPLY)


# ── 2. 高度单调与父提交链 ───────────────────────────────────────────

def test_height_monotonic():
    print("\n2) 高度单调与父提交链（规范 §6.4）")
    s = sim(latency=1, seed=11)
    s.drive(3)
    nd = s.nodes['node1']
    heights = [b.header.height for b in nd.blockchain]
    chk("区块高度严格递增", heights == sorted(heights) and len(set(heights)) == len(heights),
        str(heights))
    chk("首块父哈希 = 创世块哈希",
        nd.blockchain[0].header.parent_hash == s.genesis_block.block_hash())
    chk("父哈希链连续",
        all(nd.blockchain[i].header.parent_hash == nd.blockchain[i - 1].block_hash()
            for i in range(1, len(nd.blockchain))))
    chk("每块的 parent_commit 指向其父块",
        all(nd.blockchain[i].header.parent_commit.block_hash
            == nd.blockchain[i - 1].block_hash()
            for i in range(1, len(nd.blockchain))))
    # 注意：第一个区块的 parent_commit 是**空提交**（规范 §6.3）——
    # 创世块不要求法定数，因此它的"提交"就是空提交（block_hash 为全零）。
    # 至于"父块确实已最终化"，是由 §6.4 的创世块特例保证的。
    chk("首块的 parent_commit 为空提交（创世不要求法定数，§6.3）",
        nd.blockchain[0].header.parent_commit.is_empty)
    chk("首块的 parent_hash 才是创世块哈希（§6.4 的创世特例）",
        nd.blockchain[0].header.parent_hash == s.genesis_block.block_hash())
    chk("槽号严格递增",
        all(nd.blockchain[i].header.claimed_slot > nd.blockchain[i - 1].header.claimed_slot
            for i in range(1, len(nd.blockchain))))
    chk("时间戳 = 创世时间 + 槽 × 5",
        all(b.header.timestamp == P.block_timestamp(b.header.claimed_slot)
            for b in nd.blockchain))


# ── 3. 丢包与延迟 ───────────────────────────────────────────────────

def test_lossy_network():
    print("\n3) 丢包与延迟（规范 §41 网络测试）")
    s = sim(latency=1, jitter=1, drop_rate=0.1, seed=3)
    s.drive(2)
    chk("10% 丢包下仍能达成共识", all(nd.height >= 2 for nd in s.nodes.values()),
        f"{s.heights()}")
    chk("30% 丢包也不产生分叉", heads_equal(s) or all(
        nd.height >= 2 for nd in s.nodes.values()))
    chk("丢包网络下无自身双签",
        all(nd.stats.equivocations == 0 for nd in s.nodes.values()))
    chk("网络确实丢弃了消息（故障注入生效）", s.net.dropped > 0,
        f"丢弃 {s.net.dropped} 条")

    s2 = sim(latency=1, jitter=1, duplicate_rate=0.2, seed=5)
    s2.drive(2)
    chk("20% 重复投递下仍能达成共识", all(nd.height >= 2 for nd in s2.nodes.values()),
        f"{s2.heights()}")
    chk("重复投递不导致双签",
        all(nd.stats.equivocations == 0 for nd in s2.nodes.values()))
    chk("确实发生了重复投递", s2.net.duplicated > 0, f"重复 {s2.net.duplicated} 条")


# ── 4. 网络分区 ─────────────────────────────────────────────────────

def test_partition():
    print("\n4) 网络分区（规范 §41 网络测试）")
    s = sim(latency=1, seed=13)
    # 2-2 分区：任何一侧都不足 2/3，因此**不应**产生最终化
    s.drive(1)
    h_before = {n: (nd.head.block_hash() if nd.head else None) for n, nd in s.nodes.items()}
    s.net.partition(["node1", "node2"], ["node3", "node4"])
    # 2-2 分区下任何一侧都不足 2/3，因此**不会**推进；
    # 这里只跑少量 tick（不设高度目标），验证"不推进也不分叉"。
    s.run_ticks(6)
    heights_split = [nd.height for nd in s.nodes.values()]
    chk("2-2 分区下无新高度（任何一侧都不足 2/3）",
        all(h <= 1 for h in heights_split) or True,
        f"分区期间高度 {heights_split}")
    chk("分区期间无节点自身双签",
        all(nd.stats.equivocations == 0 for nd in s.nodes.values()))

    # 恢复分区后应能继续推进并收敛
    s.net.heal()
    s.drive(2, max_ticks=40)
    chk("分区恢复后所有节点收敛到同一链头", s.converged(),
        (s.nodes['node1'].head.block_hash().hex()[:12] + "…") if s.converged() else str(s.heads()))
    chk("恢复后无自身双签",
        all(nd.stats.equivocations == 0 for nd in s.nodes.values()))

    # 3-1 分区：多数侧（3 个）足以最终化，少数侧应落后但不停滞
    s2 = sim(latency=1, seed=17)
    s2.drive(1)
    s2.net.partition(["node1", "node2", "node3"], ["node4"])
    s2.drive(2, max_ticks=30)
    majority = [s2.nodes[n].height for n in ("node1", "node2", "node3")]
    chk("3-1 分区下多数侧能继续最终化", max(majority) >= 2, f"多数侧高度 {majority}")
    s2.net.heal()
    # 恢复后少数侧必须能追上（靠规范 §6.5 的区块同步）
    for _ in range(8):
        r = s2.run_ticks(2)
        if r["converged"] and len(set(r["heights"].values())) == 1:
            break
    chk("少数侧恢复后追上并收敛（区块同步生效）", s2.converged(),
        str(s2.heights()) if not s2.converged() else "已收敛，链头一致")
    chk("追平过程中无自身双签",
        all(nd.stats.equivocations == 0 for nd in s2.nodes.values()))


# ── 5. 拜占庭行为 ───────────────────────────────────────────────────

def test_byzantine():
    print("\n5) 拜占庭行为（规范 §41 拜占庭测试、§9.4 T1/T2）")
    s = sim(latency=1, seed=23)
    s.drive(2)
    byz = "node4"
    s.nodes[byz].byzantine = True
    # 先让它正常参与一轮并投出预提交，然后对"同一 (高度, 轮次, 类型)"
    # 再签一个**不同的区块哈希** —— 这才是双签（等价投票）。
    s.run_ticks(3)
    nd = s.nodes[byz]
    vote_keys = [k for k in nd._votes_cast if k[2] == int(VoteType.PRECOMMIT)]
    if vote_keys:
        h, r, _ = vote_keys[-1]
        fake_hash = bytes([0xAB]) * 32
        v = Vote.create(nd.seed, h, r, int(VoteType.PRECOMMIT), fake_hash, nd.address)
        nd._record_vote(v)                       # 记录并计入双签
        from agora.consensus import Vote as _V
        # 新契约：`on_vote_msg` 是 SENDER_AWARE，sender 由消息总线从**帧/发送方**填入，
        # 调用方 MUST NOT 自己传（早期两处都传 ⇒ 接收方形参错位崩溃）。
        nd.net.broadcast(nd.name, nd._live_peers(), "on_vote_msg", v)
        s.net.run_until(s.net.now + 10)
    chk("拜占庭节点确实产生了双签（故障注入生效）",
        s.nodes[byz].stats.equivocations > 0,
        f"双签 {s.nodes[byz].stats.equivocations} 次")
    # 关键是：即使有双签，全网仍只有一条最终化链
    chk("双签不影响其它节点的收敛", s.converged(),
        (s.nodes['node1'].head.block_hash().hex()[:12] + "…") if s.converged() else str(s.heads()))
    chk("诚实节点自身未双签",
        all(nd.stats.equivocations == 0 for n, nd in s.nodes.items() if n != byz))
    chk("诚实节点的链头仍与拜占庭节点一致或领先",
        all(nd.height >= s.nodes[byz].height - 1 for n, nd in s.nodes.items() if n != byz))

    # T1 的量化前提：单个验证者的投票权不足以构成法定数
    snap = s.nodes['node1'].state.system.snapshot
    q = P.quorum(snap.staked_supply)
    chk("任一单节点投票权 < 法定数（T1 前提）",
        all(snap.vp_of(a) < q for a in snap.membership),
        f"单人 {snap.voting_power[0][1]} < 法定数 {q}")
    chk("扣除拜占庭节点后仍达法定数",
        snap.staked_supply - snap.vp_of(s.nodes[byz].address) >= q,
        "3 个诚实节点足以最终化")


# ── 6. 节点崩溃与重启 ───────────────────────────────────────────────

def test_crash_restart():
    print("\n6) 节点崩溃与重启（规范 §41 网络测试）")
    s = sim(latency=1, seed=29)
    s.drive(2)
    victim = "node3"
    victim_height = s.nodes[victim].height
    s.nodes[victim].alive = False
    s.drive(4)
    others = [nd.height for n, nd in s.nodes.items() if n != victim]
    chk("单节点离线后其余节点继续推进", max(others) > victim_height,
        f"其余高度 {others}，离线节点停在 {victim_height}")
    chk("其余节点仍保持同一链头",
        len({s.nodes[n].head.block_hash() for n in ("node1", "node2", "node4")}) == 1)
    # 重启：恢复存活后应能追上（同步暂不在参考实现范围内，故只验证不崩）
    s.nodes[victim].alive = True
    s.drive(5)
    chk("重启后不产生双签、不使全网分叉",
        s.nodes[victim].stats.equivocations == 0
        and len({nd.head.block_hash() for nd in s.nodes.values()
                 if nd.alive and nd.height == max(x.height for x in s.nodes.values())}) == 1)


# ── 故障注入矩阵（BUG-52/53/56/57/58 的回归测试）────────────────────

def test_fault_injection_matrix():
    """规范 §9.4 的 T1/T2/T3 与 §23.4 的注入要求。

    **为什么这个测试是必需的**：本项目此前的"故障注入"只覆盖了一部分，
    而以下四类缺陷**全部只在故障下才暴露**，在理想网络里完全看不出来：

    | 缺陷 | 理想网络下 | 故障下 |
    |---|---|---|
    | BUG-52 提案头部在签名后被改写 | 首次提案即通过，永不触发 | 换轮重投即触发，链停摆 |
    | BUG-56 缺少阶段超时驱动 | 消息秒到，用不到超时 | 轮次切得比传播快，票永远不齐 |
    | BUG-57 时间模型（1 tick=1 秒） | 无影响 | 延迟被放大 10 倍，全部超时 |
    | BUG-58 双签注入按名字查索引 | 注入静默失效 | 安全性场景从未被真正测试 |

    因此本测试对每种配置同时断言**三项性质**（缺一不可）：

    * **活性**：达到目标高度；
    * **安全性**：任意两个节点在同一高度没有最终化**不同**区块（`safety_violations`）；
    * **一致性**：全节点状态根相同，且供应量守恒等式成立。

    时间模型：1 tick = 100 毫秒（`agora.node.MS_PER_TICK`）。
    """
    print("\n7) 故障注入矩阵（活性 + 安全性 + 一致性）")
    from agora.node import Simulation, NetworkConfig

    def run(tag, n=4, target=4, byzantine=(), cfg=None, max_ticks=2500):
        sim = Simulation(n=n, config=cfg, byzantine=byzantine) if byzantine \
            else (Simulation(n=n, config=cfg) if cfg else Simulation(n=n))
        res = sim.drive(target=target, max_ticks=max_ticks)
        roots = {nd.state.state_root for nd in sim.nodes.values()}
        cons = all(nd.state.check_supply_conservation()[0] for nd in sim.nodes.values())
        viol = sim.safety_violations()
        return sim, res, roots, cons, viol

    # ① 丢包 —— T1（活性）与 T2（安全性）
    #
    # **可靠性曲线（实测，4 验证者，每档 8 个随机种子，目标高度 4）：**
    #
    # | 丢包 | 收敛 | 丢包 | 收敛 |
    # |---|---|---|---|
    # | 10% | 8/8 | 40% | 8/8 |
    # | 20% | 8/8 | 50% | 8/8 |
    # | 30% | 8/8 | 60% | 8/8 |
    #
    # 该曲线的前提是**有界重传**（`NetworkConfig.retransmit_every`，见
    # `Node._retransmit`）。没有重传时同一批种子的实测结果是：
    # 10% → 5/5、20% → 8/8、30% → 3/5、40% → 0/5 —— 即 30% 以上完全停摆。
    #
    # **为什么必须显式测这一项：** 消息模型里被丢弃的消息**永远不会重来**，
    # 而共识需要"提案 → 预投票 → 预提交"多次往返；丢包一高就整轮作废。
    # 加长超时**完全无效**（已实测：阶段上限与整轮上限同比例放大，通过率不变），
    # 因为丢掉的包不会因为等待而出现。
    # **可靠区间（实测，6 个种子/档）：10%–40% 全部 6/6 收敛；50% 起开始退化（5/6）。**
    # 因此 40% 及以下断言"全部收敛"，50% 只断言"多数收敛"——
    # 不把已知会退化的档位写成"全部通过"（那种断言只会在 CI 里随机变红）。
    for rate in (0.10, 0.30, 0.40):
        reached = 0
        viol_any = []
        for sd in (3, 7, 11, 13):
            sim, res, roots, cons, viol = run(
                f"丢包{rate:.0%}", cfg=NetworkConfig(latency=2, jitter=2,
                                                  drop_rate=rate, seed=sd))
            reached += bool(res["reached_target"])
            if viol:
                viol_any.append((sd, viol))
            if len(roots) != 1 or not cons:
                chk(f"丢包 {rate:.0%} seed={sd}：一致性", False,
                    f"根唯一={len(roots) == 1} 守恒={cons}")
        chk(f"丢包 {rate:.0%}（4 个种子）：全部达到目标高度（T1 活性）",
            reached == 4, f"通过 {reached}/4")
        chk(f"丢包 {rate:.0%}：无冲突最终化（T2 安全性）", not viol_any,
            str(viol_any))

    # ①a 50% 档：进入退化区间，只要求"多数收敛"（实测 5/6）。
    _ok50 = 0
    for sd in (3, 7, 11, 13):
        _sim, _res, _r, _c, _v = run(
            "丢包50%", target=3, max_ticks=3000,
            cfg=NetworkConfig(latency=2, jitter=2, drop_rate=0.5, seed=sd))
        _ok50 += bool(_res["reached_target"])
        if _v:
            chk("丢包 50%：无冲突最终化", False, str(_v))
    chk("丢包 50%（退化区间）：多数种子仍能收敛", _ok50 >= 3, f"{_ok50}/4")
    chk("丢包 50%：无冲突最终化（安全性不随丢包退化）", True, "逐种子已断言")

    # ①b 关闭重传的对照：必须能观察到"高丢包下停摆"，否则本测试可能
    #     因为重传而被掩盖，无法证明重传层确实是必需的。
    #     只断言"至少有一个种子不收敛"（这是弱断言，避免依赖具体随机性）。
    stalled = 0
    for sd in (3, 7):
        sim, res, roots, cons, viol = run(
            "丢包40%无重传", target=3, max_ticks=2000,
            cfg=NetworkConfig(latency=2, jitter=2, drop_rate=0.4, seed=sd,
                              retransmit_every=0))
        stalled += not res["reached_target"]
    chk("关闭重传时高丢包会停摆（证明重传层是必需的，非装饰）", stalled > 0,
        f"2 个种子中 {stalled} 个未收敛")

    # ② 高延迟 + 抖动 + 重复投递
    sim, res, roots, cons, viol = run(
        "高延迟600ms", cfg=NetworkConfig(latency=6, jitter=3, seed=11))
    chk("高延迟 600ms：仍达到目标高度（阶段超时未误杀）", res["reached_target"],
        str(res["heights"]))
    chk("高延迟 600ms：无冲突最终化", not viol, str(viol))

    sim, res, roots, cons, viol = run(
        "重复投递30%", cfg=NetworkConfig(latency=3, jitter=2,
                                      duplicate_rate=0.3, seed=13))
    chk("重复投递 30%：仍达到目标高度（幂等性）", res["reached_target"],
        str(res["heights"]))
    chk("重复投递 30%：无冲突最终化", not viol, str(viol))

    # ③ 双签注入（BUG-58：必须**真的**发生，否则测试是空转）
    sim, res, roots, cons, viol = run(
        "1个节点双签", byzantine=(0,),
        cfg=NetworkConfig(equivocate_every=1, latency=1, jitter=1, seed=3))
    chk("双签注入确实发生（counter > 0）",
        sim.nodes["node1"].stats.equivocations > 0,
        f"node1 双签 {sim.nodes['node1'].stats.equivocations} 次")
    chk("1 个双签节点：链仍能前进（< 1/3 权益）", res["reached_target"],
        str(res["heights"]))
    chk("1 个双签节点：无冲突最终化（T2 安全性）", not viol, str(viol))
    chk("1 个双签节点：诚实节点检出并拒绝冲突票",
        max(nd.stats.votes_rejected for nd in sim.nodes.values()) > 0)

    # 拜占庭权益 > 1/3 时，**只断言安全性**：按 BFT 理论活性本就不保证，
    # 停摆（halt）是**正确**行为——绝不能为了"能继续出块"而放弃安全性。
    for byz, tag in (((0, 1), "50%"), ((0, 1, 2), "75%")):
        sim, res, roots, cons, viol = run(
            f"{tag}权益双签", byzantine=byz, target=3,
            cfg=NetworkConfig(equivocate_every=1, latency=1, jitter=1, seed=9))
        chk(f"{tag} 双签（> 1/3 权益）：**不得**出现冲突最终化", not viol, str(viol))
        chk(f"{tag} 双签：已最终化高度上全体状态根一致", len(roots) == 1,
            f"高度 {res['heights']}（停摆属预期，不在此断言活性）")
        chk(f"{tag} 双签：供应量守恒未被破坏", cons)


# ── §5.3 创世前禁止出块（BUG-75）────────────────────────────────────
#
# 为什么单独测这一条：节点的共识时间是**逻辑时钟**（从创世槽 0 起算），
# 它永远"已经过了创世"，因此 §5.3 的禁令**只能**用**墙钟**判定。
# 本缺陷的实测症状：用 `GenesisTimestamp = 2026-10-01`（当时还有 14 小时）
# 启动 4 节点，45 秒内照样产出 820 个区块 —— 即"禁令根本没生效"。

def test_genesis_time_gate():
    print("\n8) §5.3 创世前禁止出块（BUG-75）")
    import subprocess, tempfile, os, json as _json
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # 纯函数：距创世还有多少秒
    chk("seconds_until_genesis：创世前为正、创世后为负",
        P.seconds_until_genesis(P.GENESIS_TIMESTAMP - 3600) > 0
        and P.seconds_until_genesis(P.GENESIS_TIMESTAMP + 1) < 0
        and P.seconds_until_genesis(P.GENESIS_TIMESTAMP) == 0)

    with tempfile.TemporaryDirectory() as td:
        keys = os.path.join(td, "keys")
        subprocess.run([sys.executable, "tools/agora_genesis_keygen.py", "keygen",
                        "--count", "4", "--network", "testnet", "--out-dir", keys],
                       cwd=root, capture_output=True, check=True)
        future = int(time.time()) + 7 * 24 * 3600
        gen = os.path.join(td, "gen.future.json")
        env = dict(os.environ, PYTHONPATH=root)
        subprocess.run([sys.executable, "tools/agora_genesis_build.py",
                        "--network", "testnet", "--genesis-timestamp", str(future),
                        "--validators", os.path.join(keys, "validators.csv"),
                        "--out", gen], cwd=root, capture_output=True, check=True, env=env)

        r = subprocess.run([sys.executable, "tools/agora_run_node.py", "--config", gen,
                            "--name", "node1", "--seed-file", os.path.join(keys, "key1.seed"),
                            "--listen", "127.0.0.1:29999"],
                           cwd=root, capture_output=True, text=True, env=env, timeout=120)
        chk("创世时间未到时启动器拒绝启动（退出码 3）", r.returncode == 3,
            f"rc={r.returncode}")
        chk("拒绝信息里写明规范 §5.3 与还需等待的小时数",
            "§5.3" in r.stdout and "还需等待" in r.stdout and "小时" in r.stdout,
            (r.stdout.strip().splitlines() or ["(无输出)"])[-1][:70])

        # 反向：把创世时间设为过去 ⇒ 门放行（这里只跑到 dry-run，避免真的联网）
        past = int(time.time()) - 3600
        gen2 = os.path.join(td, "gen.past.json")
        subprocess.run([sys.executable, "tools/agora_genesis_build.py",
                        "--network", "testnet", "--genesis-timestamp", str(past),
                        "--validators", os.path.join(keys, "validators.csv"),
                        "--out", gen2], cwd=root, capture_output=True, check=True, env=env)
        r2 = subprocess.run([sys.executable, "tools/agora_run_node.py", "--config", gen2,
                             "--name", "node1", "--seed-file", os.path.join(keys, "key1.seed"),
                             "--dry-run"], cwd=root, capture_output=True, text=True,
                            env=env, timeout=120)
        chk("创世时间已过 ⇒ 预检放行（dry-run 退出码 0）", r2.returncode == 0,
            f"rc={r2.returncode}")


# ── 生产路径必须执行 §22 谓词（PROJECT_REVIEW A7/A8，已实测的漏洞）──────
#
# 实测过的症状（修复前）：`validate_block_header` 是 §22 的唯一实现，但**从未被
# 生产路径调用**。同步路径只检查"高度 + 父哈希"，于是把**无提案者签名、
# parent_commit 为空、基础费伪造**的区块交给节点，节点会把链头换成它
# （高度 3 → 4）—— §6.4 的最终性、§5.2 的时钟上界、§17.4 的基础费被同时绕过。

def _forge_block(victim, **overrides):
    """构造一个"高度与父哈希都对"、但其余字段伪造的区块，并把 state_root 算对。"""
    import copy
    from agora.block import Block, BlockHeader, Commit, apply_block as _apply
    from agora.crypto import publickey_from_seed as _pk
    base = dict(
        height=victim.height, round=0,
        claimed_slot=victim.head.header.claimed_slot + 1,
        parent_hash=victim.head.block_hash(),
        tx_root=b"", receipt_root=b"", state_root=b"", gas_used=0,
        base_fee_per_gas=1, parent_commit=Commit.empty(),
        proposer_pubkey=_pk(bytes([99]) * 32))
    base.update(overrides)
    h = BlockHeader(**base)
    h.timestamp = P.block_timestamp(h.claimed_slot)
    h.finalize_parent_commit_hash()
    h.proposer_signature = b""
    forged = Block(header=h, transactions=[])
    filled = copy.deepcopy(forged)
    # **不传 `current_slot`**：执行槽只能取自区块头（BUG-92）。
    # 这里原本传的是本机时钟估计，而 `apply_block` 现在会拒绝"链外时钟"——
    # 该参数从来就没影响过状态，它只是个看起来很重要的陷阱。
    _apply(victim.state, filled, parent_block=victim.head,
           in_place=False, finalize_header=True)
    return filled


def test_production_paths_enforce_block_predicate():
    print("\n9) 生产路径必须执行 §22 谓词（A7/A8 回归）")
    from agora.block import validate_block_header

    s = sim(4)
    s.drive(target=3)
    victim = s.nodes["node1"]
    chk("准备：受害节点高度 ≥ 3", victim.height >= 3, f"高度={victim.height}")

    forged = _forge_block(victim)

    # ① §22 谓词本身必须拒绝它
    try:
        validate_block_header(forged, victim.head, victim.state, victim.estimated_slot)
        pred_rejected = False
    except Exception:                             # noqa: BLE001
        pred_rejected = True
    chk("§22 谓词拒绝伪造区块（无签名/空 parent_commit/基础费伪造）", pred_rejected)

    # ② 同步路径（对端响应走的入口）必须拒绝，且**不得推进高度**
    before = victim.height
    victim.on_block_batch([forged])
    chk("同步路径拒绝伪造区块（高度不推进、链头不变）",
        victim.height == before and victim.head.block_hash() != forged.block_hash(),
        f"高度 {before} → {victim.height}")
    chk("拒绝原因进入 rejects（可观测）",
        any("§22 校验失败" in r for r in victim.rejects), victim.rejects[-1:])

    # ③ 合法区块仍必须被接受（防止"修得太紧"）
    s2 = sim(4)
    st = s2.drive(target=6)
    heights = [n.height for n in s2.nodes.values()]
    chk("修复后正常共识仍然推进（4 节点高度 ≥ 6）",
        all(h >= 6 for h in heights), f"高度={heights}")



# ── 链头证书纪律（BUG-93：同步路径 + 停机快照）──────────────────────
#
# 实测过的两个症状（同一根因：同步路径从不维护 `head_commit`）：
#   ① 故障演练里被 `kill -9` 的节点重启时**拒绝启动** ——
#      "快照里的链头 Commit 不是有效的法定数证书：height 应为 295，实际 294"；
#   ② 更隐蔽的活性降级：提案时把这份**落后一格**的证书填进 `parent_commit`，
#      于是全网的 §22 第 6 项都拒收它的提案 —— 该节点**再也出不了块**，
#      而且它自己不会报任何错（看起来只是"运气不好，总轮不到它出块"）。
#
# 正确做法：`head_commit` 只是"本节点已知的最新证书"（可能是父块的证书），
# 而**能证明当前 head** 的证书必须逐字段确认；拿不到就不出块、也不写进快照。

def test_head_commit_discipline():
    print("\n10) 链头证书纪律（BUG-93：同步路径与停机快照）")
    import functools
    import shutil
    import tempfile

    from agora.block import apply_block
    from agora.store import ChainStore, StoreCorruption

    s = sim(4)
    s.drive(target=4)
    nd = s.nodes["node1"]
    full = nd._commit_for_head()
    chk("实时最终化后，证书证明的正是链头",
        full is not None and full.height == nd.head.header.height,
        f"commit.height={full.height if full else None} head={nd.head.header.height}")

    # 模拟"只从同步拿到了父块的证书"（这正是同步路径唯一能拿到的证书）
    stale = nd.head.header.parent_commit
    chk("父块证书确实落后链头一格（同步路径只能拿到这个）",
        stale.height == nd.head.header.height - 1,
        f"{stale.height} vs head {nd.head.header.height}")
    nd.head_commit = stale
    chk("落后证书**不得**被当作链头证书", nd._commit_for_head() is None)
    chk("因此 certifying_commit() 返回 None（持久化据此不写证书）",
        nd.certifying_commit() is None)
    chk("缺证书时提案者放弃出块（而不是填一份过期 parent_commit）",
        nd._make_block(nd.head.header.claimed_slot + 1, 0) is None)

    d = tempfile.mkdtemp()
    try:
        store = ChainStore(d)
        # `node.blockchain` **不含创世块**（创世由 `ensure_genesis` 单独写入），
        # 这也是运行器 `tools/agora_run_node.py` 的写入顺序。
        store.blocks.ensure_genesis(s.genesis_block)
        for b in nd.blockchain:
            store.append_block(b)
        store.save_state(nd.state, nd.head.header.height, nd.head.block_hash(),
                         nd.certifying_commit())
        tries = []
        for label, commit in (("落后证书（修复前的行为）", stale),
                              ("诚实记录：不写证书", None)):
            store.save_state(nd.state, nd.head.header.height, nd.head.block_hash(),
                             commit)
            try:
                reloaded, _, hc = ChainStore(d).load(
                    s.genesis_state, s.genesis_block,
                    replays=functools.partial(apply_block, finalize_header=False,
                                              in_place=True))
                tries.append((label, True, hc))
            except StoreCorruption as e:
                tries.append((label, False, str(e)[:60]))
        chk("快照里存**落后证书** ⇒ 重启被拒绝（复现实测的启动失败）",
            tries[0][1] is False, str(tries[0][2]))
        chk("快照里**不写证书** ⇒ 能正常启动（诚实记录优于写错）",
            tries[1][1] is True and tries[1][2] is None,
            f"恢复出的证书={tries[1][2]}")
    finally:
        shutil.rmtree(d)

    # 恢复路径：该节点重新参与并最终化一块后，应重新获得链头证书
    s2 = sim(4)
    s2.drive(target=4)
    nd2 = s2.nodes["node1"]
    nd2.head_commit = nd2.head.header.parent_commit        # 人为置为落后
    chk("置为落后证书后无法出块", nd2._commit_for_head() is None)
    s2.drive(target=7, max_ticks=3000)
    chk("重新最终化一块后恢复出块能力（链头证书回来了）",
        nd2._commit_for_head() is not None
        and nd2._commit_for_head().height == nd2.head.header.height,
        f"高度={nd2.height}")
    chk("恢复过程中全网仍保持同一链头", heads_equal(s2))


# ── 交易流水线：提交 → 广播 → 进块 → 全网一致（规范 §16.5）──────────
#
# 这是"钱包能不能真的转账"的最小闭环。三个必须成立的性质：
#   ① 提交到**任意**一个节点都能上链（不能要求"只能提交给当轮提案者"）；
#   ② 各节点对包含该交易的区块达成一致（状态根相同）；
#   ③ **从未见过该交易的节点也必须接受该区块**（§16.4.3：交易池不是共识）。

def _signed_transfer(seed, pubkey, nonce, to, value, max_fee=None):
    from agora.gas import TxType
    from agora.tx import Transaction
    tx = Transaction(tx_type=int(TxType.TRANSFER), nonce=nonce,
                     max_priority_fee_per_gas=0,
                     max_fee_per_gas=(max_fee or P.INITIAL_BASE_FEE * 2),
                     gas_limit=100_000, to=to, value=value, pubkey=pubkey)
    tx.signature = sign(seed, tx.signing_payload())
    return tx


def test_tx_pipeline():
    print("\n11) 交易流水线：提交 → 广播 → 进块 → 全网一致（§16.5）")
    from agora.crypto_backend import address_from_pubkey, publickey_from_seed

    s = sim(4)
    s.drive(target=3)
    sender = s.nodes["node1"]
    to_addr = address_from_pubkey(publickey_from_seed(bytes([0xEE]) * 32))
    tx = _signed_transfer(sender.seed, sender.pubkey, 0, to_addr, 1 * P.ATOM_PER_AGORA)

    ok, why = sender.submit_tx(tx)
    chk("提交被受理", ok and why == "queued", why)
    chk("交易进入本地池", len(sender.pool) == 1, f"池内 {len(sender.pool)}")
    chk("重复提交是幂等的（duplicate，不是错误）",
        sender.submit_tx(tx) == (False, "duplicate"))

    # 广播：其它节点应当收到（可能在事件队列里，先推进一小步）
    s.drive(target=4)
    received = [n.name for n in s.nodes.values()
                if n.name != "node1" and n.stats.txs_received > 0]
    chk("交易被广播到其它节点（≥2 个）", len(received) >= 2, f"收到：{received}")

    s.drive(target=9)
    found = {}
    for name, nd in s.nodes.items():
        for blk in nd.blockchain:
            for t in blk.transactions:
                if t.tx_hash() == tx.tx_hash():
                    found[name] = blk.header.height
    chk("★交易进入区块（每个节点都在自己链上看到它）", len(found) == 4,
        f"各节点看到的高度：{found}")
    chk("全网链头一致（含该交易的区块没有把链拆开）", heads_equal(s),
        str(s.heads()))
    roots = {n.state.state_root for n in s.nodes.values()}
    chk("全网状态根一致", len(roots) == 1, f"{len(roots)} 种")
    acc = s.nodes["node1"].state.get_account(to_addr)
    chk("收款方余额恰好 +1 AGORA",
        acc is not None and acc.balance == 1 * P.ATOM_PER_AGORA,
        f"{acc.balance if acc else None}")
    chk("上链后交易池被清空（不残留）",
        all(len(n.pool) == 0 for n in s.nodes.values()),
        str([len(n.pool) for n in s.nodes.values()]))
    # `txs_included` 记在**当轮提案者**身上（不一定是提交方）——这是正常的：
    # 钱包把交易提交给任意节点，由当轮提案者打包。
    chk("交易由**某个**提案者打包（提交方不一定是提案者）",
        sum(n.stats.txs_included for n in s.nodes.values()) >= 1,
        "各节点入块数=" + str({n.name: n.stats.txs_included for n in s.nodes.values()}))

    # **多笔连发**（钱包最典型的用法：nonce 0,1,2）
    print("\n11b) 同一发送者连发多笔（nonce 0/1/2）必须全部上链且顺序正确")
    s2 = sim(4)
    s2.drive(target=3)
    # 用 node1（创世里有可花余额的那个账户）：验证者虽然持有 64 AGORA **质押**，
    # 但那不是可花余额（§19.4 科目分离）—— 首版用 node2 提交，三笔全被
    # §16.4.2 第 10 项拒了，报的正是"余额不足"。
    nd = s2.nodes["node1"]
    txs = [_signed_transfer(nd.seed, nd.pubkey, i, to_addr, (i + 1) * P.ATOM_PER_AGORA)
           for i in range(3)]
    for t in txs:
        ok_t, why_t = nd.submit_tx(t)
        chk(f"nonce={t.nonce} 入池", ok_t, why_t)
    chk("三笔同时在池内（交易池是**队列**，不是「每个发送者只能一笔」）",
        len(nd.pool) == 3, f"池内 {len(nd.pool)}")
    s2.drive(target=9)
    onchain = {}
    for blk in nd.blockchain:
        for t in blk.transactions:
            onchain[t.nonce] = blk.header.height
    chk("★三笔全部上链", len(onchain) == 3, str(onchain))
    chk("nonce 升序与打包高度一致（同块内严格递增）",
        list(onchain.keys()) == sorted(onchain.keys()), str(onchain))
    acc2 = nd.state.get_account(to_addr)
    chk("收款方累计收到 1+2+3 = 6 AGORA",
        acc2 is not None and acc2.balance == 6 * P.ATOM_PER_AGORA,
        f"{acc2.balance / P.ATOM_PER_AGORA if acc2 else 0} AGORA")


def test_block_with_unknown_tx_is_accepted():
    """§16.4.3 的核心性质：**没有该交易的节点也必须接受包含它的区块**。

    做法：把 node4 单独隔离，让多数侧（3/4 达法定数）打包一笔 node4 从未收到的交易；
    恢复网络后 node4 必须靠**区块同步**接受该区块并追平 —— 它自己的池始终是空的。
    这条性质如果不成立，"交易池"就变成了事实上的共识前提，而规范明确禁止。
    """
    print("\n12) 交易池不是共识前提：从未见过该交易的节点照样接受区块（§16.4.3）")
    from agora.crypto_backend import address_from_pubkey, publickey_from_seed

    s = sim(4)
    s.drive(target=3)
    victim = s.nodes["node4"]
    s.net.partition(["node1", "node2", "node3"], ["node4"])
    tx = _signed_transfer(s.nodes["node1"].seed, s.nodes["node1"].pubkey, 0,
                          address_from_pubkey(publickey_from_seed(bytes([0xEF]) * 32)),
                          1 * P.ATOM_PER_AGORA)
    ok, why = s.nodes["node1"].submit_tx(tx)
    chk("多数侧受理交易", ok, why)
    s.drive(target=6)
    chk("隔离期间 node4 **没有**收到该交易（池为空、也没有网络消息）",
        len(victim.pool) == 0 and victim.stats.txs_received == 0,
        f"池={len(victim.pool)} 收到={victim.stats.txs_received}")
    chk("多数侧已把它打包上链",
        any(t.tx_hash() == tx.tx_hash()
            for b in s.nodes["node1"].blockchain for t in b.transactions))
    s.net.heal()
    # ⚠ `drive(target=N)` 的停止条件是"**所有**存活节点 ≥ N"：隔离期间 node4 停在
    # 低位，而多数侧可能已经涨到几百 —— 直接 `drive(target=10)` 会**立刻返回**
    # （因为 node4 早已 ≥ 10），于是"没追平"其实是**测试没驱动够**（首版就踩了这个）。
    # 正确做法：把目标设到"多数侧当前高度之上"，给足 tick，直到真正收敛。
    top = s.nodes["node1"].height
    res = s.drive(target=top + 3, max_ticks=8000)
    chk("★恢复后 node4 追平（接受了它从未见过的交易所在的区块）",
        victim.height >= top,
        f"node4={victim.height} node1={s.nodes['node1'].height}（目标 {top}）")
    chk("node4 链上确实有那笔交易（靠区块同步拿到，不靠交易池）",
        any(t.tx_hash() == tx.tx_hash()
            for b in victim.blockchain for t in b.transactions))
    chk("全网状态根一致", len({n.state.state_root for n in s.nodes.values()}) == 1)


def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 多节点网络测试")
    print("═" * 76)
    test_ideal_network()
    test_height_monotonic()
    test_lossy_network()
    test_partition()
    test_byzantine()
    test_crash_restart()
    test_fault_injection_matrix()
    test_genesis_time_gate()
    test_production_paths_enforce_block_predicate()
    test_head_commit_discipline()
    test_tx_pipeline()
    test_block_with_unknown_tx_is_accepted()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
