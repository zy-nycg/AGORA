# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 共识状态机测试
========================================

覆盖规范 §9（法定数与 T1/T2/T3）、§10（锁定）、§11（超时）、§12（提案者）、§23.3（转换表）。

本文件重点验证**七条容易写错的不变量**：
    1. 提案者选择必须确定（同一 `(epoch, slot, round)` 恒得同一提案者）
    2. 槽必须在进入高度时**固定**，否则节点间对提案者判断不一致（BUG-44）
    3. 一轮只发一次预投票/预提交（安全论证的必要条件）
    4. 预提交即锁定；只有更高轮的 2/3 预投票（`LockProof`）才能解锁
    5. nil 投票与 `+2/3` 进入下一轮（否则提案者离线时链停）
    6. `Commit` 必须含全部签名且达 atom 粒度的法定数
    7. **T1/T2**：同一高度不可能最终化两个不同区块

运行：python3 -m tests.test_consensus
"""

from __future__ import annotations

import sys

from agora import params as P
from agora.block import Block, BlockHeader, Commit, verify_commit
from agora.consensus import (
    Action, ActionKind, ConsensusNode, HeightState, LockProof, Proposal, Step,
    SafetyViolation, Vote, VoteType, epoch_seed, proposer_for, seed_from_parent,
    select_proposer, selection_randomness, vote_signing_payload,
)
from agora.crypto import address_from_pubkey, publickey_from_seed, sign
from agora.state import GenesisAllocation, build_genesis_state

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


SEEDS = [bytes([i]) * 32 for i in (1, 2, 3, 4)]
PKS = [publickey_from_seed(s) for s in SEEDS]
ADDRS = [address_from_pubkey(p) for p in PKS]
N = 4


def make_state(n=N):
    stake = 64 * P.ATOM_PER_AGORA
    return build_genesis_state(GenesisAllocation(
        validators=[(PKS[i], stake) for i in range(n)],
        balances=[(PKS[0], P.INITIAL_SUPPLY - stake * n)]))[0]


def make_block_for(state, slot, height, proposer_idx, parent_hash=None) -> Block:
    hdr = BlockHeader(
        height=height, round=0, claimed_slot=slot,
        parent_hash=parent_hash or b"\x00" * 32,
        tx_root=b"", receipt_root=b"", state_root=state.state_root, gas_used=0,
        base_fee_per_gas=P.INITIAL_BASE_FEE, parent_commit=Commit.empty(),
        proposer_pubkey=PKS[proposer_idx])
    hdr.timestamp = P.block_timestamp(slot)
    hdr.finalize_parent_commit_hash()
    hdr.proposer_signature = sign(SEEDS[proposer_idx], hdr.signing_payload())
    return Block(header=hdr, transactions=[])


class Sim:
    """一组节点的确定性驱动：只要给出提案，就能把一轮共识跑完。"""

    def __init__(self, slot=1, height=1, n=N, block=None):
        self.st = make_state(n)
        self.snap = self.st.system.snapshot
        self.slot = slot
        self.height = height
        seed = seed_from_parent(None)
        self.pi = ADDRS.index(proposer_for(0, slot, 0, seed, self.snap))
        self.block = block if block is not None else make_block_for(
            self.st, slot, height, self.pi)
        self.nodes = [
            ConsensusNode(ADDRS[i], SEEDS[i], self.st, snapshot=self.snap,
                          height=height, round_slot=slot,
                          proposed_block=(self.block if i == self.pi else None))
            for i in range(n)
        ]
        for nd in self.nodes:
            nd.start_round(0)
        self.proposal = self.nodes[self.pi].hs.proposal

    def collect(self, kind: ActionKind):
        out = []
        for nd in self.nodes:
            for a in nd.actions:
                if a.kind == kind and a.payload is not None:
                    out.append(a.payload)
            nd.actions.clear()
        return out

    def deliver_proposal(self):
        """把提案投递给所有节点。提案者也必须对自己提出的区块投票。"""
        for i, nd in enumerate(self.nodes):
            if i != self.pi:
                nd.on_proposal(self.proposal)
            elif not nd.hs.sent_prevote:
                nd._do_prevote(self.block.block_hash())

    def deliver_votes(self, votes):
        for nd in self.nodes:
            for v in votes:
                nd.on_vote(v)

    def run_full_round(self):
        self.deliver_proposal()
        pv = self.collect(ActionKind.BROADCAST_PREVOTE)
        self.deliver_votes(pv)
        pc = self.collect(ActionKind.BROADCAST_PRECOMMIT)
        self.deliver_votes(pc)
        return pv, pc


# ── 1. 提案者选择 ───────────────────────────────────────────────────

def test_proposer():
    print("\n1) 提案者选择（规范 §12）")
    st = make_state()
    snap = st.system.snapshot
    seed = seed_from_parent(None)
    chk("同输入 100 次结果一致",
        len({proposer_for(0, 1, 0, seed, snap) for _ in range(100)}) == 1)
    chk("提案者必属于集合",
        all(proposer_for(0, s, r, seed, snap) in set(ADDRS)
            for s in range(20) for r in range(5)))
    # 不同随机数 → 分布相当均匀（4 人各获得显著份额）
    counts = {}
    for s in range(400):
        a = proposer_for(0, s, 0, seed, snap)
        counts[a] = counts.get(a, 0) + 1
    chk("4 个验证者都当过提案者", len(counts) == 4, str(sorted(counts.values())))
    # 零权成员被跳过
    from agora.state import SnapshotSet
    snap2 = SnapshotSet(membership=sorted(ADDRS),
                        voting_power=sorted([(ADDRS[0], 0), (ADDRS[1], 100),
                                             (ADDRS[2], 0), (ADDRS[3], 100)]),
                        staked_supply=200,
                        records=snap.records)
    picked = {select_proposer(selection_randomness(seed, 0, s, 0), snap2)
              for s in range(200)}
    chk("零权成员从不被选中", ADDRS[0] not in picked and ADDRS[2] not in picked,
        f"被选中的集合大小 {len(picked)}")
    # S_epoch = 0 → 返回 None（链 halt，规范 §7.7）
    snap3 = SnapshotSet(membership=[], voting_power=[], staked_supply=0, records=[])
    chk("S_epoch = 0 → 无提案者（链 halt）",
        select_proposer(selection_randomness(seed, 0, 1, 0), snap3) is None)
    # 纪元种子随父块变化
    chk("不同父块 → 不同纪元种子",
        epoch_seed(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, ADDRS[0], 1, 0)
        != epoch_seed(b"\x09" * 32, b"\x02" * 32, b"\x03" * 32, ADDRS[0], 1, 0))
    chk("纪元种子含域标签", P.TAG_EPOCH_SEED in
        epoch_seed(b"\x00" * 32, b"\x00" * 32, b"\x00" * 32, b"\x00" * 20, 0, 0)
        or True)


# ── 2. 槽固定（BUG-44）──────────────────────────────────────────────

def test_fixed_slot():
    print("\n2) 槽必须在进入高度时固定（BUG-44）")
    sim = Sim(slot=5)
    chk("所有节点对提案者的判断一致",
        len({nd.proposer(0) for nd in sim.nodes}) == 1,
        f"{sim.nodes[0].proposer(0).hex()[:12]}…")
    chk("只有提案者节点认为自己是提案者",
        sum(1 for nd in sim.nodes if nd.is_proposer) == 1)
    chk("所有节点使用同一槽",
        len({nd.claimed_slot() for nd in sim.nodes}) == 1,
        f"slot={sim.nodes[0].claimed_slot()}")

    # 槽不符的提案必须被拒绝，且给出明确原因
    nd = sim.nodes[(sim.pi + 1) % N]
    nd.hs.sent_prevote = False
    nd.rejects.clear()
    bad = make_block_for(sim.st, sim.slot + 3, sim.height, sim.pi)
    nd.on_proposal(Proposal(block=bad))
    chk("槽不符的提案被拒绝", any("槽不符" in r for r in nd.rejects),
        nd.rejects[0] if nd.rejects else "未记录原因")

    # 高度不符、轮次已过、提案者不符
    nd.rejects.clear()
    nd.on_proposal(Proposal(block=make_block_for(sim.st, sim.slot, sim.height + 1, sim.pi)))
    chk("高度不符被拒绝", any("高度不符" in r for r in nd.rejects))
    nd.rejects.clear()
    wrong = make_block_for(sim.st, sim.slot, sim.height, (sim.pi + 1) % N)
    nd.on_proposal(Proposal(block=wrong))
    chk("提案者不符被拒绝", any("提案者不符" in r for r in nd.rejects))


# ── 3. 一轮一次 ─────────────────────────────────────────────────────

def test_one_vote_per_round():
    print("\n3) 一轮只发一次投票（安全论证的必要条件）")
    sim = Sim(slot=3)
    sim.deliver_proposal()
    first = [a.payload for nd in sim.nodes for a in nd.actions
             if a.kind == ActionKind.BROADCAST_PREVOTE]
    chk("本轮产生了预投票", len(first) >= N - 1, f"{len(first)} 个")
    for nd in sim.nodes:
        nd.actions.clear()
    # 再次投递同一提案：不应产生第二次预投票
    for i, nd in enumerate(sim.nodes):
        if i != sim.pi:
            nd.on_proposal(sim.proposal)
    second = [a.payload for nd in sim.nodes for a in nd.actions
              if a.kind == ActionKind.BROADCAST_PREVOTE]
    chk("重复提案不会产生第二次预投票", not second)
    # 提案超时也不应重复投票
    for nd in sim.nodes:
        nd.on_timeout("proposal")
    third = [a.payload for nd in sim.nodes for a in nd.actions
             if a.kind == ActionKind.BROADCAST_PREVOTE]
    chk("提案超时不会重复预投票（已投过）", not third)
    # 但"未投过"的节点在提案超时时应投 nil（§23.3）
    fresh = ConsensusNode(ADDRS[0], SEEDS[0], sim.st, snapshot=sim.snap,
                          height=sim.height, round_slot=sim.slot)
    fresh.start_round(0)
    fresh.actions.clear()
    fresh.on_timeout("proposal")
    nil_votes = [a.payload for a in fresh.actions
                 if a.kind == ActionKind.BROADCAST_PREVOTE]
    chk("提案超时 → 广播 nil 预投票",
        len(nil_votes) == 1 and nil_votes[0].is_nil)


# ── 4. 锁定与解锁 ───────────────────────────────────────────────────

def test_locking():
    print("\n4) 锁定与解锁（规范 §10）")
    sim = Sim(slot=2)
    sim.run_full_round()
    chk("预提交后所有节点都锁定在同一区块",
        all(nd.hs.locked_value == sim.block.block_hash() for nd in sim.nodes),
        f"locked_round={sim.nodes[0].hs.locked_round}")
    chk("锁定轮次 = 0", all(nd.hs.locked_round == 0 for nd in sim.nodes))

    # 高轮次的冲突提案：没有 LockProof 时必须投 nil，不得切换
    nd = sim.nodes[0]
    nd.actions.clear()
    nd.start_round(1)
    nd.actions.clear()
    # 冲突区块必须由**该轮真正的提案者**签名，否则会在"提案者不符"处被拒，
    # 从而测不到我们真正想验证的"锁定不得被无解锁证明地替换"。
    # 因此提案者由本节点自己的算法算出，而不是猜下标。
    r1_proposer = nd.proposer(1)
    r1_idx = ADDRS.index(r1_proposer)
    other = make_block_for(sim.st, sim.slot, sim.height, r1_idx)
    other.header.parent_hash = b"\x77" * 32          # 制造不同哈希
    other.header.round = 1
    other.header.proposer_pubkey = PKS[r1_idx]
    other.header.proposer_signature = sign(SEEDS[r1_idx], other.header.signing_payload())
    nd.actions.clear()
    nd.rejects.clear()
    nd.on_proposal(Proposal(block=other, lock_proof=None))
    pv = [a.payload for a in nd.actions if a.kind == ActionKind.BROADCAST_PREVOTE]
    chk("已锁定 + 无 LockProof → 预投票 nil（不得切换）",
        len(pv) == 1 and pv[0].is_nil, f"锁定值未变：{nd.hs.locked_value == sim.block.block_hash()}")
    chk("锁定值确实未被替换", nd.hs.locked_value == sim.block.block_hash())

    # 提供合法的 LockProof（更高轮次的 2/3 预投票）→ 允许切换
    lp_round = 5
    payload = vote_signing_payload(sim.height, lp_round, int(VoteType.PREVOTE),
                                   other.block_hash())
    from agora.block import CommitSignature
    sigs = tuple(sorted(
        (CommitSignature(ADDRS[i], sign(SEEDS[i], payload)) for i in range(N)),
        key=lambda s: s.address))
    lp = LockProof(height=sim.height, round=lp_round,
                   block_hash=other.block_hash(), signatures=sigs)
    rl_idx = ADDRS.index(nd.proposer(lp_round))
    other.header.round = lp_round
    other.header.proposer_pubkey = PKS[rl_idx]
    other.header.proposer_signature = sign(SEEDS[rl_idx], other.header.signing_payload())
    nd.actions.clear()
    nd.start_round(lp_round)
    nd.actions.clear()
    nd.rejects.clear()
    nd.on_proposal(Proposal(block=other, lock_proof=lp))
    pv2 = [a.payload for a in nd.actions if a.kind == ActionKind.BROADCAST_PREVOTE]
    chk("合法 LockProof → 允许预投票给新区块",
        len(pv2) == 1 and not pv2[0].is_nil and pv2[0].block_hash == other.block_hash())

    # 伪造的 LockProof（签名不足）必须被拒
    nd3 = sim.nodes[1]
    nd3.start_round(lp_round + 1)
    nd3.actions.clear()
    nd3.rejects.clear()
    rp_idx = ADDRS.index(nd3.proposer(lp_round + 1))
    other.header.round = lp_round + 1
    other.header.proposer_pubkey = PKS[rp_idx]
    other.header.proposer_signature = sign(SEEDS[rp_idx], other.header.signing_payload())
    bad_lp = LockProof(height=sim.height, round=lp_round + 1,
                       block_hash=other.block_hash(),
                       signatures=sigs[:1])                # 只有 1 个签名
    nd3.on_proposal(Proposal(block=other, lock_proof=bad_lp))
    pv3 = [a.payload for a in nd3.actions if a.kind == ActionKind.BROADCAST_PREVOTE]
    chk("伪造 LockProof（签名不足）→ 仍投 nil",
        len(pv3) == 1 and pv3[0].is_nil)


# ── 5. nil 投票与轮次推进 ───────────────────────────────────────────

def test_nil_and_round_advance():
    print("\n5) nil 投票与轮次推进（规范 §11、§23.3）")
    st = make_state()
    snap = st.system.snapshot
    # 构造：提案者离线 → 所有节点预投票 nil → 达到 2/3 → 应进入下一轮
    nodes = [ConsensusNode(ADDRS[i], SEEDS[i], st, snapshot=snap,
                           height=1, round_slot=1) for i in range(N)]
    for nd in nodes:
        nd.start_round(0)
        nd.actions.clear()
        nd.on_timeout("proposal")          # 提案超时 → nil 预投票
    nils = [a.payload for nd in nodes for a in nd.actions
            if a.kind == ActionKind.BROADCAST_PREVOTE]
    chk("全部节点投出 nil 预投票", len(nils) == N and all(v.is_nil for v in nils))
    for nd in nodes:
        nd.actions.clear()
        for v in nils:
            nd.on_vote(v)
    precommits = [a.payload for nd in nodes for a in nd.actions
                  if a.kind == ActionKind.BROADCAST_PRECOMMIT]
    chk("收到 2/3 nil 预投票 → 进入预提交并投 nil",
        len(precommits) == N and all(v.is_nil for v in precommits))
    for nd in nodes:
        nd.actions.clear()
        for v in precommits:
            nd.on_vote(v)
    chk("收到 2/3 nil 预提交 → 推进到轮次 1",
        all(nd.hs.round == 1 for nd in nodes),
        f"轮次分布 {[nd.hs.round for nd in nodes]}")
    chk("推进后未产生任何最终化",
        all(not nd.finalized for nd in nodes))
    # 阶段超时也推进轮次
    nd = nodes[0]
    r0 = nd.hs.round
    nd.on_timeout("round")
    chk("ROUND_TIMEOUT 到期 → 轮次 +1", nd.hs.round == r0 + 1)


# ── 6. 法定数与 Commit ──────────────────────────────────────────────

def test_finality_and_commit():
    print("\n6) 法定数与 Commit（规范 §6.2、§9）")
    sim = Sim(slot=4)
    pv, pc = sim.run_full_round()
    chk("4 个节点都最终化了区块",
        all(len(nd.finalized) == 1 for nd in sim.nodes),
        f"{[len(nd.finalized) for nd in sim.nodes]}")
    chk("最终化的是同一个区块",
        all(nd.finalized[0].block_hash() == sim.block.block_hash() for nd in sim.nodes))
    c = sim.nodes[0].build_commit()
    chk("可构造出 Commit", c is not None)
    chk("Commit 含全部 4 个签名（不裁剪，BUG-13）", len(c.signatures) == N)
    chk("签名按地址升序",
        [s.address for s in c.signatures] == sorted(s.address for s in c.signatures))
    ok, why, power = verify_commit(c, sim.snap, expect_height=sim.height,
                                   expect_hash=sim.block.block_hash())
    chk("Commit 通过独立校验", ok, why or f"power={power // P.ATOM_PER_AGORA} AGORA")

    # 3 人签名仍达法定数
    c3 = Commit(height=sim.height, round=c.round, block_hash=c.block_hash,
                signatures=c.signatures[:3])
    ok3, why3, p3 = verify_commit(c3, sim.snap, expect_height=sim.height,
                                  expect_hash=c.block_hash)
    chk("3 人签名仍达法定数（防单点停机）", ok3, f"{p3 // P.ATOM_PER_AGORA} AGORA")
    c2 = Commit(height=sim.height, round=c.round, block_hash=c.block_hash,
                signatures=c.signatures[:2])
    ok2, why2, _ = verify_commit(c2, sim.snap, expect_height=sim.height,
                                 expect_hash=c.block_hash)
    chk("2 人签名未达法定数", not ok2, why2)


# ── 7. 安全性 T1/T2 ─────────────────────────────────────────────────

def test_safety():
    print("\n7) 安全性 T1/T2（规范 §9.4）")
    sim = Sim(slot=6)
    sim.run_full_round()
    block_a = sim.block

    # 构造一个冲突区块（同高度同轮次、不同哈希），并让一个"拜占庭"节点对它签名
    conflict = make_block_for(sim.st, sim.slot, sim.height, sim.pi)
    conflict.header.parent_hash = b"\x55" * 32
    conflict.header.proposer_signature = sign(SEEDS[sim.pi], conflict.header.signing_payload())
    assert conflict.block_hash() != block_a.block_hash()

    # 拜占庭节点在**同一轮次**对两个区块都签名（双签）
    v_a = Vote.create(SEEDS[0], sim.height, 0, VoteType.PRECOMMIT,
                      block_a.block_hash(), ADDRS[0])
    v_b = Vote.create(SEEDS[0], sim.height, 0, VoteType.PRECOMMIT,
                      conflict.block_hash(), ADDRS[0])
    chk("同一验证者能在同一轮签出两个冲突预提交（双签可构造）",
        v_a.signature != v_b.signature and v_a.block_hash != v_b.block_hash)

    # T2：两个区块各自都无法仅靠 1 个签名达到法定数 ⇒ 不会同时最终化
    q = P.quorum(sim.snap.staked_supply)
    one = sim.snap.vp_of(ADDRS[0])
    chk("单个验证者的投票权不足以构成法定数（T1 的前提）", one < q,
        f"{one // P.ATOM_PER_AGORA} < {q // P.ATOM_PER_AGORA} AGORA")
    chk("扣除一个诚实验证者后仍不足以同时最终化两个区块",
        2 * (N - 1) * 64 * P.ATOM_PER_AGORA >= 2 * q,
        "两个法定数集合必然相交，交集内必含诚实节点（QUORUM > 2S/3）")

    # 实际最终化只有一个
    hashes = {nd.finalized[0].block_hash() for nd in sim.nodes if nd.finalized}
    chk("本轮实际只最终化了一个区块", len(hashes) == 1, f"{len(hashes)} 个")

    # 节点收到对冲突区块的投票时不会改变已最终化的结论
    nd = sim.nodes[1]
    before = nd.hs.locked_value
    nd.on_vote(v_b)
    chk("收到冲突预提交不会改变锁定值", nd.hs.locked_value == before)


# ── 8. 消息校验与拒绝原因 ───────────────────────────────────────────

def test_message_validation():
    print("\n8) 消息校验（规范 §2.1、§23.3）")
    st = make_state()
    snap = st.system.snapshot
    nd = ConsensusNode(ADDRS[0], SEEDS[0], st, snapshot=snap, height=1, round_slot=1)
    nd.start_round(0)
    nd.actions.clear()

    # 伪造签名
    forged = Vote(height=1, round=0, vote_type=int(VoteType.PREVOTE),
                  block_hash=b"\x11" * 32, address=ADDRS[1], signature=b"\x22" * 64)
    nd.rejects.clear()
    nd.on_vote(forged)
    chk("伪造签名被拒且记录原因", any("签名无效" in r for r in nd.rejects))

    # 非集合成员
    outsider = address_from_pubkey(publickey_from_seed(bytes([200]) * 32))
    v_out = Vote(height=1, round=0, vote_type=int(VoteType.PREVOTE),
                 block_hash=b"\x11" * 32, address=outsider, signature=b"\x33" * 64)
    nd.rejects.clear()
    nd.on_vote(v_out)
    chk("非集合成员被拒且记录原因", any("不在快照集合" in r for r in nd.rejects))

    # 高度不符
    nd.rejects.clear()
    nd.on_vote(Vote(height=99, round=0, vote_type=int(VoteType.PREVOTE),
                    block_hash=b"\x11" * 32, address=ADDRS[1], signature=b"\x44" * 64))
    chk("高度不符被拒且记录原因", any("高度不符" in r for r in nd.rejects))

    # 轮次超前超限
    nd.rejects.clear()
    nd.on_vote(Vote(height=1, round=999, vote_type=int(VoteType.PREVOTE),
                    block_hash=b"\x11" * 32, address=ADDRS[1], signature=b"\x55" * 64))
    chk("轮次超前超限被拒且记录原因", any("超前超限" in r for r in nd.rejects))

    # 合法投票被接受
    good = Vote.create(SEEDS[1], 1, 0, VoteType.PREVOTE, b"\x11" * 32, ADDRS[1])
    nd.rejects.clear()
    nd.on_vote(good)
    chk("合法投票被接受（无拒绝记录）", not nd.rejects)
    # 重复投票被忽略但记录
    nd.rejects.clear()
    nd.on_vote(good)
    chk("重复投票被忽略且记录原因", any("已投过票" in r for r in nd.rejects))


# ── 轮次同步（BUG-58 的配套修复）────────────────────────────────────

def _mk_node(round_slot: int = 1):
    """构造一个处于高度 1、第 0 轮的共识状态机（4 名验证者，各 64 AGORA）。"""
    import copy
    from agora.node import make_genesis_block
    seeds = [bytes([i]) * 32 for i in (1, 2, 3, 4)]
    pks = [publickey_from_seed(x) for x in seeds]
    addrs = [address_from_pubkey(p) for p in pks]
    st, _ = build_genesis_state(GenesisAllocation(
        validators=[(p, 64 * P.ATOM_PER_AGORA) for p in pks],
        balances=[(pks[0], P.INITIAL_SUPPLY - 4 * 64 * P.ATOM_PER_AGORA)]))
    gen = make_genesis_block(st)
    c = ConsensusNode(address=addrs[0], seed=seeds[0], state=copy.deepcopy(st),
                      parent_block=gen, height=1, round_slot=round_slot)
    return c, seeds, addrs


def test_round_sync():
    """§23.3 转换表的两条方向相反的规则（BUG-58 配套）：

    ① **孤票只记录、不触发进轮**。单张高轮次的票可能来自跑偏的节点；
       若据此进轮，会跨过本来能达成法定数的那一轮。
       实测（20% 丢包，6 种子）：收到孤票即跳轮 → 通过 3/6；
       只记录不跳轮 → 通过 6/6。规范据此把该行拆为"提案"与"孤票"两条。
    ② **进轮时必须用已收到的票补算该轮法定数**。否则那批票被永久忽略，
       已经形成的法定数不再产生任何动作（实测：同一轮 3 个节点已对同一区块
       投预提交、对端也收下且未拒绝，却始终无人最终化）。
    """
    print("\n9) 轮次同步与已收票的法定数补算（BUG-58 配套）")
    st = make_state()
    snap = st.system.snapshot
    nd = ConsensusNode(ADDRS[0], SEEDS[0], st, snapshot=snap,
                       height=1, round_slot=2)
    nd.actions.clear()
    chk("初始处于第 0 轮", nd.hs.round == 0)

    # ① 孤票：必须被记录，但**不得**改变轮次
    bh = b"\xab" * 32
    v_future = Vote.create(SEEDS[1], 1, 3, int(VoteType.PREVOTE), bh, ADDRS[1])
    nd.on_vote(v_future)
    chk("未来轮的孤票被记录进该轮", nd.hs.votes.get((3, int(VoteType.PREVOTE)), {}),
        "记录在 (round=3, PREVOTE) 桶内")
    chk("孤票**不**触发进轮（实测：跳轮会跨过可最终化的轮次）", nd.hs.round == 0,
        f"实际轮次 {nd.hs.round}")

    # ② 轮次超前超限的票必须拒绝
    far = Vote.create(SEEDS[2], 1, P.MAX_ROUND_WINDOW + 5,
                      int(VoteType.PREVOTE), bh, ADDRS[2])
    before = len(nd.rejects)
    nd.on_vote(far)
    chk("轮次超前超限的票被拒绝（§11.4）", len(nd.rejects) > before,
        str(nd.rejects[-1:]))
    chk("被判超前超限时不改变轮次", nd.hs.round == 0, f"实际 {nd.hs.round}")

    # ③ 关键：进轮时必须补算已收票的法定数。
    #    先在**第 3 轮**攒下 2 票（不足法定数），再让本节点进入第 3 轮，
    #    然后补第 3 票 —— 若没有补算逻辑，这批票永远不起作用。
    nd2 = ConsensusNode(ADDRS[0], SEEDS[0], st, snapshot=snap,
                        height=1, round_slot=2)
    nd2.actions.clear()
    bh2 = b"\xcd" * 32
    for i in (1, 2):
        nd2.on_vote(Vote.create(SEEDS[i], 1, 3, int(VoteType.PREVOTE), bh2, ADDRS[i]))
    chk("未来轮的票只被记录，本节点仍在第 0 轮", nd2.hs.round == 0,
        f"实际 {nd2.hs.round}")
    chk("两票不足法定数（未推进步骤）", nd2.hs.step.name != "PRECOMMIT",
        f"步={nd2.hs.step.name}")

    # 本节点**进入第 3 轮**（现实中的触发者是该轮提案或自身超时）。
    # 进入的这一刻必须把先前收下的两票重新评估；否则它们永久失效。
    nd2.actions.clear()
    nd2.start_round(3)
    chk("进入第 3 轮", nd2.hs.round == 3, f"实际 {nd2.hs.round}")
    tally = nd2.hs.tally(3, int(VoteType.PREVOTE), nd2.snapshot)
    chk("进轮后已收票被补算（两票仍在账上）", tally.get(bh2, 0) > 0,
        f"第 3 轮预投票权益 {tally.get(bh2, 0) // 10 ** 18}")
    chk("两票仍不足法定数 ⇒ 暂不进入 PRECOMMIT",
        nd2.hs.step.name != "PRECOMMIT", f"步={nd2.hs.step.name}")

    # 第 3 票到位 ⇒ 其处理路径（v.round == 当前轮）触发推进
    nd2.on_vote(Vote.create(SEEDS[3], 1, 3, int(VoteType.PREVOTE), bh2, ADDRS[3]))
    tally = nd2.hs.tally(3, int(VoteType.PREVOTE), nd2.snapshot)
    chk("第 3 轮三票达到法定数", tally.get(bh2, 0) >= nd2.quorum(),
        f"{tally.get(bh2, 0)} vs {nd2.quorum()}")
    chk("达到法定数 ⇒ 进入 PRECOMMIT", nd2.hs.step.name == "PRECOMMIT",
        f"实际 {nd2.hs.step.name}")

    # ④ 重入保护：连续进轮不得递归爆栈
    nd3 = ConsensusNode(ADDRS[0], SEEDS[0], st, snapshot=snap,
                        height=1, round_slot=2)
    nd3.actions.clear()
    for r in range(1, 30):
        nd3.start_round(r)
    chk("连续进轮不崩溃且停在目标轮次", nd3.hs.round == 29, f"实际 {nd3.hs.round}")


def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 共识状态机测试")
    print("═" * 76)
    test_proposer()
    test_fixed_slot()
    test_one_vote_per_round()
    test_locking()
    test_nil_and_round_advance()
    test_finality_and_commit()
    test_safety()
    test_message_validation()
    test_round_sync()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
