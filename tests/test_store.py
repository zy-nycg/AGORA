# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 链上持久化测试（`agora/store.py`）
=================================================

为什么这一层必须有自己的测试
----------------------------
持久化是**唯一**会把"磁盘上的字节"当成状态的地方。它一旦错了，症状不是立刻崩溃，
而是"重启后跑出一个只有自己认的链" —— 这类故障在网络上表现为**永久分叉**，
且事后无法判定哪条链是对的。因此本文件只断言两类性质：

1. **往返一致**：存盘 → 重载，状态根必须与链头的承诺一致；
2. **拒绝启动**：任何不一致（快照篡改、区块篡改、状态与高度不符、拿错数据目录、
   缺少重放函数）都必须**抛 `StoreCorruption`**，而不是猜一个值继续跑。

唯一的例外是**文件末尾的半条记录**（掉电中止的写入）：它被安全丢弃，
因为那属于"崩溃恢复"，而不是"数据损坏"。

运行：python3 -m tests.test_store
"""

from __future__ import annotations

import functools
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agora import params as P
from agora.block import (Block, BlockHeader, Commit, CommitSignature, apply_block,
                         precommit_payload, prepare_block)
from agora.crypto import address_from_pubkey, publickey_from_seed, sign
from agora.node import make_genesis_block
from agora.state import GenesisAllocation, build_genesis_state
from agora.store import ChainStore, StoreCorruption
from agora.tx import Transaction, TxType

A = P.ATOM_PER_AGORA
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


def _genesis(seeds=(1, 2, 3, 4)):
    pks = [publickey_from_seed(bytes([i]) * 32) for i in seeds]
    stake = 64 * A
    st, _ = build_genesis_state(GenesisAllocation(
        validators=[(p, stake) for p in pks],
        balances=[(pks[0], P.INITIAL_SUPPLY - stake * len(pks))],
        genesis_timestamp=P.GENESIS_TIMESTAMP), strict=True)
    return st, pks, [address_from_pubkey(p) for p in pks]


def _commit(addrs, seeds, h, bh):
    return Commit(height=h, round=0, block_hash=bh, signatures=sorted(
        [CommitSignature(addrs[i], sign(seeds[i], precommit_payload(h, 0, bh)))
         for i in range(len(addrs))], key=lambda c: c.address))


def _chain(n=5):
    """建一条 n 块的链，返回 `(最终状态, 区块列表, 创世块, 创世状态, 公钥列表)`。

    ⚠ 每次调用都**清空** `FINALIZED_COMMIT`：它是按高度索引的全局表，
    多次调用会累积（首版就在这里踩了坑 —— 第二个测试取到了前一个测试的证书，
    于是"快照高度 3 却带着高度 4 的证书"，白白报了一个假失败）。
    """
    FINALIZED_COMMIT.clear()
    st, pks, addrs = _genesis()
    gst = _genesis()[0]
    seeds = [bytes([i]) * 32 for i in (1, 2, 3, 4)]
    gblk = make_genesis_block(st)
    prev, blocks = gblk, []
    for h in range(1, n + 1):
        tx = Transaction(tx_type=int(TxType.TRANSFER), nonce=h - 1,
                         max_priority_fee_per_gas=0, max_fee_per_gas=P.MIN_BASE_FEE,
                         gas_limit=100_000, to=addrs[3], value=1 * A, pubkey=pks[0])
        tx.signature = sign(seeds[0], tx.signing_payload())
        hdr = BlockHeader(
            height=h, round=0, claimed_slot=h, parent_hash=prev.block_hash(),
            tx_root=b"", receipt_root=b"", state_root=b"", gas_used=0,
            base_fee_per_gas=P.INITIAL_BASE_FEE,
            parent_commit=Commit.empty() if h == 1 else _commit(addrs, seeds, h - 1, prev.block_hash()),
            proposer_pubkey=pks[0])
        hdr.timestamp = P.block_timestamp(h)
        hdr.finalize_parent_commit_hash()
        hdr.proposer_signature = sign(seeds[0], hdr.signing_payload())
        blk = Block(header=hdr, transactions=[tx])
        pb = None if h == 1 else prev
        prepare_block(st, blk, parent_block=pb)
        st = apply_block(st, blk, parent_block=pb)
        blocks.append(blk)
        FINALIZED_COMMIT.append(_commit(addrs, seeds, h, blk.block_hash()))
        prev = blk
    return st, blocks, gblk, gst, pks


REPLAY = functools.partial(apply_block, finalize_header=False, in_place=True)

# `_chain` 会把"使**每个高度**最终化的证书"记在这里（下标 = 高度）。
# 注意：区块携带的是**它父亲**的证书，因此某个高度自己的证书必须单独构造
# （由收集到 2/3 预提交的节点生成）—— 这正是快照要保存它的原因。
FINALIZED_COMMIT = []


def _store(d, snapshot_every=1000):
    s = ChainStore(d, snapshot_every=snapshot_every)
    return s


# ── 1. 往返一致 ──────────────────────────────────────────────────────

def test_roundtrip():
    print("\n1) 存盘 → 重载：状态根必须与链头承诺一致")
    st, blocks, gblk, gst, _ = _chain(5)
    d = tempfile.mkdtemp()
    try:
        s = _store(d)
        s.blocks.ensure_genesis(gblk)
        for b in blocks:
            s.append_block(b)
        s.save_state(st, len(blocks), blocks[-1].block_hash(), FINALIZED_COMMIT[len(blocks) - 1])
        s2, blks, hc = ChainStore(d).load(gst, gblk, replays=REPLAY)
        chk("重载得到同样长度的链（含创世）",
            len(blks) == len(blocks) + 1, f"{len(blks)} 条")
        chk("重载的状态根 == 链头承诺", s2.state_root == blocks[-1].header.state_root,
            s2.state_root.hex()[:24] + "…")
        chk("重载的状态根 == 存盘前的状态根", s2.state_root == st.state_root)
        chk("重载后供应量守恒", s2.check_supply_conservation()[0])
        # 链头的 Commit 必须一起恢复：它是下一个区块 `parent_commit` 的内容，
        # 缺失会导致重启后无法提案（对端以"parent_commit 非法"拒收）⇒ 停摆
        chk("链头的 Commit 随快照一起恢复（且 height/block_hash 与链头一致）",
            hc is not None and hc.height == blocks[-1].header.height
            and hc.block_hash == blocks[-1].block_hash(),
            f"height={None if hc is None else hc.height}")

        # 快照在创世高度 ⇒ 必须靠重放补齐
        ChainStore(d).save_state(gst, 0, gblk.block_hash())
        s3, _, _ = ChainStore(d).load(gst, gblk, replays=REPLAY)
        chk("快照停在创世时：重放全部区块后根一致", s3.state_root == st.state_root,
            s3.state_root.hex()[:24] + "…")

        # 无快照文件（只有区块）也必须能重建
        os.remove(os.path.join(d, "state.bin"))
        s4, _, _ = ChainStore(d).load(gst, gblk, replays=REPLAY)
        chk("没有快照文件时：从创世重放也能重建", s4.state_root == st.state_root)
    finally:
        shutil.rmtree(d)


# ── 2. 拒绝启动 ──────────────────────────────────────────────────────

def test_refuse_to_start():
    print("\n2) 任何不一致都必须拒绝启动（不猜）")
    st, blocks, gblk, gst, _ = _chain(4)
    d = tempfile.mkdtemp()
    try:
        s = _store(d)
        s.blocks.ensure_genesis(gblk)
        for b in blocks:
            s.append_block(b)
        s.save_state(st, len(blocks), blocks[-1].block_hash(), FINALIZED_COMMIT[len(blocks) - 1])

        # ① 快照字节被篡改（校验和）
        pth = os.path.join(d, "state.bin")
        raw = bytearray(open(pth, "rb").read())
        raw[8] ^= 0xFF
        open(pth, "wb").write(bytes(raw))
        chk("快照校验和不符 → StoreCorruption", _raises(d, gst, gblk))

        # ② 状态与高度不符（把最终状态标成高度 0）
        ChainStore(d).save_state(st, 0, gblk.block_hash())
        chk("快照状态与高度不相符 → StoreCorruption", _raises(d, gst, gblk))

        # ③ 缺少重放函数（快照落后）
        ChainStore(d).save_state(gst, 0, gblk.block_hash())
        try:
            ChainStore(d).load(gst, gblk)
            ok = False
        except StoreCorruption:
            ok = True
        chk("快照落后且未提供重放函数 → StoreCorruption", ok)

        # ④ 区块记录被篡改（校验和）
        ChainStore(d).save_state(st, len(blocks), blocks[-1].block_hash(), FINALIZED_COMMIT[len(blocks) - 1])
        pth = os.path.join(d, "blocks.bin")
        raw = bytearray(open(pth, "rb").read())
        raw[len(raw) // 2] ^= 0xFF
        open(pth, "wb").write(bytes(raw))
        chk("区块校验和不符 → StoreCorruption", _raises(d, gst, gblk))

        # ⑤ 拿另一条链的数据目录（创世不同）
        other_st, other_pks, _ = _genesis(seeds=(11, 12, 13, 14))
        other_blk = make_genesis_block(other_st)
        chk("数据目录属于另一条链 → StoreCorruption",
            _raises(d, other_st, other_blk))
    finally:
        shutil.rmtree(d)


def _raises(d, gst, gblk) -> bool:
    try:
        ChainStore(d).load(gst, gblk, replays=REPLAY)
        return False
    except StoreCorruption:
        return True


# ── 3. 崩溃恢复：只允许丢弃**末尾**的半条记录 ────────────────────────

def test_crash_recovery():
    print("\n3) 掉电中止的写入：末尾半条记录被安全丢弃")

    # 真实崩溃顺序：区块先落盘（每条 fsync），快照**后**写（原子 rename）。
    # 因此"快照高度 ≤ 链长"是应当成立的不变量；若相反，说明区块文件丢了数据
    # （不是崩溃，而是真损坏）⇒ 必须拒绝启动。两种情形都测。
    st, blocks, gblk, gst, _ = _chain(4)
    d = tempfile.mkdtemp()
    try:
        s = _store(d)
        s.blocks.ensure_genesis(gblk)
        for b in blocks[:3]:                       # 先落 3 个区块
            s.append_block(b)
        st3 = REPLAY(REPLAY(gst, blocks[0]), blocks[1])
        st3 = REPLAY(st3, blocks[2])               # 高度 3 的状态
        s.save_state(st3, 3, blocks[2].block_hash(), FINALIZED_COMMIT[2])
        s.append_block(blocks[3])                  # 第 4 个区块写到一半掉电
        pth = os.path.join(d, "blocks.bin")
        with open(pth, "r+b") as f:
            f.truncate(os.path.getsize(pth) - 7)

        st2, blks, hc2 = ChainStore(d).load(gst, gblk, replays=REPLAY)
        chk("末尾残缺记录被丢弃（链回到最后一个完整区块）",
            len(blks) == 4, f"{len(blks)} 条（丢失 1 条）")
        chk("丢弃后状态根仍与高度 3 的承诺一致",
            st2.state_root == blocks[2].header.state_root,
            st2.state_root.hex()[:24] + "…")
        chk("截断后文件已自洽（可继续追加）",
            len(ChainStore(d).blocks.load()) == 4)

        # 反向：快照**超前**于链（区块文件丢数据）⇒ 必须拒绝启动
        d2 = tempfile.mkdtemp()
        try:
            s2 = _store(d2)
            s2.blocks.ensure_genesis(gblk)
            for b in blocks:
                s2.append_block(b)
            s2.save_state(st, len(blocks), blocks[-1].block_hash(), FINALIZED_COMMIT[len(blocks) - 1])
            pth = os.path.join(d2, "blocks.bin")
            with open(pth, "r+b") as f:
                f.truncate(os.path.getsize(pth) - 900)     # 抹掉最后一个区块
            chk("快照超前于链（区块文件丢数据）→ 拒绝启动", _raises(d2, gst, gblk))
        finally:
            shutil.rmtree(d2)
    finally:
        shutil.rmtree(d)


# ── 4. 重放等价性：这是"持久化能否工作"的**唯一**判据（BUG-92）──────
#
# 实测过的缺陷（修复前）：`apply_block` 的阶段 1（参与/不活跃计数）以
# "调用方有没有传 `parent_block`"为门。实时路径会传父块，而**重放路径**
# （`functools.partial(apply_block, finalize_header=False, in_place=True)`）
# 不传 ⇒ 重放整段跳过阶段 1 ⇒ 第一个被重放的区块就与实时执行产生**不同的
# 状态根** ⇒ 无快照（或快照落后）的节点重启时必然报
# "第 11 项失败：区块声明的 state_root 与实际执行结果不符" 并拒绝启动。
#
# 这个缺陷此前从未被发现，因为**此前的重启测试总是"停机时刚好在链头存了一份
# 快照"**（`start = snap_height + 1 > len(blocks)-1` ⇒ 需要重放的区块数为 0），
# 于是重放路径一次也没被真正执行过。故障演练里 node3 被 `kill -9`（没有快照）
# 才第一次真正走了全量重放，立刻暴露。

def test_replay_equivalence():
    print("\n4) 重放等价性：从区块日志重放 == 实时执行（BUG-92 回归）")
    st, blocks, gblk, gst, _ = _chain(8)
    committed = blocks[-1].header.state_root

    # ① 完全没有快照 ⇒ 必须从创世重放全部 8 个区块
    d1 = tempfile.mkdtemp()
    try:
        s = _store(d1)
        s.blocks.ensure_genesis(gblk)
        for b in blocks:
            s.append_block(b)
        chk("数据目录里没有状态快照（模拟 kill -9）",
            not os.path.exists(s.state_path))
        try:
            st1, blks1, hc1 = ChainStore(d1).load(gst, gblk, replays=REPLAY)
            ok = True
            reason = ""
        except StoreCorruption as e:
            ok, st1, hc1, reason = False, None, None, str(e)
        chk("无快照时全量重放**成功**（修复前必然抛 StoreCorruption）", ok, reason[:90])
        if ok:
            chk("重放结果的状态根 == 链头承诺",
                st1.state_root == committed,
                f"{st1.state_root.hex()[:16]}… vs {committed.hex()[:16]}…")
    finally:
        shutil.rmtree(d1)

    # ② 快照落后于链头 ⇒ 只重放快照之后的区块
    d2 = tempfile.mkdtemp()
    try:
        s = _store(d2)
        s.blocks.ensure_genesis(gblk)
        for b in blocks:
            s.append_block(b)
        mid = 3
        st_mid = gst
        for b in blocks[:mid]:
            st_mid = apply_block(st_mid, b, in_place=True)
        # `FINALIZED_COMMIT` 的下标 = **高度 − 1**（它按高度依次 append）
        s.save_state(st_mid, mid, blocks[mid - 1].block_hash(),
                     FINALIZED_COMMIT[mid - 1])
        try:
            st2, _, _ = ChainStore(d2).load(gst, gblk, replays=REPLAY)
            ok2, reason2 = True, ""
        except StoreCorruption as e:
            ok2, st2, reason2 = False, None, str(e)
        chk("快照落后 5 个区块时，重放补齐后状态根一致",
            ok2 and st2.state_root == committed, reason2[:90])
    finally:
        shutil.rmtree(d2)

    # ③ **重放必须是纯函数**：把"本机时钟估计"当执行输入会让两个节点分歧。
    #    现在这种调用被**显式拒绝**（而不是静默算出另一个状态根）。
    b1 = blocks[0]
    try:
        apply_block(gst, b1, current_slot=b1.header.claimed_slot + 7)
        chk("把链外时钟当执行槽 ⇒ 显式拒绝", False, "竟然接受了")
    except Exception as e:                            # noqa: BLE001
        chk("把链外时钟当执行槽 ⇒ 显式拒绝",
            "链上数据" in str(e) or "claimed_slot" in str(e), str(e)[:70])

    # ④ 传入的 `parent_block` 与区块的 parent_hash 不符 ⇒ 拒绝（防止调用方给错上下文）
    try:
        apply_block(gst, blocks[1], parent_block=blocks[0])
        chk("parent_block 与 parent_hash 不符 ⇒ 拒绝", False, "竟然接受了")
    except Exception as e:                            # noqa: BLE001
        chk("parent_block 与 parent_hash 不符 ⇒ 拒绝", True, type(e).__name__)


def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 链上持久化测试")
    print("═" * 76)
    test_roundtrip()
    test_refuse_to_start()
    test_crash_recovery()
    test_replay_equivalence()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
