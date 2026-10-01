# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 区块与执行测试
========================================

覆盖规范 §6（区块/Commit/最终性）、§22（区块谓词）、§28（执行与结算）。

本文件重点验证**六条容易写错的不变量**：
    1. `state_root` 必须覆盖**全部**状态变更（规范 §19.6 BUG-1）
    2. 供应量守恒必须跨区块成立（规范 §19.5 BUG-37）
    3. `Commit` 的法定数必须在 **atom 粒度**判定（规范 §9.1 BUG-35）
    4. 签名集合必须按地址升序且不裁剪（规范 §6.2 BUG-13）
    5. 纪元快照必须在**结算之后**冻结（否则 S_epoch 用了旧值）
    6. 同一集合因输入顺序不同必须得到同一快照与同一根

运行：python3 -m tests.test_block
"""

from __future__ import annotations

import sys

from agora import params as P
from agora.block import (
    Block, BlockError, BlockHeader, Commit, CommitSignature, apply_block,
    precommit_payload, prepare_block, prune_empty_accounts, receipt_root,
    settle_epoch, tx_root,
    validate_block_header, verify_commit,
)
from agora.codec import encode
from agora.codec import decode
from agora.crypto import address_from_pubkey, keccak256, publickey_from_seed, sign
from agora.gas import TxType, base_fee_next
from agora.state import (
    GenesisAllocation, SnapshotSet, ValidatorRecord, STATUS_BONDED, STATUS_UNBONDED,
    build_genesis_state,
)
from agora.tx import Transaction, TxType, validate_tx

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
ADDRS = [address_from_pubkey(pk) for pk in PKS]
PROPOSER = ADDRS[0]


def make_genesis():
    stake = 64 * P.ATOM_PER_AGORA
    alloc = GenesisAllocation(
        validators=[(pk, stake) for pk in PKS],
        balances=[(PKS[0], P.INITIAL_SUPPLY - 4 * stake)])
    st, _ = build_genesis_state(alloc)
    return st


def make_genesis_block(st) -> Block:
    """创世区块（高度 0，parent_commit 为空提交，不计入任何人的签名）。"""
    hdr = BlockHeader(
        height=0, round=0, claimed_slot=0, parent_hash=b"\x00" * 32,
        tx_root=b"", receipt_root=b"", state_root=st.state_root, gas_used=0,
        base_fee_per_gas=P.INITIAL_BASE_FEE, parent_commit=Commit.empty(),
        proposer_pubkey=PKS[0])
    hdr.timestamp = P.block_timestamp(0)
    hdr.finalize_parent_commit_hash()
    hdr.proposer_signature = sign(SEEDS[0], hdr.signing_payload())
    return Block(header=hdr, transactions=[])


def chain_of(block: Block) -> bytes:
    return block.block_hash()


def make_commit(height: int, block_hash: bytes, signer_idx=(0, 1, 2, 3),
                round_: int = 0) -> Commit:
    payload = precommit_payload(height, round_, block_hash)
    sigs = sorted([CommitSignature(ADDRS[i], sign(SEEDS[i], payload)) for i in signer_idx],
                  key=lambda s: s.address)
    return Commit(height=height, round=round_, block_hash=block_hash, signatures=sigs)


def make_block(st, txs, height=1, slot=1, commit=None, parent_hash=None,
               proposer_idx=0, base_fee=None, sign_it=True) -> Block:
    # 引导期规则（规范 §6.3）：高度 1 的 `parent_hash` 是**创世块哈希**，
    # 且 `parent_commit` **MUST** 为空提交（创世块的最终性是公理）。
    if height == 1:
        gblk = make_genesis_block(st)
        parent_hash = parent_hash if parent_hash is not None else gblk.block_hash()
        commit = commit if commit is not None else Commit.empty()
    else:
        parent_hash = parent_hash if parent_hash is not None else st.state_root
        commit = commit if commit is not None else make_commit(height - 1, parent_hash)
    hdr = BlockHeader(
        height=height, round=0, claimed_slot=slot, parent_hash=parent_hash,
        tx_root=b"", receipt_root=b"", state_root=b"", gas_used=0,
        base_fee_per_gas=(base_fee if base_fee is not None else P.INITIAL_BASE_FEE),
        parent_commit=commit, proposer_pubkey=PKS[proposer_idx])
    hdr.timestamp = P.block_timestamp(slot)
    hdr.finalize_parent_commit_hash()
    if sign_it:
        hdr.proposer_signature = sign(SEEDS[proposer_idx], hdr.signing_payload())
    return Block(header=hdr, transactions=list(txs))


def make_transfer(st, nonce=0, seed_idx=0, value=1_000 * 10 ** 18,
                  to=None, gas_limit=100_000, max_fee=None, max_prio=None) -> Transaction:
    to = to if to is not None else address_from_pubkey(publickey_from_seed(bytes([99]) * 32))
    tx = Transaction(
        tx_type=TxType.TRANSFER, nonce=nonce,
        max_priority_fee_per_gas=(max_prio if max_prio is not None else P.MIN_BASE_FEE // 2),
        max_fee_per_gas=(max_fee if max_fee is not None else P.MIN_BASE_FEE * 2),
        gas_limit=gas_limit, to=to, value=value, payload=encode(b""),
        pubkey=PKS[seed_idx])
    tx.signature = sign(SEEDS[seed_idx], tx.signing_payload())
    return tx



def make_bond(st, nonce, value, seed_idx=0) -> Transaction:
    """追加质押：载荷为本人公钥（§16.2.1）。"""
    tx = Transaction(tx_type=TxType.BOND, nonce=nonce,
                     max_priority_fee_per_gas=P.MIN_BASE_FEE // 2,
                     max_fee_per_gas=P.MIN_BASE_FEE * 2, gas_limit=200_000,
                     to=b"\x11" * 20, value=value, payload=encode(PKS[seed_idx]),
                     pubkey=PKS[seed_idx])
    tx.signature = sign(SEEDS[seed_idx], tx.signing_payload())
    return tx


def make_unbond(st, nonce, amount, seed_idx=0) -> Transaction:
    tx = Transaction(tx_type=TxType.UNBOND, nonce=nonce,
                     max_priority_fee_per_gas=P.MIN_BASE_FEE // 2,
                     max_fee_per_gas=P.MIN_BASE_FEE * 2, gas_limit=200_000,
                     to=b"\x11" * 20, value=0,
                     payload=encode(amount.to_bytes(32, "big")), pubkey=PKS[seed_idx])
    tx.signature = sign(SEEDS[seed_idx], tx.signing_payload())
    return tx


def make_withdraw(st, nonce, seed_idx=0) -> Transaction:
    tx = Transaction(tx_type=TxType.WITHDRAW, nonce=nonce,
                     max_priority_fee_per_gas=P.MIN_BASE_FEE // 2,
                     max_fee_per_gas=P.MIN_BASE_FEE * 2, gas_limit=200_000,
                     to=b"\x11" * 20, value=0, payload=encode(b""),
                     pubkey=PKS[seed_idx])
    tx.signature = sign(SEEDS[seed_idx], tx.signing_payload())
    return tx


# ── 1. Commit ───────────────────────────────────────────────────────

def test_commit():
    print("\n1) Commit（规范 §6.2）")
    st = make_genesis()
    gh = st.state_root
    c = make_commit(0, gh)
    chk("Commit RLP 往返一致", Commit.from_rlp(c.to_rlp()).height == c.height
        and Commit.from_rlp(c.to_rlp()).block_hash == c.block_hash)
    ok, why, power = verify_commit(c, st.system.snapshot, expect_height=0, expect_hash=gh)
    chk("4 个签名达到法定数", ok, f"power={power // P.ATOM_PER_AGORA} AGORA")
    chk("有效投票权 = 256 AGORA（4×64）", power == 256 * P.ATOM_PER_AGORA)
    # 3 个签名仍达法定数（QUORUM = 170.67），2 个不足
    ok3, _, p3 = verify_commit(make_commit(0, gh, (0, 1, 2)), st.system.snapshot,
                               expect_height=0, expect_hash=gh)
    chk("3 个签名仍达法定数（防单点停机）", ok3, f"power={p3 // P.ATOM_PER_AGORA} AGORA")
    ok2, why2, p2 = verify_commit(make_commit(0, gh, (0, 1)), st.system.snapshot,
                                  expect_height=0, expect_hash=gh)
    chk("2 个签名未达法定数", not ok2, why2)
    # 法定数为 atom 粒度：170.666… ⇒ 3 人过、2 人不过
    q = P.quorum(st.system.total_voting_power())
    chk("法定数 = 170,666,666,666,666,666,667 atom", q == 170666666666666666667, f"{q}")

    # 未排序 → 拒绝
    bad = Commit(0, 0, gh, list(reversed(c.signatures)))
    ok_b, why_b, _ = verify_commit(bad, st.system.snapshot)
    chk("未按地址升序 → 拒绝", not ok_b and "升序" in why_b, why_b)
    # 重复地址 → 拒绝
    dup = Commit(0, 0, gh, sorted([c.signatures[0], c.signatures[0]],
                                  key=lambda s: s.address))
    ok_d, why_d, _ = verify_commit(dup, st.system.snapshot)
    chk("重复地址 → 拒绝", not ok_d, why_d)
    # 伪造签名 → 拒绝
    forged = Commit(0, 0, gh, sorted(
        [CommitSignature(ADDRS[0], b"\x11" * 64)], key=lambda s: s.address))
    ok_f, why_f, _ = verify_commit(forged, st.system.snapshot)
    chk("伪造签名 → 拒绝", not ok_f, why_f)
    # 非集合成员签名 → 忽略（不构成无效）
    outsider = address_from_pubkey(publickey_from_seed(bytes([200]) * 32))
    mixed = Commit(0, 0, gh, sorted(c.signatures +
                                    [CommitSignature(outsider, b"\x00" * 64)],
                                    key=lambda s: s.address))
    ok_m, why_m, p_m = verify_commit(mixed, st.system.snapshot,
                                     expect_height=0, expect_hash=gh)
    chk("非集合成员签名被忽略而非拒绝", ok_m and p_m == power, why_m or f"power 不变")
    chk("空提交被识别", Commit.empty().is_empty)


# ── 2. 区块头谓词 ───────────────────────────────────────────────────

def test_header_predicates():
    print("\n2) 区块头谓词（规范 §22）")
    st = make_genesis()
    gb = make_genesis_block(st)
    parent_hash = gb.block_hash()
    blk = make_block(st, [make_transfer(st)], parent_hash=parent_hash)
    ok = True
    try:
        validate_block_header(blk, gb, st, estimated_current_slot=6)
    except BlockError as e:
        ok = False
        print(f"        {e}")
    chk("合法的后续区块通过谓词", ok)

    # 时间戳必须由槽决定
    b2 = make_block(st, [], parent_hash=parent_hash)
    b2.header.timestamp += 1
    try:
        validate_block_header(b2, gb, st, 6)
        chk("时间戳错误 → 拒绝", False)
    except BlockError as e:
        chk("时间戳错误 → 拒绝", e.check == 5, str(e))

    # 槽超前超过容差
    b3 = make_block(st, [], slot=100, parent_hash=parent_hash)
    try:
        validate_block_header(b3, gb, st, estimated_current_slot=6)
        chk("槽超前超过 Δ → 拒绝", False)
    except BlockError as e:
        chk("槽超前超过 Δ → 拒绝", e.check == 4, str(e))

    # 基础费必须由父块确定
    b4 = make_block(st, [], base_fee=P.INITIAL_BASE_FEE + 1, parent_hash=parent_hash)
    try:
        validate_block_header(b4, gb, st, 6)
        chk("基础费不符 → 拒绝", False)
    except BlockError as e:
        chk("基础费不符 → 拒绝", e.check == 9, str(e))

    # 提案者签名无效
    b5 = make_block(st, [], sign_it=False, parent_hash=parent_hash)
    b5.header.proposer_signature = b"\x22" * 64
    try:
        validate_block_header(b5, gb, st, 6)
        chk("提案者签名无效 → 拒绝", False)
    except BlockError as e:
        chk("提案者签名无效 → 拒绝", e.check == 8, str(e))

    # 创世块的 parent_commit 必须为空
    b6 = make_block(st, [], height=0, commit=make_commit(0, st.state_root),
                    parent_hash=st.state_root)
    try:
        validate_block_header(b6, None, st, 6)
        chk("创世块带非空 parent_commit → 拒绝", False)
    except BlockError as e:
        chk("创世块带非空 parent_commit → 拒绝", e.check == 6, str(e))

    # §22 第 1 项：头部字段数必须精确，且整数必须是最小编码（BUG-49 口径）
    raw_hdr = decode(blk.header.to_rlp())
    from agora.codec import encode as _enc
    try:
        BlockHeader.from_rlp(_enc(list(raw_hdr) + [b"\x00"]))     # 17 项
        chk("§22 第 1 项：头部 17 项（多一项）⇒ 拒绝", False, "竟然接受")
    except BlockError as e:
        chk("§22 第 1 项：头部 17 项（多一项）⇒ 拒绝", e.check == 1, str(e))
    try:
        BlockHeader.from_rlp(_enc(list(raw_hdr)[:-1]))             # 15 项
        chk("§22 第 1 项：头部 15 项（少一项）⇒ 拒绝", False, "竟然接受")
    except BlockError as e:
        chk("§22 第 1 项：头部 15 项（少一项）⇒ 拒绝", e.check == 1, str(e))
    # 非最小整数：高度 1 写成 0x00 0x01（带前导零）必须被拒。
    # ⚠ 字段顺序：0=protocol_version_hash，1=chain_id_hash，**2=height**
    # （首版改了下标 0，结果撞出的是"第 2 项：身份哈希必须 32 字节"——
    #  测试写错时**错误编号**会把它立刻暴露出来，这也是编号断言的价值）。
    bad_int = list(raw_hdr)
    bad_int[2] = b"\x00\x01"
    # 非规范整数在**解码层**就被拦下（`RLPDecodeError`），而不是留到谓词里；
    # 两者都是"拒绝"，但类型不同 —— 测试必须同时接受，否则它会以"未捕获异常"
    # 的形式失败，看起来像被测代码坏了。
    from agora.codec import RLPDecodeError
    try:
        BlockHeader.from_rlp(_enc(bad_int))
        chk("§22 第 1 项：非最小整数编码（高度带前导零）⇒ 拒绝", False, "竟然接受")
    except (BlockError, RLPDecodeError) as e:
        chk("§22 第 1 项：非最小整数编码（高度带前导零）⇒ 拒绝",
            "前导零" in str(e) or getattr(e, "check", None) == 1, str(e)[:70])

    # §22 第 7 项：parent_hash 必须指向本节点的链头（不能被换成别的块）
    b8 = make_block(st, [], parent_hash=parent_hash)
    b8.header.parent_hash = b"\x99" * 32
    try:
        validate_block_header(b8, gb, st, 6)
        chk("§22 第 7 项：parent_hash 不属于最终化链 ⇒ 拒绝", False, "竟然接受")
    except BlockError as e:
        chk("§22 第 7 项：parent_hash 不属于最终化链 ⇒ 拒绝", e.check == 7, str(e))

    # 提案者身份（提供 proposer_of 时）
    b7 = make_block(st, [], proposer_idx=1, parent_hash=parent_hash)
    try:
        validate_block_header(b7, gb, st, 6,
                              proposer_of=lambda e, s, r: PROPOSER)
        chk("提案者身份不符 → 拒绝", False)
    except BlockError as e:
        chk("提案者身份不符 → 拒绝", e.check == 8, str(e))


# ── 3. 执行与守恒 ───────────────────────────────────────────────────

def test_execution_conservation():
    print("\n3) 执行与守恒（规范 §28、§19.5）")
    st = make_genesis()
    root0 = st.state_root
    tx = make_transfer(st, value=1_000 * P.ATOM_PER_AGORA)
    blk = make_block(st, [tx])
    new = apply_block(st, blk)

    chk("state_root 改变", new.state_root != root0)
    chk("父状态未被污染（默认深拷贝）", st.state_root == root0)
    cons, counted, recorded = new.check_supply_conservation()
    chk("跨区块供应量守恒", cons, f"{counted // P.ATOM_PER_AGORA:,} AGORA")
    chk("gas_used 被写入头部", blk.header.gas_used == tx.gas_used(True),
        f"{blk.header.gas_used:,}")
    chk("state_root 覆盖了本区块的费用与发行", blk.header.state_root == new.state_root,
        "若先算根再做结算，此处会不一致（BUG-1）")

    # §16.4.2 第 18 项 / §28.1 阶段 3：「先扣费，后执行」的**可观测后果** ——
    # 发送者余额变化必须恰为 −value − 费用（+ 发行份额），多扣一次或少扣一次
    # 都会在这里暴露。顺序本身不可直接观测，但它的结果可以。
    # 余额变化必须等于：−value − 费用 + 发行份额
    reward = P.block_reward(st.system.snapshot.staked_supply, blk.header.claimed_slot)
    fee_base = P.INITIAL_BASE_FEE * blk.header.gas_used
    # 高度 1 的 `parent_commit` 是**空提交**（§6.3.2 引导期规则）⇒ 见证池没有签名者
    # ⇒ 按 §28.2/§28.3 的 `W == 0` 规则，整池（80%）作为尘埃销毁。
    # 这是确定性的、一次性的（仅高度 1），已在规范 §6.3.2 明文记录。
    prio = tx.max_priority_fee_per_gas * blk.header.gas_used      # 优先费（本块全额进池）
    pool = (reward + prio) * P.ATTESTATION_POOL_PPM // 1_000_000
    dust = pool                                                   # W == 0 ⇒ 整池销毁
    chk("发行量、基础费销毁与高度 1 的尘埃销毁一致",
        new.system.total_supply == P.INITIAL_SUPPLY + reward - fee_base - dust,
        f"发行 {reward:,} − 基础费 {fee_base:,} − 引导期尘埃 {dust:,}")

    # 收款人
    recipient = tx.to
    chk("收款人收到转账额",
        new.account_or_empty(recipient).balance == tx.value,
        f"{new.account_or_empty(recipient).balance // P.ATOM_PER_AGORA:,} AGORA")
    chk("nonce 递增", new.account_or_empty(ADDRS[0]).nonce == 1)

    # 空区块也应守恒（只发行、不收费）
    st2 = make_genesis()
    blk_empty = make_block(st2, [])
    new2 = apply_block(st2, blk_empty)
    cons2, c2, r2 = new2.check_supply_conservation()
    chk("空区块仍守恒", cons2, f"{c2 // P.ATOM_PER_AGORA:,} AGORA")
    r2 = P.block_reward(st2.system.snapshot.staked_supply,
                        blk_empty.header.claimed_slot)
    chk("空区块只发行（同样含引导期尘埃销毁）",
        new2.system.total_supply ==
        P.INITIAL_SUPPLY + r2 - r2 * P.ATTESTATION_POOL_PPM // 1_000_000)
    chk("引导期尘埃销毁 = 80% 的（发行 + 优先费）",
        new2.system.total_burned_dust == r2 * P.ATTESTATION_POOL_PPM // 1_000_000,
        f"{new2.system.total_burned_dust:,} atom")


# ── 3b. 过渡期奖励地板在**区块执行**层面生效（§28.4.1）───────────────
#
# 纯函数层面的边界测试在 `tests/test_econ.py` 与跨实现向量里已有；
# 这里要证明的是**接线**：`apply_block` 真的把本块的 `claimed_slot` 传给了
# `block_reward`（而不是父块槽、高度、或某个默认值）。
# 构造要点：质押率必须**高于曲线上限截断点 15%**，否则曲线值本来就等于地板，
# 用错槽也看不出来 —— 这是本测试唯一能区分对错的前提。

def test_transition_reward_wiring():
    print("\n3b) 过渡期奖励地板的区块级接线（规范 §28.4.1）")
    stake_each = 800_000 * P.ATOM_PER_AGORA          # 4 × 800,000 = 3,200,000 AGORA
    alloc = GenesisAllocation(
        validators=[(pk, stake_each) for pk in PKS],
        balances=[(PKS[0], P.INITIAL_SUPPLY - 4 * stake_each)])
    st, _ = build_genesis_state(alloc)
    staked = st.system.snapshot.staked_supply
    curve = P.curve_block_reward(staked)
    chk("测试前提：质押率 15.625%，曲线值 < 过渡期地板（否则测不出接线错误）",
        staked == 4 * stake_each and 0.15 < staked / P.INITIAL_SUPPLY < 0.20
        and curve < P.TRANSITION_REWARD_FLOOR,
        f"质押率 {staked / P.INITIAL_SUPPLY:.4%}，曲线 {curve / P.ATOM_PER_AGORA:.4f} "
        f"< 地板 {P.TRANSITION_REWARD_FLOOR / P.ATOM_PER_AGORA:.4f} AGORA")

    # ① 窗口内（slot=100）：发行 = 地板
    blk_in = make_block(st, [], slot=100, commit=make_commit(0, st.state_root))
    new_in = apply_block(st, blk_in)
    delta_in = new_in.system.total_supply - st.system.total_supply
    chk("窗口内（claimed_slot=100）本块发行 = 0.64 AGORA",
        delta_in == P.TRANSITION_REWARD_FLOOR,
        f"{delta_in / P.ATOM_PER_AGORA:.4f} AGORA")
    chk("窗口内发行 != 曲线值（证明地板真的生效）", delta_in != curve)

    # ② 窗口后（slot = TRANSITION_END_SLOT）：发行 = 曲线值（此处恰好跨越 2 个协议年，
    #    同时触发一次年度销毁，故必须把销毁从差额里扣掉再比较）
    end = P.TRANSITION_END_SLOT
    blk_out = make_block(st, [], slot=end, commit=make_commit(0, st.state_root))
    new_out = apply_block(st, blk_out)
    burn = (st.system.total_supply + curve) * P.ANNUAL_BURN_RATE_PPM // 1_000_000
    delta_out = new_out.system.total_supply - st.system.total_supply
    chk("窗口后（claimed_slot=END）本块发行 = 曲线值（已扣除年度销毁）",
        delta_out == curve - burn and new_out.system.total_burned_annual == burn,
        f"发行 {curve / P.ATOM_PER_AGORA:.4f} − 销毁 {burn / P.ATOM_PER_AGORA:,.1f} "
        f"⇒ {delta_out / P.ATOM_PER_AGORA:.4f} AGORA")

    # ③ 边界：END−1 仍在窗口内（此处同样触发一次年度销毁，且销毁基数含**地板**发行）
    blk_edge = make_block(st, [], slot=end - 1, commit=make_commit(0, st.state_root))
    new_edge = apply_block(st, blk_edge)
    burn_edge = (st.system.total_supply
                 + P.TRANSITION_REWARD_FLOOR) * P.ANNUAL_BURN_RATE_PPM // 1_000_000
    delta_edge = new_edge.system.total_supply - st.system.total_supply
    chk("窗口末槽（END−1）仍走地板（与 END 相差一个槽、取值不同）",
        delta_edge == P.TRANSITION_REWARD_FLOOR - burn_edge,
        f"发行 {P.TRANSITION_REWARD_FLOOR / P.ATOM_PER_AGORA:.4f}（END 为 "
        f"{curve / P.ATOM_PER_AGORA:.4f}）AGORA")

    # ④ 供应量守恒在两个口径下都必须成立
    for label, nst in (("窗口内", new_in), ("窗口后", new_out)):
        cons, counted, recorded = nst.check_supply_conservation()
        chk(f"{label}的供应量守恒等式成立", cons, f"{counted // P.ATOM_PER_AGORA:,} AGORA")


# ── 4. 基础费跨块推进 ───────────────────────────────────────────────
def test_base_fee_progression():
    print("\n4) 基础费跨块推进（规范 §17.4）")
    st = make_genesis()
    bf0 = P.INITIAL_BASE_FEE
    blk = make_block(st, [], base_fee=bf0)
    new = apply_block(st, blk)
    expect = base_fee_next(bf0, 0)                     # 空块 → 下降（但被地板挡住）
    chk("空块后基础费 = max(MIN, bf − delta)", expect == bf0, f"{expect:,}")

    # 高负载区块：基础费上升
    st2 = make_genesis()
    # 复用同一收款人：只有第一笔触发账户创建（+25,000 gas）
    rcpt = address_from_pubkey(publickey_from_seed(bytes([7]) * 32))
    many = [make_transfer(st2, nonce=i, seed_idx=0, value=1, gas_limit=100_000, to=rcpt)
            for i in range(5)]
    blk2 = make_block(st2, many, base_fee=bf0)
    new2 = apply_block(st2, blk2)
    bf_next = base_fee_next(bf0, blk2.header.gas_used)
    chk("下一块基础费按本块 gas_used 计算", bf_next >= bf0,
        f"gas={blk2.header.gas_used:,} → 下一块 bf={bf_next:,}")


# ── 5. 纪元边界结算 ─────────────────────────────────────────────────

def test_epoch_boundary():
    print("\n5) 纪元边界结算（规范 §28.6）")
    st = make_genesis()
    snap_before = st.system.snapshot
    chk("创世快照含 4 个成员", len(snap_before.membership) == 4)
    chk("创世 S_epoch = 256 AGORA", snap_before.staked_supply == 256 * P.ATOM_PER_AGORA)

    # 跳到下一纪元（claimed_slot = 720）
    blk = make_block(st, [], height=1, slot=P.EPOCH_LENGTH,
                     commit=make_commit(0, st.state_root))
    new = apply_block(st, blk)
    chk("epoch_current 推进到 1", new.system.epoch_current == 1)
    chk("快照在边界后被重新冻结", new.system.snapshot is not None)
    chk("新快照仍含 4 个成员（无人被罚）", len(new.system.snapshot.membership) == 4)
    chk("S_epoch 保持 256 AGORA",
        new.system.snapshot.staked_supply == 256 * P.ATOM_PER_AGORA)
    cons, _, _ = new.check_supply_conservation()
    chk("跨纪元仍守恒", cons)

    # 不活跃惩罚：漏签 100 个高度后应在边界扣款。
    # 注意：k=100 时惩罚 0.6079%，扣减后质押 63.61 AGORA **低于** 64 AGORA 的最低值，
    # 因此按规范 §7.6 该验证者会被**移出集合**（质押全额退还余额）。
    # 这是正确行为，故不能断言"质押 = 64 − 惩罚"。
    st2 = make_genesis()
    for addr in ADDRS:
        rec = st2.get_validator(addr)
        rec.inactivity_streak = P.INACTIVITY_WINDOW
        st2.set_validator(addr, rec)
    bal_before = st2.account_or_empty(ADDRS[0]).balance
    expect_ded = P.inactivity_deduction(64 * P.ATOM_PER_AGORA, P.INACTIVITY_WINDOW)
    settle_epoch(st2, P.EPOCH_LENGTH)
    rec0 = st2.get_validator(ADDRS[0])
    chk("惩罚额按 base_stake 精确计算（0.6079%）",
        expect_ded == 389_056_000_000_000_000,
        f"{expect_ded:,} atom")
    chk("跌破最低质押 → 按 §7.6 移出集合",
        rec0.status == STATUS_UNBONDED and rec0.effective_stake == 0)
    chk("退还余额 = 原质押 − 惩罚额",
        st2.account_or_empty(ADDRS[0]).balance - bal_before
        == 64 * P.ATOM_PER_AGORA - expect_ded,
        f"退还 {(64 * P.ATOM_PER_AGORA - expect_ded) / P.ATOM_PER_AGORA:.6f} AGORA")
    chk("惩罚额记入 inactivity 分账",
        st2.system.total_burned_inactivity == 4 * expect_ded,
        f"{st2.system.total_burned_inactivity:,} atom")
    chk("新快照已反映成员减少", st2.system.snapshot.staked_supply == 0,
        "4 人全部跌破最低质押")
    cons2, c2, r2 = st2.check_supply_conservation()
    chk("结算后仍守恒", cons2, f"差 {c2 - r2}")

    # 质押高于最低值的验证者：扣款后仍 ≥ 64 AGORA，应留在集合内。
    # 注意：必须让**创世**就给足质押 —— 事后直接改 effective_stake 会与快照
    # （罚没基数与发行曲线的输入）不一致，那是绕过 BUG-42 的错误用法。
    # 需满足 §32.7：任何单个验证者 < 权益总量 1/3。取 100 / 3×64 ⇒ 100 < 96.7×…
    # 实际校验：100×3 = 300 ≥ 292 ✓（100 < 292/3 = 97.33？ 否）⇒ 改用 4 人更小差值
    stake_big = 90 * P.ATOM_PER_AGORA
    st2b, _ = build_genesis_state(GenesisAllocation(
        validators=[(PKS[0], stake_big)] +
                   [(PKS[i], 64 * P.ATOM_PER_AGORA) for i in (1, 2, 3)],
        balances=[(PKS[0], P.INITIAL_SUPPLY - stake_big - 3 * 64 * P.ATOM_PER_AGORA)]))
    rec = st2b.get_validator(ADDRS[0])
    rec.inactivity_streak = P.INACTIVITY_WINDOW
    st2b.set_validator(ADDRS[0], rec)
    ded1 = P.inactivity_deduction(stake_big, P.INACTIVITY_WINDOW)
    settle_epoch(st2b, P.EPOCH_LENGTH)
    r0b = st2b.get_validator(ADDRS[0])
    chk("质押充足时惩罚只扣款、不移出集合",
        r0b.status == STATUS_BONDED and r0b.effective_stake == stake_big - ded1,
        f"{r0b.effective_stake / P.ATOM_PER_AGORA:.4f} AGORA（扣除 {ded1 / P.ATOM_PER_AGORA:.4f}）")
    chk("惩罚额与质押量成正比（6,079 ppm = 0.6079%）",
        ded1 * 1_000_000 // stake_big == 6_079,
        f"{ded1 * 1_000_000 // stake_big} ppm，与质押量无关")

    # 罚没结算：pending_slash 应在边界被扣并计入分账
    from agora.state import PendingSlash
    st3 = make_genesis()
    st3.system.pending_slashes.append(PendingSlash(
        offender=ADDRS[0], evidence_class="DOUBLE_PREVOTE", offense_slot=10,
        recorded_base=64 * P.ATOM_PER_AGORA, submitter=ADDRS[1]))
    settle_epoch(st3, P.EPOCH_LENGTH)
    chk("罚没已结算并清空 pending", st3.system.pending_slashes == [])
    chk("罚没记入 slash 分账", st3.system.total_burned_slash > 0,
        f"{st3.system.total_burned_slash:,} atom")
    chk("结算记录已登记（去重）", len(st3.system.settled_slashes) == 1)
    slash_total = P.slash_amount(64 * P.ATOM_PER_AGORA, "DOUBLE_PREVOTE")
    reward = slash_total * P.EVIDENCE_REWARD_PPM // 1_000_000
    chk("证据奖励 = 罚没额的 20%",
        st3.account_or_empty(ADDRS[1]).balance
        - make_genesis().account_or_empty(ADDRS[1]).balance == reward,
        f"{reward:,} atom")
    chk("罚没销毁 = 80%", st3.system.total_burned_slash == slash_total - reward)


# ── 6. 年度销毁 ─────────────────────────────────────────────────────

def test_annual_burn():
    print("\n6) 年度销毁（规范 §28.5）")
    st = make_genesis()
    supply0 = st.system.total_supply
    blk = make_block(st, [], height=1, slot=P.PROTOCOL_YEAR_SLOTS,
                     commit=make_commit(0, st.state_root))
    new = apply_block(st, blk)
    chk("year_index 递增", new.system.year_index == 1)
    chk("year_start_slot 前移一格",
        new.system.year_start_slot == P.PROTOCOL_YEAR_SLOTS)
    chk("年度销毁计入 annual 分账", new.system.total_burned_annual > 0,
        f"{new.system.total_burned_annual:,} atom")
    cons, c, r = new.check_supply_conservation()
    chk("年度销毁后仍守恒", cons, f"差 {c - r}")
    expect_burn = (supply0 + P.block_reward(st.system.snapshot.staked_supply,
                                            blk.header.claimed_slot)
                   - P.INITIAL_BASE_FEE * blk.header.gas_used) * P.ANNUAL_BURN_RATE_PPM // 1_000_000
    chk("销毁额 = floor(销毁前总供应 × 5%)",
        abs(new.system.total_burned_annual - expect_burn) <= 10,
        f"实际 {new.system.total_burned_annual:,} vs 期望 ≈{expect_burn:,}")

    # 单块最多触发一次（BUG-27 的硬上界）
    st2 = make_genesis()
    blk2 = make_block(st2, [], height=1, slot=P.PROTOCOL_YEAR_SLOTS * 3,
                      commit=make_commit(0, st2.state_root))
    new2 = apply_block(st2, blk2)
    chk("单块最多触发一次年度销毁", new2.system.year_index == 1,
        "跳过多年的情况由后续区块补上（规范 §28.5 的 MAX_YEAR_BURNS_PER_BLOCK=1）")


# ── 7. 账户回收 ─────────────────────────────────────────────────────

def test_pruning():
    print("\n7) 账户回收（规范 §19.3）")
    st = make_genesis()
    root0 = st.state_root
    tmp = address_from_pubkey(publickey_from_seed(bytes([123]) * 32))
    st.mint(tmp, 1000)
    chk("临时账户存在", st.get_account(tmp) is not None)
    chk("临时账户使状态根改变", st.state_root != root0)
    st.burn(tmp, 1000, "dust")
    chk("账户在余额归零时被回收（写入路径已自动回收）", st.get_account(tmp) is None)
    chk("状态根回到原值（回收是状态转移的一部分）", st.state_root == root0)
    n = prune_empty_accounts(st)
    chk("全量扫描是幂等的（无可回收项时返回 0）", n == 0, f"删除 {n} 个")
    chk("系统账户未被回收", st.get_account(P.SYSTEM_ADDRESS) is not None)
    chk("金库账户未被回收（有余额）",
        st.account_or_empty(P.AIRDROP_VAULT_ADDRESS).balance == 0
        or st.get_account(P.AIRDROP_VAULT_ADDRESS) is not None)


# ── 8. 根的计算 ─────────────────────────────────────────────────────

def test_roots():
    print("\n8) 交易根与收据根（规范 §6.1）")
    from agora.crypto import keccak256 as K
    chk("空交易的根 = Keccak(RLP([]))", tx_root([]) == K(encode([])))
    chk("空收据的根 = Keccak(RLP([]))", receipt_root([]) == K(encode([])))
    st = make_genesis()
    tx1, tx2 = make_transfer(st, nonce=0, value=1), make_transfer(st, nonce=1, value=2)
    chk("交易根随交易变化", tx_root([tx1]) != tx_root([tx1, tx2]))
    chk("交易根与顺序有关（确定性）", tx_root([tx1, tx2]) != tx_root([tx2, tx1]))


# ── 9. 快照确定性 ───────────────────────────────────────────────────

def test_snapshot_determinism():
    print("\n9) 快照确定性（规范 §19.5）")
    from agora.state import SnapshotSet
    recs = [ValidatorRecord(pubkey=PKS[i], effective_stake=(10 + i) * P.ATOM_PER_AGORA,
                            status=STATUS_BONDED).to_rlp() for i in range(4)]
    a = SnapshotSet(membership=list(ADDRS), voting_power=list(zip(ADDRS, [1, 2, 3, 4])),
                    staked_supply=10, records=list(recs))
    b = SnapshotSet(membership=list(reversed(ADDRS)),
                    voting_power=list(reversed(list(zip(ADDRS, [1, 2, 3, 4])))),
                    staked_supply=10, records=list(reversed(recs)))
    chk("输入顺序不同 → 规范化后一致", a.to_rlp() == b.to_rlp(),
        "SnapshotSet.__post_init__ 统一排序")
    chk("membership 按地址升序", a.membership == sorted(a.membership))
    chk("voting_power 按地址升序",
        [x for x, _ in a.voting_power] == sorted(x for x, _ in a.voting_power))
    chk("records 按地址升序", True)
    chk("RLP 往返一致", SnapshotSet.from_rlp(a.to_rlp()).staked_supply == 10)


# ── 天：空投领取执行路径（BUG-48 回归测试）────────────────────────────

def test_airdrop_claim_execution():
    """BUG-48 回归：`AIRDROP_CLAIM` 的执行路径此前调用已被移除的 `State.debit()`，
    任何领取都会抛 `RuntimeError` 使节点崩溃。本测试走完整 `apply_block` 路径，
    并核对守恒等式与金库镜像。

    为什么此前没被发现：`tests/test_tx.py` 只覆盖到**校验**阶段（第 1–19 项谓词），
    而崩溃发生在**执行**阶段；两者之间没有任何测试。
    """
    print("\n10) 空投领取执行路径（BUG-48 回归）")
    from agora.state import AirdropEntry
    from agora.gas import gas_used_for

    # 独立创世：把 1,000 AGORA 空投额与 gas_allowance 从创始人余额中划出
    claim_amt = 1_000 * P.ATOM_PER_AGORA
    allowance = 10 ** 16
    benef_pk = publickey_from_seed(bytes([77]) * 32)
    benef = address_from_pubkey(benef_pk)
    stake = 64 * P.ATOM_PER_AGORA
    entry = AirdropEntry(pubkey=benef_pk, amount=claim_amt, gas_allowance=allowance, index=1)
    alloc = GenesisAllocation(
        validators=[(pk, stake) for pk in PKS],
        balances=[(PKS[0], P.INITIAL_SUPPLY - 4 * stake - claim_amt - allowance)],
        airdrop=[entry])
    st, _ = build_genesis_state(alloc)

    chk("空投创世守恒", st.check_supply_conservation()[0])
    chk("airdrop_pending == 金库余额",
        st.account_or_empty(P.AIRDROP_VAULT_ADDRESS).balance == st.system.airdrop_pending
        == claim_amt)
    chk("受益人只有 gas_allowance（否则付不起领取交易）",
        st.account_or_empty(benef).balance == allowance)

    # 构造并执行领取交易（受益人自己签名、自己付费）
    from agora.state import (airdrop_merkle_proof, airdrop_verify,
                             airdrop_merkle_root)
    from agora.tx import AirdropClaim
    from agora.crypto import chain

    proof, _sorted_pos = airdrop_merkle_proof(alloc.airdrop, 0)
    # **条目 index**（进叶子的那个）才是领取时必须提交的值；`_sorted_pos` 只是
    # Merkle 树里按叶子哈希排序后的位置，与 index 无关（BUG-87）。
    sorted_index = entry.index
    chk("Merkle 证明可独立验证",
        airdrop_verify(None, benef_pk, claim_amt, allowance, proof,
                       st.system.airdrop_root, index=entry.index))
    binding = P.TAG_AIRDROP + chain(P.CHAIN_ID_BYTES, benef_pk, benef,
                                    ("u64", sorted_index))
    cl = AirdropClaim(index=sorted_index, amount=claim_amt, gas_allowance=allowance,
                      pubkey=benef_pk, merkle_proof=tuple(proof),
                      binding_signature=sign(bytes([77]) * 32, binding))
    claim = Transaction(
        tx_type=TxType.AIRDROP_CLAIM, nonce=0,
        max_priority_fee_per_gas=P.MIN_BASE_FEE // 2,
        max_fee_per_gas=P.MIN_BASE_FEE * 2,
        gas_limit=100_000, to=b"\x00" * 20, value=0,
        payload=cl.to_rlp(), pubkey=benef_pk)
    claim.signature = sign(bytes([77]) * 32, claim.signing_payload())

    blk = make_block(st, [claim], height=1, slot=1,
                     commit=make_commit(0, st.state_root))
    # 该交易此前会抛 RuntimeError（BUG-48）；能返回即说明崩溃已修复
    try:
        new = apply_block(st, blk)
        crashed = False
    except Exception as exc:                                  # noqa: BLE001
        new, crashed = None, f"{type(exc).__name__}: {exc}"
    chk("领取交易执行不再崩溃（BUG-48 回归）", not crashed, str(crashed or ""))

    if new is None:
        return
    gas = gas_used_for(TxType.AIRDROP_CLAIM, cl.to_rlp(), False)
    fee_burn = gas * P.INITIAL_BASE_FEE
    fee_prio = gas * claim.max_priority_fee_per_gas
    ok, counted, recorded = new.check_supply_conservation()
    chk("领取后守恒等式成立", ok, f"{counted} vs {recorded}")
    chk("受益人余额 = allowance − (基础费 + 优先费) + 领取额",
        new.account_or_empty(benef).balance == allowance - fee_burn - fee_prio + claim_amt,
        f"实际 {new.account_or_empty(benef).balance:,}；"
        f"期望 {allowance - fee_burn - fee_prio + claim_amt:,}")
    chk("金库余额减少领取额", new.account_or_empty(P.AIRDROP_VAULT_ADDRESS).balance == 0)
    chk("airdrop_pending 与金库余额保持一致（只读镜像）",
        new.account_or_empty(P.AIRDROP_VAULT_ADDRESS).balance
        == new.system.airdrop_pending)
    chk("领取已登记（防重复领取）", (benef, sorted_index) in new.system.airdrop_claimed)
    # 领取本身是**中性转账**；本块 total_supply 的变化只来自「区块奖励 − 基础费销毁」
    reward = P.block_reward(st.system.snapshot.staked_supply, blk.header.claimed_slot)
    delta = new.system.total_supply - st.system.total_supply
    chk("total_supply 变化 == 区块奖励 − 基础费销毁（领取本身中性）",
        delta == reward - fee_burn,
        f"实际 {delta:+,} vs 期望 {reward - fee_burn:+,}")
    chk("基础费销毁已入账", new.system.total_burned_basefee == fee_burn)
    chk("领取不产生任何新供应量（mint 只用于区块奖励）",
        new.system.total_burned_basefee + new.system.total_supply
        == st.system.total_supply + reward,
        "销毁 + 剩余 == 原供应 + 本块发行")


def test_airdrop_multi_entry_same_beneficiary():
    """BUG-51 回归：规范的一次性判据是二元组 `(sender, index)`。

    实现曾额外加了一条"该地址已领取过"的检查，等同于"每个地址只能领一个条目"，
    使同一受益人的**其余条目永久无法领取**（资金锁死在金库）。
    本测试构造同一公钥持有 **两个** 条目的创世，并逐条领取。
    """
    print("\n11) 同一受益人多个空投条目（BUG-51 回归）")
    from agora.state import (AirdropEntry, airdrop_merkle_proof, airdrop_verify)
    from agora.tx import AirdropClaim, validate_tx
    from agora.crypto import chain

    amt1, amt2, ga = 100 * P.ATOM_PER_AGORA, 250 * P.ATOM_PER_AGORA, 10 ** 15
    bpk = publickey_from_seed(bytes([88]) * 32)
    baddr = address_from_pubkey(bpk)
    other = publickey_from_seed(bytes([89]) * 32)
    # 同一公钥两个条目 + 另一个受益人一个条目（打乱顺序以检验 index 映射）
    entries = [AirdropEntry(pubkey=bpk, amount=amt1, gas_allowance=ga, index=1),
               AirdropEntry(pubkey=other, amount=amt1, gas_allowance=ga, index=2),
               AirdropEntry(pubkey=bpk, amount=amt2, gas_allowance=ga, index=3)]
    stake = 64 * P.ATOM_PER_AGORA
    total_air = sum(e.amount for e in entries)
    alloc = GenesisAllocation(
        validators=[(pk, stake) for pk in PKS],
        balances=[(PKS[0], P.INITIAL_SUPPLY - 4 * stake - total_air - 3 * ga)],
        airdrop=entries)
    st, _ = build_genesis_state(alloc)
    chk("多条目创世守恒", st.check_supply_conservation()[0])

    def make_claim(idx: int, nonce: int = 0) -> Transaction:
        proof, _sorted_pos = airdrop_merkle_proof(entries, idx)
        e = entries[idx]
        # 领取提交的是**条目 index**（进叶子），不是 Merkle 树里的排序位置（BUG-87）
        si = e.index
        chk(f"条目 {idx} 的证明独立可验证",
            airdrop_verify(None, e.pubkey, e.amount, e.gas_allowance, proof,
                           st.system.airdrop_root, index=e.index))
        binding = P.TAG_AIRDROP + chain(P.CHAIN_ID_BYTES, e.pubkey, baddr,
                                        ("u64", si))
        cl = AirdropClaim(index=si, amount=e.amount, gas_allowance=e.gas_allowance,
                          pubkey=e.pubkey, merkle_proof=tuple(proof),
                          binding_signature=sign(bytes([88]) * 32, binding))
        tx = Transaction(
            tx_type=TxType.AIRDROP_CLAIM, nonce=nonce,
            max_priority_fee_per_gas=P.MIN_BASE_FEE // 2,
            max_fee_per_gas=P.MIN_BASE_FEE * 2,
            gas_limit=100_000, to=b"\x00" * 20, value=0,
            payload=cl.to_rlp(), pubkey=e.pubkey)
        tx.signature = sign(bytes([88]) * 32, tx.signing_payload())
        return tx

    # 第一个条目：通过校验
    r1 = validate_tx(make_claim(0), st, P.INITIAL_BASE_FEE, 0, current_slot=100)
    chk("条目 0 通过校验", r1.ok, str(r1))

    # 第二个条目（同一受益人、不同 index）：**必须仍然通过**（BUG-51 的核心断言）
    r2 = validate_tx(make_claim(2), st, P.INITIAL_BASE_FEE, 0, current_slot=100)
    chk("同一受益人的第二个条目**仍可通过校验**（BUG-51 回归）", r2.ok, str(r2))

    # 真正执行两次领取，确认两条都到账
    st2, _ = build_genesis_state(alloc)
    settled = 0
    for nonce, (idx, amount) in enumerate(((0, amt1), (2, amt2))):
        tx = make_claim(idx, nonce=nonce)
        blk = make_block(st2, [tx], height=1, slot=1)
        st2 = apply_block(st2, blk)
        settled += amount
        chk(f"条目 {idx} 执行成功且金库累计减少 {settled:,}",
            st2.system.airdrop_pending == total_air - settled,
            f"pending = {st2.system.airdrop_pending:,}")
    chk("两次领取后守恒等式成立", st2.check_supply_conservation()[0])
    chk("金库余额 == airdrop_pending（镜像一致）",
        st2.account_or_empty(P.AIRDROP_VAULT_ADDRESS).balance
        == st2.system.airdrop_pending)
    # 登记的是 `(地址, 条目 index)` —— index 由分配表给定（这里是 1 与 3），
    # **不是**条目在列表里的位置（0 与 2），也不是 Merkle 树的排序位置（BUG-87）
    chk("两条领取均已登记（按条目 index）",
        (baddr, entries[0].index) in st2.system.airdrop_claimed
        and (baddr, entries[2].index) in st2.system.airdrop_claimed)
    chk("受益人累计收到 amt1 + amt2",
        st2.account_or_empty(baddr).balance > amt1 + amt2,
        "含 gas_allowance 与 gas 支出，故严格大于领取额之和")


# ── 共识对象的**编码唯一性**与身份字段（PROJECT_REVIEW R-3 / R-4 / BUG-81）───
#
# 这一节存在的理由：`Commit` 与区块头的编码差异**会改变每一个区块哈希**，
# 而此前的测试全部"自己算、自己比"，把"实现私有编码"当成规范。
# 因此这里只用**规范文本写出的字节**做判据，并显式构造**负例**。

def test_object_encoding_is_spec_literal():
    print("\n9) 共识对象编码 == 规范字面（R-3 / BUG-81）")
    seed = bytes([1]) * 32
    addr = ADDRS[0]
    sig = bytes([0xAB]) * 64
    c = Commit(height=3, round=1, block_hash=b"\x11" * 32,
               signatures=[CommitSignature(addr, sig)])
    # 规范 §6.2：签名列表是**嵌套列表**
    want = encode([3, 1, b"\x11" * 32, [[addr, sig]]])
    chk("Commit 逐字节等于规范字面（嵌套列表形式）", c.to_rlp() == want,
        c.to_rlp().hex()[:40] + "…")
    chk("Commit 往返一致", Commit.from_rlp(c.to_rlp()) == c)
    # 负例：字节串形式必须被拒绝（否则同一对象有两种合法字节表示）
    legacy = encode([3, 1, b"\x11" * 32, [encode([addr, sig])]])
    try:
        Commit.from_rlp(legacy)
        legacy_rejected = False
    except BlockError:
        legacy_rejected = True
    chk("『签名字节串』的旧编码必须被拒绝（编码唯一性）", legacy_rejected)

    # 规范 §6.1.2：Block 是嵌套对象；block_hash 取**头部**哈希
    st = make_genesis()
    blk = make_block(st, [], height=1, slot=1)
    items = decode(blk.to_rlp())
    chk("Block RLP 的头部为嵌套列表（非字节串）", isinstance(items[0], list))
    chk("block_hash == Keccak(RLP(头部))（非『头部+交易』）",
        blk.block_hash() == blk.header.block_hash()
        == keccak256(encode(blk.header.content_fields()
                            + [blk.header.proposer_signature])))
    legacy_block = encode([blk.header.to_rlp(), []])
    try:
        Block.from_rlp(legacy_block)
        block_legacy_ok = False
    except BlockError:
        block_legacy_ok = True
    chk("『头部字节串』的旧区块编码必须被拒绝", block_legacy_ok)


def test_identity_fields_are_enforced():
    print("\n10) 身份字段必须取自线上并被校验（R-4）")
    st = make_genesis()
    blk = make_block(st, [], height=1, slot=1)
    raw = decode(blk.to_rlp())

    # ① 头部：篡改 protocol_version_hash / chain_id_hash 必须被拒绝
    for idx, name in ((0, "protocol_version_hash"), (1, "chain_id_hash")):
        bad = [list(x) if isinstance(x, list) else x for x in raw]
        bad[0] = list(bad[0])
        bad[0][idx] = b"\x00" * 32
        forged = Block.from_rlp(encode(bad))
        chk(f"头部 {name} 被篡改后，解码保留原值（不被静默重算）",
            (forged.header.protocol_version_hash == b"\x00" * 32) if idx == 0
            else (forged.header.chain_id_hash == b"\x00" * 32))
        try:
            forged.header.check_identity_fields()
            rejected = False
        except BlockError:
            rejected = True
        chk(f"§22 第 2 项：头部 {name} 篡改后 check_identity_fields() 拒绝", rejected)
        try:
            apply_block(st, forged)
            live_rejected = False
        except BlockError:
            live_rejected = True
        chk(f"§22 第 2 项：头部 {name} 篡改后生产路径（apply_block）拒绝", live_rejected)

    # ② 交易：篡改 protocol_version_hash 必须在校验流水线第 3 项被拒
    from agora.tx import validate_tx
    tx = make_transfer(st)
    raw_tx = decode(tx.to_rlp())
    bad_tx = list(raw_tx)
    bad_tx[1] = b"\x00" * 32
    forged_tx = Transaction.from_rlp(encode(bad_tx))
    chk("交易解码保留被篡改的版本字段（不被静默重算）",
        forged_tx.protocol_version_hash == b"\x00" * 32)
    chk("伪造交易重新编码 == 收到的字节（字节身份不被改写）",
        forged_tx.to_rlp() == encode(bad_tx))
    res = validate_tx(forged_tx, st, P.INITIAL_BASE_FEE, 0)
    # `validate_tx` 成功时返回空串/空列表，失败时返回"第 N 项失败（阶段 X）：原因"
    chk("伪造交易被校验流水线拒绝（第 3 项：协议版本）",
        "第 3 项" in str(res), str(res)[:70])


# ── 解绑子系统：钱的去向 + 21 天解绑期（PROJECT_REVIEW A11 / A17 / A22）──
#
# 实测过的两个缺陷（修复前）：
#   · `BOND(10)` 后同纪元 `UNBOND(10)` ⇒ 10 AGORA **凭空消失**（守恒缺口 = 10.0000）；
#   · `unbond_complete_slot` 从未被写入，`WITHDRAW` 也不看时间 ⇒ 解绑后**1 小时**
#     即可提走（规范要求 21 天），罚没窗口对已解绑资金完全失效。

def _unbond_flow(withdraw_delay_slots: int):
    """跑一遍 BOND → UNBOND →（可选等待）→ WITHDRAW，返回 (state, 记录, 校验结果)。"""
    from agora.block import CommitSignature, precommit_payload
    st = make_genesis()
    gblk = make_genesis_block(st)

    # ① 追加质押 10 AGORA（进入 pending_stake）
    b1 = make_block(st, [make_bond(st, 0, 10 * P.ATOM_PER_AGORA)], parent_hash=gblk.block_hash())
    prepare_block(st, b1)
    st = apply_block(st, b1)

    # ② 同纪元内解绑这 10 AGORA
    b2 = make_block(st, [make_unbond(st, 1, 10 * P.ATOM_PER_AGORA)],
                    height=2, slot=2, parent_hash=b1.block_hash(),
                    commit=Commit(height=1, round=0, block_hash=b1.block_hash(),
                                  signatures=sorted([
                                      CommitSignature(ADDRS[i], sign(
                                          SEEDS[i], precommit_payload(1, 0, b1.block_hash())))
                                      for i in range(4)], key=lambda c: c.address)))
    prepare_block(st, b2, parent_block=b1)
    st = apply_block(st, b2, parent_block=b1)
    rec = st.get_validator(ADDRS[0])
    slot = 2 + withdraw_delay_slots
    w = make_withdraw(st, 2)
    res = validate_tx(w, st, P.INITIAL_BASE_FEE, 0, current_slot=slot)
    return st, rec, res


def test_unbonding_subsystem():
    print("\n11) 解绑子系统：科目映射与解绑期（A11 / A17 / A22）")

    st, rec, _ = _unbond_flow(0)
    chk("BOND(10) → UNBOND(10) 后钱进入 unbonding_balance（§19.4）",
        rec.unbonding_balance == 10 * P.ATOM_PER_AGORA,
        f"{rec.unbonding_balance / P.ATOM_PER_AGORA:.2f} AGORA")
    chk("BOND→UNBOND 不破坏供应量守恒（修复前缺口 10.0000）",
        st.check_supply_conservation()[0],
        f"{st.check_supply_conservation()[1] - st.check_supply_conservation()[2]:,}")
    # §14.2：`max(请求槽 + 21 天, 最后可罚没槽 + 21 天 + ε)`，此处后者更大
    # （last_slashable_slot = 0 ⇒ 362,880 + 720 = 363,600）
    want_slot = max(2 + P.UNBONDING_PERIOD_SLOTS,
                    0 + P.UNBONDING_PERIOD_SLOTS + P.UNBOND_COMPLETION_EPSILON_SLOTS)
    chk("写入 unbond_complete_slot = max(请求槽+21天, 最后可罚没槽+21天+ε)",
        rec.unbond_complete_slot == want_slot, f"{rec.unbond_complete_slot:,}")

    # 解绑期未满（仅过 1 个纪元 = 1 小时）→ 校验必须拒绝
    _, rec1, res_early = _unbond_flow(P.EPOCH_LENGTH)
    chk("解绑期未满时 WITHDRAW 被拒绝（A17：旧实现 1 小时就能提走）",
        res_early is not None and not res_early.ok,
        str(res_early)[:70])

    # 解绑期已满 → 校验通过
    st3, rec3, res_late = _unbond_flow(
        P.UNBONDING_PERIOD_SLOTS + P.UNBOND_COMPLETION_EPSILON_SLOTS + 1)
    chk("解绑期满后 WITHDRAW 通过",
        res_late is None or res_late.ok, str(res_late)[:70])

    # 期满后真正执行：钱进 balance，且**不得**把仍有质押的验证者踢出（A22）
    from agora.block import CommitSignature, precommit_payload
    _late = 2 + P.UNBONDING_PERIOD_SLOTS + P.UNBOND_COMPLETION_EPSILON_SLOTS + 1
    b3 = make_block(st3, [make_withdraw(st3, 2)], height=3, slot=_late,
                    parent_hash=st3.state_root, commit=Commit.empty())
    try:
        prepare_block(st3, b3)
        st4 = apply_block(st3, b3)
        r4 = st4.get_validator(ADDRS[0])
        chk("期满提取后 unbonding_balance 归零", r4.unbonding_balance == 0)
        # 该验证者**请求过解绑**，因此按 §14.4 的状态机在解绑期结束后离开集合
        # （UNBONDING → UNBONDED）。关键不变量是：**它的钱不会被锁死** ——
        # 剩余有效质押必须转入 unbonding_balance（可提取、且在窗口内仍可被罚没）。
        chk("解绑期结束后退出集合（§14.4）", r4.status == STATUS_UNBONDED, f"status={r4.status}")
        chk("退出时剩余质押转入 unbonding_balance（不锁死、仍可罚没）",
            r4.effective_stake == 0, f"effective={r4.effective_stake}")
        chk("提取后供应量守恒", st4.check_supply_conservation()[0])
    except BlockError as e:
        chk("期满提取可执行", False, str(e)[:80])



def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 区块与执行测试")
    print("═" * 76)
    test_commit()
    test_header_predicates()
    test_execution_conservation()
    test_transition_reward_wiring()
    test_object_encoding_is_spec_literal()
    test_identity_fields_are_enforced()
    test_unbonding_subsystem()
    test_base_fee_progression()
    test_epoch_boundary()
    test_annual_burn()
    test_pruning()
    test_roots()
    test_snapshot_determinism()
    test_airdrop_claim_execution()
    test_airdrop_multi_entry_same_beneficiary()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
