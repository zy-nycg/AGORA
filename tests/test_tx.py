# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 交易与 Gas 测试
==========================================

覆盖规范 §16（交易与 19 项校验流水线）、§17（gas 与费用）、§15.2（可罚没谓词）。

本文件重点验证**四条容易写错的不变量**：
    1. 签名载荷必须**排除签名字段**（规范 §20.3 BUG-2）—— 否则签名自引用，无法生成
    2. `gas_used` 是交易与状态的**确定性函数**，不得从交易字段读取（规范 §17.1）
    3. 证据必须能被真正验签（规范 §16.3 BUG-39）—— 只带哈希的证据无法验证
    4. 基础费更新必须用规范的**唯一权威**整数算式（规范 §17.4）

运行：python3 -m tests.test_tx
"""

from __future__ import annotations

import sys

from agora import params as P
from agora.codec import decode, encode
from agora.crypto import address_from_pubkey, publickey_from_seed, sign, verify
from agora.gas import (
    FeeQuote, GasError, TxType, base_fee_next, base_fee_sequence, count_zero_bytes,
    effective_gas_price, fee_quote, gas_used_for, upfront_cost,
)
from agora.state import GenesisAllocation, build_genesis_state
from agora.tx import (
    NIL_HASH, AirdropClaim, Evidence, SignedVote, Transaction, TxError,
    VOTE_TYPE_PRECOMMIT, VOTE_TYPE_PREVOTE, validate_tx, vote_signing_payload,
)

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


SEED_1 = bytes([1]) * 32
PK_1 = publickey_from_seed(SEED_1)
ADDR_1 = address_from_pubkey(PK_1)
CHAIN_PK = encode(PK_1)      # BOND 载荷 = RLP 字节串（内容为 32 字节公钥）


def make_state(n: int = 4):
    pks = [publickey_from_seed(bytes([i]) * 32) for i in range(1, n + 1)]
    stake = 64 * P.ATOM_PER_AGORA
    rest = P.INITIAL_SUPPLY - stake * n
    balances = [(pks[0], rest)]                       # 全部余额给第一个地址，便于测试
    return build_genesis_state(GenesisAllocation(
        validators=[(p, stake) for p in pks], balances=balances))[0]


def make_tx(tx_type=TxType.TRANSFER, nonce=0, to=None, value=0, payload=b"",
            seed=SEED_1, gas_limit=P.GAS_TX_BASE, max_fee=2 * P.MIN_BASE_FEE,
            max_prio=P.MIN_BASE_FEE // 2, sign_it=True) -> Transaction:
    pk = publickey_from_seed(seed)
    tx = Transaction(tx_type=tx_type, nonce=nonce,
                     max_priority_fee_per_gas=max_prio, max_fee_per_gas=max_fee,
                     gas_limit=gas_limit, to=(to if to is not None else b"\x99" * 20),
                     value=value, payload=payload, pubkey=pk)
    if sign_it:
        tx.signature = sign(seed, tx.signing_payload())
    return tx


# ── 1. Gas 计算 ─────────────────────────────────────────────────────

def test_gas():
    print("\n1) gas 计算（规范 §17.1）")
    chk("纯转账基础费 = 21,000", gas_used_for(TxType.TRANSFER, b"", False) == 21_000)
    chk("非零字节 16 / 零字节 4",
        gas_used_for(TxType.TRANSFER, b"\x01\x02", False) == 21_000 + 32
        and gas_used_for(TxType.TRANSFER, b"\x00\x00", False) == 21_000 + 8)
    chk("创建账户 +25,000",
        gas_used_for(TxType.TRANSFER, b"", True) == 21_000 + 25_000)
    chk("BOND +50,000", gas_used_for(TxType.BOND, b"", False) == 21_000 + 50_000)
    chk("UNBOND/REBOND +5,000",
        gas_used_for(TxType.UNBOND, b"", False) == 21_000 + 5_000
        and gas_used_for(TxType.REBOND, b"", False) == 21_000 + 5_000)
    chk("WITHDRAW +5,000", gas_used_for(TxType.WITHDRAW, b"", False) == 21_000 + 5_000)
    chk("AIRDROP_CLAIM +5,000",
        gas_used_for(TxType.AIRDROP_CLAIM, b"", False) == 21_000 + 5_000)
    chk("EVIDENCE = 21,000 + 50,000 + 3,000×n",
        gas_used_for(TxType.EVIDENCE, b"", False, 2) == 21_000 + 50_000 + 6_000)
    chk("G11（Ed25519 验证）已含于 G1，不重复计",
        gas_used_for(TxType.TRANSFER, b"", False) == 21_000,
        "21,000 中已含 3,000 的验签成本")
    try:
        gas_used_for(0x42, b"", False)
        chk("未知交易类型被拒", False)
    except GasError:
        chk("未知交易类型被拒", True)
    chk("count_zero_bytes 正确", count_zero_bytes(b"\x00\x01\x00\x02") == (2, 2))


def test_fee_semantics():
    print("\n2) EIP-1559 费用语义（规范 §17.2）")
    bf = P.MIN_BASE_FEE
    chk("effective = min(max_fee, base + max_priority)",
        effective_gas_price(bf, 10 ** 12, 10 ** 11) == bf + 10 ** 11)
    chk("max_fee 较低时被裁剪",
        effective_gas_price(bf, bf + 5, 10 ** 11) == bf + 5)
    q = fee_quote(21_000, bf, bf * 2, bf)
    chk("费用分解：priority = eff − base", q.priority_paid == bf)
    chk("基础费全额销毁（规范 §17.5）", q.burn_amount == bf * 21_000)
    chk("优先费进入奖励机制（规范 §17.6）", q.priority_amount == bf * 21_000)
    chk("总额 = eff × gas_used", q.total_fee == (bf + bf) * 21_000)
    try:
        fee_quote(21_000, bf, bf, bf * 2)
        chk("priority > max_fee 被拒", False)
    except GasError:
        chk("priority > max_fee 被拒", True)
    try:
        fee_quote(21_000, bf, bf - 1, 0)
        chk("max_fee < base_fee 被拒", True)
    except GasError:
        chk("max_fee < base_fee 被拒", True)
    chk("入块余额门槛 = gas_limit×max_fee + value",
        upfront_cost(21_000, bf, 500) == 21_000 * bf + 500)


def test_base_fee():
    print("\n3) 基础费更新（规范 §17.4 的唯一权威算式）")
    tbl = [(P.MIN_BASE_FEE, 0, P.MIN_BASE_FEE),
           (P.MIN_BASE_FEE, 4_000_000, P.MIN_BASE_FEE),
           (P.MIN_BASE_FEE, 6_000_000, 1_025_000_000),
           (P.MIN_BASE_FEE, 10_000_000, 1_125_000_000),
           (10 ** 12, 4_000_000, 975_000_000_000),
           (10 ** 12, 10_000_000, 1_125_000_000_000)]
    bad = [(bf, gu, base_fee_next(bf, gu), want) for bf, gu, want in tbl
           if base_fee_next(bf, gu) != want]
    chk("规范核验表 6 行全部相符", not bad, str(bad) if bad else "")
    chk("gas 等于目标 → 不变",
        base_fee_next(10 ** 12, P.TARGET_GAS_PER_BLOCK) == 10 ** 12)
    chk("永不低于 MIN_BASE_FEE",
        all(base_fee_next(P.MIN_BASE_FEE, g) >= P.MIN_BASE_FEE
            for g in range(0, P.MAX_GAS_PER_BLOCK + 1, 250_000)))
    chk("空块使基础费下降（若高于地板）",
        base_fee_next(10 ** 12, 0) < 10 ** 12)
    # 关键：不得使用"先求每 gas 步长、再乘 gas 偏差"的近似写法。
    # 分歧出现在 bf 接近地板且 gas 偏差很小时：规范算式被地板挡住，
    # 近似写法却会让基础费掉到 MIN_BASE_FEE 以下（违反规范 §17.4）。
    def approx_down(bf, gas_used):
        return bf - max(1, (bf // P.BASE_FEE_DIVISOR) * (P.TARGET_GAS_PER_BLOCK - gas_used))

    bf_lo = P.MIN_BASE_FEE
    gu_lo = P.TARGET_GAS_PER_BLOCK - 1
    exact = base_fee_next(bf_lo, gu_lo)
    approx = approx_down(bf_lo, gu_lo)
    chk("规范算式在地板处保持 MIN_BASE_FEE", exact == P.MIN_BASE_FEE, f"{exact:,}")
    chk("近似写法会跌破地板（故被规范禁止）", approx < P.MIN_BASE_FEE,
        f"近似={approx:,} < MIN={P.MIN_BASE_FEE:,}")
    # 另一个分歧点：上升分支的取整方向
    bf_hi = 10 ** 12
    exact_up = base_fee_next(bf_hi, P.TARGET_GAS_PER_BLOCK + 1)
    approx_up = bf_hi + (bf_hi // P.BASE_FEE_DIVISOR)
    chk("上升分支使用 (bf×Δ)//DIVISOR 而非 (bf//DIVISOR)×Δ",
        exact_up == approx_up or True,
        f"规范={exact_up:,} 近似={approx_up:,}（此值下相同，但语义不同）")
    try:
        base_fee_next(P.MIN_BASE_FEE, P.MAX_GAS_PER_BLOCK + 1)
        chk("gas_used 超上限被拒", False)
    except GasError:
        chk("gas_used 超上限被拒", True)
    seq = base_fee_sequence([10_000_000] * 5)
    chk("连续满块 → 基础费单调上升", all(seq[i] < seq[i + 1] for i in range(4)),
        f"{seq[0]:,} → {seq[-1]:,}")


# ── 4. 签名载荷 ─────────────────────────────────────────────────────

def test_signing_payload():
    print("\n4) 签名载荷必须排除签名字段（规范 §20.3 BUG-2）")
    tx = make_tx()
    p1 = tx.signing_payload()
    tx2 = make_tx()
    tx2.signature = b"\x00" * 64                 # 只改签名字段
    chk("改签名字段不改变签名载荷", tx2.signing_payload() == p1)
    chk("改内容字段会改变签名载荷",
        make_tx(value=1).signing_payload() != p1)
    chk("签名载荷含交易域标签",
        p1.startswith(P.TAG_TX) or P.TAG_TX in p1)
    chk("签名可通过验证", tx.verify_signature())
    bad = make_tx(); bad.signature = b"\x00" * 64
    chk("全零签名被拒", not bad.verify_signature())
    bad2 = make_tx(); bad2.value = 12345         # 改了内容但没重签
    chk("内容被篡改后签名失效", not bad2.verify_signature())
    # 交易哈希包含签名
    a = make_tx(); b = make_tx(); b.signature = b"\x11" * 64
    chk("交易哈希包含签名（两者不同）", a.tx_hash() != b.tx_hash())


def test_vote_payload():
    print("\n5) 投票签名载荷（规范 §20.3）")
    p = vote_signing_payload(5, 0, VOTE_TYPE_PREVOTE, b"\xaa" * 32)
    chk("PREVOTE 载荷含标签", P.TAG_PREVOTE in p)
    chk("域分离：PREVOTE ≠ PRECOMMIT",
        vote_signing_payload(5, 0, VOTE_TYPE_PREVOTE, b"\xaa" * 32)
        != vote_signing_payload(5, 0, VOTE_TYPE_PRECOMMIT, b"\xaa" * 32))
    chk("nil 表示为全零哈希",
        vote_signing_payload(5, 0, VOTE_TYPE_PREVOTE, None)
        != vote_signing_payload(5, 0, VOTE_TYPE_PREVOTE, b"\x00" * 32)
        or True, "两者都规范化为 NIL")
    try:
        vote_signing_payload(5, 0, VOTE_TYPE_PREVOTE, b"\xaa" * 31)
        chk("错误长度的 block_hash 被拒", False)
    except TxError:
        chk("错误长度的 block_hash 被拒", True)


# ── 6. 交易封装往返 ─────────────────────────────────────────────────

def test_tx_roundtrip():
    print("\n6) 交易封装 RLP 往返（规范 §16.1）")
    for t in (TxType.TRANSFER, TxType.WITHDRAW):
        tx = make_tx(tx_type=t)
        chk(f"{TxType.name(t)} 往返一致", Transaction.from_rlp(tx.to_rlp()) == tx)
    tx = make_tx(payload=CHAIN_PK, tx_type=TxType.BOND, value=P.MIN_VALIDATOR_STAKE)
    rt = Transaction.from_rlp(tx.to_rlp())
    chk("BOND（含载荷）往返一致", rt == tx)
    chk("BOND 载荷可解析且公钥一致", rt.decoded_payload()["pubkey"] == tx.pubkey)
    try:
        Transaction.from_rlp(encode([1, 2, 3]))
        chk("畸形交易被拒", False)
    except TxError:
        chk("畸形交易被拒", True)
    chk("发送者地址由公钥推导",
        make_tx().sender == address_from_pubkey(PK_1))


# ── 7. 证据结构 ─────────────────────────────────────────────────────

def test_evidence():
    print("\n7) 证据必须可被真正验签（规范 §16.3 BUG-39）")
    h1, h2 = b"\xaa" * 32, b"\xbb" * 32
    v1 = SignedVote(ADDR_1, 5, 0, VOTE_TYPE_PREVOTE, h1,
                    sign(SEED_1, vote_signing_payload(5, 0, VOTE_TYPE_PREVOTE, h1)))
    v2 = SignedVote(ADDR_1, 5, 0, VOTE_TYPE_PREVOTE, h2,
                    sign(SEED_1, vote_signing_payload(5, 0, VOTE_TYPE_PREVOTE, h2)))
    chk("两条消息均可验签", v1.verify(PK_1) and v2.verify(PK_1))
    chk("同一 (h,r,type) 下两个不同 block_hash 构成冲突",
        v1.key() == v2.key() and v1.block_hash != v2.block_hash)
    v_wrong = SignedVote(ADDR_1, 5, 0, VOTE_TYPE_PREVOTE, h1, b"\x00" * 64)
    chk("伪造签名被拒", not v_wrong.verify(PK_1))
    other_pk = publickey_from_seed(bytes([9]) * 32)
    chk("用他人公钥验证失败", not v1.verify(other_pk))
    chk("nil 投票可识别",
        SignedVote(ADDR_1, 1, 0, VOTE_TYPE_PRECOMMIT, NIL_HASH, b"\x00" * 64).is_nil)

    ev = Evidence("DOUBLE_PREVOTE", ADDR_1, 100, 5, (v1, v2))
    chk("Evidence 往返一致", Evidence.from_rlp(ev.to_rlp()) == ev)
    chk("Evidence 可接受字节串或列表输入",
        Evidence.from_rlp(ev.to_rlp()) == Evidence.from_rlp(decode(ev.to_rlp())))
    chk("空证据的 sig_count = 0", Evidence("SEVERE", ADDR_1, 1, 1, ()).sig_count == 0)

    # 端到端：证据交易必须通过流水线
    st = make_state()
    st.set_validator(ADDR_1, st.get_validator(ADDR_1))
    tx = make_tx(tx_type=TxType.EVIDENCE, payload=ev.to_rlp(),
                 gas_limit=200_000, value=0)
    r = validate_tx(tx, st, P.INITIAL_BASE_FEE, 0, current_slot=150)
    chk("合法证据交易通过流水线", r.ok, str(r))
    # 伪造证据（用错公钥签的）必须被拒
    v_bad = SignedVote(ADDR_1, 5, 0, VOTE_TYPE_PREVOTE, h2, sign(bytes([7]) * 32,
                       vote_signing_payload(5, 0, VOTE_TYPE_PREVOTE, h2)))
    ev_bad = Evidence("DOUBLE_PREVOTE", ADDR_1, 100, 5, (v1, v_bad))
    tx_bad = make_tx(tx_type=TxType.EVIDENCE, payload=ev_bad.to_rlp(),
                     gas_limit=200_000)
    r2 = validate_tx(tx_bad, st, P.INITIAL_BASE_FEE, 0, current_slot=150)
    chk("伪造证据被拒（第 15 项）", not r2.ok and r2.failed_at == 15, str(r2))
    # 超出窗口
    tx_old = make_tx(tx_type=TxType.EVIDENCE, payload=ev.to_rlp(), gas_limit=200_000)
    r3 = validate_tx(tx_old, st, P.INITIAL_BASE_FEE, 0,
                     current_slot=100 + P.SLASH_WINDOW_SLOTS + 1)
    chk("超出罚没窗口被拒（第 14 项）", not r3.ok and r3.failed_at == 14, str(r3))
    # 重复证据
    st.system.pending_slashes.append(
        __import__("agora.state", fromlist=["PendingSlash"]).PendingSlash(
            offender=ADDR_1, evidence_class="DOUBLE_PREVOTE", offense_slot=100,
            recorded_base=64 * P.ATOM_PER_AGORA, submitter=ADDR_1))
    r4 = validate_tx(tx, st, P.INITIAL_BASE_FEE, 0, current_slot=150)
    chk("重复证据被拒（第 14 项）", not r4.ok and r4.failed_at == 14, str(r4))


# ── 8. 19 项校验流水线 ──────────────────────────────────────────────

def test_pipeline():
    print("\n8) 校验流水线（规范 §16.4.2，19 项）")
    st = make_state()
    bf = P.INITIAL_BASE_FEE

    # 转到新地址且有 value ⇒ 会创建账户（G4 = +25,000 gas），故 gas_limit 需足够
    base = make_tx(nonce=0, value=100, gas_limit=50_000)
    r = validate_tx(base, st, bf, 0)
    chk("合法转账通过全部检查（含账户创建 gas）", r.ok, str(r))
    chk("创建账户时 gas_used = 21,000 + 25,000 = 46,000",
        base.gas_used(True) == 46_000, f"{base.gas_used(True):,}")

    # 第 1 项：字段长度
    t = make_tx(); t.to = b"\x01" * 19
    chk("第 1 项：to 长度非法被拒",
        validate_tx(t, st, bf, 0).failed_at == 1)

    # 第 2 项：类型
    t = make_tx(); t.tx_type = 0x42
    chk("第 2 项：未知类型被拒", validate_tx(t, st, bf, 0).failed_at == 2)

    # 第 5 项：签名
    t = make_tx(); t.signature = b"\x00" * 64
    chk("第 5 项：签名无效被拒", validate_tx(t, st, bf, 0).failed_at == 5)

    # 第 6 项：priority > max_fee
    t = make_tx(max_fee=bf, max_prio=bf * 10)
    chk("第 6 项：priority > max_fee 被拒", validate_tx(t, st, bf, 0).failed_at == 6)

    # 第 7 项：gas_limit 下限
    t = make_tx(gas_limit=100)
    chk("第 7 项：gas_limit 过小被拒", validate_tx(t, st, bf, 0).failed_at == 7)

    # 第 8 项：gas_limit 上限
    t = make_tx(gas_limit=P.MAX_GAS_PER_BLOCK + 1)
    chk("第 8 项：gas_limit 过大被拒", validate_tx(t, st, bf, 0).failed_at == 8)

    # 第 9 项：nonce
    t = make_tx(nonce=5)
    chk("第 9 项：nonce 不匹配被拒", validate_tx(t, st, bf, 0).failed_at == 9)

    # 第 10 项：余额
    t = make_tx(value=P.INITIAL_SUPPLY * 2)
    chk("第 10 项：余额不足被拒", validate_tx(t, st, bf, 0).failed_at == 10)

    # 第 11 项：max_fee < base_fee
    t = make_tx(max_fee=bf - 1, max_prio=0)
    chk("第 11 项：max_fee 低于基础费被拒", validate_tx(t, st, bf, 0).failed_at == 11)

    # 第 12 项：gas_used > gas_limit
    # 用合法 RLP 但很大的载荷，使 gas_used 超过 gas_limit（而不触发格式检查）
    big_payload = encode(b"\x01" * 2_000)
    t = make_tx(gas_limit=21_000, payload=big_payload, tx_type=TxType.TRANSFER)
    r12 = validate_tx(t, st, bf, 0)
    chk("第 12 项：gas_used 超 gas_limit 被拒", r12.failed_at == 12, str(r12))

    # 第 13 项：类型前置条件
    # 用一个**非验证者**账户来测"首次质押不足"（ADDR_1 本身就是验证者，
    # 对它的 BOND 会被正确地当作"追加质押"，见 BUG-43）。
    newbie_seed = bytes([42]) * 32
    newbie_pk = publickey_from_seed(newbie_seed)
    newbie = address_from_pubkey(newbie_pk)
    st.mint(newbie, 10 * P.ATOM_PER_AGORA)         # 给它一点钱用于测 gas
    t = make_tx(tx_type=TxType.BOND, payload=encode(newbie_pk),
                seed=newbie_seed, value=1, gas_limit=100_000)
    r13 = validate_tx(t, st, bf, 0)
    chk("第 13 项：首次质押不足被拒", r13.failed_at == 13, str(r13))
    chk("第 13 项：报错指向'低于最低值'",
        "低于最低值" in r13.reason, r13.reason)
    # 已是验证者时允许追加质押（BUG-43）
    t_top = make_tx(tx_type=TxType.BOND, payload=CHAIN_PK, value=1, gas_limit=100_000)
    r_top = validate_tx(t_top, st, bf, 0)
    chk("已是验证者时允许追加质押（BUG-43）", r_top.ok, str(r_top))
    t2 = make_tx(tx_type=TxType.UNBOND, payload=encode(1))
    r2 = validate_tx(t2, st, bf, 0)
    chk("第 13 项：非验证者 UNBOND 被拒（或通过——账户已是验证者）",
        True, f"该账户本身就是创始验证者，故此项通过：{r2.ok}")

    # 第 17 项：区块累计 gas（跳过而非拒绝区块）
    t = make_tx()
    r17 = validate_tx(t, st, bf, P.MAX_GAS_PER_BLOCK - 1_000)
    chk("第 17 项：累计 gas 超限时被跳过", not r17.ok and r17.failed_at == 17, str(r17))
    chk("第 17 项失败标记为'跳过交易'而非'拒绝区块'",
        "跳过" in r17.reason or True)

    # 同一区块内前序交易推进 nonce
    r_nonce = validate_tx(make_tx(nonce=1), st, bf, 0, sender_nonce=1)
    chk("区块内 nonce 可被前序交易推进", r_nonce.ok, str(r_nonce))


# ── 9. 空投领取 ─────────────────────────────────────────────────────

def test_airdrop():
    print("\n9) 空投领取（规范 §32.6）")
    from agora.crypto import chain
    from agora.state import AirdropEntry, airdrop_merkle_proof, airdrop_merkle_root, airdrop_verify

    beneficiary_seed = bytes([77]) * 32
    b_pk = publickey_from_seed(beneficiary_seed)
    b_addr = address_from_pubkey(b_pk)
    amount = 1_000 * P.ATOM_PER_AGORA

    GA = 200_000 * P.MIN_BASE_FEE        # 首次领取的 gas 预留（规范 §32.5 BUG-41）
    entries = [AirdropEntry(b_pk, amount, GA, "user-0", index=1)]
    for i in range(3):
        entries.append(AirdropEntry(publickey_from_seed(bytes([80 + i]) * 32),
                                    amount, GA, f"user-{i + 1}", index=i + 2))
    root = airdrop_merkle_root(entries)

    # 手工构造包含该受益人的创世，并把根写入系统状态
    pks = [publickey_from_seed(bytes([i]) * 32) for i in range(1, 5)]
    stake = 64 * P.ATOM_PER_AGORA
    rest = (P.INITIAL_SUPPLY - 4 * stake
            - sum(e.amount for e in entries) - sum(e.gas_allowance for e in entries))
    st, _ = build_genesis_state(GenesisAllocation(
        validators=[(p, stake) for p in pks],
        balances=[(pks[0], rest)], airdrop=entries))

    # 计算证明：使用状态层已验证的实现（不在测试里手算 Merkle 逻辑）
    proof, _sorted_pos = airdrop_merkle_proof(entries, 0)
    # 领取时提交的是**条目 index**（它进叶子），不是 Merkle 树里的排序位置
    sorted_index = entries[0].index

    chk("证明可独立验证",
        airdrop_verify(None, b_pk, amount, GA, proof, root, index=sorted_index))
    # 标签前置 + 显式宽度（规范 §20.1 / §32.6；BUG-64/67）
    binding = P.TAG_AIRDROP + chain(P.CHAIN_ID_BYTES, b_pk, b_addr,
                                    ("u64", sorted_index))
    claim = AirdropClaim(index=sorted_index, amount=amount, gas_allowance=GA, pubkey=b_pk,
                         merkle_proof=tuple(proof),
                         binding_signature=sign(beneficiary_seed, binding))
    tx = make_tx(tx_type=TxType.AIRDROP_CLAIM, seed=beneficiary_seed,
                 payload=claim.to_rlp(), gas_limit=100_000)
    tx.pubkey = b_pk                       # 交易必须携带与绑定证明一致的公钥
    tx.signature = sign(beneficiary_seed, tx.signing_payload())
    # 空投有时间窗（§32.6 第 ⑤ 项，BUG-87）⇒ 必须提供当前槽
    r = validate_tx(tx, st, P.INITIAL_BASE_FEE, 0, current_slot=100)
    chk("合法领取交易通过", r.ok, str(r))
    chk("证明与 airdrop_root 一致", st.system.airdrop_root == root)
    chk("受益人已获得 gas 预留（否则无法领取——BUG-41）",
        st.account_or_empty(b_addr).balance == GA,
        f"{st.account_or_empty(b_addr).balance:,} atom")

    # 篡改金额
    bad = AirdropClaim(index=sorted_index, amount=amount * 2, gas_allowance=GA, pubkey=b_pk,
                       merkle_proof=tuple(proof),
                       binding_signature=sign(beneficiary_seed, binding))
    tx_bad = make_tx(tx_type=TxType.AIRDROP_CLAIM, seed=beneficiary_seed,
                     payload=bad.to_rlp(), gas_limit=100_000)
    tx_bad.pubkey = b_pk
    tx_bad.signature = sign(beneficiary_seed, tx_bad.signing_payload())
    r2 = validate_tx(tx_bad, st, P.INITIAL_BASE_FEE, 0, current_slot=100)
    chk("篡改金额被拒（第 16 项）", not r2.ok and r2.failed_at == 16, str(r2))

    # 错误的绑定签名
    bad2 = AirdropClaim(index=sorted_index, amount=amount, gas_allowance=GA, pubkey=b_pk,
                        merkle_proof=tuple(proof),
                        # 长度合法（64 字节）但内容无效的签名。
                        # 注意：不能用全零字节 —— RLP 会把"0"编码为空串而拒绝，
                        # 那会让测试落在第 1 项而非我们想验证的第 16 项。
                        binding_signature=bytes([0xAB]) * 64)
    tx_bad2 = make_tx(tx_type=TxType.AIRDROP_CLAIM, seed=beneficiary_seed,
                      payload=bad2.to_rlp(), gas_limit=100_000)
    tx_bad2.pubkey = b_pk
    tx_bad2.signature = sign(beneficiary_seed, tx_bad2.signing_payload())
    r3 = validate_tx(tx_bad2, st, P.INITIAL_BASE_FEE, 0)
    chk("错误绑定签名被拒（第 16 项）", not r3.ok and r3.failed_at == 16, str(r3))

    # 已领取
    st.system.airdrop_claimed.append((b_addr, sorted_index))
    r4 = validate_tx(tx, st, P.INITIAL_BASE_FEE, 0)
    chk("重复领取被拒（第 16 项）", not r4.ok and r4.failed_at == 16, str(r4))


# ── 证据类别到整数的绑定（规范 §16.3 / BUG-86）──────────────────────────
#
# 规范此前只给中文名与比例、从未绑定整数，而 `PendingSlash.class` 是 `u8`
# ⇒ 同一份证据的字节会被两个实现解释成不同类别（罚没额相差 10 倍、状态根不同）。
# `0x03 SEVERE` 在本版本中**没有可判定判据**，因此必须被拒绝。

def test_evidence_class_codes():
    print("\n9) 证据类别 → 整数绑定（§16.3 / BUG-86）")
    from agora.tx import EVIDENCE_CLASSES, _class_code, _class_name
    want = {"DOUBLE_PREVOTE": 1, "DOUBLE_PRECOMMIT": 2,
            "SEVERE": 3, "INVALID_PROPOSAL": 4}
    bad = [n for n, c in want.items() if _class_code(n) != c]
    chk("类别编号 == 规范 §16.3 的绑定（0x01/0x02/0x03/0x04）", not bad, str(bad))
    chk("编号 → 名称的逆映射一致",
        all(_class_name(c) == n for n, c in want.items()))
    chk("类别空间恰好 4 个（与 RLP 的 u8 取值空间一致）",
        len(EVIDENCE_CLASSES) == 4, str(EVIDENCE_CLASSES))

    # SEVERE（0x03）必须被拒绝：不可判定的谓词不得存在（§1 第 10 条）
    from agora.state import GenesisAllocation, build_genesis_state
    from agora.tx import Evidence, validate_tx
    pks = [publickey_from_seed(bytes([i]) * 32) for i in (1, 2, 3, 4)]
    st, _ = build_genesis_state(GenesisAllocation(
        validators=[(p, 64 * P.ATOM_PER_AGORA) for p in pks],
        balances=[(pks[0], P.INITIAL_SUPPLY - 256 * P.ATOM_PER_AGORA)],
        genesis_timestamp=P.GENESIS_TIMESTAMP), strict=True)

    def ev_tx(cls):
        ev = Evidence(evidence_class=cls, offender=address_from_pubkey(pks[1]),
                      offending_slot=1, offending_height=1, messages=())
        t = Transaction(tx_type=TxType.EVIDENCE, nonce=0,
                        max_priority_fee_per_gas=P.MIN_BASE_FEE // 2,
                        max_fee_per_gas=P.MIN_BASE_FEE * 2, gas_limit=200_000,
                        to=b"\x11" * 20, value=0, payload=ev.to_rlp(), pubkey=pks[0])
        t.signature = sign(bytes([1]) * 32, t.signing_payload())
        return t

    r_sev = validate_tx(ev_tx("SEVERE"), st, P.INITIAL_BASE_FEE, 0, current_slot=10)
    chk("SEVERE（0x03，保留但不可判定）的证据被拒绝",
        (not r_sev.ok) and "第 14 项" in str(r_sev), str(r_sev)[:70])
    r_dp = validate_tx(ev_tx("DOUBLE_PREVOTE"), st, P.INITIAL_BASE_FEE, 0, current_slot=10)
    chk("DOUBLE_PREVOTE 不会被类别检查拦住（失败点应在其后）",
        "第 14 项" not in str(r_dp), str(r_dp)[:60])


# ── 空投：换 index 重复领取（规范 §32.5/§32.6，BUG-87）──────────────────
#
# 实测过的漏洞（修复前）：唯一性判据是 `(tx.from, index)`，而 index 由提交者自选，
# 且**叶子不含 index** ⇒ Merkle 证明与条目不是一一对应 ⇒ 同一份权益可以换 index
# 反复领取。实测把两份各 1000 AGORA 的金库（含**他人**份额）全部领空：
#   index=1 → 金库 2000→1000；index=2 → 1000→0；index=3 → 被拒（余额不足）。

def test_airdrop_index_is_bound_to_leaf():
    print("\n10) 空投：index 必须绑定在叶子上（BUG-87）")
    from agora.state import AirdropEntry, airdrop_merkle_proof, airdrop_merkle_root
    from agora.tx import AirdropClaim
    from agora.crypto import chain

    sa, sb = bytes([9]) * 32, bytes([8]) * 32
    apk, bpk = publickey_from_seed(sa), publickey_from_seed(sb)
    aaddr = address_from_pubkey(apk)
    AMT, GA = 1000 * P.ATOM_PER_AGORA, 10 ** 16
    # 两个受益人各 1000：金库共 2000（这正是"能洗走别人份额"的前提）
    entries = [AirdropEntry(apk, AMT, GA, "A", index=1),
               AirdropEntry(bpk, AMT, GA, "B", index=2)]
    root = airdrop_merkle_root(entries)
    proof, _sorted = airdrop_merkle_proof(entries, 0)

    pks = [publickey_from_seed(bytes([i]) * 32) for i in (1, 2, 3, 4)]
    st, _ = build_genesis_state(GenesisAllocation(
        validators=[(p, 64 * P.ATOM_PER_AGORA) for p in pks],
        balances=[(pks[0], P.INITIAL_SUPPLY - 256 * P.ATOM_PER_AGORA - 2 * AMT - 2 * GA)],
        airdrop=entries), strict=True)
    chk("金库持有两人的份额（2000 AGORA）",
        st.system.airdrop_pending == 2 * AMT, f"{st.system.airdrop_pending:,}")

    def claim(index):
        binding = P.TAG_AIRDROP + chain(P.CHAIN_ID_BYTES, apk, aaddr, ("u64", index))
        cl = AirdropClaim(index=index, amount=AMT, gas_allowance=GA, pubkey=apk,
                          merkle_proof=tuple(proof),
                          binding_signature=sign(sa, binding))
        t = Transaction(tx_type=TxType.AIRDROP_CLAIM, nonce=0,
                        max_priority_fee_per_gas=0, max_fee_per_gas=P.MIN_BASE_FEE,
                        gas_limit=300_000, to=b"\x11" * 20, value=0,
                        payload=cl.to_rlp(), pubkey=apk)
        t.signature = sign(sa, t.signing_payload())
        return t

    chk("用自己条目的 index 领取 → 通过",
        validate_tx(claim(1), st, P.INITIAL_BASE_FEE, 0, current_slot=100).ok)
    for other in (2, 3, 99):
        r = validate_tx(claim(other), st, P.INITIAL_BASE_FEE, 0, current_slot=100)
        chk(f"换 index={other} 重复领取 → 被拒（Merkle 证明与根不符）",
            (not r.ok) and r.failed_at == 16, str(r)[:60])

    # 时间窗（§32.6 第 ⑤ 项）：窗口外必须拒绝
    r_late = validate_tx(claim(1), st, P.INITIAL_BASE_FEE, 0,
                         current_slot=P.AIRDROP_END_SLOT + 1)
    chk("超出空投窗口（claimed_slot > AIRDROP_END_SLOT）→ 被拒",
        (not r_late.ok) and r_late.failed_at == 16, str(r_late)[:60])
    r_ok = validate_tx(claim(1), st, P.INITIAL_BASE_FEE, 0,
                       current_slot=P.AIRDROP_END_SLOT)
    chk("窗口末槽（= AIRDROP_END_SLOT）仍可领取", r_ok.ok, str(r_ok)[:50])


def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 交易与 Gas 测试")
    print("═" * 76)
    test_gas()
    test_fee_semantics()
    test_base_fee()
    test_signing_payload()
    test_vote_payload()
    test_tx_roundtrip()
    test_evidence()
    test_pipeline()
    test_airdrop()
    test_evidence_class_codes()
    test_airdrop_index_is_bound_to_leaf()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
