# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 交易池测试（`agora/mempool.py`）
===============================================

交易池**不是共识**（规范 §16.5），但它错了会**间接**破坏共识：
提案者把一笔执行必然失败的交易塞进区块 ⇒ **整个区块被判无效** ⇒ 白掉一轮。
因此本文件只盯住三件事：

1. **准入纪律**：重复、重放、nonce 空洞、签名无效、余额不足 —— 一律不入池；
2. **确定性**：同样的（池内容, 状态, base_fee, 槽）必须选出**逐字节相同**的列表
   （否则同一提案者两次出块会给出不同区块，投票被打散 —— BUG-46 的形态）；
3. **有界**：容量上限必须真的生效，且淘汰规则也是确定性的。

运行：python3 tests/test_mempool.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agora import params as P
from agora.crypto_backend import address_from_pubkey, publickey_from_seed, sign
from agora.gas import TxType
from agora.mempool import MAX_NONCE_GAP, TxPool
from agora.state import GenesisAllocation, build_genesis_state
from agora.tx import Transaction


def _bump_nonce(state, addr, nonce: int) -> None:
    """把账户 nonce 设成指定值。

    ⚠ **必须用 `set_account`**：`get_account()` 返回的是从 RLP 解码出来的**副本**，
    直接改它不会有任何效果（首版就这么写过：测试看起来"设置了 nonce"，
    实际状态没变，于是那条用例测的根本不是它说的东西）。
    """
    acc = state.get_account(addr) or _Account()
    acc.nonce = nonce
    state.set_account(addr, acc)


from agora.state import Account as _Account  # noqa: E402

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


SEEDS = [bytes([i]) * 32 for i in (1, 2, 3, 4)]
PKS = [publickey_from_seed(s) for s in SEEDS]
ADDRS = [address_from_pubkey(pk) for pk in PKS]
RICH_SEED = bytes([9]) * 32
RICH_PK = publickey_from_seed(RICH_SEED)
RICH = address_from_pubkey(RICH_PK)
TO = address_from_pubkey(publickey_from_seed(bytes([0xEE]) * 32))


def make_state():
    st, errs = build_genesis_state(GenesisAllocation(
        validators=[(pk, 64 * A) for pk in PKS],
        balances=[(RICH_PK, P.INITIAL_SUPPLY - 4 * 64 * A)],
        genesis_timestamp=P.GENESIS_TIMESTAMP), strict=True)
    assert not errs, errs
    return st


def make_tx(nonce=0, value=1 * A, seed=RICH_SEED, pk=RICH_PK, to=TO,
            prio=0, max_fee=None, gas_limit=100_000, tx_type=TxType.TRANSFER):
    tx = Transaction(tx_type=int(tx_type), nonce=nonce,
                     max_priority_fee_per_gas=prio,
                     max_fee_per_gas=(P.INITIAL_BASE_FEE * 2 if max_fee is None else max_fee),
                     gas_limit=gas_limit, to=to, value=value, pubkey=pk)
    tx.signature = sign(seed, tx.signing_payload())
    return tx


def test_admission():
    print("\n1) 准入纪律（进不来的一定有原因）")
    st = make_state()
    pool = TxPool()
    tx = make_tx()
    ok, why = pool.add(tx, st, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    chk("合法转账入池", ok and why == "accepted", why)

    ok2, why2 = pool.add(tx, st, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    chk("重复提交不入池，但也不是错误（幂等）", (not ok2) and why2 == "duplicate")

    # 重放：nonce 低于链上 nonce（用**新池**，否则命中的是"重复"而不是"重放"）
    st2 = make_state()
    _bump_nonce(st2, RICH, 5)
    ok3, why3 = TxPool().add(tx, st2, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    chk("nonce 低于链上 ⇒ 拒绝（重放）", (not ok3) and "重放" in why3, why3)

    # ── 队列语义（这是交易池的正常形态，不是"空洞"）──
    # 同一发送者的第 2、3 笔应当能**先排队**（网络乱序是常态），
    # 但在前序交易到齐之前**不得被选中** —— 选中它会让整个区块无效。
    pool2 = TxPool()
    ok_a, _ = pool2.add(make_tx(nonce=1), st, base_fee=P.INITIAL_BASE_FEE,
                        current_slot=1)
    chk("后序交易（nonce=1）可以先入池排队", ok_a)
    chk("但断档未填时**不会被选中**（选它会让整块无效）",
        pool2.select(st, P.INITIAL_BASE_FEE, 1) == [])
    ok_b, _ = pool2.add(make_tx(nonce=2), st, base_fee=P.INITIAL_BASE_FEE,
                        current_slot=1)
    chk("更后序（nonce=2）同样可以排队", ok_b)
    ok_c, _ = pool2.add(make_tx(nonce=0), st, base_fee=P.INITIAL_BASE_FEE,
                        current_slot=1)
    chk("补齐前序（nonce=0）", ok_c)
    sel2 = pool2.select(st, P.INITIAL_BASE_FEE, 1)
    chk("★补齐之后，三笔按 nonce 升序一起被选中",
        [t.nonce for t in sel2] == [0, 1, 2], str([t.nonce for t in sel2]))

    # 前瞻上界：太超前的 nonce 必须被拒（否则可被用来塞满池子）
    far = TxPool()
    ok_far, why_far = far.add(make_tx(nonce=MAX_NONCE_GAP + 5), st,
                              base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    chk("nonce 过于超前 ⇒ 拒绝（有界，防止塞满）",
        (not ok_far) and "超前" in why_far, why_far)

    # 签名无效
    bad = make_tx(nonce=0)
    bad.signature = bytes(64)
    ok6, why6 = pool.add(bad, st, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    chk("签名无效 ⇒ 拒绝（并给出第 5 项）", (not ok6) and "第 5 项" in why6, why6)

    # 余额不足
    poor_seed = bytes([0x42]) * 32
    poor_pk = publickey_from_seed(poor_seed)
    st3 = make_state()
    st3.mint(address_from_pubkey(poor_pk), 10)          # 只有 10 atom
    poor_tx = make_tx(nonce=0, value=1 * A, seed=poor_seed, pk=poor_pk)
    ok7, why7 = pool.add(poor_tx, st3, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    chk("余额不足 ⇒ 拒绝", not ok7, why7[:60])

    # 基础费门槛
    cheap = make_tx(nonce=0, max_fee=P.INITIAL_BASE_FEE // 2)
    ok8, why8 = pool.add(cheap, st, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    chk("max_fee 低于基础费 ⇒ 拒绝（第 11 项）", (not ok8) and "第 11 项" in why8, why8)


def test_determinism_and_selection():
    print("\n2) 确定性挑选（同一提案者两次必须给出同一批、同一顺序）")
    st = make_state()
    txs = [make_tx(nonce=i, prio=(i % 3) * 1000) for i in range(5)]
    # 用**不同插入顺序**构造两个池（池内部顺序必须不影响结果）
    p1, p2 = TxPool(), TxPool()
    for t in txs:
        p1.add(t, st, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    for t in reversed(txs):
        p2.add(t, st, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    s1 = p1.select(st, P.INITIAL_BASE_FEE, 1)
    s2 = p2.select(st, P.INITIAL_BASE_FEE, 1)
    chk("插入顺序不影响选择结果",
        [t.tx_hash() for t in s1] == [t.tx_hash() for t in s2],
        f"{len(s1)} 笔")
    chk("重复调用给出逐字节相同的结果（同一区块哈希）",
        [t.to_rlp() for t in p1.select(st, P.INITIAL_BASE_FEE, 1)]
        == [t.to_rlp() for t in s1])
    chk("同一发送者的 nonce 严格升序（§22 第 10 项）",
        [t.nonce for t in s1] == sorted(t.nonce for t in s1),
        str([t.nonce for t in s1]))
    # 优先费高者先被选中
    hi = make_tx(nonce=0, prio=99_999, seed=bytes([0x77]) * 32,
                 pk=publickey_from_seed(bytes([0x77]) * 32))
    st_hi = make_state()
    st_hi.mint(address_from_pubkey(hi.pubkey), 100 * A)
    p3 = TxPool()
    p3.add(make_tx(nonce=0, prio=1), st_hi, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    p3.add(hi, st_hi, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    sel = p3.select(st_hi, P.INITIAL_BASE_FEE, 1)
    chk("优先费单价高者排在前面", sel and sel[0].max_priority_fee_per_gas == 99_999,
        f"首笔 prio={sel[0].max_priority_fee_per_gas if sel else None}")

    # 累计 gas 上限
    print("\n2b) 累计 gas 上限（MAX_GAS_PER_BLOCK）")
    st_big = make_state()
    pool_big = TxPool(max_txs=10_000)
    per = 46_000                                      # 新建账户（每笔的收款方都不同）
    n_fit = P.MAX_GAS_PER_BLOCK // per
    for i in range(n_fit + 5):
        to = address_from_pubkey(publickey_from_seed(i.to_bytes(32, "big")))
        pool_big.add(make_tx(nonce=i, to=to), st_big,
                     base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    # 同一发送者的 nonce 必须连续：上面把 nonce 都设成 0/1/2…，因此都能入池
    picked = pool_big.select(st_big, P.INITIAL_BASE_FEE, 1)
    gas = sum(t.gas_used(True) for t in picked)
    chk("选中集合的累计 gas ≤ 上限", gas <= P.MAX_GAS_PER_BLOCK,
        f"gas={gas:,} ≤ {P.MAX_GAS_PER_BLOCK:,}（{len(picked)} 笔）")
    chk("上限允许的笔数都被填满（不浪费区块空间）", len(picked) >= min(n_fit, len(pool_big)),
        f"选中 {len(picked)} / 池内 {len(pool_big)}")


def test_capacity_and_reap():
    print("\n3) 有界与清理（无界的池就是一条内存耗尽路径）")
    st = make_state()
    pool = TxPool(max_txs=2)
    t1 = make_tx(nonce=0, prio=1)
    t2 = make_tx(nonce=1, prio=2)
    t3 = make_tx(nonce=2, prio=3)
    for t in (t1, t2, t3):
        pool.add(t, st, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    chk("容量上限被遵守", len(pool) == 2, f"池内 {len(pool)}")
    chk("淘汰的是优先费最低的那笔（确定性规则）",
        t1.tx_hash() not in pool._txs, f"dropped_full={pool.stats.dropped_full}")

    pool2 = TxPool()
    pool2.add(make_tx(nonce=0), st, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    pool2.add(make_tx(nonce=1), st, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    chk("清理前池内有 2 笔", len(pool2) == 2)
    st_after = make_state()
    _bump_nonce(st_after, RICH, 1)                     # 链上已吃掉 nonce 0
    n = pool2.reap(st_after, base_fee=P.INITIAL_BASE_FEE)
    chk("上链后的交易被清理（否则会长期占位）", n >= 1 and len(pool2) <= 1,
        f"清理 {n} 笔，剩 {len(pool2)}")
    chk("已被链上越过的交易不再被选中",
        all(t.nonce >= 1 for t in pool2.select(st_after, P.INITIAL_BASE_FEE, 2)))


def test_reap_keeps_slot_dependent_txs():
    """**槽相关交易必须活过 reap**（BUG-96，端到端才暴露）。

    空投领取与提现的校验**必须**知道当前槽。`reap` 若漏传 `current_slot`，
    它们会以"第 16 项：缺少当前槽"失败并被**静默清出池子** ——
    表现为"提交后有时能上链、有时永远不上链"（取决于提交与下一个区块之间
    是否恰好发生了一次 reap）。这类间歇性缺陷在单测里很难撞到，
    因此这里把"提交 → reap → 仍在池中"这件事直接断言出来。
    """
    print("\n5) 槽相关交易必须活过 reap（BUG-96）")
    from agora.state import (AirdropEntry, airdrop_merkle_proof,
                             airdrop_merkle_root)
    from agora.tx import AirdropClaim

    bseed = bytes([0xA1]) * 32
    bpk = publickey_from_seed(bseed)
    baddr = address_from_pubkey(bpk)
    ga = 5 * 10 ** 15
    ents = [AirdropEntry(pubkey=bpk, amount=1000 * A, gas_allowance=ga, index=1)]
    st, _ = build_genesis_state(GenesisAllocation(
        validators=[(pk, 64 * A) for pk in PKS],
        balances=[(RICH_PK, P.INITIAL_SUPPLY - 4 * 64 * A - 1000 * A - ga)],
        airdrop=ents, genesis_timestamp=P.GENESIS_TIMESTAMP), strict=True)
    proof, _ = airdrop_merkle_proof(ents, 0)
    cl = AirdropClaim(index=1, amount=1000 * A, gas_allowance=ga, pubkey=bpk,
                      merkle_proof=tuple(proof))
    cl = AirdropClaim(index=1, amount=1000 * A, gas_allowance=ga, pubkey=bpk,
                      merkle_proof=tuple(proof),
                      binding_signature=sign(bseed, cl.binding_message(baddr)))
    tx = make_claim_like(cl, bseed, bpk, nonce=0)
    pool = TxPool()
    ok, why = pool.add(tx, st, base_fee=P.INITIAL_BASE_FEE, current_slot=5)
    chk("空投领取交易可以入池", ok, why)
    n = pool.reap(st, base_fee=P.INITIAL_BASE_FEE, current_slot=6)
    chk("★reap 之后它仍在池中（漏传 current_slot 会被静默清掉）",
        len(pool) == 1 and n == 0, f"清理 {n} 笔，池内 {len(pool)}")
    chk("它仍能被选中（可被打包）",
        [t.tx_hash() for t in pool.select(st, P.INITIAL_BASE_FEE, 6)] ==
        [tx.tx_hash()])
    # 缺槽时**不做基于校验的清理**（"无法判定"≠"无效"）
    pool2 = TxPool()
    pool2.add(tx, st, base_fee=P.INITIAL_BASE_FEE, current_slot=5)
    n2 = pool2.reap(st, base_fee=P.INITIAL_BASE_FEE)      # 不传槽
    chk("不传槽时也不清（不能把「无法判定」当成「无效」）",
        len(pool2) == 1 and n2 == 0, f"清理 {n2} 笔")


def make_claim_like(cl, seed, pubkey, nonce):
    """构造一笔已签名的 AIRDROP_CLAIM 交易（测试用）。"""
    from agora.gas import TxType
    tx = Transaction(tx_type=int(TxType.AIRDROP_CLAIM), nonce=nonce,
                     max_priority_fee_per_gas=0,
                     max_fee_per_gas=P.INITIAL_BASE_FEE * 2, gas_limit=100_000,
                     to=b"", value=0, payload=cl.to_rlp(), pubkey=pubkey)
    tx.signature = sign(seed, tx.signing_payload())
    return tx


def test_select_skips_gap():
    print("\n4) 白盒：池内出现「断档」时，选择器必须跳过而不是硬塞")
    st = make_state()
    pool = TxPool()
    pool.add(make_tx(nonce=0), st, base_fee=P.INITIAL_BASE_FEE, current_slot=1)
    # 绕过准入直接塞入 nonce=2（模拟"准入之后状态变了"的边界）
    gap = make_tx(nonce=2)
    pool._txs[gap.tx_hash()] = gap
    sel = pool.select(st, P.INITIAL_BASE_FEE, 1)
    chk("断档的交易不会被选中（选它会让整块无效）",
        [t.nonce for t in sel] == [0], str([t.nonce for t in sel]))


def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 交易池（§16.5，非共识部分）")
    print("═" * 76)
    test_admission()
    test_determinism_and_selection()
    test_capacity_and_reap()
    test_reap_keeps_slot_dependent_txs()
    test_select_skips_gap()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
