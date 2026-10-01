# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 状态层测试
====================================

覆盖规范 §19（状态模型）、§20.5（验证者集合承诺）、§32（创世）。

本文件重点验证**五条容易写错的不变量**：
    1. 状态根必须与插入顺序无关（否则独立实现会产生不同根）
    2. `total_supply` 必须恒等于全体余额 + 金库 + 质押 + 解绑冻结之和（规范 §19.5）
    3. 账户的 `validator_key` 必须等于 `Hash(RLP(ValidatorRecord))`（规范 §19.2）
    4. 账户回收是**状态转移的一部分**，不是可选优化（规范 §19.3）
    5. 法定数运算必须在 atom 粒度（规范 §9.1 BUG-35）

运行：python3 -m tests.test_state
"""

from __future__ import annotations

import sys

from agora import params as P
from agora.codec import RLPDecodeError, decode, encode
from agora.crypto import address_from_pubkey, keccak256, publickey_from_seed
from agora.state import (
    Account, AirdropEntry, GenesisAllocation, PendingSlash, SnapshotSet, State, SystemState,
    STATUS_BONDED, STATUS_UNBONDED, STATUS_UNBONDING, ValidatorRecord,
    Account as _Acc,
    airdrop_merkle_root, build_genesis_state, genesis_hash,
    meets_account_pruning_rule, validate_genesis_closure, validator_set_commitment,
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


def pk(seed_byte: int) -> bytes:
    return publickey_from_seed(bytes([seed_byte]) * 32)


def addr(seed_byte: int) -> bytes:
    return address_from_pubkey(pk(seed_byte))


def make_alloc(n_validators: int = 4, stake_agora: int = 64,
               airdrop: int = 0) -> GenesisAllocation:
    pks = [pk(i) for i in range(1, n_validators + 1)]
    stake = stake_agora * P.ATOM_PER_AGORA
    total_stake = stake * n_validators
    airdrop_entries = []
    if airdrop:
        airdrop_entries = [AirdropEntry(index=i + 1, pubkey=pk(100 + i), amount=airdrop // 4,
                                        gas_allowance=200_000 * P.MIN_BASE_FEE,
                                        note=f"user-{i}")
                           for i in range(4)]
        airdrop = sum(e.amount for e in airdrop_entries)
    ga_total = sum(e.gas_allowance for e in airdrop_entries)
    rest = P.INITIAL_SUPPLY - total_stake - airdrop - ga_total
    each = rest // n_validators
    # 把除法余数补到第一个地址，保证精确闭合
    balances = [(pks[0], each + (rest - each * n_validators))]
    balances += [(p, each) for p in pks[1:]]
    return GenesisAllocation(validators=[(p, stake) for p in pks],
                             balances=balances, airdrop=airdrop_entries)


# ── 1. RLP 往返 ─────────────────────────────────────────────────────

def test_rlp_roundtrip():
    print("\n1) RLP 编解码往返（规范 §19.2 / §19.4 / §19.5）")
    a = Account(nonce=7, balance=123456789, validator_key=keccak256(b"v"), system_key=b"")
    chk("Account 往返一致", Account.from_rlp(a.to_rlp()) == a)
    a0 = Account()
    chk("空 Account 往返一致", Account.from_rlp(a0.to_rlp()) == a0)
    chk("Account 的 rlp_hash 稳定", a.rlp_hash() == keccak256(a.to_rlp()))
    try:
        Account.from_rlp(P.__class__ and __import__("agora.codec", fromlist=["encode"]).encode([1, 2]))
        chk("畸形 Account 被拒", False)
    except RLPDecodeError:
        chk("畸形 Account 被拒", True)

    v = ValidatorRecord(pubkey=pk(1), effective_stake=64 * P.ATOM_PER_AGORA,
                        unbonding_balance=5, status=STATUS_BONDED,
                        unbond_request_slot=1, unbond_complete_slot=2,
                        last_slashable_slot=3, inactivity_streak=4,
                        slashed_total=5, is_founder=1)
    chk("ValidatorRecord 往返一致", ValidatorRecord.from_rlp(v.to_rlp()) == v)
    chk("ValidatorRecord.status_name", v.status_name == "BONDED")
    chk("ValidatorRecord.voting_power = effective_stake",
        v.voting_power() == 64 * P.ATOM_PER_AGORA)
    un = ValidatorRecord(pubkey=pk(1), effective_stake=100, status=STATUS_UNBONDED)
    chk("非 BONDED 的投票权为 0", un.voting_power() == 0)

    ps = PendingSlash(offender=addr(1), evidence_class="DOUBLE_PREVOTE",
                      offense_slot=999, recorded_base=64 * P.ATOM_PER_AGORA,
                      submitter=addr(2))
    chk("PendingSlash 往返一致（含类别名）",
        PendingSlash.from_rlp(ps.to_rlp()) == ps)
    chk("PendingSlash 去重键 = (offender, class, offense_slot)",
        ps.dedup_key() == (addr(1), "DOUBLE_PREVOTE", 999))
    try:
        PendingSlash.from_rlp(__import__("agora.codec", fromlist=["encode"]).encode(
            [addr(1), 99, 1, 1, addr(2)]))
        chk("非法罚没类别码被拒", False)
    except RLPDecodeError:
        chk("非法罚没类别码被拒", True)

    recs = [ValidatorRecord(pubkey=pk(1), effective_stake=100, status=STATUS_BONDED).to_rlp(),
            ValidatorRecord(pubkey=pk(2), effective_stake=200, status=STATUS_BONDED).to_rlp()]
    snap = SnapshotSet(membership=sorted([addr(1), addr(2)]),
                       voting_power=sorted([(addr(1), 100), (addr(2), 200)]),
                       staked_supply=300, records=recs)
    s = SystemState(epoch_current=5, total_supply=123, snapshot=snap,
                    pending_slashes=[ps], settled_slashes=[(addr(1), "SEVERE", 7)],
                    airdrop_root=b"\xaa" * 32, airdrop_pending=9,
                    airdrop_claimed=[(addr(3), 1)])
    chk("SystemState 往返一致", SystemState.from_rlp(s.to_rlp()) == s)
    chk("SystemState.total_voting_power = 300", s.total_voting_power() == 300)
    chk("SystemState.quorum = ceil(2×300/3) = 200", s.quorum() == 200)
    chk("SystemState.voting_power_of", s.voting_power_of(addr(2)) == 200
        and s.voting_power_of(addr(9)) == 0)
    chk("SnapshotSet.record_of 可取出罚没基数来源",
        s.snapshot.record_of(addr(1)).effective_stake == 100)
    chk("向后兼容属性 epoch_set_vp 可用",
        s.epoch_set_vp == s.snapshot.voting_power
        and s.epoch_set_membership == s.snapshot.membership)


# ── 2. 状态根确定性 ─────────────────────────────────────────────────

def test_state_root_determinism():
    print("\n2) 状态根确定性（同一键值集合 ⇒ 同一根）")
    alloc = make_alloc(4)
    st1, _ = build_genesis_state(alloc)
    st2, _ = build_genesis_state(alloc)
    chk("同配置两次构建 → 同一 state_root", st1.state_root == st2.state_root,
        st1.state_root.hex()[:16] + "…")

    # 打乱输入顺序必须得到同一根
    rev = GenesisAllocation(validators=list(reversed(alloc.validators)),
                            balances=list(reversed(alloc.balances)))
    st3, _ = build_genesis_state(rev)
    chk("打乱验证者与余额顺序 → 同一 state_root", st1.state_root == st3.state_root)
    chk("打乱顺序 → 同一 validator_set_commitment",
        st1.validator_set_commitment() == st3.validator_set_commitment())
    chk("打乱顺序 → 同一 genesis_hash",
        genesis_hash(st1, alloc) == genesis_hash(st3, rev))

    # 手工构造一组账户，正反两种插入顺序
    items = [(addr(i), Account(nonce=i, balance=i * 1000).to_rlp()) for i in range(1, 40)]
    from agora.codec import MerklePatriciaTrie
    t1 = MerklePatriciaTrie()
    for a, r in items:
        t1.put(a, r)
    t2 = MerklePatriciaTrie()
    for a, r in reversed(items):
        t2.put(a, r)
    chk("正/反插入 39 个账户 → 同一根", t1.root == t2.root)

    # 任何一处改动必须改变根
    st4, _ = build_genesis_state(alloc)
    st4.mint(addr(1), 1)                        # 加 1 atom
    chk("余额 +1 atom → 根改变", st4.state_root != st1.state_root)


# ── 3. 供应量守恒 ───────────────────────────────────────────────────

def test_supply_conservation():
    print("\n3) 供应量守恒（规范 §19.5）")
    for n in (4, 5, 10):
        st, _ = build_genesis_state(make_alloc(n))
        ok, counted, recorded = st.check_supply_conservation()
        chk(f"{n} 验证者创世：统计值 == total_supply", ok,
            f"{counted // P.ATOM_PER_AGORA:,} AGORA")

    st, _ = build_genesis_state(make_alloc(4, airdrop=1_000_000 * P.ATOM_PER_AGORA))
    ok, counted, recorded = st.check_supply_conservation()
    chk("含空投金库时仍守恒", ok, f"{counted // P.ATOM_PER_AGORA:,} AGORA")
    chk("金库余额 = airdrop_pending",
        st.account_or_empty(P.AIRDROP_VAULT_ADDRESS).balance == st.system.airdrop_pending)

    # 发行 / 销毁 / 转账：三者都必须保持守恒（mint/burn 同时改 total_supply）
    st.mint(addr(1), 500, reason="test-issuance")
    ok, counted, recorded = st.check_supply_conservation()
    chk("mint 后仍守恒（total_supply 同步增加）", ok and recorded == P.INITIAL_SUPPLY + 500)
    st.burn(addr(1), 300, "dust")
    ok, counted, recorded = st.check_supply_conservation()
    chk("burn 后仍守恒（total_supply 同步减少）",
        ok and recorded == P.INITIAL_SUPPLY + 200
        and st.system.total_burned_dust == 300)
    st.transfer(addr(1), addr(2), 100)
    ok, counted, recorded = st.check_supply_conservation()
    chk("transfer 后仍守恒且 total_supply 不变",
        ok and recorded == P.INITIAL_SUPPLY + 200)
    # 凭空造币的接口必须已被移除
    for bad in ("credit", "debit"):
        try:
            getattr(st, bad)(addr(1), 1)
            chk(f"已移除会破坏守恒的 {bad}()", False, "竟然仍可调用")
        except RuntimeError:
            chk(f"已移除会破坏守恒的 {bad}()", True)


# ── 4. validator_key 完整性 ─────────────────────────────────────────

def test_validator_key():
    print("\n4) validator_key == Hash(RLP(ValidatorRecord))（规范 §19.2）")
    st, _ = build_genesis_state(make_alloc(4))
    bad = [a.hex()[:12] for a in st.validators if not st.check_validator_key(a)]
    chk("全部创始验证者的 key 一致", not bad, str(bad) if bad else f"{len(st.validators)} 个")
    rec = st.get_validator(addr(1))
    acc = st.get_account(addr(1))
    chk("账户 validator_key 等于记录哈希", acc.validator_key == rec.rlp_hash())
    # 篡改记录后应立即被发现
    rec2 = ValidatorRecord(**{**rec.__dict__, "effective_stake": rec.effective_stake + 1})
    st.validators[addr(1)] = rec2
    chk("篡改验证者记录后 key 校验失败", not st.check_validator_key(addr(1)))
    st.validators[addr(1)] = rec


# ── 5. 账户回收 ─────────────────────────────────────────────────────

def test_account_pruning():
    print("\n5) 账户回收（规范 §19.3，属状态转移的一部分）")
    chk("空账户满足回收条件", meets_account_pruning_rule(Account()))
    chk("有余额不回收", not meets_account_pruning_rule(Account(balance=1)))
    chk("有 nonce 不回收", not meets_account_pruning_rule(Account(nonce=1)))
    chk("有 validator_key 不回收",
        not meets_account_pruning_rule(Account(validator_key=keccak256(b"x"))))
    chk("有 system_key 不回收",
        not meets_account_pruning_rule(Account(system_key=keccak256(b"x"))))

    st, _ = build_genesis_state(make_alloc(4))
    root_before = st.state_root
    st.mint(addr(50), 100)                     # 造出一个新账户（同时 total_supply +100）
    chk("新账户存在", st.get_account(addr(50)) is not None)
    chk("新账户使状态根改变", st.state_root != root_before)
    st.burn(addr(50), 100, "dust")             # 清零（余额 0、nonce 0、无 key）
    chk("清零后账户被自动回收，状态根回到原值", st.state_root == root_before,
        "证明回收是状态转移的一部分，而非可选优化")
    chk("回收后账户确实不存在", st.get_account(addr(50)) is None)

    # 系统账户绝不被回收
    st2, _ = build_genesis_state(make_alloc(4))
    chk("系统账户存在且 system_key 非空",
        st2.get_account(P.SYSTEM_ADDRESS) is not None
        and bool(st2.get_account(P.SYSTEM_ADDRESS).system_key))
    chk("金库地址不是系统地址", P.AIRDROP_VAULT_ADDRESS != P.SYSTEM_ADDRESS)


# ── 6. 法定数粒度 ───────────────────────────────────────────────────

def test_quorum_granularity():
    print("\n6) 法定数运算粒度 = atom（规范 §9.1 BUG-35）")
    st, _ = build_genesis_state(make_alloc(4))
    S = st.system.total_voting_power()
    q = st.system.quorum()
    chk("S_epoch = 256 × 10^18 atom", S == 256 * P.ATOM_PER_AGORA)
    chk("QUORUM 按 atom 计算 = 170,666,666,666,666,666,667",
        q == 170666666666666666667, f"{q}")
    chk("QUORUM ≠ 整币粒度结果（171 AGORA）", q != 171 * P.ATOM_PER_AGORA,
        "整币粒度会高估 333,333,333,333,333,333 atom")
    chk("3 人可达 / 2 人不可达",
        3 * 64 * P.ATOM_PER_AGORA >= q > 2 * 64 * P.ATOM_PER_AGORA)
    # 构造会真实分歧的例子
    S2 = 100 * P.ATOM_PER_AGORA
    a = P.quorum(S2)
    b = 67 * P.ATOM_PER_AGORA
    chk("100 AGORA 时会真实分歧（原子 66.67 vs 整币 67）", a != b,
        f"原子={a} 整币={b}")


# ── 7. 创世校验 ─────────────────────────────────────────────────────

def test_genesis_validation():
    print("\n7) 创世硬约束（规范 §32.2 / §32.7）")
    chk("合法配置无错误", not validate_genesis_closure(make_alloc(4)))

    bad3 = make_alloc(3)
    errs = validate_genesis_closure(bad3)
    chk("3 名创始验证者被拒", any("≥ 4" in e for e in errs), errs[0] if errs else "")
    try:
        build_genesis_state(bad3, strict=True)
        chk("strict 模式下抛异常", False)
    except ValueError:
        chk("strict 模式下抛异常", True)
    st3, errs3 = build_genesis_state(bad3, strict=False)
    chk("non-strict 模式返回错误列表", bool(errs3))

    # 单人占 ≥1/3
    pks = [pk(1), pk(2), pk(3), pk(4)]
    unbal = GenesisAllocation(
        validators=[(pks[0], 256 * P.ATOM_PER_AGORA)] +
                   [(p, 1 * P.ATOM_PER_AGORA) for p in pks[1:]],
    )
    errs = validate_genesis_closure(unbal)
    chk("单人权益 ≥ 1/3 被拒", any("1/3" in e for e in errs), errs[0] if errs else "")

    # 不闭合
    nonclose = make_alloc(4)
    nonclose.balances[0] = (nonclose.balances[0][0], nonclose.balances[0][1] + 1)
    errs = validate_genesis_closure(nonclose)
    chk("金额不闭合被拒", any("不闭合" in e for e in errs), errs[0] if errs else "")

    # 时间戳不符
    wrong_ts = make_alloc(4)
    wrong_ts.genesis_timestamp = 0
    errs = validate_genesis_closure(wrong_ts)
    chk("GenesisTimestamp 不符被拒", any("GenesisTimestamp" in e for e in errs))

    # 空投超上限
    over = make_alloc(4, airdrop=int(P.AIRDROP_MAX_SHARE * 1.1))
    errs = validate_genesis_closure(over)
    chk("空投超 20% 上限被拒", any("空投" in e for e in errs), errs[0] if errs else "")

    # 重复地址
    dup = GenesisAllocation(validators=[(pk(1), 64 * P.ATOM_PER_AGORA)] * 4)
    errs = validate_genesis_closure(dup)
    chk("重复验证者地址被拒", any("重复" in e for e in errs))


# ── 8. 承诺与空投 ───────────────────────────────────────────────────

def test_commitments():
    print("\n8) 承诺（规范 §20.5）与空投 Merkle 根（规范 §32.5）")
    recs = [ValidatorRecord(pubkey=pk(i), effective_stake=(10 + i) * P.ATOM_PER_AGORA,
                            status=STATUS_BONDED) for i in range(1, 6)]
    c1 = validator_set_commitment(recs)
    chk("同一集合 → 同一承诺", c1 == validator_set_commitment(list(reversed(recs))))
    chk("改一个质押额 → 承诺改变",
        c1 != validator_set_commitment(
            [ValidatorRecord(**{**r.__dict__, "effective_stake": r.effective_stake + 1})
             for r in recs]))
    chk("承诺为 32 字节", len(c1) == 32)

    entries = [AirdropEntry(index=i + 1, pubkey=pk(100 + i), amount=(i + 1) * P.ATOM_PER_AGORA,
                            gas_allowance=0, note=f"u{i}") for i in range(6)]
    r1 = airdrop_merkle_root(entries)
    chk("空投根与顺序无关", r1 == airdrop_merkle_root(list(reversed(entries))))
    chk("空投根为 32 字节", len(r1) == 32)
    chk("改金额 → 根改变",
        r1 != airdrop_merkle_root(
            [AirdropEntry(index=e.index, pubkey=e.pubkey, amount=e.amount + 1,
                          gas_allowance=e.gas_allowance, note=e.note) for e in entries]))
    chk("空表 → 全零根", airdrop_merkle_root([]) == b"\x00" * 32)
    # 独立重算（不复用被测量对象）：标签前置 + 显式 u256 宽度（§20.1 / §32.5）
    _chain = __import__("agora.crypto", fromlist=["chain"]).chain
    # 叶子**必须**含 index（BUG-87）：换 index 就无法复现该叶子，因此同一份权益
    # 不能被重复领取。判据用**手写**的规范字面，而不是复用实现里的 `leaf()`。
    chk("叶子 = Hash(CHAIN(tag, u64(index), pubkey, u256(amount), u256(gas_allowance)))",
        entries[0].leaf() == keccak256(
            P.TAG_AIRDROP + _chain(("u64", entries[0].index),
                                   entries[0].pubkey,
                                   ("u256", entries[0].amount),
                                   ("u256", entries[0].gas_allowance))))
    chk("index 不同 ⇒ 叶子不同（这正是防重复领取的机制）",
        entries[0].leaf() != AirdropEntry(entries[0].pubkey, entries[0].amount,
                                          entries[0].gas_allowance, "",
                                          entries[0].index + 1).leaf())
    # 位置参数错位必须被立即发现
    try:
        AirdropEntry(pk(1), 1000, "这是 note 不是 gas_allowance", index=1)
        chk("位置参数错位被拒绝", False)
    except TypeError:
        chk("位置参数错位被拒绝", True, "AirdropEntry 会指出字段顺序")


# ── 9. 创世集合快照 ─────────────────────────────────────────────────

def test_genesis_snapshot():
    print("\n9) 创世集合快照（规范 §7.1 的 E₀ 情形）")
    alloc = make_alloc(4)
    st, _ = build_genesis_state(alloc)
    sys_ = st.system
    chk("epoch_set_membership 含全部创始验证者", len(sys_.epoch_set_membership) == 4)
    chk("epoch_set_membership 按地址升序",
        sys_.epoch_set_membership == sorted(sys_.epoch_set_membership))
    chk("epoch_set_vp 按地址升序",
        [a for a, _ in sys_.epoch_set_vp] == sorted(a for a, _ in sys_.epoch_set_vp))
    chk("epoch_set_membership 与 epoch_set_vp 地址集合一致",
        set(sys_.epoch_set_membership) == {a for a, _ in sys_.epoch_set_vp})
    chk("S_epoch = 4 × 64 AGORA", sys_.total_voting_power() == 256 * P.ATOM_PER_AGORA)
    chk("epoch_current = 0（创世块 claimed_slot = 0）", sys_.epoch_current == 0)
    chk("total_supply = INITIAL_SUPPLY", sys_.total_supply == P.INITIAL_SUPPLY)


# ── 规范 §19.2 的**字面**叶值（PROJECT_REVIEW R-1 的回归测试）──────────────
#
# 为什么必须有这一节：改动前，`Account.to_rlp` 会把 `balance` 做 zigzag 翻倍、
# 并把"无此键"写成 0 长度。改完之后**649 项测试全部照旧通过** —— 因为没有任何
# 一项把叶值钉在规范给出的字节上。于是同一处误解可以在两个实现里同时存在、
# 测试全绿、而链永远无法互通。本节用**手写的期望字节**把这件事钉死。

def test_state_leaf_is_spec_literal():
    print("\n10) 账户叶值 == 规范 §19.2 字面（R-1 回归）")
    H = keccak256(b"")

    # 期望字节由规范文本直接写出：RLP([0, 1000, Hash(""), Hash("")])
    want = bytes.fromhex(
        "f846"                                    # 列表，总长 0x46
        "80"                                      # nonce = 0
        "8203e8"                                  # balance = 1000（**原值**，不翻倍）
        "a0" + H.hex() +                          # validator_key = Hash("")
        "a0" + H.hex())                           # system_key    = Hash("")
    got = Account(nonce=0, balance=1000).to_rlp()
    chk("叶值逐字节等于规范字面（含 Hash(\"\") 空键）", got == want,
        got.hex() if got != want else "f84680 8203e8 a0Hash… a0Hash…")
    chk("余额**不做**任何变换：1000 编码为 8203e8（2000 会是 8207d0）",
        b"\x82\x03\xe8" in got and b"\x82\x07\xd0" not in got)
    chk("两个键字段恒为 32 字节", decode_len_ok(got))
    chk("往返后余额仍为 1000", Account.from_rlp(got).balance == 1000)
    chk("『无此键』在内部表示为空、编码为 Hash(\"\")",
        Account.from_rlp(got).validator_key == b""
        and Account.from_rlp(got).system_key == b"")

    # 负余额必须被拒绝（规范 §34 A11：unsigned 256-bit）
    try:
        Account(nonce=0, balance=-1).to_rlp()
        neg_ok = False
    except ValueError:
        neg_ok = True
    chk("负余额被拒绝（不得再用 zigzag 藏起来）", neg_ok)

    # 0 长度的键必须被拒绝（否则叶值有第二种合法编码）
    short = encode([0, 1000, b"", b""])
    try:
        Account.from_rlp(short)
        short_ok = False
    except RLPDecodeError:
        short_ok = True
    chk("解码时拒绝 0 长度的键（防止叶值出现第二种编码）", short_ok)

    # 创世状态根与创世哈希必须与**固定值**一致（改动叶值即在此处报警）
    st, _ = build_genesis_state(GenesisAllocation(
        validators=[(publickey_from_seed(bytes([i]) * 32), 64 * P.ATOM_PER_AGORA)
                    for i in (1, 2, 3, 4)],
        balances=[(publickey_from_seed(bytes([1]) * 32),
                   P.INITIAL_SUPPLY - 4 * 64 * P.ATOM_PER_AGORA)],
        genesis_timestamp=P.GENESIS_TIMESTAMP), strict=True)
    chk("创世状态根为已知答案（改叶值/改 MPT 必然报警）",
        st.state_root.hex() == GENESIS_ROOT_KNOWN, st.state_root.hex()[:24] + "…")
    chk("系统账户的 system_key == Hash(RLP(SystemState))",
        st.account_or_empty(P.SYSTEM_ADDRESS).system_key == keccak256(st.system.to_rlp()))


# 由规范字面编码 + 已知答案固定下来的创世根（改动叶值/MPT 会立刻失败）
GENESIS_ROOT_KNOWN = "4630e0b78bda38e0721ff1ad8fbfc1d0791036c323fa74719ee479b876db9bac"


def decode_len_ok(leaf: bytes) -> bool:
    from agora.codec import decode as _d
    it = _d(leaf)
    return len(it) == 4 and len(it[2]) == 32 and len(it[3]) == 32


# ── 结算扣款必须结构性有界（PROJECT_REVIEW R-5 的回归测试）──────────────

def test_settlement_deduction_is_bounded():
    print("\n11) 结算扣款按人聚合、且不超过可用资金（R-5 回归）")
    from agora.block import settle_epoch
    stake = 64 * P.ATOM_PER_AGORA
    pks = [publickey_from_seed(bytes([i]) * 32) for i in (1, 2, 3, 4)]
    addrs = [address_from_pubkey(p) for p in pks]
    alloc = GenesisAllocation(
        validators=[(p, stake) for p in pks],
        balances=[(pks[0], P.INITIAL_SUPPLY - 4 * stake)],
        genesis_timestamp=P.GENESIS_TIMESTAMP)

    single = P.slash_amount(stake, "DOUBLE_PREVOTE")
    for n in (1, 4, 25, 30, 200):
        st, _ = build_genesis_state(alloc, strict=True)
        for i in range(n):
            st.system.pending_slashes.append(PendingSlash(
                offender=addrs[1], evidence_class="DOUBLE_PREVOTE",
                offense_slot=100 + i, recorded_base=stake, submitter=addrs[2]))
        before = st.system.total_supply
        settle_epoch(st, current_slot=P.EPOCH_LENGTH)
        burned = (before - st.system.total_supply) / P.ATOM_PER_AGORA
        cons, counted, recorded = st.check_supply_conservation()
        chk(f"同一人 {n:>3} 条罚没：守恒等式成立", cons,
            f"申请 {n * single / P.ATOM_PER_AGORA:.2f} → 实际销毁 {burned:.2f} AGORA")
        chk(f"同一人 {n:>3} 条罚没：销毁额 ≤ 可用资金（64 AGORA 的 80%）",
            burned <= stake / P.ATOM_PER_AGORA * 0.8 + 1e-9, f"{burned:.2f}")

    # 不活跃惩罚的公式值可以超过全部资金 ⇒ 必须同样有界
    st, _ = build_genesis_state(alloc, strict=True)
    rec = st.get_validator(addrs[1])
    rec.inactivity_streak = 20000
    st.set_validator(addrs[1], rec)
    want = P.inactivity_deduction(stake, 20000)
    before = st.system.total_supply
    settle_epoch(st, current_slot=P.EPOCH_LENGTH)
    cons, counted, recorded = st.check_supply_conservation()
    chk("不活跃惩罚超过可用资金时：扣满即可、守恒仍成立", cons,
        f"公式 {want / P.ATOM_PER_AGORA:.2f} > 可用 {stake / P.ATOM_PER_AGORA:.0f}，"
        f"实际销毁 {(before - st.system.total_supply) / P.ATOM_PER_AGORA:.2f}")

    # 被罚没者**不在快照内**（已解绑/剔除）时也必须有人被扣钱，否则守恒破坏
    st, _ = build_genesis_state(alloc, strict=True)
    st.system.pending_slashes.append(PendingSlash(
        offender=addrs[1], evidence_class="DOUBLE_PREVOTE", offense_slot=5,
        recorded_base=stake, submitter=addrs[2]))
    # 把 addrs[1] 挪出快照：清空其质押并移入余额
    rec = st.get_validator(addrs[1])
    st._credit_neutral(addrs[1], rec.effective_stake + rec.unbonding_balance)
    rec.effective_stake = 0
    rec.unbonding_balance = 0
    rec.status = STATUS_UNBONDED
    st.set_validator(addrs[1], rec)
    snap = st.system.snapshot
    st.system.snapshot = SnapshotSet(
        membership=[a for a in snap.membership if a != addrs[1]],
        voting_power=[(a, v) for a, v in snap.voting_power if a != addrs[1]],
        staked_supply=snap.staked_supply - stake,
        records=[r for a, r in zip(snap.membership, snap.records) if a != addrs[1]])
    before = st.system.total_supply
    settle_epoch(st, current_slot=P.EPOCH_LENGTH)
    cons, counted, recorded = st.check_supply_conservation()
    chk("被罚没者已不在快照内时：仍从其余额扣款，守恒成立", cons,
        f"实际销毁 {(before - st.system.total_supply) / P.ATOM_PER_AGORA:.2f} AGORA")


def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 状态层测试")
    print("═" * 76)
    test_rlp_roundtrip()
    test_state_root_determinism()
    test_supply_conservation()
    test_validator_key()
    test_account_pruning()
    test_quorum_granularity()
    test_genesis_validation()
    test_commitments()
    test_genesis_snapshot()
    test_state_leaf_is_spec_literal()
    test_settlement_deduction_is_bounded()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
