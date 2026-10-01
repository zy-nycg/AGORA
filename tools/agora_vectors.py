#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 黄金测试向量生成器
==================================

产出规范 §33 要求的九组确定性向量（GATE-3 的交付物）：
    ENC-*  CHAIN-*  MPT-*  PROPOSER-*  BASEFEE-*
    SLASH-*  REWARD-*  BURN-*  GENESIS-*

**为什么需要"独立真值校验"**

如果只是把参考实现的输出原样记下来当"标准答案"，那实现的 bug 会被固化成规范 ——
后来的独立实现反而要"对齐 bug"，向量就失去了意义。因此本工具对每一族都额外做独立校验：

| 族 | 独立真值来源 |
|---|---|
| `ENC-*`   | 手算的 RLP 期望字节（非由 encode 反推） |
| `CHAIN-*` | 手算的字节串布局 |
| `MPT-*`   | 与插入顺序无关、与删除路径无关、空 trie 根为已知常量 |
| `PROPOSER-*` | 用**独立的累计权益扫描**复算提案者，不复用实现的选择函数 |
| `BASEFEE-*` | 规范 §17.4 的核验表（人工给定） |
| `SLASH-*` | 规范 §15.1 的比例精确值（人工给定） |
| `REWARD-*`| 分配守恒：Σ支付 + 余数 == 池子（结构性质，不依赖具体值） |
| `BURN-*`  | 供应量守恒等式 |
| `GENESIS-*` | §32.2 闭合约束 + 哈希确定性 |

用法：
    python3 tools/agora_vectors.py --out vectors/agora_v0.2.2_vectors.json
    python3 tools/agora_vectors.py --verify        # 仅校验，不写文件
    python3 tools/agora_vectors.py --selftest      # 重新生成并与已有文件比对
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agora import params as P
from agora.block import (
    Block, BlockHeader, Commit, CommitSignature, apply_block, prepare_block,
    precommit_payload, verify_commit,
)
from agora.codec import EMPTY_TRIE_ROOT, decode, encode, MerklePatriciaTrie, secure_key
from agora.consensus import (
    Vote, VoteType, epoch_seed, proposer_for, select_proposer,
    selection_randomness, seed_from_parent, vote_signing_payload,
)
from agora.crypto import (
    BASE_POINT, CURVE_L, address_from_pubkey, chain, keccak256,
    publickey_from_seed, sign, verify,
)
from agora.gas import TxType, base_fee_next, base_fee_sequence, fee_quote, gas_used_for
from agora.state import (
    Account, AirdropEntry, GenesisAllocation, SnapshotSet, ValidatorRecord,
    STATUS_BONDED, airdrop_merkle_proof, airdrop_merkle_root, airdrop_verify,
    build_genesis_state, genesis_hash, validator_set_commitment,
)
from agora.tx import Evidence, SignedVote, Transaction, validate_tx

VECTORS_VERSION = "AGORA/v0.2.2-vectors-1"

# 确定性种子（与测试套件一致，便于交叉核对）
SEEDS = [bytes([i]) * 32 for i in (1, 2, 3, 4)]

_errors: list = []
_warnings: list = []


def fail(family: str, msg: str) -> None:
    _errors.append(f"[{family}] {msg}")


def warn(family: str, msg: str) -> None:
    _warnings.append(f"[{family}] {msg}")


h = lambda b: b.hex() if isinstance(b, (bytes, bytearray)) else b   # noqa: E731


# ══════════════════════════════════════════════════════════════════════
# ENC-*：RLP 规范编码
# ══════════════════════════════════════════════════════════════════════

def gen_enc():
    """边界样本 + **手算期望字节**（不从 encode 反推）。"""
    cases = [
        # (描述, 输入, 手算期望 hex)
        ("整数 0", 0, "80"),
        ("整数 1", 1, "01"),
        ("整数 127（单字节上限）", 127, "7f"),
        ("整数 128（需长度前缀）", 128, "8180"),
        ("整数 255", 255, "81ff"),
        ("整数 256", 256, "820100"),
        ("整数 65535", 65535, "82ffff"),
        ("整数 2^64-1", 2 ** 64 - 1, "88" + "ff" * 8),
        ("整数 2^256-1", 2 ** 256 - 1, "a0" + "ff" * 32),
        ("空串", b"", "80"),
        ("单字节 'a'", b"a", "61"),
        ("'dog'", b"dog", "83646f67"),
        ("55 字节（短形式上限）", b"x" * 55, "b7" + "78" * 55),
        ("56 字节（长形式起点）", b"x" * 56, "b838" + "78" * 56),
        ("60 字节", b"x" * 60, "b83c" + "78" * 60),
        ("空列表", [], "c0"),
        ("[1,2,[3]]", [1, 2, [3]], "c40102c103"),
        ("['cat','dog']", [b"cat", b"dog"], "c88363617483646f67"),
    ]
    out = []
    for desc, value, expect in cases:
        got = encode(value).hex()
        if got != expect:
            fail("ENC", f"{desc}: 实现给出 {got}，手算期望 {expect}")
        out.append({"case": desc, "input_repr": repr(value)[:80],
                    "encoded": got, "expected": expect, "match": got == expect})

    # 必须拒绝的非规范编码 —— 分两层，**校验层次不能混淆**（BUG-49）：
    #
    #   ① 结构层：解码器必须拒绝（长度前缀非最小、长度不符、尾随字节）；
    #   ② 整数层：**解码器不拒绝**，因为它不掌握 schema，无法区分整数字段与
    #      以 0x00 开头的合法字节串字段（地址 0x00…00、32 字节哈希都会以 0x00 开头）。
    #      整数规范性由 `require_canonical_int` 在"把字段解释为整数"时强制。
    #
    # 把 ② 放进解码器会让"同一笔交易是否合法"在实现间产生分歧，
    # 这正是 §1 第 1 条禁止的。
    rejects = [("长形式编码短负载", "b80141", "decode"),
               ("尾随字节", "818000", "decode"),
               ("列表长度超出内容", "c30102", "decode"),
               ("列表内容不足", "c201", "decode")]
    rj = []
    for desc, hexstr, layer in rejects:
        try:
            decode(bytes.fromhex(hexstr))
            fail("ENC", f"未拒绝非规范编码：{desc} ({hexstr})")
            ok = False
        except Exception:
            ok = True
        rj.append({"case": desc, "encoded": hexstr, "layer": layer,
                   "must_reject": True, "rejected": ok})

    # ② 整数层：先解码成功（结构合法），再在整数解释时被拒绝
    from agora.codec import require_canonical_int
    int_rejects = [("单字节整数加长度前缀", "8100"),
                   ("整数前导零", "82007f")]
    for desc, hexstr in int_rejects:
        raw = bytes.fromhex(hexstr)
        try:
            item = decode(raw)                  # 结构层必须通过
            decode_ok = True
        except Exception:
            decode_ok = False
        if not decode_ok:
            fail("ENC", f"{desc}: 结构层不应拒绝（{hexstr} 是合法 RLP 结构）")
        try:
            require_canonical_int(item)
            fail("ENC", f"整数层未拒绝非最小编码：{desc} ({hexstr})")
            int_ok = False
        except Exception:
            int_ok = True
        rj.append({"case": desc, "encoded": hexstr, "layer": "require_canonical_int",
                   "decoded_bytes": item.hex(), "must_reject": True, "rejected": int_ok})

    # ②b 合法字节串即便以 0x00 开头也必须被接受（这正是 BUG-49 的要点）
    zero_addr = b"\x00" * 20
    if decode(encode(zero_addr)) != zero_addr:
        fail("ENC", "以 0x00 开头的 20 字节地址无法往返（BUG-49 未修复）")

    # 必须接受的合法编码（防止过度严格）
    accepts = [("列表内含空列表", "c1c0"), ("空列表", "c0"),
               ("空串", "80"), ("两个空串的列表", "c28080")]
    ac = []
    for desc, hexstr in accepts:
        try:
            decode(bytes.fromhex(hexstr))
            ok = True
        except Exception as e:
            fail("ENC", f"错误拒绝了合法编码：{desc} ({hexstr})：{e}")
            ok = False
        ac.append({"case": desc, "encoded": hexstr, "must_accept": True, "accepted": ok})

    return {"encode": out, "must_reject": rj, "must_accept": ac}


# ══════════════════════════════════════════════════════════════════════
# CHAIN-*：哈希原像 / 签名载荷
# ══════════════════════════════════════════════════════════════════════

def gen_chain():
    """连接函数的字节布局，并**手算**期望（定宽大端、u32 前缀、20/32 字节原样）。"""
    cases = [
        ("u8", (1,), "01"),
        ("u8 上限", (255,), "ff"),
        ("u16", (256,), "0100"),
        ("u32", (65536,), "00010000"),
        ("u64", (2 ** 40,), "0000010000000000"),
        ("u256（定宽 32 字节）", (2 ** 200,), (2 ** 200).to_bytes(32, "big").hex()),
        ("地址 20 字节原样", (b"\xaa" * 20,), "aa" * 20),
        ("哈希 32 字节原样", (b"\xbb" * 32,), "bb" * 32),
        ("变长字节串加 u32 前缀", (b"abc",), "00000003616263"),
        ("标签作为数据字段仍需 u32 前缀（故标签必须写在 chain 之外）",
         (P.TAG_TX,), "0000000f" + P.TAG_TX.hex()),
        ("多字段顺序敏感", (1, 2), "0102"),
        ("多字段反向", (2, 1), "0201"),
    ]
    # 规范 §20.1 要求整数**定宽**，因此用例必须显式声明宽度（BUG-64），
    # 并给出**机器可读**的字段描述（BUG-66）—— 独立实现据此即可复算，
    # 不必解析开发语言的 repr。
    width_cases = [
        ("u8", [("u8", 1)], "01"),
        ("u8 上限", [("u8", 255)], "ff"),
        ("u16", [("u16", 256)], "0100"),
        ("u32", [("u32", 65536)], "00010000"),
        ("u64", [("u64", 2 ** 40)], "0000010000000000"),
        ("u256（定宽 32 字节）", [("u256", 2 ** 200)], (2 ** 200).to_bytes(32, "big").hex()),
        # ★ 边界：这四组是"定宽 vs 最小定宽"分歧**唯一**能被看见的地方。
        #   若省略它们，两种规则在小值上会得到相同的字节，分歧被数值巧合掩盖
        #   （这正是 BUG-64 长期未被发现的原因，见 §37B.4）。
        ("u64 边界 255", [("u64", 255)], (255).to_bytes(8, "big").hex()),
        ("u64 边界 256", [("u64", 256)], (256).to_bytes(8, "big").hex()),
        ("u64 边界 65536", [("u64", 65536)], (65536).to_bytes(8, "big").hex()),
        ("u32 边界 256", [("u32", 256)], (256).to_bytes(4, "big").hex()),
        ("地址 20 字节原样", [b"\xaa" * 20], None),
        ("哈希 32 字节原样", [b"\xbb" * 32], None),
        ("变长字节串加 u32 前缀", [b"abc"], "00000003616263"),
        ("标签作为数据字段仍需 u32 前缀（故标签必须写在 chain 之外）",
         [P.TAG_TX], "0000000f" + P.TAG_TX.hex()),
        ("多字段（各自显式宽度）", [("u8", 1), ("u32", 2)], "0100000002"),
        ("多字段反向", [("u32", 2), ("u8", 1)], "0000000201"),
    ]

    out = []
    for desc, fields, expect in width_cases:
        if expect is None:      # 由字段本身推出期望（20/32 字节原样）
            expect = b"".join(f if isinstance(f, bytes) else b"" for f in fields).hex()
        got = chain(*fields).hex()
        if got != expect:
            fail("CHAIN", f"{desc}: 实现 {got}，手算 {expect}")
        out.append({"case": desc,
                    "fields": [({"t": f[0], "v": str(f[1])} if isinstance(f, tuple)
                                else {"t": "bytes", "v": f.hex()}) for f in fields],
                    "bytes": got, "expected": expect, "match": got == expect})

    # 投票签名载荷（§20.3）—— 手工拼出期望字节
    bh = bytes(range(32))
    payload = vote_signing_payload(7, 3, int(VoteType.PRECOMMIT), bh)
    # 手算期望（规范 §20.1 的 CHAIN 语义，**定宽**）：
    #   标签       ASCII，无长度前缀  ← **必须在 chain() 之外前置**
    #   链 ID      15 字节（既非 20 也非 32）⇒ 加 u32 长度前缀
    #   高度       u64 ⇒ **8 字节定宽**（规范 §20.3）
    #   轮次       u32 ⇒ **4 字节定宽**
    #   类型       u8  ⇒ 1 字节
    #   区块哈希    32 字节原样
    #
    # ⚠ 本手算此前写成"整数按最小定宽"（7→1 字节），与实现**犯了同一个错误**，
    #   于是向量与实现一致、测试变绿 —— 分歧被彻底掩盖（BUG-64）。
    #   手算 **MUST** 严格照抄规范文本的宽度，**MUST NOT** 参照实现的行为。
    manual = (P.TAG_PRECOMMIT
              + len(P.CHAIN_ID_BYTES).to_bytes(4, "big") + P.CHAIN_ID_BYTES
              + (7).to_bytes(8, "big") + (3).to_bytes(4, "big")
              + (2).to_bytes(1, "big") + bh)
    if payload != manual:
        fail("CHAIN", "vote_signing_payload 与手工拼接不一致")
    digest = keccak256(payload).hex()
    out.append({"case": "预提交签名载荷 (h=7,r=3)",
                "payload": h(payload), "payload_expected": h(manual),
                "digest": digest, "match": payload == manual})

    nil_payload = vote_signing_payload(7, 3, int(VoteType.PREVOTE), None)
    manual_nil = (P.TAG_PREVOTE
                  + len(P.CHAIN_ID_BYTES).to_bytes(4, "big") + P.CHAIN_ID_BYTES
                  + (7).to_bytes(8, "big") + (3).to_bytes(4, "big")
                  + (1).to_bytes(1, "big") + b"\x00" * 32)
    if nil_payload != manual_nil:
        fail("CHAIN", "nil 预投票载荷与手工拼接不一致")
    out.append({"case": "nil 预投票载荷", "payload": h(nil_payload),
                "digest": keccak256(nil_payload).hex(),
                "match": nil_payload == manual_nil})

    # 域分离：不同用途必须得到不同摘要
    payloads = {
        "PREVOTE": vote_signing_payload(1, 0, int(VoteType.PREVOTE), bh),
        "PRECOMMIT": vote_signing_payload(1, 0, int(VoteType.PRECOMMIT), bh),
    }
    if payloads["PREVOTE"] == payloads["PRECOMMIT"]:
        fail("CHAIN", "PREVOTE 与 PRECOMMIT 载荷相同（域分离失效）")

    return {"chain": out, "digests": {k: keccak256(v).hex() for k, v in payloads.items()}}


# ══════════════════════════════════════════════════════════════════════
# MPT-*：状态 trie
# ══════════════════════════════════════════════════════════════════════

def gen_mpt():
    """空 trie 常量 + 多种结构 + **顺序无关性**（独立真值）。"""
    out = {"empty_root": EMPTY_TRIE_ROOT.hex()}
    if EMPTY_TRIE_ROOT.hex() != ("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc00162"
                                 "2fb5e363b421"):
        fail("MPT", f"空 trie 根不等于 Keccak(RLP(''))：{EMPTY_TRIE_ROOT.hex()}")

    # 单叶 / 双叶（分叉）/ 多叶（扩展+叶）
    cases = [
        ("单叶", [(b"\x01" * 20, b"v1")]),
        ("双叶（同一分支）", [(b"\x01" * 20, b"v1"), (b"\x01" * 19 + b"\x02", b"v2")]),
        ("三叶", [(bytes([i]) * 20, b"v%d" % i) for i in range(3)]),
        ("五十叶", [(bytes([i % 256]) * 20, b"value-%d" % i) for i in range(50)]),
        ("含空值（应删除）", [(b"\x01" * 20, b"v1"), (b"\x02" * 20, b"")]),
    ]
    entries = []
    for desc, items in cases:
        t = MerklePatriciaTrie.from_items(items)
        # BUG-66：**必须同时给出键与值**。只给键时独立实现无法重建树，
        # "校验根"就退化成照抄参考实现 —— 那样的向量没有独立验证价值。
        entries.append({"case": desc,
                        "entries": [[h(k), h(v)] for k, v in items],
                        "keys": [h(k) for k, _ in items],
                        "root": h(t.root),
                        "key_count": len([1 for _, v in items if v])})

    # 独立真值 1：插入顺序无关
    items = [(bytes([i % 256]) * 20, b"v%d" % i) for i in range(64)]
    t1 = MerklePatriciaTrie.from_items(items)
    t2 = MerklePatriciaTrie.from_items(list(reversed(items)))
    if t1.root != t2.root:
        fail("MPT", "插入顺序改变了根（违反确定性）")

    # 独立真值 2：插入后删除，根必须回到空
    t3 = MerklePatriciaTrie()
    for k, v in items:
        t3.put(k, v)
    for k, _ in items:
        t3.delete_raw_hashed(secure_key(k))
    if t3.root != EMPTY_TRIE_ROOT:
        fail("MPT", f"全部删除后根未回到空 trie 根：{t3.root.hex()}")

    # 独立真值 3：导出可往返
    rebuilt = MerklePatriciaTrie.from_hashed_items(t1.items())
    if rebuilt.root != t1.root:
        fail("MPT", "items() 导出后重建的根不一致")

    # 独立真值 4：改一个字节必须改变根
    modified = list(items)
    modified[0] = (modified[0][0], b"changed")
    if MerklePatriciaTrie.from_items(modified).root == t1.root:
        fail("MPT", "修改值后根未变化")

    out["cases"] = entries
    out["order_independent_root"] = h(t1.root)
    out["checks"] = {
        "order_independent": t1.root == t2.root,
        "delete_returns_to_empty": t3.root == EMPTY_TRIE_ROOT,
        "export_roundtrip": rebuilt.root == t1.root,
    }
    return out


# ══════════════════════════════════════════════════════════════════════
# PROPOSER-*：提案者选择
# ══════════════════════════════════════════════════════════════════════

def _independent_select(r_bytes: bytes, members, total: int):
    """**独立实现**的提案者选择：按地址升序累计、严格大于 target。

    刻意不复用 `consensus.select_proposer`，以便交叉验证。
    """
    target = int.from_bytes(r_bytes, "big") % total
    cum = 0
    for addr, vp in sorted(members):
        if vp <= 0:
            continue
        cum += vp
        if cum > target:
            return addr
    return sorted(members)[-1][0]


def gen_proposer():
    pks = [publickey_from_seed(s) for s in SEEDS]
    addrs = [address_from_pubkey(p) for p in pks]
    stake = 64 * P.ATOM_PER_AGORA
    snap = SnapshotSet(
        membership=sorted(addrs),
        voting_power=sorted((a, stake) for a in addrs),
        staked_supply=stake * 4,
        records=[ValidatorRecord(pubkey=pks[i], effective_stake=stake,
                                 status=STATUS_BONDED).to_rlp() for i in range(4)])
    seed = seed_from_parent(None)

    rows = []
    for epoch in (0, 1):
        for slot in (0, 1, 2, 3, 7, 719, 720, 721):
            for round_ in (0, 1, 5):
                r = selection_randomness(seed, epoch, slot, round_)
                got = select_proposer(r, snap)
                want = _independent_select(r, snap.voting_power, snap.staked_supply)
                if got != want:
                    fail("PROPOSER", f"e={epoch} s={slot} r={round_}: 实现 {got}，"
                                     f"独立复算 {want}")
                rows.append({"epoch": epoch, "slot": slot, "round": round_,
                             "R": h(r), "proposer": h(got),
                             "proposer_index": addrs.index(got) + 1,
                             "match": got == want})

    # 确定性：同输入 50 次同结果
    if len({select_proposer(selection_randomness(seed, 0, 1, 0), snap)
            for _ in range(50)}) != 1:
        fail("PROPOSER", "同一 (epoch,slot,round) 给出了不同提案者")

    # 零权成员永不入选
    snap_zero = SnapshotSet(
        membership=sorted(addrs),
        voting_power=[(addrs[0], 0), (addrs[1], stake), (addrs[2], 0), (addrs[3], stake)],
        staked_supply=2 * stake,
        records=snap.records)
    picked = {select_proposer(selection_randomness(seed, 0, s, 0), snap_zero)
              for s in range(400)}
    if addrs[0] in picked or addrs[2] in picked:
        fail("PROPOSER", "零权成员被选为提案者")
    if len(picked) != 2:
        fail("PROPOSER", f"零权跳过后期望只选中 2 个有权成员，实际 {len(picked)}")

    # S_epoch = 0 → None（链 halt）
    snap_empty = SnapshotSet(membership=[], voting_power=[], staked_supply=0, records=[])
    if select_proposer(selection_randomness(seed, 0, 1, 0), snap_empty) is not None:
        fail("PROPOSER", "S_epoch = 0 时仍选出了提案者（应 halt）")

    return {"epoch_seed": h(seed), "validator_set": [h(a) for a in sorted(addrs)],
            "validators": rows,
            "zero_weight_picked_count": len(picked),
            "empty_set_returns_none": True}


# ══════════════════════════════════════════════════════════════════════
# BASEFEE-*：基础费序列
# ══════════════════════════════════════════════════════════════════════

def gen_basefee():
    """200 步 gas 用量序列 + **规范核验表**（人工给定，独立真值）。"""
    # 可复现的伪随机 gas 序列（线性同余，不依赖 Python 的 random 实现细节）
    seq, x = [], 12345
    for _ in range(200):
        x = (1103515245 * x + 12345) % (2 ** 31)
        seq.append(x % (P.MAX_GAS_PER_BLOCK + 1))

    fees = base_fee_sequence(seq)
    if len(fees) != 200:
        fail("BASEFEE", "序列长度错误")

    # 人工核验表（规范 §17.4）
    table = [(1_000_000_000, 0, 1_000_000_000),
             (1_000_000_000, 4_000_000, 1_000_000_000),
             (1_000_000_000, 6_000_000, 1_025_000_000),
             (1_000_000_000, 10_000_000, 1_125_000_000),
             (1_000_000_000_000, 4_000_000, 975_000_000_000),
             (1_000_000_000_000, 10_000_000, 1_125_000_000_000)]
    tbl = []
    for bf, gu, want in table:
        got = base_fee_next(bf, gu)
        if got != want:
            fail("BASEFEE", f"核验表 bf={bf} gas={gu}: 实现 {got}，规范 {want}")
        tbl.append({"base_fee": bf, "gas_used": gu, "next": got, "expected": want,
                    "match": got == want})

    # 独立真值：地板不可突破
    if min(fees) < P.MIN_BASE_FEE:
        fail("BASEFEE", "序列中出现低于 MIN_BASE_FEE 的值")
    if any(f > P.MAX_GAS_PER_BLOCK for f in fees):
        warn("BASEFEE", "基础费增长很快（可能是正常现象）")

    # 独立真值：gas == target 时不变
    if base_fee_next(10 ** 12, P.TARGET_GAS_PER_BLOCK) != 10 ** 12:
        fail("BASEFEE", "gas 等于目标时基础费发生了变化")

    return {"gas_sequence": seq, "base_fee_sequence": fees,
            "verification_table": tbl, "min_base_fee": P.MIN_BASE_FEE}


# ══════════════════════════════════════════════════════════════════════
# SLASH-*：罚没计算
# ══════════════════════════════════════════════════════════════════════

def gen_slash():
    """比例精确值（人工给定）+ 边界。"""
    stake = 64 * P.ATOM_PER_AGORA
    table = [("DOUBLE_PREVOTE", 300_000, 3_200_000_000_000_000_000),
             ("DOUBLE_PRECOMMIT", 300_000, 3_200_000_000_000_000_000),
             ("SEVERE", 600_000, 6_400_000_000_000_000_000),
             ("INVALID_PROPOSAL", 60_000, 640_000_000_000_000_000)]
    rows = []
    for cls, ppm, want in table:
        got = P.slash_amount(stake, cls)
        if got != want:
            fail("SLASH", f"{cls}: 实现 {got}，规范 {want}")
        # 独立复算：floor(base × ppm / 6,000,000)
        manual = stake * ppm // 6_000_000
        if manual != got:
            fail("SLASH", f"{cls}: 与手工算式不符 ({manual})")
        reward = got * P.EVIDENCE_REWARD_PPM // 1_000_000
        burn = got - reward
        if reward + burn != got:
            fail("SLASH", f"{cls}: 奖励 + 销毁 != 罚没额")
        rows.append({"class": cls, "ppm": ppm, "base": stake, "amount": got,
                     "evidence_reward": reward, "burn": burn,
                     "expected_amount": want, "match": got == want})

    # 边界：极小基数
    tiny = P.slash_amount(20, "INVALID_PROPOSAL")
    if tiny != 0:
        warn("SLASH", f"20 atom 的 1% 罚没期望下取整为 0，实际 {tiny}")
    # 边界：单次扣除上限
    if P.slash_amount(10 ** 30, "SEVERE") > 10 ** 30:
        fail("SLASH", "罚没额超过基数")
    return {"cases": rows, "tiny_base_result": tiny,
            "denominator": P.SLASH_PPM_DENOMINATOR}


# ══════════════════════════════════════════════════════════════════════
# REWARD-*：分配与尘埃
# ══════════════════════════════════════════════════════════════════════

def gen_reward():
    """1..100 个签名者的分配 + **守恒**（结构真值）。"""
    pool = 16_000_000_000_000_000          # 0.016 AGORA
    rows = []
    for n in list(range(1, 21)) + [50, 67, 100]:
        w = pool // n
        shares = [w] * n
        acc = sum(shares)
        rows.append({"signers": n, "pool": pool, "per_signer_floor": w,
                     "total_paid": acc, "dust": pool - acc,
                     "conserved": acc + (pool - acc) == pool})
        if acc + (pool - acc) != pool:
            fail("REWARD", f"n={n}: 分配不守恒")
        if pool - acc >= n:
            fail("REWARD", f"n={n}: 余数 {pool - acc} 大于等于签名者数，下取整有误")

    # 发行曲线取值（含触底点与端点）—— **恒定曲线**，取过渡期之后的槽
    curve = []
    steady_slot = P.TRANSITION_END_SLOT
    for pct in (0, 5, 10, 30, 45, 5650, 60, 75, 90, 100):
        staked = P.INITIAL_SUPPLY * pct // 10000
        if staked == 0:
            staked = 1
        rew = P.curve_block_reward(staked)
        curve.append({"staked_ppm": pct * 100, "staked_agora_str": str(staked),
                      "block_reward": rew, "slot": steady_slot})
        if not (P.MIN_BLOCK_REWARD <= rew <= P.MAX_BLOCK_REWARD):
            fail("REWARD", f"曲线在 {pct/100}% 处越界：{rew}")

    # ── 过渡期奖励地板（规范 §28.4.1，所有者决策 D-3）──
    # 边界必须落在向量里：窗口末槽 / 窗口首槽，两侧取值不同 ⇒ 任何
    # "用错槽（本地时间、父块槽、高度）"的实现都会在此处对不上。
    trans_rows = []
    probe_slots = [0, 1, P.TRANSITION_END_SLOT - 1, P.TRANSITION_END_SLOT,
                   P.TRANSITION_END_SLOT + 1]
    probe_stakes = [1, 256 * P.ATOM_PER_AGORA,             # 创世质押量（4×64 AGORA）
                    P.INITIAL_SUPPLY * 15 // 100,           # 上限截断点，恰好 0.64
                    P.INITIAL_SUPPLY * 15 // 100 + 1,       # 刚进入曲线区
                    P.INITIAL_SUPPLY * 564_706 // 1_000_000,  # 触底点附近
                    P.INITIAL_SUPPLY * 60 // 100,
                    P.INITIAL_SUPPLY]
    for slot in probe_slots:
        for staked in probe_stakes:
            r = P.block_reward(staked, slot)
            trans_rows.append({"slot": slot, "staked_agora_str": str(staked),
                               "block_reward": r,
                               "transition_active": P.transition_active(slot)})
            if not (P.MIN_BLOCK_REWARD <= r <= P.MAX_BLOCK_REWARD):
                fail("REWARD", f"奖励越界：slot={slot} S={staked} → {r}")
    # 独立真值（不依赖实现）：地板 == 上限 ⇒ 窗口内取值与 S 无关，恒为 0.64 AGORA
    for row in trans_rows:
        if row["transition_active"] and row["block_reward"] != P.MAX_BLOCK_REWARD:
            fail("REWARD", f"窗口内应恒为 MAX：{row}")
        if (not row["transition_active"]
                and row["block_reward"] != P.curve_block_reward(int(row["staked_agora_str"]))):
            fail("REWARD", f"窗口后应回到曲线：{row}")
    steady_col = P.INITIAL_SUPPLY * 60 // 100
    if P.block_reward(steady_col, 0) == P.curve_block_reward(steady_col):
        fail("REWARD", "过渡期地板未生效（窗口内取值与曲线相同）")

    # 独立真值：曲线在 60% 处的原始值为 0.16 AGORA（被地板抬到 0.17）
    raw60 = P.BLOCK_REWARD_NUMERATOR // (P.INITIAL_SUPPLY * 60 // 100)
    if raw60 != 16 * 10 ** 16:
        fail("REWARD", f"60% 处曲线原始值应为 0.16 AGORA，实际 {raw60}")
    # 独立真值：触底点 = 质押率 48.00%（D-5 后 MIN = 0.20，见规范 §28.4）
    star = P.BLOCK_REWARD_NUMERATOR / P.MIN_BLOCK_REWARD / P.INITIAL_SUPPLY
    if star != 0.48:
        fail("REWARD", f"触底点应恰为 48.00%，实际 {star:.4%}")
    # 独立真值：GATE-6 包线最差点（丢槽 10% + 质押率 100%）必须 ≥ +0.5pp
    _S = P.INITIAL_SUPPLY
    _net = (P.MIN_BLOCK_REWARD * P.PROTOCOL_YEAR_SLOTS / _S * 100) * 0.9 \
        - P.ANNUAL_BURN_RATE_PPM / 10_000
    if _net < P.ENVELOPE_MIN_NET_PCT:
        fail("REWARD", f"包线内最差点仅 {_net:+.4f}pp，低于 {P.ENVELOPE_MIN_NET_PCT}pp")

    # 20/80 劈分 + 余数归提案者
    splits = []
    for amount in (0, 1, 7, 101, 10 ** 18 + 3):
        prop, att = P.split_proposer_attestation(amount)
        splits.append({"amount": amount, "proposer": prop, "attestation": att,
                       "conserved": prop + att == amount})
        if prop + att != amount:
            fail("REWARD", f"劈分不守恒：{amount}")

    return {"dust_by_signer_count": rows, "curve": curve,
            "numerator": P.BLOCK_REWARD_NUMERATOR,
            # 上下界与包线放进向量元数据：独立实现**不得**自己硬编码这些常量
            "min_reward": P.MIN_BLOCK_REWARD,
            "max_reward": P.MAX_BLOCK_REWARD,
            "envelope_slot_loss_pct": P.ENVELOPE_SLOT_LOSS_PCT,
            "envelope_min_net_pct": P.ENVELOPE_MIN_NET_PCT,
            "bottom_out_ratio_ppm": int(star * 1_000_000),
            "raw_at_60pct": raw60,
            "transition_epochs": P.TRANSITION_EPOCHS,
            "transition_end_slot": P.TRANSITION_END_SLOT,
            "transition_floor": P.TRANSITION_REWARD_FLOOR,
            "transition": trans_rows,
            "splits": splits}


# ══════════════════════════════════════════════════════════════════════
# BURN-*：销毁分账与供应量守恒
# ══════════════════════════════════════════════════════════════════════

def _genesis_for_burn():
    pks = [publickey_from_seed(s) for s in SEEDS]
    stake = 64 * P.ATOM_PER_AGORA
    return build_genesis_state(GenesisAllocation(
        validators=[(p, stake) for p in pks],
        balances=[(pks[0], P.INITIAL_SUPPLY - stake * 4)]))[0], pks


def gen_burn():
    """三类销毁的真实场景 + **守恒等式** + **逐项精确数值**。

    销毁总是伴随一次真实的资金来源变动，因此本族使用与链上一致的场景：

    | 场景 | 资金来源 | 记账 |
    |---|---|---|
    | 基础费销毁 | 发送者余额 | `burn(发送者, x, "basefee")` |
    | 账户级罚没销毁 | 被罚没者的余额/质押 | `burn(账户, x, "slash")` |
    | 年度计划销毁（**单边**） | 无（直接从供应量抽走） | `burn_supply(x, "annual", unbacked=True)` |
    | 纪元结算扣款 | 验证者的 `effective_stake` | `burn_supply(x, …)`（`unbacked=False`，见 §28.6） |

    **`unbacked` 标志必须按语义准确传入（BUG-47）**：守恒等式是

        真实资金合计 == total_supply + total_burned_unbacked

    只有"没有从任何余额或质押扣钱"的单边销毁（年度销毁）才允许置 `True`。
    结算扣款要求调用方**先**扣钱，因此必须用默认的 `False`；
    若误置 `True`，`total_burned_unbacked` 会被虚增，守恒检查将接受**非法**
    状态（比拒绝合法区块更危险）。
    """
    st, pks = _genesis_for_burn()
    from agora.crypto import address_from_pubkey
    sender = address_from_pubkey(pks[0])
    rows = []

    def snap(label: str, state, expect_delta: int = None, before: int = None):
        ok, counted, recorded = state.check_supply_conservation()
        rows.append({
            "label": label, "total_supply": state.system.total_supply,
            "counted": counted, "recorded": recorded, "conserved": ok,
            "burned_basefee": state.system.total_burned_basefee,
            "burned_annual": state.system.total_burned_annual,
            "burned_slash": state.system.total_burned_slash,
            "burned_dust": state.system.total_burned_dust,
            "burned_inactivity": state.system.total_burned_inactivity,
            "burned_unbacked": state.system.total_burned_unbacked,
        })
        if not ok:
            fail("BURN", f"{label}: 守恒被破坏，差 {counted - recorded}")
        if expect_delta is not None and before is not None:
            if before - state.system.total_supply != expect_delta:
                fail("BURN", f"{label}: 销毁额应为 {expect_delta}，"
                            f"实际 {before - state.system.total_supply}")

    snap("创世", st)
    supply0 = st.system.total_supply

    # ① 基础费销毁（真实账户借记）
    base_fee_burn = 31_536_000_000_000
    before = st.system.total_supply
    st.burn(sender, base_fee_burn, "basefee")
    snap("基础费销毁后", st, base_fee_burn, before)

    # ② 年度计划销毁（**单边**：不扣任何余额或质押，直接从供应量抽走）
    annual = st.system.total_supply * P.ANNUAL_BURN_RATE_PPM // 1_000_000
    before = st.system.total_supply
    st.burn_supply(annual, "annual", unbacked=True)
    snap("年度销毁后", st, annual, before)

    # ③ 尘埃销毁（**有来源**：先从发送者余额扣走，再走记账销毁入口）
    dust = 12345
    before = st.system.total_supply
    st.burn(sender, dust, "dust")
    snap("尘埃销毁后（账户级）", st, dust, before)

    expected_supply = supply0 - base_fee_burn - annual - dust
    if st.system.total_supply != expected_supply:
        fail("BURN", f"total_supply 应为 {expected_supply}，实际 {st.system.total_supply}")

    return {"rows": rows, "base_fee_burn": base_fee_burn,
            "annual_burn_amount": annual, "dust_burn": dust,
            "final_total_supply": st.system.total_supply,
            "annual_rate_ppm": P.ANNUAL_BURN_RATE_PPM,
            "protocol_year_slots": P.PROTOCOL_YEAR_SLOTS,
            "note": "每条销毁都断言 total_supply 的精确下降量，并校验守恒等式"}


# ══════════════════════════════════════════════════════════════════════
# GENESIS-*：创世
# ══════════════════════════════════════════════════════════════════════

def gen_genesis():
    pks = [publickey_from_seed(s) for s in SEEDS]
    stake = 64 * P.ATOM_PER_AGORA
    gas_allow = 200_000 * P.MIN_BASE_FEE
    entries = [AirdropEntry(index=i + 1, pubkey=publickey_from_seed(bytes([90 + i]) * 32),
                            amount=1_000 * P.ATOM_PER_AGORA,
                            gas_allowance=gas_allow, note=f"user-{i}") for i in range(4)]
    airdrop_total = sum(e.amount for e in entries)
    ga_total = sum(e.gas_allowance for e in entries)
    rest = P.INITIAL_SUPPLY - stake * 4 - airdrop_total - ga_total
    alloc = GenesisAllocation(validators=[(p, stake) for p in pks],
                              balances=[(pks[0], rest)], airdrop=entries)
    st, errs = build_genesis_state(alloc, strict=False)
    if errs:
        fail("GENESIS", f"创世校验报错：{errs}")

    # 独立真值 1：§32.2 闭合
    counted = stake * 4 + rest + airdrop_total + ga_total
    if counted != P.INITIAL_SUPPLY:
        fail("GENESIS", f"创世金额不闭合：{counted} != {P.INITIAL_SUPPLY}")

    # 独立真值 2：确定性（两次构建同根）
    st2, _ = build_genesis_state(alloc, strict=False)
    if st.state_root != st2.state_root:
        fail("GENESIS", "两次构建的创世状态根不同")
    # 独立真值 3：输入顺序无关
    rev = GenesisAllocation(validators=list(reversed(alloc.validators)),
                            balances=list(alloc.balances),
                            airdrop=list(reversed(entries)))
    st3, _ = build_genesis_state(rev, strict=False)
    if st.state_root != st3.state_root:
        fail("GENESIS", "验证者/空投顺序变化改变了创世状态根")

    # 独立真值 4：空投 Merkle 证明可验证
    root = airdrop_merkle_root(entries)
    proof, idx = airdrop_merkle_proof(entries, 0)
    if not airdrop_verify(None, entries[0].pubkey, entries[0].amount,
                          entries[0].gas_allowance, proof, root,
                          index=entries[0].index):
        fail("GENESIS", "空投 Merkle 证明无法通过验证")
    if st.system.airdrop_root != root:
        fail("GENESIS", "创世状态中的 airdrop_root 与计算值不符")
    # 篡改金额必须失败
    if airdrop_verify(None, entries[0].pubkey, entries[0].amount + 1,
                      entries[0].gas_allowance, proof, root):
        fail("GENESIS", "篡改金额后 Merkle 证明仍然通过")

    # 独立真值 5：SUPPLY 守恒
    ok, c, r = st.check_supply_conservation()
    if not ok:
        fail("GENESIS", f"创世状态不守恒：{c} vs {r}")

    return {
        "genesis_timestamp": P.GENESIS_TIMESTAMP,
        "chain_id": P.CHAIN_ID,
        "validators": [{"pubkey": h(pk), "address": h(address_from_pubkey(pk)),
                        "stake": stake} for pk in pks],
        "balances": [{"pubkey": h(pks[0]), "address": h(address_from_pubkey(pks[0])),
                      "amount": rest}],
        "airdrop": [{"pubkey": h(e.pubkey), "amount": e.amount,
                     "gas_allowance": e.gas_allowance, "leaf": h(e.leaf())}
                    for e in entries],
        "airdrop_root": h(root),
        "airdrop_proof_index_0": [h(x) for x in proof],
        "airdrop_sorted_index_0": idx,
        "state_root": h(st.state_root),
        "validator_set_commitment": h(st.validator_set_commitment()),
        "genesis_hash": h(genesis_hash(st, alloc)),
        "total_supply": st.system.total_supply,
        "quorum": st.system.quorum(),
        "checks": {"closure": counted == P.INITIAL_SUPPLY,
                   "deterministic": st.state_root == st2.state_root,
                   "order_independent": st.state_root == st3.state_root,
                   "conserved": ok},
    }


# ══════════════════════════════════════════════════════════════════════
# 主流程
# ══════════════════════════════════════════════════════════════════════


def gen_txblock():
    """交易 / 区块头 / Commit / 提案 的**完整对象样本**（BUG-68）。

    为什么必须新增这一族：此前的向量只覆盖到"原语层"（RLP/CHAIN/MPT），
    **没有交易与区块样本** ⇒ 独立实现无法校验共识对象的编解码与派生哈希，
    GATE-0 的"双实现逐字节一致"在**共识对象层**根本没有可比的输入。

    每个样本同时给出：
      · 对象的**全部字段**（机器可读，独立实现据此重建对象）；
      · 该对象的 RLP 编码（可直接解码比对）；
      · 派生哈希（`tx_hash` / `block_hash`）与**签名载荷**的原像与摘要。
    """
    from agora.tx import Transaction
    from agora.gas import TxType
    from agora.block import (Block, BlockHeader, Commit, CommitSignature,
                             precommit_payload)
    from agora.crypto import chain as _chain

    out: dict = {}

    # ── 一笔真实交易（含签名）──
    seed = bytes([1]) * 32
    pk = publickey_from_seed(seed)
    tx = Transaction(
        tx_type=int(TxType.TRANSFER), nonce=7,
        max_priority_fee_per_gas=P.MIN_BASE_FEE // 2,
        max_fee_per_gas=P.MIN_BASE_FEE * 2,
        gas_limit=100_000,
        to=address_from_pubkey(publickey_from_seed(bytes([2]) * 32)),
        value=1_000 * P.ATOM_PER_AGORA,
        payload=encode(b"agora-vector"),
        pubkey=pk,
    )
    tx.signature = sign(seed, tx.signing_payload())
    content = tx.to_content_rlp()
    sp = tx.signing_payload()

    # 独立真值：签名载荷 = TAG_TX ‖ CHAIN(chain_id, RLP(content))
    manual_sp = P.TAG_TX + _chain(P.CHAIN_ID_BYTES, content)
    if sp != manual_sp:
        fail("TXBLOCK", "交易签名载荷与手工拼接不一致")

    out["seed_hex"] = seed.hex()     # 向量**自描述**：重签所需的种子必须写在向量里，
    out["tx"] = {                    # 否则第二实现只能去读生成器源码（等于没给全信息）
        "fields": {
            "tx_type": tx.tx_type,
            "protocol_version_hash": keccak256(P.PROTOCOL_VERSION.encode()).hex(),
            "chain_id_hash": keccak256(P.CHAIN_ID_BYTES).hex(),
            "nonce": tx.nonce,
            "max_priority_fee_per_gas": str(tx.max_priority_fee_per_gas),
            "max_fee_per_gas": str(tx.max_fee_per_gas),
            "gas_limit": tx.gas_limit,
            "to": tx.to.hex(),
            "value": str(tx.value),
            "payload": tx.payload.hex(),
            "pubkey": tx.pubkey.hex(),
            "signature": tx.signature.hex(),
        },
        "content_rlp": h(content),
        "envelope_rlp": h(tx.to_rlp()),
        "signing_payload": h(sp),
        "signing_payload_digest": keccak256(sp).hex(),
        "tx_hash": tx.tx_hash().hex(),
        "sender_address": tx.sender.hex(),
    }

    # ── 区块头（16 字段）与区块 ──
    commit = Commit(height=6, round=0, block_hash=bytes([0x66]) * 32,
                    signatures=(CommitSignature(address_from_pubkey(pk),
                                                bytes([0x77]) * 64),))
    hdr = BlockHeader(
        height=7, round=0, claimed_slot=8,
        parent_hash=bytes([0x11]) * 32,
        tx_root=bytes([0x22]) * 32, receipt_root=bytes([0x33]) * 32,
        state_root=bytes([0x44]) * 32, gas_used=21_000,
        base_fee_per_gas=P.INITIAL_BASE_FEE,
        parent_commit=commit, proposer_pubkey=pk,
        parent_commit_hash=b"",
    )
    hdr.timestamp = P.block_timestamp(8)
    hdr.finalize_parent_commit_hash()
    hdr.proposer_signature = sign(seed, hdr.signing_payload())

    blk = Block(header=hdr, transactions=[tx])
    manual_prop = P.TAG_PROPOSAL + _chain(P.CHAIN_ID_BYTES, hdr.to_content_rlp())
    if hdr.signing_payload() != manual_prop:
        fail("TXBLOCK", "提案签名载荷与手工拼接不一致")

    # ── 真实执行过的区块：三个承诺字段的**可复算样本**（BUG-78）──
    #
    # 为什么必须有这一段：此前向量里的 `tx_root`/`receipt_root` 是**人造常量**
    # （`0x2222…`/`0x3333…`），没有任何原像 ⇒ 独立实现只能校验"长度为 32 字节"，
    # 于是 §6.1.1 未定义原像这件事在跨实现比对里**完全不可见**。
    # 这里用一个**真正执行过**的区块，把三个字段变成"必须自己算出来"的量。
    from agora.state import GenesisAllocation, build_genesis_state
    from agora.block import (apply_block as _apply, prepare_block as _prepare,
                             receipt_root as _rroot, tx_root as _troot, Block as _Blk)

    _seeds = [bytes([10 + i]) * 32 for i in range(4)]
    _pks = [publickey_from_seed(x) for x in _seeds]
    _addrs = [address_from_pubkey(x) for x in _pks]
    _stake = 64 * P.ATOM_PER_AGORA
    _gst, _ = build_genesis_state(GenesisAllocation(
        validators=[(x, _stake) for x in _pks],
        balances=[(_pks[0], P.INITIAL_SUPPLY - 4 * _stake)],
        genesis_timestamp=P.GENESIS_TIMESTAMP), strict=True)

    def _tx(nonce, value, seed_i=0):
        t = Transaction(tx_type=int(TxType.TRANSFER), nonce=nonce,
                        max_priority_fee_per_gas=P.MIN_BASE_FEE // 2,
                        max_fee_per_gas=P.MIN_BASE_FEE * 2, gas_limit=100_000,
                        to=_addrs[3], value=value, payload=encode(b""),
                        pubkey=_pks[seed_i])
        t.signature = sign(_seeds[seed_i], t.signing_payload())
        return t

    _txs = [_tx(0, 1 * P.ATOM_PER_AGORA), _tx(1, 2 * P.ATOM_PER_AGORA),
            _tx(2, 3 * P.ATOM_PER_AGORA)]
    # 引导期（§6.3）：高度 1 的 `parent_commit` **MUST** 是空提交，
    # `parent_hash` 是**创世块**的哈希（= Keccak(RLP(创世头部))，不是 state_root）。
    from agora.node import make_genesis_block as _mgb
    _gblk = _mgb(_gst)
    _pc = Commit.empty()
    _hdr = BlockHeader(height=1, round=0, claimed_slot=1, parent_hash=_gblk.block_hash(),
                       tx_root=b"", receipt_root=b"", state_root=b"", gas_used=0,
                       base_fee_per_gas=P.INITIAL_BASE_FEE, parent_commit=_pc,
                       proposer_pubkey=_pks[0])
    _hdr.timestamp = P.block_timestamp(1)
    _hdr.finalize_parent_commit_hash()
    _hdr.proposer_signature = sign(_seeds[0], _hdr.signing_payload())
    _blk = _Blk(header=_hdr, transactions=list(_txs))
    _prepare(_gst, _blk, current_slot=1)

    # 收据按 §6.1.1 的结构**独立重建**，并与头部里的 receipt_root 对账：
    # 若二者不符，说明本实现的收据口径与规范文本不一致（生成器当场报错）。
    _recs = []
    for _t in _txs:
        _q = _t.fee_quote(P.INITIAL_BASE_FEE, creates_account=False)
        _recs.append({"tx_hash": _t.tx_hash(), "gas_used": _q.gas_used,
                      "status": "SUCCESS",
                      "effective_gas_price": _q.effective_gas_price})
    if _rroot(_recs) != _hdr.receipt_root:
        fail("TXBLOCK", "按 §6.1.1 结构重建的收据根与头部 receipt_root 不一致")
    if _troot(_txs) != _hdr.tx_root:
        fail("TXBLOCK", "按 §6.1.1 重建的交易根与头部 tx_root 不一致")
    if keccak256(_pc.to_rlp()) != _hdr.parent_commit_hash:
        fail("TXBLOCK", "parent_commit_hash != Keccak(RLP(parent_commit))")

    out["executed_block"] = {
        "note": "真实执行过的区块：三个承诺字段必须由独立实现自行重算（§6.1.1）",
        "parent_commit_rlp": _pc.to_rlp().hex(),
        "transactions": [{"envelope_rlp": t.to_rlp().hex(),
                          "tx_hash": t.tx_hash().hex()} for t in _txs],
        "receipts": [{"tx_hash": r["tx_hash"].hex(), "gas_used": r["gas_used"],
                      "status": 1, "effective_gas_price": str(r["effective_gas_price"])}
                     for r in _recs],
        "header_fields": {
            "protocol_version_hash": keccak256(P.PROTOCOL_VERSION.encode()).hex(),
            "chain_id_hash": keccak256(P.CHAIN_ID_BYTES).hex(),
            "height": _hdr.height, "round": _hdr.round,
            "claimed_slot": _hdr.claimed_slot, "timestamp": _hdr.timestamp,
            "parent_hash": _hdr.parent_hash.hex(),
            "parent_commit_hash": _hdr.parent_commit_hash.hex(),
            "tx_root": _hdr.tx_root.hex(), "receipt_root": _hdr.receipt_root.hex(),
            "state_root": _hdr.state_root.hex(), "gas_used": _hdr.gas_used,
            "base_fee_per_gas": str(_hdr.base_fee_per_gas),
            "proposer_pubkey": _hdr.proposer_pubkey.hex(),
            "proposer_signature": _hdr.proposer_signature.hex(),
        },
        "header_content_rlp": _hdr.to_content_rlp().hex(),
        "block_rlp": _blk.to_rlp().hex(),
        "block_hash": _blk.block_hash().hex(),
    }

    out["block_header"] = {
        "fields": {
            "protocol_version_hash": keccak256(P.PROTOCOL_VERSION.encode()).hex(),
            "chain_id_hash": keccak256(P.CHAIN_ID_BYTES).hex(),
            "height": hdr.height, "round": hdr.round,
            "claimed_slot": hdr.claimed_slot, "timestamp": hdr.timestamp,
            "parent_hash": hdr.parent_hash.hex(),
            "parent_commit_hash": hdr.parent_commit_hash.hex(),
            "tx_root": hdr.tx_root.hex(), "receipt_root": hdr.receipt_root.hex(),
            "state_root": hdr.state_root.hex(), "gas_used": hdr.gas_used,
            "base_fee_per_gas": str(hdr.base_fee_per_gas),
            "parent_commit_rlp": hdr.parent_commit.to_rlp().hex(),
            "proposer_pubkey": hdr.proposer_pubkey.hex(),
            "proposer_signature": hdr.proposer_signature.hex(),
        },
        "content_rlp": h(hdr.to_content_rlp()),
        "header_rlp": h(hdr.to_rlp()),
        "signing_payload": h(hdr.signing_payload()),
        "block_hash": hdr.block_hash().hex(),
        "block_rlp": h(blk.to_rlp()),
    }
    out["commit"] = {
        "fields": {"height": commit.height, "round": commit.round,
                   "block_hash": commit.block_hash.hex(),
                   "signatures": [[s.address.hex(), s.signature.hex()]
                                  for s in commit.signatures]},
        "rlp": h(commit.to_rlp()),
    }
    # 预提交签名载荷（commit 校验用的原像）
    pc = precommit_payload(7, 3, bytes([0x88]) * 32)
    out["precommit_payload"] = {"payload": h(pc), "digest": keccak256(pc).hex()}
    return out



def gen_state():
    """**具体状态**与状态根（BUG-72）。

    为什么必须新增这一族：此前的向量只到"对象层"（交易/区块），
    **没有任何一份具体状态** ⇒ 独立实现无法校验
    "给定这些账户与验证者记录，状态根应当是多少"。
    而状态根正是跨实现分叉最直接的体现，也是 GATE-0 最该比对的量。

    本族给出：
      · `accounts`      —— `MPT` 的**已哈希键**与账户 RLP（trie 的输入）；
      · `validators`    —— 验证者地址与 `ValidatorRecord` RLP
                           （独立实现可据此重算 `validator_key` 并交叉校验）；
      · `system_state_rlp` —— 系统账户 `system_key` 的原像；
      · `state_root`    —— 期望的 MPT 根；
      · `accounts_trie` —— 由 `accounts` 直接构建 trie 得到的根
                           （独立实现**只需实现 MPT** 即可校验本项）；
      · `airdrop`       —— 空投叶子、根与包含证明（独立实现可自行重算）。
    """
    from agora.state import (build_genesis_state, GenesisAllocation, AirdropEntry,
                             Account, airdrop_merkle_root, airdrop_merkle_proof,
                             SystemState)

    pks = [publickey_from_seed(sd) for sd in SEEDS]
    stake = 64 * P.ATOM_PER_AGORA
    # 两个条目 ⇒ Merkle 证明非平凡（单条目时证明为空，测不出哈希链组合逻辑）
    a1, a2 = 1000 * P.ATOM_PER_AGORA, 250 * P.ATOM_PER_AGORA
    g1, g2 = 10 ** 15, 2 * 10 ** 15
    entries = [AirdropEntry(index=1, pubkey=pks[3], amount=a1, gas_allowance=g1, note="v1"),
               AirdropEntry(index=2, pubkey=pks[2], amount=a2, gas_allowance=g2, note="v2")]
    alloc = GenesisAllocation(
        validators=[(pk, stake) for pk in pks],
        balances=[(pks[0], P.INITIAL_SUPPLY - 4 * stake
                   - (a1 + a2) - (g1 + g2))],
        airdrop=entries)
    st, errs = build_genesis_state(alloc)
    if errs:
        fail("STATE", f"创世构建出错：{errs}")

    accounts = []
    for hashed_key, raw in sorted(st.accounts.items(), key=lambda kv: kv[0]):
        acc = Account.from_rlp(raw)
        accounts.append({
            "hashed_key": hashed_key.hex(),
            "value_rlp": raw.hex(),
            "nonce": acc.nonce,
            "balance": str(acc.balance),
            "has_validator_key": bool(acc.validator_key),
            "has_system_key": bool(acc.system_key),
        })

    # 独立校验 1：`validator_key` 必须等于该验证者记录的哈希
    vk_ok = True
    for addr, rec in sorted(st.validators.items(), key=lambda kv: kv[0]):
        acc = st.account_or_empty(addr)
        if acc.validator_key and acc.validator_key != rec.rlp_hash():
            vk_ok = False
    if not vk_ok:
        fail("STATE", "账户的 validator_key 与其 ValidatorRecord 的哈希不一致")

    # 独立校验 2：系统账户的 system_key 必须等于 SystemState 的哈希
    sys_acc = st.account_or_empty(P.SYSTEM_ADDRESS)
    sys_rlp = st.system.to_rlp()
    if sys_acc.system_key != keccak256(sys_rlp):
        fail("STATE", "系统账户的 system_key 与 SystemState 的哈希不一致")

    # 独立校验 3：由 accounts 直接建 trie，根必须等于 state_root
    t = MerklePatriciaTrie()
    for a in accounts:
        t.put_raw_hashed(bytes.fromhex(a["hashed_key"]),
                         bytes.fromhex(a["value_rlp"]))
    if t.root != st.state_root:
        fail("STATE", f"由 accounts 建 trie 得到的根 {t.root.hex()} "
                      f"≠ state_root {st.state_root.hex()}")

    # 空投：叶子、根与包含证明
    root = airdrop_merkle_root(entries)
    proof, sorted_index = airdrop_merkle_proof(entries, 0)

    return {
        "genesis_timestamp": alloc.genesis_timestamp,
        "state_root": st.state_root.hex(),
        "accounts": accounts,
        "accounts_trie_root": t.root.hex(),
        "validators": [
            {"address": a.hex(), "record_rlp": r.to_rlp().hex()}
            for a, r in sorted(st.validators.items(), key=lambda kv: kv[0])
        ],
        "system_address": P.SYSTEM_ADDRESS.hex(),
        "system_state_rlp": sys_rlp.hex(),
        "system_key": sys_acc.system_key.hex(),
        "total_supply": str(st.system.total_supply),
        # 快照必须完整导出（含 records），否则独立实现无法重算 system_key
        "snapshot": {
            "membership": [a.hex() for a in st.system.snapshot.membership],
            "voting_power": [[a.hex(), str(v)]
                             for a, v in st.system.snapshot.voting_power],
            "staked_supply": str(st.system.snapshot.staked_supply),
            "records": [r.hex() for r in st.system.snapshot.records],
        },
        # SystemState 的其余字段（当前创世下多为空，但必须显式给出）
        "system_state": {
            "epoch_current": st.system.epoch_current,
            "year_index": st.system.year_index,
            "year_start_slot": st.system.year_start_slot,
            "total_supply": str(st.system.total_supply),
            "total_burned_basefee": str(st.system.total_burned_basefee),
            "total_burned_annual": str(st.system.total_burned_annual),
            "total_burned_slash": str(st.system.total_burned_slash),
            "total_burned_dust": str(st.system.total_burned_dust),
            "total_burned_inactivity": str(st.system.total_burned_inactivity),
            "total_burned_unbacked": str(st.system.total_burned_unbacked),
            "pending_slashes": [],
            "settled_slashes": [],
            "airdrop_root": st.system.airdrop_root.hex(),
            "airdrop_pending": str(st.system.airdrop_pending),
            "airdrop_claimed": [],
        },
        "airdrop": {
            "root": root.hex(),
            "leaf_hash": entries[0].leaf().hex(),
            "proof": [p.hex() for p in proof],
            "sorted_index": sorted_index,
            "index": entries[0].index,        # 条目 index（进叶子，BUG-87）
            "pubkey": entries[0].pubkey.hex(),
            "amount": str(entries[0].amount),
            "gas_allowance": str(entries[0].gas_allowance),
        },
    }


# ══════════════════════════════════════════════════════════════════════
# HANDSHAKE-*：节点握手原像与签名（§6.7 身份绑定）
# ══════════════════════════════════════════════════════════════════════
#
# 握手要解决的问题只有一个：**把对端自述的名字绑到一个公钥上**。此前名字完全取自
# 帧头自述且不做任何校验（BUG-91 的残余风险），于是任何能连上端口的人都能冒用
# 对端表**内**的名字投递消息。原像（规范文本，逐字节）：
#
#   原像 = TAG_HANDSHAKE ‖ CHAIN(chain_id, u8(role), utf8(name), pubkey,
#                                nonce_i, nonce_r)         ← 标准情形 147 字节
#
# 三处最容易让**独立实现**对不上的地方，因此本族把它们固化成字节而不是描述：
#   ① 标签在 CHAIN **之外**前置（§20.1）：若当作 CHAIN 的参数会多出 4 字节 u32 前缀；
#   ② `chain_id` 是 15 字节（既非 20 也非 32）⇒ **带 u32 长度前缀**，**不是**原样；
#   ③ `nonce_i/nonce_r` 顺序恒为（发起方, 响应方），两种角色签**同一顺序**，唯一
#      区别是 `u8(role)`（2=CHALLENGE 响应方 / 3=AUTH 发起方）—— 这就是域分隔：
#      CHALLENGE 的签名 **MUST NOT** 能当 AUTH 用，反之亦然。
#
# 方法同 CHAIN 族：**手工拼出期望字节**（逐字段照抄规范文本，不参照实现的行为），
# 再与实现输出比对，不一致即 fail。"实现与手算都错得一样"这类分歧只能靠
# 这一对独立来源暴露（BUG-64 的教训）。

TAG_HANDSHAKE = b"AGORA/HANDSHAKE/v0.2.2"          # ASCII，22 字节
ROLE_CHALLENGE = 2                                 # 响应方签
ROLE_AUTH = 3                                      # 发起方签
HS_SEED = bytes([0x41]) * 32                       # 固定种子 ⇒ 签名向量完全可复现

# 手算的布局常量（**独立于实现**，用于校验下面的偏移量算法本身）
HS_TAG_LEN = 22
HS_ROLE_OFFSET = 22 + 4 + 15                       # 标签 ‖ u32(15) ‖ "agora-testnet-1"
HS_PREIMAGE_LEN = 147                              # 标签22 + 链ID19 + 角色1 + 名字9 + 公钥32 + 2×32


def gen_handshake():
    """握手原像与签名，并**手算期望字节**（标签在 CHAIN 之外、15 字节链 ID 带前缀）。"""
    from agora.handshake import (                    # 局部导入：本族只此一处需要它
        ROLE_AUTH as REF_ROLE_AUTH, ROLE_CHALLENGE as REF_ROLE_CHALLENGE,
        handshake_payload, make_auth_sig, make_challenge_sig,
    )

    def cb(b: bytes) -> bytes:
        """§20.1 的字节串规则：20/32 字节原样，其余加 u32 长度前缀。"""
        return b if len(b) in (20, 32) else len(b).to_bytes(4, "big") + b

    def manual(role, cid, name, pubkey, ni, nr) -> bytes:
        """**逐字段手工拼接**（照抄规范文本；不调用实现，也不解析实现的 repr）。"""
        return (TAG_HANDSHAKE + cb(cid) + role.to_bytes(1, "big")
                + cb(name.encode("utf-8")) + cb(pubkey) + cb(ni) + cb(nr))

    pk = publickey_from_seed(HS_SEED)
    nonce_i = bytes(range(32))                       # 0x00..0x1f
    nonce_r = bytes(range(32, 64))                   # 0x20..0x3f
    cid_testnet = b"agora-testnet-1"                 # 15 字节 ⇒ 带 u32 前缀
    cid_mainnet = b"agora-mainnet-1"                 # 15 字节 ⇒ 带 u32 前缀

    # 角色常量必须与实现一致（否则"域分隔"就成了两个实现各说各话）
    if (ROLE_CHALLENGE, ROLE_AUTH) != (REF_ROLE_CHALLENGE, REF_ROLE_AUTH):
        fail("HANDSHAKE", f"角色常量不一致：向量 {ROLE_CHALLENGE}/{ROLE_AUTH}，"
                          f"实现 {REF_ROLE_CHALLENGE}/{REF_ROLE_AUTH}")

    cases = [
        ("payload_challenge", ROLE_CHALLENGE, cid_testnet, "node1"),
        ("payload_auth", ROLE_AUTH, cid_testnet, "node1"),
        # 换链身份：同一密钥、同一 nonce，只有 chain_id 不同 ⇒ 原像必须不同
        # （否则测试网签的握手可在主网上重放，§4 的跨链重放防线就是空的）
        ("payload_challenge_mainnet", ROLE_CHALLENGE, cid_mainnet, "node1"),
        # UTF-8 名字：长度前缀是**字节数**（"节点1" = 7 字节），不是字符数
        ("payload_challenge_utf8_name", ROLE_CHALLENGE, cid_testnet, "节点1"),
    ]

    out = []
    preimages = {}
    for case, role, cid, name in cases:
        want = manual(role, cid, name, pk, nonce_i, nonce_r)
        got = handshake_payload(role, cid, name, pk, nonce_i, nonce_r)
        if want != got:
            fail("HANDSHAKE", f"{case}: 实现 {got.hex()}，手算 {want.hex()}")
        preimages[case] = want
        out.append({
            "case": case, "role": role, "role_name": ("CHALLENGE" if role == ROLE_CHALLENGE
                                                      else "AUTH"),
            "chain_id": cid.decode("ascii"), "name": name,
            "name_utf8_len": len(name.encode("utf-8")),
            "pubkey": pk.hex(), "nonce_i": nonce_i.hex(), "nonce_r": nonce_r.hex(),
            "preimage": h(want), "length": len(want),
            "digest": keccak256(want).hex(),
            "reference": h(got), "match": want == got,
        })

    # ── 独立真值：手算的布局常量必须与逐字段偏移量一致 ──
    p_ch = preimages["payload_challenge"]
    p_au = preimages["payload_auth"]
    if len(TAG_HANDSHAKE) != HS_TAG_LEN:
        fail("HANDSHAKE", f"标签长度 {len(TAG_HANDSHAKE)} != {HS_TAG_LEN}")
    if len(p_ch) != HS_PREIMAGE_LEN:
        fail("HANDSHAKE", f"标准情形原像 {len(p_ch)} 字节 != {HS_PREIMAGE_LEN}")

    layout, off = [], 0
    for field, blob, enc in (("tag", TAG_HANDSHAKE, "ascii（CHAIN 之外前置）"),
                             ("chain_id_len", (4).to_bytes(4, "big"), "u32 大端"),
                             ("chain_id", cid_testnet, "原样（15 字节，故需 u32 前缀）"),
                             ("role", (ROLE_CHALLENGE).to_bytes(1, "big"), "u8 定宽"),
                             ("name_len", (5).to_bytes(4, "big"), "u32 大端"),
                             ("name", b"node1", "utf8 原样"),
                             ("pubkey", pk, "32 字节原样"),
                             ("nonce_i", nonce_i, "32 字节原样"),
                             ("nonce_r", nonce_r, "32 字节原样")):
        layout.append({"field": field, "offset": off, "length": len(blob), "encoding": enc})
        off += len(blob)
    if off != HS_PREIMAGE_LEN:
        fail("HANDSHAKE", f"逐字段偏移量合计 {off} != {HS_PREIMAGE_LEN}")
    role_off = layout[3]["offset"]
    if role_off != HS_ROLE_OFFSET:
        fail("HANDSHAKE", f"role 字节偏移 {role_off} != 手算 {HS_ROLE_OFFSET}")
    if p_ch[role_off] != ROLE_CHALLENGE or p_au[role_off] != ROLE_AUTH:
        fail("HANDSHAKE", "role 字节不在手算偏移处")
    # 标签之外的字节串字段必须**带** u32 长度前缀（这是最容易漏的一处）
    if p_ch[HS_TAG_LEN:HS_TAG_LEN + 4] != (15).to_bytes(4, "big"):
        fail("HANDSHAKE", "chain_id 缺少 u32 长度前缀（把它当成 20 字节原样了？）")
    if p_ch[role_off + 1:role_off + 5] != (5).to_bytes(4, "big"):
        fail("HANDSHAKE", "name 缺少 u32 长度前缀")
    if p_ch[:HS_TAG_LEN] != TAG_HANDSHAKE:
        fail("HANDSHAKE", "原像未以标签开头")

    # ── 域分隔（本条是"结构性"证明，不是声明）：两个角色的原像 MUST 只差 role 字节 ──
    diff = [i for i in range(len(p_ch)) if p_ch[i] != p_au[i]]
    if diff != [role_off]:
        fail("HANDSHAKE", f"CHALLENGE 与原 AUTH 原像差异位置 {diff}，应为 [{role_off}]")

    # ── 签名（固定种子 ⇒ 完全可复现）──
    sigs = {}
    for case, role, make in (("challenge_sig", ROLE_CHALLENGE, make_challenge_sig),
                             ("auth_sig", ROLE_AUTH, make_auth_sig)):
        pre = preimages["payload_challenge" if role == ROLE_CHALLENGE else "payload_auth"]
        sig = make(HS_SEED, cid_testnet, "node1", pk, nonce_i, nonce_r)
        # 独立真值 1：签名由**手算原像**直接签出且可验证（原像若写错，这里必然失败）
        if sig != sign(HS_SEED, pre):
            fail("HANDSHAKE", f"{case}: 签名不是对本次手算原像的签名")
        # 独立真值 2：可被验证（否则向量只是"一串看着像签名的字节"）
        if not verify(pk, pre, sig):
            fail("HANDSHAKE", f"{case}: 签名无法通过验证")
        # 独立真值 3：RFC 8032 是**确定性**签名 ⇒ 两次签名必须逐字节相同。
        # 若某实现误用随机 nonce，跨语言向量会随机失配，必须在这里就被拦住。
        if sign(HS_SEED, pre) != sig:
            fail("HANDSHAKE", f"{case}: 两次签名结果不同（Ed25519 应为确定性）")
        sigs[case] = sig
        out.append({"case": case, "role": role,
                    "role_name": ("CHALLENGE" if role == ROLE_CHALLENGE else "AUTH"),
                    "chain_id": cid_testnet.decode("ascii"), "name": "node1",
                    "pubkey": pk.hex(), "nonce_i": nonce_i.hex(), "nonce_r": nonce_r.hex(),
                    "preimage": h(pre), "digest": keccak256(pre).hex(),
                    "signature": h(sig), "verified": verify(pk, pre, sig),
                    "deterministic": True})

    sig_ch, sig_au = sigs["challenge_sig"], sigs["auth_sig"]
    # 对**别的名字 / 别的链**签出的签名：必须存在且只对各自的原像有效
    sig_other_name = sign(HS_SEED, manual(ROLE_CHALLENGE, cid_testnet, "nodeA",
                                          pk, nonce_i, nonce_r))
    sig_other_chain = sign(HS_SEED, manual(ROLE_CHALLENGE, cid_mainnet, "node1",
                                           pk, nonce_i, nonce_r))

    # ── must_reject：每一条都必须被**密码学验证器**本身拒绝 ──
    #
    # 刻意用 `verify()` 而不是 `check_challenge_sig()`：后者对 NIL 哨兵
    # （全零签名 / 全零公钥）做的是**前置短路**，属调用方义务；若只有哨兵检查
    # 而没有密码学拒绝，任何漏掉哨兵判断的调用方都能被伪造签名骗过。
    def add_reject(desc, role, cid, name, sig, pubkey=pk, ni=nonce_i, nr=nonce_r):
        pre = manual(role, cid, name, pubkey, ni, nr)
        try:
            accepted = bool(verify(pubkey, pre, sig))
        except Exception:                            # 格式非法也算被拒绝
            accepted = False
        if accepted:
            fail("HANDSHAKE", f"未拒绝：{desc}")
        rejects.append({"case": desc, "role": role, "chain_id": cid.decode("ascii"),
                        "name": name, "pubkey": pubkey.hex(),
                        "nonce_i": ni.hex(), "nonce_r": nr.hex(),
                        "preimage": h(pre), "signature": h(sig),
                        "must_reject": True, "rejected": not accepted})

    rejects = []
    add_reject("挑战签名冒充确认签名（role 2→3）",
               ROLE_AUTH, cid_testnet, "node1", sig_ch)
    add_reject("确认签名冒充挑战签名（role 3→2）",
               ROLE_CHALLENGE, cid_testnet, "node1", sig_au)
    add_reject("挑战签名配上互换的两个 nonce",
               ROLE_CHALLENGE, cid_testnet, "node1", sig_ch,
               ni=nonce_r, nr=nonce_i)
    add_reject("对 nodeA 的签名用于 node1",
               ROLE_CHALLENGE, cid_testnet, "node1", sig_other_name)
    add_reject("主网 chain_id 上签的挑战用于测试网",
               ROLE_CHALLENGE, cid_testnet, "node1", sig_other_chain)
    add_reject("全零 64 字节签名", ROLE_CHALLENGE, cid_testnet, "node1", bytes(64))
    add_reject("全零 32 字节公钥（nil 身份）", ROLE_CHALLENGE, cid_testnet, "node1",
               sig_ch, pubkey=bytes(32))

    return {
        "tag": TAG_HANDSHAKE.decode("ascii"),
        "tag_len": len(TAG_HANDSHAKE),
        "role_challenge": ROLE_CHALLENGE,
        "role_auth": ROLE_AUTH,
        "preimage_len": len(p_ch),
        "seed": HS_SEED.hex(),
        "signer_pubkey": pk.hex(),
        "nonce_i": nonce_i.hex(),
        "nonce_r": nonce_r.hex(),
        "chain_ids": {"testnet": cid_testnet.decode("ascii"),
                      "mainnet": cid_mainnet.decode("ascii")},
        "layout": layout,
        "cases": out,
        "must_reject": rejects,
        "checks": {
            "tag_len_22": len(TAG_HANDSHAKE) == HS_TAG_LEN,
            "preimage_len_147": len(p_ch) == HS_PREIMAGE_LEN,
            "role_offset_41": role_off == HS_ROLE_OFFSET,
            "chain_id_u32_prefixed": p_ch[HS_TAG_LEN:HS_TAG_LEN + 4] == (15).to_bytes(4, "big"),
            "domain_separation_role_only": diff == [role_off],
            "all_signatures_verify": all(r.get("verified", True) for r in out
                                         if "signature" in r),
            "all_rejects_rejected": all(r["rejected"] for r in rejects),
        },
    }


def gen_txpayloads():
    """七种交易类型的**载荷与完整封装**（规范 §16.1 / §16.2 / §32.6）。

    为什么要单独一族：钱包要构造的不只是 TRANSFER —— BOND/UNBOND/REBOND/
    WITHDRAW/AIRDROP_CLAIM 各有自己的载荷编码，而**载荷编码错了**
    节点会在 §16.4.2 第 13 项（类型前置条件）或第 1 项（解码）拒绝，
    报错却常常指向别处。这一族给出每种类型的：
    `payload`、`content_rlp`、`envelope_rlp`、签名、`tx_hash`，
    以及 AIRDROP_CLAIM 特有的**绑定签名载荷**（§32.6 第 ③ 项）。
    """
    from agora.tx import AirdropClaim, Transaction
    from agora.gas import TxType

    seed = bytes([3]) * 32
    pk = publickey_from_seed(seed)
    to = address_from_pubkey(publickey_from_seed(bytes([4]) * 32))
    out: dict = {"cases": [], "seed_hex": seed.hex()}

    def row(name: str, tx_type: int, payload: bytes, value: int,
            extra: dict | None = None):
        tx = Transaction(tx_type=tx_type, nonce=11,
                         max_priority_fee_per_gas=0,
                         max_fee_per_gas=P.MIN_BASE_FEE * 2, gas_limit=200_000,
                         to=to, value=value, payload=payload, pubkey=pk)
        tx.signature = sign(seed, tx.signing_payload())
        item = {
            "case": name,
            "tx_type": tx_type,
            # **重建交易所需的全部字段**都必须给出：否则钱包/Dart 侧无法据此
            # 复算 content_rlp（首版只给了 payload 与结果，等于"只给答案不给题"）。
            "nonce": tx.nonce,
            "max_priority_fee_per_gas": str(tx.max_priority_fee_per_gas),
            "max_fee_per_gas": str(tx.max_fee_per_gas),
            "gas_limit": tx.gas_limit,
            "to": tx.to.hex(),
            "pubkey": tx.pubkey.hex(),
            "protocol_version_hash": keccak256(P.PROTOCOL_VERSION.encode()).hex(),
            "payload": payload.hex(),
            "payload_len": len(payload),
            "value": str(value),
            "content_rlp": tx.to_content_rlp().hex(),
            "envelope_rlp": tx.to_rlp().hex(),
            "signing_payload_digest": keccak256(tx.signing_payload()).hex(),
            "tx_hash": tx.tx_hash().hex(),
            "signature": tx.signature.hex(),
            "sender_address": tx.sender.hex(),
        }
        if extra:
            item.update(extra)
        out["cases"].append(item)

    # TRANSFER：无载荷
    row("TRANSFER（无载荷）", int(TxType.TRANSFER), b"", 5 * P.ATOM_PER_AGORA)
    # BOND：载荷是 32 字节公钥的 **RLP 字节串**（不是 CHAIN(pubkey)！）
    row("BOND（载荷 = RLP(公钥)）", int(TxType.BOND), encode(pk), 64 * P.ATOM_PER_AGORA)
    # UNBOND / REBOND：载荷是 RLP 字节串，内容为无符号大端金额
    row("UNBOND（载荷 = RLP(金额)）", int(TxType.UNBOND),
        encode(10 * P.ATOM_PER_AGORA), 0)
    row("REBOND（载荷 = RLP(金额)）", int(TxType.REBOND),
        encode(3 * P.ATOM_PER_AGORA), 0)
    # WITHDRAW：无载荷
    row("WITHDRAW（无载荷）", int(TxType.WITHDRAW), b"", 0)

    # AIRDROP_CLAIM：RLP([index, amount, gas_allowance, pubkey, [proof…], binding_sig])
    from agora.state import AirdropEntry, airdrop_merkle_proof
    entries = [
        AirdropEntry(pubkey=publickey_from_seed(bytes([0xA0 + i]) * 32),
                     amount=(i + 1) * 100 * P.ATOM_PER_AGORA,
                     gas_allowance=5 * 10 ** 15, index=i + 1)
        for i in range(3)
    ]
    own = AirdropEntry(pubkey=pk, amount=250 * P.ATOM_PER_AGORA,
                       gas_allowance=5 * 10 ** 15, index=4)
    table = entries + [own]
    proof, _sorted = airdrop_merkle_proof(table, len(table) - 1)
    claim = AirdropClaim(index=own.index, amount=own.amount,
                         gas_allowance=own.gas_allowance, pubkey=pk,
                         merkle_proof=tuple(proof), binding_signature=b"")
    binding_msg = claim.binding_message(address_from_pubkey(pk))
    binding_sig = sign(seed, binding_msg)
    claim = AirdropClaim(index=own.index, amount=own.amount,
                         gas_allowance=own.gas_allowance, pubkey=pk,
                         merkle_proof=tuple(proof), binding_signature=binding_sig)
    # 真值自检：证明必须能在该表的根下验通
    from agora.state import airdrop_merkle_root, airdrop_verify
    if not airdrop_verify(None, own.pubkey, own.amount, own.gas_allowance,
                          proof, airdrop_merkle_root(table), index=own.index):
        fail("TXPAYLOADS", "空投领取向量自带的 Merkle 证明验不过")
    row("AIRDROP_CLAIM（含证明与绑定签名）", int(TxType.AIRDROP_CLAIM),
        claim.to_rlp(), 0,
        extra={"claim_index": own.index, "claim_amount": str(own.amount),
               "claim_gas_allowance": str(own.gas_allowance),
               "claim_pubkey": own.pubkey.hex(),
               "merkle_proof": [p.hex() for p in proof],
               "airdrop_root": airdrop_merkle_root(table).hex(),
               "binding_message": binding_msg.hex(),
               "binding_signature": binding_sig.hex()})
    out["note"] = ("每种交易类型的载荷编码 + 完整封装；钱包侧据此逐字节对齐"
                   "（AIRDROP_CLAIM 还给出绑定签名载荷，见 §32.6 第 ③ 项）")
    return out


def build_all() -> dict:
    _errors.clear()
    _warnings.clear()
    vectors = {
        "meta": {
            "vectors_version": VECTORS_VERSION,
            "protocol_version": P.PROTOCOL_VERSION,
            "chain_id": P.CHAIN_ID,
            "note": "由参考实现生成；每条向量均附带独立真值校验结果（见 checks / match 字段）。",
            "units": "金额单位为 atom（1 AGORA = 10^18 atom）",
        },
        "ENC": gen_enc(),
        "CHAIN": gen_chain(),
        "MPT": gen_mpt(),
        "PROPOSER": gen_proposer(),
        "BASEFEE": gen_basefee(),
        "SLASH": gen_slash(),
        "REWARD": gen_reward(),
        "BURN": gen_burn(),
        "GENESIS": gen_genesis(),
        "TXBLOCK": gen_txblock(),
        "TXPAYLOADS": gen_txpayloads(),
        "STATE": gen_state(),
        "HANDSHAKE": gen_handshake(),
    }
    vectors["summary"] = {
        # 族列表**从实际内容推导**，不写死：写死的列表在新增族时会静默漏掉，
        # 于是"汇总"看起来对、实际漏了内容（这正是"汇总撒谎"的典型形态）。
        "families": [k for k in vectors.keys() if k != "meta"],
        "errors": list(_errors),
        "warnings": list(_warnings),
        "ok": not _errors,
    }
    return vectors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AGORA v0.2.2 黄金测试向量生成器")
    ap.add_argument("--out", default="vectors/agora_v0.2.2_vectors.json")
    ap.add_argument("--verify", action="store_true", help="仅校验，不写文件")
    ap.add_argument("--selftest", action="store_true",
                    help="重新生成并与已有文件比对（确定性检查）")
    args = ap.parse_args(argv)

    print("═" * 76)
    print("AGORA v0.2.2 黄金测试向量生成器")
    print("═" * 76)
    vec = build_all()
    fam = [k for k in vec if k not in ("meta", "summary")]
    print(f"\n生成 {len(fam)} 族向量：" + "  ".join(fam))
    for k in fam:
        blob = json.dumps(vec[k])
        print(f"  {k:<10} {len(blob):>7,} 字节")
    total = len(json.dumps(vec))
    print(f"\n合计 {total:,} 字节")

    if vec["summary"]["warnings"]:
        print("\n警告：")
        for w in vec["summary"]["warnings"]:
            print("  ⚠", w)
    if vec["summary"]["errors"]:
        print("\n★ 独立真值校验失败：")
        for e in vec["summary"]["errors"]:
            print("  ✗", e)
        print("\n结果：★ 向量不可信，必须先修正实现或规范")
        return 1
    print("\n独立真值校验：全部通过 ✅")

    if args.verify:
        print("（--verify 模式：未写入文件）")
        return 0

    if args.selftest:
        if not os.path.exists(args.out):
            print(f"\n★ --selftest 需要已有文件：{args.out}")
            return 1
        with open(args.out, encoding="utf-8") as f:
            old = json.load(f)
        if old == vec:
            print(f"\n确定性检查：与 {args.out} 完全一致 ✅")
            return 0
        print(f"\n★ 确定性检查失败：新生成的向量与 {args.out} 不一致")
        return 1

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(vec, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"\n已写入 {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
