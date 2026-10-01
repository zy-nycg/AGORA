# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 区块与区块执行
========================================

对应规范：
    §6     区块头、Commit、最终性、叉选择
    §22    区块有效性谓词（12 项）
    §28.1  `apply_block` 的 9 个阶段
    §28.6  `settle_epoch` 边界结算
    §28.4  发行曲线
    §28.5  年度销毁

本模块是"从单笔交易到整条链"的桥梁。五个**顺序敏感**之处必须严格照 §28.1 实现：

    ① 父高度参与记录（先于纪元结算）
    ② 纪元推进与边界结算
    ③ 交易执行（先扣费，后执行）
    ④ 费用、发行、**即时分配**
    ⑤ 年度销毁（带硬上界的循环）
    ⑥ 账户回收
    ⑦ 最后才计算 `state_root`

第 ⑦ 点尤其重要（规范 §19.6 BUG-1）：`state_root` **MUST** 覆盖全部状态变更。
若先算根再做费用/发行结算，则该区块的根不包含本区块的销毁与发行，
两个实现会从第一个区块起就分叉。
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from . import params as P
from .codec import RLPDecodeError, decode, encode, require_canonical_int
from .crypto_backend import (address_from_pubkey, chain, keccak256,
                             verify as ed25519_verify)
from .gas import TxType, base_fee_next, fee_quote
from .state import (
    Account, PendingSlash, SnapshotSet, State, SystemState, ValidatorRecord,
    STATUS_BONDED, STATUS_UNBONDED, STATUS_UNBONDING, meets_account_pruning_rule,
)
from .tx import Transaction, validate_tx, NIL_HASH

__all__ = [
    "CommitSignature", "Commit", "BlockHeader", "Block", "BlockError",
    "proposal_signing_payload", "apply_block", "settle_epoch",
    "validate_block_header", "verify_commit",
]

BLOCK_ERRORS = []


class BlockError(ValueError):
    """区块层面的确定性错误（规范 §22 的 12 项谓词失败）。"""

    def __init__(self, check: int, msg: str):
        super().__init__(f"第 {check} 项失败：{msg}")
        self.check = check
        self.msg = msg


# ══════════════════════════════════════════════════════════════════════
# 1. Commit（规范 §6.2）
# ══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CommitSignature:
    """`[address(20), signature(64)]`。"""
    address: bytes
    signature: bytes

    def to_rlp(self) -> bytes:
        return encode([self.address, self.signature])

    @classmethod
    def from_rlp(cls, raw) -> "CommitSignature":
        if isinstance(raw, (bytes, bytearray)):
            raw = decode(raw)
        if not isinstance(raw, list) or len(raw) != 2:
            raise BlockError(1, "CommitSignature 必须为 2 项列表")
        if len(raw[0]) != 20 or len(raw[1]) != 64:
            raise BlockError(1, "CommitSignature 的地址/签名长度不符")
        return cls(bytes(raw[0]), bytes(raw[1]))


@dataclass
class Commit:
    """规范 §6.2：
        Commit = RLP([height, round, block_hash, signatures])

    **BUG-13（方案 A）：** 签名集合 **MUST** 包含全部有效签名，**不得**裁剪为最小法定数子集。
    裁剪会让两个实现产生不同的区块哈希（因为 `Commit` 被嵌入区块头）。
    """
    height: int
    round: int
    block_hash: bytes
    signatures: List[CommitSignature] = field(default_factory=list)

    def to_fields(self) -> list:
        """规范 §6.2 的**嵌套列表**形式：`signatures:[[address(20), signature(64)], …]`。

        历史实现把每个签名写成"它的 RLP 字节串"，与规范的列表形式**字节不同**
        （见 PROJECT_REVIEW R-3）：`Commit` 被嵌进区块头并参与 `parent_commit_hash`，
        因此那处差异会让**每个区块哈希**都与照规范实现的节点不同。
        """
        return [self.height, self.round, self.block_hash,
                [[s.address, s.signature] for s in self.signatures]]

    def to_rlp(self) -> bytes:
        return encode(self.to_fields())

    @classmethod
    def from_rlp(cls, raw) -> "Commit":
        if isinstance(raw, (bytes, bytearray)):
            raw = decode(raw)
        if not isinstance(raw, list) or len(raw) != 4:
            raise BlockError(1, "Commit 必须为 4 项列表")
        # BUG-49：整数字段必须走 `require_canonical_int`（拒绝前导零/长度前缀
        # 形式的非最小编码），否则两个实现会对同一区块是否合法产生分歧。
        i = require_canonical_int
        if not isinstance(raw[3], list):
            raise BlockError(1, "Commit.signatures 必须为列表（规范 §6.2）")
        sigs = []
        for item in raw[3]:
            # **必须**是 `[address, signature]` 的列表；字节串形式是历史实现的
            # 私有编码，接收它等于让同一个 Commit 有两种合法字节表示（§20 禁止）。
            if not isinstance(item, list) or len(item) != 2:
                raise BlockError(1, "Commit 的每项签名必须为 [address, signature] 列表")
            if len(item[0]) != 20 or len(item[1]) != 64:
                raise BlockError(1, "Commit 签名的地址/签名长度不符")
            sigs.append(CommitSignature(bytes(item[0]), bytes(item[1])))
        return cls(height=i(raw[0]), round=i(raw[1]), block_hash=bytes(raw[2]),
                   signatures=sigs)

    def rlp_hash(self) -> bytes:
        return keccak256(self.to_rlp())

    @property
    def is_empty(self) -> bool:
        """创世块的 `parent_commit`（规范 §6.3）为空提交，不要求法定数。"""
        return (self.height == 0 and self.round == 0
                and self.block_hash == NIL_HASH and not self.signatures)

    @staticmethod
    def empty() -> "Commit":
        return Commit(height=0, round=0, block_hash=NIL_HASH, signatures=[])

    def addresses(self) -> List[bytes]:
        return [s.address for s in self.signatures]


def precommit_payload(height: int, round_: int, block_hash: bytes) -> bytes:
    """规范 §20.3 的预提交签名载荷。"""
    return P.TAG_PRECOMMIT + chain(P.CHAIN_ID_BYTES, ("u64", height), ("u32", round_),
                 0x02, block_hash)


def verify_commit(commit: Commit, snapshot: SnapshotSet,
                  expect_height: Optional[int] = None,
                  expect_hash: Optional[bytes] = None,
                  require_quorum: bool = True) -> Tuple[bool, str, int]:
    """规范 §6.2 的 Commit 有效性谓词。返回 `(是否有效, 原因, 有效投票权)`。"""
    if expect_height is not None and commit.height != expect_height:
        return False, f"height 应为 {expect_height}，实际 {commit.height}", 0
    if expect_hash is not None and commit.block_hash != expect_hash:
        return False, "block_hash 与父块哈希不符", 0
    addrs = [s.address for s in commit.signatures]
    if addrs != sorted(addrs):
        return False, "签名未按地址升序排列（规范 §6.2 第 3 项）", 0
    if len(set(addrs)) != len(addrs):
        return False, "存在重复地址的签名", 0

    payload = precommit_payload(commit.height, commit.round, commit.block_hash)
    power = 0
    for s in commit.signatures:
        vp = snapshot.vp_of(s.address)
        if vp == 0:
            # 规范 §6.2 第 6 项：不在快照集合中的签名被**忽略**（不构成无效）
            continue
        rec = snapshot.record_of(s.address)
        if rec is None:
            continue
        if not ed25519_verify(rec.pubkey, payload, s.signature):
            return False, f"签名无效：{s.address.hex()[:12]}…", 0
        power += vp
    if require_quorum:
        q = P.quorum(snapshot.staked_supply)
        if power < q:
            return False, f"未达法定数：{power} < {q}", power
    return True, "", power


# ══════════════════════════════════════════════════════════════════════
# 2. 区块头与区块（规范 §6.1）
# ══════════════════════════════════════════════════════════════════════

@dataclass
class BlockHeader:
    """规范 §6.1 的 16 字段；`proposer_signature` **不参与签名载荷**（BUG-2）。"""
    height: int
    round: int
    claimed_slot: int
    parent_hash: bytes
    tx_root: bytes
    receipt_root: bytes
    state_root: bytes
    gas_used: int
    base_fee_per_gas: int
    parent_commit: Commit
    proposer_pubkey: bytes
    timestamp: int = 0
    parent_commit_hash: bytes = b""
    proposer_signature: bytes = b""
    # 规范 §6.1 的前两个字段。**必须**保留从线上读到的原值（PROJECT_REVIEW R-4）：
    # 历史实现在解码时把它们丢弃、再用规范值重算，于是"拒绝跨版本/跨链重放"
    # （§22 第 2 项）成了空检查，且 `block_hash != Keccak(收到的字节)`。
    # 本地新建头部时二者为 `b""`，`content_fields()` 会自动填入规范值。
    protocol_version_hash: bytes = b""
    chain_id_hash: bytes = b""

    def __post_init__(self) -> None:
        # 本地构造时填入规范值；从线上解码时**保留原值**（R-4）。
        if not self.protocol_version_hash:
            self.protocol_version_hash = keccak256(P.PROTOCOL_VERSION.encode())
        if not self.chain_id_hash:
            self.chain_id_hash = keccak256(P.CHAIN_ID_BYTES)

    def content_fields(self) -> list:
        """被签名的 15 个字段（不含 `proposer_signature`，规范 §20.3）。

        `parent_commit` **MUST** 以**嵌套列表**形式出现（规范 §6.1 写的是
        `parent_commit:Commit`，而本规范对"需要预序列化的字段"一律显式写成
        `bytes`，例如 §19.5 的 `snapshot:bytes`）。历史实现这里写的是
        `parent_commit.to_rlp()` 字节串，与规范不同 ⇒ 区块哈希不同。
        """
        return [
            self.protocol_version_hash or keccak256(P.PROTOCOL_VERSION.encode()),
            self.chain_id_hash or keccak256(P.CHAIN_ID_BYTES),
            self.height, self.round, self.claimed_slot, self.timestamp,
            self.parent_hash, self.parent_commit_hash,
            self.tx_root, self.receipt_root, self.state_root,
            self.gas_used, self.base_fee_per_gas,
            self.parent_commit.to_fields(), self.proposer_pubkey,
        ]

    def to_content_rlp(self) -> bytes:
        return encode(self.content_fields())

    def to_rlp(self) -> bytes:
        return encode(self.content_fields() + [self.proposer_signature])

    @classmethod
    def from_rlp(cls, raw) -> "BlockHeader":
        if isinstance(raw, (bytes, bytearray)):
            raw = decode(raw)
        if not isinstance(raw, list) or len(raw) != 16:
            raise BlockError(1, "区块头必须为 16 项列表")
        # BUG-49：整数字段必须走 `require_canonical_int`（拒绝前导零/长度前缀
        # 形式的非最小编码），否则两个实现会对同一区块是否合法产生分歧。
        i = require_canonical_int
        if len(raw[0]) != 32 or len(raw[1]) != 32:
            raise BlockError(2, "协议版本/链身份哈希必须为 32 字节")
        return cls(height=i(raw[2]), round=i(raw[3]), claimed_slot=i(raw[4]),
                   timestamp=i(raw[5]), parent_hash=bytes(raw[6]),
                   parent_commit_hash=bytes(raw[7]), tx_root=bytes(raw[8]),
                   receipt_root=bytes(raw[9]), state_root=bytes(raw[10]),
                   gas_used=i(raw[11]), base_fee_per_gas=i(raw[12]),
                   parent_commit=Commit.from_rlp(raw[13]),
                   proposer_pubkey=bytes(raw[14]),
                   proposer_signature=bytes(raw[15]),
                   protocol_version_hash=bytes(raw[0]),
                   chain_id_hash=bytes(raw[1]))

    def signing_payload(self) -> bytes:
        """规范 §20.3：提案签名载荷 = `CHAIN(tag, chain_id, RLP(头内容))`。"""
        return P.TAG_PROPOSAL + chain(P.CHAIN_ID_BYTES, self.to_content_rlp())

    def block_hash(self) -> bytes:
        return keccak256(self.to_rlp())

    @property
    def proposer(self) -> bytes:
        return address_from_pubkey(self.proposer_pubkey)

    def check_identity_fields(self) -> None:
        """规范 §22 第 2 项 / §16.4.2 第 3 项：两个身份哈希必须等于规范值。

        这是**唯一**能阻止"跨协议版本 / 跨链重放区块"的检查。实现 **MUST** 在
        解码后、接受区块前调用它（历史上本检查从未被生产路径调用过）。
        """
        want_pv = keccak256(P.PROTOCOL_VERSION.encode())
        want_cid = keccak256(P.CHAIN_ID_BYTES)
        # 本地新建的头部这两个字段为 `b""`（表示"按规范值编码"，见 `content_fields`）；
        # 从线上解码的头部则**必有** 32 字节原值，因此这里比较的是**有效值**：
        # 伪造/跨版本/跨链的头部一律在此被拒。
        if (self.protocol_version_hash or want_pv) != want_pv:
            raise BlockError(2, "protocol_version_hash 不匹配（拒绝跨协议版本重放）")
        if (self.chain_id_hash or want_cid) != want_cid:
            raise BlockError(2, "chain_id_hash 不匹配（拒绝跨链重放）")

    def finalize_timestamp(self) -> None:
        self.timestamp = P.block_timestamp(self.claimed_slot)

    def finalize_parent_commit_hash(self) -> None:
        self.parent_commit_hash = self.parent_commit.rlp_hash()

    def verify_proposer_signature(self) -> bool:
        if len(self.proposer_pubkey) != 32 or len(self.proposer_signature) != 64:
            return False
        return ed25519_verify(self.proposer_pubkey, self.signing_payload(),
                              self.proposer_signature)


@dataclass
class Block:
    """`Block = (header, transactions)`。"""
    header: BlockHeader
    transactions: List[Transaction] = field(default_factory=list)

    def to_fields(self) -> list:
        """规范 §6.1.2 的**嵌套**形式：`[BlockHeader, [Transaction, …]]`。

        历史实现把头部与每笔交易都写成"它们各自的 RLP 字节串"，与规范的
        "对象嵌套"不同（RLP 里列表与字节串前缀不同）⇒ 区块字节不同。
        """
        return [self.header.content_fields() + [self.header.proposer_signature],
                [tx.content_fields() + [tx.signature] for tx in self.transactions]]

    def to_rlp(self) -> bytes:
        return encode(self.to_fields())

    @classmethod
    def from_rlp(cls, raw) -> "Block":
        if isinstance(raw, (bytes, bytearray)):
            raw = decode(raw)
        if not isinstance(raw, list) or len(raw) != 2:
            raise BlockError(1, "区块必须为 2 项列表")
        if not isinstance(raw[0], list):
            raise BlockError(1, "区块头必须以嵌套列表形式出现（规范 §6.1.2）")
        if not isinstance(raw[1], list):
            raise BlockError(1, "交易列表必须为列表")
        return cls(header=BlockHeader.from_rlp(raw[0]),
                   transactions=[Transaction.from_rlp(t) for t in raw[1]])

    def block_hash(self) -> bytes:
        """规范 §6.1.2：`block_hash := Keccak(RLP(BlockHeader))`（**头部**哈希）。

        为什么是头部而不是"头部+交易"：§6.1 的填充顺序写明"④ 全网对**这个**
        block_hash 预投票、预提交"，而提案者签名的是**头部内容**；交易已由头部的
        `tx_root` 承诺（§6.1.1），因此头部哈希足以唯一确定整个区块。
        历史实现这里有**两个**不同的哈希（`Block.block_hash()` = 头+交易、
        `BlockHeader.block_hash()` = 头部），而规范从未定义取哪一个 —— 见 BUG-81。
        """
        return self.header.block_hash()


# ══════════════════════════════════════════════════════════════════════
# 3. 区块有效性谓词（规范 §22）
# ══════════════════════════════════════════════════════════════════════

def validate_block_header(block: Block, parent: Optional[Block], state: State,
                          estimated_current_slot: int,
                          proposer_of: Optional[callable] = None,
                          verify_parent_commit: Optional[callable] = None) -> None:
    """规范 §22 的 12 项谓词。任一项失败抛 `BlockError`。

    `proposer_of(epoch, slot, round) -> address` 为提案者选择函数（由 consensus 层提供）；
    为 `None` 时跳过第 8 项的提案者身份检查（便于在尚未实现提案者选择时测试）。

    `verify_parent_commit(commit, parent) -> (ok, why)` 用于第 6 项的**法定数**检查：
    §22 第 6 项要求 `parent_commit` 满足 §6.2 的**全部**条件（含 2/3 签名），
    而不仅仅是"height/block_hash 对得上"。为 `None` 时只做绑定检查
    （仅用于尚未接入验证者集合的单元测试；**生产路径 MUST 提供**）。
    """
    h = block.header

    # 2. 协议版本 / 链身份（规范 §22 第 2 项）：跨版本、跨链重放必须被拒绝
    h.check_identity_fields()

    # 3. height / round
    if parent is None:
        if h.height != 0:
            raise BlockError(3, f"创世块高度必须为 0，实际 {h.height}")
    else:
        if h.height != parent.header.height + 1:
            raise BlockError(3, f"高度应为 {parent.header.height + 1}，实际 {h.height}")
    if h.round > P.MAX_ROUND_WINDOW:
        raise BlockError(3, f"round {h.round} 超出消息处理上界 {P.MAX_ROUND_WINDOW}")

    # 4. claimed_slot 的单调性与全局时钟上界（规范 §5.2，BUG-6/25）
    if parent is not None:
        if not (parent.header.claimed_slot < h.claimed_slot):
            raise BlockError(4, "claimed_slot 必须严格递增")
    if h.claimed_slot > estimated_current_slot + P.CLOCK_TOLERANCE:
        raise BlockError(4, f"claimed_slot {h.claimed_slot} 超前于估计当前槽 "
                            f"{estimated_current_slot} 超过容差 {P.CLOCK_TOLERANCE}")

    # 5. 时间戳必须由槽确定（规范 §5.4）
    if h.timestamp != P.block_timestamp(h.claimed_slot):
        raise BlockError(5, f"时间戳应为 {P.block_timestamp(h.claimed_slot)}，"
                            f"实际 {h.timestamp}")

    # 6. parent_commit 合法性（规范 §6.2；创世例外见 §6.3）
    if parent is not None and parent.header.height == 0:
        # 引导期（§6.3）：创世块的最终性**是公理**（`genesis_hash` 就是信任锚），
        # 因此高度 1 的 `parent_commit` MUST 是空提交，第 6 项的绑定与法定数检查
        # 对它不适用 —— 否则第一块永远无法满足 §22，链根本无法启动。
        if not h.parent_commit.is_empty:
            raise BlockError(6, "高度 1 的 parent_commit 必须为空提交（创世无需法定数，§6.3）")
    elif parent is not None:
        if h.parent_commit.height != parent.header.height:
            raise BlockError(6, f"parent_commit.height 应为 {parent.header.height}，"
                                f"实际 {h.parent_commit.height}")
        if h.parent_commit.block_hash != parent.block_hash():
            raise BlockError(6, "parent_commit.block_hash 与父块哈希不符")
        if h.parent_commit_hash != h.parent_commit.rlp_hash():
            raise BlockError(6, "parent_commit_hash 与 parent_commit 不符")
        if verify_parent_commit is not None:
            ok_c, why_c = verify_parent_commit(h.parent_commit, parent)
            if not ok_c:
                raise BlockError(6, f"parent_commit 未达法定数或非法：{why_c}")
    else:
        if not h.parent_commit.is_empty:
            raise BlockError(6, "创世块的 parent_commit 必须为空提交")
        if h.parent_hash != NIL_HASH:
            raise BlockError(6, "创世块的 parent_hash 必须为全零")

    # 7. 父哈希一致
    if parent is not None and h.parent_hash != parent.block_hash():
        raise BlockError(7, "parent_hash 与父块哈希不符")

    # 8. 提案者授权
    if not h.verify_proposer_signature():
        raise BlockError(8, "提案者签名无效")
    if proposer_of is not None:
        want = proposer_of(P.epoch_of(h.claimed_slot), h.claimed_slot, h.round)
        if h.proposer != want:
            raise BlockError(8, f"提案者应为 {want.hex()[:12]}…，"
                                f"实际 {h.proposer.hex()[:12]}…")

    # 9. 基础费必须由父状态确定
    if parent is not None:
        expect_bf = base_fee_next(parent.header.base_fee_per_gas, parent.header.gas_used)
    else:
        expect_bf = P.INITIAL_BASE_FEE
    if h.base_fee_per_gas != expect_bf:
        raise BlockError(9, f"基础费应为 {expect_bf}，实际 {h.base_fee_per_gas}")

    # 10. 交易序列逐笔校验
    if h.gas_used > P.MAX_GAS_PER_BLOCK:
        raise BlockError(10, f"gas_used {h.gas_used} 超过 {P.MAX_GAS_PER_BLOCK}")

    # 11/12. 由调用方在重放后比对（见 apply_block）


# ══════════════════════════════════════════════════════════════════════
# 4. 区块执行（规范 §28.1）
# ══════════════════════════════════════════════════════════════════════

def _distribute_pool(st: State, pool: int, signers: Sequence[bytes]) -> Tuple[int, int]:
    """规范 §28.2 的**每块即时分配**的"分账"部分。

    返回 `(已分配总额, 销毁尘埃)`。

    调用约定（关键，避免重复铸币）：
      · 调用方**已经**把整池 `mint` 到某个临时持有者名下（池子属于新发行或已收费用）；
      · 本函数只负责把池子从临时持有者转出到各签名者，**不再 mint**；
      · 权重取纪元快照的 `VotingPower`（BUG-3），**不得**取结算时的 `effective_stake`；
      · 权重和为 0 时整池销毁（BUG-10）。
    """
    if pool <= 0:
        return 0, 0
    snap = st.system.snapshot
    weights = [(a, snap.vp_of(a)) for a in sorted(set(signers))]
    total_w = sum(w for _, w in weights)
    if total_w == 0:
        return 0, pool
    shares = []
    acc = 0
    for addr, w in weights:
        share = pool * w // total_w
        if share:
            shares.append((addr, share))
            acc += share
    return acc, pool - acc


def _pay_pool(st: State, holder: bytes, pool: int, signers: Sequence[bytes],
              minted: bool) -> None:
    """把 `pool` 从 `holder` 支付给各签名者。

    `minted=True` 表示该池是本区块**新发行**的（调用方已 `mint` 给 `holder`）；
    为 `False` 表示它已从发送者扣出（优先费），此时 `holder` 只是记账中介。
    """
    if pool <= 0:
        return
    snap = st.system.snapshot
    weights = [(a, snap.vp_of(a)) for a in sorted(set(signers))]
    total_w = sum(w for _, w in weights)
    if total_w == 0:
        # 无人有权分配 ⇒ 整池销毁
        st.burn(holder, pool, "dust")
        return
    paid = 0
    for addr, w in weights:
        share = pool * w // total_w
        if share:
            st.transfer(holder, addr, share)
            paid += share
    dust = pool - paid
    if dust:
        st.burn(holder, dust, "dust")


def prepare_block(parent_state: State, block: Block,
                  parent_block: Optional[Block] = None,
                  current_slot: Optional[int] = None) -> Block:
    """提案者出块**之前**调用：执行一次并把结果写入头部。

    返回同一个 `Block`（头部已被填充），此后其 `block_hash` 不再变化。
    提案者随后对该头部签名，因此**签名、投票、Commit 都指向同一个哈希**。
    """
    apply_block(parent_state, block, parent_block=parent_block,
                current_slot=current_slot, in_place=False, finalize_header=True)
    return block


def apply_block(parent_state: State, block: Block,
                parent_block: Optional[Block] = None,
                current_slot: Optional[int] = None,
                in_place: bool = False,
                finalize_header: bool = True,
                receipts_out: Optional[List[dict]] = None) -> State:
    """规范 §28.1 的 9 个阶段。返回**新区块之后**的状态。

    `in_place=False`（默认）时先深拷贝父状态，因此可以安全地"试着执行"一个区块
    而不污染父状态 —— 这是区块校验必须的行为。

    `receipts_out`：**执行侧**把本块的真实回执追加进去（调用方可选）。
    为什么需要它：回执里的 `gas_used` 取决于"该交易是否**新建账户**"（+25,000 gas），
    而这只能由**执行时**的状态判断。区块里只承诺了 `receipt_root`，
    所以事后想拿到精确回执，必须在执行的那一刻把它记下来
    （否则查询接口只能给近似值 —— 钱包据此显示的**手续费会是错的**）。

    ⚠ 顺序不可调换：参与记录 → 纪元推进/结算 → 交易 → 费用 → 发行 → 即时分配
      → 年度销毁 → 账户回收 → **最后**算 `state_root`。

    **本函数 MUST 是 `(父状态, 区块)` 的纯函数（BUG-92，MUST）。**
    规范 §22 第 11 项要求"重放得到的 `state_root` 等于头部承诺"，而节点重启后
    正是**从区块日志重放**来恢复状态（`agora/store.py`）。只要执行结果还依赖任何
    **链外**输入（本机的时钟估计、调用方临时传进来的父块对象…），重放就会算出
    另一个状态根，"持久化恢复"必然失败、且**任何**两节点都可能随时分歧。

    因此这里把两个参数都改成**校验项**而不是输入项：

    * 阶段 1 的参与/不活跃计数**只看区块头里的 `parent_commit`**（链上数据），
      不再以"调用方是否传了 `parent_block`"为门 —— 曾经的写法让**重放路径**
      （不传父块）整段跳过阶段 1，于是第一个被重放的区块就与实时执行分叉；
    * `current_slot` 若被传入，**必须**等于 `block.header.claimed_slot`，否则报错。
      执行槽只能取自链上数据：早先实时路径传的是本机时钟估计
      （`self.estimated_slot`），一旦两个节点的估计不同，同一区块就会算出
      不同的状态根 —— 这不是理论问题，而是"节点自己拒绝自己的链"的成因。
    """
    st = parent_state if in_place else copy.deepcopy(parent_state)
    h = block.header
    # 规范 §22 第 2 项：身份字段必须在**接受区块的状态转移**里校验。
    # （`validate_block_header` 是 §22 的完整谓词，但历史实现的生产路径并未调用它；
    #  这里把与共识身份有关的检查直接前置到状态转移入口，见 PROJECT_REVIEW R-4/A8。）
    h.check_identity_fields()
    E = P.epoch_of(h.claimed_slot)

    # ── 纯函数自检（BUG-92）：链外输入**不得**改变执行结果 ──
    if current_slot is not None and current_slot != h.claimed_slot:
        raise BlockError(
            11, f"执行槽只能取自链上数据：调用方给了 current_slot={current_slot}，"
                f"而区块头 claimed_slot={h.claimed_slot}"
                f"（状态转移 MUST NOT 依赖本机时钟估计）")
    if (parent_block is not None and h.height > 0
            and parent_block.block_hash() != h.parent_hash):
        raise BlockError(
            7, f"调用方给的 parent_block 与区块的 parent_hash 不符："
               f"{parent_block.block_hash().hex()[:12]}… ≠ {h.parent_hash.hex()[:12]}…")

    # ── 阶段 1：父高度参与与不活跃计数（必须在结算之前）──
    # 门是**高度**（链上数据），不是"调用方有没有传父块"（BUG-92）：
    # 重放路径不传父块，若以此为止回门，重放就会整段跳过阶段 1 而与实时执行分叉。
    if h.height > 0:
        pc = h.parent_commit
        signer_addrs = set(pc.addresses())
        for addr in list(st.system.snapshot.membership):
            rec = st.get_validator(addr)
            if rec is None:
                continue
            if addr in signer_addrs:
                if rec.inactivity_streak:
                    rec.inactivity_streak = 0
                    st.set_validator(addr, rec)
            else:
                rec.inactivity_streak += 1
                st.set_validator(addr, rec)

    # ── 阶段 2：纪元推进与边界结算 ──
    if E > st.system.epoch_current:
        settle_epoch(st, h.claimed_slot)
        st.system.epoch_current = E
    elif E < st.system.epoch_current:
        raise BlockError(4, f"纪元回退：{E} < {st.system.epoch_current}")

    # ── 阶段 3：交易执行（先扣费，后执行；规范 §16.4.2 第 18 项）──
    #
    # 记账口径（必须严格照此，否则供应量守恒会被破坏）：
    #   · 基础费：从发送者扣出后**立即销毁**（规范 §23）
    #   · 优先费：从发送者扣出 → 20% 给提案者，80% 进入见证池
    receipts = []
    block_gas = 0
    attest_pool = 0
    for tx in block.transactions:
        creates = bool(tx.to) and st.get_account(tx.to) is None and tx.value > 0
        gu = tx.gas_used(creates)
        res = validate_tx(tx, st, h.base_fee_per_gas, block_gas,
                          current_slot=h.claimed_slot)
        if not res.ok:
            if res.failed_at == 17:
                continue                       # 规范：跳过该交易，不拒绝区块
            raise BlockError(10, f"交易 {tx.tx_hash().hex()[:12]}… 校验失败：{res}")

        sender = tx.sender
        q = fee_quote(gu, h.base_fee_per_gas, tx.max_fee_per_gas,
                      tx.max_priority_fee_per_gas)

        # ① 校验门槛（规范 §16.4.2 第 10 项）：余额须覆盖 gas_limit×max_fee + value。
        #    这是**门槛检查**，不是实际扣费额 —— 实际只收 eff×gu。
        # ② 执行状态变更（本版本无失败分支；此时 value 的转账由 _execute_tx 完成）
        _execute_tx(st, tx, res, h.claimed_slot)
        # ③ 收取实际费用：eff × gu（基础费 + 优先费），一次性从发送者扣出。
        #    注意：**不得**先按 max_fee 扣再退，也不得与 burn 叠加——
        #    那会造成双重扣款，使余额低于"余额之和 == total_supply"的守恒要求。
        st.deduct(sender, q.total_fee, purpose="tx fee")
        # ④ 基础费部分立即销毁（规范 §23：100% 销毁）
        if q.burn_amount:
            st.burn_supply(q.burn_amount, "basefee")
        # ⑤ 优先费部分：提案者 20%，其余进见证池
        if q.priority_amount:
            prop_share, rest = P.split_proposer_attestation(q.priority_amount)
            if prop_share:
                st._credit_neutral(h.proposer, prop_share)
            attest_pool += rest
        # ⑥ nonce +1
        acc = st.account_or_empty(sender)
        acc.nonce += 1
        st.set_account(sender, acc)

        block_gas += gu
        receipts.append({"tx_hash": tx.tx_hash(), "gas_used": gu,
                         "status": "SUCCESS",
                         "effective_gas_price": q.effective_gas_price,
                         # 额外记录"是否新建账户"：它是 gas 差额的唯一原因，
                         # 排查"我算的手续费和链上不一致"时第一眼就要看它。
                         "creates_account": bool(creates)})

    # ── 阶段 4：发行与即时分配（规范 §28.2 / §28.4 / §28.4.1）──
    # 第二个参数**必须**是本块的 `claimed_slot`（头部被签名字段）：
    # 过渡期奖励地板按槽判定（§28.4.1），用本地时间或父块槽都会分叉。
    reward = P.block_reward(st.system.snapshot.staked_supply, h.claimed_slot)
    reward_prop, reward_pool = P.split_proposer_attestation(reward)
    st.mint(h.proposer, reward)                       # 本区块的全部发行
    if reward_pool:
        # 见证池：从提案者转出给各签名者，余数销毁
        _pay_pool(st, h.proposer, reward_pool, h.parent_commit.addresses(), minted=True)
    if attest_pool:
        # 优先费池：先把已扣出的池子暂存在系统账户，再转给签名者
        st._credit_neutral(P.SYSTEM_ADDRESS, attest_pool)
        _pay_pool(st, P.SYSTEM_ADDRESS, attest_pool,
                  h.parent_commit.addresses(), minted=False)

    # ── 阶段 5：年度销毁（规范 §28.5，带硬上界的循环）──
    burns = 0
    while (h.claimed_slot >= st.system.year_start_slot + P.PROTOCOL_YEAR_SLOTS
           and burns < P.MAX_YEAR_BURNS_PER_BLOCK):
        burn_amt = st.system.total_supply * P.ANNUAL_BURN_RATE_PPM // 1_000_000
        if burn_amt:
            # 年度销毁是**单边**销毁：它没有从任何余额或质押扣钱，
            # 而是直接从总供应量中抽走 5%（§28.5 "口径 = 总供应"）。
            # 因此必须传 `unbacked=True`，把它累加进 `total_burned_unbacked`，
            # 使守恒等式 `counted == total_supply + total_burned_unbacked` 配平。
            # 对比：`settle_epoch` 的惩罚/罚没销毁传默认 `unbacked=False`，
            # 因为那里调用方已经先从质押池/余额扣了钱。
            st.burn_supply(burn_amt, "annual", unbacked=True)
        st.system.year_start_slot += P.PROTOCOL_YEAR_SLOTS
        st.system.year_index += 1
        burns += 1

    # ── 阶段 6：账户回收（规范 §19.3）──
    prune_empty_accounts(st)

    # ── 阶段 7：结算系统状态 ──
    st.flush_system()

    # ── 阶段 8：同步头部的确定性字段（**仅当调用方要求时**）──
    #
    # 关键设计（BUG-45）：区块哈希必须在**签名之前**就最终确定。
    # 若在这里改写头部，则提案者签名与全部预提交所指向的 `block_hash`
    # 会变成"另一个块"，Commit 校验必然失败（症状是
    # "block_hash 与父块哈希不符"，而错误信息指向 Commit 而非头部，极易误导）。
    #
    # 因此提供两种入口：
    #   · `prepare_block`  —— 提案者在出块**之前**调用，执行一次并填充头部；
    #                         之后头部不再变化，哈希在整个共识过程中恒定。
    #   · `apply_block`    —— 最终化时调用，`finalize_header=False` 表示
    if receipts_out is not None:
        receipts_out.extend(receipts)
    #                         头部已确定，只推进状态。
    if finalize_header:
        h.gas_used = block_gas
        h.receipt_root = receipt_root(receipts)
        h.tx_root = tx_root(block.transactions)
        h.state_root = st.state_root
        h.finalize_parent_commit_hash()
    else:
        # 规范 §22 第 11 项：**三个**派生量都必须与重放结果一致。
        # 历史实现只比对 state_root 与 gas_used，于是伪造 `tx_root`/`receipt_root`
        # 的区块（承诺了不存在的交易/收据）仍会被接受（PROJECT_REVIEW A29）。
        if h.state_root != st.state_root:
            raise BlockError(
                11, f"区块声明的 state_root 与实际执行结果不符："
                    f"声明 {h.state_root.hex()[:12]}…，实际 {st.state_root.hex()[:12]}…")
        if h.gas_used != block_gas:
            raise BlockError(
                11, f"区块声明的 gas_used {h.gas_used} 与实际 {block_gas} 不符")
        if h.tx_root != tx_root(block.transactions):
            raise BlockError(11, "区块声明的 tx_root 与实际交易列表不符")
        if h.receipt_root != receipt_root(receipts):
            raise BlockError(11, "区块声明的 receipt_root 与实际收据不符")
    return st


def _sum_distributed(pool: int, st: State, block: Block) -> int:
    """辅助：计算实际分配额（占位实现，见 apply_block 的说明）。"""
    snap = st.system.snapshot
    addrs = sorted(set(block.header.parent_commit.addresses()))
    total_w = sum(snap.vp_of(a) for a in addrs)
    if total_w == 0:
        return 0
    return sum(pool * snap.vp_of(a) // total_w for a in addrs)


def _execute_tx(st: State, tx: Transaction, res, current_slot: int = 0) -> None:
    """执行一笔交易的状态变更（规范 §16.2）。本版本**不存在失败分支**。"""
    if tx.tx_type == TxType.TRANSFER:
        if tx.value:
            if tx.to:
                st.transfer(tx.sender, tx.to, tx.value)
            else:
                # 无 to 的转账视为销毁（本版本保留但极少使用）
                st.burn(tx.sender, tx.value, "dust")
        return

    if tx.tx_type == TxType.BOND:
        p = tx.decoded_payload()
        st.deduct(tx.sender, tx.value, purpose="bond")
        rec = st.get_validator(tx.sender) or ValidatorRecord(pubkey=p["pubkey"])
        rec.pubkey = p["pubkey"]
        # 规范 §7.3（BUG-42）：投票权变更**只在纪元边界生效**。
        # 因此新质押先进入 `pending_stake`，由 `_freeze_snapshot` 在边界并入
        # `effective_stake`。若立即并入，则纪元内的 `effective_stake` 会与
        # 快照中的 `VotingPower` 不一致 —— 罚没基数、发行曲线、法定数三者
        # 会各自取到不同的值，产生分歧。
        rec.pending_stake += tx.value
        if rec.status == STATUS_UNBONDED:
            rec.status = STATUS_BONDED
        st.set_validator(tx.sender, rec)
        return

    if tx.tx_type == TxType.UNBOND:
        p = tx.decoded_payload()
        rec = st.get_validator(tx.sender)
        amt = p["amount"]
        # §19.4 科目映射：`UNBOND: effective_stake → unbonding_balance`，**绝不进入 balance**。
        # 两部分分开处理，**任何一部分都不得被丢弃**（BUG-84，实测：旧实现丢掉
        # 从 `pending_stake` 撤回的那部分 ⇒ 守恒等式缺口正好等于该金额）：
        #   · 从 `pending_stake` 撤回（追加质押尚未生效）→ **立即**进 `unbonding_balance`；
        #   · 从 `effective_stake` 解绑                        → 记入 `pending_unbond`，
        #     由纪元边界转入 `unbonding_balance`（保持"投票权只在边界变化"）。
        take_pending = min(amt, rec.pending_stake)
        rec.pending_stake -= take_pending
        rec.unbonding_balance += take_pending
        rest = amt - take_pending
        if rest:
            rec.pending_unbond += rest
        # §14.2 完成时刻：`max(请求槽 + 21 天, 最后可罚没槽 + 21 天 + ε)`
        rec.unbond_request_slot = current_slot
        rec.unbond_complete_slot = max(
            current_slot + P.UNBONDING_PERIOD_SLOTS,
            rec.last_slashable_slot + P.UNBONDING_PERIOD_SLOTS
            + P.UNBOND_COMPLETION_EPSILON_SLOTS)
        rec.status = STATUS_UNBONDING
        st.set_validator(tx.sender, rec)
        return

    if tx.tx_type == TxType.REBOND:
        rec = st.get_validator(tx.sender)
        # §19.4：`REBOND: unbonding_balance → effective_stake`。
        # 旧实现只清了 `pending_unbond`、**没有把钱从 unbonding_balance 移回**
        # ⇒ 与映射表不符（且 `rebond` 后钱仍可被 WITHDRAW 提走）。
        amt = min(tx.decoded_payload()["amount"], rec.unbonding_balance)
        rec.unbonding_balance -= amt
        rec.effective_stake += amt
        rec.pending_unbond = 0          # 未生效的解绑请求直接作废（那部分钱从未离开 effective）
        rec.status = STATUS_BONDED
        rec.unbond_request_slot = 0
        rec.unbond_complete_slot = 0
        st.set_validator(tx.sender, rec)
        return

    if tx.tx_type == TxType.WITHDRAW:
        rec = st.get_validator(tx.sender)
        amt = rec.unbonding_balance
        rec.unbonding_balance = 0
        # 规范 §19.4：`WITHDRAW: unbonding_balance → balance`，**仅当**
        # `claimed_slot ≥ unbond_complete_slot`（校验层已强制，见 §16.4.2 第 13 项）。
        #
        # **不得**无条件把状态置为 UNBONDED（A22）：仍有 `effective_stake` 的验证者
        # 只是取走了"已解绑的那部分"，其共识席位必须保留。旧实现无条件置 UNBONDED，
        # 会把这个验证者在下一个纪元边界静默踢出集合。
        if rec.effective_stake == 0:
            rec.status = STATUS_UNBONDED
        rec.unbond_complete_slot = 0
        st.set_validator(tx.sender, rec)
        st._credit_neutral(tx.sender, amt)
        return

    if tx.tx_type == TxType.EVIDENCE:
        ev = tx.evidence()
        offender = ev.offender
        rec = st.get_validator(offender)
        base = st.system.snapshot.vp_of(offender) or (
            rec.effective_stake if rec else 0)
        st.system.pending_slashes.append(PendingSlash(
            offender=offender, evidence_class=ev.evidence_class,
            offense_slot=ev.offending_slot, recorded_base=base,
            submitter=tx.sender))
        # §14.2：解绑完成时刻依赖"最后可罚没槽" —— 罚没窗口自该槽起算，
        # 必须在此更新，否则解绑者可在证据窗口内把钱提走（A17 的另一半）。
        if rec is not None:
            rec.last_slashable_slot = max(
                rec.last_slashable_slot,
                ev.offending_slot + P.SLASH_WINDOW_SLOTS)
            st.set_validator(offender, rec)
        return

    if tx.tx_type == TxType.AIRDROP_CLAIM:
        cl = tx.airdrop_claim()
        # BUG-48：这里曾调用 `st.debit()`——该方法已按 BUG-37 移除（任何"只动余额、
        # 不改 total_supply"的入口都必须消失），因此**任何空投领取都会抛
        # RuntimeError 使节点崩溃**。领取是金库 → 受益人的**中性转账**：
        # 两侧都是真实账户余额，`total_supply` 不变，必须走 `transfer`。
        st.transfer(P.AIRDROP_VAULT_ADDRESS, tx.sender, cl.amount)
        st.system.airdrop_pending -= cl.amount
        st.system.airdrop_claimed.append((tx.sender, cl.index))
        return

    raise BlockError(2, f"未实现的交易类型 0x{tx.tx_type:02x}")


# ══════════════════════════════════════════════════════════════════════
# 5. 纪元边界结算（规范 §28.6）
# ══════════════════════════════════════════════════════════════════════

def settle_epoch(st: State, current_slot: int) -> None:
    """规范 §28.6：结算**当前快照**所对应的纪元，然后冻结下一个快照。

    顺序要求（BUG-9）：先冻结基数，再算不活跃与罚没，最后一次性写回，
    使两个扣减的执行顺序**不影响结果**。
    """
    snap = st.system.snapshot

    # (0) 冻结基线
    base_stake = {a: snap.vp_of(a) for a in snap.membership}
    ded_inact = {a: 0 for a in snap.membership}
    ded_slash = {a: 0 for a in snap.membership}       # 从被罚没者收走的全额
    ded_slash_burn = {}                               # 其中需要销毁的部分（80%）

    # (1)+(2) 扣款额计算 —— **全部按人聚合、且结构性不超过可用资金**
    #
    # 规范 §28.6 的修订要点（PROJECT_REVIEW R-5，本节是唯一权威实现）：
    #   ① 上限**按人聚合**：逐条施加上限时，同一人的多条证据会各自"通过"检查，
    #      累加后超过其全部可扣资金，而销毁额按累加值记账 ⇒ total_supply 被销毁得
    #      比真实扣走的钱更多，守恒等式当场失效（实测 25 条双签即差 16 AGORA）；
    #   ② 不活跃惩罚同样可能超过可用资金（公式在 k 很大时 ppm 可 > 100%）⇒ 一并设界；
    #   ③ 扣款对象包含**已不在快照内**的被罚没者（§7.6 / D12：解绑者仍可罚没）。
    #
    # `avail[v]` 在结算开始时**一次冻结**，随后被不活跃与罚没依次递减，
    # 因此在 (3) 应用扣款时**不可能**出现"扣不满"的情形，
    # 于是 `销毁额 == 实际扣款额` 恒成立 ⇒ 守恒等式是**结构性**成立的，而不是巧合。
    avail: dict = {}

    def _available(addr: bytes) -> int:
        rec = st.get_validator(addr)
        return (base_stake.get(addr, 0)
                + (rec.unbonding_balance if rec else 0)
                + st.account_or_empty(addr).balance)

    # (1) 不活跃惩罚（以冻结基线计算，规范 §13.2；再按可用资金设界）
    for addr in snap.membership:
        rec = st.get_validator(addr)
        if rec is None:
            continue
        k = rec.inactivity_streak
        if k >= P.INACTIVITY_WINDOW:
            avail[addr] = _available(addr)
            want = P.inactivity_deduction(base_stake[addr], k)
            ded_inact[addr] = min(want, avail[addr])
            avail[addr] -= ded_inact[addr]

    # (2) 罚没（以入块时记录的 recorded_base 计算，规范 §15.4）
    #
    # 记账口径（必须精确，否则供应量对不上）：
    #   罚没额 amt 从头到尾都是**从被罚没者收走**的：
    #     · 其中 20% 转给证据提交者 —— 这是**再分配**，不改变 total_supply
    #     · 其余 80% 销毁        —— 只有这部分离开 total_supply
    #   因此 (3b) 中要销毁的是 `amt − reward`，而**不是**整个 amt。
    #   早期实现把整个 amt 都记成销毁，导致凭空少了 20%（被守恒检查抓到）。
    for ps in sorted(st.system.pending_slashes,
                     key=lambda x: (x.offense_slot, x.offender)):
        v = ps.offender
        if v not in avail:                   # 未做不活跃扣减的地址（含非成员）
            avail[v] = _available(v)
        amt = P.slash_amount(ps.recorded_base, ps.evidence_class)
        amt = max(0, min(amt, avail[v]))     # ← 按人聚合的上限（递减同一个余额）
        avail[v] -= amt
        ded_slash[v] = ded_slash.get(v, 0) + amt
        # 罚没额的 20% 给证据提交者；其余在 (3b) 通过系统销毁实现。
        # 注意：**不得**用 "credit 给系统账户再 burn" 的写法 —— 那会在系统账户
        # 留下余额，使"余额之和 == total_supply"的守恒等式失效。
        reward = amt * P.EVIDENCE_REWARD_PPM // 1_000_000
        st._credit_neutral(ps.submitter, reward)      # 再分配：提交者得到 20%
        ded_slash_burn[v] = ded_slash_burn.get(v, 0) + (amt - reward)
        st.system.settled_slashes.append(
            (v, ps.evidence_class, ps.offense_slot))

    # (3) 一次性应用扣减（超出基线的部分依次取 unbonding_balance、balance）
    ded_inact_total = 0
    ded_slash_burn_total = sum(ded_slash_burn.values())
    _members = set(snap.membership)
    _targets = list(snap.membership) + [a for a in ded_slash if a not in _members]
    for addr in _targets:
        total = ded_inact.get(addr, 0) + ded_slash.get(addr, 0)
        if not total:
            continue
        ded_inact_total += ded_inact.get(addr, 0)
        rec = st.get_validator(addr)
        base = base_stake.get(addr, 0)
        if rec is None:
            # 没有验证者记录 ⇒ 无质押科目，只能从余额扣（avail 上界保证够扣）
            acc = st.account_or_empty(addr)
            assert acc.balance >= total, "罚没额超过可扣余额（avail 上界失效）"
            acc.balance -= total
            st.set_account(addr, acc)
            continue
        rec.effective_stake = max(0, base - total)
        overflow = total - base
        if overflow > 0:
            take = min(overflow, rec.unbonding_balance)
            rec.unbonding_balance -= take
            overflow -= take
            if overflow > 0:
                acc = st.account_or_empty(addr)
                assert acc.balance >= overflow, "罚没额超过余额（avail 上界失效）"
                acc.balance -= overflow
                st.set_account(addr, acc)
        rec.slashed_total += ded_slash.get(addr, 0)
        st.set_validator(addr, rec)

    # (3b) **同步销毁**：扣掉的钱必须离开 `total_supply`，否则破坏守恒
    #      （规范 §19.5）。不活跃惩罚与罚没销毁分别记入各自的分账科目。
    if ded_inact_total:
        st.burn_supply(ded_inact_total, "inactivity")
    if ded_slash_burn_total:
        st.burn_supply(ded_slash_burn_total, "slash")
    st.system.pending_slashes = []

    # (4) 成员资格结算（规范 §7.6）
    for addr in list(st.validators.keys()):
        rec = st.get_validator(addr)
        if rec.status == STATUS_UNBONDING and current_slot >= rec.unbond_complete_slot > 0:
            rec.status = STATUS_UNBONDED
            # 解绑期结束后退出集合：**剩余质押必须转入 `unbonding_balance`**，
            # 不得留在 `effective_stake` 里（那会让它既不算票、又提不出来，等于锁死）。
            # 转入 `unbonding_balance` 而非 `balance` 是刻意的：它在窗口内**仍可被罚没**
            # （§14.3 / §19.4 的"仍可罚没"），且由 `unbond_complete_slot` 控制提取时机。
            rec.unbonding_balance += rec.effective_stake
            rec.effective_stake = 0
            st.set_validator(addr, rec)
        if rec.status == STATUS_BONDED and rec.effective_stake < P.MIN_VALIDATOR_STAKE:
            rec.status = STATUS_UNBONDED
            st._credit_neutral(addr, rec.effective_stake + rec.unbonding_balance)
            rec.effective_stake = 0
            rec.unbonding_balance = 0
            st.set_validator(addr, rec)

    # (5) 冻结新快照
    _freeze_snapshot(st)


def _freeze_snapshot(st: State) -> None:
    """规范 §7.1 + §7.3 + §7.6：先把待生效的质押变动并入，再冻结新快照。

    这里是**唯一**让 `pending_stake` 生效的地方 —— 保证"投票权只在纪元边界变化"。
    """
    for addr, rec in list(st.validators.items()):
        changed = False
        if rec.pending_stake:
            rec.effective_stake += rec.pending_stake
            rec.pending_stake = 0
            changed = True
        pend_unbond = rec.pending_unbond
        if pend_unbond:
            take = min(pend_unbond, rec.effective_stake)
            rec.effective_stake -= take
            rec.unbonding_balance += take
            rec.pending_unbond = 0
            changed = True
        if changed:
            st.set_validator(addr, rec)

    candidates = [(addr, rec) for addr, rec in st.validators.items()
                  if rec.status == STATUS_BONDED
                  and rec.effective_stake >= P.MIN_VALIDATOR_STAKE]
    candidates.sort(key=lambda kv: (-kv[1].effective_stake, kv[0]))
    chosen = candidates[:P.MAX_VALIDATORS]
    membership = sorted(addr for addr, _ in chosen)
    vp = sorted(((addr, rec.effective_stake) for addr, rec in chosen),
                key=lambda kv: kv[0])
    st.system.snapshot = SnapshotSet(
        membership=membership, voting_power=vp,
        staked_supply=sum(v for _, v in vp),
        records=[rec.to_rlp() for _, rec in sorted(chosen, key=lambda kv: kv[0])])


# ══════════════════════════════════════════════════════════════════════
# 6. 根与回收
# ══════════════════════════════════════════════════════════════════════

def tx_root(transactions: Sequence[Transaction]) -> bytes:
    """交易根。空区块时为 `Keccak(RLP([]))`。"""
    if not transactions:
        return keccak256(encode([]))
    return keccak256(encode([tx_hash_leaf(t) for t in transactions]))


def tx_hash_leaf(tx: Transaction) -> bytes:
    return tx.tx_hash()


def receipt_root(receipts: Sequence[dict]) -> bytes:
    if not receipts:
        return keccak256(encode([]))
    leaves = []
    for r in receipts:
        leaves.append(keccak256(encode([
            r["tx_hash"], r["gas_used"], 1 if r["status"] == "SUCCESS" else 0,
            r["effective_gas_price"]])))
    return keccak256(encode(leaves))


def prune_empty_accounts(st: State) -> int:
    """规范 §19.3：删除满足条件的账户。返回删除数量。

    必须遍历**已哈希键**并逐条判断，不能只处理本区块触及的账户 ——
    否则"何时回收"会依赖实现细节，产生状态根分歧。
    """
    victims = []
    for hashed_key, raw in st.accounts.items():
        acc = Account.from_rlp(raw)
        if meets_account_pruning_rule(acc):
            victims.append(hashed_key)
    for hk in victims:
        st.accounts.delete_raw_hashed(hk)
    return len(victims)
