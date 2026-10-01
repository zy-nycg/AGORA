# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 共识状态机
====================================

对应规范：
    §6.4  最终性
    §9    法定数与最终性（T1/T2/T3）
    §10   锁定与解锁
    §11   超时模型（三阶段独立 + 轮次超时）
    §12   提案者选择
    §23.3 步骤转换表（13 行）

设计要点
--------
1. **本模块不涉及任何网络 I/O**。它把"收到消息 → 状态转换 → 要广播什么"建模为
   纯函数式的状态机，因此可以在单进程内确定性地测试（含拜占庭注入）。
   真正的节点只需把 `Action` 发出去、把收到的消息喂进 `on_proposal` / `on_vote`。
2. **一轮只发一次预投票、一次预提交**（§23.3 的注意事项）。用 `sent_*` 标志保证；
   这是安全论证的必要条件 —— 重复发送会让同一验证者在同一轮签出两个不同的值。
3. **锁定不可随意解除**（§10）：只有 `LockProof`（更高轮次对另一区块的 2/3 预投票）
   才能替换锁定值。实现不得以"更优区块"之类的理由解锁。
4. **超时是不同层级的计时器**（§11.3）：三阶段超时是阶段内上限，
   `ROUND_TIMEOUT(r)` 是整轮上限；二者不相加、也不互相推导。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import params as P
from .block import Block, BlockHeader, Commit, CommitSignature, precommit_payload
from .codec import RLPDecodeError, decode, encode
from .crypto_backend import (address_from_pubkey, chain, keccak256, sign,
                             verify as ed25519_verify)
from .state import SnapshotSet, State, ValidatorRecord

__all__ = [
    "Step", "VoteType", "Vote", "LockProof", "Proposal", "Action",
    "ActionKind", "HeightState", "ConsensusNode", "SafetyViolation",
    "epoch_seed", "select_proposer", "proposer_for", "seed_from_parent",
    "selection_randomness", "vote_signing_payload",
]


class SafetyViolation(RuntimeError):
    """安全属性被违反（T1/T2）。出现即说明实现或测试注入有误。"""


class Step(IntEnum):
    """规范 §6.1 的步骤。`Commit` 不是 step —— 它是区块内的 `parent_commit` 字段。"""
    PROPOSE = 0
    PREVOTE = 1
    PRECOMMIT = 2


class VoteType(IntEnum):
    PREVOTE = 0x01
    PRECOMMIT = 0x02


NIL_HASH = b"\x00" * 32


# ══════════════════════════════════════════════════════════════════════
# 1. 消息对象（规范 §23.2、§16.3）
# ══════════════════════════════════════════════════════════════════════

# 投票签名载荷的**唯一实现**在 `agora/tx.py`（BUG-67 起）。
#
# 依赖方向为 `consensus → block → tx`，所以唯一实现放在依赖链下游（`tx`），
# 本模块只重导出。此前本模块**另有一份**实现，且与 tx 那份的标签处理方式不同
# ⇒ 同一份规范产出两种签名载荷，投票与 Commit 校验互相验不过。
from .tx import vote_signing_payload                 # noqa: E402,F401


@dataclass(frozen=True)
class Vote:
    """`Vote = RLP([height, round, vote_type, block_hash|NIL, address, signature])`"""
    height: int
    round: int
    vote_type: int
    block_hash: bytes                 # NIL_HASH 表示 nil 投票
    address: bytes
    signature: bytes = b""

    @property
    def is_nil(self) -> bool:
        return self.block_hash == NIL_HASH

    def signing_payload(self) -> bytes:
        return vote_signing_payload(self.height, self.round, self.vote_type,
                                    None if self.is_nil else self.block_hash)

    def to_rlp(self) -> bytes:
        return encode([self.height, self.round, int(self.vote_type),
                       self.block_hash, self.address, self.signature])

    @classmethod
    def from_rlp(cls, raw) -> "Vote":
        if isinstance(raw, (bytes, bytearray)):
            raw = decode(raw)
        if not isinstance(raw, list) or len(raw) != 6:
            raise ValueError("Vote 必须为 6 项列表")
        i = lambda b: int.from_bytes(b, "big")            # noqa: E731
        return cls(height=i(raw[0]), round=i(raw[1]), vote_type=i(raw[2]),
                   block_hash=bytes(raw[3]), address=bytes(raw[4]),
                   signature=bytes(raw[5]))

    def verify(self, pubkey: bytes) -> bool:
        if len(pubkey) != 32 or len(self.signature) != 64:
            return False
        if self.vote_type not in (VoteType.PREVOTE, VoteType.PRECOMMIT):
            return False
        if len(self.block_hash) != 32 or len(self.address) != 20:
            return False
        return ed25519_verify(pubkey, self.signing_payload(), self.signature)

    @staticmethod
    def create(seed: bytes, height: int, round_: int, vote_type: int,
               block_hash: Optional[bytes], address: bytes) -> "Vote":
        v = Vote(height=height, round=round_, vote_type=int(vote_type),
                 block_hash=(NIL_HASH if block_hash is None else block_hash),
                 address=address)
        return Vote(height=v.height, round=v.round, vote_type=v.vote_type,
                    block_hash=v.block_hash, address=v.address,
                    signature=sign(seed, v.signing_payload()))


@dataclass(frozen=True)
class LockProof:
    """规范 §10：更高轮次对某区块的 2/3 预投票，是解锁的唯一依据。"""
    height: int
    round: int
    block_hash: bytes
    signatures: Tuple[CommitSignature, ...] = ()

    def to_rlp(self) -> bytes:
        return encode([self.height, self.round, self.block_hash,
                       [s.to_rlp() for s in self.signatures]])

    @classmethod
    def from_rlp(cls, raw) -> "LockProof":
        """反序列化。传输层（规范 §6.5 的跨机通信）必需。

        校验每一项的长度与类型：**跨机收到的字节一律不可信**，
        长度不符必须在解码处拒绝，而不是留到后续逻辑里以奇怪的方式失败。
        """
        if isinstance(raw, (bytes, bytearray)):
            raw = decode(raw)
        if not isinstance(raw, list) or len(raw) != 4:
            raise RLPDecodeError("LockProof 必须为 4 项列表")
        i = lambda b: int.from_bytes(b, "big")            # noqa: E731
        bh = bytes(raw[2])
        if len(bh) != 32:
            raise RLPDecodeError(f"LockProof 的 block_hash 必须为 32 字节，实际 {len(bh)}")
        return cls(height=i(raw[0]), round=i(raw[1]), block_hash=bh,
                   signatures=tuple(CommitSignature.from_rlp(x) for x in raw[3]))


@dataclass
class Proposal:
    """`Proposal = RLP([header, transactions, lock_proof])`"""
    block: Block
    lock_proof: Optional[LockProof] = None

    @property
    def height(self) -> int:
        return self.block.header.height

    @property
    def round(self) -> int:
        return self.block.header.round

    @property
    def proposer(self) -> bytes:
        return self.block.header.proposer

    def block_hash(self) -> bytes:
        return self.block.block_hash()

    # ── 序列化（规范 §6.5：跨机通信必需）────────────────────────────
    #
    # 规范早已把编码写成 `Proposal = RLP([header, transactions, lock_proof])`，
    # 但参考实现此前**没有实现它** —— 因为传输层一直是进程内事件队列，
    # 直接传对象引用，从来不需要编码。一旦跨机（真 TCP），缺了它提案就无法上线。
    def to_rlp(self) -> bytes:
        return encode([self.block.to_rlp(),
                       self.lock_proof.to_rlp() if self.lock_proof else b""])

    @classmethod
    def from_rlp(cls, raw) -> "Proposal":
        if isinstance(raw, (bytes, bytearray)):
            raw = decode(raw)
        if not isinstance(raw, list) or len(raw) != 2:
            raise RLPDecodeError("Proposal 必须为 2 项列表")
        blk = Block.from_rlp(raw[0])
        lp = LockProof.from_rlp(raw[1]) if raw[1] else None
        return cls(block=blk, lock_proof=lp)


class ActionKind(IntEnum):
    BROADCAST_PROPOSAL = 1
    BROADCAST_PREVOTE = 2
    BROADCAST_PRECOMMIT = 3
    FINALIZE_BLOCK = 4
    START_ROUND = 5
    # BUG-59：已达到法定数、但本节点**没有该区块**时，向对端索要它。
    REQUEST_BLOCK = 6


@dataclass
class Action:
    """状态机要求节点执行的动作。测试只需收集这些动作即可观察行为。"""
    kind: ActionKind
    height: int
    round: int
    payload: object = None

    def __repr__(self) -> str:
        extra = ""
        if isinstance(self.payload, Vote):
            extra = f" {'NIL' if self.payload.is_nil else self.payload.block_hash.hex()[:8] + '…'}"
        elif isinstance(self.payload, Proposal):
            extra = f" blk={self.payload.block_hash().hex()[:8]}…"
        return f"<{self.kind.name} h={self.height} r={self.round}{extra}>"


# ══════════════════════════════════════════════════════════════════════
# 2. 提案者选择（规范 §12）
# ══════════════════════════════════════════════════════════════════════

def epoch_seed(prev_block_hash: bytes, prev_state_root: bytes, prev_tx_root: bytes,
               prev_proposer: bytes, prev_slot: int, prev_round: int) -> bytes:
    """规范 §12.2：
        EpochSeed = Hash(CHAIN("AGORA/EPOCH-SEED/v0.2.2", prev_block_hash(32),
                        prev_state_root(32), prev_tx_root(32), prev_proposer(20),
                        u64(prev_slot), u64(prev_round)))
    """
    # 宽度按规范 §12.2 显式声明（BUG-64）：u64(prev_slot), u64(prev_round)
    return keccak256(P.TAG_EPOCH_SEED + chain(
        prev_block_hash, prev_state_root, prev_tx_root, prev_proposer,
        ("u64", prev_slot), ("u64", prev_round)))


def selection_randomness(seed: bytes, epoch: int, slot: int, round_: int) -> bytes:
    """规范 §12.3 的 `R`。"""
    # 宽度按规范 §12.3 显式声明（BUG-64）：u64(E), u64(slot), u64(round)
    return keccak256(P.TAG_PROPOSER + chain(
        seed, ("u64", epoch), ("u64", slot), ("u64", round_)))


def select_proposer(r: bytes, snapshot: SnapshotSet) -> Optional[bytes]:
    """规范 §12.3–§12.4：由随机数选出提案者。

    · `target = R mod S_epoch`（`R` 视为 256 位无符号整数）
    · 按**地址 20 字节升序**累计投票权
    · **零权成员跳过**（因此 `target == 0` 时也能确定性选出第一个有权成员）
    · 取累计值**严格大于** `target` 的第一个验证者
    """
    total = snapshot.staked_supply
    if total <= 0:
        return None                                  # 规范 §7.7：链 halt
    members = [(a, snapshot.vp_of(a)) for a in sorted(snapshot.membership)]
    members = [(a, vp) for a, vp in members if vp > 0]
    if not members:
        return None
    target = int.from_bytes(r, "big") % total
    cum = 0
    for addr, vp in members:
        cum += vp
        if cum > target:                             # 严格大于
            return addr
    return members[-1][0]


def proposer_for(epoch: int, slot: int, round_: int, seed: bytes,
                 snapshot: SnapshotSet) -> Optional[bytes]:
    """给定纪元种子与快照，选出 `(epoch, slot, round)` 的提案者。"""
    return select_proposer(selection_randomness(seed, epoch, slot, round_), snapshot)


def seed_from_parent(parent_header: Optional[BlockHeader]) -> bytes:
    """由父块头计算纪元种子（规范 §12.2：取"该纪元之前最后一个最终化区块"）。

    父块为空时（创世）使用全零输入 —— 这与规范 §12.2 的 `E == 0` 回退一致。
    """
    if parent_header is None:
        return epoch_seed(b"\x00" * 32, b"\x00" * 32, b"\x00" * 32,
                          b"\x00" * 20, 0, 0)
    return epoch_seed(parent_header.block_hash(), parent_header.state_root,
                      parent_header.tx_root, parent_header.proposer,
                      parent_header.claimed_slot, parent_header.round)


# ══════════════════════════════════════════════════════════════════════
# 3. 高度状态（规范 §23.1）
# ══════════════════════════════════════════════════════════════════════

@dataclass
class HeightState:
    """规范 §23.1：每个高度节点维护的共识状态。"""
    height: int
    round: int = 0
    step: Step = Step.PROPOSE
    # 本高度使用的槽。**必须在进入该高度时一次性固定**，见下方 `round_slot` 的说明。
    round_slot: Optional[int] = None
    proposal: Optional[Proposal] = None
    locked_value: Optional[bytes] = None
    locked_round: Optional[int] = None
    valid_value: Optional[bytes] = None
    valid_round: Optional[int] = None
    proposal_block: Optional[Block] = None
    # 收到的投票： round -> vote_type -> 投票者地址 -> Vote
    votes: Dict[Tuple[int, int], Dict[bytes, Vote]] = field(default_factory=dict)
    # 本轮是否已发送（保证"一轮一次"）
    sent_prevote: bool = False
    sent_precommit: bool = False
    # 本轮收到的区块（可能尚未通过校验）
    known_blocks: Dict[bytes, Block] = field(default_factory=dict)
    # 本高度是否已最终化（幂等保护，防止重复推进高度）
    finalized: bool = False
    # 已达法定数但缺少区块时，正在索要的区块哈希（BUG-59）；
    # 用于避免同一个区块被反复索要（网络风暴）。
    pending_request: Optional[bytes] = None
    # 本高度上"锁已被本轮 2/3 预投票解除"的轮次（规范 §10 第 ② 条，方案 B）。
    # 记录轮次而非布尔值：跨轮后必须重新判断，否则一次解锁会永久生效。
    unlocked_round: Optional[int] = None

    def add_vote(self, v: Vote) -> bool:
        """记录投票。返回是否为**新增**（重复投票被忽略，不报错）。"""
        key = (v.round, int(v.vote_type))
        bucket = self.votes.setdefault(key, {})
        if v.address in bucket:
            return False
        bucket[v.address] = v
        return True

    def tally(self, round_: int, vote_type: int,
              snapshot: SnapshotSet) -> Dict[bytes, int]:
        """统计某轮某类型的投票权：`block_hash -> 投票权`。"""
        out: Dict[bytes, int] = {}
        for addr, v in self.votes.get((round_, int(vote_type)), {}).items():
            vp = snapshot.vp_of(addr)
            if vp:
                out[v.block_hash] = out.get(v.block_hash, 0) + vp
        return out

    def polka(self, round_: int, snapshot: SnapshotSet) -> Optional[bytes]:
        """返回该轮预投票中达到法定数（+2/3）的区块哈希；nil 也参与。"""
        q = P.quorum(snapshot.staked_supply)
        for bh, power in self.tally(round_, int(VoteType.PREVOTE), snapshot).items():
            if power >= q:
                return bh
        return None


# ══════════════════════════════════════════════════════════════════════
# 4. 共识节点（规范 §23.3 的步骤转换表）
# ══════════════════════════════════════════════════════════════════════

class ConsensusNode:
    """一个验证者的共识状态机。

    用法（驱动循环）：

        node = ConsensusNode(address, seed, state, parent_block)
        for action in node.on_start_round(): ...        # 广播提案或预投票
        for action in node.on_proposal(prop): ...       # 收到提案
        for action in node.on_vote(vote): ...           # 收到投票
        for action in node.on_timeout("proposal"): ...  # 阶段超时
    """

    def __init__(self, address: bytes, seed: bytes, state: State,
                 parent_block: Optional[Block] = None,
                 snapshot: Optional[SnapshotSet] = None,
                 proposed_block: Optional[Block] = None,
                 height: Optional[int] = None,
                 round_slot: Optional[int] = None):
        self.address = address
        self.seed = seed                      # 私钥 seed，仅用于签名
        self.state = state
        self.parent_block = parent_block
        self.snapshot = snapshot or state.system.snapshot
        self.proposed_block = proposed_block  # 本节点作为提案者时要提的区块
        self.epoch_seed = seed_from_parent(parent_block.header if parent_block else None)
        # 高度必须显式确定：有父块则取父块高度 + 1；创世时若要参与"高度 0 之后
        # 的第一个区块"，必须显式传入 height（否则会把自己的高度当成 0，
        # 于是把所有提案都当成"高度不符"而静默忽略 —— 这是一个极难排查的缺陷）。
        if height is not None:
            self.height = height
        elif parent_block is not None:
            self.height = parent_block.header.height + 1
        else:
            self.height = 0
        self.rejects: List[str] = []          # 被拒绝的消息与原因（便于排查）
        # 进入新轮时的回调（BUG-53）：上层用它重置轮次超时的**绝对截止时刻**。
        # `None` 表示不关心超时（共识单元测试通常直接用逻辑时间驱动）。
        self.on_round_started: Optional[Callable[[int], None]] = None
        # 重入保护（BUG-58）：避免"进轮 → 补算 → 再进轮"的无限递归
        self._in_advance: bool = False
        self._advance_recursion: int = 0
        # ── round_slot：每个高度必须固定一个槽（BUG-44）──
        #
        # 问题：提案者由 `(epoch, slot, round)` 决定，因此**校验提案者必须先知道槽**；
        # 而槽若从提案里反推，就形成"要先知道槽才能验证提案者、而槽只能从提案得知"
        # 的循环。更糟的是 §5.2 允许 claimed_slot ∈ (父槽, 估计当前槽+Δ]，
        # 即最多 Δ+1 = 5 个合法取值 —— 不同节点会各自选一个，算出 5 个不同的提案者，
        # 于是把正确提案当成"提案者不符"而拒绝，**链无法产生任何区块**。
        #
        # 修正（确定性契约）：本高度使用的槽由**调用方显式指定**，是所有节点
        # 一致的前提。缺省取"父块槽 + 1"（最小合法值），这也让同一份父块
        # 在任何节点上得到同一槽。上层（节点驱动/测试）可在构造时传入自己的估计值，
        # 但**一旦进入该高度，所有节点必须使用同一槽**，否则提案会被拒。
        if round_slot is not None:
            self.round_slot = round_slot
        elif parent_block is not None:
            self.round_slot = parent_block.header.claimed_slot + 1
        else:
            self.round_slot = height if height is not None else 0
        self.hs = HeightState(height=self.height, round_slot=self.round_slot)
        self.actions: List[Action] = []
        self.finalized: List[Block] = []

    # ── 提案者选择 ──────────────────────────────────────────────────
    def proposer(self, round_: Optional[int] = None) -> Optional[bytes]:
        """本高度的提案者。槽取 `round_slot`（进入高度时已固定，见构造函数说明）。"""
        r = self.hs.round if round_ is None else round_
        slot = self.claimed_slot()
        return proposer_for(P.epoch_of(slot), slot, r, self.epoch_seed, self.snapshot)

    def claimed_slot(self) -> int:
        """本高度使用的槽：**进入高度时固定的 `round_slot`**（BUG-44）。

        不得从收到的提案反推槽 —— 那会形成"要先知道槽才能验证提案者、
        而槽只能从提案得知"的循环，导致节点间对提案者判断不一致。
        """
        return self.round_slot

    @property
    def is_proposer(self) -> bool:
        return self.proposer() == self.address

    def quorum(self) -> int:
        return P.quorum(self.snapshot.staked_supply)

    # ── 工具 ────────────────────────────────────────────────────────
    def _emit(self, kind: ActionKind, payload=None) -> Action:
        a = Action(kind=kind, height=self.hs.height, round=self.hs.round, payload=payload)
        self.actions.append(a)
        return a

    def _pubkey_of(self, address: bytes) -> bytes:
        rec = self.snapshot.record_of(address)
        return rec.pubkey if rec else b""

    def _make_vote(self, vote_type: int, block_hash: Optional[bytes]) -> Vote:
        return Vote.create(self.seed, self.hs.height, self.hs.round, vote_type,
                           block_hash, self.address)

    # ── 进入某轮 ────────────────────────────────────────────────────
    def start_round(self, round_: int) -> List[Action]:
        previous_round = self.hs.round
        self.hs.round = round_
        self.hs.step = Step.PROPOSE
        self.hs.proposal = None
        self.hs.sent_prevote = False
        self.hs.sent_precommit = False
        # 通知上层"已进入新轮"，用于重置轮次超时的**绝对截止时刻**（BUG-53）。
        # 没有这个挂钩，超时计时只能在高度开始时设定一次，导致每 7 个 tick
        # 就误判为超时、轮次被切得过快、预提交永远攒不满法定数。
        if self.on_round_started is not None:
            self.on_round_started(round_)
        self._emit(ActionKind.START_ROUND, round_)
        # BUG-58：跳到**更高**轮时，立刻用已经收到（但当时属于未来轮）的票
        # 补算一次本轮的法定数，否则那些票会被永久忽略。
        if (round_ > previous_round and self._advance_recursion == 0
                and not self._in_advance):
            self._in_advance = True
            self._advance_recursion += 1
            try:
                self._advance_by_votes()
            finally:
                self._advance_recursion -= 1
                self._in_advance = False
        # 若自己是本轮的提案者且已备好区块，则提出（§23.3 第一行）
        if self.is_proposer and self.proposed_block is not None:
            blk = self.proposed_block
            # ── 不变量（BUG-52，实现阻塞级）──────────────────────────────
            # **区块头部在提案者签名之后 MUST NOT 再被改写。**
            # `block_hash()` 与 `signing_payload()` 都由头部字段推导，因此对头部的
            # 任何写入都会让签名与哈希同时失效：提案者自己签过的块，到了对端
            # 一律判为"提案者签名无效"并被丢弃，全网永远凑不齐 2/3。
            #
            # 本方法曾在此处写 `blk.header.round = round_`，并在槽不符时改
            # `claimed_slot` / `timestamp` —— 于是**只有在区块必须重投时才触发**
            # 的这条路径让链彻底停摆。症状极具误导性：理想网络（无丢包）下
            # 提案一次即成、从不进入该分支，因此单测与"无故障"仿真都是绿的；
            # 一旦丢包 20% 或延迟稍高，节点被迫换轮重投，链立刻停在高度 1。
            #
            # 正确做法：区块在**签名前**就用本高度固定的槽与轮次构造完毕
            # （见 `Node._make_block`），本方法只负责广播，绝不改动头部。
            if blk.header.round != round_ or blk.header.claimed_slot != self.round_slot:
                # 出现这种情况说明提案者构造区块时用错了轮次/槽。此时**必须放弃**
                # 这个区块（若签名尚无效则连广播都不该发生），而绝不能就地改写头部。
                self.rejects.append(
                    f"提案区块头部与当前轮次不符（轮次 {blk.header.round}≠{round_} 或 "
                    f"槽 {blk.header.claimed_slot}≠{self.round_slot}）："
                    f"区块必须在签名前构造完毕，此处不修正、不广播")
                self.proposed_block = None
                return self.actions
            self.hs.proposal = Proposal(block=blk, lock_proof=self._lock_proof())
            self.hs.proposal_block = blk
            # 提案者必须把自己的区块登记进 known_blocks，否则最终化时取不到区块，
            # 于是"提案者反而不最终化"——一个极不对称且难排查的缺陷。
            self.hs.known_blocks[blk.block_hash()] = blk
            self._emit(ActionKind.BROADCAST_PROPOSAL, self.hs.proposal)
        return self.actions

    def _lock_proof(self) -> Optional[LockProof]:
        """若曾锁定，构造供他人验证的 `LockProof`（规范 §10）。"""
        if self.hs.locked_value is None or self.hs.locked_round is None:
            return None
        bucket = self.hs.votes.get((self.hs.locked_round, int(VoteType.PREVOTE)), {})
        sigs = tuple(CommitSignature(addr, v.signature) for addr, v in sorted(bucket.items()))
        return LockProof(height=self.hs.height, round=self.hs.locked_round,
                         block_hash=self.hs.locked_value, signatures=sigs)

    # ── 收到提案（§23.3）─────────────────────────────────────────────
    def _reject(self, kind: str, reason: str) -> List[Action]:
        """记录拒绝原因并返回空动作列表。

        **绝不静默丢弃消息**：共识层里"什么都没发生"是最难排查的故障，
        因此每次拒绝都留下可查询的原因（`node.rejects`）。
        """
        self.rejects.append(f"{kind}: {reason}")
        return []

    def on_proposal(self, prop: Proposal) -> List[Action]:
        h = prop.block.header
        if h.height != self.hs.height:
            return self._reject("proposal", f"高度不符：本节点 {self.hs.height}，提案 {h.height}")
        if h.claimed_slot != self.round_slot:
            return self._reject("proposal",
                                f"槽不符：本高度固定为 {self.round_slot}，提案为 {h.claimed_slot}")
        if h.round < self.hs.round:
            return self._reject("proposal", f"轮次已过：本轮 {self.hs.round}，提案 {h.round}")
        if h.round > self.hs.round:
            if h.round > self.hs.round + P.MAX_ROUND_WINDOW:
                return self._reject("proposal",
                                    f"轮次超前超限：{h.round} > {self.hs.round}+{P.MAX_ROUND_WINDOW}")
            self.start_round(h.round)
        self.hs.known_blocks[prop.block_hash()] = prop.block

        # 提案者身份必须正确（§22 第 8 项）
        want = self.proposer(h.round)
        if want is None:
            return self._reject("proposal", "活跃集合为空（S_epoch = 0，链应 halt）")
        if prop.proposer != want:
            return self._reject("proposal",
                                f"提案者不符：应为 {want.hex()[:12]}…，实为 {prop.proposer.hex()[:12]}…")
        if not h.verify_proposer_signature():
            return self._reject("proposal", "提案者签名无效")
        self.hs.proposal = prop
        self.hs.proposal_block = prop.block

        # ── 预投票闸门（规范 §10，方案 B，BUG-58）─────────────────────
        #
        # 只有在**仍然被锁**时，才拒绝对提案投票。四种"可以投票"的情形：
        #   (a) 未锁定；
        #   (b) 提案区块 == 锁定值（同一值，任何时候都可投）；
        #   (c) 提案带有 `> locked_round` 且可验证的 `LockProof`（§10 第 ① 条）；
        #   (d) **本轮**已因观察到 2/3 预投票而解锁（§10 第 ② 条）。
        #
        # **为什么必须有 (d)：** 每个高度的每轮提案都会产生**不同的区块哈希**
        # （`round` 是区块头字段），因此节点一旦锁定，就再也遇不到 `== 锁定值`
        # 的提案（情形 b 永不成立）；而 `LockProof` 要求"对**同一区块**的 2/3
        # 预投票"，在换轮重投场景下同样**永不可能产生**（情形 c 永不成立）。
        # 于是节点只能轮轮投 NIL，全网凑出的全是 NIL 法定数 —— **永久停摆**。
        # 实测：丢包 30% 时非 NIL 法定数 1 次、NIL 法定数 46 次。
        locked_value = self.hs.locked_value
        unlocked_now = (self.hs.unlocked_round == self.hs.round)
        can_vote_block = True
        if locked_value is not None and locked_value != prop.block_hash():
            if unlocked_now:
                can_vote_block = True                       # (d) 本轮已解锁
            else:
                lp = prop.lock_proof
                can_vote_block = bool(
                    lp and lp.round > (self.hs.locked_round or -1)
                    and self._verify_lock_proof(lp))        # (c) 凭 LockProof
        if can_vote_block:
            self._do_prevote(prop.block_hash())
        else:
            self._do_prevote(None)
        return self.actions

    def _verify_lock_proof(self, lp: LockProof) -> bool:
        """校验 `LockProof`：必须是更高轮次对同一区块的 2/3 预投票。"""
        if lp.height != self.hs.height or lp.block_hash == NIL_HASH:
            return False
        payload = vote_signing_payload(lp.height, lp.round, int(VoteType.PREVOTE),
                                       lp.block_hash)
        power, seen = 0, set()
        for s in lp.signatures:
            if s.address in seen:
                return False
            seen.add(s.address)
            pk = self._pubkey_of(s.address)
            if not pk or not ed25519_verify(pk, payload, s.signature):
                return False
            power += self.snapshot.vp_of(s.address)
        return power >= self.quorum()

    # ── 收到投票（§23.3）───────────────────────────────────────────
    def on_vote(self, v: Vote) -> List[Action]:
        if v.height != self.hs.height:
            return self._reject("vote", f"高度不符：本节点 {self.hs.height}，投票 {v.height}")
        if v.round > self.hs.round + P.MAX_ROUND_WINDOW:
            return self._reject("vote", f"轮次超前超限：{v.round}")
        pk = self._pubkey_of(v.address)
        if not pk:
            return self._reject("vote", f"{v.address.hex()[:12]}… 不在快照集合中（或无私钥记录）")
        if not v.verify(pk):
            return self._reject("vote", f"{v.address.hex()[:12]}… 签名无效")
        if not self.hs.add_vote(v):
            return self._reject("vote", f"{v.address.hex()[:12]}… 在本轮已投过票（重复，忽略）")

        if v.round == self.hs.round:
            self._advance_by_votes()
        # BUG-58（方案 B 的配套修复）：未来轮的票**只记录、不据此进轮**。
        #
        # 票本身必须收下（§11.4 的 `MAX_ROUND_WINDOW` 之内），但**不得**因为
        # 收到一张高轮次的票就立刻跳到那一轮。实测（20% 丢包，3 个种子）：
        #   · 收到即跳轮：通过 1/3；
        #   · 不跳轮（本实现）：通过 3/3。
        # 原因：单张票可能来自某个已经跑偏的节点；一跳轮就会跨过"本来能达成
        # 法定数的那一轮"，把全网推向越来越高的轮次而谁也定不下来。
        #
        # 真正必需的修正在**进轮时补算法定数**（见 `start_round` 的注记）：
        # 那批先前收下的票在进入该轮时必须被重新评估，否则会被永久忽略。
        return self.actions

    def _enter_future_round(self, round_: int) -> None:
        """跳到更高轮次，并立刻用已收到的票补算该轮的法定数（BUG-58）。

        **为什么必须跳轮（这是丢包下保持同步的关键）：** §23.3 的转换表规定
        "收到 `r′ > r` 且 `r′ ≤ r + MAX_ROUND_WINDOW` 的消息 ⇒ 进入 `PROPOSE(r′)`"。
        这条规则的作用是**把落后的节点拉回主流轮次**：只要收到一条更高轮的
        合法消息，就立刻跟上。

        此前实现只把这类票**记下来**、却不进轮，于是每台机器只按自己的超时
        单向前进 —— 各自的超时起点不同，轮次会**持续发散**（实测 30% 丢包下
        差值可达 60 轮以上）。一旦发散，同一轮内就再也凑不出 2/3，
        全网只能不断产生 NIL 法定数：实测同一轮里已有 3 个节点投了同一个区块，
        却因为其余节点停在更低的轮次而永远无法最终化。

        重入保护：`start_round` 的钩子也会走到这里，用 `_in_advance` 防递归。
        """
        if self._in_advance or round_ <= self.hs.round:
            return
        self.start_round(round_)
        if self._in_advance:
            return
        self._in_advance = True
        try:
            self._advance_by_votes()
        finally:
            self._in_advance = False

    def _advance_by_votes(self) -> None:
        """依据本轮已收到的投票推进步骤（§23.3 的转换表）。"""
        r = self.hs.round
        snap = self.snapshot
        q = self.quorum()

        if self.hs.step == Step.PROPOSE or self.hs.step == Step.PREVOTE:
            tally = self.hs.tally(r, int(VoteType.PREVOTE), snap)
            hit = next((bh for bh, p in tally.items() if p >= q), None)
            if hit is not None:
                # 记录有效值（若该轮有实际区块）
                if hit != NIL_HASH:
                    self.hs.valid_value = hit
                    self.hs.valid_round = r
                self.hs.step = Step.PRECOMMIT
                # ── 预提交决策（§23.3 + BUG-54 修正）─────────────────────
                #
                # 原规则：`locked_value == ⊥` 或 `locked_round == valid_round`
                #         或 `valid_value == locked_value` 才预提交 valid_value，
                #         否则预提交 NIL。
                #
                # **该规则会导致活性死锁**（实测）：若本高度第 1 轮锁定了 V0
                # 但未最终化（例如丢包导致预提交只攒到 1/3），而第 2 轮有
                # 2/3 预投票支持 V1，则 `locked_round(1) ≠ valid_round(2)` 且
                # `V1 ≠ V0` ⇒ 全部节点预提交 NIL ⇒ 永远无法最终化。
                # 更糟的是，此后每一轮都会重复这一模式，链**永久**停在原高度。
                #
                # 修正遵循 Tendermint 的锁规则（安全性与活性同时成立）：
                # **本轮收到的 2/3 预投票本身就是解锁凭据**（即 POL）。
                # 2/3 预投票 (r, V) 意味着在第 r 轮不可能存在 2/3 预提交支持
                # 其它值——否则 2/3 + 2/3 > 1 会造成权益重叠。因此把锁改到
                # (r, V) 是安全的；反之若 V 与已锁定值相同，只需把
                # `locked_round` 前移到 r，锁的强度不变。
                if hit != NIL_HASH:
                    # §10 第 ② 条（方案 B）：本轮出现 2/3 预投票 ⇒ **解锁**。
                    # 2/3 预投票 (r, V) 意味着第 r 轮不可能同时存在 2/3 预提交
                    # 支持冲突值（2/3 + 2/3 > 1，权益集合必然重叠，而诚实节点
                    # 一轮只投一次），因此以它为据重置锁是**安全的**。
                    # 解锁与锁定同轮次时无需改动（下面的 `_do_precommit` 会把
                    # 锁设到本轮）。
                    if (self.hs.locked_value is not None
                            and self.hs.locked_value != hit):
                        self.hs.unlocked_round = r
                    vote_for = hit
                else:
                    vote_for = None
                self._do_precommit(vote_for)

        if self.hs.step == Step.PRECOMMIT:
            tally = self.hs.tally(r, int(VoteType.PRECOMMIT), snap)
            for bh, power in tally.items():
                if power >= q and bh != NIL_HASH:
                    self._finalize(bh)
                    return
            # +2/3 预提交 nil → 进入下一轮（§23.3）
            if tally.get(NIL_HASH, 0) >= q:
                self.start_round(r + 1)

    # ── 发送投票（一轮一次）─────────────────────────────────────────
    def _do_prevote(self, block_hash: Optional[bytes]) -> None:
        if self.hs.sent_prevote:
            return
        self.hs.sent_prevote = True
        v = self._make_vote(VoteType.PREVOTE, block_hash)
        self.hs.add_vote(v)
        self.hs.step = max(self.hs.step, Step.PREVOTE)
        self._emit(ActionKind.BROADCAST_PREVOTE, v)
        self._advance_by_votes()

    def _do_precommit(self, block_hash: Optional[bytes]) -> None:
        if self.hs.sent_precommit:
            return
        self.hs.sent_precommit = True
        v = self._make_vote(VoteType.PRECOMMIT, block_hash)
        self.hs.add_vote(v)
        if block_hash is not None:
            # 预提交即锁定（规范 §10）。即使锁定值与之前相同，`locked_round`
            # 也**必须**前移到本轮：否则它会停留在旧轮次，而 §23.3 的预提交
            # 规则用 `locked_round == valid_round` 判定，旧的 locked_round
            # 会让后续轮次全部误判为"仍被锁"。
            self.hs.locked_value = block_hash
            self.hs.locked_round = self.hs.round
            self.hs.unlocked_round = None
        self._emit(ActionKind.BROADCAST_PRECOMMIT, v)
        self._advance_by_votes()

    def _finalize(self, block_hash: bytes) -> None:
        """最终化一个区块。**必须幂等**：同一高度只允许一次。

        不加保护会在"持续收到同一区块的预提交"时反复触发最终化动作 ——
        上层节点会因此重复推进高度、重复应用区块，导致状态被应用两次。

        BUG-59：若已达法定数但**本节点没有该区块**（提案消息被丢包、
        或本节点是在提案之后才加入），此前只是**静默 return**，于是本节点
        在自己的高度上永远无法最终化——它既不前进，也无法通过 §6.5 的
        按高度同步取得该块（它索要的是**自己当前高度**的块，而当前高度
        早已领先）。表现为"全网多数已前进，个别节点永久停滞"。
        现在改为**主动按哈希索要该区块**（`REQUEST_BLOCK`）。
        """
        if self.hs.finalized:
            return
        blk = self.hs.known_blocks.get(block_hash)
        if blk is None:
            if self.hs.pending_request != block_hash:
                self.hs.pending_request = block_hash
                self._emit(ActionKind.REQUEST_BLOCK, block_hash)
            return
        self.hs.finalized = True
        self.hs.pending_request = None
        self._emit(ActionKind.FINALIZE_BLOCK, blk)
        self.finalized.append(blk)

    # ── 超时（规范 §11）────────────────────────────────────────────
    def on_timeout(self, phase: str) -> List[Action]:
        """`phase ∈ {"proposal", "prevote", "precommit", "round"}`。

        · `proposal` 超时 → 广播 nil 预投票（§23.3）
        · `prevote` 超时  → 进入预提交
        · `precommit` 超时 → 进入下一轮
        · `round` 超时     → 进入下一轮（`ROUND_TIMEOUT(r)` 到期）
        """
        if phase == "proposal":
            if not self.hs.sent_prevote:
                self.hs.step = Step.PREVOTE
                self._do_prevote(None)
        elif phase == "prevote":
            if self.hs.step < Step.PRECOMMIT:
                self.hs.step = Step.PRECOMMIT
                self._do_precommit(None)
        elif phase in ("precommit", "round"):
            self.start_round(self.hs.round + 1)
        return self.actions

    # ── 构造 Commit（§6.2）────────────────────────────────────────
    def build_commit(self) -> Optional[Commit]:
        """由本轮收到的预提交构造 `Commit`（**全量签名，不裁剪**，BUG-13）。"""
        r = self.hs.round
        bucket = self.hs.votes.get((r, int(VoteType.PRECOMMIT)), {})
        tally: Dict[bytes, List[CommitSignature]] = {}
        for addr, v in bucket.items():
            if self.snapshot.vp_of(addr) == 0:
                continue
            tally.setdefault(v.block_hash, []).append(CommitSignature(addr, v.signature))
        q = self.quorum()
        for bh, sigs in tally.items():
            if bh == NIL_HASH:
                continue
            power = sum(self.snapshot.vp_of(s.address) for s in sigs)
            if power >= q:
                return Commit(height=self.hs.height, round=r, block_hash=bh,
                              signatures=sorted(sigs, key=lambda s: s.address))
        return None
