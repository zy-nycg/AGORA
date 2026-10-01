# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 节点驱动与多节点测试网
================================================

对应规范：
    §6.4  最终性 → 高度推进
    §11   超时驱动的轮次推进
    §22   区块有效性谓词
    §28   区块执行与纪元结算

本模块把 `consensus`（状态机）、`block`（执行）与一个**消息总线**接起来，
形成可运行的多节点网络。设计目标有三个：

1. **确定性**：使用「事件队列 + 逻辑时钟」而非真实 socket 与线程。
   同一份种子与同一串事件必然得到同一结果，因此共识缺陷可被**复现**。
   （规范 §41 要求做网络与拜占庭测试；不确定的测试框架无法用于定位分歧。）

2. **可注入故障**：分区、丢包、延迟、重复、乱序、节点崩溃/重启，
   都只是"改变事件入队方式"，不需要改动协议代码。

3. **结构即规范**：`_on_finalize` 严格按 §28.1 的顺序推进高度，
   并把 `parent_commit` 嵌入下一区块（§6.1）。

注意：本模块**不实现真实网络传输**。真实 P2P（TCP/QUIC、握手、对等管理）
属于工程实现，不影响共识正确性 —— 而共识正确性是本参考实现的目标。
"""

from __future__ import annotations

import random
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Dict, Final, List, Optional, Sequence, Tuple

from . import params as P
from .block import (
    Block, BlockError, BlockHeader, Commit, CommitSignature, apply_block,
    prepare_block, settle_epoch, validate_block_header, verify_commit,
)
from .consensus import (
    Action, ActionKind, ConsensusNode, LockProof, Proposal, Step, Vote, VoteType,
    proposer_for, seed_from_parent, vote_signing_payload,
)
from .crypto_backend import (address_from_pubkey, keccak256,
                             publickey_from_seed, sign)
from .state import State, SnapshotSet, ValidatorRecord

__all__ = [
    "Network", "Node", "Simulation", "NetworkConfig", "NodeStats",
    "make_genesis_block", "MS_PER_TICK", "ticks_from_ms",
]


def make_genesis_block(state: State) -> Block:
    """构造创世区块（规范 §32.1）。

    它必须是**真实且哈希确定**的区块，而不是"全零哨兵值"：
    `apply_block` 会按 `parent_hash == parent.block_hash()` 校验第一个区块，
    若创世块哈希为全零，则第一块就会被判为"父哈希不符"，
    而有意思的是错误信息会指向 Commit 校验，排查时极易走错方向。

    创世块的 `parent_commit` 是**空提交**（规范 §6.3），因此不要求法定数。
    """
    # 创世块的头部字段**必须**是确定性推导的（规范 §6.3，BUG-82）：
    # 它的 `block_hash` 就是高度 1 的 `parent_hash`，两个实现只要有一个字段不同，
    # 第二条链从第一块起就对不上。历史实现这里用 `b"\x11"*32` 当提案者公钥、
    # 空字节串当 `tx_root`/`receipt_root`/签名 —— 全是"随便填的"，无法被第二实现复现。
    from .codec import encode as _encode
    empty_root = keccak256(_encode([]))
    # 提案者 = 创世验证者集合中**地址最小**者（确定性、可推导，无需私钥）
    members = sorted(state.validators.items(), key=lambda kv: kv[0])
    proposer_pk = members[0][1].pubkey if members else b"\x00" * 32
    hdr = BlockHeader(
        height=0, round=0, claimed_slot=0, parent_hash=b"\x00" * 32,
        tx_root=empty_root, receipt_root=empty_root,
        state_root=state.state_root,
        gas_used=0, base_fee_per_gas=P.INITIAL_BASE_FEE,
        parent_commit=Commit.empty(), proposer_pubkey=proposer_pk,
        proposer_signature=b"\x00" * 64)
    hdr.timestamp = P.block_timestamp(0)
    hdr.finalize_parent_commit_hash()
    return Block(header=hdr, transactions=[])


# ══════════════════════════════════════════════════════════════════════
# 1. 网络：事件队列 + 故障注入
# ══════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════
# 0. 逻辑时间模型（BUG-53 的关键前提）
# ══════════════════════════════════════════════════════════════════════
#
# **约定：1 个逻辑 tick = 100 毫秒。**
#
# 为什么必须显式约定：协议的超时参数以**毫秒**给定（`PROPOSAL_TIMEOUT = 3000`
# 等，规范 §11.1），而仿真的消息延迟以**tick**给定。若二者之间没有明确换算，
# 就极易出现"1 tick = 1 秒"的隐含假设 —— 那会把 `latency=2` 变成"消息延迟 2 秒"，
# 比协议的 3 秒提案超时还慢，于是**任何**丢包或抖动都会让共识在超时前收不齐票，
# 链彻底停摆。实测正是如此：`drop_rate=0.05`（5% 丢包）就足以让链永久停在高度 1。
#
# 取 100 毫秒的理由：
#   · 与真实部署一致：局域网 RTT 约 1–200 毫秒，`latency=1~3` 即 100–300 毫秒；
#   · 协议超时随之落在合理的 tick 数上：提案 3 秒 = 30 tick，整轮 7 秒 = 70 tick；
#   · 仍保持整数运算，仿真完全确定（无浮点、无墙钟）。
MS_PER_TICK: Final[int] = 100


def ticks_from_ms(ms: int) -> int:
    """把协议里的**毫秒**超时换算为逻辑 tick 数（向上取整，最小 1）。"""
    return max(1, (int(ms) + MS_PER_TICK - 1) // MS_PER_TICK)


@dataclass
class NetworkConfig:
    """故障注入参数。全部为 0 时是理想网络。

    **设计要点（规范 §9）**：故障注入只改变"消息何时、是否、投几次到达"，
    绝不触碰任何共识规则代码。因此同一份 `NetworkConfig` 保证同一结果
    （随机源种子固定），且注入关掉后就是理想网络。
    """
    latency: int = 1                 # 每个消息的基础延迟（逻辑时钟单位）
    jitter: int = 0                  # 额外随机延迟上限
    drop_rate: float = 0.0           # 丢包率 [0,1)
    duplicate_rate: float = 0.0      # 重复投递率
    seed: int = 0                    # 随机源种子（保证可复现）
    equivocate_every: int = 0        # 拜占庭节点每隔几个 tick 双签一次（0 = 不注入）
    retransmit_every: int = 3        # 每几个 tick 重传一次未确认的提案/投票（0 = 关闭）
                                     # 见 `Node._retransmit`：丢包场景下的关键机制


class Network:
    """确定性消息总线。

    事件为 `(时间, 序号, 回调, 参数)`，按 `(时间, 序号)` 排序出队 —— 序号保证
    同一时刻的事件顺序也是确定的（不依赖 Python dict/set 的迭代顺序）。
    """

    def __init__(self, config: Optional[NetworkConfig] = None):
        self.cfg = config or NetworkConfig()
        self.now: int = 0
        self.queue: List[Tuple[int, int, Callable, tuple]] = []
        self._seq: int = 0
        self._rng = random.Random(self.cfg.seed)
        # 分区：双向集合，键为节点名
        self.partitions: List[set] = []
        self.handlers: Dict[str, object] = {}
        # 统计
        self.sent = 0
        self.dropped = 0
        self.duplicated = 0

    # ── 调度 ────────────────────────────────────────────────────────
    def schedule(self, delay: int, fn: Callable, *args) -> None:
        self._seq += 1
        self.queue.append((self.now + max(0, delay), self._seq, fn, args))
        self.queue.sort(key=lambda e: (e[0], e[1]))

    def register(self, name: str, handler) -> None:
        """登记一个可接收消息的实体（节点）。"""
        self.handlers[name] = handler

    def broadcast(self, sender: str, receivers: Sequence[str],
                  method_name: str, *args) -> None:
        """把一次投递排入**每个接收者自己**的处理方法。

        ⚠ 这里必须是"接收者的绑定方法"，而不是发送者的方法加一个 receiver 参数。
        早期实现把发送者的方法连同 receiver 名字一起入队，结果所有投递都落在
        发送者身上、被 `receiver != self.name` 静默挡掉 —— 表现为"全网零投票"，
        而代码看起来完全正确。消息总线必须在**入队时**就分发到目标对象。
        """
        for r in receivers:
            if r == sender:
                continue
            if not self.can_deliver(sender, r):
                self.dropped += 1
                continue
            if self.cfg.drop_rate and self._rng.random() < self.cfg.drop_rate:
                self.dropped += 1
                continue
            handler = self.handlers.get(r)
            if handler is None:
                self.dropped += 1
                continue
            # **必须**走接收者的 `on_any`，与 `TcpTransport` 的两条投递路径
            # （`_dispatch` / `_serve`）语义完全一致：由它按 `SENDER_AWARE`
            # 决定是否把 `sender` 追加为最后一个形参。
            # 直接 `getattr(handler, method_name)(*args)` 的写法会让"要不要传
            # sender"变成**每个调用点各自判断**，于是同一份代码在仿真里正确、
            # 在真实 TCP 上形参错位（实测：4 节点一收到同步请求就 TypeError 崩溃）。
            # 三处投递路径现在只有一处实现该细节。
            target = handler.on_any if hasattr(handler, "on_any") else getattr(handler, method_name)
            delay = self.cfg.latency
            if self.cfg.jitter:
                delay += self._rng.randrange(self.cfg.jitter + 1)
            self.sent += 1
            if hasattr(handler, "on_any"):
                self.schedule(delay, target, method_name, args, sender)
            else:
                self.schedule(delay, target, *args)
            if self.cfg.duplicate_rate and self._rng.random() < self.cfg.duplicate_rate:
                self.duplicated += 1
                if hasattr(handler, "on_any"):
                    self.schedule(delay + 1, target, method_name, args, sender)
                else:
                    self.schedule(delay + 1, target, *args)

    def can_deliver(self, a: str, b: str) -> bool:
        for grp in self.partitions:
            if (a in grp) != (b in grp):
                return False
        return True

    def partition(self, group_a: Sequence[str], group_b: Sequence[str]) -> None:
        self.partitions.append(set(group_a))
        self.partitions.append(set(group_b))

    def heal(self) -> None:
        self.partitions.clear()

    # ── 推进 ────────────────────────────────────────────────────────
    def step(self) -> bool:
        """推进到下一个事件。返回是否还有事件。"""
        if not self.queue:
            return False
        t, _, fn, args = self.queue.pop(0)
        self.now = max(self.now, t)
        fn(*args)
        return True

    def run_until(self, deadline: int, max_events: int = 2_000_000) -> int:
        """推进逻辑时钟到 `deadline`。返回处理的事件数。"""
        n = 0
        while self.queue and self.queue[0][0] <= deadline and n < max_events:
            self.step()
            n += 1
        self.now = max(self.now, deadline)
        return n


# ══════════════════════════════════════════════════════════════════════
# 2. 节点
# ══════════════════════════════════════════════════════════════════════

@dataclass
class NodeStats:
    proposals_sent: int = 0
    proposals_accepted: int = 0
    proposals_rejected: int = 0
    votes_sent: int = 0
    votes_accepted: int = 0
    votes_rejected: int = 0
    height_advanced: int = 0
    rounds_entered: int = 0
    blocks_applied: int = 0
    equivocations: int = 0            # 双签次数（仅拜占庭节点会 > 0）
    # BUG-59：已达法定数但缺区块时的按哈希索要计数，用于判定该路径是否被走到
    block_requests: int = 0
    blocks_received: int = 0
    # 有界重传计数（丢包场景的关键指标）
    proposals_retransmitted: int = 0
    votes_retransmitted: int = 0
    # ── 交易（§16.5）：观测"钱包说提交了，但为什么没上链"这类问题 ──
    txs_submitted: int = 0            # 本地受理并广播
    txs_gossiped: int = 0             # 广播出去（含中继转发）
    txs_received: int = 0             # 从对端收到（含重复）
    txs_included: int = 0             # 真正装进区块的笔数


# 落后多久（tick）才主动索要缺失区块。1 tick = 100 ms ⇒ 100 tick ≈ 10 秒逻辑时间。
# 太短会刷屏、太长则恢复慢；10 秒约为 2 个槽，足以区分"暂时抖动"与"真的落后"。
REQUEST_MISSING_INTERVAL = 100


class Node:
    """一个完整节点：持有状态 + 共识状态机 + 驱动逻辑。"""

    def __init__(self, name: str, seed: bytes, state: State,
                 network: Network, peers: Sequence[str],
                 byzantine: bool = False,
                 genesis: Optional[Block] = None):
        self.name = name
        self.seed = seed
        self.pubkey = publickey_from_seed(seed)
        self.address = address_from_pubkey(self.pubkey)
        self.state = state
        self.net = network
        self.peer_names = list(peers)
        self.byzantine = byzantine
        self.stats = NodeStats()
        self.alive = True

        # 链头：创世块必须是**真实区块**（哈希确定），见 `make_genesis_block`。
        self.head: Optional[Block] = genesis if genesis is not None else None
        self.head_commit: Optional[Commit] = None    # 使 head 最终化的 Commit
        # 创世块占据高度 0，因此节点从一开始就工作在高度 1。
        # 若从 0 开始，会把"高度 0 的区块"当成第一个区块而白白多走一轮。
        self.height = 1
        self.blockchain: List[Block] = []
        # 由**持久化恢复**时填充（见 `resume_from`）：`blockchain` 之外的字段
        # 都由本方法按"已经最终化了这些区块"的状态重建，避免调用方各自拼装。
        self._resume_height = 0
        # 本高度已投出的票（用于检测自己的双签；拜占庭节点会故意违反）
        self._votes_cast: Dict[Tuple[int, int, int], bytes] = {}
        # 待提区块（提案者在本轮填充）
        self._pending_block: Optional[Block] = None
        # ── 交易池（**不是共识状态**：区块有效性只看 §22 第 10 项）──────
        # 池子只影响"提案者往区块里放什么"，不影响任何验证判定。
        from .mempool import TxPool
        self.pool = TxPool()
        # ── 回执索引（**执行侧**记录，因为只有执行时才知道是否新建账户）──
        # 区块里只有 `receipt_root` 这个承诺，没有回执表；不记下来，
        # 查询接口就只能猜 gas（钱包显示的手续费会错）。有界，防止内存无界增长。
        self.receipts: "OrderedDict[bytes, dict]" = OrderedDict()
        self.receipt_limit = 20_000
        self.consensus: Optional[ConsensusNode] = None
        self.estimated_slot = 0
        self._round_started = 0
        # 本轮超时的**绝对截止时刻**（BUG-53）：None 表示尚未设定，
        # 首次 tick 时按 `round_timeout_ms(round)` 设定。
        self._round_deadline: Optional[int] = None
        # 当前**阶段**超时的绝对截止时刻（规范 §11.1 的 3/2/2 秒）
        self._phase_deadline: Optional[int] = None
        self._proposed_round: Optional[Tuple[int, int]] = None
        # 待重传的提案与本轮已投的票（见 `_retransmit`）
        self._pending_proposal: Optional[Tuple[int, int, object]] = None
        self._last_vote: Optional[Tuple[int, int, object]] = None
        self._last_send_tick: int = 0
        self.rejected_messages: List[str] = []
        self.rejects: List[str] = []
        self._start_height()

    # ── 高度初始化 ──────────────────────────────────────────────────
    def resume_from(self, blocks: Sequence[Block], head_commit=None) -> None:
        """从持久化的区块序列恢复链头（供重启后的节点调用）。

        `blocks[0]` **必须**是创世块；之后的每一块都视为已最终化，
        因此 `blockchain` / `head` / `height` / `estimated_slot` 一并前移，
        并立刻开始新高度 —— 与"刚最终化完一个区块"走**同一条**路径，
        避免恢复路径与正常运行路径出现两套语义（那正是分叉的来源）。

        调用方必须已经用持久化的状态**替换**了 `self.state`
        （`ChainStore.load` 会复算状态根并与链头承诺对账）。
        """
        if not blocks:
            return
        if blocks[0].header.height != 0:
            raise ValueError("恢复序列的第一条必须是创世块（height = 0）")
        self.head = blocks[-1]
        # **必须**恢复链头的 Commit：下一个区块的 `parent_commit` 要用它证明
        # "父块已最终化"（§6.4）。缺失时节点只能提交空提交 ⇒ 对端一律拒收 ⇒ 停摆。
        self.head_commit = head_commit
        self.blockchain = list(blocks[1:])
        self.height = blocks[-1].header.height + 1
        self.estimated_slot = max(self.estimated_slot,
                                  blocks[-1].header.claimed_slot + 1)
        self._start_height()

    def _start_height(self) -> None:
        """进入新高度：选定槽、构造共识状态机、如果是提案者则出块。"""
        parent_slot = self.head.header.claimed_slot if self.head else -1
        round_slot = parent_slot + 1                  # 规范 §5.4.1（BUG-44）
        self.estimated_slot = max(self.estimated_slot, round_slot)
        self.consensus = ConsensusNode(
            address=self.address, seed=self.seed, state=self.state,
            parent_block=self.head, snapshot=self.state.system.snapshot,
            height=self.height, round_slot=round_slot)
        self.consensus.rejects = self.rejects
        # 让共识层在每次进入新轮时回调本节点，重置轮次截止时刻（BUG-53）
        self.consensus.on_round_started = self._on_round_started
        self._pending_block = None
        self._round_started = self.net.now
        self._round_deadline = None            # 由 _on_round_started 设定
        # 落后检测（规范 §6.5）：`request_missing` 此前**只在仿真器里**被调用，
        # 生产节点从不主动索要缺失区块 ⇒ 一旦因启动慢/分区/重启落后，就**永远追不上**
        # （实测：4 节点重启后有 1 个节点停在恢复高度，其余跑到 +440 块）。
        self._stuck_height = 0                 # 上次观察到的高度
        self._stuck_since = 0                  # 该高度的起始 tick
        self._phase_deadline = None            # 由 tick 按当前阶段设定
        self._emit_actions(self.consensus.start_round(0))
        self.stats.rounds_entered += 1

    def _make_block(self, slot: int, round_: int) -> Optional[Block]:
        """作为提案者构造区块（本项目版本：空区块，不含交易）。

        **守卫：没有"能证明当前 head"的证书时不出块（BUG-93）。**
        高度 1 是引导期例外：按 §6.3.2 其 `parent_commit` **必须**为空。
        其余高度若拿不到证明 head 已最终化的法定数证书，就只能放弃本轮出块 ——
        这不是"少出块"的取舍，而是**必须**：填一份过期的 `parent_commit`，
        全网的 §22 第 6 项都会拒收，等于白白浪费一轮并把轮次推高。
        """
        if self.height > 1 and self._commit_for_head() is None:
            self.stats.proposals_skipped = getattr(self.stats, "proposals_skipped", 0) + 1
            if self.stats.proposals_skipped <= 3:
                self.rejects.append(
                    f"放弃出块（高度 {self.height}）：尚无证明链头已最终化的证书"
                    "（同步追赶后会自然恢复）")
            return None
        # ── 从交易池挑交易（确定性；见 `agora/mempool.py` 的排序规则）──
        selected = self.pool.select(self.state, self._expected_base_fee(),
                                    self.estimated_slot)
        # 逐次尝试：若执行时报某笔交易失败（状态在准入之后变过），把它剔掉重试；
        # 全都失败就出**空块** —— 活性优先：宁可少装交易，也不能让这一轮白过
        # （更重要的原因：装进一笔执行失败的交易会让**整个区块**被判无效）。
        blk = None
        for _attempt in range(4):
            hdr = BlockHeader(
                height=self.height, round=round_, claimed_slot=slot,
                parent_hash=(self.head.block_hash() if self.head else b"\x00" * 32),
                tx_root=b"", receipt_root=b"", state_root=self.state.state_root,
                gas_used=0, base_fee_per_gas=self._expected_base_fee(),
                parent_commit=(self._commit_for_head() or Commit.empty()),
                proposer_pubkey=self.pubkey)
            hdr.timestamp = P.block_timestamp(slot)
            hdr.finalize_parent_commit_hash()
            blk = Block(header=hdr, transactions=list(selected))
            # 先执行一次把 state_root / gas_used / 各项根填入头部，
            # 使 block_hash 在**签名之前**就最终确定（BUG-45）。
            try:
                prepare_block(self.state, blk, parent_block=self.head,
                              current_slot=self.estimated_slot)
                break
            except Exception as e:                       # noqa: BLE001
                bad = self._blame_tx(e, selected)
                self.rejects.append(
                    f"打包失败（高度 {self.height}）：{e}"
                    + (f" ⇒ 剔除交易 {bad.hex()[:12]}… 重试" if bad else " ⇒ 改为空块"))
                if bad is None:
                    selected = []
                else:
                    self.pool.remove([bad])
                    selected = [t for t in selected
                                if t.tx_hash() != bad]
                blk = None
        if blk is None:
            return None
        if blk.header.gas_used > P.MAX_GAS_PER_BLOCK:
            # 兜底：宁可空块也不出违反 §22 第 10 项的块
            self.rejects.append(
                f"打包后累计 gas {blk.header.gas_used} 超过上限，改为空块")
            return None
        if blk.transactions:
            self.stats.txs_included += len(blk.transactions)
        hdr.proposer_signature = sign(self.seed, hdr.signing_payload())
        return blk

    @staticmethod
    def _blame_tx(exc: Exception, selected) -> Optional[bytes]:
        """从执行异常里找出"是哪一笔交易"（`apply_block` 的报错里带 tx_hash 前 12 个字符）。

        为什么需要它：准入校验用的是**当时的**状态，而打包时状态已经变了
        （别的区块最终化、同一发送者的前一笔交易已被打包…）。遇到这种"计划赶不上变化"，
        必须能定位并剔除那一笔，而不是把整个区块作废。
        """
        msg = str(exc)
        m = re.search(r"([0-9a-f]{12})…", msg)
        if not m:
            return None
        prefix = m.group(1)
        for t in selected:
            if t.tx_hash().hex().startswith(prefix):
                return t.tx_hash()
        return None

    def _expected_base_fee(self) -> int:
        from .gas import base_fee_next
        if self.head is None:
            return P.INITIAL_BASE_FEE
        return base_fee_next(self.head.header.base_fee_per_gas, self.head.header.gas_used)

    # ── 交易：提交、广播、接收（规范 §16.5，**均不影响区块有效性**）────

    def submit_tx(self, tx) -> Tuple[bool, str]:
        """本地提交一笔交易：入池 + **广播**给对端。返回 `(是否接受, 原因)`。

        广播是"尽力而为"：丢包就靠钱包重发（`tx_hash` 去重，重发幂等）。
        这也是为什么规范 §16.5 明确"交易池同步 **MUST NOT** 成为活性前提"——
        任何节点都必须能在**没有**看到该交易的情况下验证包含它的区块。
        """
        ok, why = self.pool.add(tx, self.state,
                                base_fee=self._expected_base_fee(),
                                current_slot=self.estimated_slot)
        if not ok:
            return False, why
        self.stats.txs_submitted += 1
        self._gossip_tx(tx)
        return True, "queued"

    def on_tx_msg(self, tx, sender: str = "") -> None:
        """收到对端广播的交易：入池（**不再转发**，靠 tx_hash 去重切断回路）。"""
        if not self.alive:
            return
        self.stats.txs_received += 1
        before = len(self.pool)
        ok, _why = self.pool.add(tx, self.state,
                                 base_fee=self._expected_base_fee(),
                                 current_slot=self.estimated_slot)
        if ok:
            self.pool.stats.received += 1
            if len(self.pool) > before:
                self._gossip_tx(tx)      # 转发给其它对端（本节点是"中继"）

    def _record_receipts(self, blk, recs: List[dict]) -> None:
        """把**执行时**算出的回执写入索引。

        ⚠ 回执**不能**事后重算：`gas_used` 取决于"这笔交易是否新建账户"，
        而那要看**执行时**的父状态。区块里只承诺了 `receipt_root`，
        所以想给钱包精确的手续费，就必须在执行的那一刻记下来。
        """
        for r in recs:
            self._put_receipt(blk.header.height, blk.block_hash(), r)

    def _put_receipt(self, height: int, block_hash: bytes, r: dict) -> None:
        h = r["tx_hash"]
        self.receipts[h] = {
            "tx_hash": h, "status": 1 if r.get("status") == "SUCCESS" else 0,
            "gas_used": int(r["gas_used"]),
            "effective_gas_price": str(int(r["effective_gas_price"])),
            "creates_account": bool(r.get("creates_account", False)),
            "block_height": int(height), "block_hash": block_hash,
        }
        while len(self.receipts) > self.receipt_limit:
            self.receipts.popitem(last=False)             # 淘汰最旧的

    def receipt_for(self, tx_hash: bytes) -> Optional[dict]:
        return self.receipts.get(tx_hash)

    def _gossip_tx(self, tx) -> None:
        peers = self._live_peers()
        if not peers:
            return
        self.net.broadcast(self.name, peers, "on_tx_msg", tx)
        self.stats.txs_gossiped += 1
        self.pool.stats.gossiped += 1

    def _commit_for_head(self) -> Optional[Commit]:
        """使**当前 head**最终化的 Commit —— 它将嵌入下一区块的 `parent_commit`。

        没有它，下一区块就无法被他人验证其父块确实已最终化（规范 §6.4）。

        ⚠ 必须**逐字段确认**它证明的正是当前 head（BUG-93）：
        `head_commit` 保存的是"本节点已知的最新证书"，而同步路径拿到的证书
        证明的是**父块**（落后一格）。若只做 `return self.head_commit`，
        这份落后证书就会被填进提案的 `parent_commit`，被全网按 §22 第 6 项拒收，
        而节点自己毫无察觉（表现为"只有它出不了块"）。
        """
        c = self.head_commit
        if c is None or self.head is None or c.is_empty:
            return None
        if (c.height != self.head.header.height
                or c.block_hash != self.head.block_hash()):
            return None
        return c

    def certifying_commit(self) -> Optional[Commit]:
        """供持久化使用：**能证明当前 head** 的证书；没有就返回 `None`。

        停机快照 MUST 存这份证书，而不是 `head_commit` 字段本身 —— 磁盘上的
        自检（`agora/store.py`）要求"快照高度处有合法法定数证书"，存一份落后的
        证书会让节点重启时**拒绝启动**（实测：`height 应为 295，实际 294`）。
        """
        return self._commit_for_head()

    # ── 动作处理 ────────────────────────────────────────────────────
    def _live_peers(self) -> List[str]:
        """当前连接得到的对端。**必须在发送时刻计算**。

        早期实现把构造时的 `peer_names` 缓存下来，分区恢复后节点仍然以为
        对端不可达（或反之），表现为"恢复了却永远追不上"。
        """
        return [n for n in self.peer_names
                if n != self.name and self.alive and self.net.can_deliver(self.name, n)]

    def _emit_actions(self, actions: Sequence[Action]) -> None:
        for a in actions:
            self._handle_action(a)

    def _handle_action(self, a: Action) -> None:
        if a.kind == ActionKind.BROADCAST_PROPOSAL and a.payload is not None:
            self.stats.proposals_sent += 1
            # 记下待重传的提案（见 `_retransmit`）
            self._pending_proposal = (self.height, a.payload.block.header.round, a.payload)
            self._last_send_tick = self.net.now
            self.net.broadcast(self.name, self._live_peers(),
                               "on_proposal_msg", a.payload)
        elif a.kind == ActionKind.BROADCAST_PREVOTE and a.payload is not None:
            self._record_vote(a.payload)
            self.stats.votes_sent += 1
            self._remember_vote(a.payload)
            self.net.broadcast(self.name, self._live_peers(),
                               "on_vote_msg", a.payload)
        elif a.kind == ActionKind.BROADCAST_PRECOMMIT and a.payload is not None:
            self._record_vote(a.payload)
            self.stats.votes_sent += 1
            self._remember_vote(a.payload)
            self.net.broadcast(self.name, self._live_peers(),
                               "on_vote_msg", a.payload)
        elif a.kind == ActionKind.FINALIZE_BLOCK and a.payload is not None:
            self._on_finalize(a.payload)
        elif a.kind == ActionKind.REQUEST_BLOCK and a.payload is not None:
            # BUG-59：已达法定数但缺少该区块 —— 主动按**哈希**向对端索要。
            # 按高度的同步（`request_missing`）帮不上忙：本节点索要的是自己
            # 当前高度的块，而缺的这块属于**已越过的高度**。
            self.stats.block_requests += 1
            # 同 `request_missing` 的理由：必须用 `net.broadcast(...)`；
            # `net.handlers[...]` 只存在于仿真器里（生产路径会 KeyError 打挂节点）。
            peers = self._live_peers()
            if peers:
                # 同上：`on_block_by_hash_request` 也是 SENDER_AWARE，
                # sender 由传输层追加，**MUST NOT** 自己再传。
                self.net.broadcast(self.name, peers, "on_block_by_hash_request",
                                   bytes(a.payload))
        # START_ROUND 无网络副作用

    def _remember_vote(self, v: Vote) -> None:
        """记下本节点本轮投出的票，供丢包时的重传（`_retransmit`）。"""
        self._last_vote = (self.height, v.round, v)

    def _retransmit(self, tick: int) -> None:
        """**有界重传**：每隔 `retransmit_every` 个 tick 重发本高度本轮的提案与自己的票。

        **为什么必须有这一层（BUG-60）：** 消息模型里被丢弃的消息
        **永远不会重来**，而共识全流程需要"提案 → 预投票 → 预提交"多次往返。
        丢包率一高，某一环没人收到，就整轮作废——**单纯加长超时完全无效**
        （实测：把阶段上限与整轮上限同比例放大，通过率无改善）。

        实测证据（30% 丢包，4 验证者）：
        * 预投票在**区块**上达成法定数 **26** 次，而预提交在区块上只达成 **2** 次；
        * 即票早就到了，但等到第 2 个节点攒够法定数、发出预提交时，
          那一轮已经被别的节点的 NIL 超时结束掉了。

        安全性：重传的**是同一条消息**（同一 height/round/类型/值/签名），
        接收方对重复投票一律忽略（`HeightState.add_vote` 返回 False），
        因此既不产生双签，也不改变任何共识规则——纯通信层幂等重发。
        规范 §11.5 已把本机制定为**规范性要求**。
        """
        every = self.net.cfg.retransmit_every
        c = self.consensus
        if not every or tick % every or c is None or not self.alive:
            return
        peers = self._live_peers()
        if not peers:
            return
        # ① 提案者重发本轮提案（直到进入下一轮）
        pp = self._pending_proposal
        if (pp is not None and pp[0] == self.height and pp[1] == c.hs.round
                and c.is_proposer and not c.hs.sent_precommit):
            self.net.broadcast(self.name, peers, "on_proposal_msg", pp[2])
            self.stats.proposals_retransmitted += 1
        # ② 重发自己本轮已投的票（预投票 / 预提交各一次，直到轮次推进）
        lv = self._last_vote
        if lv is not None and lv[0] == self.height and lv[1] == c.hs.round:
            self.net.broadcast(self.name, peers, "on_vote_msg", lv[2])
            self.stats.votes_retransmitted += 1

    def _record_vote(self, v: Vote) -> None:
        """记录自己投出的票；若在同一 (height, round, type) 投出**不同**值，
        则计入 `equivocations`（双签）。正确实现永不应触发它。"""
        key = (v.height, v.round, int(v.vote_type))
        prev = self._votes_cast.get(key)
        if prev is not None and prev != v.block_hash:
            self.stats.equivocations += 1
            self.rejects.append(
                f"自身双签：高度 {v.height} 轮次 {v.round} 类型 {v.vote_type} "
                f"{prev.hex()[:8]}… → {v.block_hash.hex()[:8]}…")
            return
        self._votes_cast[key] = v.block_hash

    # ── 收到消息 ────────────────────────────────────────────────────
    def on_any(self, method_name: str, args: tuple, sender: str = "") -> None:
        """统一投递入口：按方法名分派，并按签名决定是否附加 `sender`。

        传输层（含跨机 TCP）用它投递，避免各处重复处理"哪些方法要 sender"
        这一不一致细节。`Node` 自身的业务方法保持不变。
        """
        from .transport import SENDER_AWARE
        fn = getattr(self, method_name)
        if SENDER_AWARE.get(method_name, False):
            fn(*args, sender)
        else:
            fn(*args)

    def on_proposal_msg(self, prop: Proposal, sender: str) -> None:
        if not self.alive:
            return
        self.consensus.actions.clear()
        # 提案者自己也要投票：`on_proposal` 会因"一轮只发一次"的规则挡住
        # 已经投过的节点，因此提案者必须显式对自己的区块投预投票，
        # 否则会出现"只有 3/4 的预投票"这种极不对称、极难排查的启动故障。
        if prop.proposer == self.address:
            if not self.consensus.hs.sent_prevote:
                self.consensus._do_prevote(prop.block_hash())
            self._emit_actions(self.consensus.actions)
            self.consensus.actions.clear()
            self.stats.proposals_accepted += 1
            return
        # §22 谓词（最终化路径）：提案区块必须先通过完整校验才进入共识。
        # 历史实现只在共识层检查"槽/轮次/提案者/签名"，因此**基础费伪造、
        # 时间戳伪造、parent_commit 为空提交**的提案都能走到最终化（A8）。
        try:
            self._validate_incoming_block(prop.block, relax_clock=False)
        except Exception as e:                       # noqa: BLE001
            self.rejects.append(f"提案 §22 校验失败：{e}")
            self.stats.proposals_rejected += 1
            return
        before = len(self.rejects)
        self.consensus.on_proposal(prop)
        rejected = len(self.rejects) > before
        if rejected:
            self.stats.proposals_rejected += 1
        else:
            self.stats.proposals_accepted += 1
        self._emit_actions(self.consensus.actions)
        self.consensus.actions.clear()

    def on_vote_msg(self, v: Vote, sender: str) -> None:
        if not self.alive:
            return
        self.consensus.actions.clear()
        before = len(self.rejects)
        self.consensus.on_vote(v)
        rejected = len(self.rejects) > before
        if rejected:
            self.stats.votes_rejected += 1
        else:
            self.stats.votes_accepted += 1
        self._emit_actions(self.consensus.actions)
        self.consensus.actions.clear()

    # ── 高度推进（规范 §28.1）──────────────────────────────────────
    def _on_finalize(self, blk: Block) -> None:
        """最终化一个区块：校验 → 应用 → 推进高度。

        必须校验高度：节点可能因网络延迟仍停留在旧高度，此时它持有的
        ConsensusNode 会发出"针对旧高度"的最终化动作。若不丢弃，就会把
        高度 H+1 的区块套用到高度 H 的状态上，导致状态根错乱
        （表现为"block_hash 与父块哈希不符"这类间接错误）。

        顺序不可调换：先构造 `Commit` 并校验（§6.2），再 `apply_block`（§28.1），
        最后以新区块为父块开始下一高度。
        """
        if blk.header.height != self.height:
            self.rejects.append(
                f"丢弃过期最终化：区块高度 {blk.header.height}，本节点高度 {self.height}")
            return
        if self.head is not None and blk.header.parent_hash != self.head.block_hash():
            self.rejects.append("丢弃最终化：区块的父哈希与本节点链头不符")
            return
        c = self.consensus
        commit = c.build_commit()
        if commit is None:
            self.rejects.append("最终化时无法构造 Commit（不应发生）")
            return
        # Commit 的语义是"使**这个高度**的区块最终化"的证据，因此它的
        # `height` 等于被最终化区块的高度，`block_hash` 等于该区块哈希。
        # 早期实现用 `expect_hash=blk.header.height`（把高度当哈希传）导致
        # 每次最终化都报"block_hash 与父块哈希不符"，节点永远无法推进高度。
        ok, why, power = verify_commit(
            commit, self.state.system.snapshot,
            expect_height=blk.header.height,
            expect_hash=blk.block_hash())
        if not ok:
            self.rejects.append(
                f"最终化的 Commit 校验失败（高度 {blk.header.height}）：{why}"
                f" | commit.height={commit.height} commit.round={commit.round}"
                f" commit.block_hash={commit.block_hash.hex()[:12]}"
                f" 实际区块={blk.block_hash().hex()[:12]}"
                f" 区块parent_hash={blk.header.parent_hash.hex()[:12]}"
                f" 本节点head={(self.head.block_hash().hex()[:12] if self.head else None)}"
                f" 签名数={len(commit.signatures)}")
            return
        # 用区块头里的 parent_commit（若提案者填了）或刚构造的 commit 作为下一块引用
        recs: List[dict] = []
        try:
            # 头部已由提案者确定，因此这里不再改写头部（finalize_header=False），
            # Block 的哈希在整个共识过程中保持恒定。
            # **不传 `current_slot`**：执行槽取自区块头（BUG-92）。
            # 曾经的写法传 `self.estimated_slot`（本机时钟估计），使"同一区块的
            # 执行结果"依赖各节点自己的时钟 —— 两个节点只要差一格，就会算出
            # 不同的状态根，然后互相指责对方"第 11 项失败"。
            self.state = apply_block(self.state, blk, parent_block=self.head,
                                     finalize_header=False, receipts_out=recs)
        except Exception as e:                       # noqa: BLE001
            self.rejects.append(f"apply_block 失败：{e}")
            return
        # 记录本块回执（含执行时的 creates_account 判定）
        self._record_receipts(blk, recs)
        # 交易池维护：移除已上链的、清理已失效的。
        # **不做**这一步的后果：池里长期堆着已经上链或已被取代的交易，
        # 下次出块时反复选中又跳过，白白占用容量。
        if blk.transactions:
            self.pool.remove([t.tx_hash() for t in blk.transactions])
        # **`current_slot` 必须传**：空投领取/提现的校验依赖它；
        # 漏传会把合法交易静默清出池子（BUG-96，端到端才暴露）。
        self.pool.reap(self.state, base_fee=self._expected_base_fee(),
                       current_slot=self.estimated_slot)
        self.head = blk
        self.head_commit = commit
        self.blockchain.append(blk)
        self.height += 1
        self.stats.height_advanced += 1
        self.stats.blocks_applied += 1
        self.estimated_slot = max(self.estimated_slot, blk.header.claimed_slot + 1)
        self._start_height()

    # ── 超时 ────────────────────────────────────────────────────────
    # ── 区块同步（规范 §6.5）────────────────────────────────────────
    def request_missing(self) -> None:
        """向对端索要高度 `self.height` 的区块（本节点正缺这一块）。

        没有它，节点一旦因分区或崩溃落后就**永远追不上**：它自己出的块别人
        嫌低（"高度不符"），别人的块它又因为缺少中间块而无法验证。
        这是"少数侧恢复后必须能追上"的关键。
        """
        # **必须**用 `net.broadcast(...)`（仿真器与 `TcpTransport` 同签名），
        # 而不是 `net.handlers[peer]` —— 后者是**仿真器专有**的处理器注册表，
        # 真实 TCP 节点上并不存在，生产路径一调用就会 `KeyError` 把节点打挂
        # （实测：4 节点启动十几块后全部崩溃）。这类"只在仿真里成立"的写法
        # 是死代码之外的第二类陷阱：仿真测不出来，因为它恰好能跑。
        peers = self._live_peers()
        if peers:
            self.net.broadcast(self.name, peers, "on_block_request", self.height)

    # ── 入块校验（§22 的统一入口，MUST 被两条路径共同调用）─────────
    def _verify_parent_commit(self, commit, parent):
        """§22 第 6 项：父块的 Commit 必须是**合法法定数证书**。"""
        from .block import verify_commit
        ok, why, _power = verify_commit(
            commit, self.state.system.snapshot,
            expect_height=parent.header.height, expect_hash=parent.block_hash())
        return ok, why

    def proposer_of(self, epoch: int, slot: int, round_: int):
        """§22 第 8 项的提案者选择函数（由共识层提供）。"""
        c = self.consensus
        if c is None:
            return None
        try:
            return c.proposer(round_)
        except Exception:                       # noqa: BLE001
            return None

    def _validate_incoming_block(self, blk: Block, relax_clock: bool) -> None:
        """对**任何来源**的区块执行规范 §22 谓词（抛 `BlockError` 表示拒绝）。

        **为什么必须有这个入口（PROJECT_REVIEW A7/A8，已实测）：**
        `validate_block_header` 是 §22 的唯一实现，但历史实现的生产路径**从未调用它**：
        同步路径只检查"高度与父哈希"，最终化路径只检查"槽/轮次/提案者/签名"。
        实测后果：一个对端把**无提案者签名、`parent_commit` 为空提交、基础费伪造**
        的区块发给节点，节点会把链头换成它（高度 3 → 4），
        §6.4 的最终性与 §5.2 的时钟上界被同时绕过。

        `relax_clock=True`（同步追赶）：允许 `claimed_slot` 超前于本地估计槽 ——
        落后的节点本来就会看到"未来"的槽。此时**仍强制**校验提案者签名、
        `parent_commit` 的法定数、基础费与三个派生量，这些都与"本地进度"无关。
        """
        parent = self.head
        if parent is None:
            return
        est = (max(self.estimated_slot, blk.header.claimed_slot) if relax_clock
               else self.estimated_slot)
        validate_block_header(blk, parent, self.state, est,
                              proposer_of=self.proposer_of,
                              verify_parent_commit=self._verify_parent_commit)

    def on_block_request(self, height: int, requester: str, limit: int = 32) -> None:
        """回送从 `height` 起的一段区块（**批量**，规范 §6.5）。

        逐块同步在落后很多时会产生"每块一个往返"的开销，实测把一次
        5→20 的追赶拖到近 30 秒。批量回送是工程上必须的。
        """
        if not self.alive or self.height <= height:
            return
        batch = [b for b in self.blockchain if b.header.height >= height][:limit]
        if not batch:
            return
        # **应答侧**同样必须走 `broadcast`：它是生产路径 —— 任何节点都会响应
        # 对端的区块请求，用仿真器注册表会让它在被请求时直接崩溃。
        self.net.broadcast(self.name, [requester], "on_block_batch", batch)

    def on_block_batch(self, batch: Sequence[Block]) -> None:
        """按序应用一批区块（每个都必须正好接在当前链头上）。"""
        for blk in sorted(batch, key=lambda b: b.header.height):
            if not self.alive or blk.header.height != self.height:
                break
            before = self.height
            self.on_block_response(blk)
            if self.height == before:
                break                      # 应用失败即停止（避免乱序推进）

    # ── 按哈希索要区块（BUG-59）────────────────────────────────────

    def on_block_by_hash_request(self, block_hash: bytes, requester: str) -> None:
        """对端缺某个**具体**区块（不应答自己也不知道的哈希）。"""
        if not self.alive:
            return
        blk = None
        for b in self.blockchain:
            if b.block_hash() == block_hash:
                blk = b
                break
        if blk is None and self.head is not None and self.head.block_hash() == block_hash:
            blk = self.head
        if blk is None:
            return
        self.net.broadcast(self.name, [requester],
                           "on_block_by_hash_response", blk)

    def on_block_by_hash_response(self, blk: Block) -> None:
        """收到按哈希索要的区块：登记进共识层的已知区块表。

        **不直接应用**：该区块的高度可能已被本节点通过同步越过；一律交给
        共识层 `on_block_response` 处理，由它判定是否可以最终化。
        """
        if not self.alive:
            return
        self.stats.blocks_received += 1
        c = self.consensus
        if c is not None:
            c.hs.known_blocks[blk.block_hash()] = blk
            try:
                c.on_block_response(blk)
            except Exception:                       # noqa: BLE001
                pass
            self._emit_actions(c.actions)
            c.actions.clear()

    def on_block_response(self, blk: Block) -> None:
        """收到缺失区块：它必须正好是本节点当前高度的块，且父块与本节点链头一致。"""
        if not self.alive or blk.header.height != self.height:
            return
        if self.head is not None and blk.header.parent_hash != self.head.block_hash():
            return
        # §22 谓词：**同步来的区块与本地产生的区块走同一条校验**
        try:
            self._validate_incoming_block(blk, relax_clock=True)
        except Exception as e:                       # noqa: BLE001
            self.rejects.append(f"同步区块 §22 校验失败（高度 {blk.header.height}）：{e}")
            self.stats.blocks_rejected = getattr(self.stats, "blocks_rejected", 0) + 1
            return
        # 该区块必须携带足以证明父块已最终化的提交（`parent_commit`），
        # 因此同步来的区块与本地产生的区块走完全相同的应用路径。
        recs: List[dict] = []
        try:
            self.state = apply_block(self.state, blk, parent_block=self.head,
                                     finalize_header=False, receipts_out=recs)
        except Exception as e:                       # noqa: BLE001
            self.rejects.append(f"同步区块应用失败（高度 {blk.header.height}）：{e}")
            return
        self._record_receipts(blk, recs)
        # ── 同步路径也必须维护"最新已知证书"（BUG-93，实测）──────────────
        # 同步来的区块在头部携带的 `parent_commit` 是**能证明其父块已最终化**的
        # 法定数证书，也是本节点此后唯一能拿到的证书来源。此前这条路径**完全没
        # 更新** `head_commit`，后果有两个，且都不报错：
        #   ① 停机快照里会存进一份"高度对不上head"的证书 ⇒ 重启时自检
        #      "快照里的链头 Commit 不是有效的法定数证书" ⇒ **节点再也起不来**；
        #   ② 提案时会把这份过期证书填进 `parent_commit` ⇒ 全网的 §22 第 6 项
        #      都会拒收 ⇒ 该节点**再也无法出块**（活性静默降级）。
        # 只保留**更新**的证书：不要用父块的证书覆盖我们已经持有的更高证书。
        pc = blk.header.parent_commit
        if (pc is not None and not pc.is_empty
                and (self.head_commit is None
                     or pc.height > self.head_commit.height)):
            self.head_commit = pc
        self.head = blk
        self.blockchain.append(blk)
        self.height += 1
        self.stats.height_advanced += 1
        self.stats.blocks_applied += 1
        self.estimated_slot = max(self.estimated_slot, blk.header.claimed_slot + 1)
        self._proposed_round = None
        self._start_height()

    def tick(self, now: int) -> None:
        """逻辑时钟推进：驱动**阶段超时**与**轮次超时**（规范 §11.1 / §11.2）。

        BUG-53：这里此前只用"整轮超时"驱动，且超时基准只在本高度开始时设置一次，
        实际效果是每 7 个 tick 强行换轮。两个后果叠加：

        * **阶段超时完全未实现**（规范 §11.1 的 3/2/2 秒三个独立上限），
          因此"提案阶段最多等 3 秒"这条规则在实现里根本不存在；
        * 整轮上限被误当成"每 7 个 tick 一跳"，轮次被切得比消息传播还快。

        实测后果（丢包仅 5% 即触发）：预提交在 `t=5~7` 广播，但各节点在
        `t=7~8` 已切到下一轮，于是这些预提交**全部迟到被丢弃**，预提交权益
        永远停在 `128/256`（法定数 171），链**永久**停在高度 1。

        正确做法（两个上限各自独立，§11.3 明确禁止互相推导）：

        | 上限 | 判定 | 到期动作 |
        |---|---|---|
        | `PROPOSAL_TIMEOUT` = 3 s（固定） | 处于 PROPOSE 且超时 | 广播 `PREVOTE(r, NIL)` |
        | `PREVOTE_TIMEOUT` = 2 s（固定） | 处于 PREVOTE 且超时 | 进入 `PRECOMMIT(r)` |
        | `PRECOMMIT_TIMEOUT` = 2 s（固定） | 处于 PRECOMMIT 且超时 | 进入 `r+1` |
        | `ROUND_TIMEOUT(r)` = 7 s + r×0.5 s | **整轮**兜底 | 进入 `r+1` |

        阶段上限是**阶段内**的推进上限、**固定不变**；随轮次放宽的是**整轮**上限。
        它们取**先到者**，但**绝不相加**（§11.3 的禁令）。

        阶段上限是"阶段内"的推进上限，整轮上限是兜底：二者取**先到者**，
        但**绝不相加**（这正是 §11.3 的禁令）。
        """
        c = self.consensus
        if c is None or not self.alive:
            return

        # ⓪ 有界重传（通信层，见 `_retransmit`）
        self._retransmit(now)

        # ① 轮次超时（整轮兜底，§11.2）
        if self._round_deadline is None:
            self._round_deadline = now + ticks_from_ms(P.round_timeout_ms(c.hs.round))
        # ── 落后检测与追块（规范 §6.5）──────────────────────────────
        # 判据刻意简单且**本地**：高度在 `REQUEST_MISSING_INTERVAL` 个 tick 内没变，
        # 就向对端索要本高度的区块。不依赖"看到别人更高的高度"（那需要解析别人的
        # 消息），也不引入任何共享状态 ⇒ 每个节点独立判定、行为可复现。
        if self.height != self._stuck_height:
            self._stuck_height = self.height
            self._stuck_since = now
        elif now - self._stuck_since >= REQUEST_MISSING_INTERVAL:
            self._stuck_since = now                    # 限速：每 N tick 最多请求一次
            if self._live_peers():
                self.request_missing()

        if now >= self._round_deadline:
            c.on_timeout("round")
            self._emit_actions(c.actions)
            c.actions.clear()
            self.stats.rounds_entered += 1
            if self._round_deadline is None or self._round_deadline <= now:
                self._round_deadline = now + ticks_from_ms(
                    P.round_timeout_ms(c.hs.round))
            return

        # ② 阶段超时（§11.1）：只对**当前阶段**生效，到期即推进恰好一步
        phase = self._phase_of(c)
        if phase is None:
            return
        if self._phase_deadline is None:
            self._phase_deadline = now + ticks_from_ms(self._phase_timeout_ms(phase))
        if now >= self._phase_deadline:
            c.on_timeout(phase)
            self._emit_actions(c.actions)
            c.actions.clear()
            # 阶段可能已推进；若层内未改变阶段，兜底重设截止点，
            # 避免同一个 tick 序列里反复触发同一阶段超时。
            if self._phase_of(c) == phase:
                self._phase_deadline = now + ticks_from_ms(
                    self._phase_timeout_ms(phase))

    @staticmethod
    def _phase_of(c) -> Optional[str]:
        """把共识层的 `Step` 映射为规范 §11.1 的**阶段名**。"""
        try:
            name = c.hs.step.name
        except AttributeError:
            return None
        return {"PROPOSE": "proposal",
                "PREVOTE": "prevote",
                "PRECOMMIT": "precommit"}.get(name)

    @staticmethod
    def _phase_timeout_ms(phase: str) -> int:
        """规范 §11.1 的阶段上限（毫秒，**固定值**，与轮次无关）。

        随轮次放宽的是**整轮**上限（`round_timeout_ms`），不是阶段上限——
        二者是独立层级（§11.3）。
        """
        return P.phase_timeout_ms(phase)

    def _on_round_started(self, round_: int) -> None:
        """共识层进入新一轮时由 `Node` 挂钩，重置两个截止时刻（BUG-53）。"""
        self._round_deadline = self.net.now + ticks_from_ms(
            P.round_timeout_ms(round_))
        self._round_started = self.net.now
        self._phase_deadline = None

    # ── 提案者填充区块 ──────────────────────────────────────────────
    def prepare_as_proposer(self) -> None:
        """若本方是本高度的提案者，则构造并广播提案。

        三条守卫缺一不可（BUG-46）：
          ① 只在**本节点尚未在本轮投过票**时出块；
          ② 同一轮**只出一次块**（`_proposed_round`）—— 否则每次调用都会基于
             当时状态重新执行一次 `prepare_block`，得到一个**不同的区块哈希**，
             于是同一轮里出现多个候选区块，把全网的投票打散；
          ③ 出块前自检签名，连自己都验不过的提案绝不广播。
        """
        c = self.consensus
        if c is None or not c.is_proposer or c.hs.sent_prevote:
            return
        if self._proposed_round == (self.height, c.hs.round):
            return
        slot = c.round_slot
        # **必须使用本高度固定的槽与当前轮次构造区块**（BUG-52）。
        # 此前这里传的是 `c.claimed_slot()`（随轮次推进而变），而 `start_round`
        # 又会在签名之后把头部改回 `round_slot`，于是签名与头部不再匹配：
        # 对端一律判"提案者签名无效"，链在需要换轮重投时彻底停摆。
        # 现在区块在签名前就带正确的 `round`/`claimed_slot`，头部此后不得再变。
        blk = self._make_block(slot, c.hs.round)
        if blk is None:
            return
        if not blk.header.verify_proposer_signature():
            self.rejects.append("自检失败：自己构造的提案签名无效，已放弃广播")
            return
        # 头部自检：槽/轮次必须与共识状态一致，避免"签名时一个块、广播时另一个块"
        if (blk.header.claimed_slot != c.round_slot
                or blk.header.round != c.hs.round):
            self.rejects.append(
                f"自检失败：提案头部槽/轮次与共识状态不符"
                f"（{blk.header.claimed_slot}/{blk.header.round} vs "
                f"{c.round_slot}/{c.hs.round}），已放弃广播")
            return
        self._proposed_round = (self.height, c.hs.round)
        c.proposed_block = blk
        # 清掉上一轮遗留的提案，避免 `start_round` 取到**属于旧轮次**的区块
        # （旧区块的头部轮次与新轮次不符，广播出去必然被对端拒绝——BUG-52 的第二形态）
        c.hs.proposal = None
        c.hs.proposal_block = None
        c.actions.clear()
        c.start_round(c.hs.round)
        # 提案者必须**立即**对自己的区块投预投票，而不是等待自己广播的消息
        # 绕回自己 —— 那条消息可能被丢包，一旦丢弃提案者就永远不投票，
        # 于是全网只有 n-1 票、永远够不到法定数（表现为"网络略差就完全停摆"）。
        if not c.hs.sent_prevote:
            c._do_prevote(blk.block_hash())
        self._emit_actions(c.actions)
        c.actions.clear()

    # ── 拜占庭行为（用于测试注入）──────────────────────────────────
    def equivocate(self, block_hash: bytes) -> None:
        """故意在同一轮对另一个区块也签一票（双签）。

        规范意义上这是**最危险的攻击**：同一 `(height, round)` 对两个不同区块
        各签一票，试图让不同节点最终化冲突区块。因此仿真必须能真正触发它，
        否则"安全性测试"只是空转（见 BUG-58）。
        """
        c = self.consensus
        if c is None or not self.byzantine:
            return
        v = Vote.create(self.seed, self.height, c.hs.round,
                        int(VoteType.PRECOMMIT), block_hash, self.address)
        # 把自己的双签也登记到本节点的计数器上：否则"双签是否真的发生"
        # 在仿真里无从判断（此前该计数恒为 0，无法区分"注入无效"与"攻击失效"）。
        self._record_vote(v)
        self.net.broadcast(self.name, self._live_peers(), "on_vote_msg", v)


# ══════════════════════════════════════════════════════════════════════
# 3. 仿真驱动
# ══════════════════════════════════════════════════════════════════════

class Simulation:
    """把若干节点跑起来，并驱动到指定高度。"""

    def __init__(self, n: int = 4, config: Optional[NetworkConfig] = None,
                 stake_agora: int = 64, byzantine: Sequence[int] = ()):
        from .state import GenesisAllocation, build_genesis_state

        self.net = Network(config)
        self.seeds = [bytes([i + 1]) * 32 for i in range(n)]
        self.pubkeys = [publickey_from_seed(s) for s in self.seeds]
        self.addrs = [address_from_pubkey(p) for p in self.pubkeys]
        stake = stake_agora * P.ATOM_PER_AGORA
        total = stake * n
        self.genesis_state, _ = build_genesis_state(GenesisAllocation(
            validators=[(p, stake) for p in self.pubkeys],
            balances=[(self.pubkeys[0], P.INITIAL_SUPPLY - total)]))
        self.genesis_block = make_genesis_block(self.genesis_state)
        self.names = [f"node{i + 1}" for i in range(n)]
        self.byzantine = set(byzantine)
        self.nodes: Dict[str, Node] = {}
        for i, name in enumerate(self.names):
            st = self.genesis_state if i == 0 else _clone_state(self.genesis_state)
            self.nodes[name] = Node(
                name=name, seed=self.seeds[i], state=st, network=self.net,
                peers=self.names, byzantine=(i in self.byzantine),
                genesis=self.genesis_block)
            self.net.register(name, self.nodes[name])

    # ── 驱动 ────────────────────────────────────────────────────────
    def drive(self, target: int = 1, max_events: int = 20_000,
              max_ticks: int = 3000) -> dict:
        """驱动仿真直到**所有存活节点达到 `target` 高度**，或达到上限。

        每个"tick"做三件事：推进事件到下一个时间片 → 让提案者出块 → 触发轮次超时。
        `max_events` 是**硬上限**：轮次超时会不断产生新事件，没有上限的循环
        会在测试中静默失控（本实现曾在一次测试中超时 60 秒）。
        """
        events = 0
        for tick in range(max_ticks):
            live = [nd for nd in self.nodes.values() if nd.alive]
            if live and all(nd.height >= target for nd in live):
                break
            events += self.net.run_until(self.net.now + 1, max_events=2_000)
            for nd in live:
                nd.prepare_as_proposer()
            # 拜占庭行为注入（规范 §9）：`byzantine` 标记此前只被写入节点属性、
            # **从未真正触发任何恶意行为**，于是"有拜占庭节点"的仿真其实等于
            # "所有节点都诚实"，最需要验证的安全性场景被静默跳过。
            self._inject_byzantine(tick)
            # 落后节点主动同步（规范 §6.5）：用"最高高度"判断是否落后
            if live:
                top = max(nd.height for nd in live)
                for nd in live:
                    if nd.height < top and (self.net.now % 3 == 0):
                        nd.request_missing()
            for name in self.names:
                nd = self.nodes[name]
                if nd.alive:
                    nd.tick(self.net.now)
            if events >= max_events:
                break
        return {"events": events, "heights": self.heights(),
                "converged": self.converged(),
                "reached_target": all(nd.height >= target
                                      for nd in self.nodes.values())}

    def run_to_height(self, target: int, max_rounds: int = 400) -> None:
        """兼容旧签名：内部转为 `drive`。"""
        self.drive(target=target, max_ticks=max_rounds)

    def _inject_byzantine(self, tick: int) -> None:
        """按 `NetworkConfig.equivocate_every` 让拜占庭节点双签。

        双签（equivocation）是 BFT 里最危险的攻击：它在同一 `(height, round)`
        对**两个不同区块**各签一票，试图让不同节点最终化冲突区块。
        安全性的正确断言不是"链能前进"，而是**任何两个诚实节点都不会在同一高度
        最终化不同的区块哈希**（见 `safety_violations`）。
        """
        every = self.net.cfg.equivocate_every
        if not every or tick % every:
            return
        # BUG-58：`self.byzantine` 保存的是**索引**（构造参数 `byzantine=(0,1)`），
        # 而节点字典的键是**名字**（"node1"…）。此处曾直接 `self.nodes.get(name)`，
        # 于是永远取不到节点、`continue` 静默跳过 —— 双签注入**从未生效**，
        # 所谓"有拜占庭节点"的仿真实际等价于"全员诚实"，最危险的安全性场景
        # （同一高度出现冲突最终化）从未被真正测试过。
        for idx in sorted(self.byzantine):
            name = self.names[idx] if 0 <= idx < len(self.names) else str(idx)
            nd = self.nodes.get(name)
            if nd is None or not nd.alive or nd.consensus is None:
                continue
            # 造一个与本轮真实提案**不同**的哈希，让它在同一 (height, round)
            # 对两个不同区块各签一票（最经典的 BFT 攻击）
            alt = keccak256(b"AGORA/EQUIVOCATE/" + name.encode()
                            + tick.to_bytes(8, "big"))
            nd.equivocate(alt)

    def safety_violations(self) -> List[str]:
        """检查 BFT 安全性：同一高度不允许出现两个不同的最终化区块哈希。

        规范 §11 的安全性要求是"两个诚实节点不会在同一高度最终化不同区块"。
        若该断言失败，说明共识存在**可被利用的安全性缺陷**（可导致双花），
        这比活性问题严重得多，因此必须独立于"链是否前进"来断言。
        """
        seen: Dict[int, bytes] = {}
        bad: List[str] = []
        for name in sorted(self.nodes):
            nd = self.nodes[name]
            chain_obj = self._finalized_chain(nd)
            for h, bh in chain_obj.items():
                if h in seen and seen[h] != bh:
                    bad.append(
                        f"高度 {h} 出现冲突最终化："
                        f"{seen[h].hex()[:16]}… vs {bh.hex()[:16]}…（节点 {name}）")
                seen.setdefault(h, bh)
        return bad

    @staticmethod
    def _finalized_chain(nd) -> Dict[int, bytes]:
        """取出该节点**已最终化**的 `(height → block_hash)` 映射。

        本实现的节点在最终化时把区块追加到 `blockchain`，并把 `head` 前移，
        因此"已最终化链"就是 `blockchain` 里每个区块的 `(height, block_hash)`。
        判定安全性的唯一依据是这些**已最终化**的条目——仅"收到过某个区块"
        不构成最终化，不能作为安全性证据。
        """
        out: Dict[int, bytes] = {}
        for blk in getattr(nd, "blockchain", []) or []:
            out[int(blk.header.height)] = blk.block_hash()
        head = getattr(nd, "head", None)
        if head is not None:
            out[int(head.header.height)] = head.block_hash()
        return out

    def run_ticks(self, ticks: int = 20) -> dict:
        """在**不设高度目标**的情况下继续运行若干 tick。

        用于"分区恢复后让落后节点追上"这类场景：此时目标高度已经达到，
        `drive` 会立即返回，必须先解除目标才能让同步机制有机会工作。
        """
        events = 0
        for _ in range(ticks):
            events += self.net.run_until(self.net.now + 1, max_events=2_000)
            live = [nd for nd in self.nodes.values() if nd.alive]
            for nd in live:
                nd.prepare_as_proposer()
            if live:
                top = max(nd.height for nd in live)
                for nd in live:
                    if nd.height < top and self.net.now % 2 == 0:
                        nd.request_missing()
            for name in self.names:
                nd = self.nodes[name]
                if nd.alive:
                    nd.tick(self.net.now)
        return {"events": events, "heights": self.heights(),
                "converged": self.converged()}

    def heights(self) -> Dict[str, int]:
        return {n: nd.height for n, nd in self.nodes.items()}

    def heads(self) -> Dict[str, Optional[bytes]]:
        return {n: (nd.head.block_hash() if nd.head else None)
                for n, nd in self.nodes.items()}

    def converged(self) -> bool:
        hs = set(self.heads().values())
        return len(hs) == 1


def _clone_state(st: State):
    import copy
    return copy.deepcopy(st)
