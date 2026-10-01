# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 跨机传输层（真 TCP）
====================================

把 `agora/node.py` 的进程内消息总线换成**真正的 TCP 连接**，使香橙派可以作为
独立机器接入测试网（`TESTNET_RUNBOOK.md` 阶段 C）。

设计纪律（**最重要的一条**）
----------------------------
传输层 **MUST NOT** 改变共识行为。因此本模块**不重新实现调度**，而是：

    TcpTransport = 复用 Network（调度/故障注入/统计） + 把"跨机投递"交给 socket

具体做法：`TcpTransport` 内部持有一个 `Network` 实例，把所有 `broadcast` 通过
socket 发出；收到对端字节后，**再交给同一个 `Network.schedule()`** 投递。
于是：

* 故障注入（延迟/抖动/丢包/重复/分区）语义与仿真**完全一致**；
* 仿真中验证过的活性/安全性结论**可以迁移**到实网（这正是规范 §9 的要求）；
* 共识代码一行都不用改 —— 它看到的仍是同样的 8 个接口。

线格式
------
    ┌─────────┬────────┬──────────────┬──────────┬──────────────────┐
    │ len:u32 │ tag:u8 │ slen:u8      │ sender   │ payload          │
    │ 大端     │ 类型    │ 发送者名长度  │ UTF-8    │ len = 1+slen+plen │
    └─────────┴────────┴──────────────┴──────────┴──────────────────┘

**为什么发送者名要在帧里，而不能由对端"自称"后再信任：**

`Node.on_vote_msg(v, sender)` 与 `on_proposal_msg(prop, sender)` 需要发送者名。
但它**只用于日志与对端可达性判断**，不参与任何密码学校验 ——
真正的身份由消息自带的签名决定（投票有 `address` + 签名，提案有提案者签名）。
因此：

* 帧内携带发送者名，接收方**直接采用**（不另行校验），因为它不影响安全判定；
* **MUST NOT** 把发送者名当作身份依据 —— 一旦将来有代码依赖它做安全判定，
  就等于允许对端伪造身份。凡涉及身份的判定 **MUST** 走签名校验。

**为什么自己定帧而不用 pickle/JSON 传对象：**
  · 消息必须与共识编码一致（§20 RLP），才能被独立实现（GATE-7）解析；
  · 跨机收到的字节**一律不可信**，必须在解码处做长度与类型校验；
  · 发送方是"不可信输入"的边界 —— 长度前缀必须在读满之前就做上界检查，
    否则一个 4GB 的虚假长度声明就能耗尽内存（见 `_recv_frame` 的 MAX_FRAME）。

安全性
------
**消息内容**自带签名（投票有 `address` + 签名、提案有提案者签名），因此
"伪造一条别人的投票/提案"是做不到的 —— 接收方按 §6.4 / §23.3 校验签名即可。

但**消息的发送者名**不在这层保护之内：帧头里的名字是对端自述的字符串。
它会被用作应答的投递目标（§6.5），也决定了"这句话是谁说的"。
因此本模块额外做一层**名字↔连接的签名握手**（`agora/handshake.py`，
规范 §6.7）：每次连接建立时双方都要证明持有某个 Ed25519 私钥，
并把该密钥与自述名字绑定到**这一条连接**上；此后该连接上所有帧的自述名字
**必须**等于绑定的名字。于是"名字"从可任意自述的字符串变成需要私钥证明的身份。

配置纪律（**生产路径 MUST 遵守**）：

* 每个节点 **MUST** 配置自己的身份（`identity_seed` / `identity_pubkey`）；
* 每个 `Peer` **SHOULD** 配置对方公钥；`strict_identity=True` 时它是**必需**的，
  且"未验证"的连接一律拒绝；
* 未配置身份（全零公钥/签名）**仅供本机联调**：本实现会把它计入
  `unverified_conns` 并在收尾时打印，绝不静默放过。
"""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import params as P
from .block import Block
from .codec import decode
from .codec import encode as _rlp_encode
from .consensus import LockProof, Proposal, Vote
from .tx import Transaction
from .crypto_backend import publickey_from_seed    # MUST 走 crypto_backend（BUG-61）
from .handshake import (NIL_PUBKEY, NIL_SIG, NONCE_LEN, PUBKEY_LEN, SIG_LEN,
                        chain_mismatch_hint, check_auth_sig, check_challenge_sig,
                        make_auth_sig, make_challenge_sig)
from .node import Network, NetworkConfig

__all__ = ["TcpTransport", "Peer", "MAX_FRAME", "MSG_TAGS"]

# 单帧上限：规范里最大的对象是带交易的区块。MAX_GAS_PER_BLOCK 决定交易数上限，
# 每笔按最坏情况估算后留 4 倍余量。**必须**有上界 —— 否则对端只需声明一个
# 巨大长度就能让我们分配巨量内存（拒绝服务）。
MAX_FRAME: int = 32 * 1024 * 1024          # 32 MiB

# 消息类型标签（跨机协议的一部分，改动即为协议变更）
MSG_VOTE = 1
MSG_PROPOSAL = 2
MSG_BLOCK_REQUEST = 3          # on_block_request(height, requester)
MSG_BLOCK_BATCH = 4            # on_block_batch([Block, ...])
MSG_BLOCK_BY_HASH_REQ = 5      # on_block_by_hash_request(hash, requester)
MSG_BLOCK_BY_HASH_RESP = 6     # on_block_by_hash_response(Block)
MSG_TX = 7                     # on_tx_msg(Transaction) —— 交易广播（§16.5）

# 握手消息（规范 §6.7）。**这三类由传输层自己消费，绝不投递给应用层** ——
# 它们不是"节点收到了一条消息"，而是"这条连接正在被认证"。
MSG_HELLO = 0x20               # on_hello(name, pubkey, nonce_i)
MSG_CHALLENGE = 0x21           # on_challenge(name, pubkey, nonce_r, sig_r)
MSG_AUTH = 0x22                # on_auth(sig_i)

MSG_TAGS: Dict[str, int] = {
    "on_vote_msg": MSG_VOTE,
    "on_proposal_msg": MSG_PROPOSAL,
    "on_block_request": MSG_BLOCK_REQUEST,
    "on_block_batch": MSG_BLOCK_BATCH,
    "on_block_by_hash_request": MSG_BLOCK_BY_HASH_REQ,
    "on_block_by_hash_response": MSG_BLOCK_BY_HASH_RESP,
    "on_tx_msg": MSG_TX,
    "on_hello": MSG_HELLO,
    "on_challenge": MSG_CHALLENGE,
    "on_auth": MSG_AUTH,
}


# 需要 `sender` 参数的消息类型（与 `Node` 的方法签名一致）。
#
# 这个不一致是历史遗留：`on_block_batch(blk)` 不需要 sender，而
# `on_vote_msg(v, sender)` 需要。传输层**必须**按签名精确适配，
# 否则跨机会以 `TypeError` 崩溃（正是首次接线时暴露的问题）。
SENDER_AWARE: Dict[str, bool] = {
    "on_vote_msg": True,
    "on_proposal_msg": True,
    "on_block_request": True,
    "on_block_batch": False,
    "on_block_by_hash_request": True,
    "on_block_by_hash_response": False,
    "on_tx_msg": True,               # on_tx_msg(tx, sender)：sender 用于日志/排障
    # 握手三类由传输层在**认证阶段**自行处理（见 `_conn_loop`），
    # 不会走到 `on_any` 分派；此处登记它们只为让编码表与签名表保持同构
    # （测试会断言两张表的键集合完全一致）。
    "on_hello": False,
    "on_challenge": False,
    "on_auth": False,
}


def _dispatch(handler, method_name: str, args: tuple, sender: str) -> None:
    """调用接收者的处理方法。

    优先走 `handler.on_any`（`Node` 提供），使"哪些方法需要 sender"这一细节
    只有一处实现；若接收者没提供（如测试里的简易记录器），则按签名表适配。
    """
    if hasattr(handler, "on_any"):
        handler.on_any(method_name, args, sender)
        return
    fn = getattr(handler, method_name)
    if SENDER_AWARE.get(method_name, False):
        fn(*args, sender)
    else:
        fn(*args)


class PeerClosed(Exception):
    """对端在读取过程中**关闭了连接**（EOF）。

    必须与"读超时"区分开：两者在握手阶段的含义截然不同 ——
    对端关闭连接通常意味着**它拒绝了我们的身份**（名字/公钥不符或签名无效），
    而超时意味着它没有回应。首版把两者都报成"握手超时"，实测中
    对着真实节点做冒用探测时就得到了"超时"这种误导性的诊断。
    """


class Peer:
    """一个对端的连接信息。

    `pubkey` 是该对端的**验证者公钥**（32 字节），用于把手握的密钥绑定到名字上。
    未配置（`None`）时：严格模式下拒绝该连接；非严格模式下握照做，
    但结论只能是"未验证"并计入 `unverified_conns`（**生产路径 MUST 配置**）。
    """

    __slots__ = ("name", "host", "port", "pubkey")

    def __init__(self, name: str, host: str, port: int,
                 pubkey: Optional[bytes] = None):
        self.name, self.host, self.port = name, host, port
        if pubkey is not None:
            pubkey = bytes(pubkey)
            if len(pubkey) != PUBKEY_LEN:
                raise ValueError(f"对端公钥必须为 {PUBKEY_LEN} 字节，"
                                 f"实际 {len(pubkey)}")
        self.pubkey = pubkey

    def __repr__(self) -> str:
        pk = "" if self.pubkey is None else f" pk={self.pubkey.hex()[:12]}…"
        return f"Peer({self.name}@{self.host}:{self.port}{pk})"


# ══════════════════════════════════════════════════════════════════════
# 编码 / 解码（不可信边界）
# ══════════════════════════════════════════════════════════════════════

def _encode(method_name: str, args: tuple, sender: str = "") -> bytes:
    """把一次投递编码为线格式字节。`sender` 为发送者名（仅用于日志/可达性）。"""
    tag = MSG_TAGS.get(method_name)
    if tag is None:
        raise ValueError(f"传输层不支持的消息类型：{method_name!r}")

    if tag == MSG_VOTE:
        payload = args[0].to_rlp()
    elif tag == MSG_PROPOSAL:
        payload = args[0].to_rlp()
    elif tag == MSG_BLOCK_REQUEST:
        # **请求者名字不进载荷**：它已由帧头的 `sender` 字段携带，接收侧由
        # `on_any` 统一追加为 `requester` 形参（§6.5）。
        # 早期写法把名字同时放进载荷，于是接收方的第三个形参（`limit`）
        # 会收到一个字符串 ⇒ `[:limit]` 抛 TypeError，节点在**响应同步请求**时崩溃。
        from .codec import encode as _enc
        payload = _enc([args[0]])
    elif tag == MSG_BLOCK_BATCH:
        from .codec import encode as _enc
        payload = _enc([b.to_rlp() for b in args[0]])
    elif tag == MSG_BLOCK_BY_HASH_REQ:
        from .codec import encode as _enc
        payload = _enc([args[0]])          # 同上：请求者取帧头的 sender
    elif tag == MSG_BLOCK_BY_HASH_RESP:
        payload = args[0].to_rlp()
    elif tag == MSG_TX:
        payload = args[0].to_rlp()        # 交易自带签名，无需额外封装
    elif tag == MSG_HELLO:
        name, pubkey, nonce = args
        payload = _rlp_encode([name.encode("utf-8"), bytes(pubkey), bytes(nonce)])
    elif tag == MSG_CHALLENGE:
        name, pubkey, nonce_r, sig = args
        payload = _rlp_encode([name.encode("utf-8"), bytes(pubkey),
                               bytes(nonce_r), bytes(sig)])
    elif tag == MSG_AUTH:
        payload = _rlp_encode([bytes(args[0])])
    else:                                            # pragma: no cover
        raise ValueError(f"未处理的标签 {tag}")

    sb = sender.encode("utf-8")
    if len(sb) > 255:
        raise ValueError(f"发送者名过长：{len(sb)} 字节（上限 255）")
    return (struct.pack(">IBB", len(payload) + 1 + 1 + len(sb), tag, len(sb))
            + sb + payload)


def decode_frame(frame: bytes) -> Tuple[str, str, tuple]:
    """把线格式字节解码为 `(method_name, sender, args)`。**所有校验在此集中完成。**

    跨机输入是不可信边界：长度、结构、字段长度都必须在这里拒绝，
    不得留给后续逻辑以难以定位的方式失败。
    """
    if len(frame) < 6:
        raise ValueError(f"帧过短：{len(frame)} 字节（最小 6）")
    ln, tag, slen = struct.unpack(">IBB", frame[:6])
    if ln < 2:
        raise ValueError(f"帧长度非法：{ln}（长度含标签与发送者名长度字节，最小 2）")
    if 6 + slen > len(frame):
        raise ValueError(f"发送者名长度 {slen} 超出帧长 {len(frame)}")
    sender = frame[6:6 + slen].decode("utf-8", errors="replace")
    payload = frame[6 + slen:]
    if ln - 2 - slen != len(payload):
        raise ValueError(f"长度不符：声明 {ln - 2 - slen}，实际 {len(payload)}")

    if tag == MSG_VOTE:
        return "on_vote_msg", sender, (Vote.from_rlp(payload),)
    if tag == MSG_PROPOSAL:
        return "on_proposal_msg", sender, (Proposal.from_rlp(payload),)
    if tag == MSG_BLOCK_REQUEST:
        it = decode(payload)
        if len(it) != 1:
            raise ValueError("区块请求载荷必须只含高度")
        return "on_block_request", sender, (int.from_bytes(it[0], "big"),)
    if tag == MSG_BLOCK_BATCH:
        it = decode(payload)
        return "on_block_batch", sender, ([Block.from_rlp(b) for b in it],)
    if tag == MSG_BLOCK_BY_HASH_REQ:
        it = decode(payload)
        # 长度先判、再取元素：顺序反了时，空载荷会在 `it[0]` 抛 IndexError，
        # 而不可信输入必须以 ValueError 被拒（调用方只按协议错误捕获）。
        if len(it) != 1:
            raise ValueError("按哈希请求的载荷必须只含哈希")
        bh = bytes(it[0])
        if len(bh) != 32:
            raise ValueError(f"block_hash 必须为 32 字节，实际 {len(bh)}")
        return "on_block_by_hash_request", sender, (bh,)
    if tag == MSG_BLOCK_BY_HASH_RESP:
        return "on_block_by_hash_response", sender, (Block.from_rlp(payload),)
    if tag == MSG_TX:
        # 解码失败会抛 RLPDecodeError → 上层记为解码错误并丢弃该帧（不可信输入）
        return "on_tx_msg", sender, (Transaction.from_rlp(payload),)
    if tag == MSG_HELLO:
        it = decode(payload)
        if len(it) != 3:
            raise ValueError("HELLO 必须为 3 项（name, pubkey, nonce）")
        nm, pk, nc = bytes(it[0]), bytes(it[1]), bytes(it[2])
        if not 1 <= len(nm) <= 255:
            raise ValueError(f"HELLO 的节点名长度非法：{len(nm)}")
        if len(pk) != PUBKEY_LEN:
            raise ValueError(f"HELLO 的 pubkey 必须为 {PUBKEY_LEN} 字节")
        if len(nc) != NONCE_LEN:
            raise ValueError(f"HELLO 的 nonce 必须为 {NONCE_LEN} 字节")
        return "on_hello", sender, (nm.decode("utf-8"), pk, nc)
    if tag == MSG_CHALLENGE:
        it = decode(payload)
        if len(it) != 4:
            raise ValueError("CHALLENGE 必须为 4 项（name, pubkey, nonce, sig）")
        nm, pk, nc, sg = bytes(it[0]), bytes(it[1]), bytes(it[2]), bytes(it[3])
        if not 1 <= len(nm) <= 255:
            raise ValueError(f"CHALLENGE 的节点名长度非法：{len(nm)}")
        if len(pk) != PUBKEY_LEN:
            raise ValueError(f"CHALLENGE 的 pubkey 必须为 {PUBKEY_LEN} 字节")
        if len(nc) != NONCE_LEN:
            raise ValueError(f"CHALLENGE 的 nonce 必须为 {NONCE_LEN} 字节")
        if len(sg) != SIG_LEN:
            raise ValueError(f"CHALLENGE 的签名必须为 {SIG_LEN} 字节")
        return "on_challenge", sender, (nm.decode("utf-8"), pk, nc, sg)
    if tag == MSG_AUTH:
        it = decode(payload)
        if len(it) != 1:
            raise ValueError("AUTH 必须为 1 项（sig）")
        sg = bytes(it[0])
        if len(sg) != SIG_LEN:
            raise ValueError(f"AUTH 的签名必须为 {SIG_LEN} 字节")
        return "on_auth", sender, (sg,)
    raise ValueError(f"未知消息标签：{tag}")


# ══════════════════════════════════════════════════════════════════════
# TCP 传输层
# ══════════════════════════════════════════════════════════════════════

class TcpTransport:
    """与 `network.Network` 接口兼容的 TCP 传输层。

    用法（每个节点进程一份）：

        t = TcpTransport("node1", "0.0.0.0", 26656, peers=[
                Peer("node2", "192.168.1.20", 26666),
                Peer("node3", "192.168.1.21", 26676)])
        t.start()
        t.register("node1", node)          # 与 Network.register 同签名
        ...
        t.broadcast("node1", ["node2"], "on_vote_msg", vote)

    **确定性说明：** `TcpTransport` 用于**真实网络**，其到达时刻由操作系统与
    网络决定，因此**不得**用于判定共识结论是否"确定"。确定性验证仍走
    `Network`（仿真）。二者共用同一个调度器，故故障注入语义一致。
    """

    def __init__(self, name: str, bind_host: str, bind_port: int,
                 peers: Sequence[Peer] = (), config: Optional[NetworkConfig] = None,
                 connect_timeout: float = 3.0, io_timeout: float = 5.0,
                 identity_seed: Optional[bytes] = None,
                 identity_pubkey: Optional[bytes] = None,
                 strict_identity: bool = False,
                 handshake_timeout: float = 2.0,
                 dial_backoff_max: float = 8.0):
        # ── 身份（规范 §6.7 的名字↔连接握手）─────────────────────────
        # `identity_seed` 只用于**签名**，绝不写入日志/状态/网络。
        if identity_seed is not None and identity_pubkey is None:
            identity_pubkey = publickey_from_seed(identity_seed)
        if identity_pubkey is not None:
            identity_pubkey = bytes(identity_pubkey)
            if len(identity_pubkey) != PUBKEY_LEN:
                raise ValueError(f"identity_pubkey 必须为 {PUBKEY_LEN} 字节")
            if identity_seed is not None:
                # 自检：私钥与公钥必须配套，否则我们会用错误的身份签名，
                # 表现为"所有对端都拒绝我们"，极难定位。
                derived = publickey_from_seed(identity_seed)
                if derived != identity_pubkey:
                    raise ValueError("identity_seed 与 identity_pubkey 不匹配")
        self._id_seed = identity_seed
        self._id_pubkey = identity_pubkey                # None 或 32 字节
        self.strict_identity = bool(strict_identity)
        self._ident_configured = identity_pubkey is not None or identity_seed is not None
        if self.strict_identity and not self._ident_configured:
            raise ValueError(
                "strict_identity=True 需要配置本节点身份（identity_seed/identity_pubkey）"
                "—— 否则无法向对端证明任何东西")
        if self.strict_identity:
            missing = [p.name for p in peers if p.pubkey is None]
            if missing:
                raise ValueError(
                    f"strict_identity=True 时每个对端都必须给出公钥（--peer name@host:port@<hex>）；"
                    f"缺少公钥的对端：{missing}")
        # 是否需要握手：只要**任一方**配置了身份就必须做（否则一边在挑战、另一边
        # 沉默 ⇒ 连接建立不起来，且症状是"莫名其妙连不上"）。
        self._need_handshake = (self._ident_configured
                                or any(p.pubkey is not None for p in peers))
        self.name = name
        self.bind_host, self.bind_port = bind_host, bind_port
        self.peers = {p.name: p for p in peers}
        # 复用仿真调度器：故障注入与统计语义完全一致
        self._sched = Network(config)
        self.cfg = self._sched.cfg
        self.now = 0                              # 由 tick_clock 维护
        self._connect_timeout = connect_timeout
        self._io_timeout = io_timeout
        # 握手是**同步**做的（在 `_conn_for` 里），它会占用调用方线程
        # （生产路径就是节点主循环）。因此必须有独立且更短的上限：
        # 对端"半死不活"时，`_io_timeout=5s` 会把一个槽位整个吃掉。
        self._handshake_timeout = max(0.2, float(handshake_timeout))
        # 拨号失败退避：连续失败时不再每次广播都去重试，避免主循环被反复拖住。
        # 用**墙钟**计时（这是工程问题，不参与任何共识判定）。
        self._dial_backoff_max = max(1.0, float(dial_backoff_max))
        self._dial_backoff: Dict[str, float] = {}      # name -> 允许下次拨号的最早时刻
        self._dial_fail_count: Dict[str, int] = {}
        self.dial_backoffs = 0                         # 因退避而跳过的拨号次数

        self._srv: Optional[socket.socket] = None
        self._conns: Dict[str, socket.socket] = {}     # name -> socket（出站/入站复用）
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []

        # 统计（与 Network 同名，便于统一观测）
        self.sent = 0
        self.dropped = 0
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.decode_errors: List[str] = []
        self.connect_errors: List[str] = []
        # 声明了"不是我方配置中的对端"的名字的帧数（见 `_conn_loop` 的绑定检查）
        self.peer_errors: List[str] = []
        # ── 握手统计（§6.7）─────────────────────────────────────────
        self.handshakes_ok = 0            # 完成且**身份已绑定**的握手
        self.unverified_conns = 0         # 完成但无法绑定身份（未配置公钥/未配置本方身份）
        self.identity_errors: List[str] = []   # 握手失败（公钥不符/签名无效/未配置）
        self.identity_violations: List[str] = []  # 握手后帧的自述名与绑定名不符
        self._conn_ident: Dict[int, Tuple[str, bytes, bool]] = {}  # 连接 → (名字, 公钥, 已验证)

    # ── 与 Network 相同的接口 ────────────────────────────────────────

    def register(self, name: str, handler) -> None:
        self._sched.register(name, handler)

    @property
    def handlers(self):
        return self._sched.handlers

    def can_deliver(self, a: str, b: str) -> bool:
        """本节点视角：只要对端在 peer 列表里就认为可达。

        真实网络的可达性由 TCP 连接状态决定，而不由分区集合决定 ——
        但为兼容 `Node._live_peers()`，这里保留同一签名。
        """
        return b in self.peers or b == self.name

    def schedule(self, delay: int, fn: Callable, *args) -> None:
        self._sched.now = self.now
        self._sched.schedule(delay, fn, *args)

    def run_until(self, t: int, max_events: int = 2000) -> int:
        """把调度器推进到时刻 `t`（与 `Network.run_until` 语义一致）。"""
        self._sched.now = max(self._sched.now, self.now)
        n = self._sched.run_until(t, max_events=max_events)
        self.now = max(self.now, self._sched.now)
        return n

    def tick_clock(self, seconds: float = 1.0) -> None:
        """真实时间下推进逻辑时钟（供 `Node.tick` 使用）。

        真实节点的逻辑时钟以**秒**为单位推进；仿真里由驱动循环负责，
        实网里由调用方周期性调用本方法。
        """
        self.now += int(seconds)

    # ── 发送 ────────────────────────────────────────────────────────

    def broadcast(self, sender: str, receivers: Sequence[str],
                  method_name: str, *args) -> None:
        """把消息编码后经 TCP 发给每个接收者。

        `sender != self.name` 时**只做本地投递**（用于本机多进程/同进程场景），
        与 `Network.broadcast` 的语义保持兼容。
        """
        frame = _encode(method_name, args, sender)
        for r in receivers:
            if r == sender:
                continue
            if sender != self.name:
                # 不是本进程发出的：走本地调度（回环投递）
                self._deliver_local(r, method_name, args, sender)
                continue
            sock = self._conn_for(r)
            if sock is None:
                self.dropped += 1
                continue
            try:
                sock.sendall(frame)
                with self._lock:
                    self.sent += 1
                    self.tx_bytes += len(frame)
            except OSError as e:
                self.connect_errors.append(f"发送给 {r} 失败：{e}")
                self.dropped += 1
                self._drop_conn(r)

    def _deliver_local(self, receiver: str, method_name: str, args: tuple,
                       sender: str = "") -> None:
        """本地投递（与 `Network.broadcast` 一致：走调度器，保留延迟语义）。"""
        handler = self._sched.handlers.get(receiver)
        if handler is None:
            self.dropped += 1
            return
        delay = self.cfg.latency + (self.cfg.jitter // 2 if self.cfg.jitter else 0)
        self.schedule(delay, handler.on_any, method_name, args, sender)

    def _conn_for(self, name: str) -> Optional[socket.socket]:
        with self._lock:
            s = self._conns.get(name)
        if s is not None:
            return s
        peer = self.peers.get(name)
        if peer is None:
            return None
        # 退避窗口内不再重试：否则"每次广播都拨号一次"会在对端离线时
        # 反复把主循环拖住（实测：`kill -9` 掉一个节点后，
        # 其余节点的每次广播都要等一次连接失败）。
        if time.monotonic() < self._dial_backoff.get(name, 0.0):
            self.dial_backoffs += 1
            return None
        try:
            s = socket.create_connection((peer.host, peer.port),
                                         timeout=self._connect_timeout)
            # 握手阶段用**更短**的超时；握手完成后恢复常规 I/O 超时。
            s.settimeout(self._handshake_timeout)
        except OSError as e:
            self.connect_errors.append(f"连接 {name} ({peer.host}:{peer.port}) 失败：{e}")
            self._note_dial_failure(name)
            return None
        # 在**使用**这条连接之前完成握手（§6.7）：否则第一条业务帧会先到达对端，
        # 而对端在认证完成前一律丢弃业务帧 —— 表现为"偶尔丢第一条消息"，
        # 这类间歇性故障极难定位，所以顺序必须固定。
        if self._need_handshake and name != self.name:
            ok, verified = self._handshake_initiate(s, name)
            if not ok:
                try:
                    s.close()
                except OSError:
                    pass
                self.dropped += 1
                self._note_dial_failure(name)
                return None
            self._conn_ident[id(s)] = (name, self.peers[name].pubkey or b"", verified)
            s.settimeout(self._io_timeout)
        with self._lock:
            self._conns[name] = s
        self._dial_backoff.pop(name, None)             # 成功即清空退避
        self._dial_fail_count.pop(name, None)
        return s

    def _note_dial_failure(self, name: str) -> None:
        """记录一次拨号/握手失败，并把下一次尝试推迟（指数退避，上限 8 秒）。"""
        n = self._dial_fail_count.get(name, 0) + 1
        self._dial_fail_count[name] = n
        delay = min(self._dial_backoff_max, float(2 ** min(n - 1, 3)))
        self._dial_backoff[name] = time.monotonic() + delay

    def _drop_conn(self, name: str) -> None:
        with self._lock:
            s = self._conns.pop(name, None)
        if s is not None:
            try:
                s.close()
            except OSError:
                pass

    # ── 名字↔连接的签名握手（规范 §6.7）─────────────────────────────

    def _hello_frame(self, nonce_i: bytes) -> bytes:
        return _encode("on_hello", (self.name, self._id_pubkey or NIL_PUBKEY, nonce_i),
                       sender=self.name)

    def _identity_note(self) -> str:
        pk = self._id_pubkey
        return "（无身份，仅供联调）" if not pk else f"pk={pk.hex()[:12]}…"

    def _handshake_initiate(self, sock: socket.socket,
                            peer_name: str) -> Tuple[bool, bool]:
        """我方主动拨号时的握手。返回 `(连接是否可用, 身份是否已验证)`。

        **在返回之前，对端已经验证完我们** —— 因此此后发出的第一条业务帧
        一定是在"身份已确认"的连接上发出的。
        """
        peer = self.peers.get(peer_name)
        if peer is None:
            self.identity_errors.append(f"拨号 {peer_name}：该名字不在对端表中")
            return False, False
        nonce_i = os.urandom(NONCE_LEN)
        try:
            sock.sendall(self._hello_frame(nonce_i))
            try:
                frame = self._recv_frame(sock, raise_on_close=True)
            except PeerClosed:
                raise ValueError(
                    "对端在握手第一步就关闭了连接 ⇒ **它拒绝了我们的身份**"
                    "（常见原因：名字与公钥不匹配、公钥未配置、或本机 chain_id 与对端不同）")
            if frame is None:
                raise OSError("握手超时：对端未回应 HELLO（连接是通的，但它没有说话）")
            method, sender, args = decode_frame(frame)
            if method != "on_challenge":
                # 对端把我们的 HELLO 当成了业务帧（或版本不一致）
                raise ValueError(f"期望 CHALLENGE，实际收到 {method}")
            name_r, pk_r, nonce_r, sig_r = args
            if sender != peer_name or name_r != peer_name:
                # 对端自述的名字必须**就是我方拨号的名字**：否则它是另一台机器
                raise ValueError(f"对端自述名字 {name_r!r} 与我方拨号名 {peer_name!r} 不符")
            if peer.pubkey is not None and pk_r != peer.pubkey:
                raise ValueError(f"对端公钥与配置不符：{pk_r.hex()[:12]}…"
                                 f" ≠ 配置的 {peer.pubkey.hex()[:12]}…")
            if sig_r == NIL_SIG or pk_r == NIL_PUBKEY:
                # 对端（或我方）未配置身份 ⇒ 只能"未验证"
                if self.strict_identity:
                    raise ValueError("对端未配置身份（全零签名），严格模式拒绝")
                self.unverified_conns += 1
                return True, False
            if self._id_seed is None or self._id_pubkey is None:
                if self.strict_identity:
                    raise ValueError("本方未配置身份，无法完成握手（严格模式拒绝）")
                self.unverified_conns += 1
                return True, False
            if not check_challenge_sig(pk_r, sig_r, P.CHAIN_ID_BYTES, name_r,
                                      nonce_i, nonce_r):
                # 失败原因可能是"被篡改/重放"，也可能是**两边链身份配错**——
                # 两者在观察面上一样，但处置完全不同，因此这里给出诊断。
                raise ValueError("挑战签名无效（可能被重放或篡改）"
                                 + chain_mismatch_hint(
                                     pk_r, sig_r, 2, name_r, nonce_i, nonce_r,
                                     P.CHAIN_ID_BYTES))
            sig_i = make_auth_sig(self._id_seed, P.CHAIN_ID_BYTES, self.name,
                                  self._id_pubkey, nonce_i, nonce_r)
            sock.sendall(_encode("on_auth", (sig_i,), sender=self.name))
            verified = peer.pubkey is not None
            if verified:
                self.handshakes_ok += 1
            else:
                self.unverified_conns += 1
            return True, verified
        except Exception as e:                            # noqa: BLE001
            self.identity_errors.append(f"与 {peer_name} 的握手失败：{e}")
            return False, False

    def _handshake_respond(self, conn: socket.socket) -> Optional[Tuple[str, bytes, bool]]:
        """我方接受连接时的握手。失败返回 `None`（调用方**必须**关闭连接）。

        失败时**绝不**回退成"没有身份也放行" —— 那正是本机制要消灭的东西。
        """
        try:
            try:
                frame = self._recv_frame(conn, raise_on_close=True)
            except PeerClosed:
                raise ValueError("对端在发出 HELLO 之前就关闭了连接")
            if frame is None:
                raise OSError("握手超时：未收到 HELLO")
            method, sender, args = decode_frame(frame)
            if method != "on_hello":
                # 业务帧在握手完成**之前**到达 ⇒ 直接丢弃并断开。
                raise ValueError(f"握手前收到 {method}（要求的第一个帧是 HELLO）")
            name_i, pk_i, nonce_i = args
            if sender != name_i:
                raise ValueError(f"HELLO 的帧头名字 {sender!r} 与载荷名字 {name_i!r} 不符")
            peer = self.peers.get(name_i)
            if peer is None:
                raise ValueError(f"自述名字 {name_i!r} 不在本节点对端表中")
            nonce_r = os.urandom(NONCE_LEN)
            if (pk_i == NIL_PUBKEY or self._id_seed is None
                    or self._id_pubkey is None):
                if self.strict_identity:
                    raise ValueError("对端或本方未配置身份，严格模式拒绝")
                conn.sendall(_encode("on_challenge",
                                     (self.name, NIL_PUBKEY, nonce_r, NIL_SIG),
                                     sender=self.name))
                self.unverified_conns += 1
                return name_i, pk_i, False
            if peer.pubkey is not None and pk_i != peer.pubkey:
                raise ValueError(f"对端公钥与配置不符：{pk_i.hex()[:12]}…"
                                 f" ≠ 配置的 {peer.pubkey.hex()[:12]}…")
            sig_r = make_challenge_sig(self._id_seed, P.CHAIN_ID_BYTES, self.name,
                                       self._id_pubkey, nonce_i, nonce_r)
            conn.sendall(_encode("on_challenge",
                                 (self.name, self._id_pubkey, nonce_r, sig_r),
                                 sender=self.name))
            try:
                frame = self._recv_frame(conn, raise_on_close=True)
            except PeerClosed:
                raise ValueError("对端在收到 CHALLENGE 后关闭了连接"
                                 "（通常是它验不过我们的挑战签名）")
            if frame is None:
                raise OSError("握手超时：未收到 AUTH")
            method2, sender2, args2 = decode_frame(frame)
            if method2 != "on_auth":
                raise ValueError(f"期望 AUTH，实际收到 {method2}")
            sig_i = args2[0]
            if not check_auth_sig(pk_i, sig_i, P.CHAIN_ID_BYTES, name_i,
                                  nonce_i, nonce_r):
                raise ValueError("AUTH 签名无效（对端未持有该私钥，或消息被重放）"
                                 + chain_mismatch_hint(
                                     pk_i, sig_i, 3, name_i, nonce_i, nonce_r,
                                     P.CHAIN_ID_BYTES))
            verified = peer.pubkey is not None
            if verified:
                self.handshakes_ok += 1
            else:
                self.unverified_conns += 1
            return name_i, pk_i, verified
        except Exception as e:                            # noqa: BLE001
            self.identity_errors.append(f"来自 {conn.getpeername() if hasattr(conn, 'getpeername') else '?'} "
                                        f"的握手失败：{e}")
            return None

    def identity_summary(self) -> str:
        """一行式身份汇总（供节点收尾打印）。**未验证连接数非 0 必须显式告警。**"""
        pk = self._id_pubkey
        me = "（未配置身份）" if pk is None else pk.hex()[:12] + "…"
        return (f"本节点身份 {me} 严格模式={self.strict_identity} "
                f"握手成功={self.handshakes_ok} 未验证连接={self.unverified_conns} "
                f"握手失败={len(self.identity_errors)} "
                f"名字不符={len(self.identity_violations)} 退避跳过={self.dial_backoffs}")

    # ── 接收 ────────────────────────────────────────────────────────

    def start(self) -> None:
        """启动监听线程。"""
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((self.bind_host, self.bind_port))
        self._srv.listen(16)
        self._srv.settimeout(1.0)
        th = threading.Thread(target=self._accept_loop, daemon=True)
        th.start()
        self._threads.append(th)

    def stop(self) -> None:
        self._stop.set()
        if self._srv is not None:
            try:
                self._srv.close()
            except OSError:
                pass
        with self._lock:
            conns = list(self._conns.values())
            self._conns.clear()
        for s in conns:
            try:
                s.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        assert self._srv is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(self._io_timeout)
            th = threading.Thread(target=self._conn_loop, args=(conn, addr),
                                  daemon=True)
            th.start()
            self._threads.append(th)

    def _recv_exact(self, conn: socket.socket, n: int) -> Optional[bytes]:
        """读满 n 字节。**超时**返回 `None`；对端**关闭连接**抛 `PeerClosed`。"""
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = conn.recv(n - len(buf))
            except socket.timeout:
                return None
            except OSError:
                return None
            if not chunk:
                raise PeerClosed("对端关闭了连接")
            buf.extend(chunk)
        return bytes(buf)

    def _recv_frame(self, conn: socket.socket,
                    raise_on_close: bool = False) -> Optional[bytes]:
        """读一个完整帧（4 字节长度前缀 + 帧体）。长度在**读满之前**就做上界检查。

        `raise_on_close=False`（业务循环）：连接断开与超时都返回 `None`；
        `raise_on_close=True`（握手）：把"对端关闭连接"以 `PeerClosed` 抛出，
        以便给出准确诊断（"被拒绝" ≠ "没回应"）。
        """
        try:
            head = self._recv_exact(conn, 4)
            if head is None:
                return None
            (ln,) = struct.unpack(">I", head)
            if ln < 1 or ln > MAX_FRAME:
                self.decode_errors.append(f"帧长度非法：{ln}（上限 {MAX_FRAME}）")
                return None
            rest = self._recv_exact(conn, ln)
            if rest is None:
                return None
            return head + rest
        except PeerClosed:
            if raise_on_close:
                raise
            return None

    def _conn_loop(self, conn: socket.socket, addr) -> None:
        """读帧循环。长度前缀在**读满之前**就做上界检查（拒绝服务防护）。

        **认证先于一切（§6.7）**：握手未完成之前，任何业务帧都不得进入调度器。
        """
        # ── 第一步：握手。失败即断开（**绝不**回退成"放行"）──────────
        ident: Optional[Tuple[str, bytes, bool]] = None
        if self._need_handshake:
            ident = self._handshake_respond(conn)
            if ident is None:
                try:
                    conn.close()
                except OSError:
                    pass
                return
            self._conn_ident[id(conn)] = ident
        bound_name = ident[0] if ident is not None else None

        while not self._stop.is_set():
            body = self._recv_frame(conn)
            if body is None:
                break
            with self._lock:
                self.rx_bytes += len(body)
            try:
                method_name, sender, args = decode_frame(body)
            except Exception as e:                 # noqa: BLE001
                self.decode_errors.append(f"来自 {addr} 的帧解码失败：{e}")
                continue                           # 丢弃该帧，不断开
            # ── 名字↔连接的绑定（§6.7）────────────────────────────────
            # 握手已经把这条连接绑定到某个 (名字, 公钥)。此后任何"换个名字说话"
            # 的帧都必须丢弃：这正是"冒用对端表内名字"的封堵点。
            if bound_name is not None and sender != bound_name:
                self.identity_violations.append(
                    f"来自 {addr} 的 {method_name} 帧自述名 {sender!r}，"
                    f"与该连接的握手身份 {bound_name!r} 不符 ⇒ 丢弃")
                self.dropped += 1
                continue
            if ident is not None and not ident[2] and self.strict_identity:
                self.dropped += 1
                continue
            # ── 不可信边界：**帧头里的 `sender` 只由发送方自述** ──────────
            # 它会被 `on_any` 追加成 `requester` 形参，而应答方据此选投递目标
            # （`on_block_batch` / `on_block_by_hash_response`）。若不加约束，
            # 任何能连上端口的人都能用一个**伪造的名字**让我们把大块数据
            # 发给第三方（反射/放大），或以他人身份投递消息。
            # 这里要求自述名字必须在本节点的对端表里 —— 于是投递目标只可能是
            # 我们自己已经配置过的对端，且 `_conn_for()` 对未知名字本就返回 None。
            # 代价：**对端配置必须双向一致**（A 配了 B 的名字，B 也必须配 A 的），
            # 这一条已写入规范 §6.5 与测试网手册。
            if sender not in self.peers:
                self.peer_errors.append(
                    f"来自 {addr} 的帧自述发送者 {sender!r}，不在本节点对端表中 ⇒ 丢弃")
                self.dropped += 1
                continue
            # 交给**同一个**调度器投递 ⇒ 故障注入语义与仿真一致
            handler = self._sched.handlers.get(self.name)
            if handler is None:
                self.dropped += 1
                continue
            self.schedule(self.cfg.latency, _dispatch, handler,
                          method_name, args, sender)
        self._conn_ident.pop(id(conn), None)
        try:
            conn.close()
        except OSError:
            pass
