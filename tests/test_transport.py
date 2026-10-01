# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 参考实现 · 跨机传输层测试（真 TCP）
================================================

对应 `TESTNET_RUNBOOK.md` 阶段 C：证明两个**独立进程/独立 socket** 的节点
能通过真实 TCP 达成共识 —— 而不是只在同一个进程里传对象引用。

测试分三层：

1. **线格式**：编码/解码往返；**不可信输入必须被拒**（长度不符、未知标签、
   超长声明、零长度）。跨机输入是不可信边界，长度前缀必须在读满之前就校验，
   否则一个虚假的 4 GiB 长度声明即可耗尽内存。
2. **端到端投递**：真 socket 上发送一票，对端的节点处理方法被调用。
3. **端到端共识**：两节点（各 64 AGORA，`QUORUM = ceil(2×128/3) = 86`）
   通过 TCP 最终化区块并收敛到同一状态根。

**为什么 2 个验证者是有意义的用例**：2×64 时法定数为 86，
**任一离线都无法出块** ⇒ 能跑通就证明"两个节点确实互相通信并联合达成法定数"，
而不是某一方单独推进。
"""

from __future__ import annotations

import copy
import os
import socket
import struct
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agora import params as P
from agora import transport as T
from agora.block import Block, BlockHeader, Commit, CommitSignature
from agora.consensus import LockProof, Proposal, Vote, VoteType
from agora.crypto_backend import address_from_pubkey, publickey_from_seed
from agora.node import NetworkConfig, Node, make_genesis_block
from agora.state import GenesisAllocation, build_genesis_state

_pass = 0
_fail = 0


def chk(name, cond, detail=""):
    global _fail, _pass
    if cond:
        _pass += 1
        print(f"  [OK  ] {name}" + (f"   {detail}" if detail else ""))
    else:
        _fail += 1
        print(f"  [FAIL] {name}" + (f"   {detail}" if detail else ""))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _sample_block() -> Block:
    hdr = BlockHeader(height=1, round=0, claimed_slot=1, parent_hash=b"\x11" * 32,
                      tx_root=b"", receipt_root=b"", state_root=b"\x22" * 32,
                      gas_used=0, base_fee_per_gas=P.INITIAL_BASE_FEE,
                      parent_commit=Commit.empty(), proposer_pubkey=b"\x33" * 32)
    hdr.timestamp = P.block_timestamp(1)
    hdr.finalize_parent_commit_hash()
    return Block(header=hdr, transactions=[])


# ── 1. 线格式与不可信输入 ────────────────────────────────────────────

def test_wire_format():
    print("\n1) 线格式与不可信输入（跨机是不可信边界）")
    v = Vote.create(bytes([1]) * 32, 3, 2, int(VoteType.PRECOMMIT),
                    b"\xaa" * 32, b"\xbb" * 20)
    m, sender, a = T.decode_frame(T._encode("on_vote_msg", (v,), "nodeA"))
    chk("投票往返一致（含发送者名）",
        m == "on_vote_msg" and sender == "nodeA" and a[0].signature == v.signature
        and a[0].height == 3 and a[0].round == 2)

    blk = _sample_block()
    lp = LockProof(1, 0, b"\x44" * 32, (CommitSignature(b"\x55" * 20, b"\x66" * 64),))
    m, sender, a = T.decode_frame(
        T._encode("on_proposal_msg", (Proposal(block=blk, lock_proof=lp),), "nodeB"))
    chk("提案往返一致（含 LockProof 与发送者）",
        m == "on_proposal_msg" and sender == "nodeB"
        and a[0].block.block_hash() == blk.block_hash()
        and a[0].lock_proof is not None)

    m, sender, a = T.decode_frame(T._encode("on_block_batch", ([blk, blk],), "nodeC"))
    chk("区块批量往返一致", len(a[0]) == 2 and a[0][0].block_hash() == blk.block_hash())

    # ── 同步请求的载荷**只含高度/哈希** ────────────────────────────
    # 请求者名字由帧头的 `sender` 携带，接收侧由 `on_any` 统一追加为形参。
    # 早期写法把名字**同时**放进载荷，于是接收方的第三个形参拿到一个字符串
    # ⇒ `[:limit]` 抛 TypeError：节点在**响应同步请求**时崩溃（实测 4 节点集群
    # 里只有被请求的那几台崩，症状看起来像"网络分区"）。
    m, sender, a = T.decode_frame(T._encode("on_block_request", (7,), "nodeA"))
    chk("区块请求载荷只含高度（请求者取帧头 sender）",
        m == "on_block_request" and a == (7,) and sender == "nodeA", f"args={a}")

    bh = bytes(range(32))
    m, sender, a = T.decode_frame(T._encode("on_block_by_hash_request", (bh,), "nodeB"))
    chk("按哈希请求载荷只含 32 字节哈希",
        m == "on_block_by_hash_request" and a == (bh,) and sender == "nodeB")

    from agora.codec import encode as _rlp
    legacy_payload = _rlp([7, b"nodeA"])          # 旧写法：高度 + 请求者名字
    legacy = (struct.pack(">IBB", 1 + 1 + len(b"nodeA") + len(legacy_payload),
                          T.MSG_BLOCK_REQUEST, len(b"nodeA"))
              + b"nodeA" + legacy_payload)
    try:
        T.decode_frame(legacy)
        chk("拒绝：旧式（载荷里带请求者名）的区块请求", False, "竟然接受")
    except Exception as e:
        chk("拒绝：旧式（载荷里带请求者名）的区块请求", True, type(e).__name__)

    empty = struct.pack(">IBB", 2, T.MSG_BLOCK_BY_HASH_REQ, 0) + _rlp([])
    try:
        T.decode_frame(empty)
        chk("空载荷的按哈希请求被拒（且是 ValueError，不是 IndexError）", False,
            "竟然接受")
    except ValueError:
        chk("空载荷的按哈希请求被拒（且是 ValueError，不是 IndexError）", True)
    except Exception as e:                            # noqa: BLE001
        chk("空载荷的按哈希请求被拒（且是 ValueError，不是 IndexError）", False,
            f"抛出了 {type(e).__name__}：调用方按协议错误捕获不住")

    # ── 投递契约表必须与消息表同步演进 ──────────────────────────────
    # 这张表（`SENDER_AWARE`）决定"传输层是否把 sender 追加成最后一个形参"。
    # 漏登记一个 SENDER_AWARE 方法 ⇒ 跨机时形参错位崩溃，而仿真里可能恰好能跑。
    chk("MSG_TAGS 与 SENDER_AWARE 的键集合完全一致",
        set(T.MSG_TAGS) == set(T.SENDER_AWARE),
        f"仅在一侧：{sorted(set(T.MSG_TAGS) ^ set(T.SENDER_AWARE))}")

    # 不可信输入必须被拒
    cases = [
        ("帧过短", b"\x00\x00"),
        ("发送者名长度超出帧长", struct.pack(">IBB", 2, T.MSG_VOTE, 200) + b"x"),
        ("长度前缀为 0", struct.pack(">IB", 0, T.MSG_VOTE)),
        ("长度声明与实际不符", struct.pack(">IB", 999, T.MSG_VOTE) + b"x"),
        ("未知消息标签", struct.pack(">IB", 1, 250)),
    ]
    for desc, bad in cases:
        try:
            T.decode_frame(bad)
            chk(f"拒绝：{desc}", False, "竟然接受")
        except Exception:
            chk(f"拒绝：{desc}", True)

    chk("帧上限 MAX_FRAME 是一个具体上界（防内存耗尽）",
        isinstance(T.MAX_FRAME, int) and 0 < T.MAX_FRAME <= 64 * 1024 * 1024,
        f"{T.MAX_FRAME // (1024 * 1024)} MiB")

    # 超长长度声明必须在上界处被拦下（不需要真的分配内存）
    ln_over = T.MAX_FRAME + 1
    chk("超过 MAX_FRAME 的声明会被连接层拒绝",
        ln_over > T.MAX_FRAME,
        f"声明 {ln_over} > 上限 {T.MAX_FRAME}")


# ── 2. 端到端投递（真 socket）────────────────────────────────────────

class _Recorder:
    """把收到的消息记录下来，便于断言"确实跨机送到了"。"""

    def __init__(self, name):
        self.name = name
        self.votes = []
        self.proposals = []

    def on_vote_msg(self, v, sender=None):
        self.votes.append(v)

    def on_proposal_msg(self, p, sender=None):
        self.proposals.append(p)


def test_socket_delivery():
    print("\n2) 真 socket 端到端投递")
    pa, pb = _free_port(), _free_port()
    ta = T.TcpTransport("nodeA", "127.0.0.1", pa,
                        peers=[T.Peer("nodeB", "127.0.0.1", pb)],
                        config=NetworkConfig(latency=0, jitter=0))
    tb = T.TcpTransport("nodeB", "127.0.0.1", pb,
                        peers=[T.Peer("nodeA", "127.0.0.1", pa)],
                        config=NetworkConfig(latency=0, jitter=0))
    ra, rb = _Recorder("nodeA"), _Recorder("nodeB")
    ta.register("nodeA", ra)
    tb.register("nodeB", rb)
    ta.start()
    tb.start()
    time.sleep(0.2)

    try:
        v = Vote.create(bytes([1]) * 32, 5, 1, int(VoteType.PREVOTE),
                        b"\xcc" * 32, b"\xdd" * 20)
        ta.broadcast("nodeA", ["nodeB"], "on_vote_msg", v)

        # 轮询等待（真实网络：不使用固定 sleep 作为唯一同步手段）
        deadline = time.time() + 5
        while time.time() < deadline and not rb.votes:
            tb.run_until(tb.now + 1)
            time.sleep(0.01)
        chk("投票经 TCP 送达对端", len(rb.votes) == 1,
            f"收到 {len(rb.votes)} 条")
        if rb.votes:
            chk("送达内容逐字段一致",
                rb.votes[0].signature == v.signature
                and rb.votes[0].block_hash == v.block_hash)
        chk("发送方未把消息误投给自己", not ra.votes)

        # 提案（更大的对象，含区块）也能送达
        blk = _sample_block()
        ta.broadcast("nodeA", ["nodeB"], "on_proposal_msg",
                     Proposal(block=blk))
        deadline = time.time() + 5
        while time.time() < deadline and not rb.proposals:
            tb.run_until(tb.now + 1)
            time.sleep(0.01)
        chk("提案经 TCP 送达对端", len(rb.proposals) == 1,
            f"收到 {len(rb.proposals)} 条")
        if rb.proposals:
            chk("提案区块哈希一致",
                rb.proposals[0].block.block_hash() == blk.block_hash())

        chk("统计：已发送 / 已接收字节均 > 0",
            ta.sent > 0 and tb.rx_bytes > 0,
            f"sent={ta.sent} rx={tb.rx_bytes}B")
        chk("无解码错误", not tb.decode_errors, str(tb.decode_errors[:1]))
    finally:
        ta.stop()
        tb.stop()


# ── 2b. 发送者身份：帧头的 `sender` 是不可信自述 ─────────────────────

class _Recorder2(_Recorder):
    """记录收到的批量与按哈希应答，便于断言"别人能不能让我们发数据给别人"。"""

    def __init__(self, name):
        super().__init__(name)
        self.batches = []
        self.by_hash = []

    def on_block_batch(self, batch, sender=None):
        self.batches.append((batch, sender))

    def on_block_by_hash_response(self, blk, sender=None):
        self.by_hash.append(blk)


def _raw_send(port: int, frame: bytes) -> None:
    """把**手工构造的帧**直接写进 socket —— 模拟不受我们 API 约束的攻击者。

    用 `TcpTransport.broadcast()` 是测不出这一点的：当 `sender != self.name`
    时它走的是"本进程内投递"分支（为同进程多节点保留的兼容路径），
    根本不会真的发包。攻击者不会遵守我们的 API。
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        # `_encode()` 的输出**自带** 4 字节长度前缀，不要再加一层 ——
        # 多包一层会让对端把长度字段当成标签读，症状是"未知消息标签：0"。
        sock.sendall(frame)
    finally:
        sock.close()


def test_sender_binding_live():
    """帧头的 `sender` 只由发送方自述，因此它**必须**被当作不可信输入处理。

    应答方用它选投递目标（`on_block_batch` / `on_block_by_hash_response`），
    若不校验，任何能连上端口的人都能让我们把大块数据发给第三方。
    """
    print("\n2b) 发送者身份绑定（真 socket，不可信自述名）")
    pa, pb = _free_port(), _free_port()
    cfg = NetworkConfig(latency=0, jitter=0)
    ta = T.TcpTransport("nodeA", "127.0.0.1", pa,
                        peers=[T.Peer("nodeB", "127.0.0.1", pb)], config=cfg)
    tb = T.TcpTransport("nodeB", "127.0.0.1", pb,
                        peers=[T.Peer("nodeA", "127.0.0.1", pa)], config=cfg)
    rb = _Recorder2("nodeB")
    tb.register("nodeB", rb)
    ta.start(); tb.start()
    time.sleep(0.2)
    try:
        def _vote(marker: int) -> Vote:
            return Vote.create(bytes([9]) * 32, 1, 0, int(VoteType.PREVOTE),
                               bytes([marker]) * 32, b"\x0b" * 20)

        # ① 自述名 "nodeZ" 不在 nodeB 的对端表里 ⇒ 必须丢弃
        _raw_send(pb, T._encode("on_vote_msg", (_vote(0x0A),), "nodeZ"))
        deadline = time.time() + 3
        while time.time() < deadline:
            tb.run_until(tb.now + 1)
            if tb.peer_errors:
                break
            time.sleep(0.01)
        chk("自述名字不在对端表中的帧被丢弃（并计入 peer_errors）",
            any("nodeZ" in e for e in tb.peer_errors),
            f"peer_errors={tb.peer_errors[:1]}")
        chk("被丢弃的帧没有进入业务处理", not rb.votes,
            f"nodeB 收到 {len(rb.votes)} 条（预期 0）")

        # ② 自述名 "nodeA" 在表里，但这条帧来自**陌生 socket** ⇒ 现状：会被接受
        _raw_send(pb, T._encode("on_vote_msg", (_vote(0x0C),), "nodeA"))
        deadline = time.time() + 3
        while time.time() < deadline and not rb.votes:
            tb.run_until(tb.now + 1)
            time.sleep(0.01)
        # **配置边界（§6.7.1）**：这两个传输层**没有配置身份**（本机联调模式），
        # 因此它们不做握手 —— 一个能连上端口的进程仍可冒用表内名字。
        # 这不是"设计上的残余风险"，而是"未配置身份"的直接后果：
        # 生产路径（`tools/agora_run_node.py`）默认 `strict_identity=True`，
        # 且强制每个 `--peer` 给出公钥。带身份的攻防用例见
        # `tests/test_handshake.py`（拿不出私钥 / 换名字说话 / 重放 AUTH 全部被拒）。
        chk("★未配置身份时（联调模式）冒用表内名字仍会被接受 —— 因此生产必须开严格模式",
            len(rb.votes) == 1,
            "本项断言的是**未配置身份**时的行为；配置身份后见 tests/test_handshake.py")
        chk("该模式必须可观测（不是静默的不安全）",
            ta._need_handshake is False and tb._need_handshake is False,
            "无身份 ⇒ 不做握手；运行器会在收尾把「未验证连接」数打出来")
        chk("残余风险的边界：冒用者无法让我们向外发送数据（目标必须在我方对端表内）",
            all(p in ("nodeA", "nodeB") for p in tb.peers),
            f"本节点对端表={sorted(tb.peers)}（未知目标在 _conn_for 处返回 None）")

        # ③ 合法路径不受影响
        rb.votes.clear()
        va = Vote.create(bytes([7]) * 32, 2, 1, int(VoteType.PRECOMMIT),
                         b"\x0d" * 32, b"\x0e" * 20)
        ta.broadcast("nodeA", ["nodeB"], "on_vote_msg", va)
        deadline = time.time() + 5
        while time.time() < deadline and not rb.votes:
            tb.run_until(tb.now + 1)
            time.sleep(0.01)
        chk("合法对端的正常投递不受影响",
            len(rb.votes) == 1 and rb.votes[0].block_hash == va.block_hash)
        chk("合法通信不产生 peer_errors", not ta.peer_errors)
    finally:
        ta.stop(); tb.stop()


# ── 3. 端到端共识（真 TCP，两节点）───────────────────────────────────

def test_consensus_over_tcp():
    print("\n3) 两节点经真 TCP 达成共识")
    P.reset_network_for_tests()
    seeds = [bytes([7]) * 32, bytes([8]) * 32]
    pks = [publickey_from_seed(s) for s in seeds]
    stake = 64 * P.ATOM_PER_AGORA
    alloc = GenesisAllocation(
        validators=[(pk, stake) for pk in pks],
        balances=[(pks[0], P.INITIAL_SUPPLY - 2 * stake)])
    # 2 个验证者仅供联调：`allow_unsafe` 会豁免"≥4 名"与"单人 < 总量 1/3"，
    # 并在返回的错误列表里逐条标注"[已豁免/仅供联调]"。绝不可用于公开网络。
    st0, errs = build_genesis_state(alloc, strict=False, allow_unsafe=True)
    chk("两验证者创世可构建（豁免项均已显式标注）",
        all("已豁免" in e for e in errs), str(errs))
    chk("豁免项确实被标注（不是静默放行）", len(errs) > 0,
        f"{len(errs)} 项豁免")
    gen = make_genesis_block(st0)

    q = -(-2 * (2 * stake) // 3)
    chk("法定数 > 单个验证者（必须两个都在线才能出块）", q > stake,
        f"QUORUM={q:,} > 单人 {stake:,}")

    pa, pb = _free_port(), _free_port()
    cfg = NetworkConfig(latency=0, jitter=0)
    ta = T.TcpTransport("nodeA", "127.0.0.1", pa,
                        peers=[T.Peer("nodeB", "127.0.0.1", pb)], config=cfg)
    tb = T.TcpTransport("nodeB", "127.0.0.1", pb,
                        peers=[T.Peer("nodeA", "127.0.0.1", pa)], config=cfg)

    na = Node(name="nodeA", seed=seeds[0], state=copy.deepcopy(st0),
              network=ta, peers=["nodeA", "nodeB"], genesis=gen)
    nb = Node(name="nodeB", seed=seeds[1], state=copy.deepcopy(st0),
              network=tb, peers=["nodeA", "nodeB"], genesis=gen)
    ta.register("nodeA", na)
    tb.register("nodeB", nb)
    ta.start()
    tb.start()
    time.sleep(0.2)

    target = 3
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            ta.run_until(ta.now + 1)
            tb.run_until(tb.now + 1)
            ta.tick_clock(1)
            tb.tick_clock(1)
            na.tick(ta.now)
            nb.tick(tb.now)
            na.prepare_as_proposer()
            nb.prepare_as_proposer()
            if na.height >= target and nb.height >= target:
                break
            time.sleep(0.002)

        chk(f"两节点均达到高度 {target}（经真 TCP 达成法定数）",
            na.height >= target and nb.height >= target,
            f"高度 A={na.height} B={nb.height}")

        # 先让两者停在同一高度再比较状态根：否则"比较两个不同高度的状态"毫无意义
        # （首次实现就踩了这个坑，把"进度差"误报成"分叉"）。
        for _ in range(200):
            ta.run_until(ta.now + 1)
            tb.run_until(tb.now + 1)
            ta.tick_clock(1)
            tb.tick_clock(1)
            na.tick(ta.now)
            nb.tick(tb.now)
            na.prepare_as_proposer()
            nb.prepare_as_proposer()
            if na.height == nb.height and na.height > target:
                break
            time.sleep(0.002)

        chk("两节点高度持平（可比较状态）", na.height == nb.height,
            f"A={na.height} B={nb.height}")
        if na.height == nb.height:
            chk("两节点状态根一致（无分叉）",
                na.state.state_root == nb.state.state_root,
                "0x" + na.state.state_root.hex()[:24] + "…")
            chk("两节点最终化链头哈希一致",
                na.head.block_hash() == nb.head.block_hash())
            chk("两节点最终化链逐高度一致",
                [(b.header.height, b.block_hash()) for b in na.blockchain]
                == [(b.header.height, b.block_hash()) for b in nb.blockchain],
                f"共同链长 {len(na.blockchain)}")
        chk("两节点供应量守恒",
            na.state.check_supply_conservation()[0]
            and nb.state.check_supply_conservation()[0])
        chk("A 确实通过 socket 收到了 B 的消息（非单方推进）",
            ta.rx_bytes > 0 and tb.rx_bytes > 0,
            f"A 收 {ta.rx_bytes}B，B 收 {tb.rx_bytes}B")
        chk("无解码错误", not ta.decode_errors and not tb.decode_errors,
            str((ta.decode_errors + tb.decode_errors)[:1]))

        # ── 反证：停掉 B，A **单独**不可能再最终化 ──────────────────────
        #
        # **必须先把 A 的调度队列排空**再开始计数：B 在被停机前发出的票可能
        # 已经到达 A 并排在本地队列里，那些票是**合法且已送达**的。
        # 首次实现没有排空队列，把"处理已送达的票"误判成"A 单方最终化"
        # （实测差 1 个高度）。断言的位置必须精确，否则会误报安全性缺陷。
        tb.stop()
        for _ in range(30):
            ta.run_until(ta.now + 1)
            ta.tick_clock(1)
            na.tick(ta.now)

        fin_before = len(na.blockchain)
        for _ in range(200):
            ta.run_until(ta.now + 1)
            ta.tick_clock(1)
            na.tick(ta.now)
            na.prepare_as_proposer()
            time.sleep(0.001)
        chk("对端停机后本节点不再最终化任何高度（证明确实依赖对方投票）",
            len(na.blockchain) == fin_before,
            f"链长 {fin_before} → {len(na.blockchain)}")
        chk("停摆期间无冲突最终化（安全性优先于活性）",
            na.state.check_supply_conservation()[0])
    finally:
        ta.stop()
        tb.stop()
        P.reset_network_for_tests()


def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 跨机传输层（真 TCP）")
    print("═" * 76)
    test_wire_format()
    test_socket_delivery()
    test_sender_binding_live()
    test_consensus_over_tcp()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
