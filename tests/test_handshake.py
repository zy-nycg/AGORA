# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 名字↔连接的**签名握手**测试（规范 §6.7）
========================================================

这一层要证明的性质（**每一条都对应一个具体攻击**）
--------------------------------------------------
1. **原像符合规范**：握手签名原像的字节必须与 §6.7 逐字节一致
   （测试里**手写**期望字节，而不是调用被测函数自己算 —— 后者只能证明自洽）；
2. **域分隔**：CHALLENGE 的签名不能当作 AUTH 用（否则可反射）；
3. **nonce 双向绑定**：签名覆盖（发起方 nonce, 响应方 nonce）⇒ 录下来的
   CHALLENGE/AUTH **无法重放**到新连接上；
4. **名字绑定**：握手完成后，该连接上任何"换个名字说话"的帧都被丢弃
   （这是"冒用对端表内名字"的直接封堵点）；
5. **公钥绑定**：自称某名字但拿不出对应私钥 ⇒ 连接被拒；
6. **认证先于业务**：握手完成前的业务帧绝不进入应用层；
7. **失败即断开**：任何握手中断都不得回退成"没身份也放行"；
8. **不破坏共识**：带身份 + 严格模式的两个节点仍能经真 TCP 达成共识。

运行：python3 tests/test_handshake.py
"""

from __future__ import annotations

import copy
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agora import handshake as H
from agora import params as P
from agora import transport as T
from agora.consensus import Vote, VoteType
from agora.crypto import publickey_from_seed, sign
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


class _Recorder:
    """记录收到的业务消息的简易接收者（不实现 `on_any`）。"""

    def __init__(self, name):
        self.name = name
        self.votes = []

    def on_vote_msg(self, v, sender=None):
        self.votes.append((v, sender))


SEEDS = {"nodeA": bytes([11]) * 32, "nodeB": bytes([12]) * 32}
PKS = {n: publickey_from_seed(s) for n, s in SEEDS.items()}


# ── 1. 原像逐字节符合规范 ───────────────────────────────────────────

def test_payload_conformance():
    print("\n1) 握手原像逐字节符合规范 §6.7（手写期望值，不调用被测函数）")
    chain_id = P.CHAIN_ID_BYTES
    name = "nodeA"
    pk = bytes(range(32))
    ni = bytes(range(32, 64))
    nr = bytes(range(64, 96))

    # 规范：TAG ‖ CHAIN(chain_id, u8(role), u32(len(name))‖name, pubkey, nonce_i, nonce_r)
    # 其中 chain_id = "agora-mainnet-1"（15 字节）⇒ 按 §20.1 的 bytes 规则**加 u32 前缀**。
    cb = chain_id
    expect = (H.TAG_HANDSHAKE
              + len(cb).to_bytes(4, "big") + cb
              + bytes([H.ROLE_CHALLENGE])
              + len(name.encode()).to_bytes(4, "big") + name.encode()
              + pk + ni + nr)
    got = H.handshake_payload(H.ROLE_CHALLENGE, cb, name, pk, ni, nr)
    chk("CHALLENGE 原像 == 手写期望字节", got == expect,
        f"{len(got)} 字节；首 12 字节 {got[:12].hex()}")
    chk("原像以域标签开头（标签在 CHAIN 之外，§20.1）",
        got.startswith(b"AGORA/HANDSHAKE/v0.2.2")
        and H.TAG_HANDSHAKE == b"AGORA/HANDSHAKE/v0.2.2")
    chk("chain_id 按 bytes 规则加 u32 前缀（15 字节 ⇒ 带前缀）",
        got[len(H.TAG_HANDSHAKE):len(H.TAG_HANDSHAKE) + 4] == (15).to_bytes(4, "big"))

    chk("AUTH 原像 = 同一结构、仅角色字节不同（2 → 3）",
        H.handshake_payload(H.ROLE_AUTH, cb, name, pk, ni, nr)
        == expect[:len(H.TAG_HANDSHAKE) + 4 + len(cb)] + bytes([H.ROLE_AUTH])
        + expect[len(H.TAG_HANDSHAKE) + 4 + len(cb) + 1:])

    # 角色必须被拒绝在集合之外（防止域分隔被绕过）
    try:
        H.handshake_payload(1, cb, name, pk, ni, nr)
        chk("角色字节只接受 2/3（其它值被拒绝）", False, "竟然接受角色 1")
    except H.HandshakeError:
        chk("角色字节只接受 2/3（其它值被拒绝）", True)

    # 长度校验（不可信输入）
    for desc, args in (
        ("pubkey 31 字节", (H.ROLE_CHALLENGE, cb, name, bytes(31), ni, nr)),
        ("nonce 31 字节", (H.ROLE_CHALLENGE, cb, name, pk, bytes(31), nr)),
        ("空名字", (H.ROLE_CHALLENGE, cb, "", pk, ni, nr)),
    ):
        try:
            H.handshake_payload(*args)
            chk(f"原像拒绝：{desc}", False, "竟然接受")
        except H.HandshakeError:
            chk(f"原像拒绝：{desc}", True)

    # 签名/验签的域分隔与 nonce 绑定
    sig_c = H.make_challenge_sig(SEEDS["nodeA"], cb, name, PKS["nodeA"], ni, nr)
    sig_a = H.make_auth_sig(SEEDS["nodeA"], cb, name, PKS["nodeA"], ni, nr)
    chk("CHALLENGE 签名验得过", H.check_challenge_sig(PKS["nodeA"], sig_c, cb, name, ni, nr))
    chk("CHALLENGE 签名**不能**当作 AUTH 使用（域分隔）",
        not H.check_auth_sig(PKS["nodeA"], sig_c, cb, name, ni, nr))
    chk("AUTH 签名**不能**当作 CHALLENGE 使用（域分隔）",
        not H.check_challenge_sig(PKS["nodeA"], sig_a, cb, name, ni, nr))
    chk("交换两个 nonce 后签名失效（双向绑定）",
        not H.check_challenge_sig(PKS["nodeA"], sig_c, cb, name, nr, ni))
    chk("换一个公钥后签名失效", not H.check_challenge_sig(PKS["nodeB"], sig_c, cb, name, ni, nr))
    chk("换一个名字后签名失效",
        not H.check_challenge_sig(PKS["nodeA"], sig_c, cb, "nodeB", ni, nr))
    chk("换一条链（chain_id 不同）后签名失效",
        not H.check_challenge_sig(PKS["nodeA"], sig_c, b"agora-testnet-1", name, ni, nr))
    chk("全零签名**绝不**被当作有效签名",
        not H.check_challenge_sig(PKS["nodeA"], H.NIL_SIG, cb, name, ni, nr)
        and not H.check_auth_sig(PKS["nodeA"], H.NIL_SIG, cb, name, ni, nr))


# ── 2. 线格式（不可信输入）──────────────────────────────────────────

def test_handshake_wire():
    print("\n2) 握手消息的线格式与不可信输入")
    ni, nr = bytes(32), bytes(range(32))
    pk = bytes([9]) * 32
    sig = bytes([8]) * 64

    for method, args in (("on_hello", ("nodeA", pk, ni)),
                         ("on_challenge", ("nodeA", pk, nr, sig)),
                         ("on_auth", (sig,))):
        m, sender, a = T.decode_frame(T._encode(method, args, "nodeA"))
        chk(f"{method} 往返一致", m == method and sender == "nodeA" and a == args)

    # 手写帧构造器：让长度前缀由代码算出来（手算长度只会把测试写成算术题）
    def _frame(tag, sender, payload):
        sb = sender.encode("utf-8")
        return (struct.pack(">IBB", len(payload) + 2 + len(sb), tag, len(sb))
                + sb + payload)

    bad = [
        ("HELLO 只有 2 项", _frame(T.MSG_HELLO, "nodeA", _rlp(["nodeA", pk]))),
        ("HELLO 的 pubkey 只有 31 字节",
         _frame(T.MSG_HELLO, "nodeA", _rlp(["nodeA", bytes(31), ni]))),
        ("HELLO 的 nonce 只有 31 字节",
         _frame(T.MSG_HELLO, "nodeA", _rlp(["nodeA", pk, bytes(31)]))),
        ("CHALLENGE 的签名只有 63 字节",
         _frame(T.MSG_CHALLENGE, "nodeA", _rlp(["nodeA", pk, nr, bytes(63)]))),
        ("AUTH 有 2 项", _frame(T.MSG_AUTH, "nodeA", _rlp([sig, sig]))),
        ("HELLO 的节点名为空",
         _frame(T.MSG_HELLO, "nodeA", _rlp(["", pk, ni]))),
        ("CHALLENGE 只有 3 项",
         _frame(T.MSG_CHALLENGE, "nodeA", _rlp(["nodeA", pk, nr]))),
    ]
    for desc, frame in bad:
        try:
            T.decode_frame(frame)
            chk(f"拒绝：{desc}", False, "竟然接受")
        except Exception as e:                        # noqa: BLE001
            chk(f"拒绝：{desc}", isinstance(e, ValueError), f"{type(e).__name__}")

    # 帧头名字与载荷名字不符（HELLO）必须被拒绝 —— 由握手逻辑校验，见第 3 节。


def _rlp(items):
    from agora.codec import encode
    return encode(items)


# ── 3. 真 socket 上的握手与攻击 ─────────────────────────────────────

def _raw_connect(port: int) -> socket.socket:
    return socket.create_connection(("127.0.0.1", port), timeout=4)


def _raw_read_frame(sock: socket.socket) -> bytes:
    head = b""
    while len(head) < 4:
        chunk = sock.recv(4 - len(head))
        if not chunk:
            raise OSError("连接被对端关闭")
        head += chunk
    (ln,) = struct.unpack(">I", head)
    body = b""
    while len(body) < ln:
        chunk = sock.recv(ln - len(body))
        if not chunk:
            raise OSError("连接被对端关闭")
        body += chunk
    return head + body


def _play_initiator(port: int, name: str, seed: bytes, pk: bytes,
                    auth_override: bytes = None) -> tuple:
    """扮演发起方完成握手（`auth_override` 用于重放测试）。

    返回 `(socket, nonce_i, nonce_r, 是否收到 CHALLENGE)`。
    """
    cb = P.CHAIN_ID_BYTES
    ni = os.urandom(H.NONCE_LEN)
    sock = _raw_connect(port)
    sock.sendall(T._encode("on_hello", (name, pk, ni), name))
    frame = _raw_read_frame(sock)
    method, sender, args = T.decode_frame(frame)
    if method != "on_challenge":
        return sock, ni, None, False
    _, pk_r, nr, sig_r = args
    if auth_override is None:
        sig_i = H.make_auth_sig(seed, cb, name, pk, ni, nr)
    else:
        sig_i = auth_override
    sock.sendall(T._encode("on_auth", (sig_i,), name))
    return sock, ni, nr, True


def test_handshake_live():
    print("\n3) 真 socket：握手、名字绑定与三类攻击")
    pa, pb = _free_port(), _free_port()
    cfg = NetworkConfig(latency=0, jitter=0)
    ta = T.TcpTransport("nodeA", "127.0.0.1", pa,
                        peers=[T.Peer("nodeB", "127.0.0.1", pb, PKS["nodeB"])],
                        config=cfg, identity_seed=SEEDS["nodeA"],
                        strict_identity=True)
    tb = T.TcpTransport("nodeB", "127.0.0.1", pb,
                        peers=[T.Peer("nodeA", "127.0.0.1", pa, PKS["nodeA"])],
                        config=cfg, identity_seed=SEEDS["nodeB"],
                        strict_identity=True)
    ra = _Recorder("nodeA")
    rb = _Recorder("nodeB")
    ta.register("nodeA", ra)
    tb.register("nodeB", rb)
    ta.start(); tb.start()
    time.sleep(0.2)
    try:
        # ── ① 正常路径：握手成功 + 业务帧送达 ──
        v = Vote.create(SEEDS["nodeA"], 1, 0, int(VoteType.PREVOTE),
                        b"\xaa" * 32, b"\xbb" * 20)
        ta.broadcast("nodeA", ["nodeB"], "on_vote_msg", v)
        deadline = time.time() + 6
        while time.time() < deadline and not rb.votes:
            tb.run_until(tb.now + 1)
            time.sleep(0.01)
        chk("配置身份 + 严格模式下，业务帧正常送达", len(rb.votes) == 1,
            f"收到 {len(rb.votes)} 条")
        chk("两侧都完成了**已验证**的握手",
            ta.handshakes_ok == 1 and tb.handshakes_ok == 1,
            f"A={ta.handshakes_ok} B={tb.handshakes_ok}")
        chk("没有未验证连接、没有握手失败、没有名字不符",
            ta.unverified_conns == 0 and tb.unverified_conns == 0
            and not ta.identity_errors and not tb.identity_errors
            and not tb.identity_violations,
            tb.identity_summary())

        rb.votes.clear()

        # ── ② 攻击一：自称 "nodeA" 但没有 nodeA 的私钥 ──
        attacker_seed = bytes([77]) * 32
        attacker_pk = publickey_from_seed(attacker_seed)
        try:
            s, ni, nr, got = _play_initiator(pb, "nodeA", attacker_seed, attacker_pk)
            # 我们（攻击者）能收到 CHALLENGE，但发不出有效的 AUTH；
            # 若服务器接受了伪造 AUTH，则下面的业务帧会被处理 —— 必须不会。
            s.sendall(T._encode("on_vote_msg", (v,), "nodeA"))
            time.sleep(0.4)
            tb.run_until(tb.now + 1)
            s.close()
        except OSError:
            pass
        chk("★攻击一：拿不出 nodeA 私钥 ⇒ 连接被拒，业务帧不进入应用层",
            not rb.votes and not tb.identity_violations,
            f"nodeB 收到 {len(rb.votes)} 条；identity_errors={len(tb.identity_errors)}")

        # ── ③ 攻击二：完成了合法握手，但换个名字说话 ──
        s2, _, _, got2 = _play_initiator(pb, "nodeA", SEEDS["nodeA"], PKS["nodeA"])
        chk("（前置）攻击二确实完成了合法握手", got2)
        # 等对端把 AUTH 校验完（它在同一连接上读下一个帧）
        time.sleep(0.2)
        s2.sendall(T._encode("on_vote_msg", (v,), "nodeB"))
        time.sleep(0.4)
        tb.run_until(tb.now + 1)
        s2.close()
        chk("★攻击二：握手身份是 nodeA，却以 nodeB 名义投递 ⇒ 被丢弃",
            not rb.votes and tb.identity_violations,
            tb.identity_violations[:1] or "（没有记录到违规）")
        chk("违规被计入 identity_violations（可观测）",
            len(tb.identity_violations) >= 1)

        # ── ④ 攻击三：重放录下来的 AUTH ──
        # 先做一次合法握手，把 AUTH 帧**录下来**
        cb = P.CHAIN_ID_BYTES
        ni1 = os.urandom(H.NONCE_LEN)
        s3 = _raw_connect(pb)
        s3.sendall(T._encode("on_hello", ("nodeA", PKS["nodeA"], ni1), "nodeA"))
        f3 = _raw_read_frame(s3)
        _, _, a3 = T.decode_frame(f3)
        nr1 = a3[2]
        recorded_auth = H.make_auth_sig(SEEDS["nodeA"], cb, "nodeA", PKS["nodeA"], ni1, nr1)
        s3.sendall(T._encode("on_auth", (recorded_auth,), "nodeA"))
        time.sleep(0.2)
        s3.close()
        # 在新连接上重放那段 AUTH（新的 nonce ⇒ 必须失败）
        s4, ni2, nr2, got4 = _play_initiator(pb, "nodeA", SEEDS["nodeA"],
                                             PKS["nodeA"], auth_override=recorded_auth)
        time.sleep(0.3)
        s4.sendall(T._encode("on_vote_msg", (v,), "nodeA"))
        time.sleep(0.4)
        tb.run_until(tb.now + 1)
        s4.close()
        chk("★攻击三：重放旧 AUTH（nonce 已变）⇒ 握手失败、业务帧被丢弃",
            got4 and ni2 != ni1 and not rb.votes,
            f"nonce 是否新生成={ni2 != ni1}；收到 {len(rb.votes)} 条")
        chk("重放尝试被计入 identity_errors",
            len(tb.identity_errors) >= 1, tb.identity_errors[-1:])

        # ── ⑤ 认证先于业务：握手完成前直接发业务帧 ──
        s5 = _raw_connect(pb)
        s5.sendall(T._encode("on_vote_msg", (v,), "nodeA"))
        time.sleep(0.4)
        tb.run_until(tb.now + 1)
        s5.close()
        chk("★认证先于业务：握手前发的业务帧被丢弃（不进入应用层）",
            not rb.votes, f"nodeB 收到 {len(rb.votes)} 条")

        # ── ⑥ 合法连接在经历这些攻击之后仍然可用 ──
        v2 = Vote.create(SEEDS["nodeA"], 9, 0, int(VoteType.PRECOMMIT),
                         b"\xcc" * 32, b"\xbb" * 20)
        ta.broadcast("nodeA", ["nodeB"], "on_vote_msg", v2)
        deadline = time.time() + 6
        while time.time() < deadline and not rb.votes:
            tb.run_until(tb.now + 1)
            time.sleep(0.01)
        chk("★攻击之后合法连接仍然可用（没有把好连接一起打死）",
            len(rb.votes) == 1 and rb.votes[0][0].block_hash == v2.block_hash)
    finally:
        ta.stop(); tb.stop()


# ── 4. 配置纪律（严格模式 / 未配置身份）─────────────────────────────

def test_config_discipline():
    print("\n4) 配置纪律：严格模式拒绝「没有身份的对端」，非严格模式必须计数")
    pa, pb = _free_port(), _free_port()
    cfg = NetworkConfig(latency=0, jitter=0)

    # ① 严格模式但没给本方身份 ⇒ 构造即失败（配置错误，不能等到运行时）
    try:
        T.TcpTransport("nodeA", "127.0.0.1", pa, peers=[], config=cfg,
                       strict_identity=True)
        chk("严格模式少了本方身份 ⇒ 构造即报错", False, "竟然构造成功")
    except ValueError as e:
        chk("严格模式少了本方身份 ⇒ 构造即报错", "身份" in str(e), str(e)[:60])

    # ② 严格模式但某个对端没给公钥 ⇒ 构造即失败（否则会出现"未验证连接"）
    try:
        T.TcpTransport("nodeA", "127.0.0.1", pa,
                       peers=[T.Peer("nodeB", "127.0.0.1", pb)], config=cfg,
                       identity_seed=SEEDS["nodeA"], strict_identity=True)
        chk("严格模式下对端缺公钥 ⇒ 构造即报错", False, "竟然构造成功")
    except ValueError as e:
        chk("严格模式下对端缺公钥 ⇒ 构造即报错", "公钥" in str(e), str(e)[:70])

    # ③ 私钥与公钥不配套 ⇒ 构造即失败（否则所有对端都会拒绝我们，极难定位）
    try:
        T.TcpTransport("nodeA", "127.0.0.1", pa, peers=[], config=cfg,
                       identity_seed=SEEDS["nodeA"], identity_pubkey=PKS["nodeB"])
        chk("私钥与公钥不配套 ⇒ 构造即报错", False, "竟然构造成功")
    except ValueError as e:
        chk("私钥与公钥不配套 ⇒ 构造即报错", "不匹配" in str(e), str(e)[:60])

    # ④ 未配置身份 + 非严格模式 ⇒ 可以跑，但必须计数为"未验证"
    ta = T.TcpTransport("nodeA", "127.0.0.1", pa, peers=[
        T.Peer("nodeB", "127.0.0.1", pb)], config=cfg)
    tb = T.TcpTransport("nodeB", "127.0.0.1", pb, peers=[
        T.Peer("nodeA", "127.0.0.1", pa)], config=cfg)
    ra = _Recorder("nodeA"); rb = _Recorder("nodeB")
    ta.register("nodeA", ra); tb.register("nodeB", rb)
    ta.start(); tb.start()
    time.sleep(0.2)
    try:
        v = Vote.create(SEEDS["nodeA"], 1, 0, int(VoteType.PREVOTE), b"\xaa" * 32,
                        b"\xbb" * 20)
        ta.broadcast("nodeA", ["nodeB"], "on_vote_msg", v)
        deadline = time.time() + 5
        while time.time() < deadline and not rb.votes:
            tb.run_until(tb.now + 1)
            time.sleep(0.01)
        chk("未配置身份（联调模式）下仍可投递", len(rb.votes) == 1,
            "本机联调兼容性保留")
        chk("但**看起来**完全不需要握手（_need_handshake=False，不得因此宣称安全）",
            ta._need_handshake is False and tb._need_handshake is False)
    finally:
        ta.stop(); tb.stop()

    # ⑤ 一方有身份、另一方没有 ⇒ 有身份的那侧必须拒绝（严格模式）
    pc, pd = _free_port(), _free_port()
    te = T.TcpTransport("nodeA", "127.0.0.1", pc,
                        peers=[T.Peer("nodeB", "127.0.0.1", pd, PKS["nodeB"])],
                        config=cfg, identity_seed=SEEDS["nodeA"],
                        strict_identity=True)
    tf = T.TcpTransport("nodeB", "127.0.0.1", pd, peers=[], config=cfg)
    re_ = _Recorder("nodeA"); rf = _Recorder("nodeB")
    te.register("nodeA", re_); tf.register("nodeB", rf)
    te.start(); tf.start()
    time.sleep(0.2)
    try:
        v2 = Vote.create(SEEDS["nodeA"], 2, 0, int(VoteType.PREVOTE), b"\xdd" * 32,
                         b"\xbb" * 20)
        te.broadcast("nodeA", ["nodeB"], "on_vote_msg", v2)
        deadline = time.time() + 3
        while time.time() < deadline:
            tf.run_until(tf.now + 1)
            time.sleep(0.01)
        chk("严格模式 + 对端无身份 ⇒ 连接被拒、消息不投递",
            not rf.votes and te.identity_errors,
            te.identity_errors[:1] or "（没有记录到失败）")
    finally:
        te.stop(); tf.stop()


# ── 5. 不破坏共识（真 TCP，严格身份）────────────────────────────────

def test_consensus_with_identity():
    print("\n5) 带身份 + 严格模式的两个节点仍能经真 TCP 达成共识")
    P.reset_network_for_tests()
    seeds = [bytes([21]) * 32, bytes([22]) * 32]
    pks = [publickey_from_seed(s) for s in seeds]
    stake = 64 * P.ATOM_PER_AGORA
    alloc = GenesisAllocation(validators=[(pk, stake) for pk in pks],
                              balances=[(pks[0], P.INITIAL_SUPPLY - 2 * stake)])
    st0, errs = build_genesis_state(alloc, strict=False, allow_unsafe=True)
    gen = make_genesis_block(st0)

    pa, pb = _free_port(), _free_port()
    cfg = NetworkConfig(latency=0, jitter=0)
    ta = T.TcpTransport("nodeA", "127.0.0.1", pa,
                        peers=[T.Peer("nodeB", "127.0.0.1", pb, pks[1])], config=cfg,
                        identity_seed=seeds[0], strict_identity=True)
    tb = T.TcpTransport("nodeB", "127.0.0.1", pb,
                        peers=[T.Peer("nodeA", "127.0.0.1", pa, pks[0])], config=cfg,
                        identity_seed=seeds[1], strict_identity=True)
    na = Node(name="nodeA", seed=seeds[0], state=copy.deepcopy(st0), network=ta,
              peers=["nodeA", "nodeB"], genesis=gen)
    nb = Node(name="nodeB", seed=seeds[1], state=copy.deepcopy(st0), network=tb,
              peers=["nodeA", "nodeB"], genesis=gen)
    ta.register("nodeA", na)
    tb.register("nodeB", nb)
    ta.start(); tb.start()
    time.sleep(0.2)
    try:
        target = 3
        deadline = time.time() + 60
        while time.time() < deadline:
            ta.run_until(ta.now + 1)
            tb.run_until(tb.now + 1)
            ta.tick_clock(1); tb.tick_clock(1)
            na.tick(ta.now); nb.tick(tb.now)
            na.prepare_as_proposer(); nb.prepare_as_proposer()
            if na.height >= target and nb.height >= target:
                break
            time.sleep(0.002)
        chk(f"两节点在严格身份下达到高度 {target}",
            na.height >= target and nb.height >= target,
            f"高度 A={na.height} B={nb.height}")
        chk("两侧的身份统计干净（已握手 / 无未验证 / 无失败 / 无名字不符）",
            ta.handshakes_ok >= 1 and tb.handshakes_ok >= 1
            and ta.unverified_conns == 0 and tb.unverified_conns == 0
            and not ta.identity_errors and not tb.identity_errors
            and not ta.identity_violations and not tb.identity_violations)
        chk("供应量守恒未被破坏", na.state.check_supply_conservation()[0]
            and nb.state.check_supply_conservation()[0])
    finally:
        ta.stop(); tb.stop()
        P.reset_network_for_tests()


# ── 6. 对端离线时不得把主循环拖住（退避窗口）────────────────────────

def test_dial_backoff():
    print("\n6) 对端离线时：拨号必须有退避，不得每次广播都去等超时")

    class _DeadPort:
        pass

    dead = _free_port()                       # 这个端口没人监听
    pa = _free_port()
    cfg = NetworkConfig(latency=0, jitter=0)
    ta = T.TcpTransport("nodeA", "127.0.0.1", pa,
                        peers=[T.Peer("nodeB", "127.0.0.1", dead, PKS["nodeB"])],
                        config=cfg, identity_seed=SEEDS["nodeA"],
                        strict_identity=True, connect_timeout=1.0)
    ra = _Recorder("nodeA")
    ta.register("nodeA", ra)
    ta.start()
    time.sleep(0.1)
    try:
        v = Vote.create(SEEDS["nodeA"], 1, 0, int(VoteType.PREVOTE), b"\xaa" * 32,
                        b"\xbb" * 20)
        # 第一次：真的去拨号（失败，进入退避）
        t0 = time.time()
        ta.broadcast("nodeA", ["nodeB"], "on_vote_msg", v)
        first = time.time() - t0
        chk("第一次拨号确实失败并被记录",
            bool(ta.connect_errors), ta.connect_errors[-1][:60])
        # 之后 20 次广播：**一次都不该真的去拨号**。
        # 判据用「连接错误数不再增长」而不是耗时：回环上"连接被拒"本来就是 0ms，
        # 拿耗时比较测不出退避有没有生效（首版就是这么写错的）；
        # 而"是否真的发起过连接"是唯一能区分"跳过"与"试了但很快失败"的证据。
        n_err = len(ta.connect_errors)
        t1 = time.time()
        for _ in range(20):
            ta.broadcast("nodeA", ["nodeB"], "on_vote_msg", v)
        later = time.time() - t1
        chk("后续 20 次广播都没有真的拨号（命中退避窗口）",
            ta.dial_backoffs >= 20 and len(ta.connect_errors) == n_err,
            f"新增连接错误 {len(ta.connect_errors) - n_err} 条，"
            f"退避跳过 {ta.dial_backoffs} 次；20 次广播共 {later * 1000:.1f}ms"
            f"（首次 {first * 1000:.0f}ms）")
        chk("总耗时被限制在毫秒级（否则每个槽位都会被拖掉）",
            later < 0.5, f"{later * 1000:.1f}ms")
    finally:
        ta.stop()


# ── 7. 诊断质量：失败原因必须能分清（否则运维会误判）──────────────────

def test_diagnostics():
    print("\n7) 诊断：验签失败的原因必须能分清（链身份 / 被拒绝 / 超时）")
    cb = P.CHAIN_ID_BYTES                       # 本进程的链身份（mainnet）
    other = b"agora-testnet-1"
    pk = PKS["nodeA"]
    ni, nr = bytes(range(32)), bytes(range(32, 64))

    # ① 用**另一条链**的 chain_id 签出来的挑战：验不过，但必须能诊断出"链身份不一致"
    sig_other = H.make_challenge_sig(SEEDS["nodeA"], other, "nodeA", pk, ni, nr)
    chk("跨链（chain_id 不同）的挑战签名验不过",
        not H.check_challenge_sig(pk, sig_other, cb, "nodeA", ni, nr))
    hint = H.chain_mismatch_hint(pk, sig_other, H.ROLE_CHALLENGE, "nodeA", ni, nr, cb)
    chk("但诊断能指出「链身份不一致」（而不是含糊的签名无效）",
        "链身份" in hint and "agora-testnet-1" in hint, hint[:80])
    chk("诊断里包含本方链身份，便于对照",
        cb.decode() in hint, cb.decode())

    # ② 真正被篡改的签名不能给出"链身份"这种错误诊断（避免误导）
    tampered = bytes([sig_other[0] ^ 0xFF]) + sig_other[1:]
    chk("被篡改的签名不会被误诊为「链身份不一致」",
        H.chain_mismatch_hint(pk, tampered, H.ROLE_CHALLENGE, "nodeA", ni, nr, cb) == "")

    # ③ AUTH 角色同理
    sig_a = H.make_auth_sig(SEEDS["nodeA"], other, "nodeA", pk, ni, nr)
    chk("AUTH 跨链同样可诊断",
        "链身份" in H.chain_mismatch_hint(pk, sig_a, H.ROLE_AUTH, "nodeA", ni, nr, cb))

    # ④ "对端关闭连接"必须与"读超时"区分开（实测踩过：冒用探测被报成"超时"）
    import socket as _s
    a_sock, b_sock = _s.socketpair()
    t = T.TcpTransport("nodeA", "127.0.0.1", _free_port(), peers=[], config=NetworkConfig())
    try:
        b_sock.close()                                  # 对端直接关闭
        try:
            t._recv_frame(a_sock, raise_on_close=True)
            chk("对端关闭连接 ⇒ 抛 PeerClosed（而不是返回 None）", False, "竟然没抛")
        except T.PeerClosed as e:
            chk("对端关闭连接 ⇒ 抛 PeerClosed（而不是返回 None）", True, str(e))
        chk("业务循环仍把关闭当作普通断开（返回 None）",
            t._recv_frame(a_sock) is None)
    finally:
        a_sock.close()
        t.stop()


def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 名字↔连接的签名握手（规范 §6.7）")
    print("═" * 76)
    test_payload_conformance()
    test_handshake_wire()
    test_handshake_live()
    test_config_discipline()
    test_consensus_with_identity()
    test_dial_backoff()
    test_diagnostics()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
