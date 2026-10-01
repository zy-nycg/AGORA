# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 握手探测工具（对着**运行中的节点**验证"能不能冒用名字"）
========================================================================

为什么需要它（与单元测试的分工）
--------------------------------
`tests/test_handshake.py` 用两个**进程内**传输层验证握手逻辑；
那证明的是"代码里的状态机对"。它证明不了"真实运行的那个进程会拒绝我" ——
而这恰恰是运维最需要确认的一件事：**我的节点会不会被别人冒用名字投递消息？**

本工具就是干这个的：它用本实现的传输层当客户端，去**探测一个真实节点**，
给出可判定的结论：

    --expect accept   用正确的私钥 + 名字握手，并触发一次真实应答
                      （按需索取一段区块，要求对方**回送**区块批量）
    --expect reject   用一个**不匹配的**私钥冒充某个名字，要求对方**不处理**我们的帧
                      （判定依据：对方永不回送任何东西）

用法（对着一个本机节点）
------------------------
```bash
# ① 诚实探测：以 node1 的身份（持有 key1.seed）向 node4 索要高度 1 起的区块
python3 tools/agora_handshake_probe.py \\
    --target node4@127.0.0.1:26686@<node4_pubkey> \\
    --as node1 --seed-file wallet/runs/devkeys/key1.seed \\
    --listen 127.0.0.1:26656 --expect accept

# ② 冒用探测：用**别人的**私钥冒充 node1（必须被拒）
python3 tools/agora_handshake_probe.py \\
    --target node4@127.0.0.1:26686@<node4_pubkey> \\
    --as node1 --seed-file /tmp/attacker.seed \\
    --listen 127.0.0.1:26656 --expect reject
```

判读
----
* `accept` 判定：探测方**收到**了 `on_block_batch`（对方确实处理了我们的帧，
  并且按 §6.5 回送）；
* `reject` 判定：在超时窗口内**没有**收到任何回送，且对方连接被关闭；
* 退出码 0 = 与 `--expect` 一致；1 = 不一致（**这是安全上必须查清的信号**）。

**为什么"没收到回送"能证明被拒**：应答走的是对方**主动拨号**（§6.5 的批量回送），
因此只有它**真正处理了我们的请求**才会向我们发起连接。握手没通过 ⇒ 帧被丢弃 ⇒
不会有任何回送。反过来，如果 ① 的诚实探测也收不到回送，说明是
"地址/名字配错"而不是"被拒"，工具会把两者区分开并明确报出来。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agora import params as P
from agora.node import NetworkConfig
from agora.transport import Peer, TcpTransport


def _parse_peer(text: str) -> Peer:
    if "@" not in text:
        raise SystemExit("--target 格式应为 name@host:port[@pubkeyhex]")
    name, rest = text.split("@", 1)
    pk = None
    if "@" in rest:
        rest, _, pkhex = rest.partition("@")
        pkhex = pkhex.strip().lower().removeprefix("0x")
        if len(pkhex) != 64:
            raise SystemExit("--target 的公钥必须是 32 字节十六进制")
        pk = bytes.fromhex(pkhex)
    host, _, port = rest.rpartition(":")
    if not name or not host or not port.isdigit():
        raise SystemExit(f"--target 解析失败：{text!r}")
    return Peer(name, host, int(port), pubkey=pk)


def _load_seed(path: str) -> bytes:
    raw = open(path, encoding="utf-8").read().strip()
    seed = bytes.fromhex(raw.removeprefix("0x"))
    if len(seed) != 32:
        raise SystemExit("私钥种子必须为 32 字节（64 位十六进制）")
    return seed


class _Recorder:
    """至少实现 `on_any` —— 探测方必须能**吞下任何**对端发来的消息类型。

    首版只实现了 `on_block_batch`，结果真实节点握手通过后照常广播提案/投票，
    探测方在 `getattr(handler, "on_vote_msg")` 处抛 AttributeError 崩掉 ——
    这个崩溃本身恰好证明了"握手通过了、对端在正常广播"，
    但工具不能靠崩溃来报信。计数器把所有收到的类型都记下来，便于判读。
    """

    def __init__(self):
        self.batches = []
        self.seen: dict = {}

    def on_any(self, method_name, args, sender=""):
        self.seen[method_name] = self.seen.get(method_name, 0) + 1
        if method_name == "on_block_batch":
            self.batches.append((sender, len(args[0])))


def main() -> int:
    ap = argparse.ArgumentParser(description="握手探测：验证运行中的节点能否被冒用名字")
    ap.add_argument("--target", required=True, help="被探测节点 name@host:port[@pubkeyhex]")
    ap.add_argument("--as", dest="as_name", required=True, help="我们要声称的名字（须在该节点的对端表里）")
    ap.add_argument("--seed-file", required=True, help="我们用于握手的私钥（冒用时故意给错的）")
    ap.add_argument("--listen", required=True, help="我们监听的 host:port（须是该节点为 --as 配置的地址）")
    ap.add_argument("--expect", choices=("accept", "reject"), required=True)
    # **链身份必须先设定**：它进了握手签名原像（§6.7.1），配错时症状是
    # "挑战签名无效" —— 与"被篡改/被重放"一模一样。本工具首版就漏了这一步，
    # 对着真实 testnet 节点报出"签名无效"，差点被误读成"节点有安全缺陷"。
    ap.add_argument("--config", default=None,
                    help="创世配置 JSON（从中读出 network；与 --network 同时给出时必须一致）")
    ap.add_argument("--network", choices=tuple(P.ALLOWED_NETWORKS), default=None,
                    help="链身份；不给则必须用 --config 指定")
    ap.add_argument("--ask-height", type=int, default=1, help="索要区块的起始高度")
    ap.add_argument("--timeout", type=float, default=6.0, help="等待回送的秒数")
    ap.add_argument("--retry-interval", type=float, default=1.5,
                    help="重发区块请求的间隔（秒）")
    a = ap.parse_args()

    # 先定链身份，再构造传输层（顺序不能反：传输层一旦签名/验签就会冻结身份）
    net = a.network
    if a.config:
        cfg_net = json.load(open(a.config, encoding="utf-8"))["network"]
        if net is not None and net != cfg_net:
            raise SystemExit(f"--network={net} 与 {a.config} 里的 network={cfg_net} 不一致")
        net = cfg_net
    if net is None:
        raise SystemExit("必须给出 --network（或用 --config 指定创世配置）："
                         "链身份进了握手签名原像，配错会表现为签名无效")
    P.set_network(net)
    print(f"链身份：{P.CHAIN_ID}")

    peer = _parse_peer(a.target)
    host, _, port = a.listen.rpartition(":")
    cfg = NetworkConfig(latency=0, jitter=0)
    t = TcpTransport(a.as_name, host or "127.0.0.1", int(port), peers=[peer],
                     config=cfg, identity_seed=_load_seed(a.seed_file),
                     strict_identity=True, connect_timeout=3.0, handshake_timeout=3.0)
    rec = _Recorder()
    t.register(a.as_name, rec)
    t.start()
    time.sleep(0.2)

    print("═" * 74)
    print("AGORA 握手探测")
    print(f"  被探测 : {peer}")
    print(f"  我方声称: {a.as_name}（监听 {a.listen}，私钥 {a.seed_file}）")
    print(f"  期望   : {'接受（诚实握手并回送数据）' if a.expect == 'accept' else '拒绝（冒用必须失败）'}")
    print("═" * 74)
    try:
        # **周期性重发请求**（与真实节点的追赶行为一致）：
        # 应答是"一次尽力而为的主动拨号"（§6.5 的批量回送），若那一瞬间对端
        # 正处于拨号退避窗口（对端此前一直在找我们的地址），这一次回送就丢了。
        # 实测踩到过：单发一次请求 → 只收到 on_vote_msg/on_proposal_msg（说明
        # 握手已通过、对端在正常广播），却始终等不到区块批量。
        # 因此判据是"**在超时窗口内至少收到一次回送**"，而不是"第一次就必须回送"。
        deadline = time.time() + a.timeout
        n_req = 0
        next_req = 0.0
        while time.time() < deadline and not rec.batches:
            if time.time() >= next_req:
                t.broadcast(a.as_name, [peer.name], "on_block_request", a.ask_height)
                n_req += 1
                next_req = time.time() + a.retry_interval
            t.run_until(t.now + 1)
            t.tick_clock(1)
            time.sleep(0.01)
        got = len(rec.batches)
        replied = got > 0
        print(f"\n  观察到的结果（共发出 {n_req} 次区块请求）：")
        print(f"    · 收到的区块批量回送 : {got} 次"
              + (f"（{rec.batches[0][0]} → {rec.batches[0][1]} 个区块）" if replied else ""))
        print(f"    · 我方握手成功计数   : {t.handshakes_ok}")
        print(f"    · 未验证连接         : {t.unverified_conns}")
        print(f"    · 我方握手失败       : {len(t.identity_errors)}"
              + (f" {t.identity_errors[:1]}" if t.identity_errors else ""))
        # **必须把"连不上"与"被拒绝"分开报**：两者在观察面上都是"没有任何回送"，
        # 但含义完全相反。首版漏了这两行，我自己就被它误导过一次
        # （目标进程其实已经退出，报告却像是"对方拒绝了我们"）。
        for line in getattr(t, "connect_errors", [])[:2]:
            print(f"    · 连接错误           : {line}")
        if t.dropped:
            print(f"    · 丢弃计数           : {t.dropped}")
        if rec.seen:
            kinds = ", ".join(f"{k}×{v}" for k, v in sorted(rec.seen.items()))
            print(f"    · 收到的消息类型     : {kinds}")
        unreachable = bool(getattr(t, "connect_errors", [])) and not replied
        if a.expect == "accept":
            ok = replied
            if ok:
                why = "对方处理后按 §6.5 主动回送 ⇒ 诚实身份被接受"
            elif unreachable:
                why = ("**连不上目标节点**（Connection refused/超时）⇒ 这次探测**无效**，"
                       "不是「被拒绝」。请确认目标进程在监听、地址与端口正确后重跑")
            else:
                why = ("**没有收到回送但连接是通的** ⇒ 要么对方拒绝了我们（严重），"
                       "要么 --listen 不是对方为 --as 配置的地址、或 --as 不在对方对端表里")
        else:
            ok = not replied
            why = ("对方未处理我们的帧、也没有任何回送 ⇒ 冒用被拒 ✅"
                   if ok else
                   "**对方竟然回送了数据** ⇒ 冒用成功（严重：握手没有生效或对端未开严格模式）")
        print(f"\n  结论：{'✅ 与期望一致' if ok else '★ 与期望不一致'}")
        print(f"  说明：{why}")
        print("═" * 74)
        return 0 if ok else 1
    finally:
        t.stop()


if __name__ == "__main__":
    sys.exit(main())
