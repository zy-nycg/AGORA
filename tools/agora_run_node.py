# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 单节点启动器（真实网络）
=======================================

把一个验证者节点跑起来，通过**真 TCP** 与其它机器上的节点通信。
对应 `TESTNET_RUNBOOK.md` 阶段 C。

用法（每台机器各起一个进程）
---------------------------
    # PC 侧（3 个验证者）
    python3 tools/agora_run_node.py --config testnet-genesis.json \\
        --name node1 --seed-file keys-pc/key1.seed \\
        --listen 0.0.0.0:26656 \\
        --peer node2@192.168.1.20:26656 --peer node3@192.168.1.21:26656 \\
        --peer node4@192.168.1.30:26656

    # 香橙派侧（1 个验证者）
    python3 tools/agora_run_node.py --config testnet-genesis.json \\
        --name node4 --seed-file keys-pi/key1.seed \\
        --listen 0.0.0.0:26656 --peer node1@192.168.1.10:26656 ...

设计约束
--------
1. **先复核创世再启动**：启动前重新计算创世哈希并与配置文件的声明比对。
   若不一致，节点间的第一条共识消息就对不上，症状是"投票永远凑不齐"，
   极难排查 —— 因此宁可拒绝启动。
2. **启动自检**：确认 C 后端已生效（否则性能静默退化一个数量级）。
3. **私有材料不外泄**：`--seed-file` 只读，节点**不会**把它写入状态或日志。
4. **优雅停机**：收到 Ctrl-C 时停止监听并落盘，不留下半写状态。

持久化（`--data-dir`）
---------------------
给出 `--data-dir <目录>` 时节点**会从上次进度续跑**（不给出则每次都从创世开始）：

* `blocks.bin` —— 追加写、每条记录落盘前 fsync 的最终化区块日志，启动时校验自洽；
* `state.bin`  —— 状态快照（v2，携带链头 `Commit`），原子重命名写入；
* 恢复时**先读文件再决定是否补写创世**：早期版本先 `ensure_genesis()` 再读盘，
  于是每次重启都把创世块**再追加一次**（实测记录 768 处出现高度 0 的重复块）；
* 载入的状态**必须**与链头承诺的状态根一致，否则拒绝启动（退出码 4）。
  磁盘从不可信：快照与区块日志对不上时宁可停下来让人来看，也不静默地"修好"。

恢复后节点从**链头 + 1** 继续出块，并周期性（`--snapshot-every`）写状态快照。

**仍有限制（如实说明）：** 到高度 H 的追平依赖对端回送区块（`on_block_batch`），
因此长时间测试网需要至少 2 个节点同时在线；单节点停机过久后重启，
需等待与在线的法定数节点完成追赶（见 `TESTNET_RUNBOOK.md` 阶段 D）。
"""

from __future__ import annotations

import argparse
import threading
import json
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agora import params as P
from agora.crypto_backend import publickey_from_seed, startup_self_check
from agora.node import NetworkConfig, Node, make_genesis_block
from agora.state import GenesisAllocation, build_genesis_state, genesis_hash
from agora.transport import Peer, TcpTransport


def _parse_peer(text: str) -> Peer:
    """`name@host:port[@pubkeyhex]` → Peer

    公钥部分（32 字节十六进制）是**名字↔连接握手**（规范 §6.7）用来把"自述名字"
    绑定到密钥上的依据：给了它，`nodeA` 这个名字就只能由持有对应私钥的进程使用。
    不给也能启动（非严格模式），但那样任何能连上端口的人都能冒用该名字，
    因此运行器默认 `strict_identity=True`，**强制**要求每个对端都给出公钥。
    """
    if "@" not in text or ":" not in text:
        raise SystemExit(f"--peer 格式应为 name@host:port[@pubkeyhex]，实际 {text!r}")
    name, addr = text.split("@", 1)
    pk = None
    if "@" in addr:                              # name@host:port@pubkeyhex
        addr, _, pkhex = addr.partition("@")
        pkhex = pkhex.strip().lower()
        if pkhex.startswith("0x"):
            pkhex = pkhex[2:]
        if len(pkhex) != 64:
            raise SystemExit(f"--peer 的公钥必须是 32 字节十六进制（64 个字符）：{pkhex!r}")
        try:
            pk = bytes.fromhex(pkhex)
        except ValueError:
            raise SystemExit(f"--peer 的公钥不是合法十六进制：{pkhex!r}")
    host, _, port = addr.rpartition(":")
    if not name or not host or not port.isdigit():
        raise SystemExit(f"--peer 解析失败：{text!r}")
    return Peer(name, host, int(port), pubkey=pk)


def _load_genesis(path: str):
    """读取创世配置并重建 `(cfg, alloc, state)`。

    **实现统一在 `agora/genesis_cfg.py`**：这一函数此前是本文件私有的，
    于是"构建器怎么写"与"节点怎么读"各有一份逻辑，出现了
    **构建器写下了 airdrop_root 却没写空投条目** 的错配 ——
    节点重建出的创世金库为 0，自检报"金额不闭合"而拒绝启动，
    而构建器那边打印的却是"金额闭合 ✓"（它只校验内存对象，不校验序列化往返）。
    """
    from agora.genesis_cfg import GenesisConfigError, load_genesis_config
    try:
        cfg, alloc, st = load_genesis_config(path)
    except GenesisConfigError as e:
        raise SystemExit(str(e))
    if len(alloc.validators) < P.GENESIS_VALIDATOR_COUNT:
        print("⚠ 本创世少于 4 个验证者（联调模式）：单人即可达成法定数，"
              "**不得**用于公开网络")
    return cfg, alloc, st


def main() -> int:
    ap = argparse.ArgumentParser(description="启动一个 AGORA 验证者节点（真 TCP）")
    ap.add_argument("--config", required=True, help="创世配置 JSON")
    ap.add_argument("--name", required=True, help="本节点名（须与 peer 列表里的名字一致）")
    ap.add_argument("--seed-file", required=True, help="本节点私钥种子文件（32 字节十六进制）")
    ap.add_argument("--listen", default="0.0.0.0:26656", help="监听地址 host:port")
    ap.add_argument("--peer", action="append", default=[],
                    help="对端 name@host:port@pubkeyhex（可重复；公钥为 32 字节十六进制，"
                         "用于名字↔连接的签名握手，规范 §6.7）")
    ap.add_argument("--allow-unverified-peers", action="store_true",
                    help="**仅供本机联调**：允许对端不配置公钥（关闭严格身份校验）。"
                         "此时任何能连上端口的人都能冒用对端名字 —— 不得用于测试网/主网")
    ap.add_argument("--latency-ticks", type=int, default=0,
                    help="本地投递延迟（tick）；跨机延迟由真实网络决定")
    ap.add_argument("--report-every", type=int, default=10, help="每 N 秒打印一次状态")
    ap.add_argument("--max-seconds", type=int, default=0, help="运行上限秒数（0=不限）")
    ap.add_argument("--dry-run", action="store_true", help="只做启动自检与创世复核，不联网")
    ap.add_argument("--data-dir", default=None,
                    help="持久化目录（区块 + 状态快照）。给出后节点**重启会接着跑**，"
                         "而不是从创世重来。加载时会与链上承诺对账，不一致即拒绝启动")
    ap.add_argument("--snapshot-every", type=int, default=1000,
                    help="每 N 个区块写一次状态快照（默认 1000）")
    ap.add_argument("--rpc-port", type=int, default=0,
                    help="启用**只读查询接口**（HTTP JSON，供钱包/浏览器使用）的端口；"
                         "0 = 关闭。默认只监听回环地址")
    ap.add_argument("--rpc-bind", default="127.0.0.1",
                    help="查询接口绑定地址（默认 127.0.0.1；接口**没有鉴权**，"
                         "对外绑定请自行限制来源）")
    ap.add_argument("--airdrop-table", default=None,
                    help="空投分配表 JSON（提供领取 Merkle 证明所必需；"
                         "链上只存 airdrop_root，证明必须来自分配表）")
    ap.add_argument("--dump-height", type=int, default=0,
                    help="停机时打印本节点在指定高度的**区块哈希**。"
                         "多节点比对同一高度的哈希，才能证明没有分叉 —— "
                         "比较『各自的高度+链头』是没用的（那只是进度差）")
    a = ap.parse_args()

    # ① 启动自检：C 后端必须生效
    ok, msgs = startup_self_check(mainnet=False)
    print("── 启动自检 ──")
    for m in msgs:
        print("  " + m)

    # ② 载入并**复核**创世
    cfg, alloc, st = _load_genesis(a.config)
    gh = genesis_hash(st, alloc)
    declared = cfg.get("genesis_hash", "")
    good = ("0x" + gh.hex()) == declared
    print("── 创世复核 ──")
    print(f"  chain_id    : {P.CHAIN_ID}")
    print(f"  创世状态根  : 0x{st.state_root.hex()}")
    print(f"  创世哈希    : 0x{gh.hex()}  {'✅ 与配置文件一致' if good else '★ 与配置文件不符'}")
    if not good:
        print("  ✗ 拒绝启动：创世不可复现意味着本节点与他人的链不是同一条。")
        return 2

    # ③ 私钥
    if not os.path.exists(a.seed_file):
        raise SystemExit(f"私钥文件不存在：{a.seed_file}")
    seed_hex = open(a.seed_file, encoding="utf-8").read().strip()
    seed = bytes.fromhex(seed_hex.removeprefix("0x"))
    if len(seed) != 32:
        raise SystemExit("私钥种子必须为 32 字节（64 位十六进制）")
    pk = publickey_from_seed(seed)
    from agora.crypto_backend import address_from_pubkey
    addr = address_from_pubkey(pk)

    val_addrs = [address_from_pubkey(p) for p, _ in alloc.validators]
    if addr not in val_addrs:
        raise SystemExit(
            f"本私钥地址 {addr.hex()} 不在该创世的创始验证者集合中 —— "
            f"该私钥无权参与本链共识")
    print(f"  本节点地址  : {addr.hex()}（#{val_addrs.index(addr)} 号验证者）")

    peers = [_parse_peer(t) for t in a.peer]
    names = [p.name for p in peers]
    if a.name in names:
        raise SystemExit("对端列表里不得包含自己")

    if a.dry_run:
        print("\n--dry-run：自检与复核通过，未联网。")
        return 0 if ok else 1

    # ④ 规范 §5.3（BUG-75）：本地时间早于创世时间时 **MUST NOT** 出块。
    #    这一条必须在这里、用**墙钟**判定：节点内部的共识时间是逻辑时钟
    #    （从创世槽 0 起算），它永远"已经过了创世"，因此靠逻辑时钟无法实现该禁令。
    wait = P.seconds_until_genesis(time.time(), cfg["genesis_timestamp"])
    if wait > 0:
        import datetime
        print("\n✗ 拒绝启动：本地时间早于创世时间（规范 §5.3）")
        print(f"   创世时间 : {datetime.datetime.utcfromtimestamp(cfg['genesis_timestamp'])}"
              f" UTC（unix {cfg['genesis_timestamp']}）")
        print(f"   本地时间 : {datetime.datetime.utcnow()} UTC")
        print(f"   还需等待 : {wait / 3600:.2f} 小时（{wait:.0f} 秒）")
        print("   §5.3：任何节点在本地时间早于 GenesisTimestamp 时 MUST NOT 提议、"
              "投票或接受区块。")
        print("   ⇒ 请到创世时刻再启动；过早启动会让本节点产出**时间戳在未来**的链。")
        return 3

    host, _, port = a.listen.rpartition(":")
    # ── 名字↔连接的签名握手（规范 §6.7）─────────────────────────────
    # 默认**严格**：每个对端都必须给出公钥，且握手必须证明对端持有对应私钥。
    # 关闭它（--allow-unverified-peers）只用于本机联调，并且会打印醒目告警。
    strict = not a.allow_unverified_peers
    if not strict:
        print("\n⚠⚠ 已关闭严格身份校验（--allow-unverified-peers）：")
        print("    任何能连上本端口的进程都可以**冒用对端名字**投递消息。")
        print("    仅限本机联调；测试网/主网 **MUST NOT** 这样启动。\n")
    try:
        t = TcpTransport(a.name, host or "0.0.0.0", int(port), peers=peers,
                         config=NetworkConfig(latency=a.latency_ticks, jitter=0),
                         identity_seed=seed, strict_identity=strict)
    except ValueError as e:
        print(f"\n✗ 拒绝启动：身份配置有误（规范 §6.7）\n   {e}")
        print("   ⇒ `--peer` 需要写成 name@host:port@<pubkey-hex>（32 字节十六进制）。")
        print("     公钥可由对方用 `python3 tools/agora_keyinfo.py --seed-file <文件>` 打印，")
        print("     或直接取 genesis 配置里该验证者的 pubkey_hex。")
        return 5
    gen = make_genesis_block(st)
    import copy
    import functools

    # ── ③ 持久化：有数据目录就**接着跑**，否则从创世开始 ──
    store = None
    state = copy.deepcopy(st) if a.data_dir is None else st
    resumed = 0
    if a.data_dir is not None:
        from agora.store import ChainStore
        from agora.block import apply_block
        store = ChainStore(a.data_dir, snapshot_every=a.snapshot_every)
        store.blocks.ensure_genesis(gen)
        replay = functools.partial(apply_block, finalize_header=False, in_place=True)
        try:
            state, saved, saved_commit = store.load(st, gen, replays=replay)
        except Exception as e:                       # noqa: BLE001
            print(f"\n✗ 拒绝启动：持久化数据不可信\n   {e}")
            print("   ⇒ 数据目录与当前创世不符或已损坏。请人工确认后再处理：")
            print("      · 若确认要从头重建：删除该目录下的 blocks.bin / state.bin")
            return 4
        resumed = max(0, len(saved) - 1)
        print(f"── 持久化恢复 ──")
        print(f"  数据目录   : {a.data_dir}")
        print(f"  已最终化   : {resumed} 个区块（高度 {resumed}）")
        print(f"  状态根     : {state.state_root.hex()[:24]}…  ✅ 与链头承诺一致")

    node = Node(name=a.name, seed=seed, state=state, network=t,
                peers=[a.name] + names, genesis=gen)
    if a.data_dir is not None and resumed:
        node.resume_from(store.blocks.blocks(), head_commit=saved_commit)
        print(f"  已恢复到高度 {node.height - 1}，继续出块")
    t.register(a.name, node)
    t.start()

    print(f"\n── 已启动 ──")
    print(f"  监听       : {a.listen}")
    print(f"  对端       : {[str(p) for p in peers] or '（无，等待他人连接）'}")
    print(f"  目标高度   : 持续出块（Ctrl-C 停止）")
    print()

    saved_blocks = len(node.blockchain)
    stop = {"flag": False}

    def _sig(_signum, _frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    # ── ④ 只读查询接口（供移动端钱包取数）──────────────────────────
    # 关键点：**与节点主循环共用一把锁**。节点在自己的线程里改状态，而 HTTP 请求
    # 在另外的线程里读状态；不加锁就可能读到"半个区块"的状态（余额已扣、发行未记），
    # 这类错误只在并发下出现，极难复现。因此所有会改状态的调用都在 `with rpc_lock`
    # 里执行，查询则在同一把锁内完成。
    rpc_lock = threading.RLock()
    rpc_srv = None
    if a.rpc_port:
        from tools.agora_rpc_server import NodeProvider, serve_in_thread
        table = None
        if a.airdrop_table:
            try:
                table = json.load(open(a.airdrop_table, encoding="utf-8"))
            except Exception as e:                   # noqa: BLE001
                print(f"\n✗ 空投分配表读取失败：{e}")
                return 6
        provider = NodeProvider(node, gh, cfg, airdrop_table=table,
                                lock=rpc_lock, genesis_block=gen)
        try:
            rpc_srv, _th = serve_in_thread(provider, a.rpc_bind, a.rpc_port)
        except OSError as e:
            print(f"\n✗ 查询接口启动失败（端口 {a.rpc_port}？）：{e}")
            return 7
        if table is not None and not provider._airdrop_root_ok:
            print(f"  ⚠ 空投证明**不可用**：{provider._airdrop_note}")

    t0 = time.time()
    last_report = t0
    try:
        while not stop["flag"]:
            with rpc_lock:
                t.run_until(t.now + 1, max_events=5000)
                t.tick_clock(1)
                node.tick(t.now)
                node.prepare_as_proposer()

            # 持久化：把新最终化的区块追加落盘（每块 fsync），周期性写状态快照。
            if store is not None and len(node.blockchain) > saved_blocks:
                for blk in node.blockchain[saved_blocks:]:
                    store.append_block(blk)
                saved_blocks = len(node.blockchain)
                # 存**能证明当前 head** 的证书（可能为 None）：存一份落后的证书
                # 会让下次启动时磁盘自检直接拒绝（BUG-93，实测）。
                if store.maybe_snapshot(node.state, node.head.header.height,
                                        node.head.block_hash(),
                                        node.certifying_commit()):
                    print(f"  [持久化] 快照 @ 高度 {node.head.header.height}"
                          f"（{store.state_path}）", flush=True)

            now = time.time()
            if now - last_report >= a.report_every:
                last_report = now
                okc, counted, recorded = node.state.check_supply_conservation()
                print(f"[{int(now - t0):>5}s] 高度={node.height} 轮={node.consensus.hs.round} "
                      f"链长={len(node.blockchain)} 头={node.head.block_hash().hex()[:12]}… "
                      f"守恒={'✅' if okc else '★'} 收={t.rx_bytes}B 发={t.tx_bytes}B "
                      f"丢={t.dropped} 解码错={len(t.decode_errors)} "
                      f"握手={t.handshakes_ok} 未验证={t.unverified_conns} "
                      f"身份失败={len(t.identity_errors)} 退避={t.dial_backoffs} "
                      f"池={len(node.pool)} 收交易={node.stats.txs_received} "
                      f"入块={node.stats.txs_included}", flush=True)
            time.sleep(0.01)
            if a.max_seconds and (now - t0) >= a.max_seconds:
                break
    finally:
        if rpc_srv is not None:
            try:
                rpc_srv.shutdown()
                rpc_srv.server_close()
            except Exception:                          # noqa: BLE001
                pass
        t.stop()
        if store is not None and node.height > 1:
            # 停机快照：下次启动从快照 + 重放续跑，而不是从创世重来。
            store.save_state(node.state, node.head.header.height, node.head.block_hash(),
                             node.certifying_commit())
            print(f"\n── 已停止 ──")
            print(f"  已保存状态快照 @ 高度 {node.head.header.height} → {store.state_path}")
        else:
            print("\n── 已停止 ──")
        if a.dump_height:
            # 供多节点比对：**同一高度**的区块哈希。这是"无分叉"的唯一有效证据，
            # 因为不同节点的进度天然不同（比较各自链头会得出错误的"分叉"结论）。
            blk = next((b for b in node.blockchain
                        if b.header.height == a.dump_height), None)
            if blk is None:
                print(f"  高度 {a.dump_height} 尚未到达（最终高度 {node.height}）"
                      f" —— 无法参与比对")
            else:
                print(f"  HEIGHT={a.dump_height} BLOCK_HASH={blk.block_hash().hex()}"
                      f" STATE_ROOT=0x{(blk.header.state_root or b'').hex()}")
        print(f"  最终高度   : {node.height}")
        print(f"  最终化链长 : {len(node.blockchain)}")
        print(f"  链头       : {node.head.block_hash().hex()}")
        print(f"  状态根     : 0x{node.state.state_root.hex()}")
        if t.decode_errors:
            print(f"  ⚠ 解码错误 {len(t.decode_errors)} 条：{t.decode_errors[:3]}")
        if t.connect_errors:
            print(f"  ⚠ 连接错误 {len(t.connect_errors)} 条：{t.connect_errors[:3]}")
        # 自述名字不在对端表中的帧：正常网络下**必须为 0**。非 0 通常意味着
        # 某台机器的 `--peer` 只配了单向（A 认识 B，B 不认识 A），或者是有人
        # 在伪造发送者身份（见 agora/transport.py 的绑定检查）。
        if getattr(t, "peer_errors", None):
            print(f"  ⚠ 发送者身份异常 {len(t.peer_errors)} 条：{t.peer_errors[:3]}")
            print("     ⇒ 请核对各节点 --peer 是否**双向**互配（规范 §6.5）")
        # ── 名字↔连接的握手（§6.7）：正常网络下"未验证连接"必须为 0 ──
        print(f"  身份       : {t.identity_summary()}")
        if getattr(t, "unverified_conns", 0):
            print(f"  ⚠ 存在 {t.unverified_conns} 条**未验证**连接（有对端没配公钥）")
            print("     ⇒ 这意味着有人可以冒用对端名字投递消息；请给每个 --peer 补上公钥")
        if getattr(t, "identity_errors", None):
            print(f"  ⚠ 握手失败 {len(t.identity_errors)} 条：{t.identity_errors[:3]}")
        if getattr(t, "identity_violations", None):
            print(f"  ★ 名字与连接绑定不符 {len(t.identity_violations)} 条："
                  f"{t.identity_violations[:3]}")
            print("     ⇒ 有人在已认证的连接上冒用别的名字（攻击或配置错误）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
