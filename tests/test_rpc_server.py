# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 只读查询接口的测试（`tools/agora_rpc_server.py`）
================================================================

这个接口是**钱包与浏览器唯一的数据入口**，因此它的契约必须被测试钉住。
本文件盯住四类事（每一类都对应一个真实风险）：

1. **信封与新鲜度**：每个响应都带 `chain_id` / `genesis_hash` / `height` /
   状态根 —— 钱包据此判断"是不是同一条链""数据有多旧"；
2. **金额是字符串**：`*_atom` 字段必须是**十进制字符串**。
   一旦变成 JSON number，Dart/JS 的 double 会在 2^53 以上静默丢精度 ——
   界面显示"余额正常"，转账却算错。这是本接口最重要的一条契约；
3. **错误结构化**：400/404/501 各自返回带 `code`/`message`/`detail` 的 JSON，
   而不是 HTML 或空响应；查不到**不是**故障（404 而非 500）；
4. **诚实报告缺口**：交易提交必须明确 501 并说明缺什么，
   **绝不能**返回"已受理"然后什么都不做（那会让用户以为钱转出去了）。

另外验证并发安全：HTTP 线程读状态、节点线程改状态 —— 两者共用一把锁，
因此"边出块边查询"不得出现异常或读到不一致的响应。

运行：python3 tests/test_rpc_server.py
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agora import params as P
from agora.node import NetworkConfig, Simulation
from tools.agora_rpc_server import AgoraRpcServer, NodeProvider

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


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _get(url: str):
    """返回 `(status, json)`；4xx/5xx 也返回，不抛异常。"""
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _post(url: str, body: dict):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def main() -> int:
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 只读查询接口（钱包/浏览器数据入口）")
    print("═" * 76)

    # ── 起一条小链（4 节点仿真，跑到高度 3）──
    sim = Simulation(4, NetworkConfig(latency=1, seed=11))
    sim.drive(target=3)
    node = sim.nodes["node1"]
    gen_hash = sim.genesis_block.block_hash()
    lock = threading.RLock()
    provider = NodeProvider(node, gen_hash, {"network": "testnet"}, lock=lock,
                            genesis_block=sim.genesis_block)
    app = AgoraRpcServer(provider)

    print("\n1) 信封与新鲜度（钱包据此判断「是不是同一条链」）")
    st = app.get_status()
    assert P.ATOM_PER_AGORA > 0
    for key in ("chain_id", "protocol_version", "genesis_hash", "height",
                "head_hash", "state_root"):
        chk(f"status 含 {key}", key in st and st[key] is not None)
    chk("genesis_hash 是 32 字节十六进制",
        len(st["genesis_hash"]) == 66 and st["genesis_hash"].startswith("0x"))
    chk("height 与节点一致", st["height"] == node.height, f"{st['height']}")
    chk("空投字段齐备（窗口/根/已领数）",
        all(k in st for k in ("airdrop_root", "airdrop_claimed_count",
                              "airdrop_pending_atom")))
    chk("明确标注信任模型（未做客户端密码学校验）", "trust_model" in st)

    print("\n2) 金额契约：`*_atom` 必须是十进制字符串（否则 double 丢精度）")
    addr = node.head.header.proposer.hex()
    acc = app.get_account(addr)
    chk("balance_atom 是 str（不是 int/float）",
        isinstance(acc["balance_atom"], str), repr(acc["balance_atom"])[:40])
    chk("balance_atom 是纯十进制整数", acc["balance_atom"].isdigit())
    chk("nonce 是 JSON number（小整数）", isinstance(acc["nonce"], int))
    chk("账户不存在时是 exists=false + 余额 0（不是 404）",
        app.get_account("0x" + "77" * 20)["exists"] is False)
    vs = app.get_validators()
    chk("验证者金额字段同样是字符串",
        all(isinstance(v["effective_stake_atom"], str) for v in vs["validators"]))
    chk("法定数 = ceil(2S/3)",
        int(vs["quorum_atom"]) == -(-2 * int(vs["staked_supply_atom"]) // 3),
        f"S={vs['staked_supply_atom']} QUORUM={vs['quorum_atom']}")

    print("\n2b) 每个可核对端点都必须带齐信封（含 /v1/params）")
    pj = app.get_params()
    for key in ("chain_id", "protocol_version", "genesis_hash", "height",
                "head_hash", "state_root"):
        chk(f"params 含 {key}（否则钱包无法核对链身份）", key in pj)
    chk("params 的信封与 status 一致",
        pj["genesis_hash"] == st["genesis_hash"] and pj["chain_id"] == st["chain_id"])

    print("\n3) 区块与交易")
    blk = app.get_block("latest")["block"]
    for key in ("height", "block_hash", "parent_hash", "state_root", "tx_root",
                "receipt_root", "claimed_slot", "timestamp", "gas_used"):
        chk(f"block 含 {key}", key in blk)
    chk("按高度取回的块与 latest 一致",
        app.get_block(str(blk["height"]))["block"]["block_hash"] == blk["block_hash"])
    chk("按哈希取回的块与 latest 一致",
        app.get_block(blk["block_hash"])["block"]["block_hash"] == blk["block_hash"])
    chk("创世块（高度 0）也能取到", app.get_block("0")["block"]["height"] == 0)
    tx = app.get_tx("0x" + "11" * 32)
    chk("未知交易返回 found=false（不是错误）", tx["found"] is False)
    chk("未找到时**顶层** tx_hash 仍是查询键（客户端据此对账）",
        tx.get("tx_hash") == "0x" + "11" * 32, str(tx.get("tx_hash")))

    print("\n4) 空投：证明必须来自分配表；没有表时必须说明原因")
    ad = app.get_airdrop(addr)
    chk("未加载分配表时 eligible=false 且**给出可读原因**",
        ad["eligible"] is False and "分配表" in ad.get("reason", ""),
        ad.get("reason", "")[:40])
    chk("仍然返回窗口与金库余额（界面可展示）",
        "claim_window" in ad and "vault_balance_atom" in ad)
    chk("窗口边界取自参数（不硬编码）",
        ad["claim_window"]["start_slot"] == 0
        and ad["claim_window"]["end_slot"] > 0)

    print("\n5) 交易提交：受理 → 广播 → 进块 → 可查询（§16.5 端到端）")
    try:
        app.post_tx({})
        chk("空请求体必须被拒", False, "竟然接受")
    except Exception as e:                                # noqa: BLE001
        chk("空请求体必须被拒（400 + missing_tx_rlp）",
            getattr(e, "code", "") == "missing_tx_rlp", str(e)[:60])
    try:
        app.post_tx({"tx_rlp": "0xdeadbeef"})
        chk("畸形 RLP 必须被拒（400 + bad_tx_rlp）", False, "竟然接受了交易")
    except Exception as e:                                # noqa: BLE001
        chk("畸形 RLP 必须被拒（400 + bad_tx_rlp）",
            getattr(e, "status", None) == 400
            and getattr(e, "code", "") == "bad_tx_rlp", str(e)[:70])
    try:
        app.post_tx({"tx_rlp": "0xzz"})
        chk("非十六进制必须被拒（400 + bad_tx_rlp）", False, "竟然接受")
    except Exception as e:                                # noqa: BLE001
        chk("非十六进制必须被拒（400 + bad_tx_rlp）",
            getattr(e, "code", "") == "bad_tx_rlp")

    # ── 端到端：造一笔**已签名**的转账，提交 → 广播 → 进块 → 查询 ──
    print("\n5b) 端到端：提交一笔已签名转账，并在真链上查到它")
    from agora.crypto_backend import address_from_pubkey, publickey_from_seed, sign
    from agora.gas import TxType
    from agora.tx import Transaction

    sender_seed = sim.seeds[0]
    sender_pk = sim.pubkeys[0]
    sender_addr = address_from_pubkey(sender_pk)
    # **收款方必须是非验证者**：验证者会因为出块签名拿到发行奖励，
    # 用它做收款方时"余额增量 = 转账额"这条断言必然不成立（首版就踩了这个坑，
    # 实测多出 0.512 AGORA —— 那正是区块奖励，不是转账）。
    # 用一个全新的地址还顺带覆盖了"新建账户"路径（gas 46,000 而非 21,000）。
    to_pk = publickey_from_seed(bytes([0xEE]) * 32)
    to_addr = address_from_pubkey(to_pk)
    before_to = node.state.get_account(to_addr)
    before_to_bal = before_to.balance if before_to else 0
    chk("前置：收款方是一个尚未存在的新账户（覆盖新建账户路径）",
        before_to is None, f"余额={before_to_bal}")

    tx = Transaction(tx_type=int(TxType.TRANSFER), nonce=0,
                     max_priority_fee_per_gas=0,
                     max_fee_per_gas=P.INITIAL_BASE_FEE * 2,
                     gas_limit=100_000, to=to_addr, value=P.ATOM_PER_AGORA,
                     pubkey=sender_pk)
    tx.signature = sign(sender_seed, tx.signing_payload())
    rlp_hex = "0x" + tx.to_rlp().hex()
    tx_hash = tx.tx_hash()

    res = app.post_tx({"tx_rlp": rlp_hex})
    chk("提交被受理（accepted=true / status=queued）",
        res["accepted"] is True and res["status"] == "queued",
        f"tx_hash={res['tx_hash'][:18]}… pool={res['pool_size']}")
    chk("提交响应带链身份（钱包据此核对提交给了哪条链）",
        res.get("chain_id") == P.CHAIN_ID)
    chk("响应里明确提示「以链上查询为准」", "GET /v1/tx" in res.get("note", ""))

    dup = app.post_tx({"tx_rlp": rlp_hex})
    chk("重复提交是幂等的（status=duplicate，不报错）",
        dup["accepted"] is False and dup["status"] == "duplicate")

    # ① 队列语义：**适度超前**的 nonce 应当被受理（等前序交易到齐再打包），
    #    但**绝不会**在断档未填时被选中（选它会让整块无效）。
    from agora.mempool import MAX_NONCE_GAP
    t_queued = Transaction(tx_type=int(TxType.TRANSFER), nonce=5,
                           max_priority_fee_per_gas=0,
                           max_fee_per_gas=P.INITIAL_BASE_FEE * 2,
                           gas_limit=100_000, to=to_addr, value=P.ATOM_PER_AGORA,
                           pubkey=sender_pk)
    t_queued.signature = sign(sender_seed, t_queued.signing_payload())
    r_q = app.post_tx({"tx_rlp": "0x" + t_queued.to_rlp().hex()})
    chk("适度超前的 nonce 入池排队（交易池是队列，不是「只能一笔」）",
        r_q["accepted"] is True and r_q["status"] == "queued",
        f"pool={r_q['pool_size']}")
    chk("但断档未填时不会被选中（否则整块无效）",
        all(t.tx_hash() != t_queued.tx_hash()
            for t in node.pool.select(node.state, P.INITIAL_BASE_FEE,
                                      node.estimated_slot)))
    node.pool.remove([t_queued.tx_hash()])                # 清掉，别影响后面的断言

    # ② 过于超前（超出深度上限）⇒ 直接拒绝（否则可被用来塞满池子）
    t_far = Transaction(tx_type=int(TxType.TRANSFER), nonce=MAX_NONCE_GAP + 10,
                        max_priority_fee_per_gas=0,
                        max_fee_per_gas=P.INITIAL_BASE_FEE * 2,
                        gas_limit=100_000, to=to_addr, value=P.ATOM_PER_AGORA,
                        pubkey=sender_pk)
    t_far.signature = sign(sender_seed, t_far.signing_payload())
    try:
        app.post_tx({"tx_rlp": "0x" + t_far.to_rlp().hex()})
        chk("nonce 过于超前（超出深度上限）⇒ 400 + tx_rejected", False, "竟然接受")
    except Exception as e:                                # noqa: BLE001
        chk("nonce 过于超前（超出深度上限）⇒ 400 + tx_rejected",
            getattr(e, "code", "") == "tx_rejected"
            and "超前" in getattr(e, "message", ""),
            str(getattr(e, "message", e))[:60])

    # ③ 签名无效 ⇒ 400（并把 §16.4.2 的项号告诉钱包）
    t_sig = Transaction(tx_type=int(TxType.TRANSFER), nonce=0,
                        max_priority_fee_per_gas=0,
                        max_fee_per_gas=P.INITIAL_BASE_FEE * 2,
                        gas_limit=100_000, to=to_addr, value=P.ATOM_PER_AGORA,
                        pubkey=sender_pk)
    t_sig.signature = bytes(64)
    try:
        app.post_tx({"tx_rlp": "0x" + t_sig.to_rlp().hex()})
        chk("签名无效 ⇒ 400 + tx_rejected（含项号）", False, "竟然接受")
    except Exception as e:                                # noqa: BLE001
        chk("签名无效 ⇒ 400 + tx_rejected（含项号）",
            getattr(e, "code", "") == "tx_rejected"
            and "第 5 项" in getattr(e, "message", ""),
            str(getattr(e, "message", e))[:60])

    # 让它真上链：推进仿真（提案者从池/广播里取到它并打包）
    target = node.height + 3
    sim.drive(target=target)
    chk("链继续推进（打包交易不影响活性）", node.height >= target,
        f"高度={node.height}")

    found = app.get_tx("0x" + tx_hash.hex())
    chk("★交易最终上链：GET /v1/tx 查得到", found["found"] is True,
        f"found={found['found']} height={found.get('block_height')}")
    # 这一条是 Dart 客户端解析的前提：找到时**也必须**有顶层 tx_hash
    chk("找到时顶层 tx_hash 等于查询键（否则客户端解析会失败）",
        found.get("tx_hash") == "0x" + tx_hash.hex(), str(found.get("tx_hash")))
    if found["found"]:
        chk("回执存在且状态为成功",
            found["receipt"] is not None and found["receipt"]["status"] == 1,
            f"gas_used={found['receipt']['gas_used']}")
        chk("新建账户的交易 gas_used = 46,000（§17.1 的 G4 附加）",
            found["receipt"]["gas_used"] == 46_000,
            f"实际 {found['receipt']['gas_used']}")
        chk("确认数 > 0", (found.get("confirmations") or 0) > 0,
            f"confirmations={found.get('confirmations')}")
    acc_to = app.get_account(to_addr.hex())
    chk("收款方余额恰好增加 1 AGORA（不多不少）",
        int(acc_to["balance_atom"]) == before_to_bal + P.ATOM_PER_AGORA,
        f"{before_to_bal} → {acc_to['balance_atom']}")
    # 上链后**该交易**必须离开池子；池里允许有"别的、尚未轮到"的交易
    # （本例里那是我特意提交的 nonce=5 队列用例 —— 它还会被对端**转发回来**，
    #  所以"池必须完全为空"是个错误断言；真正的不变量是"已上链的不残留"）。
    from agora.tx import validate_tx as _vt
    stale = []
    for _h, _t in node.pool._txs.items():
        _acc = node.state.get_account(_t.sender)
        _n = _acc.nonce if _acc else 0
        if _t.nonce < _n:
            stale.append(_t.nonce)
    chk("交易池在上链后被清理（已上链的不残留、无过期 nonce 堆积）",
        tx_hash not in node.pool and not stale,
        f"{node.pool.summary()}；池内 nonce={sorted(t.nonce for t in node.pool._txs.values())}")

    print("\n6) HTTP 层：状态码与错误结构（真实 socket）")
    from tools.agora_rpc_server import serve_in_thread
    port = _free_port()
    srv, _th = serve_in_thread(provider, "127.0.0.1", port, quiet=True)
    base = f"http://127.0.0.1:{port}"
    try:
        s, b = _get(f"{base}/healthz")
        chk("GET /healthz → 200 且 {ok:true}", s == 200 and b.get("ok") is True)
        s, b = _get(f"{base}/v1/status")
        chk("GET /v1/status → 200 且信封完整",
            s == 200 and b["chain_id"] and b["height"] >= 0)
        s, b = _get(f"{base}/v1/account/0xzz")
        chk("坏地址 → 400 + code=bad_request",
            s == 400 and b["error"]["code"] == "bad_request", str(b)[:90])
        s, b = _get(f"{base}/v1/block/99999")
        chk("不存在的高度 → 404 + code=block_not_found（不是 500）",
            s == 404 and b["error"]["code"] == "block_not_found")
        s, b = _get(f"{base}/v1/nope")
        chk("未知路径 → 404 + code=not_found",
            s == 404 and b["error"]["code"] == "not_found")
        s, b = _post(f"{base}/v1/tx", {"tx_rlp": "0xdeadbeef"})
        chk("POST /v1/tx 畸形输入 → 400 + bad_tx_rlp",
            s == 400 and b["error"]["code"] == "bad_tx_rlp",
            str(b["error"]["message"])[:60])
        s, b = _post(f"{base}/v1/tx", {"nope": 1})
        chk("POST 缺字段 → 400",
            s == 400 and b["error"]["code"] == "missing_tx_rlp")
        s, b = _get(f"{base}/v1/params")
        chk("GET /v1/params → 200 且金额字段也是字符串",
            s == 200 and isinstance(b["atom_per_agora"], str)
            and b["chain_id"] == st["chain_id"])

        print("\n7) 并发：边出块边查询不得出错（HTTP 线程读 / 节点线程写）")
        errors = []

        def reader():
            for _ in range(12):
                try:
                    code_, body_ = _get(f"{base}/v1/account/{addr}")
                    if code_ != 200 or not isinstance(body_["balance_atom"], str):
                        errors.append(f"异常响应 {code_}")
                except Exception as e:                    # noqa: BLE001
                    errors.append(repr(e))

        threads = [threading.Thread(target=reader) for _ in range(3)]
        for t_ in threads:
            t_.start()
        sim.drive(target=6)                               # 同时继续出块
        for t_ in threads:
            t_.join()
        chk("并发查询期间零异常/零坏响应", not errors, str(errors[:2]))
        chk("查询期间链确实在推进", node.height >= 4, f"高度={node.height}")
    finally:
        srv.shutdown()
        srv.server_close()

    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
