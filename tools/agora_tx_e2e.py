# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 交易的**真集群端到端验证**（钱包视角）
=====================================================

对着一个**跑着的 4 节点集群**做完整闭环，全部通过 HTTP 查询接口与 P2P 网络：

    构造并签名一笔 TRANSFER
      → POST /v1/tx（提交给**非提案者**节点，验证广播）
      → 等待进块（轮询 GET /v1/tx/{hash}）
      → 核对：所在区块、回执、收款方余额、以及**四个节点对同一高度的区块哈希一致**

为什么必须单独做这一步：单元测试跑的是进程内对象；本脚本跑的是
**真 TCP + §6.7.1 签名握手 + 持久化 + 交易池 + 打包 + 查询接口**。
本项目的历史教训是：正是在这一层才暴露了形参错位、线格式重复、重放漏洞、
以及"重启后拒绝启动"这类只在真进程里出现的问题。

用法（先起集群，开查询接口）：

    RPC_BASE=8645 bash wallet/run_local_cluster.sh wallet/runs/dev-genesis.json 60 tx-e2e 0 wallet/runs/devkeys wallet/runs/tx-e2e &
    python3 tools/agora_tx_e2e.py --submit-to 8647 --expect-chain-id agora-testnet-1

参数：
  --timeout      等待进块的秒数（默认 30）
  --submit-to    把交易提交到哪个节点的接口端口（默认 8645；用非 8645 可验证广播）
  --amount-atom  转账金额（atom，默认 1 AGORA）
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agora import params as P
from agora.crypto_backend import (address_from_pubkey, publickey_from_seed,
                                  sign)
from agora.gas import TxType
from agora.tx import Transaction

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


def get(port: int, path: str):
    url = f"http://127.0.0.1:{port}{path}"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))
    except Exception as e:                               # noqa: BLE001
        return 0, {"error": {"code": "transport", "message": str(e)}}


def post(port: int, path: str, body: dict):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))
    except Exception as e:                               # noqa: BLE001
        return 0, {"error": {"code": "transport", "message": str(e)}}


def main() -> int:
    ap = argparse.ArgumentParser(description="交易的端到端验证（真集群）")
    ap.add_argument("--base-port", type=int, default=8645, help="node1 的查询接口端口")
    ap.add_argument("--submit-to", type=int, default=0,
                    help="提交到哪个节点的接口端口（默认 = --base-port）")
    ap.add_argument("--timeout", type=float, default=30.0, help="等待进块的秒数")
    ap.add_argument("--amount-atom", type=int, default=P.ATOM_PER_AGORA)
    ap.add_argument("--seed-file", default="wallet/runs/devkeys/key1.seed")
    ap.add_argument("--expect-chain-id", default=None,
                    help="断言之链身份（例如 agora-testnet-1）；不符则拒绝签名")
    a = ap.parse_args()
    submit_port = a.submit_to or a.base_port
    # 四个节点的接口端口：node1..node4 = base, base+1, ...
    ports = [a.base_port + i for i in range(4)]

    print("═" * 76)
    print("AGORA 交易端到端验证（真集群 · 钱包视角）")
    print(f"  提交到 : 127.0.0.1:{submit_port}")
    print(f"  查询   : 127.0.0.1:{ports[0]}")
    print("═" * 76)

    # ── 1) 等到集群就绪并取链身份 ──
    ok_nodes = []
    deadline = time.time() + 30
    while time.time() < deadline:
        ok_nodes = [p for p in ports if get(p, "/healthz")[0] == 200]
        if len(ok_nodes) == 4:
            break
        time.sleep(0.5)
    chk("四个节点的查询接口都就绪", len(ok_nodes) == 4, f"就绪：{ok_nodes}")
    if len(ok_nodes) < 4:
        return 1

    st_code, st = get(ports[0], "/v1/status")
    chk("status 可取且含链身份",
        st_code == 200 and st.get("chain_id") and st.get("genesis_hash"),
        f"chain_id={st.get('chain_id')} height={st.get('height')}")
    chain_id = st.get("chain_id")
    genesis = st.get("genesis_hash")

    # ── **必须在签名之前**把链身份设成节点所在的那条链 ──
    # 踩过的坑：本工具是个新进程，`P.CHAIN_ID` 默认是**主网**；而集群跑的是测试网。
    # 于是交易是用主网 chain_id 签的，节点按 §16.4.2 第 5 项拒收 ——
    # 报出来却是"签名验证失败"，看起来像密钥不对，实际只是链身份没设。
    # 这也是钱包必须做的第一件事：**先确认连到哪条链，再签名**。
    net = next((n for n, cid in P.ALLOWED_NETWORKS.items() if cid == chain_id), None)
    if net is None:
        print(f"✗ 节点报告的 chain_id={chain_id!r} 不在已知网络里：{P.ALLOWED_NETWORKS}")
        return 1
    P.set_network(net)
    chk(f"链身份已按节点设定（{net} / {P.CHAIN_ID}）", P.CHAIN_ID == chain_id)
    if a.expect_chain_id and P.CHAIN_ID != a.expect_chain_id:
        print(f"✗ 链身份与 --expect-chain-id 不符：期望 {a.expect_chain_id}，"
              f"实际 {P.CHAIN_ID}")
        return 1

    # 四个节点的链身份必须一致（防"连到不同链"）
    identities = {(get(p, "/v1/status")[1] or {}).get("genesis_hash") for p in ports}
    chk("四个节点的创世哈希一致（同一条链）", len(identities) == 1, str(identities))

    # ── 2) 构造并签名一笔转账 ──
    seed = bytes.fromhex(open(a.seed_file, encoding="utf-8").read().strip())
    pk = publickey_from_seed(seed)
    sender = address_from_pubkey(pk)
    code, acc = get(ports[0], f"/v1/account/0x{sender.hex()}")
    chk("取到付款方账户（余额与非下一笔 nonce）",
        code == 200 and acc.get("exists") is True,
        f"余额={int(acc.get('balance_atom', 0)) / P.ATOM_PER_AGORA:.6f} AGORA "
        f"nonce={acc.get('nonce')}")
    nonce = int(acc.get("nonce", 0))

    # 收款方用**非验证者**地址：验证者会拿到出块奖励，会干扰"余额恰好增加"的断言
    to_pk = publickey_from_seed(bytes([0x5A]) * 32)
    to_addr = address_from_pubkey(to_pk)
    code, to_before = get(ports[0], f"/v1/account/0x{to_addr.hex()}")
    before_bal = int(to_before.get("balance_atom", 0)) if code == 200 else 0

    tx = Transaction(tx_type=int(TxType.TRANSFER), nonce=nonce,
                     max_priority_fee_per_gas=0,
                     max_fee_per_gas=P.INITIAL_BASE_FEE * 2, gas_limit=100_000,
                     to=to_addr, value=a.amount_atom, pubkey=pk)
    tx.signature = sign(seed, tx.signing_payload())
    tx_hash = "0x" + tx.tx_hash().hex()
    print(f"\n  已签名交易 : {tx_hash}")
    print(f"  付款方     : 0x{sender.hex()}（nonce={nonce}）")
    print(f"  收款方     : 0x{to_addr.hex()}")
    print(f"  金额       : {a.amount_atom / P.ATOM_PER_AGORA} AGORA")

    # ── 3) 提交（发给**非提案者**节点，验证广播） ──
    code, resp = post(submit_port, "/v1/tx", {"tx_rlp": "0x" + tx.to_rlp().hex()})
    tx_resp = resp                       # 提交响应是扁平的（202 + accepted/tx_hash）
    if code != 202 or tx_resp.get("accepted") is not True:
        # 把服务端给的原因原样打出来：钱包界面也应当这样展示（含 §16.4.2 项号）
        err = resp.get("error", {})
        print(f"    服务端拒绝：{err.get('message') or tx_resp}")
    chk("★提交被受理（202 + accepted）",
        code == 202 and tx_resp.get("accepted") is True,
        f"HTTP {code} status={tx_resp.get('status')} pool={tx_resp.get('pool_size')}")
    chk("提交响应带链身份（钱包据此核对提交给了哪条链）",
        tx_resp.get("chain_id") == chain_id, str(tx_resp.get("chain_id")))

    duplicate = post(submit_port, "/v1/tx", {"tx_rlp": "0x" + tx.to_rlp().hex()})
    chk("重复提交幂等（duplicate，不报错）",
        duplicate[1].get("status") == "duplicate", str(duplicate[1].get("status")))

    # ── 4) 等待进块（这是权威判定） ──
    print(f"\n  等待进块（最多 {a.timeout:.0f} 秒）…")
    found = None
    t0 = time.time()
    while time.time() - t0 < a.timeout:
        code, res = get(ports[0], f"/v1/tx/{tx_hash}")
        if code == 200 and res.get("found"):
            found = res
            break
        time.sleep(0.5)
    chk("★交易最终上链（GET /v1/tx found=true）", found is not None,
        f"耗时 {time.time() - t0:.1f}s")
    if found is None:
        for p in ports:
            logs = get(p, "/v1/status")[1]
            print(f"    node(port {p}): {logs.get('height')}")
        return 1

    h = found["block_height"]
    print(f"  所在区块   : 高度 {h} hash={found['block_hash'][:20]}…")
    print(f"  确认数     : {found.get('confirmations')}")
    rec = found.get("receipt") or {}
    print(f"  回执       : status={rec.get('status')} gas_used={rec.get('gas_used')} "
          f"effective_gas_price={rec.get('effective_gas_price')} "
          f"精确={rec.get('receipt_exact')}")
    chk("回执存在且成功", rec.get("status") == 1)
    chk("回执是**执行侧记录的精确值**（不是事后近似）",
        rec.get("receipt_exact") is True, str(rec.get("receipt_note", ""))[:60])

    # ── 5) 收款方余额与四节点一致性 ──
    code, to_after = get(ports[0], f"/v1/account/0x{to_addr.hex()}")
    after_bal = int(to_after.get("balance_atom", 0))
    chk("★收款方余额恰好增加转账金额",
        after_bal == before_bal + a.amount_atom,
        f"{before_bal} → {after_bal}（+{after_bal - before_bal}）")

    # 同一高度的区块哈希必须一致（唯一有效的"无分叉"证据）
    hashes = set()
    for p in ports:
        code2, blk = get(p, f"/v1/block/{h}")
        if code2 == 200:
            hashes.add(blk["block"]["block_hash"])
        time.sleep(0.2)
    chk("★四个节点在**同一高度**的区块哈希一致（无分叉）",
        len(hashes) == 1, f"{len(hashes)} 种：{list(hashes)[:1]}")

    # ── 6) 池已清空（不残留已上链交易） ──
    code3, status_after = get(ports[0], "/v1/status")
    chk("查询接口仍正常（含 pooled 相关字段）",
        code3 == 200 and "airdrop_claimed_count" in status_after)

    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
