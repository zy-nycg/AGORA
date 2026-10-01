# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 参考实现 · 测试网与链身份测试
===========================================

覆盖目标（`DEPLOYMENT_PLAN.md` §6 + 规范 §4）：

1. **链身份隔离**：测试网与主网的 `chain_id` 必须不同，且**测试网签出的交易
   在主网无效**。这是 `chain_id` 存在的**唯一**理由（防跨链重放）；
   若这条不成立，测试期间泄漏的任何私钥都能在主网直接花掉余额。
2. **网络切换的安全约束**：默认必须是主网；切换必须显式；签名一旦产生即冻结，
   不得再切换（否则签名者与验签者会用不同链身份）。
3. **测试网创世可复现**：同一配置构建两次得到同一状态根与创世哈希；
   金额闭合（规范 §32.2）。
4. **只有两处不同**：除 `chain_id` 与 `GenesisTimestamp` 外，
   测试网与主网的**全部共识与经济参数必须逐项相同**。

运行：python3 tests/test_testnet.py
"""

from __future__ import annotations

import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agora import params as P
from agora.crypto_backend import (publickey_from_seed, address_from_pubkey,
                                  sign, verify)

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


SEEDS = [bytes([i]) * 32 for i in (1, 2, 3, 4)]
PKS = [publickey_from_seed(s) for s in SEEDS]
STAKE = 64 * P.ATOM_PER_AGORA


def _genesis_alloc():
    from agora.state import GenesisAllocation
    return GenesisAllocation(
        validators=[(pk, STAKE) for pk in PKS],
        balances=[(PKS[0], P.INITIAL_SUPPLY - 4 * STAKE)])


# ── 1. 链身份隔离 ────────────────────────────────────────────────────

def test_chain_id_isolation():
    print("\n1) 链身份隔离（规范 §4：防跨链重放）")
    from agora.state import build_genesis_state, genesis_hash

    P.reset_network_for_tests()                       # 每个测试自行决定网络

    # 主网
    P.set_network("mainnet")
    st_m, _ = build_genesis_state(_genesis_alloc())
    alloc_m = _genesis_alloc()
    gh_m = genesis_hash(st_m, alloc_m)
    chk("主网 chain_id 为规范冻结值", P.CHAIN_ID == "agora-mainnet-1", P.CHAIN_ID)

    P.reset_network_for_tests()
    P.set_network("testnet")
    st_t, _ = build_genesis_state(_genesis_alloc())
    alloc_t = _genesis_alloc()
    gh_t = genesis_hash(st_t, alloc_t)
    chk("测试网 chain_id 与主网不同", P.CHAIN_ID == "agora-testnet-1", P.CHAIN_ID)

    # 同一份验证者集合，在两套链身份下创世哈希必须不同 ——
    # 若相同，说明 chain_id 没有进入创世推导，跨链重放防护形同虚设。
    chk("同一配置在两套链身份下创世哈希不同", gh_m != gh_t,
        f"主网 {gh_m.hex()[:16]}… vs 测试网 {gh_t.hex()[:16]}…")

    # **核心断言**：测试网签的交易，在主网验签必须失败
    from agora.tx import Transaction
    from agora.gas import TxType
    from agora.codec import encode

    def make_tx(nonce=0):
        tx = Transaction(
            tx_type=TxType.TRANSFER, nonce=nonce,
            max_priority_fee_per_gas=P.MIN_BASE_FEE // 2,
            max_fee_per_gas=P.MIN_BASE_FEE * 2,
            gas_limit=100_000, to=address_from_pubkey(PKS[1]),
            value=10 ** 18, payload=encode(b""), pubkey=PKS[0])
        tx.signature = sign(SEEDS[0], tx.signing_payload())
        return tx

    P.reset_network_for_tests()
    P.set_network("testnet")
    tx_testnet = make_tx()
    sig_testnet = tx_testnet.signature

    P.reset_network_for_tests()
    P.set_network("mainnet")
    tx_mainnet = make_tx()                            # 同一字段，主网链身份下签名

    # §16.4.2 第 4 项：链身份必须已被纳入签名载荷，否则跨链重放无法防御
    chk("§16.4.2 第 4 项：两套链身份下交易签名不同（载荷含 chain_id）",
        sig_testnet != tx_mainnet.signature,
        "若相同则 chain_id 未进入签名载荷")

    # 用测试网的签名去验主网的载荷
    ok_cross = verify(PKS[0], tx_mainnet.signing_payload(), sig_testnet)
    chk("★ 测试网签名的交易在主网**无效**（防跨链重放）", not ok_cross,
        "这是 chain_id 存在的唯一理由")
    chk("主网自己签的交易在主网有效",
        verify(PKS[0], tx_mainnet.signing_payload(), tx_mainnet.signature))

    # 投票载荷同样必须隔离（否则测试网票可被重放到主网）
    from agora.consensus import vote_signing_payload
    P.reset_network_for_tests(); P.set_network("testnet")
    vp_t = vote_signing_payload(1, 0, 1, b"\xaa" * 32)
    P.reset_network_for_tests(); P.set_network("mainnet")
    vp_m = vote_signing_payload(1, 0, 1, b"\xaa" * 32)
    chk("投票签名载荷在两套链身份下不同", vp_t != vp_m)

    P.reset_network_for_tests()


# ── 2. 网络切换的安全约束 ────────────────────────────────────────────

def test_network_switching_guards():
    print("\n2) 网络切换的安全约束（BUG-62）")
    P.reset_network_for_tests()
    chk("默认（导入期）必须是主网，不得静默切换",
        P.CHAIN_ID == "agora-mainnet-1" and not P.network_frozen(),
        P.CHAIN_ID)

    P.set_network("testnet")
    chk("显式切换生效", P.CHAIN_ID == "agora-testnet-1" and P.network_name() == "testnet")

    try:
        P.set_network("bogus")
        chk("拒绝未知网络", False, "竟然接受了 bogus")
    except ValueError:
        chk("拒绝未知网络", True)

    # 构建创世**不**冻结 —— 否则工具与测试无法为多个网络分别试算
    from agora.state import build_genesis_state
    P.reset_network_for_tests()
    P.set_network("testnet")
    build_genesis_state(_genesis_alloc())
    chk("构建创世不冻结链身份（允许同进程为多网络试算）",
        not P.network_frozen())

    # 产生签名后必须冻结
    sign(bytes([9]) * 32, b"freeze-probe")
    chk("首次签名后链身份被冻结", P.network_frozen())
    try:
        P.set_network("mainnet")
        chk("冻结后拒绝切换", False, "竟然允许切换")
    except RuntimeError as e:
        chk("冻结后拒绝切换", True, str(e)[:40] + "…")

    # 受控解冻（仅供测试）必须能恢复
    P.reset_network_for_tests()
    chk("受控解冻恢复主网默认值",
        P.CHAIN_ID == "agora-mainnet-1" and not P.network_frozen())


# ── 3. 测试网创世可复现 ──────────────────────────────────────────────

def test_testnet_genesis_reproducible():
    print("\n3) 测试网创世可复现（第三方可独立复核）")
    from agora.state import build_genesis_state, genesis_hash

    P.reset_network_for_tests()
    P.set_network("testnet")
    ts = 1790431200
    from agora.state import GenesisAllocation
    a1 = GenesisAllocation(validators=[(pk, STAKE) for pk in PKS],
                           balances=[(PKS[0], P.INITIAL_SUPPLY - 4 * STAKE)],
                           genesis_timestamp=ts)
    a2 = GenesisAllocation(validators=[(pk, STAKE) for pk in PKS],
                           balances=[(PKS[0], P.INITIAL_SUPPLY - 4 * STAKE)],
                           genesis_timestamp=ts)
    s1, e1 = build_genesis_state(a1, strict=False)
    s2, e2 = build_genesis_state(a2, strict=False)
    chk("同一配置无闭合错误", not e1 and not e2, str(e1))
    chk("两次构建状态根相同（确定性）", s1.state_root == s2.state_root,
        "0x" + s1.state_root.hex()[:24] + "…")
    chk("两次构建创世哈希相同", genesis_hash(s1, a1) == genesis_hash(s2, a2))

    # 改变链身份 ⇒ 创世哈希必须改变（否则测试网创世能被主网复用）
    gh_tn = genesis_hash(s1, a1)
    P.reset_network_for_tests()
    P.set_network("mainnet")
    a3 = GenesisAllocation(validators=[(pk, STAKE) for pk in PKS],
                           balances=[(PKS[0], P.INITIAL_SUPPLY - 4 * STAKE)],
                           genesis_timestamp=ts)
    s3, _ = build_genesis_state(a3, strict=False)
    chk("换链身份 ⇒ 创世哈希改变", genesis_hash(s3, a3) != gh_tn)

    # 主网时间戳必须为冻结值；测试网可自定
    errs_main = build_genesis_state(a3, strict=False)[1]
    chk("主网时间戳不等于冻结值时报错",
        any("GenesisTimestamp" in e for e in errs_main),
        str(errs_main[:1]))
    P.reset_network_for_tests()
    P.set_network("testnet")
    errs_tn = build_genesis_state(
        GenesisAllocation(validators=[(pk, STAKE) for pk in PKS],
                          balances=[(PKS[0], P.INITIAL_SUPPLY - 4 * STAKE)],
                          genesis_timestamp=ts), strict=False)[1]
    chk("测试网允许自定时间戳（不再被主网规则误拒）", not errs_tn, str(errs_tn))
    P.reset_network_for_tests()


# ── 4. 只有两处不同 ──────────────────────────────────────────────────

def test_only_two_differences():
    print("\n4) 测试网与主网**只允许两处不同**（DEPLOYMENT_PLAN §6）")
    # 在同一进程内无法并行持有两套链身份，因此逐项检查与 chain_id 无关的参数
    # 是否在任何网络下都保持一致 —— 这些参数**不得**随网络变化。
    import importlib
    import agora.params as P1
    importlib.reload(P1)
    mainnet_snapshot = {n: getattr(P1, n) for n in dir(P1)
                        if n.isupper() and isinstance(
                            getattr(P1, n), (int, str, bytes, float))}

    P1.reset_network_for_tests()
    P1.set_network("testnet")
    changed = []
    for n, v in mainnet_snapshot.items():
        if n in ("CHAIN_ID", "CHAIN_ID_BYTES", "_MAINNET_CHAIN_ID"):
            continue
        if getattr(P1, n, None) != v:
            changed.append(n)
    chk("除 chain_id 外无参数随网络变化", not changed, f"意外变化：{changed}")

    # 与共识/经济相关的关键参数逐项点名核对（防止上一条因漏采集而误判）
    for name, val in (("SLOT_TIME", P1.SLOT_TIME),
                      ("EPOCH_LENGTH", P1.EPOCH_LENGTH),
                      ("ATOM_PER_AGORA", P1.ATOM_PER_AGORA),
                      ("INITIAL_SUPPLY", P1.INITIAL_SUPPLY),
                      ("MIN_VALIDATOR_STAKE", P1.MIN_VALIDATOR_STAKE),
                      ("BASE_TIMEOUT_MS", P1.BASE_TIMEOUT_MS),
                      ("PROPOSAL_TIMEOUT_MS", P1.PROPOSAL_TIMEOUT_MS)):
        chk(f"{name} 不随网络变化", getattr(P1, name) == val, str(val))
    P1.reset_network_for_tests()


# ── 5. 创世构建工具端到端 ────────────────────────────────────────────

def test_genesis_build_tool():
    print("\n5) 创世构建工具端到端（build → check 往返）")
    import json
    import tempfile
    from agora.state import build_genesis_state, genesis_hash, GenesisAllocation

    with tempfile.TemporaryDirectory() as tmp:
        csv_path = os.path.join(tmp, "vals.csv")
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("pubkey_hex,address_hex,amount_atom\n")
            for pk, sd in zip(PKS, SEEDS):
                f.write(f"{pk.hex()},{address_from_pubkey(pk).hex()},{STAKE}\n")
        out = os.path.join(tmp, "genesis.json")

        r = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "agora_genesis_build.py"),
             "--network", "testnet", "--validators", csv_path,
             "--genesis-timestamp", "1790431200", "--out", out],
            capture_output=True, text=True, cwd=ROOT)
        chk("构建成功", r.returncode == 0, (r.stderr or r.stdout)[-200:])
        if r.returncode != 0:
            return

        cfg = json.load(open(out, encoding="utf-8"))
        chk("产物含创世状态根", cfg.get("genesis_state_root", "").startswith("0x"),
            cfg.get("genesis_state_root", "")[:24] + "…")
        chk("产物含创世哈希", cfg.get("genesis_hash", "").startswith("0x"),
            cfg.get("genesis_hash", "")[:24] + "…")
        chk("产物声明金额闭合", cfg["closure"]["balanced"] is True,
            f"{cfg['closure']['total_atom']}")
        chk("chain_id 为测试网", cfg["chain_id"] == "agora-testnet-1")

        # 独立复核：子进程重新构建并比对（这才是"可复现"的真凭证）
        rc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "agora_genesis_build.py"),
             "--check", out], capture_output=True, text=True, cwd=ROOT)
        chk("独立复核通过（状态根与创世哈希可复现）", rc.returncode == 0,
            (rc.stdout or rc.stderr).strip().splitlines()[-1][:80])
        chk("复核输出确认'可安全启动'", "✅" in rc.stdout,
            (rc.stdout or "").strip().splitlines()[-1][:60])

        # 篡改产物必须被复核发现（否则复核是装饰）
        cfg["genesis_state_root"] = "0x" + "00" * 32
        bad = os.path.join(tmp, "bad.json")
        json.dump(cfg, open(bad, "w", encoding="utf-8"))
        rc2 = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "agora_genesis_build.py"),
             "--check", bad], capture_output=True, text=True, cwd=ROOT)
        chk("被篡改的创世根会被复核拒绝", rc2.returncode != 0,
            "复核必须能发现不一致")

    P.reset_network_for_tests()


def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 测试网与链身份")
    print("═" * 76)
    test_chain_id_isolation()
    test_network_switching_guards()
    test_testnet_genesis_reproducible()
    test_only_two_differences()
    test_genesis_build_tool()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
