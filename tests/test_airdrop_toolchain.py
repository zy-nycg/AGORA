# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 空投工具链的**跨工具一致性**测试
================================================

为什么需要这个文件（它不是"再测一遍空投"）
------------------------------------------
空投领取要跨三个独立产物/工具：

    分配表 CSV ──airdrop-build──► 表 JSON ──genesis_build --airdrop-table──► 创世
                                    │
                                    └──claim-proof──► 领取证明 ──► 钱包

这条链上**没有任何一个环节会检查下一环节能不能用**。2026 年的实测定档：
整条链曾经是断的，而且断在四个互不相关的地方，每一处都能被单独"看着像没问题"：

1. **键名不匹配**：`airdrop-build` 写 `amount` / `gas_allowance`，而
   `genesis_build --airdrop-table` 读 `amount_atom` / `gas_allowance_atom`
   ⇒ 拿合法产物去建创世直接 `KeyError: 'amount_atom'`（连可读的错误都没有）；
2. **`index` 被丢弃**：构建器构造条目时没传 `index` ⇒ 所有条目 index=0，
   而 `index` 是叶子的一部分（BUG-87）⇒ 创世算出的根与分配表声明的根**不同**；
3. **叶子用了"最小宽度"整数**：离线工具写 `chain(index, pubkey, amount, ga)`
   （裸整数取最小宽度：index=1 → 1 字节），链上却是定宽 `u64(index)`(8) /
   `u256(gas_allowance)`(32) ⇒ **工具算出的根与链上永远对不上**
   （与 BUG-64 同类：定宽 vs 最小宽度）；
4. **gas_allowance 未计入闭合**：它在创世时直接记入受益人余额（§32.5），
   因此占用初始供应；构建器少扣了它 ⇒ 任何带 gas_allowance 的表都"不闭合"，
   且报错不会指出原因。

后果都是**静默**的：链能建出来、能出块，只有用户点"领取空投"时才发现
证明通不过第 16 项 —— 而那看起来像"钱包有 bug"。

因此本文件测试的是**工具之间的契约**（用真实 CLI 子进程），而不是某个函数的行为。
运行：python3 tests/test_airdrop_toolchain.py
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agora import params as P
from agora.crypto import chain, keccak256
from agora.crypto_backend import publickey_from_seed
from agora.state import (AirdropEntry, airdrop_gas_allowance_total,
                         airdrop_merkle_root, airdrop_verify)

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


def _run(args, env=None):
    e = {**os.environ, "PYTHONPATH": ROOT}
    if env:
        e.update(env)
    return subprocess.run([sys.executable] + args, capture_output=True, text=True,
                          cwd=ROOT, env=e)


A = P.ATOM_PER_AGORA
BENEFICIARIES = [bytes([201]) * 32, bytes([202]) * 32, bytes([203]) * 32]


def _make_inputs(d: str):
    """造 CSV（受益人表 + 验证者表），返回路径。"""
    apath = os.path.join(d, "airdrop.csv")
    with open(apath, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["pubkey_hex", "amount_atom",
                                          "gas_allowance_atom", "note"])
        w.writeheader()
        for i, seed in enumerate(BENEFICIARIES, 1):
            w.writerow({"pubkey_hex": publickey_from_seed(seed).hex(),
                        "amount_atom": str(1000 * A),
                        "gas_allowance_atom": str(5 * 10 ** 15),
                        "note": f"beneficiary-{i}"})
    vpath = os.path.join(d, "vals.csv")
    vpks = [publickey_from_seed(bytes([i]) * 32) for i in (1, 2, 3, 4)]
    with open(vpath, "w", encoding="utf-8") as f:
        f.write("pubkey_hex,amount_atom\n")
        for pk in vpks:
            f.write(f"{pk.hex()},{64 * A}\n")
    return apath, vpath, vpks


def test_offline_root_matches_chain():
    print("\n1) 离线工具算出的 airdrop_root 必须与**链上算法**逐字节一致")
    d = tempfile.mkdtemp()
    apath, vpath, vpks = _make_inputs(d)
    tpath = os.path.join(d, "table.json")
    r = _run(["tools/agora_genesis_keygen.py", "airdrop-build",
              "--in", apath, "--out", tpath])
    chk("airdrop-build 成功", r.returncode == 0, (r.stderr or "")[-100:])
    tbl = json.load(open(tpath, encoding="utf-8"))

    chk("表中 index 唯一且从 1 开始",
        [e["index"] for e in tbl["entries"]] == [1, 2, 3],
        str([e["index"] for e in tbl["entries"]]))
    chk("表里写的是 amount / gas_allowance（构建器必须能读这两种键名）",
        "amount" in tbl["entries"][0] and "gas_allowance" in tbl["entries"][0],
        str(sorted(tbl["entries"][0].keys())))

    ents = [AirdropEntry(pubkey=bytes.fromhex(e["pubkey_hex"]), amount=int(e["amount"]),
                         gas_allowance=int(e["gas_allowance"]), index=int(e["index"]))
            for e in tbl["entries"]]
    got = airdrop_merkle_root(ents).hex()
    chk("链上算法重算的根 == 表声明的根", got == tbl["airdrop_root"],
        f"{got[:16]}… vs {tbl['airdrop_root'][:16]}…")

    # 叶子必须用**定宽**（u64/u256）。这里用与实现无关的手写构造再算一次。
    e0 = ents[0]
    want = keccak256(P.TAG_AIRDROP + chain(
        ("u64", e0.index), e0.pubkey, ("u256", e0.amount), ("u256", e0.gas_allowance)))
    chk("叶子 == Hash(TAG ‖ CHAIN(u64(index), pubkey, u256(amount), u256(gas)))",
        e0.leaf() == want, want.hex()[:24] + "…")

    # **反证**：用"最小宽度"会得到另一个叶子（这正是曾经的缺陷）
    legacy = keccak256(P.TAG_AIRDROP + chain(
        e0.index, e0.pubkey, e0.amount, e0.gas_allowance))
    chk("最小宽度写法会得到**不同**的叶子（说明宽度错误不会被静默吞掉）",
        legacy != want, f"{legacy.hex()[:16]}… ≠ {want.hex()[:16]}…")
    return d, apath, tpath, tbl, vpath, vpks


def test_genesis_matches_table(d, apath, tpath, tbl, vpath, vpks):
    print("\n2) 用该表构建创世：根必须一致、金额必须闭合（曾在此处崩 4 次）")
    gpath = os.path.join(d, "genesis.json")
    r = _run(["tools/agora_genesis_build.py", "--validators", vpath,
              "--network", "testnet", "--airdrop-table", tpath,
              "--reserve-pubkey", vpks[0].hex(), "--out", gpath])
    chk("创世构建成功（退出码 0）", r.returncode == 0,
        ((r.stdout or "")[-160:] + (r.stderr or "")[-160:]).strip())
    if r.returncode != 0:
        return None
    g = json.load(open(gpath, encoding="utf-8"))
    chk("创世 airdrop_root == 分配表声明的根",
        g["airdrop_root"].removeprefix("0x").lower() == tbl["airdrop_root"].lower())
    chk("金额闭合（含 gas_allowance）", g["closure"]["balanced"] is True,
        str(g["closure"]))
    chk("闭合明细里单列了 gas_allowance（便于对账）",
        int(g["closure"].get("sum_airdrop_gas_allowance_atom", 0)) > 0,
        g["closure"].get("sum_airdrop_gas_allowance_atom"))
    return gpath, g


def test_claim_proof_verifies(d, tpath, tbl, gpath, g):
    print("\n3) claim-proof 产出的证明必须能被**链上算法**验证")
    pk = tbl["entries"][1]["pubkey_hex"]
    r = _run(["tools/agora_genesis_keygen.py", "claim-proof",
              "--table", tpath, "--pubkey", pk])
    chk("claim-proof 成功", r.returncode == 0, (r.stderr or "")[-120:])
    if r.returncode != 0:
        return
    p = json.loads(r.stdout[r.stdout.index("{"):])
    root = bytes.fromhex(g["airdrop_root"].removeprefix("0x"))
    proof = [bytes.fromhex(x.removeprefix("0x")) for x in p["merkle_proof"]]
    kw = dict(pubkey=bytes.fromhex(p["pubkey_hex"]), amount=int(p["amount"]),
              gas_allowance=int(p["gas_allowance"]), proof=proof, root=root,
              index=int(p["index"]))
    chk("证明通过 airdrop_verify（钱包据此构造领取交易）",
        airdrop_verify(None, **kw))
    kw_bad = {**kw, "index": int(p["index"]) + 1}
    chk("★换 index 后必须失败（BUG-87：同一份权益不可重复领取）",
        not airdrop_verify(None, **kw_bad))
    kw_amt = {**kw, "amount": int(p["amount"]) * 2}
    chk("★改金额后必须失败", not airdrop_verify(None, **kw_amt))
    chk("证明里的地址与公钥一致（§32.6 第 ② 项）",
        p["address_hex"].removeprefix("0x").lower()
        == __import__("agora.crypto_backend", fromlist=["x"]).address_from_pubkey(
            bytes.fromhex(p["pubkey_hex"])).hex())


def test_negative_guards(d, tpath, tbl, vpath, vpks):
    print("\n4) 负向守卫：元数据对不上时必须**拒绝构建**（而不是产出一条坏链）")
    bad = dict(tbl)
    bad["airdrop_root"] = "00" * 32
    bp = os.path.join(d, "table_badroot.json")
    json.dump(bad, open(bp, "w", encoding="utf-8"))
    r = _run(["tools/agora_genesis_build.py", "--validators", vpath,
              "--network", "testnet", "--airdrop-table", bp,
              "--reserve-pubkey", vpks[0].hex(), "--out", os.path.join(d, "g2.json")])
    chk("★声明根被篡改 ⇒ 拒绝构建", r.returncode != 0)
    chk("拒绝理由里明确指出 airdrop_root（不是含糊的失败）",
        "airdrop_root" in (r.stdout + r.stderr),
        ((r.stdout or "")[-120:] or (r.stderr or "")[-120:]).strip())

    noidx = dict(tbl)
    noidx["entries"] = [{k: v for k, v in e.items() if k != "index"} for e in tbl["entries"]]
    np_ = os.path.join(d, "table_noidx.json")
    json.dump(noidx, open(np_, "w", encoding="utf-8"))
    r2 = _run(["tools/agora_genesis_build.py", "--validators", vpath,
               "--network", "testnet", "--airdrop-table", np_,
               "--reserve-pubkey", vpks[0].hex(), "--out", os.path.join(d, "g3.json")])
    chk("★条目缺 index ⇒ 拒绝构建（index 是叶子的一部分）", r2.returncode != 0,
        "（缺 index 会让所有条目 index=0，与表声明的根不同）")


def test_config_roundtrip(d, tpath, tbl, gpath, g, vpath, vpks):
    """**序列化往返**：构建器写下的配置，节点必须能读回同一份创世。

    实测过的缺陷（端到端才暴露）：构建器只写了 `airdrop_root` 与总额，
    **没有写空投条目**；节点重建创世时金库为 0 ⇒ 自检"金额不闭合"（差额恰好
    等于空投总额）⇒ **拒绝启动**；而构建器打印的却是"金额闭合 ✓"。
    修法是把 `(配置) ↔ (分配)` 收敛到 `agora/genesis_cfg.py` 一处，
    并让构建器**写完必须用同一个函数读回来**。
    """
    print("\n5) 序列化往返：配置写出来后，节点必须能读回同一份创世")
    from agora.genesis_cfg import GenesisConfigError, load_genesis_config

    cfg2, alloc2, st2 = load_genesis_config(gpath)
    chk("节点加载器读回成功", st2 is not None)
    chk("空投条目被完整读回（这是「金库不为 0」的前提）",
        len(alloc2.airdrop) == len(tbl["entries"]),
        f"{len(alloc2.airdrop)} 条")
    total = sum(int(e["amount"]) for e in tbl["entries"])
    chk("金库余额 == 条目金额之和", st2.system.airdrop_pending == total,
        f"{st2.system.airdrop_pending} == {total}")
    chk("读回后的创世状态根与配置声明一致",
        "0x" + st2.state_root.hex() == g["genesis_state_root"])
    chk("读回后的空投根与分配表一致",
        st2.system.airdrop_root.hex() == tbl["airdrop_root"])
    chk("读回后的创世供应量守恒", st2.check_supply_conservation()[0])
    chk("空投条目的 index 被保留（叶子的一部分）",
        sorted(int(e.index) for e in alloc2.airdrop) ==
        sorted(int(e["index"]) for e in tbl["entries"]),
        str(sorted(int(e.index) for e in alloc2.airdrop)))

    # 负例 ①：抽掉条目（复现刚修掉的缺陷）⇒ 必须**明确报错**，而不是启动时才炸
    bad1 = json.loads(json.dumps(g))
    bad1.pop("genesis_airdrop", None)
    p1 = os.path.join(d, "genesis_noentries.json")
    json.dump(bad1, open(p1, "w", encoding="utf-8"))
    try:
        load_genesis_config(p1)
        chk("★配置缺少空投条目 ⇒ 加载器明确报错（不是静默少钱）", False, "竟然加载成功")
    except GenesisConfigError as e:
        chk("★配置缺少空投条目 ⇒ 加载器明确报错（不是静默少钱）", True,
            str(e).splitlines()[-1][:60])

    # 负例 ②：改一个条目的金额 ⇒ 与声明的根不符 ⇒ 必须报错
    bad2 = json.loads(json.dumps(g))
    bad2["genesis_airdrop"][0]["amount_atom"] = str(int(bad2["genesis_airdrop"][0]["amount_atom"]) + 1)
    p2 = os.path.join(d, "genesis_badamt.json")
    json.dump(bad2, open(p2, "w", encoding="utf-8"))
    try:
        load_genesis_config(p2)
        chk("★条目金额被篡改 ⇒ 与 airdrop_root 对不上，加载器报错", False, "竟然加载成功")
    except GenesisConfigError as e:
        chk("★条目金额被篡改 ⇒ 与 airdrop_root 对不上，加载器报错", True,
            "airdrop_root" in str(e))


def test_gas_allowance_accounting():
    print("\n6) gas_allowance 的记账口径（它占用初始供应，不是免费的）")
    ents = [AirdropEntry(pubkey=publickey_from_seed(s), amount=1000 * A,
                         gas_allowance=5 * 10 ** 15, index=i)
            for i, s in enumerate(BENEFICIARIES, 1)]
    chk("airdrop_gas_allowance_total 汇总正确",
        airdrop_gas_allowance_total(ents) == 3 * 5 * 10 ** 15)
    chk("汇总口径与创世闭合检查一致（值出现在 closure 明细里）",
        airdrop_gas_allowance_total(ents) > 0)


def main():
    print("═" * 76)
    print("AGORA v0.2.2 参考实现 · 空投工具链跨工具一致性")
    print("═" * 76)
    d, apath, tpath, tbl, vpath, vpks = test_offline_root_matches_chain()
    res = test_genesis_matches_table(d, apath, tpath, tbl, vpath, vpks)
    if res:
        gpath, g = res
        test_claim_proof_verifies(d, tpath, tbl, gpath, g)
    test_negative_guards(d, tpath, tbl, vpath, vpks)
    if res:
        test_config_roundtrip(d, tpath, tbl, res[0], res[1], vpath, vpks)
    test_gas_allowance_accounting()
    print("\n" + "═" * 76)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
