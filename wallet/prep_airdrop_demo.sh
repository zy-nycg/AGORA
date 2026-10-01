#!/usr/bin/env bash
# 准备一套"带空投的测试网"：分配表 → 创世 → 受益人私钥文件 → 打印领取参数
# 用法: bash wallet/prep_airdrop_demo.sh [输出目录]
set -u
OUT="${1:-wallet/runs/airdrop-demo}"
cd "$(dirname "$0")/.." || exit 1
rm -rf "$OUT" && mkdir -p "$OUT"
PYTHONPATH=. python3 - "$OUT" <<'PY'
import csv, json, os, sys, subprocess
sys.path.insert(0, ".")
from agora.crypto_backend import publickey_from_seed
out = sys.argv[1]
# 3 个受益人（种子固定，便于复现）
bene = []
for i, tag in enumerate((0xA1, 0xA2, 0xA3), start=1):
    seed = bytes([tag]) * 32
    pk = publickey_from_seed(seed)
    with open(f"{out}/beneficiary{i}.seed", "w", encoding="utf-8") as f:
        f.write(seed.hex())
    bene.append({"pubkey_hex": pk.hex(), "amount_atom": str(1000 * 10**18),
                 "gas_allowance_atom": str(5 * 10**15), "note": f"demo-{i}"})
with open(f"{out}/airdrop.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["pubkey_hex", "amount_atom",
                                      "gas_allowance_atom", "note"])
    w.writeheader(); w.writerows(bene)
r = subprocess.run(["python3", "tools/agora_genesis_keygen.py", "airdrop-build",
                    "--in", f"{out}/airdrop.csv", "--out", f"{out}/table.json"],
                   capture_output=True, text=True, env={**os.environ, "PYTHONPATH": "."})
assert r.returncode == 0, r.stderr
tbl = json.load(open(f"{out}/table.json"))
vals = open("wallet/runs/devkeys/validators.csv").read().strip().splitlines()[1:]
with open(f"{out}/validators.csv", "w", encoding="utf-8") as f:
    f.write("pubkey_hex,amount_atom\n")
    for row in vals[:4]:
        f.write(f"{row.split(',')[0]},64000000000000000000\n")
r = subprocess.run(["python3", "tools/agora_genesis_build.py",
                    "--validators", f"{out}/validators.csv", "--network", "testnet",
                    "--airdrop-table", f"{out}/table.json",
                    "--reserve-pubkey", vals[0].split(",")[0],
                    "--out", f"{out}/genesis.json"], capture_output=True, text=True,
                   env={**os.environ, "PYTHONPATH": "."})
assert r.returncode == 0, (r.stdout + r.stderr)
g = json.load(open(f"{out}/genesis.json"))
print("分配表根      :", tbl["airdrop_root"])
print("创世 airdrop_root:", g["airdrop_root"].removeprefix("0x"))
print("一致          :", tbl["airdrop_root"].lower() == g["airdrop_root"].removeprefix("0x").lower())
print("创世哈希      :", g["genesis_hash"])
print("受益人        :", [e["pubkey_hex"][:12] + "…" for e in tbl["entries"]])
print("产出目录      :", out)
PY
