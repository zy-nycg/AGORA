#!/usr/bin/env bash
# AGORA — 本机 4 节点集群启动器（真 TCP，环回地址）
# ==================================================
#
# 用法：
#   bash wallet/run_local_cluster.sh <genesis.json> [运行秒数] [日志标签]
#
# 例：
#   bash wallet/run_local_cluster.sh wallet/genesis.testnet.json 90 testnet
#   bash wallet/run_local_cluster.sh wallet/genesis.mainnet-params.json 45 mainnet
#
# 说明：
#   · 4 个**独立操作系统进程**，各自持有自己那把 `wallet/founder/keyN.seed`；
#   · 监听 127.0.0.1（只在本机可见，**不**对外暴露端口）；
#   · 日志写到 wallet/runs/<标签>/nodeN.log，脚本会等全部节点退出后返回。
#
# 判读要点（详见 TESTNET_RUNBOOK.md 阶段 C4）：
#   · 高度持续增长 ⇒ 共识成立；
#   · 比较不同节点的状态根时**必须先在相同高度**比较（否则只是进度差）；
#   · 4 个验证者需 **3 个在线**才能最终化（QUORUM = 171，3×64 = 192 ≥ 171）。
set -u

GENESIS="${1:?用法: run_local_cluster.sh <genesis.json> [秒数] [标签] [比对高度] [私钥目录]}"
SECONDS_RUN="${2:-90}"
TAG="${3:-run}"
DUMP_HEIGHT="${4:-0}"
KEYDIR="${5:-wallet/founder}"      # 私钥目录（默认用创世验证者密钥；本机演练可用临时密钥）
# 设了 AIRDROP_TABLE 就把空投分配表交给每个节点（链上只存 airdrop_root，
# 只有拿到分配表的节点才能提供领取 Merkle 证明 —— 见 §32.5）。
AIRDROP_TABLE="${AIRDROP_TABLE:-}"

DATADIR="${6:-}"                   # 持久化目录根（给出则每个节点用 $DATADIR/nodeN，可重启续跑）

cd "$(dirname "$0")/.." || exit 1
LOG="wallet/runs/${TAG}"
mkdir -p "$LOG"
: > "$LOG/summary.txt"

BASE_PORT=26656
STEP=10
PIDS=()

echo "创世文件 : $GENESIS"
echo "运行上限 : ${SECONDS_RUN}s"
echo "日志目录 : $LOG"
echo

# ── 读每个节点的**公钥**：名字↔连接的签名握手（规范 §6.7）需要它 ──
# 公钥从 `keyN.pub.json` 读（该文件由密钥生成工具写出、只含公开材料）。
# 没有公钥时**不能**启动：运行器默认严格模式，会拒绝启动并提示怎么补。
pubkey_of() {  # pubkey_of <编号>
    local f="${KEYDIR}/key$1.pub.json"
    if [ -f "$f" ]; then
        python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['public_key_hex'])" "$f"
    else
        PYTHONPATH=. python3 tools/agora_keyinfo.py --seed-file "${KEYDIR}/key$1.seed" --pubkey-only
    fi
}

declare -A PUBKEY
for i in 1 2 3 4; do
    PUBKEY[$i]="$(pubkey_of "$i")" || { echo "✗ 读不到 node${i} 的公钥（${KEYDIR}/key${i}.*）"; exit 1; }
done

for i in 1 2 3 4; do
    port=$((BASE_PORT + (i - 1) * STEP))
    peers=""
    for j in 1 2 3 4; do
        [ "$j" -eq "$i" ] && continue
        pj=$((BASE_PORT + (j - 1) * STEP))
        peers="$peers --peer node${j}@127.0.0.1:${pj}@${PUBKEY[$j]}"
    done
    # shellcheck disable=SC2086
    PYTHONPATH=. python3 tools/agora_run_node.py \
        --config "$GENESIS" \
        --name "node${i}" \
        --seed-file "${KEYDIR}/key${i}.seed" \
        --listen "127.0.0.1:${port}" \
        --report-every 15 \
        --max-seconds "$SECONDS_RUN" \
        --dump-height "$DUMP_HEIGHT" \
        ${RPC_BASE:+--rpc-port $((RPC_BASE + i - 1)) --rpc-bind 127.0.0.1} \
        ${AIRDROP_TABLE:+--airdrop-table "$AIRDROP_TABLE"} \
        ${DATADIR:+--data-dir "$DATADIR/node${i}"} \
        $peers > "$LOG/node${i}.log" 2>&1 &
    PIDS+=($!)
    echo "  已启动 node${i}  pid=${PIDS[-1]}  port=${port}"
done

echo
echo "等待全部节点退出（最多 ${SECONDS_RUN}s）…"
for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done

echo
if [ "$DUMP_HEIGHT" != "0" ]; then
    echo "── 同一高度（${DUMP_HEIGHT}）的区块哈希比对（唯一有效的无分叉证据）──"
    grep -h "HEIGHT=" "$LOG"/node*.log | sort -u
    n_hash=$(grep -h "HEIGHT=" "$LOG"/node*.log | sed 's/.*BLOCK_HASH=\([0-9a-f]*\).*/\1/' | sort -u | wc -l)
    if [ "$n_hash" -eq 1 ]; then
        echo "  ⇒ ✅ 全部节点在同一高度的区块哈希完全一致（无分叉）"
    else
        echo "  ⇒ ★ 出现 ${n_hash} 种不同的区块哈希 —— 必须排查"
    fi
    echo
fi
echo "── 各节点最终状态 ──"
for i in 1 2 3 4; do
    tail -6 "$LOG/node${i}.log" | sed "s/^/  node${i}: /"
    echo
done > "$LOG/summary.txt"
cat "$LOG/summary.txt"
echo "完整日志：$LOG/nodeN.log"
