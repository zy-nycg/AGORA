#!/usr/bin/env bash
# 起一个带**只读查询接口**的单节点（钱包联调用）：数据目录复用已有链，因此立刻有数据可查
# 用法: bash wallet/run_rpc_demo.sh [数据目录] [秒数] [端口]
set -u
DIR="${1:-wallet/runs/drill-final/node4}"
SECS="${2:-300}"
PORT="${3:-8645}"
cd "$(dirname "$0")/.." || exit 1
PK1=$(python3 tools/agora_keyinfo.py --seed-file wallet/runs/devkeys/key1.seed --pubkey-only)
PK2=$(python3 tools/agora_keyinfo.py --seed-file wallet/runs/devkeys/key2.seed --pubkey-only)
PK3=$(python3 tools/agora_keyinfo.py --seed-file wallet/runs/devkeys/key3.seed --pubkey-only)
PYTHONPATH=. exec python3 tools/agora_run_node.py \
    --config wallet/runs/dev-genesis.json --name node4 \
    --seed-file wallet/runs/devkeys/key4.seed --listen 127.0.0.1:26686 \
    --peer "node1@127.0.0.1:26656@$PK1" \
    --peer "node2@127.0.0.1:26666@$PK2" \
    --peer "node3@127.0.0.1:26676@$PK3" \
    --report-every 10 --max-seconds "$SECS" --data-dir "$DIR" \
    --rpc-port "$PORT" --rpc-bind 127.0.0.1
