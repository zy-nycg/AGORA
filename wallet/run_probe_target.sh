#!/usr/bin/env bash
# 启动**单个**节点作为握手探测的目标（用于 tools/agora_handshake_probe.py）
# 用法: bash wallet/run_probe_target.sh [数据目录] [秒数]
set -u
DIR="${1:-wallet/runs/drill-verify/node4}"
SECS="${2:-150}"
cd "$(dirname "$0")/.." || exit 1
PK1=$(python3 tools/agora_keyinfo.py --seed-file wallet/runs/devkeys/key1.seed --pubkey-only)
PK2=$(python3 tools/agora_keyinfo.py --seed-file wallet/runs/devkeys/key2.seed --pubkey-only)
PK3=$(python3 tools/agora_keyinfo.py --seed-file wallet/runs/devkeys/key3.seed --pubkey-only)
echo "$PK1" > wallet/runs/pk1.txt
python3 tools/agora_keyinfo.py --seed-file wallet/runs/devkeys/key4.seed --pubkey-only > wallet/runs/pk4.txt
PYTHONPATH=. exec python3 tools/agora_run_node.py \
    --config wallet/runs/dev-genesis.json --name node4 \
    --seed-file wallet/runs/devkeys/key4.seed --listen 127.0.0.1:26686 \
    --peer "node1@127.0.0.1:26656@$PK1" \
    --peer "node2@127.0.0.1:26666@$PK2" \
    --peer "node3@127.0.0.1:26676@$PK3" \
    --report-every 5 --max-seconds "$SECS" --data-dir "$DIR"
