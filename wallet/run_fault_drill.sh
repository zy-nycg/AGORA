#!/usr/bin/env bash
# AGORA — 本机 4 节点「故障演练」脚本（TESTNET_RUNBOOK.md 阶段 D 的本机彩排）
# =========================================================================
#
# 用法：
#   bash wallet/run_fault_drill.sh <genesis.json> [每阶段秒数] [私钥目录] [数据目录根]
#
# 例：
#   bash wallet/run_fault_drill.sh wallet/runs/dev-genesis.json 20 wallet/runs/devkeys wallet/runs/drill
#
# 数据目录**刻意复用**（脚本只清理日志，不清理 nodeN/）：
#   重复执行时第一阶段会从上次的高度续跑 —— 这本身就是"重启能续跑"的重复证据。
#   若要完全从创世开始一次干净的演练，先删掉数据目录根：
#     rm -rf wallet/runs/drill
#
# 演练内容（每一阶段都有明确判据，脚本自己给出结论）：
#
#   阶段 1  4 节点正常出块              → 判据：高度增长
#   阶段 2  `kill -9` 掉 node3（**模拟断电**，不给它优雅落盘的机会）
#           → 判据：其余 3 节点**仍在出块**（3/4 达法定数）
#           → 判据：node3 留下的半写记录在重启时被自动截断
#   阶段 3  用**同一数据目录**重启 node3 → 判据：从磁盘恢复（不是从创世重来），
#           并靠区块同步**追平**其余节点（这是同步路径的唯一真实验证）
#   阶段 4  全部停机后用同一数据目录重启四节点
#           → 判据：四节点都恢复，且**相同高度**的区块哈希完全一致
#
# 为什么必须做这一步：**仿真测不出这一类缺陷。**
# 丢包/分区/双签的故障注入矩阵全部在仿真里跑，而仿真不走 TCP、也不重启进程。
# 实测教训：形参错位（BUG-89）与线格式重复携带请求者（BUG-90）在**全部仿真
# 测试全绿**的情况下，让"响应第一次同步请求"的两台节点立刻崩溃 ——
# 只有真进程、真 socket、真重启才能触发这一类缺陷。
set -u

GENESIS="${1:?用法: run_fault_drill.sh <genesis.json> [秒数] [私钥目录] [数据目录根]}"
SECS="${2:-20}"
KEYDIR="${3:-wallet/founder}"
DATAROOT="${4:-wallet/runs/drill}"
LOG="${DATAROOT}/logs"
DUMP_HEIGHT=100               # 阶段 4 的"相同高度"比对点
BASE_PORT=26656
STEP=10

cd "$(dirname "$0")/.." || exit 1
mkdir -p "$LOG"

PASS=0
FAIL=0
verdict() {  # verdict <1=通过/0=失败> <判据> <详情>
    if [ "$1" = "1" ]; then
        PASS=$((PASS + 1)); echo "  [OK  ] $2   $3"
    else
        FAIL=$((FAIL + 1)); echo "  [FAIL] $2   $3"
    fi
}

port_of() { echo $((BASE_PORT + ($1 - 1) * STEP)); }

# ── 公钥表（名字↔连接的签名握手，规范 §6.7）──
pubkey_of() {
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

# ⚠ **不要**用 `$(start_node ...)` 取 PID：命令替换会在**子 shell** 里启动进程，
# 于是 `wait` 在父 shell 里找不到这个子进程、立刻返回（错误还被 2>/dev/null 吞掉）。
# 实测后果：脚本在节点刚启动时就去读日志 ⇒ 全部读成"未报告"，
# 表面上像"四个节点都没起来"，实际是脚本自己在抢跑。
# 因此用全局变量回传 PID，并**直接调用**函数。
LAST_PID=""
start_node() {  # start_node <编号> <秒数> <日志名> [比对高度] [报告间隔秒]
    local i="$1" secs="$2" logname="$3" dump="${4:-0}"
    local port peers j
    port=$(port_of "$i")
    peers=""
    for j in 1 2 3 4; do
        [ "$j" -eq "$i" ] && continue
        peers="$peers --peer node${j}@127.0.0.1:$(port_of "$j")@${PUBKEY[$j]}"
    done
    # shellcheck disable=SC2086
    PYTHONPATH=. python3 tools/agora_run_node.py \
        --config "$GENESIS" --name "node${i}" \
        --seed-file "${KEYDIR}/key${i}.seed" \
        --listen "127.0.0.1:${port}" \
        --report-every "${5:-10}" --max-seconds "$secs" --dump-height "$dump" \
        --data-dir "${DATAROOT}/node${i}" \
        $peers > "$LOG/${logname}.log" 2>&1 &
    LAST_PID=$!
}

# ⚠ 高度**必须**取进程收尾时打印的最终值，不能取周期报告：
# 周期报告的时间点取决于各进程各自的启动时刻与 10s 间隔，节点间相差一格报告
# 就是上百个区块的"假差距"（本脚本首版据此判过一次"节点落后 115 块"，
# 实际上四个节点在**相同高度**上的区块哈希完全一致）。
height_of() {  # 最终化链长（收尾时打印，确定性）
    grep -o "最终化链长 *: *[0-9]*" "$1" 2>/dev/null | tail -1 | grep -o "[0-9]*$"
}

live_height_of() {  # 仍在运行时：最后一条周期报告的高度（只用于"启动后有没有增长"）
    grep -o "高度=[0-9]*" "$1" 2>/dev/null | tail -1 | cut -d= -f2
}

resumed_of() {  # 从磁盘恢复的区块数（注意日志里是"已最终化   : N 个区块"）
    grep -o "已最终化 *: *[0-9]* *个区块" "$1" 2>/dev/null | head -1 | grep -o "[0-9]*" | head -1
}

cleanup() { pkill -f "agora_run_node.py --config $GENESIS" 2>/dev/null || true; sleep 1; }

echo "════════════════════════════════════════════════════════════════════"
echo "AGORA 4 节点故障演练（本机彩排）"
echo "  创世       : $GENESIS"
echo "  每阶段时长 : ${SECS}s"
echo "  数据目录   : $DATAROOT/nodeN（**复用** ⇒ 重启会续跑，而不是从创世重来）"
echo "════════════════════════════════════════════════════════════════════"
cleanup
rm -rf "$LOG"
mkdir -p "$LOG"

# ── 阶段 1：正常运行 ─────────────────────────────────────────────────
echo
echo "阶段 1) 4 节点正常运行 ${SECS}s"
PIDS=()
for i in 1 2 3 4; do start_node "$i" "$SECS" "p1-node${i}"; PIDS+=("$LAST_PID"); done
for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
h1=(); for i in 1 2 3 4; do h1+=("$(height_of "$LOG/p1-node${i}.log")"); done
echo "  各节点高度：${h1[0]} ${h1[1]} ${h1[2]} ${h1[3]}"
min1=$(printf '%s\n' "${h1[@]}" | sort -n | head -1)
verdict "$([ "${min1:-0}" -ge 20 ] && echo 1 || echo 0)" \
    "阶段 1：四节点均正常出块（链长 ≥ 20）" "最短链 ${min1}"

# ── 阶段 2：kill -9 node3（模拟断电）────────────────────────────────
echo
echo "阶段 2) 断电 node3（kill -9，不给它优雅落盘的机会），其余 3 节点继续 ${SECS}s"
PIDS=()
for i in 1 2 4; do start_node "$i" "$SECS" "p2-node${i}" 0 3; PIDS+=("$LAST_PID"); done
sleep $((SECS / 3))
# node3 以"正常在跑"的形态启动，随后被强杀（不给它落盘的机会）
# shellcheck disable=SC2086
PYTHONPATH=. python3 tools/agora_run_node.py \
    --config "$GENESIS" --name node3 --seed-file "${KEYDIR}/key3.seed" \
    --listen "127.0.0.1:$(port_of 3)" --report-every 2 \
    --data-dir "${DATAROOT}/node3" \
    --peer node1@127.0.0.1:$(port_of 1)@${PUBKEY[1]} \
    --peer node2@127.0.0.1:$(port_of 2)@${PUBKEY[2]} \
    --peer node4@127.0.0.1:$(port_of 4)@${PUBKEY[4]} > "$LOG/p2-node3.log" 2>&1 &
PID3=$!
# 等到它至少报过一次高度再强杀：否则"被杀时高度"会读成"未报告"，
# 而阶段 2 的判据要靠这个数（脚本自己抢跑过一次，教训记在这里）。
sleep 8
kill -9 "$PID3" 2>/dev/null || true
wait "$PID3" 2>/dev/null || true     # 回收僵尸，避免 shell 打印"已杀死"噪声
echo "  已 kill -9 node3（pid=${PID3}，模拟断电：状态快照与最后一次落盘之后的数据全部丢失）"
h2k=$(live_height_of "$LOG/p2-node3.log")
# 断电**那一刻**其余节点的进度（此时它们还在跑，只能取周期报告）
at_kill=(); for i in 1 2 4; do at_kill+=("$(live_height_of "$LOG/p2-node${i}.log")"); done
for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
h2=(); for i in 1 2 4; do h2+=("$(height_of "$LOG/p2-node${i}.log")"); done
echo "  node3 被杀时链长：${h2k:-未报告}"
echo "  其余节点：断电时刻 ${at_kill[0]}/${at_kill[1]}/${at_kill[2]} → 结束时 ${h2[0]}/${h2[1]}/${h2[2]}"
# 判据是"**杀掉一个之后，其余节点继续增长**"（3/4 仍达法定数）——
# 不能拿 node3 的高度与其余节点的最终高度直接比：它们的时间点不同，
# 而且 node3 可能是刚追赶上来、暂时领先的那一个（首版就在这里误判过）。
grew=1
for k in 0 1 2; do
    [ "${at_kill[$k]:-0}" -gt 0 ] || grew=0
    [ "${h2[$k]:-0}" -gt "${at_kill[$k]:-0}" ] || grew=0
done
verdict "$grew" \
    "阶段 2：node3 断电后其余 3 节点仍在推进（3/4 达法定数）" \
    "结束后链长均 > 断电时刻链长"

# ── 阶段 3：同目录重启 node3 → 必须从磁盘恢复并追平 ─────────────────
echo
echo "阶段 3) 用同一数据目录重启 node3：验证「磁盘恢复 + 区块同步追平」"
PIDS=()
for i in 1 2 4; do start_node "$i" "$SECS" "p3-node${i}"; PIDS+=("$LAST_PID"); done
start_node 3 "$SECS" "p3-node3"; PIDS+=("$LAST_PID")
for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
rec=$(resumed_of "$LOG/p3-node3.log")
echo "  node3 恢复信息：${rec:-未报告} 个区块"
echo "  崩溃安全自检（kill -9 若留下半写记录，应在启动时被识别并截断）："
if grep -q "未完成的写入" "$LOG/p3-node3.log" 2>/dev/null; then
    grep -n "未完成的写入" "$LOG/p3-node3.log" | head -3 | sed 's/^/    /'
    echo "    ⇒ ✅ 残缺尾巴被识别并截断，节点照常启动（这正是「落盘崩溃安全」的证据）"
else
    echo "    （本次强杀恰好落在记录边界上，没有半写记录 —— 属正常，不强求复现）"
fi
h3=(); for i in 1 2 3 4; do h3+=("$(height_of "$LOG/p3-node${i}.log")"); done
echo "  各节点最终链长：${h3[0]} ${h3[1]} ${h3[2]} ${h3[3]}"
gap=$(( h3[0] - h3[2] )); [ "$gap" -lt 0 ] && gap=$(( -gap ))
verdict "$([ "${rec:-0}" -gt 0 ] && echo 1 || echo 0)" \
    "阶段 3：node3 从磁盘恢复（不是从创世重来）" "恢复到链长 ${rec:-0}"
# 不同节点的进程在不同时刻停止，链长天然可差几块；判据放宽到 20 块，
# 真正的"无分叉"证据是阶段 4 的**相同高度哈希比对**。
verdict "$([ "$gap" -le 20 ] && echo 1 || echo 0)" \
    "阶段 3：node3 追到同一水平（与 node1 差 ≤ 20 块）" "相差 ${gap} 块"

# ── 阶段 4：全部重启 + 相同高度哈希比对 ─────────────────────────────
echo
echo "阶段 4) 四节点全部重启（同目录），比对**相同高度**（${DUMP_HEIGHT}）的区块哈希"
PIDS=()
for i in 1 2 3 4; do
    start_node "$i" "$SECS" "p4-node${i}" "$DUMP_HEIGHT"; PIDS+=("$LAST_PID")
done
for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
nrec=0
for i in 1 2 3 4; do [ "$(resumed_of "$LOG/p4-node${i}.log")" != "" ] && nrec=$((nrec + 1)); done
verdict "$([ "$nrec" -eq 4 ] && echo 1 || echo 0)" \
    "阶段 4：四节点全部从磁盘恢复" "报告恢复的节点数 ${nrec}/4"
h4=(); for i in 1 2 3 4; do h4+=("$(height_of "$LOG/p4-node${i}.log")"); done
echo "  各节点最终链长：${h4[0]} ${h4[1]} ${h4[2]} ${h4[3]}"
# ⚠ 先**计数**再**去重**：首版直接 `sort -u` 之后数行数，四个节点给出同一个哈希时
# 会被去重成 1 行，于是"4 个里只有 1 个导出了"这种假失败。
RAW=$(grep -ho "HEIGHT=${DUMP_HEIGHT} BLOCK_HASH=[0-9a-f]*" "$LOG"/p4-node*.log)
echo "  相同高度（${DUMP_HEIGHT}）的导出："; echo "$RAW" | sed 's/^/    /'
n_hash=$(echo "$RAW" | grep -c "BLOCK_HASH=")
uniq_hash=$(echo "$RAW" | sed 's/.*BLOCK_HASH=//' | sort -u | wc -l)
verdict "$([ "$n_hash" -eq 4 ] && [ "$uniq_hash" -eq 1 ] && echo 1 || echo 0)" \
    "阶段 4：相同高度的区块哈希四节点一致（无分叉）" \
    "导出 ${n_hash}/4 个，不同哈希 ${uniq_hash} 种"

cleanup

echo
echo "════════════════════════════════════════════════════════════════════"
echo "故障演练结果：通过 ${PASS} 项，失败 ${FAIL} 项"
if [ "$FAIL" -eq 0 ]; then
    echo "结论：全部通过 ✅（本机彩排；香橙派真机断电演练仍需做一次）"
else
    echo "结论：★ 存在失败 —— 看上面 [FAIL] 行与 $LOG 下的日志"
fi
echo "日志目录：$LOG"
echo "════════════════════════════════════════════════════════════════════"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
