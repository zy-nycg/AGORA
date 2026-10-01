# AGORA 双机测试网 · 操作手册

> 目标机器：**PC（x86_64）+ 香橙派 Zero 2W（aarch64，1GB）**
> 网络形态：PC 跑 3 个验证者进程，香橙派跑 1 个 —— 这样**任一离线仍能出块**
> （4 × 64 AGORA 质押，`QUORUM = ceil(2S/3) = 170.67`，3 人 = 192 ≥ 170）。
>
> **状态（已实测）：** 跨机的 **TCP 传输层已实现并验证** ——
> `agora/transport.py` + `tools/agora_run_node.py`。
> 实测：**4 个独立操作系统进程** 经真 TCP（不同端口）在 40 秒内产出
> **642 个区块**，状态根与链头逐高度一致、无分叉、供应量守恒。
> 因此阶段 A/B/C 现在都可以执行。
>
> **链上持久化已实现并实测（2026-xx 更新）：** `--data-dir <目录>` 下节点
> 把每个最终化区块追加落盘（每块 fsync），并周期性写状态快照（携带链头 `Commit`）；
> **同目录重启会从上次进度续跑**，且载入的状态必须与链头承诺的状态根一致，
> 否则**拒绝启动**（退出码 4）—— 磁盘从不可信。
>
> **两阶段实测证据：** 4 节点跑至高度 **521** → 全部停机 → 同目录重启 →
> 4 个节点全部从高度 **520** 续跑至 **1245–1247**；在**相同高度**
> （250 / 687 / 872 / 1051）比较，四节点的**区块哈希与状态根逐一相同**，
> 零解码错误、零丢包、供应量守恒 ✅。因此**阶段 D 现在可以执行**。
>
> 🔐 **名字↔连接的签名握手已实现（规范 §6.7.1）。** 运行器默认**严格身份模式**：
> 每个 `--peer` 都必须给出该对端的**公钥**，写成 `name@host:port@<pubkey-hex>`；
> 每个 TCP 连接建立时双方都要证明持有对应私钥，此后该连接上任何"换个名字说话"
> 的帧都会被丢弃。要拿到公钥，在**对方机器**上执行：
>
> ```bash
> python3 tools/agora_keyinfo.py --seed-file keys/key1.seed     # 打印 name/pubkey/address
> ```
>
> 把输出的公钥填进其它机器的 `--peer`。缺公钥时运行器会**拒绝启动**
> （退出码 5）并提示怎么写 —— 这是刻意的：没有握手时，任何能连上端口的人
> 都能冒用对端名字。
> ⚠ **一条硬性配置要求（规范 §6.5 第 7 项）：`--peer` 必须双向互配。**
> A 把 B 列入对端表，B 也必须把 A 列入；否则 A 发来的帧会因"自述名不在
> 本节点对端表内"被丢弃，症状是**单向失聪**（A 看起来一切正常）。
> 启动器会在收尾打印 `发送者身份异常` 提示，正常网络下该项必须为 0。

---

## 0. 一分钟看清全貌

| 阶段 | 内容 | 现在能做吗 |
|---|---|---|
| A | 两台机器环境准备 + 编译 C 后端 + 生成密钥 + 冻结创世 | ✅ 可以 |
| B | 单机 4 进程测试网 | ✅ 可以 |
| C | 香橙派作为**独立机器**接入（跨机 TCP） | ✅ **已实测通过** |
| D | 24h 稳定性 + 断电/抖动演练 | ✅ 可以（持久化 + 签名握手均已就绪，见阶段 D） |

---

## 阶段 A：两台机器准备

### A1. 香橙派系统（一次性）

烧 **Raspberry Pi OS Lite 64-bit** 或 **Armbian**（必须 64 位，32 位下
`u64` 运算与内存都吃紧），开 SSH，**接网线**（WiFi 抖动会触发不活跃惩罚）。

```bash
sudo apt update
sudo apt install -y git python3 build-essential
# build-essential 是**必需**的：香橙派必须自己编译 C 后端（见 A3）
```

### A2. 取代码（两台机器一致）

```bash
git clone <你的仓库地址> agora && cd agora
python3 -c "import sys; print(sys.version)"
# 需要 Python >= 3.10
```

> **两台机器的代码必须完全相同**（同一 commit）。若不同，创世哈希或
> 签名载荷可能不同，症状是"投票永远凑不齐"，极难排查。

### A3. 编译 C 后端（**两台机器都必须做**）

```bash
python3 tools/agora_build_native.py
```

期望输出以 `✓ 已生成 native/libagora_keccak.so` 开头，并列出向量校验全部 `OK`。

**为什么这不是可选项：** 不编译会**静默**回退纯 Python，链仍能跑但性能掉一个数量级：

| 项 | 纯 Python | C 后端 |
|---|---:|---:|
| Ed25519 验证 | 4,600 µs | 80 µs |
| Keccak-256 | 800 µs | 2.4 µs |
| 峰值满载区块（476 笔） | 1,723 ms（34% 槽） | **57 ms（1.13% 槽）** |

**确认已生效**（两台机器都要看到两个 ✅）：

```bash
python3 -c "from agora.crypto_backend import startup_self_check as s; \
            ok,msgs = s(mainnet=True); print('OK' if ok else 'FAIL'); [print(' ',m) for m in msgs]"
```

```
OK
  Ed25519 后端 = nacl（PyNaCl / libsodium）  ✅
  Keccak-256 后端 = 自带 C 库（native/libagora_keccak.so）  ✅
```

> 香橙派上若 `nacl` 不可用，`auto` 会回退 `cryptography`；两者都不可用时
> Ed25519 会退回纯 Python。可用 `pip3 install pynacl` 补上（离线环境则接受回退，
> 此时**不要**用于主网）。

### A4. 环境自检（两台机器，输出应完全一致）

```bash
python3 tools/agora_genesis_keygen.py selftest     # 10 项
python3 tools/agora_check_spec.py                  # 49 项
python3 tools/agora_vectors.py --verify            # 九族黄金向量
```

三项都必须全绿。**若香橙派上任何一项与 PC 不同，先停下排查**，
不要继续 -- 环境不一致是后续所有诡异故障的根源。

---

## 阶段 B：生成密钥与创世

### B1. 生成测试网密钥

```bash
# PC 侧 3 把，香橙派侧 1 把（或反过来；总之每台机器只放自己那几把）
python3 tools/agora_genesis_keygen.py keygen --count 3 --network testnet \
    --out-dir keys-pc --stake 64
python3 tools/agora_genesis_keygen.py keygen --count 1 --network testnet \
    --out-dir keys-pi --stake 64
```

每条命令会写出：

```
keys-pc/key1.seed … key3.seed     私钥（权限 0600，**不外传**）
keys-pc/key1.pub.json …           公钥 + 地址（可外传）
keys-pc/validators.csv            可直接用于创世构建（每人质押 64 AGORA）
```

> **私钥不会打印到终端**（刻意的：终端输出会进日志与 shell 历史）。
> 若确实需要看私钥，用不带 `--out-dir` 的旧用法（会在屏幕上打印）。
>
> **本仓库已备好一份可直接用的钱包目录**：`wallet/`（4 把创始验证者密钥、
> 100 个开发者奖励钱包、两份创世、本机 4 节点启动器）。见 `wallet/README.md`。
> 本手册讲的是**跨机部署**流程；本机演练可直接用
> `bash wallet/run_local_cluster.sh wallet/genesis.testnet.json 70 testnet 800`。

**测试网允许单机批量**；**主网必须单把生成**（工具会拒绝批量，这是刻意的）。

> `--network testnet` 会令 `chain_id = agora-testnet-1`。用测试密钥签出的交易
> 在**主网无效**（`tests/test_testnet.py` 有专门的跨链重放断言）。
> 反过来：若你忘了加这个参数，密钥就带主网标记 —— **切勿**把这种密钥当测试密钥用。

### B2. 合并验证者名单并冻结创世

把全部 4 把公钥合并成一个 CSV（**只需公钥，私钥永不离开各自机器**）：

```csv
pubkey_hex,address_hex,amount_atom
<PC第1把公钥>,<地址>,64000000000000000000
<PC第2把公钥>,<地址>,64000000000000000000
<PC第3把公钥>,<地址>,64000000000000000000
<香橙派公钥>,<地址>,64000000000000000000
```

```bash
python3 tools/agora_genesis_build.py \
    --network testnet \
    --validators validators.csv \
    --out testnet-genesis.json
```

摘要里必须看到：

```
金额闭合            : ✓
创始验证者          : 4 名
QUORUM              : 170666666666666666667 atom
```

### B3. **两台机器分别独立复核创世**（关键一步）

把 `testnet-genesis.json` 拷到香橙派，在**两台机器**上各跑一次：

```bash
python3 tools/agora_genesis_build.py --check testnet-genesis.json
```

期望两台都输出：

```
  [OK  ] 创世状态根：0x…
  [OK  ] 创世哈希：0x…
  [OK  ] 链身份：agora-testnet-1
  [OK  ] 金额闭合：20,480,000,000,000,000,000,000,000 == 20,480,000,000,000,000,000,000,000
结果：✅ 创世可复现，全节点可安全启动
```

> **这一步为什么不能省：** 若两台机器算出的创世不同（参数、代码版本、
> C 后端任一不一致），节点之间连第一条共识消息都对不上，表现为
> "投票永远凑不齐 2/3" —— 一个几乎无法从日志定位的故障。
> 复核命令就是用来把这个故障**提前到启动之前**暴露。

`testnet-genesis.json` 里的 `genesis_hash` 即两台的**共同锚点**，
记录它并互相核对。

---

## 阶段 C：跨机接入（TCP，已实测）

### C1. 准备（每台机器）

把 `testnet-genesis.json` 拷到每台机器；私钥**只放各自机器的自己那一把**。

### C2. 启动

每台机器一条命令。`--peer` 列出**除自己以外**的全部节点（可重复）。
**每个 `--peer` 末尾 MUST 带上该对端的公钥**（§6.7.1 的签名握手用它把名字绑定到密钥）：

```bash
# PC 侧（3 个验证者，各起一个进程，端口递增）
python3 tools/agora_run_node.py --config testnet-genesis.json \
    --name node1 --seed-file keys-pc/key1.seed --listen 0.0.0.0:26656 \
    --peer node2@<PC_IP>:26666@<node2_pubkey> \
    --peer node3@<PC_IP>:26676@<node3_pubkey> \
    --peer node4@<PI_IP>:26656@<node4_pubkey>

python3 tools/agora_run_node.py --config testnet-genesis.json \
    --name node2 --seed-file keys-pc/key2.seed --listen 0.0.0.0:26666 \
    --peer node1@<PC_IP>:26656@<node1_pubkey> \
    --peer node3@<PC_IP>:26676@<node3_pubkey> \
    --peer node4@<PI_IP>:26656@<node4_pubkey>

python3 tools/agora_run_node.py --config testnet-genesis.json \
    --name node3 --seed-file keys-pc/key3.seed --listen 0.0.0.0:26676 \
    --peer node1@<PC_IP>:26656@<node1_pubkey> \
    --peer node2@<PC_IP>:26666@<node2_pubkey> \
    --peer node4@<PI_IP>:26656@<node4_pubkey>

# 香橙派侧
python3 tools/agora_run_node.py --config testnet-genesis.json \
    --name node4 --seed-file keys-pi/key1.seed --listen 0.0.0.0:26656 \
    --peer node1@<PC_IP>:26656@<node1_pubkey> \
    --peer node2@<PC_IP>:26666@<node2_pubkey> \
    --peer node3@<PC_IP>:26676@<node3_pubkey>
```

启动器会**先做两项检查再联网**（任一不过就拒绝启动）：

1. **C 后端自检** —— 不通过会打印提示（性能会掉一个数量级）；
2. **创世复核** —— 重新计算创世哈希并与配置文件比对。不一致说明本节点与
   他人的链**不是同一条**，此时启动只会产生"投票永远凑不齐"这种最难查的故障。

`Ctrl-C` 会优雅停机并打印最终高度、链头与状态根。

### C3. 期望输出

```
── 启动自检 ──
  Ed25519 后端 = nacl（PyNaCl / libsodium）  ✅
  Keccak-256 后端 = 自带 C 库（native/libagora_keccak.so）  ✅
── 创世复核 ──
  创世哈希    : 0x4fad46b6…  ✅ 与配置文件一致
  本节点地址  : 9aea038c…（#1 号验证者）
── 已启动 ──
[    6s] 高度=96 轮=0 链长=95 头=3f9c1a2b… 守恒=✅ 收=139KB 发=138KB 丢=0 解码错=0 握手=3 未验证=0 身份失败=0
```

收尾时会另打一行身份汇总，**判读标准是"未验证=0、身份失败=0、名字不符=0"**：

```
  身份       : 本节点身份 c4d36de9241f… 严格模式=True 握手成功=6 未验证连接=0 握手失败=0 名字不符=0
```

### C3b. 用探测工具确认"别人冒用不了我的节点"（推荐每台机器做一次）

```bash
# 起一个"单节点但带完整历史链"的探测目标（本机演练用）
bash wallet/run_probe_target.sh wallet/runs/drill-verify/node4 300

# ① 诚实探测：以 node1 的身份（持有 key1.seed）索要一段区块 ⇒ 期望收到回送
python3 tools/agora_handshake_probe.py \
    --config testnet-genesis.json --target node4@<IP>:26686@<node4_pubkey> \
    --as node1 --seed-file keys/key1.seed --listen <本机IP>:26656 --expect accept

# ② 冒用探测：名字仍写 node1，但**拿别人的私钥** ⇒ 期望被拒（零回送）
python3 tools/agora_handshake_probe.py \
    --config testnet-genesis.json --target node4@<IP>:26686@<node4_pubkey> \
    --as node1 --seed-file keys/key2.seed --listen <本机IP>:26656 --expect reject
```

判据与常见误读：

| 观察 | 含义 |
|---|---|
| ① 收到 `on_block_batch` | ✅ 诚实身份被接受（应答是对方**主动拨号**回送，只有真处理了请求才会有） |
| ② 零回送 + `对端在握手第一步就关闭了连接` | ✅ 冒用被拒 |
| ② **有回送** | ★ 严重：对端没有开严格模式，或握手未生效 —— 立刻停网排查 |
| 任意一侧出现 `连不上目标节点` | 探测**无效**（不是"被拒"）：确认目标在监听、地址/端口/名字正确后重跑 |
| `挑战签名无效 … 链身份不一致` | 两边的 `network`/创世配错（**不是**攻击）；核对创世文件 |

⚠ 探测目标与探测方**必须**用同一份创世配置（`--config` 会自动设定链身份；
不给 `--config` 时必须给 `--network`，否则工具会拒绝运行）。

### C3c. 验证"交易真的能上链"（§16.5）

```bash
# 起 4 节点并给每个节点开查询接口（端口 8645..8648）
RPC_BASE=8645 bash wallet/run_local_cluster.sh wallet/runs/dev-genesis.json 60 tx-e2e 0 \
    wallet/runs/devkeys wallet/runs/tx-e2e &

# 钱包视角的完整闭环：签名 → 提交（给**非提案者**节点）→ 等进块 → 查回执
python3 tools/agora_tx_e2e.py --base-port 8645 --submit-to 8647 \
    --expect-chain-id agora-testnet-1
```

判据（脚本会逐条打印）：

| 观察 | 含义 |
|---|---|
| `HTTP 202 + accepted=true` | 节点已受理并转发（**不是**上链） |
| 重复提交返回 `duplicate` | 幂等，钱包重试安全 |
| `GET /v1/tx` 查到 `found=true` | ★ 真正上链（权威结论只看这里） |
| 回执 `receipt_exact=true` | 手续费是**执行侧记录的精确值** |
| 收款方余额恰好 +转账额 | 账目正确 |
| 四个节点同高度区块哈希 1 种 | 无分叉 |

⚠ 两个常见误判：① 把 202 当成"转账成功"；② 提交时**忘了先设链身份**
（新进程默认主网，而测试网集群是 testnet）—— 报错却是"签名验证失败"，
看起来像密钥不对，实际只是 chain_id 不匹配（`--expect-chain-id` 可以提前拦住）。

### C4. 判读要点（重要）

* **高度持续增长** ⇒ 跨机共识成立；
* **各节点链头在相同高度必须相同**。⚠ 若两台机器的**高度不同**，
  直接比较状态根会得出"分叉"的错误结论 —— 那只是进度差。
  **必须先在相同高度比较**（本仓库的 `tests/test_transport.py` 就是这么做的，
  而且第一版测试正是在这里误报过一次）。
  单机演练时用启动器的 `--dump-height N` 直接拿到"高度 N 的区块哈希"：
  `bash wallet/run_local_cluster.sh wallet/genesis.testnet.json 70 testnet 800`
  会打印四个节点在高度 800 的哈希并自动比对（一致才算无分叉）；
* **停掉一台后，其余节点应停止最终化**（4 验证者需 3 台在线）。
  但要注意：停机前**已送达**的票仍可能排在本地队列里，因此要等队列排空
  再开始观察，否则会看到"停摆后还前进 1 个高度"的假象。
* **启动器会用墙钟检查创世时刻（规范 §5.3，BUG-75）。**
  若本地时间早于创世的 `GenesisTimestamp`，节点会打印"还需等待 N 小时"并**拒绝启动**。
  节点内部的共识时间是逻辑时钟（从创世槽 0 起算），靠它**无法**实现这条禁令 ——
  所以这一条必须在联网之前用真实时间挡住。
* **块奖励在测试期恒为 0.64 AGORA（规范 §28.4.1 过渡期地板）。**
  这是**正确行为**，不要按"质押越多、奖励越少"去核对：
  前 17,520 个纪元（= 2 年）内窗口地板 `0.64 = MAX_BLOCK_REWARD` 生效，
  奖励与质押率**无关**。测试网从创世起算，因此**整场测试都在过渡期内**。
  窗口边界（第 12,614,400 槽）在测试网上**不可能提前到达**，
  它由 `tests/test_block.py` 的 3b 与 REWARD 族的 `transition` 向量覆盖
  （详见 `DEPLOYMENT_PLAN.md` §6 的已知限制说明）。

## 阶段 D：稳定性与故障演练（跨机就绪后）

> **前置：** 每个节点都必须带 `--data-dir` 启动（否则重启从创世重来）。
> 重启后判读日志：`── 持久化恢复 ──` 段应显示 `已最终化 N 个区块` 与
> `状态根 … ✅ 与链头承诺一致`。若显示 `✗ 拒绝启动：持久化数据不可信`，
> **不要**删目录了事 —— 先确认两点：① 数据目录是否与当前创世配套；
> ② 磁盘是否被外部改动。确认要重建时才删除该目录下的 `blocks.bin` / `state.bin`。

**本机彩排脚本：** `bash wallet/run_fault_drill.sh wallet/runs/dev-genesis.json 20 wallet/runs/devkeys wallet/runs/drill`
—— 四阶段（正常出块 → `kill -9` 断电 → 同目录重启恢复 → 全部重启比对相同高度哈希），
脚本自带判据并逐条打印 `[OK]/[FAIL]`。**跨机演练请照它的判据手工做一遍**
（本机彩排不能替代真机断电：香橙派的 SD 卡写入路径与 PC 不同）。

| 演练 | 做法 | 观察指标 |
|---|---|---|
| 24h 连续运行 | 常驻跑，记录高度/轮次 | 高度单调、无分叉 |
| 香橙派断电重启 | 直接拔电（**不要**先 Ctrl-C） | 重启后能从磁盘续跑并追平，**不产生双签**；`blocks.bin` 尾部若为半写记录会被自动截断 |
| 单节点长时间离线 | 停一个进程 10 分钟后重启 | 该节点靠 `on_block_batch` 追平（需 ≥3 个节点在线），追平期间无自身双签 |
| 网络抖动 | `tc netem delay 200ms loss 5%` | 仍能出块（C 后端的余量足够） |
| 3/4 在线 | 停掉 PC 上一个进程 | 链**仍出块**（这是 4 验证者配置的意义） |
| 2/4 在线 | 再停一个 | 链**停止出块**但**不分叉**（这是正确行为） |
| 奖励口径核对 | 每 1000 块比对 `total_supply` 增量 | 应恒为 `0.64 AGORA × 有效块数`（过渡期内，§28.4.1） |

最后一条尤其重要：**停摆是安全性正确的表现，不要为了"能继续出块"而放宽规则。**

---

## 附：出问题时的排查顺序

1. 两台机器的 `startup_self_check` 是否都是 ✅？
2. `agora_genesis_build.py --check` 在两台是否都通过？
3. `chain_id` 是否两台都是 `agora-testnet-1`？
4. 代码是否同一 commit？
5. 只有以上都对，才去怀疑共识逻辑 —— 前四项占了实际故障的绝大多数。

## 附一之二：故障演练的判据怎么读（含三个"别被骗"的坑）

| 坑 | 现象 | 正确做法 |
|---|---|---|
| 拿**周期报告**的高度跨节点比较 | 节点间"相差上百块"，看着像分叉 | 只能用**收尾时打印的最终链长**；跨节点比较必须用**相同高度的区块哈希**（`--dump-height`） |
| 用 `$(start_node ...)` 取 PID | `wait` 立刻返回，脚本在节点刚启动时读日志 ⇒ 全读成"未报告" | PID 用变量回传、**直接调用**函数（命令替换在子 shell 里启动进程） |
| 相同高度哈希比对时先去重再计数 | 四节点一致时被去重成 1 行 ⇒ 假失败 | **先计数、后去重** |
| 判据写成"其余节点最终高度 > 被杀节点高度" | 杀得早、被杀者刚追赶上来时会误判 | 判据应是"**杀掉一个之后，其余节点继续增长**"（3/4 仍达法定数） |

## 附二：持久化目录结构与排障

```
<data-dir>/
  blocks.bin     # 追加写；每条记录 = 长度前缀 + 区块 RLP + 校验和；每块 fsync
  state.bin      # 状态快照 v2（含链头 Commit）；先写临时文件再原子重命名
```

判读要点：

* **重启不追加重复创世块**：早期版本每次启动都会把创世块再追加一次
  （实测在记录 768 处出现高度 0 的重复块）。现在启动顺序是"**先读文件、
  再决定是否补写创世**"，这一条有回归测试守着。
* **快照与区块日志必须自洽**：恢复走"快照 + 重放剩余区块"，
  最终状态根必须等于链头承诺的状态根；不相等即拒绝启动。
* **`--snapshot-every` 决定落盘频率**（默认 1000）：值越小重启越快、
  写盘越多；断电演练时可调小到 100 以便观察。
* **磁盘满/写失败**：节点会拒绝继续并把错误打在前台 —— 这是刻意的
  （宁可停下，也不要"内存里是对的、磁盘上是错的"）。
