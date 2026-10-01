# AGORA · 参考实现（v0.2.2）

AGORA 是一条**槽原生（slot-native）的 BFT 链**参考实现：Python 参考实现 +
Node.js 独立实现（用于跨实现逐字节互认）+ 移动端钱包数据层（Dart/Flutter）。
规范见 [`AGORA_v0.2.2_SPEC.md`](AGORA_v0.2.2_SPEC.md)（3,400 行，含 96 条缺陷台账）。

> ⚠ **状态：测试网阶段。未经外部安全审查，主网不具备上线条件。**
> 结论与依据见 [`MAINNET_READINESS.md`](MAINNET_READINESS.md) 与
> [`PROJECT_REVIEW.md`](PROJECT_REVIEW.md)。**不要把本仓库当作已审计的生产软件使用。**

---

## 现在能做什么（都经过自动化验证）

| 能力 | 状态 |
|---|---|
| 4 节点 BFT 共识（真 TCP，§6.7.1 签名握手） | ✅ 多轮实测：四节点同高度区块哈希一致 |
| 链上持久化（区块日志 + 状态快照，崩溃安全） | ✅ 四阶段故障演练 6/6（`kill -9` → 恢复 → 追平 → 无分叉） |
| 交易流转（交易池 + 广播 + 出块打包） | ✅ 真集群：提交给非提案者节点，**0.5 秒进块**，精确回执 |
| 只读查询接口（HTTP JSON，供钱包/浏览器） | ✅ `tools/agora_rpc_server.py`（`--rpc-port`） |
| 空投领取（Merkle 证明 + 双签名） | ✅ 端到端：三笔领取全部上链，金库 3000 → 1000 AGORA |
| 移动端钱包数据层（Dart） | ✅ 取数 + 校验 + 签名（RLP/Keccak/Ed25519），与黄金向量**逐字节一致** |
| 第二实现（Node.js）跨实现互认 | ✅ 165 项逐字节一致（RLP/CHAIN/MPT/握手/签名） |

**仍缺的（如实登记）**：外部安全审查（GATE-8）、公共测试网（GATE-9）、
创始密钥独立生成 + 空投表（GATE-11）、香橙派 aarch64 性能实测、
名字↔连接的签名握手之外的身份加固（见规范 §6.7）。

---

## 快速开始（本机 4 节点，5 分钟）

```bash
# 0) 依赖：Python 3.10+、gcc（编译 Keccak C 后端）。Dart/Flutter 仅钱包需要。
python3 tools/agora_build_native.py          # 编译 C 后端（性能差 400 倍，别跳过）
python3 tools/agora_genesis_keygen.py selftest   # 内置自检（规范算术 + RFC 8032）

# 1) 生成一套本地开发密钥与创世（**这些产物已被 .gitignore 排除**，需自行生成）
python3 tools/agora_genesis_keygen.py keygen --count 4 --network testnet \
    --note devrun --out-dir wallet/runs/devkeys --stake 64
python3 tools/agora_genesis_build.py --network testnet \
    --validators wallet/runs/devkeys/validators.csv \
    --reserve-pubkey <其中一个验证者的公钥> \
    --out wallet/runs/dev-genesis.json

# 2) 起 4 节点集群（真 TCP + 签名握手），并给每个节点开只读查询接口
RPC_BASE=8645 bash wallet/run_local_cluster.sh \
    wallet/runs/dev-genesis.json 120 devrun 0 wallet/runs/devkeys wallet/runs/nodes

# 3) 另一个终端：验证查询接口
curl -s http://127.0.0.1:8645/v1/status | head -c 300
```

## 端到端验证（钱包视角）

```bash
# 起带查询接口的集群（同上），然后：
python3 tools/agora_tx_e2e.py --base-port 8645 --submit-to 8647 \   # 交易：签名→提交→进块→回执
    --expect-chain-id agora-testnet-1

bash wallet/run_fault_drill.sh wallet/runs/dev-genesis.json 15 \      # 故障演练：断电/恢复/追平/无分叉
    wallet/runs/devkeys wallet/runs/drill

bash wallet/prep_airdrop_demo.sh wallet/runs/airdrop-demo             # 带空投的链（可领取）
python3 tools/agora_handshake_probe.py --config wallet/runs/dev-genesis.json \
    --target node4@127.0.0.1:26686@<公钥> --as node1 --seed-file ... --expect reject
```

Dart/Flutter 侧见 [`mobile/agora_wallet_dart/README.md`](mobile/agora_wallet_dart/README.md)
与 [`docs/FLUTTER_INTEGRATION.md`](mobile/agora_wallet_dart/docs/FLUTTER_INTEGRATION.md)。

---

## 全部验证命令（当前结果）

```bash
python3 tools/agora_check_spec.py          # 规范一致性          88/88 ✅
node independent/node/crosscheck.js        # 跨实现（Python⇄Node）165/165 ✅
python3 tools/agora_coverage.py            # 条款↔测试追溯       31/31 断言级 ✅
python3 tools/agora_vectors.py --selftest  # 黄金向量确定性        ✅
for f in tests/test_*.py; do python3 $f; done   # 17 套件 954 项 ✅
cd mobile/agora_wallet_dart && dart analyze && dart run tool/selftest.dart   # 70 项 ✅
```

---

## 仓库结构

```
agora/            参考实现（共识/状态/区块/交易/传输/持久化/交易池/握手）
tools/            命令行工具：节点启动器、查询接口、创世构建、向量、追溯矩阵、端到端脚本
tests/            17 套件 954 项（含黄金向量对齐、故障注入、真 socket、持久化重放）
independent/node/ 第二实现（Node.js）：独立重算编码/状态根/握手/签名并与参考实现互认
vectors/          黄金向量（由参考实现生成，供第二实现与钱包逐字节对齐）
mobile/…/dart     移动端钱包数据层（取数 + 校验 + RLP/Keccak/Ed25519 签名）
wallet/           创世产物与运行脚本（私钥与运行数据**不入库**，见 .gitignore）
native/           Keccak-256 的 C 后端源码（.so 各机器自行编译）
*.md              规范、部署计划、测试网手册、主网就绪度、项目审查记录
```

## 几条设计纪律（为什么代码长这样）

1. **规范是唯一权威**：实现里每一处关键决策都标注规范条款；`agora_check_spec.py`
   会校验"规范声明 == 实现"（含字段数、顺序、字节宽度）。
2. **黄金向量逐字节对齐**：跨实现只看字节，不看"我觉得对"。
3. **不信任边界**：跨机输入、磁盘内容、钱包提交的数据都被当作不可信输入处理。
4. **缺陷台账**：规范里 96 条 BUG 记录（含每条的真实症状与修法），
   `PROJECT_REVIEW.md` 记录每轮修复的动机与证据 —— 包括我们**自己写错**的地方。

## 许可

[Apache License 2.0](LICENSE)（含显式专利授权；Copyright 2026 zy-nycg）。
若你要换成其它许可证（例如 MIT，或改成组织名义），只需替换 `LICENSE` 并同步这一节。
