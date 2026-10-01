# `wallet/` —— 创世钱包、创世配置与本机运行产物

> **这个目录里有私钥。** 先读第 3 节，再动里面的任何文件。

---

## 1. 这里有什么

| 路径 | 内容 | 能否公开 | 权限 |
|---|---|---|---|
| `dev_wallets.csv` | 100 个开发者奖励钱包的**公开**分配表（地址/公钥/数量/权重） | ✅ 可公开 | 644 |
| `dev_balances.csv` | 同上，只保留 `公钥,数量` 两列，供创世构建器使用 | ✅ | 644 |
| `ALLOCATION_REPORT.md` | 分配报告：总数、分布、复现方法、治理提醒 | ✅ | 644 |
| `keys/dev_wallets_keys.json` | **100 个钱包的私钥** | ❌ 绝不可 | 600 |
| `founder/key1..4.seed` | **4 把创始验证者私钥**（共识密钥，必须在线） | ❌ 绝不可 | 600 |
| `founder/key1..4.pub.json` | 对应公钥/地址 | ✅ | 644 |
| `founder/validators.csv` | 创世验证者名单（公钥 + 64 AGORA 质押） | ✅ | 644 |
| `founder/handoff/founder_1..3.txt` | 交给他人的**交接单**（含该人私钥） | ❌ 一对一交付 | 600 |
| `treasury/key1.seed` | **国库私钥**（89.9988% 的供应量）—— 应当**离线** | ❌ 绝不可 | 600 |
| `genesis.testnet.json` | 测试网创世（`chain_id = agora-testnet-1`） | ✅ | 644 |
| `genesis.mainnet-params.json` | **主网参数**创世（`agora-mainnet-1`，创世时刻 2026-10-01 00:00 UTC） | ✅（带 DEV-UNSAFE 标记） | 644 |
| `run_local_cluster.sh` | 本机 4 节点集群启动器 | ✅ | 755 |
| `runs/` | 历次运行的节点日志 | ✅ | 644 |

---

## 2. 一分钟上手

```bash
cd <仓库根>

# ① 复核创世（**每台机器都必须做**，哈希不一致就不要启动）
python3 tools/agora_genesis_build.py --check wallet/genesis.testnet.json

# ② 本机起 4 节点（真 TCP，环回地址），跑 70 秒，并在高度 800 比对区块哈希
#    注意：第 5 个参数是**私钥目录**。4 把验证者私钥在离线介质上，
#    本机要用临时开发密钥跑，就先按下节生成一套。
#    ⚠ `wallet/runs/` **已被 .gitignore 排除**（里面是本机运行数据与临时私钥），
#      因此克隆仓库后**没有** wallet/runs/devkeys 与 dev-genesis.json，必须自行生成。
bash wallet/run_local_cluster.sh wallet/genesis.testnet.json 70 testnet 800 [私钥目录]

# 用现成的开发密钥 + 开发创世（验证者私钥已离线时的标准做法）：
bash wallet/run_local_cluster.sh wallet/runs/dev-genesis.json 70 devrun 800 wallet/runs/devkeys

# ③ 校验 100 个钱包的链上余额与分配表是否一致
python3 tools/agora_dev_wallet.py check-genesis \
    --genesis wallet/genesis.testnet.json --table wallet/dev_wallets.csv
```

最近一次运行（`wallet/runs/devrun-run.txt`，编码修订后用开发密钥重跑）实测：

```
4 节点 → 高度 1261，四个节点的状态根完全相同
高度 800 的区块哈希：四个节点完全一致 ✅（这才是"无分叉"的有效证据）
供应量守恒 ✅
```

> ⚠️ **不要用"各自的高度 + 链头"比较来判定分叉** —— 节点进度天然不同，
> 那样比较会得到错误的结论。必须**在同一高度**比较区块哈希
> （`run_local_cluster.sh` 的第 4 个参数就是比对高度）。

---

## 3. 私钥纪律（照做，不要问为什么）

1. **`*.seed` 与 `keys/` 永不进仓库、云盘、聊天、截图。** `.gitignore` 已排除，
   但"提交过一次"就等于永久泄露（Git 历史删不干净）。
2. **生成后立刻转移到离线介质**（纸质抄写 + U 盘各一份），然后删除本机副本。
   本机一旦被入侵，这里的所有账户都会被接管。
3. **验证者密钥与国库密钥分开保管。** 验证者密钥必须**在线**（要签名出块），
   国库密钥应当**离线**（只用它做转账）。
4. **主网前重新生成验证者密钥。** 本次这 4 把是在**同一台机器**上生成的，
   安全假设已被削弱：生成者见过全部私钥。主网的正确流程是——
   **每位开发者在自己机器上生成，只把公钥交给发起人**。
5. **不要"把公钥给开发者让他当验证者"。** 公钥不能签名；要么把**私钥**安全交付给本人
   （本目录的 `founder/handoff/` 就是这个形式），要么让他自己生成再报公钥给你。

---

## 3b. 创世哈希（2026-09-30 重算，**以本表为准**）

终审修复了账户叶值编码（余额曾被 zigzag 翻倍，见 `PROJECT_REVIEW.md` R-1），
**全部状态根因此改变**。重建时**沿用原来的 4 把创始验证者公钥与国库公钥**，
所以你已经转移到离线介质的那批私钥**仍然有效**，只需换用新的创世文件：

| 文件 | chain_id | 创世状态根 | 创世哈希 |
|---|---|---|---|
| `genesis.testnet.json` | `agora-testnet-1` | `0x99649bc8a4197653c85b0275115e7de9f136f0eb86b8863c2e4f7de6e2287e3d` | `0x7032e5f19c2e205aaa48b247dc8323e6ab9d57558fb9267eebddb9771c4d14ea` |
| `genesis.mainnet-params.json` | `agora-mainnet-1` | `0x99649bc8a4197653c85b0275115e7de9f136f0eb86b8863c2e4f7de6e2287e3d` | `0xb44350f29ec211b9cc544275d5867a9a3b850c34c9896078647e53ecb28cbbfd` |

> **私钥已不在本机**（已按第 3 节转移到离线介质）。本目录里现在只有**公钥**材料：
> `founder/validators.csv`（4 把创始公钥）与 `treasury/pubkey.hex`（国库公钥）——
> 重建创世时从旧产物里复原的，用途仅限于重新构建/复核创世。
> 100 个开发者钱包的链上余额已复核：**100/100 一致**。

---

## 4. 关于"主网运行"

* `genesis.mainnet-params.json` 用的是**主网参数**（`agora-mainnet-1`、
  创世时刻 **2026-10-01 00:00:00 UTC**），但它是**本机演练链**，
  产物里带 `DEV-UNSAFE` 标记，**不是**主网发布。
* 规范 §5.3 禁止在创世时刻之前出块。该禁令由启动器用**墙钟**强制：
  在 2026-10-01 00:00 UTC 之前启动会得到

  ```
  ✗ 拒绝启动：本地时间早于创世时间（规范 §5.3）
     还需等待 : 14.33 小时
  ```

* 真正的"主网"还缺三样**代码之外**的东西：4 位**互相独立**的验证者、
  F2 空投表、外部安全审查。详见 `MAINNET_READINESS.md`。

---

## 5. 这个目录是怎么生成的（可复现）

```bash
# ① 100 个开发者钱包 + 随机分配（种子写在 ALLOCATION_REPORT.md 里）
python3 tools/agora_dev_wallet.py gen --count 100 --pool-pct 10 --out-dir wallet \
    --seed-hex <报告里的种子>

# ② 4 把创始验证者密钥（每把一个文件，私钥 0600）
python3 tools/agora_genesis_keygen.py keygen --count 4 --network testnet \
    --note founder --out-dir wallet/founder --stake 64

# ②b 本机联调用的一套临时密钥 + 开发创世（**不要**用于任何公开网络）
#     keygen 会同时写出 validators.csv 与 keyN.pub.json（公钥），供 --peer 与创世构建使用
python3 tools/agora_genesis_keygen.py keygen --count 4 --network testnet \
    --note devrun --out-dir wallet/runs/devkeys --stake 64
python3 tools/agora_genesis_build.py --network testnet \
    --validators wallet/runs/devkeys/validators.csv \
    --reserve-pubkey $(head -2 wallet/runs/devkeys/validators.csv | tail -1 | cut -d, -f1) \
    --out wallet/runs/dev-genesis.json

# ③ 国库密钥（离线保管）
python3 tools/agora_genesis_keygen.py keygen --count 1 --network testnet \
    --note treasury --out-dir wallet/treasury

# ④ 创世（测试网 / 主网参数）
python3 tools/agora_genesis_build.py --network testnet \
    --validators wallet/founder/validators.csv \
    --balances-csv wallet/dev_balances.csv \
    --reserve-pubkey $(cat wallet/treasury/pubkey.hex) \
    --out wallet/genesis.testnet.json

python3 tools/agora_genesis_build.py --network mainnet --dev-mainnet-unsafe \
    --genesis-timestamp 1790812800 \
    --validators wallet/founder/validators.csv \
    --balances-csv wallet/dev_balances.csv \
    --reserve-pubkey $(cat wallet/treasury/pubkey.hex) \
    --out wallet/genesis.mainnet-params.json
```
