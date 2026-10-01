# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 协议参数
==================================

本模块是规范 §34「参数表（全量，无 TBD）」的**代码化**。每一项都标注了规范条目号。

硬性约定
--------
1. **任何实现都不得修改本文件的取值**。改参数 = 改协议 = 必须走 §36 冻结规则
   （原因 / 受影响参数 / 安全影响 / 活性影响 / 经济影响 / 兼容性 / 测试变更 / 规范 diff
   + 人类协议负责人批准）。
2. 本文件与规范文本的一致性由 `tests/test_params.py` 自动校验：
   它同时检查"代码 == 规范文本"与"代码 == 硬编码期望值"，任何一侧漂移都会失败。
3. 所有金额单位为 **atom**（1 AGORA = 10^18 atom），与规范 §34 A10 一致。
"""

from __future__ import annotations

from typing import Final

# ══════════════════════════════════════════════════════════════════════
# A. 密码学与编码（规范 §34 A）
# ══════════════════════════════════════════════════════════════════════

# <<<CHAINID>>>
# ── 链身份（chain_id）────────────────────────────────────────────────
#
# **主网值在此冻结。** 测试网/开发网通过 `set_network()` 显式切换，
# 且**只能在构建创世之前调用**（见下）。
#
# 为什么必须允许切换：规范 §4 要求测试网使用 `agora-testnet-1` 以防跨链重放；
# 若测试网沿用主网 chain_id，用测试密钥签出的交易在主网上**有效**，
# 这是最容易被忽视也最危险的一类事故。
#
# 为什么必须是显式开关而不是读配置文件：任何"静默生效"的网络切换都可能
# 让节点以为在跑测试网、实际用主网参数（或反之）。因此：
#   · 默认值永远是主网（硬编码、不经任何外部输入）；
#   · 切换必须由调用方**显式**调用；
#   · 切换后若已构建过创世状态则**拒绝**再次切换（防止同一进程内混用两套链身份）。
PROTOCOL_VERSION: Final[str] = "AGORA/v0.2.2"
_MAINNET_CHAIN_ID: Final[str] = "agora-mainnet-1"
CHAIN_ID: str = _MAINNET_CHAIN_ID
# 注意：链身份是**变长**的（`agora-mainnet-1` / `agora-testnet-1` 都是 15 字节）。
# 早期这里写着"20 字节"，与下面的 `CHAIN` 调用混在一起会让人以为它是定宽字段 ——
# 实际编码取决于 §20.1 的 bytes 规则：20/32 字节原样，其余加 `u32(len)` 前缀。
# 这条错误注释曾直接导致握手原像被写成"chain_id 原样"（第九轮，见 PROJECT_REVIEW §16）。
CHAIN_ID_BYTES: bytes = CHAIN_ID.encode("ascii")

# 网络已冻结标记：一旦产生过签名/验签就不得再切换（见 `freeze_network`）
_NETWORK_FROZEN: bool = False
_FREEZE_REASON: str = ""
ALLOWED_NETWORKS: Final[dict] = {
    "mainnet": "agora-mainnet-1",
    "testnet": "agora-testnet-1",
    "devnet": "agora-devnet-1",
}


def set_network(network: str) -> str:
    """切换链身份（**仅测试网/开发网**需要；主网为默认值）。

    返回生效的 `chain_id`。调用约束：

    * `network` ∈ {mainnet, testnet, devnet}；主网即恢复冻结值；
    * **MUST** 在任何签名 / 验签 / 创世构建**之前**调用；
    * 若本进程已调用过 `freeze_network()`（构建创世时会自动调用）则抛
      `RuntimeError` —— 同一进程内混用两套链身份会让签名与验签使用不同的
      `chain_id`，产出**无法被任何人验证**的交易。
    """
    global CHAIN_ID, CHAIN_ID_BYTES
    if _NETWORK_FROZEN:
        raise RuntimeError(
            f"链身份已冻结为 {CHAIN_ID}，不得再切换到 {network}"
            + (f"（冻结原因：{_FREEZE_REASON}）" if _FREEZE_REASON else "")
            + "。如需切换请新起一个进程 —— 同一进程混用两套 chain_id 会让"
              "签名与验签使用不同链身份，产出无法被验证的交易")
    if network not in ALLOWED_NETWORKS:
        raise ValueError(
            f"未知网络：{network!r}（可选：{sorted(ALLOWED_NETWORKS)}）")
    CHAIN_ID = ALLOWED_NETWORKS[network]
    CHAIN_ID_BYTES = CHAIN_ID.encode("ascii")
    return CHAIN_ID


def freeze_network(reason: str = "") -> str:
    """冻结链身份。**首次签名时**自动调用（见 `crypto_backend._on_first_sign`）。

    冻结时机为什么是"首次签名"而不是"构建创世"：构建创世只是**计算**，
    一次进程里可能为多个网络分别试算（工具与测试都这么做）；
    而一旦产生了签名或验签，`chain_id` 就已经渗入到不可撤销的字节里，
    此时再切换必然产出"签名者与验签者用不同链身份"的垃圾数据。
    """
    global _NETWORK_FROZEN, _FREEZE_REASON
    _NETWORK_FROZEN = True
    _FREEZE_REASON = reason or _FREEZE_REASON
    return CHAIN_ID


def reset_network_for_tests() -> str:
    """**仅供测试与工具**：解除冻结并恢复主网默认值。

    名字里带 `for_tests` 是刻意的：它必须显眼到不会被误用于生产代码路径。
    生产代码**MUST NOT** 调用它 —— 它存在的唯一理由是让同一个测试进程
    能够分别验证主网与测试网两条路径（否则第一次构建创世后就再也切不回来，
    而链身份是进程级全局量）。
    """
    global CHAIN_ID, CHAIN_ID_BYTES, _NETWORK_FROZEN, _FREEZE_REASON
    CHAIN_ID = _MAINNET_CHAIN_ID
    CHAIN_ID_BYTES = CHAIN_ID.encode("ascii")
    _NETWORK_FROZEN = False
    _FREEZE_REASON = ""
    return CHAIN_ID


def network_frozen() -> bool:
    """链身份是否已冻结（供启动自检与测试断言）。"""
    return _NETWORK_FROZEN


def network_name() -> str:
    """当前链身份对应的网络名（无法识别时返回 `"unknown"`）。"""
    for _name, _cid in ALLOWED_NETWORKS.items():
        if _cid == CHAIN_ID:
            return _name
    return "unknown"
# <<<END>>>

ATOM_PER_AGORA: Final[int] = 10 ** 18                            # A9
NAGORA_PER_AGORA: Final[int] = 10 ** 9                           # A9：nAGORA 仅展示用
U256_MAX: Final[int] = 2 ** 256 - 1                              # A10

# 域标签（规范 §20.4，A7）
TAG_TX: Final[bytes] = b"AGORA/TX/v0.2.2"
TAG_PREVOTE: Final[bytes] = b"AGORA/PREVOTE/v0.2.2"
TAG_PRECOMMIT: Final[bytes] = b"AGORA/PRECOMMIT/v0.2.2"
TAG_PROPOSAL: Final[bytes] = b"AGORA/PROPOSAL/v0.2.2"
TAG_EVIDENCE_TX: Final[bytes] = b"AGORA/EVIDENCE-TX/v0.2.2"
TAG_EPOCH_SEED: Final[bytes] = b"AGORA/EPOCH-SEED/v0.2.2"
TAG_PROPOSER: Final[bytes] = b"AGORA/PROPOSER/v0.2.2"
TAG_VALSET: Final[bytes] = b"AGORA/VALSET/v0.2.2"
TAG_GENESIS: Final[bytes] = b"AGORA/GENESIS/v0.2.2"
TAG_AIRDROP: Final[bytes] = b"AGORA/AIRDROP/v0.2.2"

# ══════════════════════════════════════════════════════════════════════
# B. 链与时间（规范 §34 B、§5）
# ══════════════════════════════════════════════════════════════════════

GENESIS_TIMESTAMP: Final[int] = 1790812800          # B4：2026-10-01 00:00:00 UTC
SLOT_TIME: Final[int] = 5                           # B3
EPOCH_LENGTH: Final[int] = 720                      # B7
CLOCK_TOLERANCE: Final[int] = 4                     # B5：Δ = 4 槽 = 20 秒

# 时间常量（规范 §5.7；日历天数仅为注释）
SLOTS_PER_DAY: Final[int] = 86400 // SLOT_TIME      # 17,280
SUBJECTIVITY_PERIOD_SLOTS: Final[int] = 14 * SLOTS_PER_DAY          # 241,920
UNBONDING_PERIOD_SLOTS: Final[int] = 21 * SLOTS_PER_DAY             # 362,880
SLASH_WINDOW_SLOTS: Final[int] = 21 * SLOTS_PER_DAY                 # 362,880
PROTOCOL_YEAR_SLOTS: Final[int] = 365 * SLOTS_PER_DAY               # 6,307,200

# ══════════════════════════════════════════════════════════════════════
# C. 共识与验证者（规范 §34 C、§9、§11、§12）
# ══════════════════════════════════════════════════════════════════════

# ── 阶段超时（§11.1）── 固定值（**曾评估"随轮次递增"，实测无增益，已否决**）──
#
# 阶段上限与整轮上限是**两个独立层级**的计时器（§11.3）。
# 高丢包下曾怀疑"阶段上限太紧"是停摆主因，因此评估过让它们与
# `ROUND_TIMEOUT(r)` 同构地递增。**实测否决：**
#
# | 策略（均已开启有界重传） | 丢包 20% | 30% | 40% |
# |---|---|---|---|
# | 阶段上限随轮次递增 | 10/10 | 10/10 | 10/10 |
# | 固定 3/2/2 秒（本实现） | 10/10 | 10/10 | 10/10 |
#
# 两者**完全相同** ⇒ 瓶颈不在时间预算，而在"丢包后消息永不重传"。
# 修复落在通信层（`Node._retransmit`），共识参数因此**保持原样**（FROZEN）。
PROPOSAL_TIMEOUT_MS: Final[int] = 3000              # C5
PREVOTE_TIMEOUT_MS: Final[int] = 2000               # C5
PRECOMMIT_TIMEOUT_MS: Final[int] = 2000             # C5
BASE_TIMEOUT_MS: Final[int] = 7000                  # C6：独立常量，**不是** 3000+2000+2000
ROUND_TIMEOUT_INCREMENT_MS: Final[int] = 500        # C7
MAX_ROUND_WINDOW: Final[int] = 64                   # C10：消息处理上界（轮次本身无上界）

MIN_VALIDATOR_STAKE: Final[int] = 64 * ATOM_PER_AGORA   # C11
MAX_VALIDATORS: Final[int] = 100                        # C12
MIN_ACTIVE_VALIDATORS: Final[int] = 3                   # C19/F10：低于此值链 halt

FOUNDER_PERIOD_EPOCHS: Final[int] = 8760            # F8：约 1 年
GENESIS_VALIDATOR_COUNT: Final[int] = 4             # §32.7：≥4 且每人 < 总量/3

# ══════════════════════════════════════════════════════════════════════
# D. 惩罚 / 罚没（规范 §34 D、§13、§15）
# ══════════════════════════════════════════════════════════════════════

# 罚没比例以 ppm 表示（1 ppm = 1/1,000,000），算式见规范 §15.1
SLASH_RATE_PPM: Final[dict] = {                     # D1/D2/D3
    "DOUBLE_PREVOTE": 300_000,      # 5%
    "DOUBLE_PRECOMMIT": 300_000,    # 5%
    "SEVERE": 600_000,              # 10%
    "INVALID_PROPOSAL": 60_000,     # 1%
}
SLASH_PPM_DENOMINATOR: Final[int] = 6_000_000       # 规范 §15.1 的固定分母
SLASH_MAX_DEDUCTION_PPM: Final[int] = 1_000_000     # D4：单次扣除不超过基数的 100%
EVIDENCE_REWARD_PPM: Final[int] = 200_000           # D8：20%
EVIDENCE_BURN_PPM: Final[int] = 800_000             # D8：80%
SETTLED_SLASH_RETENTION_SLOTS: Final[int] = 2 * SLASH_WINDOW_SLOTS   # D6：保留 2 倍窗口

UNBOND_COMPLETION_EPSILON_SLOTS: Final[int] = EPOCH_LENGTH           # D11：ε = 720 槽

INACTIVITY_WINDOW: Final[int] = 100                 # D13：连续未参与的已最终化高度数
INACTIVITY_PENALTY_BASE_PPM: Final[int] = 1         # D14：1 ppm = 0.0001%
INACTIVITY_PENALTY_CAP: Final[int] = 64             # D14：指数封顶 2^(k-1) ≤ 64
JAIL_ENABLED: Final[bool] = False                   # D15

MAX_EVIDENCE_PER_BLOCK: Final[int] = 64             # D17

# ══════════════════════════════════════════════════════════════════════
# E. Gas / 费用 / 发行 / 销毁（规范 §34 E、§17、§28）
# ══════════════════════════════════════════════════════════════════════

# gas 成本表 G1–G11（规范 §17.1）
GAS_TX_BASE: Final[int] = 21_000            # G1
GAS_PER_NONZERO_BYTE: Final[int] = 16       # G2
GAS_PER_ZERO_BYTE: Final[int] = 4           # G3
GAS_ACCOUNT_CREATION: Final[int] = 25_000   # G4
GAS_BOND: Final[int] = 50_000               # G5
GAS_UNBOND: Final[int] = 5_000              # G6
GAS_REBOND: Final[int] = 5_000              # G6
GAS_EVIDENCE_BASE: Final[int] = 50_000      # G7
GAS_EVIDENCE_PER_SIG: Final[int] = 3_000    # G8
GAS_WITHDRAW: Final[int] = 5_000            # G9
GAS_AIRDROP_CLAIM: Final[int] = 5_000       # G10
GAS_ED25519_VERIFY: Final[int] = 3_000      # G11（已含于 G1，不重复计）

TARGET_GAS_PER_BLOCK: Final[int] = 5_000_000        # E2
MAX_GAS_PER_BLOCK: Final[int] = 10_000_000          # E2
INITIAL_BASE_FEE: Final[int] = 1 * NAGORA_PER_AGORA         # E3：1 nAGORA/gas
MIN_BASE_FEE: Final[int] = 1 * NAGORA_PER_AGORA             # E3
BASE_FEE_CHANGE_DENOMINATOR: Final[int] = 8                 # E4：12.5%
BASE_FEE_DIVISOR: Final[int] = TARGET_GAS_PER_BLOCK * BASE_FEE_CHANGE_DENOMINATOR   # 40,000,000

INITIAL_SUPPLY: Final[int] = 20_480_000 * ATOM_PER_AGORA    # E17

# 发行曲线（规范 §28.4；BUG-33 修复后的因子化定义）
BASE_BLOCK_REWARD: Final[int] = 16 * 10 ** 16               # 0.16 AGORA
TARGET_STAKED_PPM: Final[int] = 600_000                     # 目标质押率 60%（ppm）
# MIN_BLOCK_REWARD：0.17（BUG-33 的 1(b) 定值）→ **0.20 AGORA（所有者决策 D-5）**。
#
# 为什么改（实测，见规范 §37C.3）：GATE-6 的验收范围为**丢槽率 ≤ 10%**（声明的运行包线），
# 并要求包线内 `NetValidatorRevenue ≥ +0.5` 个百分点（余量用于覆盖"5% 年度销毁是否应
# 全额计入验证者成本"这一口径争议）。包线内最差点出现在「丢槽 10% + 质押率 100%」：
#     净收益 = (MIN × 6,307,200 / INITIAL_SUPPLY × 100) × (1 − 10%) − 5
# 取 0.17 时该点为 **−0.288%**（即"只收窄验收范围"并不够，必须同时调参数）；
# 解 `(r/S×100)×0.9 − 5 ≥ 0.5` 得 r ≥ 0.1984 AGORA，故取整为 **0.20**（该点 +0.543%）。
# 副产物：曲线触底点由质押率 56.47% 前移到 **48.00%**（NUMERATOR / 0.20 / INITIAL_SUPPLY），
# 是个便于记忆的整数。本次调整只在质押率 ≥48% 时生效 ⇒ 对引导期（<15%）**无任何影响**。
MIN_BLOCK_REWARD: Final[int] = 20 * 10 ** 16                # E12：0.20 AGORA（D-5）
MAX_BLOCK_REWARD: Final[int] = 64 * 10 ** 16                # E12：0.64 AGORA
# NUMERATOR = BASE × TARGET × INITIAL_SUPPLY，用整数运算避免浮点误差
BLOCK_REWARD_NUMERATOR: Final[int] = (
    BASE_BLOCK_REWARD * TARGET_STAKED_PPM * INITIAL_SUPPLY // 1_000_000
)

# 过渡期奖励地板（规范 §28.4.1；所有者决策 D-3，裁决记录见 §37E）
#
# **这不是"加发"，而是把发行曲线在前 N 个纪元压成常数。** 依据（实测，见 §28.4.1 表）：
#   · 质押率 ≤ 15.0000% 时曲线被**上限**截断为 `MAX_BLOCK_REWARD = 0.64 AGORA/块`；
#   · 创世质押率 = 256 / 20,480,000 = 0.00125% ⇒ 曲线当下就处在该截断区，
#     年发行 4,036,608 AGORA = 初始供应的 19.71%/年。
# 因此把过渡期地板设为 `MAX_BLOCK_REWARD` 时，**当下发行量一分不变**，
# 但窗口内的块奖励不再依赖 `StakedSupply` ⇒ 验证者可预期、不会被曲线中途砍掉。
# 取值上界由 self_check 强制：`MIN ≤ TRANSITION_REWARD_FLOOR ≤ MAX`，
# 因为地板高于上限会让 `clamp(·, MIN, MAX)` 语义自相矛盾。
TRANSITION_EPOCHS: Final[int] = 17_520               # E23：= 2 年（与 AIRDROP_END_SLOT 同期）
TRANSITION_REWARD_FLOOR: Final[int] = MAX_BLOCK_REWARD   # E24：0.64 AGORA/块（= 曲线上限）
TRANSITION_END_SLOT: Final[int] = TRANSITION_EPOCHS * EPOCH_LENGTH   # 12,614,400

PROPOSER_REWARD_PPM: Final[int] = 200_000           # E13：20%
ATTESTATION_POOL_PPM: Final[int] = 800_000          # E13：80%
ANNUAL_BURN_RATE_PPM: Final[int] = 50_000           # E18：5%
MAX_YEAR_BURNS_PER_BLOCK: Final[int] = 1            # E19

# GATE-6 的声明验收包线（所有者决策 D-5，规范 §30 / §37C）
ENVELOPE_SLOT_LOSS_PCT: Final[int] = 10             # 包线：丢槽率 ≤ 10%
ENVELOPE_MIN_NET_PCT: Final[float] = 0.5            # 包线内净收益下限（百分点，留出可见余量）

# ══════════════════════════════════════════════════════════════════════
# F. 创世（规范 §34 F、§32）
# ══════════════════════════════════════════════════════════════════════

AIRDROP_MAX_SHARE_PPM: Final[int] = 200_000         # F5：20%
AIRDROP_MAX_SHARE: Final[int] = INITIAL_SUPPLY * AIRDROP_MAX_SHARE_PPM // 1_000_000
AIRDROP_START_SLOT: Final[int] = 0                  # F6
AIRDROP_END_SLOT: Final[int] = 12_614_400           # F6：约 2 年
AIRDROP_VAULT_ADDRESS: Final[bytes] = b"\x00" * 20  # §32.5：无私钥的空地址
SYSTEM_ADDRESS: Final[bytes] = b"\x00" * 19 + b"\x01"   # §19.5：0x…0001

# 创世占位（GATE-11 通过前不得用于主网）
PENDING_MARKER: Final[str] = "PENDING-MAINNET-VALUE"


# ══════════════════════════════════════════════════════════════════════
# 派生量（唯一权威算式；实现不得另行推导）
# ══════════════════════════════════════════════════════════════════════

def epoch_of(slot: int) -> int:
    """规范 §5.7：`epoch_of(slot) = floor(slot / 720)`"""
    if slot < 0:
        raise ValueError("slot 必须非负")
    return slot // EPOCH_LENGTH


def epoch_slots(epoch: int) -> tuple:
    """规范 §5.7：`epoch_slots(E) = [E×720, (E+1)×720 − 1]`"""
    return (epoch * EPOCH_LENGTH, (epoch + 1) * EPOCH_LENGTH - 1)


def block_timestamp(slot: int) -> int:
    """规范 §5.4：`timestamp == GenesisTimestamp + claimed_slot × SLOT_TIME`"""
    return GENESIS_TIMESTAMP + slot * SLOT_TIME


def seconds_until_genesis(local_now: float,
                          genesis_timestamp: int = GENESIS_TIMESTAMP) -> float:
    """规范 §5.3：距创世时刻还有多少秒（≤ 0 表示已到/已过）。

    §5.3 原文：**任何节点在本地时间早于 `GenesisTimestamp` 时 MUST NOT 提议、投票或接受区块。**

    为什么必须显式实现（BUG-75）：节点的共识时间是**逻辑时钟**（从创世槽 0 起算），
    它与真实日期无关。因此在"逻辑时钟"里永远"已经过了创世"，
    未来创世时间的链照样出块 —— 该禁令如果不与**墙钟**比较，就等于没有。
    实测：用 `GenesisTimestamp = 2026-10-01`（当时还有 14 小时）的创世启动 4 节点，
    45 秒内产出了 820 个区块。
    """
    return float(genesis_timestamp) - float(local_now)


def round_timeout_ms(r: int) -> int:
    """规范 §11.2：`ROUND_TIMEOUT(r) = 7 秒 + r × 500 毫秒`

    注意：**不得**用三阶段超时相加推导本值（规范 §11.3 明确禁止）。
    """
    if r < 0:
        raise ValueError("round 必须非负")
    return BASE_TIMEOUT_MS + r * ROUND_TIMEOUT_INCREMENT_MS


PHASE_TIMEOUT_BASE_MS: Final[dict] = {
    "proposal": PROPOSAL_TIMEOUT_MS,
    "prevote": PREVOTE_TIMEOUT_MS,
    "precommit": PRECOMMIT_TIMEOUT_MS,
}


def phase_timeout_ms(phase: str) -> int:
    """规范 §11.1：阶段超时（**固定值**，与轮次无关）。

    §11.3 规定阶段上限是"**阶段内**推进上限"，整轮上限是"**整轮**推进上限"，
    两者是独立层级、**绝不相加**。阶段上限不随轮次变化；随轮次放宽的是**整轮**
    上限（`round_timeout_ms`）。
    """
    base = PHASE_TIMEOUT_BASE_MS.get(phase)
    if base is None:
        raise ValueError(f"未知阶段：{phase!r}（应为 proposal/prevote/precommit）")
    return base


def quorum(total_voting_power: int) -> int:
    """规范 §9.1：`QUORUM = ceil(2 × S_epoch / 3)`（整数上取整）"""
    if total_voting_power < 0:
        raise ValueError("总投票权必须非负")
    return -(-2 * total_voting_power // 3)


def transition_active(slot: int) -> bool:
    """规范 §28.4.1：过渡期奖励地板是否生效。

    `epoch_of(slot) < TRANSITION_EPOCHS`（等价于 `slot < TRANSITION_END_SLOT`）。

    **必须以区块头里被签名的 `claimed_slot` 为输入**（§5.4.1），
    不得用本地墙钟 —— 否则两个节点会对同一区块算出不同奖励 ⇒ 状态根分叉。
    """
    if slot < 0:
        raise ValueError("slot 必须非负")
    return slot < TRANSITION_END_SLOT


def curve_block_reward(staked_supply: int) -> int:
    """规范 §28.4：**恒定发行曲线**（不含过渡期地板）。

    `BLOCK_REWARD = clamp(floor(NUMERATOR / StakedSupply), MIN, MAX)`

    · `StakedSupply == 0` 时返回 `MAX_BLOCK_REWARD`（链此时应已 halt，见 §7.7）
    · 质押率 60% 处曲线值为 0.16 AGORA；因 `MIN_BLOCK_REWARD = 0.20` 更高，
      曲线在 **48.00%** 处触底，此后恒为 0.20 AGORA
    · 质押率 ≤ 15.0000% 处曲线被**上限**截断，此后恒为 0.64 AGORA
      （即：曲线上界区间的反馈完全失效，这正是需要过渡期地板的实测依据）
    """
    if staked_supply < 0:
        raise ValueError("质押总量必须非负")
    if staked_supply == 0:
        return MAX_BLOCK_REWARD
    raw = BLOCK_REWARD_NUMERATOR // staked_supply
    return max(MIN_BLOCK_REWARD, min(MAX_BLOCK_REWARD, raw))


def block_reward(staked_supply: int, slot: int) -> int:
    """规范 §28.4 / §28.4.1：区块的发行额（共识关键，两个实现必须逐 atom 一致）。

    ```
    base = curve_block_reward(StakedSupply)
    return max(base, TRANSITION_REWARD_FLOOR) if transition_active(slot) else base
    ```

    `slot` **MUST** 是本块的 `claimed_slot`（区块头字段，被提案者签名、被
    §5.2 的时钟上界校验），不得是本地时间、不得是父块槽、不得省略。
    签名刻意**不提供默认值**：漏传参数必须报错，而不是静默按曲线或按过渡期计算。

    `TRANSITION_REWARD_FLOOR == MAX_BLOCK_REWARD`（当前取值）时，过渡期内
    `base` 与地板取大恒为 `MAX_BLOCK_REWARD` ⇒ **窗口内发行量与质押率无关**。
    """
    base = curve_block_reward(staked_supply)
    if transition_active(slot):
        return max(base, TRANSITION_REWARD_FLOOR)
    return base


def gas_used_for_tx(tx_type: int, payload_len: int, zero_bytes: int,
                    nonzero_bytes: int, creates_account: bool) -> int:
    """规范 §17.1 的 gas 计算。`zero_bytes + nonzero_bytes` 必须等于 `payload_len`。"""
    if zero_bytes + nonzero_bytes != payload_len:
        raise ValueError("零/非零字节数之和必须等于载荷长度")
    total = GAS_TX_BASE
    total += nonzero_bytes * GAS_PER_NONZERO_BYTE
    total += zero_bytes * GAS_PER_ZERO_BYTE
    if creates_account:
        total += GAS_ACCOUNT_CREATION
    total += {
        0x02: GAS_BOND,
        0x03: GAS_UNBOND,
        0x04: GAS_REBOND,
        0x06: GAS_WITHDRAW,
        0x07: GAS_AIRDROP_CLAIM,
    }.get(tx_type, 0)
    return total


def ceil_div(a: int, b: int) -> int:
    """整数上取整。规范 §17.4 明确禁止浮点运算。"""
    if b <= 0:
        raise ValueError("除数必须为正")
    return -(-a // b)


def base_fee_next(bf: int, gas_used: int) -> int:
    """规范 §17.4 的**唯一权威**基础费更新算式。

    上升分支下取整、下降分支上取整，并各自以 `max(1, …)` 保底；
    下降结果不得低于 `MIN_BASE_FEE`。

    ⚠ 不得改用"近似步长"（如 `step = bf // DIVISOR` 再乘 gas 偏差）：
       那与规范结果在 `bf` 较大时相差可达数百万倍。
    """
    if bf < MIN_BASE_FEE:
        raise ValueError("基础费不得低于 MIN_BASE_FEE")
    if gas_used > TARGET_GAS_PER_BLOCK:
        delta = max(1, (bf * (gas_used - TARGET_GAS_PER_BLOCK)) // BASE_FEE_DIVISOR)
        return bf + delta
    if gas_used < TARGET_GAS_PER_BLOCK:
        delta = max(1, ceil_div(bf * (TARGET_GAS_PER_BLOCK - gas_used), BASE_FEE_DIVISOR))
        return max(MIN_BASE_FEE, bf - delta)
    return bf


def slash_amount(recorded_base: int, evidence_class: str) -> int:
    """规范 §15.1：`floor(recorded_base × rate / 6,000,000)`"""
    if evidence_class not in SLASH_RATE_PPM:
        raise ValueError(f"未知的罚没类别：{evidence_class}")
    return recorded_base * SLASH_RATE_PPM[evidence_class] // SLASH_PPM_DENOMINATOR


def split_proposer_attestation(amount: int) -> tuple:
    """规范 §28.2：提案者 20% / 见证池 80%，**余数归提案者**（避免尘埃）。"""
    pool = amount * ATTESTATION_POOL_PPM // 1_000_000
    return amount - pool, pool


def inactivity_penalty_sum(k: int) -> int:
    """规范 §13.2 的 `p`：`Σ_{j=1..k} 1,000,000 × min(2^(j−1), 64)`（精确整数和）。

    注意量纲：这里的 `p` 尚未除以 `10^6`，因此 `k=1` 时 `p = 1,000,000`。
    真正表示"损失比例"的是 `inactivity_penalty_ppm(k)`。
    """
    if k < 0:
        raise ValueError("连续漏槽数必须非负")
    total = 0
    for j in range(1, k + 1):
        total += 1_000_000 * min(2 ** (j - 1), INACTIVITY_PENALTY_CAP)
    return total


def inactivity_penalty_ppm(k: int) -> int:
    """连续漏槽 `k` 个高度所造成的损失比例，单位 ppm（1 ppm = 0.0001%）。

    规范 §13.2 的注入比例 = `p / 10^6`，故本函数返回 `p / 10^6`（以 ppm 计）。
    核验：k=1 → 1 ppm；k=64 → 3,775 ppm；k=100 → 6,079 ppm。
    """
    return inactivity_penalty_sum(k) // 1_000_000


def inactivity_deduction(stake: int, k: int) -> int:
    """规范 §13.2 的扣除额（atom）：
        `floor(stake / 10^6) × min(p / 10^6, k × 64)`
    """
    return (stake // 1_000_000) * min(INACTIVITY_CAP_DIVISOR(k), k * INACTIVITY_PENALTY_CAP)


def INACTIVITY_CAP_DIVISOR(k: int) -> int:      # noqa: N802（与规范记号对应）
    """`min(p / 10^6, k × 64)`，其中 `p = inactivity_penalty_sum(k)`。"""
    return min(inactivity_penalty_sum(k) // 1_000_000,
               k * INACTIVITY_PENALTY_CAP)


# ══════════════════════════════════════════════════════════════════════
# 启动自检：把"参数之间的关系"变成不可绕过的断言
# ══════════════════════════════════════════════════════════════════════

def _self_check() -> None:
    # 时间换算必须精确（无余秒），否则槽数与日历天数会漂移
    assert SLOT_TIME == 5
    assert 14 * 86400 % SLOT_TIME == 0 and 21 * 86400 % SLOT_TIME == 0
    assert SUBJECTIVITY_PERIOD_SLOTS * SLOT_TIME == 14 * 86400
    assert UNBONDING_PERIOD_SLOTS * SLOT_TIME == 21 * 86400
    assert PROTOCOL_YEAR_SLOTS * SLOT_TIME == 365 * 86400

    # 超时模型：轮次超时是**独立常量**（规范 §11.3 禁止从三阶段推导）。
    # 注意：BASE_TIMEOUT_MS 的数值恰好等于 3000+2000+2000 = 7000，这是巧合。
    # 因此这里**不能**断言"两者不等" —— 那会让实现误以为必须修改数值。
    # 真正要保证的是：它们是不同层级的计时器，且轮次超时按 500 ms 线性增长。
    assert BASE_TIMEOUT_MS == 7000 and ROUND_TIMEOUT_INCREMENT_MS == 500
    assert round_timeout_ms(0) == 7000 and round_timeout_ms(1) == 7500
    assert PROPOSAL_TIMEOUT_MS == 3000 and PREVOTE_TIMEOUT_MS == 2000 \
        and PRECOMMIT_TIMEOUT_MS == 2000
    # §11.3 的层级关系：每个阶段上限必须是**固定值**，且**任何轮次下都不超过**
    # 整轮上限（阶段是整轮之内的推进上限，不得反过来包住整轮）。
    assert phase_timeout_ms("proposal") == 3000
    assert phase_timeout_ms("prevote") == 2000
    assert phase_timeout_ms("precommit") == 2000
    for _r in (0, 1, 2, 10, 40, 100, 1000, 100000):
        for _p in ("proposal", "prevote", "precommit"):
            assert phase_timeout_ms(_p) <= round_timeout_ms(_r), (
                f"阶段上限超过整轮上限：{_p} r={_r}")

    # 创世分配闭合（规范 §32.2）
    assert AIRDROP_MAX_SHARE + (INITIAL_SUPPLY - AIRDROP_MAX_SHARE) == INITIAL_SUPPLY
    assert AIRDROP_MAX_SHARE == 4_096_000 * ATOM_PER_AGORA

    # 4 名创始验证者的法定数性质（规范 §32.7）
    _s = GENESIS_VALIDATOR_COUNT * MIN_VALIDATOR_STAKE
    _q = quorum(_s)
    assert GENESIS_VALIDATOR_COUNT >= 4
    assert MIN_VALIDATOR_STAKE < _q, "单人不得单独达成法定数（防独裁）"
    assert (GENESIS_VALIDATOR_COUNT - 1) * MIN_VALIDATOR_STAKE >= _q, \
        "任一验证者离线后仍须能出块（防单点停机）"

    # 发行曲线：上下界与触底点（**恒定曲线**，不含过渡期地板）
    assert MIN_BLOCK_REWARD <= MAX_BLOCK_REWARD, "clamp 的上下界顺序颠倒"
    assert curve_block_reward(INITIAL_SUPPLY * 60 // 100) == MIN_BLOCK_REWARD
    assert curve_block_reward(INITIAL_SUPPLY) == MIN_BLOCK_REWARD
    assert curve_block_reward(1) == MAX_BLOCK_REWARD
    # 触底点与上限截断点（两处反馈失效边界的解析位置）
    assert BLOCK_REWARD_NUMERATOR / MIN_BLOCK_REWARD / INITIAL_SUPPLY == 12 / 25, \
        "曲线触底点应恰为质押率 48%（D-5）"
    assert BLOCK_REWARD_NUMERATOR // MAX_BLOCK_REWARD == INITIAL_SUPPLY * 15 // 100, \
        "上限截断点应恰为质押率 15%"

    # ── GATE-6 包线不变量（所有者决策 D-5）──
    # 声明的验收包线：丢槽率 ≤ ENVELOPE_SLOT_LOSS_PCT；要求包线内
    # `NetValidatorRevenue ≥ ENVELOPE_MIN_NET_PCT` 个百分点。
    # 此处用**最保守**口径自检：① 优先费按 0 计（§30 允许利用率 0%）；
    # ② 取包线内最差组合（丢槽 10% + 质押率 100%）。参数一旦被改小，导入即失败。
    for _pct in (10, 30, 45, 48, 56.5, 60, 75, 90, 100):
        _staked = int(INITIAL_SUPPLY * _pct / 100)
        _annual = curve_block_reward(_staked) * PROTOCOL_YEAR_SLOTS / ATOM_PER_AGORA
        _gross = _annual / (_staked / ATOM_PER_AGORA) * 100
        _net = _gross * (1 - ENVELOPE_SLOT_LOSS_PCT / 100) - ANNUAL_BURN_RATE_PPM / 10_000
        assert _net >= ENVELOPE_MIN_NET_PCT, (
            f"包线内净收益不足：质押率 {_pct}% 丢槽 {ENVELOPE_SLOT_LOSS_PCT}% → "
            f"{_net:+.4f}pp < {ENVELOPE_MIN_NET_PCT}pp（见规范 §37C.3）")

    # 过渡期奖励地板（规范 §28.4.1）
    assert TRANSITION_EPOCHS >= 0
    assert MIN_BLOCK_REWARD <= TRANSITION_REWARD_FLOOR <= MAX_BLOCK_REWARD, \
        "过渡期地板必须落在 [MIN_BLOCK_REWARD, MAX_BLOCK_REWARD] 内"
    assert TRANSITION_END_SLOT == TRANSITION_EPOCHS * EPOCH_LENGTH
    # 设计耦合：过渡窗口与空投窗口同期（均为 2 年）。若故意不同，**必须**同步
    # 更新本断言与规范 §28.4.1/§32.5 的说明，不得静默漂移。
    assert TRANSITION_END_SLOT == AIRDROP_END_SLOT, "过渡期与空投窗口应同为 2 年"
    # 边界行为：末槽仍在过渡期、首槽已回到曲线
    assert transition_active(0) and transition_active(TRANSITION_END_SLOT - 1)
    assert not transition_active(TRANSITION_END_SLOT)
    for _s in (1, INITIAL_SUPPLY * 15 // 100, INITIAL_SUPPLY * 60 // 100, INITIAL_SUPPLY):
        assert block_reward(_s, 0) == max(curve_block_reward(_s), TRANSITION_REWARD_FLOOR)
        assert block_reward(_s, TRANSITION_END_SLOT - 1) \
            == max(curve_block_reward(_s), TRANSITION_REWARD_FLOOR)
        assert block_reward(_s, TRANSITION_END_SLOT) == curve_block_reward(_s)
        assert block_reward(_s, TRANSITION_END_SLOT + 7_200) == curve_block_reward(_s)
    # 当前取值下（地板 == 上限）过渡期内发行量与质押率**无关**
    assert TRANSITION_REWARD_FLOOR == MAX_BLOCK_REWARD
    assert block_reward(1, 0) == block_reward(INITIAL_SUPPLY, 0) == MAX_BLOCK_REWARD
    # 缺 slot 参数必须报错，不得静默取默认
    try:
        block_reward(1)                                      # type: ignore[call-arg]
    except TypeError:
        pass
    else:
        raise AssertionError("block_reward 必须强制要求 slot 参数")

    # 基础费：地板与单块上限
    assert base_fee_next(MIN_BASE_FEE, 0) == MIN_BASE_FEE
    assert base_fee_next(MIN_BASE_FEE, MAX_GAS_PER_BLOCK) == MIN_BASE_FEE + 125_000_000
    assert base_fee_next(MIN_BASE_FEE, TARGET_GAS_PER_BLOCK) == MIN_BASE_FEE

    # 罚没比例
    assert slash_amount(64 * ATOM_PER_AGORA, "DOUBLE_PREVOTE") == 3_200_000_000_000_000_000
    assert slash_amount(64 * ATOM_PER_AGORA, "SEVERE") == 6_400_000_000_000_000_000
    assert slash_amount(64 * ATOM_PER_AGORA, "INVALID_PROPOSAL") == 640_000_000_000_000_000

    # 系统地址与金库地址不得相同
    assert SYSTEM_ADDRESS != AIRDROP_VAULT_ADDRESS
    assert len(SYSTEM_ADDRESS) == 20 and len(AIRDROP_VAULT_ADDRESS) == 20

    # 链身份：导入期**必须**是主网（任何静默切换都是事故）
    assert CHAIN_ID == _MAINNET_CHAIN_ID == "agora-mainnet-1"
    assert CHAIN_ID_BYTES == b"agora-mainnet-1"
    assert set(ALLOWED_NETWORKS) == {"mainnet", "testnet", "devnet"}
    assert len(set(ALLOWED_NETWORKS.values())) == 3, "三个网络的 chain_id 必须互不相同"


_self_check()

__all__ = [n for n in dir() if not n.startswith("_")]
