# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · Gas 与费用
====================================

对应规范：
    §17.1  gas 成本表 G1–G11
    §17.2  EIP-1559 费用语义
    §17.3  基础费上下限
    §17.4  基础费整数更新算式（唯一权威形式）
    §17.5  基础费 100% 销毁
    §17.6  优先费进入验证者奖励机制

三条不可违反的规则
------------------
1. **未列入 G1–G11 的操作不存在**（规范 §17.1 明文）。实现 MUST NOT 为任何
   其它操作定义 gas 成本 —— 否则状态根与其它实现不一致。
2. **基础费算式不得改用"近似步长"**（规范 §17.4 注记）。`bf // DIVISOR` 再乘
   gas 偏差的做法在 `bf` 较大时与规范结果相差可达数百万倍。
3. **一切金额与 gas 运算为整数**；本模块不使用任何浮点。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from . import params as P

__all__ = [
    "TxType", "FeeQuote", "gas_used_for", "fee_quote", "GasError",
    "base_fee_next", "count_zero_bytes", "effective_gas_price",
]


class GasError(ValueError):
    """gas 相关的确定性错误（规范 §16.4.2 的拒绝原因）。"""


class TxType:
    """规范 §16.1 的交易类型。仅此 7 种；其它类型 MUST 被拒绝。"""
    TRANSFER = 0x01
    BOND = 0x02
    UNBOND = 0x03
    REBOND = 0x04
    EVIDENCE = 0x05
    WITHDRAW = 0x06
    AIRDROP_CLAIM = 0x07

    ALL = (TRANSFER, BOND, UNBOND, REBOND, EVIDENCE, WITHDRAW, AIRDROP_CLAIM)
    NAMES = {
        TRANSFER: "TRANSFER", BOND: "BOND", UNBOND: "UNBOND", REBOND: "REBOND",
        EVIDENCE: "EVIDENCE", WITHDRAW: "WITHDRAW", AIRDROP_CLAIM: "AIRDROP_CLAIM",
    }

    @classmethod
    def name(cls, t: int) -> str:
        return cls.NAMES.get(t, f"UNKNOWN(0x{t:02x})")

    @classmethod
    def is_valid(cls, t: int) -> bool:
        return t in cls.ALL


# ══════════════════════════════════════════════════════════════════════
# gas 计算（规范 §17.1）
# ══════════════════════════════════════════════════════════════════════

def count_zero_bytes(data: bytes) -> Tuple[int, int]:
    """返回 `(零字节数, 非零字节数)`（规范 §17.1 的 G2/G3 区分依据）。"""
    zeros = sum(1 for b in data if b == 0)
    return zeros, len(data) - zeros


def _type_surcharge(tx_type: int) -> int:
    """类型附加费（G5–G10）。**未列出的类型一律为 0，且调用方必须先验证类型合法。**"""
    return {
        TxType.BOND: P.GAS_BOND,
        TxType.UNBOND: P.GAS_UNBOND,
        TxType.REBOND: P.GAS_REBOND,
        TxType.WITHDRAW: P.GAS_WITHDRAW,
        TxType.AIRDROP_CLAIM: P.GAS_AIRDROP_CLAIM,
    }.get(tx_type, 0)


def gas_used_for(tx_type: int, data: bytes, creates_account: bool,
                 evidence_sig_count: int = 0) -> int:
    """规范 §17.1 的 `gas_used` 计算。

    ```
    gas_used = 21,000 + Σ_bytes(零 ? 4 : 16) + (创建账户 ? 25,000 : 0) + 类型附加费
    ```

    注意：`EVIDENCE` 的每条冲突签名另计 `GAS_EVIDENCE_PER_SIG = 3,000`（G8）。
    `G11`（Ed25519 验证 3,000）**已含于 G1**，不重复计。
    """
    if not TxType.is_valid(tx_type):
        raise GasError(f"未知交易类型 0x{tx_type:02x}（规范 §16.1 要求拒绝）")
    if evidence_sig_count < 0:
        raise GasError("冲突签名数不能为负")
    zeros, nonzeros = count_zero_bytes(data)
    total = P.GAS_TX_BASE
    total += nonzeros * P.GAS_PER_NONZERO_BYTE
    total += zeros * P.GAS_PER_ZERO_BYTE
    if creates_account:
        total += P.GAS_ACCOUNT_CREATION
    total += _type_surcharge(tx_type)
    if tx_type == TxType.EVIDENCE:
        total += P.GAS_EVIDENCE_BASE
        total += evidence_sig_count * P.GAS_EVIDENCE_PER_SIG
    return total


# ══════════════════════════════════════════════════════════════════════
# EIP-1559 费用语义（规范 §17.2）
# ══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class FeeQuote:
    """一笔交易的费用分解（全部为整数，单位 atom）。"""
    base_fee_per_gas: int
    effective_gas_price: int
    priority_paid: int          # 每 gas 的优先费
    base_paid: int              # 每 gas 的基础费（全部销毁）
    gas_used: int

    @property
    def total_fee(self) -> int:
        return self.effective_gas_price * self.gas_used

    @property
    def burn_amount(self) -> int:
        """规范 §17.5：100% 基础费销毁。"""
        return self.base_paid * self.gas_used

    @property
    def priority_amount(self) -> int:
        """规范 §17.6：优先费进入验证者奖励机制。"""
        return self.priority_paid * self.gas_used


def effective_gas_price(base_fee: int, max_fee: int, max_priority_fee: int) -> int:
    """规范 §17.2：
        `effective_gas_price = min(max_fee_per_gas, base_fee + max_priority_fee_per_gas)`

    拒绝条件（由调用方在 §16.4.2 的第 6/11 项检查）：
        · `max_priority_fee_per_gas > max_fee_per_gas`
        · `max_fee_per_gas < base_fee_per_gas`
    """
    if base_fee < 0 or max_fee < 0 or max_priority_fee < 0:
        raise GasError("费用参数不能为负")
    return min(max_fee, base_fee + max_priority_fee)


def fee_quote(gas_used: int, base_fee: int, max_fee: int, max_priority_fee: int) -> FeeQuote:
    """产出费用分解。要求交易已通过 §16.4.2 的第 6 与第 11 项检查。"""
    if max_priority_fee > max_fee:
        raise GasError("max_priority_fee_per_gas 不得超过 max_fee_per_gas（§16.4.2 第 6 项）")
    if max_fee < base_fee:
        raise GasError("max_fee_per_gas 低于区块基础费（§16.4.2 第 11 项）")
    eff = effective_gas_price(base_fee, max_fee, max_priority_fee)
    return FeeQuote(base_fee_per_gas=base_fee, effective_gas_price=eff,
                    priority_paid=eff - base_fee, base_paid=base_fee, gas_used=gas_used)


def upfront_cost(gas_limit: int, max_fee: int, value: int) -> int:
    """规范 §16.4.2 第 10 项的余额门槛：`gas_limit × max_fee + value`。

    注意：这是**检查门槛**；实际扣除发生在执行之前（规范 §28.1 阶段 3），
    先扣 `gas_limit × max_fee`，再退还未用 gas。
    """
    if gas_limit < 0 or max_fee < 0 or value < 0:
        raise GasError("参数不能为负")
    return gas_limit * max_fee + value


# ══════════════════════════════════════════════════════════════════════
# 基础费（规范 §17.4）
# ══════════════════════════════════════════════════════════════════════

def base_fee_next(bf: int, gas_used: int) -> int:
    """规范 §17.4 的**唯一权威**整数算式。

    ```
    gas_used > TARGET:  delta = max(1, (bf × Δ) // DIVISOR)          bf' = bf + delta
    gas_used < TARGET:  delta = max(1, ceil(bf × Δ / DIVISOR))       bf' = max(MIN, bf − delta)
    gas_used == TARGET: bf' = bf
    ```
    `DIVISOR = TARGET_GAS_PER_BLOCK × 8 = 40,000,000`

    委托给 `params.base_fee_next` 以保证"参数层是唯一权威"。
    本包装仅额外做 `gas_used` 的合法性检查。
    """
    if gas_used < 0 or gas_used > P.MAX_GAS_PER_BLOCK:
        raise GasError(f"gas_used 超出 [0, {P.MAX_GAS_PER_BLOCK}]：{gas_used}")
    return P.base_fee_next(bf, gas_used)


def base_fee_sequence(gas_usages) -> list:
    """给定逐块 `gas_used` 序列，产出逐块基础费（供测试向量 §33 BASEFEE-* 使用）。"""
    bf, out = P.INITIAL_BASE_FEE, []
    for gu in gas_usages:
        bf = base_fee_next(bf, gu)
        out.append(bf)
    return out
