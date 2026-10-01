# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 交易
==============================

对应规范：
    §16    交易类型、载荷、校验流水线（19 项）
    §17    gas 与费用
    §20.3  签名载荷（**绝不包含签名字段**）
    §35    交易校验顺序
    §32.6  AIRDROP_CLAIM 的公钥-地址绑定

三条不可违反的规则
------------------
1. **签名载荷必须排除签名字段**（规范 §20.3 BUG-2）。若把 `signature` 放进
   `tx_signing_payload`，签名将自引用，任何实现都无法生成或校验签名。
2. **交易无效即拒绝，不入块、不计 gas、不消耗 nonce**（规范 §16.4.1）。
   本版本**不存在失败交易**；`Receipt.status` 恒为 `SUCCESS`。
3. **一切校验都是确定性的**：两个实现对同一笔交易必须得出相同结论。

关于规范 §16.4.2 第 10 项的一处澄清
-----------------------------------
规范原文写"`balance ≥ gas_limit × max_fee + value`"，而第 18 项要求执行前先扣
`gas_limit × max_fee`。若第 10 项已要求覆盖 `value`，则两者口径不一致。
正确读法（已登记于规范 BUG-38）是把第 10 项拆为两步：

    ① `balance ≥ gas_limit × max_fee`            入块门槛（可被任何实现一致判定）
    ② 执行前扣费后 `余额' ≥ value`                余额不足 ⇒ 交易无效、**不入块**

因此"余额不足以支付转账额"属于**拒绝**，而非"入块后失败"。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from . import params as P
from .codec import RLPDecodeError, decode, encode, require_canonical_int
from .crypto_backend import (address_from_pubkey, chain, keccak256,
                             verify as ed25519_verify)
from .gas import GasError, TxType, count_zero_bytes, fee_quote, gas_used_for, upfront_cost
from .state import State, STATUS_UNBONDED

__all__ = [
    "Transaction", "Evidence", "AirdropClaim", "SignedVote",
    "CheckResult", "validate_tx", "vote_signing_payload", "EVIDENCE_CLASSES",
]

EVIDENCE_CLASSES = ("DOUBLE_PREVOTE", "DOUBLE_PRECOMMIT", "SEVERE", "INVALID_PROPOSAL")
NIL_HASH = b"\x00" * 32


class TxError(ValueError):
    """交易层面的确定性错误。"""


# ══════════════════════════════════════════════════════════════════════
# 1. 载荷结构
# ══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class SignedVote:
    """规范 §16.3（**BUG-39 修正后**）：证据中的一条已签名投票。

    ```
    SignedVote = RLP([address(20), height:u64, round:u32, vote_type:u8,
                      block_hash(32), signature(64)])
    ```

    ⚠ **BUG-39（必须记录）**：本规范早期版本把本结构定义为 `[address, vote_digest, signature]`，
    其中的 `vote_digest` 是**哈希值**。哈希不可逆，因此**任何实现都无法用这种结构验证证据**——
    无法确认某地址是否真的在某个 `(height, round)` 对某个 `block_hash` 签过名。
    结果是"罚没在规范层面不可执行"。修正方式是让条目携带**全部投票内容**，
    由验证方按 §20.3 重算签名载荷并严格验签。
    """
    address: bytes          # 20 字节
    height: int
    round: int
    vote_type: int          # 1 = PREVOTE, 2 = PRECOMMIT
    block_hash: bytes       # 32 字节（nil 用全零）
    signature: bytes        # 64 字节

    def signing_payload(self) -> bytes:
        """规范 §20.3 的投票签名载荷。"""
        return vote_signing_payload(self.height, self.round, self.vote_type,
                                    None if self.block_hash == NIL_HASH else self.block_hash)

    def verify(self, pubkey: bytes) -> bool:
        if len(pubkey) != 32 or len(self.signature) != 64:
            return False
        if self.vote_type not in (VOTE_TYPE_PREVOTE, VOTE_TYPE_PRECOMMIT):
            return False
        if len(self.block_hash) != 32:
            return False
        return ed25519_verify(pubkey, self.signing_payload(), self.signature)

    @property
    def is_nil(self) -> bool:
        return self.block_hash == NIL_HASH

    def key(self) -> tuple:
        """冲突判定键：同一 `(height, round, vote_type)` 下比较 `block_hash`。"""
        return (self.height, self.round, self.vote_type)

    def to_rlp(self) -> bytes:
        return encode([self.address, self.height, self.round, self.vote_type,
                       self.block_hash, self.signature])

    @classmethod
    def from_rlp(cls, raw) -> "SignedVote":
        raw = _as_list(raw)
        if len(raw) != 6:
            raise TxError("SignedVote 必须为 6 项列表")
        if len(raw[0]) != 20 or len(raw[4]) != 32 or len(raw[5]) != 64:
            raise TxError("SignedVote 的地址/区块哈希/签名长度不符")
        # BUG-49：整数必须为最小字节串编码（无前导零），见 codec.require_canonical_int
        i = require_canonical_int
        return cls(address=raw[0], height=i(raw[1]), round=i(raw[2]),
                   vote_type=i(raw[3]), block_hash=raw[4], signature=raw[5])


@dataclass(frozen=True)
class Evidence:
    """规范 §16.3：
        Evidence = RLP([type, offender, offending_slot, offending_height,
                        conflicting_messages])

    `offending_slot` 与 `offending_height` **两者都要**：
    · `offending_slot` 决定罚没基数所取的纪元快照（§15.3）与窗口判定（§15.6）；
    · `offending_height` 用于确定冲突消息所在的共识高度（§6.4 的最终性判定）。
    """
    evidence_class: str
    offender: bytes                 # 20 字节
    offending_slot: int
    offending_height: int
    messages: Tuple[SignedVote, ...] = ()

    def to_rlp(self) -> bytes:
        return encode([_class_code(self.evidence_class), self.offender,
                       self.offending_slot, self.offending_height,
                       [m.to_rlp() for m in self.messages]])

    @classmethod
    def from_rlp(cls, raw) -> "Evidence":
        raw = _as_list(raw)
        if len(raw) != 5:
            raise TxError("Evidence 必须为 5 项列表")
        # BUG-49：整数必须为最小字节串编码（无前导零），见 codec.require_canonical_int
        i = require_canonical_int
        return cls(evidence_class=_class_name(i(raw[0])),
                   offender=raw[1], offending_slot=i(raw[2]),
                   offending_height=i(raw[3]),
                   messages=tuple(SignedVote.from_rlp(m) for m in _as_list(raw[4])))

    @property
    def sig_count(self) -> int:
        """用于 G8 的 gas 计算。"""
        return len(self.messages)


@dataclass(frozen=True)
class AirdropClaim:
    """规范 §32.6（BUG-41 修正后）：
        payload = RLP([index, amount, gas_allowance, pubkey, merkle_proof,
                       binding_signature])

    `gas_allowance` 必须列入，因为它是**创世分配表叶子哈希的一部分**；
    若领取交易不携带它，协议无法重算叶子从而无法验证 Merkle 证明。
    """
    index: int
    amount: int
    gas_allowance: int
    pubkey: bytes                   # 32 字节
    merkle_proof: Tuple[bytes, ...] = ()
    binding_signature: bytes = b""  # 64 字节

    def to_rlp(self) -> bytes:
        return encode([self.index, self.amount, self.gas_allowance, self.pubkey,
                       list(self.merkle_proof), self.binding_signature])

    @classmethod
    def from_rlp(cls, raw) -> "AirdropClaim":
        raw = _as_list(raw)
        if len(raw) != 6:
            raise TxError("AirdropClaim 必须为 6 项列表")
        # BUG-49：整数必须为最小字节串编码（无前导零），见 codec.require_canonical_int
        i = require_canonical_int
        return cls(index=i(raw[0]), amount=i(raw[1]), gas_allowance=i(raw[2]),
                   pubkey=raw[3], merkle_proof=tuple(raw[4]),
                   binding_signature=raw[5])

    def binding_message(self, sender: bytes) -> bytes:
        """规范 §32.6 第 ③ 项的绑定签名载荷。"""
        # index 的宽度规范未写死；按 §32.6 的 `index:u64` 取 u64（BUG-67 已登记）
        return P.TAG_AIRDROP + chain(P.CHAIN_ID_BYTES, self.pubkey, sender,
                                     ("u64", self.index))


def _as_list(raw):
    """把 `from_rlp` 的输入统一成已解码的 RLP 列表。

    约定：这些 `from_rlp` **同时接受**字节串与已解码列表。
    只接受列表的写法极易误用（调用方常常忘记先 `decode`），
    因此在同一处统一处理，避免每个解析函数各写一份。
    """
    if isinstance(raw, (bytes, bytearray)):
        raw = decode(bytes(raw))
    if not isinstance(raw, list):
        raise TxError("RLP 输入必须解码为列表")
    return raw


# 规范 §16.3（BUG-86）的类别编号：`0x01`–`0x04`。`0x03` 在本版本中"保留但不可判定"。
SEVERE_RESERVED = "SEVERE"


def _class_code(name: str) -> int:
    if name not in EVIDENCE_CLASSES:
        raise TxError(f"未知证据类别：{name}")
    return EVIDENCE_CLASSES.index(name) + 1


def _class_name(code: int) -> str:
    if not 1 <= code <= len(EVIDENCE_CLASSES):
        raise TxError(f"非法证据类别码：{code}")
    return EVIDENCE_CLASSES[code - 1]


# ══════════════════════════════════════════════════════════════════════
# 2. 投票签名载荷（规范 §20.3）
# ══════════════════════════════════════════════════════════════════════

VOTE_TYPE_PREVOTE = 0x01
VOTE_TYPE_PRECOMMIT = 0x02


def vote_signing_payload(height: int, round_: int, vote_type: int,
                         block_hash: Optional[bytes]) -> bytes:
    """规范 §20.3：
        CHAIN("AGORA/{PREVOTE|PRECOMMIT}/v0.2.2", chain_id, u64(height),
              u32(round), u8(vote_type), block_hash(32) 或 NIL(32 个 0x00))

    **本函数是全协议唯一实现（BUG-67）。**

    此前本模块与 `agora/consensus.py` **各有一份**同签名实现，且编码写法不同：
    本模块把标签**作为 `chain()` 的参数**传入（22 字节标签因此被动加上 u32
    长度前缀），而 consensus 那份把标签**前置在 `chain()` 之外**（符合 §20.1）。
    后果是同一份规范产出**两种签名载荷**，投票与 Commit 校验互相验不过 ——
    而这种"重复实现"极难通过测试发现（各自的测试都只测自己那一份）。

    放在本模块的原因：依赖方向是 `consensus → block → tx`，
    因此唯一实现必须位于依赖链的**下游**（`tx`），上游重导出即可。
    """
    tag = P.TAG_PREVOTE if vote_type == VOTE_TYPE_PREVOTE else P.TAG_PRECOMMIT
    bh = NIL_HASH if block_hash is None else block_hash
    if len(bh) != 32:
        raise TxError("block_hash 必须为 32 字节（nil 用 32 个 0x00）")
    # 标签 **MUST** 前置在 chain() 之外（§20.1：标签 ASCII，无长度前缀）；
    # 宽度 **MUST** 按 §20.3 显式声明（BUG-64）。
    return tag + chain(P.CHAIN_ID_BYTES, ("u64", height), ("u32", round_),
                       ("u8", int(vote_type)), bh)


# ══════════════════════════════════════════════════════════════════════
# 3. 交易封装（规范 §16.1）
# ══════════════════════════════════════════════════════════════════════

@dataclass
class Transaction:
    """规范 §16.1。

    ```
    TxContent  = RLP([type, chain_id_hash, nonce, max_priority_fee, max_fee,
                      gas_limit, to, value, payload, pubkey])      # 被签名的部分
    TxEnvelope = TxContent + signature                             # 链上/网络中传输的部分
    ```

    `pubkey` 纳入签名载荷：由它推导地址，从而建立"发送者身份 ↔ 公钥 ↔ 签名"的完整链条。
    """
    tx_type: int
    nonce: int
    max_priority_fee_per_gas: int
    max_fee_per_gas: int
    gas_limit: int
    to: bytes                                   # 20 字节；空 bytes 表示创建
    value: int
    payload: bytes = b""                        # 已 RLP 编码的类型载荷
    pubkey: bytes = b""                         # 32 字节
    signature: bytes = b""                      # 64 字节（不参与签名载荷）
    # 规范 §16.1 的第 2 字段。**必须**保留从线上读到的原值（PROJECT_REVIEW R-4）：
    # 历史实现在解码时丢弃它、再用规范值重算，于是 §16.4.2 第 3 项
    # （"不匹配则拒绝"）成了空检查，且 `tx_hash != Keccak(收到的字节)`。
    protocol_version_hash: bytes = b""

    def __post_init__(self) -> None:
        # 本地构造时填入规范值；从线上解码时**保留原值**（R-4：不得静默重算）。
        if not self.protocol_version_hash:
            object.__setattr__(
                self, "protocol_version_hash",
                keccak256(P.PROTOCOL_VERSION.encode()))

    # ── 种类与载荷 ──────────────────────────────────────────────────
    @property
    def type_name(self) -> str:
        return TxType.name(self.tx_type)

    @property
    def sender(self) -> bytes:
        """发送者地址 = `Last20Bytes(Keccak256(pubkey))`（规范 §3）。"""
        return address_from_pubkey(self.pubkey) if len(self.pubkey) == 32 else b""

    def decoded_payload(self):
        """按类型解析载荷；无载荷的类型返回 `None`。"""
        if not self.payload:
            return None
        raw = decode(self.payload)
        if self.tx_type == TxType.EVIDENCE:
            return Evidence.from_rlp(raw)
        if self.tx_type == TxType.AIRDROP_CLAIM:
            return AirdropClaim.from_rlp(raw)
        if self.tx_type == TxType.BOND:
            # BOND 载荷的规范形式是 **RLP 字节串**，内容为 32 字节公钥。
            # 因此 `decode(payload)` 直接返回公钥字节（长度 32），而不是列表。
            # 注意：不要写成 CHAIN(pubkey) —— CHAIN 是哈希原像编码，
            # 其输出通常不是合法的 RLP（会触发"尾随字节"错误）。
            if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
                raise TxError(f"BOND 载荷必须为 32 字节公钥的 RLP 字节串，实际 {type(raw)}")
            return {"pubkey": bytes(raw)}
        if self.tx_type in (TxType.UNBOND, TxType.REBOND):
            # 载荷为 RLP 字节串，内容为无符号大端金额
            if not isinstance(raw, (bytes, bytearray)):
                raise TxError("UNBOND/REBOND 载荷必须为 RLP 字节串")
            return {"amount": int.from_bytes(bytes(raw), "big")}
        return raw

    def evidence(self) -> Optional[Evidence]:
        p = self.decoded_payload()
        return p if isinstance(p, Evidence) else None

    def airdrop_claim(self) -> Optional[AirdropClaim]:
        p = self.decoded_payload()
        return p if isinstance(p, AirdropClaim) else None

    # ── 编解码 ──────────────────────────────────────────────────────
    def content_fields(self) -> list:
        return [self.tx_type,
                self.protocol_version_hash or keccak256(P.PROTOCOL_VERSION.encode()),
                self.nonce, self.max_priority_fee_per_gas, self.max_fee_per_gas,
                self.gas_limit, self.to, self.value, self.payload, self.pubkey]

    def to_content_rlp(self) -> bytes:
        return encode(self.content_fields())

    def to_rlp(self) -> bytes:
        return encode(self.content_fields() + [self.signature])

    @classmethod
    def from_rlp(cls, raw: bytes) -> "Transaction":
        it = _as_list(raw)
        if len(it) != 11:
            raise TxError("交易封装必须为 11 项列表")
        # BUG-49：整数必须为最小字节串编码（无前导零），见 codec.require_canonical_int
        i = require_canonical_int
        if len(it[1]) != 32:
            raise TxError("protocol_version_hash 必须为 32 字节")
        return cls(tx_type=i(it[0]), nonce=i(it[2]),
                   max_priority_fee_per_gas=i(it[3]), max_fee_per_gas=i(it[4]),
                   gas_limit=i(it[5]), to=it[6], value=i(it[7]), payload=it[8],
                   pubkey=it[9], signature=it[10],
                   protocol_version_hash=bytes(it[1]))   # 保留线上原值（R-4）

    # ── 签名 ────────────────────────────────────────────────────────
    def signing_payload(self) -> bytes:
        """规范 §20.3：**绝不包含签名字段**。"""
        return P.TAG_TX + chain(P.CHAIN_ID_BYTES, self.to_content_rlp())

    def tx_hash(self) -> bytes:
        """交易哈希 = 对完整封装取 Keccak（含签名）。"""
        return keccak256(self.to_rlp())

    def verify_signature(self) -> bool:
        """严格验证：公钥-地址绑定 + Ed25519 严格校验（规范 §2.1）。"""
        if len(self.pubkey) != 32 or len(self.signature) != 64:
            return False
        return ed25519_verify(self.pubkey, self.signing_payload(), self.signature)

    # ── gas（确定性推导，不来自交易字段）────────────────────────────
    def gas_used(self, creates_account: bool) -> int:
        """规范 §17.1。`gas_used` 是交易与状态的**确定性函数**，不从交易里读。

        载荷解析失败**不在此处抛错**：那会让"畸形载荷"变成异常而非校验失败。
        此处按 0 条签名计 gas，畸形载荷随后由 §16.4.2 第 13/14 项拒绝。
        """
        sig_count = 0
        if self.tx_type == TxType.EVIDENCE and self.payload:
            try:
                ev = self.evidence()
                sig_count = ev.sig_count if ev else 0
            except (TxError, RLPDecodeError, ValueError):
                sig_count = 0
        return gas_used_for(self.tx_type, self.payload, creates_account, sig_count)

    def upfront(self) -> int:
        return upfront_cost(self.gas_limit, self.max_fee_per_gas, self.value)

    def fee_quote(self, base_fee: int, creates_account: bool):
        return fee_quote(self.gas_used(creates_account), base_fee,
                         self.max_fee_per_gas, self.max_priority_fee_per_gas)


# ══════════════════════════════════════════════════════════════════════
# 4. 校验流水线（规范 §16.4.2，19 项）
# ══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CheckResult:
    ok: bool
    failed_at: Optional[int] = None       # 失败的检查项编号
    reason: str = ""
    stage: str = ""                       # "I" / "II" / "III"

    def __bool__(self) -> bool:
        return self.ok

    def __str__(self) -> str:
        if self.ok:
            return "OK（通过全部检查）"
        return f"第 {self.failed_at} 项失败（阶段 {self.stage}）：{self.reason}"


def _fail(n: int, stage: str, reason: str) -> CheckResult:
    return CheckResult(False, n, reason, stage)


def validate_tx(tx: Transaction, state: State, base_fee: int,
                block_gas_used: int, sender_nonce: Optional[int] = None,
                current_slot: Optional[int] = None) -> CheckResult:
    """规范 §16.4.2 的完整校验流水线。

    阶段 I  = 无状态校验（仅需交易字节）
    阶段 II = 有状态校验（需父状态）

    返回 `CheckResult`；调用方在失败时**必须拒绝该交易**（不入块、不计 gas、不消耗 nonce）。
    """
    # ── 阶段 I ──────────────────────────────────────────────────────
    # 1. 规范解码（由 from_rlp 保证；此处确认字段完整性）
    if len(tx.to) not in (0, 20):
        return _fail(1, "I", f"to 字段长度必须为 0 或 20，实际 {len(tx.to)}")
    if len(tx.pubkey) != 32:
        return _fail(1, "I", f"pubkey 长度必须为 32，实际 {len(tx.pubkey)}")
    if len(tx.signature) != 64:
        return _fail(1, "I", f"signature 长度必须为 64，实际 {len(tx.signature)}")

    # 2. 交易类型合法
    if not TxType.is_valid(tx.tx_type):
        return _fail(2, "I", f"未知交易类型 0x{tx.tx_type:02x}")

    # 3. 协议版本
    raw = decode(tx.to_content_rlp())
    if raw[1] != keccak256(P.PROTOCOL_VERSION.encode()):
        return _fail(3, "I", "protocol_version_hash 不匹配")

    # 4. 链 ID（BUG-40）
    #    规范 §4 声称"Chain ID 必须为 20 字节"，但实际值 `agora-mainnet-1` 只有 **15 字节**，
    #    两者自相矛盾。本实现按"链身份 = ASCII 字节串，长度可变"处理，并在
    #    §20.1 的 CHAIN 中对非 20/32 字节的字节串自动加 u32 长度前缀。
    #    因此第 4 项检查的是"链身份确实已被纳入签名载荷"，而非某个固定长度。
    expected_chain_hash = keccak256(P.CHAIN_ID_BYTES)
    if raw[1] != keccak256(P.PROTOCOL_VERSION.encode()):
        return _fail(3, "I", "protocol_version_hash 不匹配")
    if len(P.CHAIN_ID) == 0:
        return _fail(4, "I", "chain_id 不得为空")
    if expected_chain_hash != keccak256(P.CHAIN_ID.encode("ascii")):
        return _fail(4, "I", "chain_id 编码不一致")
    # 链身份已进入签名载荷（见 Transaction.signing_payload 的 CHAIN 第 2 项）
    if P.CHAIN_ID_BYTES not in tx.signing_payload():
        return _fail(4, "I", "chain_id 未出现在签名载荷中（无法防跨链重放）")

    # 5. 签名严格验证
    if not tx.verify_signature():
        return _fail(5, "I", "Ed25519 签名验证失败（或公钥-地址绑定不符）")

    # 6. 优先费不得超过最大费
    if tx.max_priority_fee_per_gas > tx.max_fee_per_gas:
        return _fail(6, "I", "max_priority_fee_per_gas 超过 max_fee_per_gas")

    # 7. gas_limit 下限
    if tx.gas_limit < P.GAS_TX_BASE:
        return _fail(7, "I", f"gas_limit {tx.gas_limit} < {P.GAS_TX_BASE}")

    # 8. gas_limit 不得超过区块上限
    if tx.gas_limit > P.MAX_GAS_PER_BLOCK:
        return _fail(8, "I", f"gas_limit {tx.gas_limit} > {P.MAX_GAS_PER_BLOCK}")

    # ── 阶段 II ─────────────────────────────────────────────────────
    sender = tx.sender
    acc = state.get_account(sender)
    nonce = acc.nonce if acc else 0
    balance = acc.balance if acc else 0
    if sender_nonce is not None:                # 同一区块内前序交易带来的 nonce 变化
        nonce = sender_nonce

    # 9. nonce 匹配
    if tx.nonce != nonce:
        return _fail(9, "II", f"nonce 不匹配：交易 {tx.nonce}，账户 {nonce}")

    # 10. 余额门槛（分两步，见模块文档的澄清）
    if balance < tx.gas_limit * tx.max_fee_per_gas:
        return _fail(10, "II", "余额不足以支付 gas_limit × max_fee_per_gas")
    if balance - tx.gas_limit * tx.max_fee_per_gas < tx.value:
        return _fail(10, "II", "扣除 gas 预留后余额不足以支付 value（交易应被拒绝，而非入块失败）")

    # 11. max_fee 不得低于区块基础费
    if tx.max_fee_per_gas < base_fee:
        return _fail(11, "II", f"max_fee_per_gas {tx.max_fee_per_gas} < 区块基础费 {base_fee}")

    # 12. gas_used ≤ gas_limit（需要知道是否创建账户）
    #     先确认载荷本身可被规范解码；不可解码 ⇒ 第 1 项（格式）失败，
    #     而不是让异常冒泡（规范要求"拒绝"，不是"崩溃"）。
    try:
        tx.decoded_payload()
    except (TxError, RLPDecodeError, ValueError) as e:
        return _fail(1, "I", f"载荷无法按规范解码：{e}")
    creates = bool(tx.to) and state.get_account(tx.to) is None and tx.value > 0
    gu = tx.gas_used(creates)
    if gu > tx.gas_limit:
        return _fail(12, "II", f"gas_used {gu} > gas_limit {tx.gas_limit}")

    # 13. 类型前置条件
    r = _check_type_preconditions(tx, state, sender, current_slot)
    if r is not None:
        return r

    # 14/15. EVIDENCE 专属检查
    if tx.tx_type == TxType.EVIDENCE:
        r = _check_evidence(tx, state, current_slot)
        if r is not None:
            return r

    # 16. AIRDROP_CLAIM 专属检查
    if tx.tx_type == TxType.AIRDROP_CLAIM:
        r = _check_airdrop(tx, state, sender, current_slot)
        if r is not None:
            return r

    # 17. 区块累计 gas（规范要求：**跳过该交易，而非拒绝区块**）
    if block_gas_used + gu > P.MAX_GAS_PER_BLOCK:
        return _fail(17, "II",
                     f"区块累计 gas 将达 {block_gas_used + gu} > {P.MAX_GAS_PER_BLOCK}（跳过本交易）")

    return CheckResult(True)


def _check_type_preconditions(tx: Transaction, state: State,
                              sender: bytes,
                              current_slot: Optional[int] = None
                              ) -> Optional[CheckResult]:
    """规范 §16.4.2 第 13 项：类型前置条件。"""
    rec = state.get_validator(sender)

    if tx.tx_type == TxType.TRANSFER:
        if tx.to and len(tx.to) != 20:
            return _fail(13, "II", "to 必须为 20 字节")
        return None

    if tx.tx_type == TxType.BOND:
        p = tx.decoded_payload()
        if p is None:
            return _fail(13, "II", "BOND 缺少载荷")
        if p["pubkey"] != tx.pubkey:
            return _fail(13, "II", "BOND 载荷中的 pubkey 与交易 pubkey 不一致")
        # 先查金额（更基本的条件），再查状态：这样"质押不足"不会被
        # "已是验证者"掩盖，报错信息对实现者更有指向性。
        #
        # 关于"追加质押"（BUG-43）：若账户**已是验证者**，BOND 表示**追加质押**，
        # 此时金额只需 > 0（不必再满足最低质押，因为它本来就已满足）。
        # 早期实现一律拒绝"已是验证者"的 BOND，导致验证者无法提高质押，
        # 也就无法在质押被罚没后自行补足 —— 这是一个真实的可用性缺陷。
        if rec is not None and rec.status != STATUS_UNBONDED:
            if rec.pubkey != tx.pubkey:
                return _fail(13, "II", "追加质押时公钥必须与原验证者一致")
            if tx.value <= 0:
                return _fail(13, "II", "追加质押的金额必须为正")
        else:
            if tx.value < P.MIN_VALIDATOR_STAKE:
                return _fail(13, "II",
                             f"首次质押额 {tx.value} 低于最低值 {P.MIN_VALIDATOR_STAKE}")
        return None

    if tx.tx_type == TxType.UNBOND:
        p = tx.decoded_payload()
        if p is None:
            return _fail(13, "II", "UNBOND 缺少载荷")
        if rec is None or rec.status == 0:
            return _fail(13, "II", "未绑定的账户不能解绑")
        # 上限 = `effective_stake + pending_stake`（BUG-84）：尚未生效的追加质押
        # 也属于该验证者的权益，必须允许撤回；只按 `effective_stake` 限制会让
        # "本纪元刚追加的质押"无法解绑，并迫使实现去做"从 pending 里悄悄扣掉"这种
        # 会丢钱的补救（旧实现正是如此）。
        total_stake = rec.effective_stake + rec.pending_stake
        if p["amount"] <= 0 or p["amount"] > total_stake:
            return _fail(13, "II",
                         f"解绑额 {p['amount']} 超出质押总额 {total_stake}"
                         f"（有效 {rec.effective_stake} + 待生效 {rec.pending_stake}）")
        return None

    if tx.tx_type == TxType.REBOND:
        if rec is None or rec.status != 2:      # UNBONDING
            return _fail(13, "II", "仅 UNBONDING 状态可 rebond")
        p = tx.decoded_payload()
        if p is None or p["amount"] <= 0:
            return _fail(13, "II", "REBOND 必须携带正的复投金额")
        if p["amount"] > rec.unbonding_balance + rec.pending_unbond:
            return _fail(13, "II",
                         f"复投额 {p['amount']} 超出可复投余额 "
                         f"{rec.unbonding_balance + rec.pending_unbond}")
        return None

    if tx.tx_type == TxType.WITHDRAW:
        if rec is None:
            return _fail(13, "II", "非验证者不能提取")
        if rec.unbonding_balance <= 0:
            return _fail(13, "II", "没有可提取的解绑余额")
        # 规范 §19.4 / §14.2：**仅当** `claimed_slot ≥ unbond_complete_slot` 才可提取。
        # 这是"21 天解绑期"在实现里唯一的落地点（BUG-85：旧实现从未写入
        # `unbond_complete_slot`，也从不检查时间 ⇒ 实测解绑后 1 小时即可提走，
        # 罚没窗口对已解绑资金完全失效）。
        if current_slot is None:
            return _fail(13, "II", "WITHDRAW 校验缺少当前槽（时间条件无法判定）")
        if rec.unbond_complete_slot <= 0:
            return _fail(13, "II", "该账户没有有效的解绑完成槽（不得提取）")
        if current_slot < rec.unbond_complete_slot:
            return _fail(13, "II",
                         f"解绑期未满：当前槽 {current_slot} < 完成槽 "
                         f"{rec.unbond_complete_slot}")
        return None

    return None


def _check_evidence(tx: Transaction, state: State, current_slot: Optional[int] = None
                    ) -> Optional[CheckResult]:
    """规范 §16.4.2 第 14/15 项 + §15.2 的可罚没谓词（**可判定**版本）。

    这是 v0.2.2 中唯一能真正判定"双签"的地方，因此必须逐条验签，
    不能依赖提交者自述（规范 §38：「不得仅因某节点声称他人作恶而罚没」）。
    """
    ev = tx.evidence()
    if ev is None:
        return _fail(14, "II", "EVIDENCE 载荷无法解析")
    if ev.evidence_class not in EVIDENCE_CLASSES:
        return _fail(14, "II", f"未知证据类别 {ev.evidence_class}")
    # 规范 §16.3（BUG-86）：`0x03 SEVERE`（10% 档）在本版本中**没有任何可判定判据**，
    # 编号保留但**必须被拒绝** —— §1 第 10 条禁止"实现无法判定的谓词"存在。
    # 缺少这一条时，任何人都能凭一句"严重共识故障"触发 10% 罚没（比双签的 5% 更重）。
    if ev.evidence_class == SEVERE_RESERVED:
        return _fail(14, "II",
                     f"证据类别 {SEVERE_RESERVED}（SEVERE）在本版本中保留但不可判定，"
                     f"MUST 被拒绝（§16.3 / BUG-86）")
    if len(ev.offender) != 20:
        return _fail(14, "II", "offender 必须为 20 字节")

    # ── 第 15 项：冲突消息的密码学有效性与冲突性 ──
    if len(ev.messages) < 2:
        return _fail(15, "II", "证据必须包含至少两条签名消息")
    pk = _pubkey_of(ev.offender, state)
    if len(pk) != 32:
        return _fail(15, "II", "offender 不在验证者集合中，无法取得其公钥")

    for m in ev.messages:
        if m.address != ev.offender:
            return _fail(15, "II", "冲突消息的地址与 offender 不一致")
        if not m.verify(pk):
            return _fail(15, "II", "冲突消息的 Ed25519 签名无效")
        if m.height != ev.offending_height:
            return _fail(15, "II",
                         f"冲突消息高度 {m.height} 与 offending_height {ev.offending_height} 不符")

    # 冲突性：同一 (height, round, vote_type) 下必须出现两个不同的 block_hash
    groups: dict = {}
    for m in ev.messages:
        groups.setdefault(m.key(), set()).add(m.block_hash)
    if not any(len(hashes) >= 2 for hashes in groups.values()):
        return _fail(15, "II", "未发现同一 (height, round, vote_type) 下的两个不同 block_hash，"
                               "不构成冲突")

    # ── 类别与冲突形态必须匹配 ──
    if ev.evidence_class in ("DOUBLE_PREVOTE",) and not any(
            k[2] == VOTE_TYPE_PREVOTE and len(v) >= 2 for k, v in groups.items()):
        return _fail(14, "II", "声称双重预投票，但证据中无同轮次的双预投票")
    if ev.evidence_class in ("DOUBLE_PRECOMMIT", "SEVERE") and not any(
            k[2] == VOTE_TYPE_PRECOMMIT and len(v) >= 2 for k, v in groups.items()):
        return _fail(14, "II", "声称双重预提交，但证据中无同轮次的双预提交")

    # ── 第 14 项：窗口与去重 ──
    if current_slot is not None:
        if not (ev.offending_slot <= current_slot <= ev.offending_slot + P.SLASH_WINDOW_SLOTS):
            return _fail(14, "II",
                         f"证据超出罚没窗口（offense_slot={ev.offending_slot}, "
                         f"current={current_slot}, 窗口={P.SLASH_WINDOW_SLOTS}）")
    key = (ev.offender, ev.evidence_class, ev.offending_slot)
    if key in state.system.pending_dedup() or key in state.system.prereq_dedup():
        return _fail(14, "II", "该违规已被登记或已结算（重复证据）")

    # 规范 §15.2 第 2 项：冲突提交所在高度必须已最终化。
    # 该判定需要链头信息，由调用方（区块处理器）在链上下文中完成：
    if current_slot is None:
        return _fail(14, "II", "缺少链上下文，无法判定冲突高度是否已最终化（§15.2）")
    return None


def _pubkey_of(address: bytes, state: State) -> bytes:
    """由地址反查验证者公钥（仅最终化链上的验证者可知）。"""
    rec = state.get_validator(address)
    return rec.pubkey if rec else b""


def _check_airdrop(tx: Transaction, state: State, sender: bytes,
                   current_slot: Optional[int] = None) -> Optional[CheckResult]:
    """规范 §16.4.2 第 16 项 + §32.6 的 5 条规则。"""
    from .state import airdrop_merkle_root   # noqa: F401（保持依赖显式）
    cl = tx.airdrop_claim()
    if cl is None:
        return _fail(16, "II", "AIRDROP_CLAIM 载荷无法解析")
    # ② 公钥-地址绑定
    if address_from_pubkey(cl.pubkey) != sender:
        return _fail(16, "II", "公钥-地址绑定不符")
    # ③ 绑定签名
    if not ed25519_verify(cl.pubkey, cl.binding_message(sender), cl.binding_signature):
        return _fail(16, "II", "绑定签名无效")
    # ④ 未领取过 —— 一次性判据是**二元组 (sender, index)**，见规范 §32.6
    #
    # BUG-51：这里曾额外加了一条 "该地址已领取过" 的检查，等同于"每个地址只能领取
    # 一个空投条目"。但分配表允许同一受益人持有**多个条目**（不同 index），
    # 该检查会让其余条目**永久无法领取**（钱锁死在金库），并且与规范
    # "二元组 (tx.from, index) 未被领取过" 的措辞直接冲突。
    # 重复领取已由 (sender, index) 判据完全阻断，无需再加地址级限制。
    if (sender, cl.index) in set(state.system.airdrop_claimed):
        return _fail(16, "II", "该条目已被领取")
    # ⑤ 时间窗（规范 §32.6 / BUG-87）：此前这里只校验"窗口配置本身有效"，
    #    是一个**恒真**的表达式 —— 等于根本没检查时间，领取可以永远进行下去。
    if current_slot is None:
        return _fail(16, "II", "AIRDROP_CLAIM 校验缺少当前槽（时间窗无法判定）")
    if not (P.AIRDROP_START_SLOT <= current_slot <= P.AIRDROP_END_SLOT):
        return _fail(16, "II",
                     f"不在空投窗口内：当前槽 {current_slot} 应落在 "
                     f"[{P.AIRDROP_START_SLOT}, {P.AIRDROP_END_SLOT}]")
    # ① Merkle 证明（需要原始分配表；此处用叶子哈希重算根并比对系统状态中的根）
    # ① Merkle 证明：叶子 **必须**把 `index` 算进去（BUG-87）。
    #    旧叶子不含 index ⇒ 证明与条目不是一一对应 ⇒ 受益人可换 index 反复领取，
    #    把整个金库（含他人份额）领空。实测：应领 1000 的受益人以 index=1/2
    #    两次领取把 2000 的金库领到 0。
    leaf = keccak256(P.TAG_AIRDROP + chain(
        ("u64", cl.index), cl.pubkey,
        ("u256", cl.amount), ("u256", cl.gas_allowance)))
    h = leaf
    for sib in cl.merkle_proof:
        if len(sib) != 32:
            return _fail(16, "II", "Merkle 证明节点长度必须为 32")
        a, b = (h, sib) if h <= sib else (sib, h)
        h = keccak256(b"\x01" + a + b)
    if h != state.system.airdrop_root:
        return _fail(16, "II", "Merkle 证明与 airdrop_root 不符")
    # 金库余额必须足够
    if state.system.airdrop_pending < cl.amount:
        return _fail(16, "II", "空投金库余额不足")
    return None
