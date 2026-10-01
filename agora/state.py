# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 状态层
================================

对应规范：
    §19   状态模型（账户、验证者记录、系统状态、MPT 状态根、账户回收）
    §20.5 验证者集合承诺
    §7    验证者集合与快照
    §28   记账、结算与分配
    §32   创世（闭合约束、金库、Merkle 承诺）

设计要点（每条都对应规范中的一处明确要求）
------------------------------------------
1. `validator_key` 字段**必须是** `Hash(RLP(ValidatorRecord))`（规范 §19.2）。
   它既可作为完整性校验，也可作为"验证者记录是否被篡改"的快速断言。
2. 验证者记录**不进**账户 trie，而是作为独立对象由 `state_root` 承诺
   （规范 §19.5 的 `epoch_set_membership` + §20.5 的 `ValidatorSetCommitment`）。
   这样做让"读验证者记录"不依赖 trie 路径，也便于独立实现复现。
3. 一切**金额运算在 atom 粒度**（规范 §9.1 BUG-35）。本模块的所有函数都接受
   并返回 atom，绝不在中途换算成 AGORA。
4. 账户回收规则（规范 §19.3）是**状态转移的一部分**，不是可选优化。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import params as P
from .codec import (MerklePatriciaTrie, RLPDecodeError, decode, encode,
                    require_canonical_int, secure_key)
from .crypto_backend import chain, keccak256


def _i(b) -> int:
    """把 RLP 解码得到的字节串按无符号大端解释为整数。

    规范 §33.0 明确：RLP 解码器**一律返回字节串**，整数语义由调用方决定。
    因此解码路径上每个整数字段都必须显式经过本函数，不得直接当 int 使用。

    BUG-49：本函数委托给 `require_canonical_int`，即**同时强制最小字节串编码**
    （拒绝 `0x00` 开头的前导零形式）。规范性校验放在这里而不是解码器里，
    是因为解码器无法区分整数字段与以 `0x00` 开头的合法字节串字段（如地址）。
    """
    if isinstance(b, int):
        return b                      # 容错：某些路径可能已转换
    return require_canonical_int(b)

__all__ = [
    "Account", "ValidatorRecord", "PendingSlash", "SystemState", "AirdropEntry",
    "State", "GenesisAllocation",
    "STATUS_UNBONDED", "STATUS_BONDED", "STATUS_UNBONDING", "EVIDENCE_CLASSES",
    "SnapshotSet",
    "validator_set_commitment", "meets_account_pruning_rule",
    "build_genesis_state", "validate_genesis_closure",
    "airdrop_merkle_root", "airdrop_merkle_proof", "airdrop_verify",
    "airdrop_gas_allowance_total", "genesis_hash",
]

# 验证者状态（规范 §19.4）
STATUS_UNBONDED: int = 0
STATUS_BONDED: int = 1
STATUS_UNBONDING: int = 2
_STATUS_NAMES = {0: "UNBONDED", 1: "BONDED", 2: "UNBONDING"}

# 罚没类别（规范 §16.3）
EVIDENCE_CLASSES = ("DOUBLE_PREVOTE", "DOUBLE_PRECOMMIT", "SEVERE", "INVALID_PROPOSAL")


# ══════════════════════════════════════════════════════════════════════
# 1. 值对象与 RLP 编解码
# ══════════════════════════════════════════════════════════════════════

# 规范 §19.2：`Hash("")` —— 表示"该账户没有此键"的**唯一**编码。
HASH_EMPTY = keccak256(b"")


@dataclass
class Account:
    """规范 §19.2：
        StateLeafAccount = RLP([nonce:u64, balance:u256, validator_key:bytes32, system_key:bytes32])
    """
    nonce: int = 0
    balance: int = 0
    validator_key: bytes = b""          # 空哈希表示非验证者账户
    system_key: bytes = b""             # 仅系统账户可非空

    def to_rlp(self) -> bytes:
        """规范 §19.2 的**字面**编码。

        **不得**做任何变换（历史上这里做过 zigzag 映射把 `balance` 翻倍，
        理由是"系统账户余额可为负" —— 那个理由既不在规范里，也早已没有调用方
        （没有任何资金入口允许负数），却让本实现的状态根与任何照规范写的
        实现**永久不同**。见 `PROJECT_REVIEW.md` R-1。）
        """
        if self.balance < 0:
            raise ValueError(
                f"账户余额不得为负（规范 §19.2 的 `balance:u256`）：{self.balance}")
        return encode([self.nonce, self.balance,
                       self.validator_key if self.validator_key else HASH_EMPTY,
                       self.system_key if self.system_key else HASH_EMPTY])

    @classmethod
    def from_rlp(cls, raw: bytes) -> "Account":
        items = decode(raw)
        if not isinstance(items, list) or len(items) != 4:
            raise RLPDecodeError("账户结构必须为 4 项列表")
        vk, sk = items[2], items[3]
        # 规范 §19.2：两个键字段恒为 32 字节；"无此键"用 `Hash("")` 表示，
        # **不得**写成 0 长度（否则叶值有第二种合法编码，状态根不再唯一）。
        for name, v in (("validator_key", vk), ("system_key", sk)):
            if len(v) != 32:
                raise RLPDecodeError(
                    f"{name} 必须为 32 字节（无此键时写 Hash(\"\")），实际 {len(v)} 字节")
        return cls(nonce=_i(items[0]), balance=_i(items[1]),
                   validator_key=b"" if vk == HASH_EMPTY else vk,
                   system_key=b"" if sk == HASH_EMPTY else sk)

    def rlp_hash(self) -> bytes:
        return keccak256(self.to_rlp())


@dataclass
class ValidatorRecord:
    """规范 §19.4：
        ValidatorRecord = RLP([pubkey, effective_stake, unbonding_balance, status,
                               unbond_request_slot, unbond_complete_slot,
                               last_slashable_slot, inactivity_streak,
                               slashed_total, is_founder])
    """
    pubkey: bytes = b""
    effective_stake: int = 0
    unbonding_balance: int = 0
    status: int = STATUS_UNBONDED
    unbond_request_slot: int = 0
    unbond_complete_slot: int = 0
    last_slashable_slot: int = 0
    inactivity_streak: int = 0
    slashed_total: int = 0
    is_founder: int = 0
    pending_stake: int = 0
    pending_unbond: int = 0

    def to_rlp(self) -> bytes:
        return encode([self.pubkey, self.effective_stake, self.unbonding_balance,
                       self.status, self.unbond_request_slot, self.unbond_complete_slot,
                       self.last_slashable_slot, self.inactivity_streak,
                       self.slashed_total, self.is_founder, self.pending_stake,
                       self.pending_unbond])

    @classmethod
    def from_rlp(cls, raw: bytes) -> "ValidatorRecord":
        it = decode(raw)
        if not isinstance(it, list) or len(it) != 12:
            raise RLPDecodeError("验证者记录必须为 12 项列表")
        if len(it[0]) != 32:
            raise RLPDecodeError("验证者公钥必须为 32 字节")
        return cls(pubkey=it[0],
                   effective_stake=_i(it[1]), unbonding_balance=_i(it[2]),
                   status=_i(it[3]), unbond_request_slot=_i(it[4]),
                   unbond_complete_slot=_i(it[5]), last_slashable_slot=_i(it[6]),
                   inactivity_streak=_i(it[7]), slashed_total=_i(it[8]),
                   is_founder=_i(it[9]), pending_stake=_i(it[10]),
                   pending_unbond=_i(it[11]))

    def rlp_hash(self) -> bytes:
        """规范 §19.2：账户的 `validator_key` 必须等于本值。"""
        return keccak256(self.to_rlp())

    @property
    def status_name(self) -> str:
        return _STATUS_NAMES.get(self.status, f"UNKNOWN({self.status})")

    @property
    def in_set(self) -> bool:
        """是否为当前集合成员（BONDED 且在集合快照中）。"""
        return self.status == STATUS_BONDED

    def voting_power(self) -> int:
        """规范 §7.2：`VotingPower_i(E) = EffectiveStake_i(E)`。"""
        return self.effective_stake if self.status == STATUS_BONDED else 0


@dataclass
class PendingSlash:
    """规范 §15.3：证据入块时立即登记（**登记不等于扣除**）。

    关键设计（BUG-4）：`recorded_base` 在**入块时刻**写入，
    因为那时还能读到 `offense_slot` 所属纪元的快照。若等到纪元边界再读，
    历史快照可能已被覆盖 —— 这正是早期草案的缺陷。
    """
    offender: bytes = b""           # 20 字节地址
    evidence_class: str = ""
    offense_slot: int = 0
    recorded_base: int = 0          # atom
    submitter: bytes = b""          # 20 字节地址

    def to_rlp(self) -> bytes:
        return encode([self.offender, _class_code(self.evidence_class),
                       self.offense_slot, self.recorded_base, self.submitter])

    @classmethod
    def from_rlp(cls, raw: bytes) -> "PendingSlash":
        it = decode(raw)
        if not isinstance(it, list) or len(it) != 5:
            raise RLPDecodeError("PendingSlash 必须为 5 项列表")
        return cls(offender=it[0], evidence_class=_class_name(_i(it[1])),
                   offense_slot=_i(it[2]), recorded_base=_i(it[3]), submitter=it[4])

    def dedup_key(self) -> tuple:
        """规范 §15.3 的去重键：`(offender, class, offense_slot)`"""
        return (self.offender, self.evidence_class, self.offense_slot)


def _class_code(name: str) -> int:
    return EVIDENCE_CLASSES.index(name) + 1


def _class_name(code: int) -> str:
    if not 1 <= code <= len(EVIDENCE_CLASSES):
        raise RLPDecodeError(f"非法罚没类别码：{code}")
    return EVIDENCE_CLASSES[code - 1]


@dataclass
class SnapshotSet:
    """规范 §7.1 的纪元快照集合。

    这是**只读**的分配与法定数依据（规范 §7.5 BUG-8）。把三项放在一起，是为了让
    "法定数用一个集合、分配用另一个集合"这类错误在类型层面就无法表达：

    · `membership`    —— 参与法定数计算的地址（规范 §7.4：零权成员被排除）
    · `voting_power`  —— 地址 → 投票权（= `EffectiveStake`，规范 §7.2）
    · `staked_supply` —— 集合内有效质押之和；发行曲线的输入（规范 §28.4）
    · `records`       —— 快照时的验证者记录副本，用于罚没基数（规范 §15.3）
    """
    membership: List[bytes] = field(default_factory=list)
    voting_power: List[Tuple[bytes, int]] = field(default_factory=list)
    staked_supply: int = 0
    records: List[bytes] = field(default_factory=list)     # 各记录的 RLP，**按地址升序**

    def __post_init__(self) -> None:
        """规范 §19.5：一切列表都按地址 20 字节升序。

        快照必须在**类型层面**保证顺序确定性 —— 若按输入顺序存储，
        同一的验证者集合因输入顺序不同会产生不同的 `state_root`，
        独立实现之间就无法互认。此处统一排序，调用方无需关心顺序。
        """
        from .crypto_backend import address_from_pubkey
        self.membership = sorted(self.membership)
        self.voting_power = sorted(self.voting_power, key=lambda kv: kv[0])

        def _addr(raw: bytes) -> bytes:
            return address_from_pubkey(ValidatorRecord.from_rlp(raw).pubkey)

        self.records = sorted(self.records, key=_addr)

    def vp_of(self, address: bytes) -> int:
        for a, vp in self.voting_power:
            if a == address:
                return vp
        return 0

    def record_of(self, address: bytes) -> Optional[ValidatorRecord]:
        """从快照取该地址的验证者记录（罚没基数必须由此得出，规范 §15.3）。"""
        from .crypto_backend import address_from_pubkey
        for raw in self.records:
            rec = ValidatorRecord.from_rlp(raw)
            if address_from_pubkey(rec.pubkey) == address:
                return rec
        return None

    def to_rlp(self) -> bytes:
        return encode([list(self.membership),
                       [[a, v] for a, v in self.voting_power],
                       self.staked_supply, list(self.records)])

    @classmethod
    def from_rlp(cls, raw) -> "SnapshotSet":
        it = decode(raw)
        if not isinstance(it, list) or len(it) != 4:
            raise RLPDecodeError("SnapshotSet 必须为 4 项列表")
        i = lambda b: int.from_bytes(b, "big")            # noqa: E731
        return cls(membership=[bytes(a) for a in it[0]],
                   voting_power=[(e[0], i(e[1])) for e in it[1]],
                   staked_supply=i(it[2]), records=[bytes(r) for r in it[3]])


@dataclass
class SystemState:
    """规范 §19.5：系统账户 `0x…0001` 的 `system_key` 所承诺的链级状态。"""
    epoch_current: int = 0
    year_index: int = 0
    year_start_slot: int = 0
    total_supply: int = 0
    total_burned_basefee: int = 0
    total_burned_annual: int = 0
    total_burned_slash: int = 0
    total_burned_dust: int = 0
    total_burned_inactivity: int = 0
    # **单边销毁累计**（规范 §19.5 / BUG-47）：已从供应量中销毁、但**从未归属
    # 任何真实资金科目**（账户余额或质押池）的量。唯一来源是年度销毁（§28.5），
    # 它不扣任何余额或质押，直接把 5% 从 `total_supply` 抽走。
    #
    # 它是**唯一**参与守恒等式的销毁科目，其余四个 `total_burned_*` 分账只是审计留痕：
    #     Σ 真实资金 == total_supply + total_burned_unbacked
    total_burned_unbacked: int = 0
    snapshot: SnapshotSet = field(default_factory=SnapshotSet)
    pending_slashes: List[PendingSlash] = field(default_factory=list)
    settled_slashes: List[Tuple[bytes, str, int]] = field(default_factory=list)
    airdrop_root: bytes = b"\x00" * 32
    airdrop_pending: int = 0
    airdrop_claimed: List[Tuple[bytes, int]] = field(default_factory=list)

    # ── 向后兼容属性（旧字段名仍可用，避免大量调用点改名出错）──
    @property
    def epoch_set_vp(self):
        return self.snapshot.voting_power

    @property
    def epoch_set_membership(self):
        return self.snapshot.membership

    # ── RLP ──
    def to_rlp(self) -> bytes:
        return encode([
            self.epoch_current, self.year_index, self.year_start_slot,
            self.total_supply, self.total_burned_basefee, self.total_burned_annual,
            self.total_burned_slash, self.total_burned_dust,
            self.total_burned_inactivity, self.total_burned_unbacked,
            self.snapshot.to_rlp(),
            [ps.to_rlp() for ps in self.pending_slashes],
            [[o, _class_code(c), s] for o, c, s in self.settled_slashes],
            self.airdrop_root if self.airdrop_root else b"",
            self.airdrop_pending,
            [[a, i] for a, i in self.airdrop_claimed],
        ])

    @classmethod
    def from_rlp(cls, raw: bytes) -> "SystemState":
        it = decode(raw)
        if not isinstance(it, list) or len(it) != 16:
            raise RLPDecodeError("SystemState 必须为 16 项列表")
        i = _i
        return cls(
            epoch_current=i(it[0]), year_index=i(it[1]), year_start_slot=i(it[2]),
            total_supply=i(it[3]), total_burned_basefee=i(it[4]),
            total_burned_annual=i(it[5]), total_burned_slash=i(it[6]),
            total_burned_dust=i(it[7]), total_burned_inactivity=i(it[8]),
            total_burned_unbacked=i(it[9]),
            snapshot=SnapshotSet.from_rlp(it[10]),
            pending_slashes=[PendingSlash.from_rlp(x) for x in it[11]],
            settled_slashes=[(e[0], _class_name(i(e[1])), i(e[2])) for e in it[12]],
            airdrop_root=it[13] if it[13] else b"\x00" * 32,
            airdrop_pending=i(it[14]),
            airdrop_claimed=[(e[0], i(e[1])) for e in it[15]],
        )

    def rlp_hash(self) -> bytes:
        return keccak256(self.to_rlp())

    # ── 派生量 ──
    def total_voting_power(self) -> int:
        return self.snapshot.staked_supply

    def quorum(self) -> int:
        """规范 §9.1：`ceil_div(2 × S_epoch, 3)`，**atom 粒度**（BUG-35）。"""
        return P.quorum(self.total_voting_power())

    def voting_power_of(self, address: bytes) -> int:
        return self.snapshot.vp_of(address)

    def prereq_dedup(self) -> set:
        return {k for k in (_class_dedup(s) for s in self.settled_slashes)}

    def pending_dedup(self) -> set:
        return {ps.dedup_key() for ps in self.pending_slashes}


def _class_dedup(t: Tuple[bytes, str, int]) -> tuple:
    return (t[0], t[1], t[2])


# ══════════════════════════════════════════════════════════════════════
# 2. 承诺与规则
# ══════════════════════════════════════════════════════════════════════

def validator_set_commitment(records: Sequence[ValidatorRecord]) -> bytes:
    """规范 §20.5：`Hash(CHAIN("AGORA/VALSET/v0.2.2", RLP(按地址升序的记录列表)))`

    排序规则按 §R-05.3 的"规范排序 = 地址 20 字节升序"。
    调用方必须传入已按地址升序的记录；本函数会**再次排序**以保证确定性。
    """
    from .crypto_backend import address_from_pubkey
    ordered = sorted(records, key=lambda r: address_from_pubkey(r.pubkey))
    return keccak256(P.TAG_VALSET + chain(encode([r.to_rlp() for r in ordered])))


def meets_account_pruning_rule(acc: Account) -> bool:
    """规范 §19.3：账户回收条件。

    `balance == 0` 且 `nonce == 0` 且 `validator_key` 为空哈希 且 `system_key` 为空哈希
      ⇒ 必须从状态中删除。
    """
    return (acc.balance == 0 and acc.nonce == 0
            and not acc.validator_key and not acc.system_key)


# ══════════════════════════════════════════════════════════════════════
# 3. 状态容器
# ══════════════════════════════════════════════════════════════════════

class State:
    """规范 §19 的状态。

    内部结构：
        · `accounts`   —— MPT，键为原始 20 字节地址（`put` 内部会做 `secure_key`）
        · `validators` —— 地址 → ValidatorRecord 的映射（不在 trie 中，由 state_root
                          与 ValidatorSetCommitment 共同承诺）
        · `system`     —— SystemState（其承诺写入系统账户的 `system_key`）
    """

    __slots__ = ("accounts", "validators", "_system", "_dirty")

    def __init__(self) -> None:
        self.accounts = MerklePatriciaTrie()
        self.validators: Dict[bytes, ValidatorRecord] = {}
        self._system = SystemState()
        self._dirty = False

    # ── 账户 ────────────────────────────────────────────────────────
    def get_account(self, address: bytes) -> Optional[Account]:
        raw = self.accounts.get(address)
        return Account.from_rlp(raw) if raw else None

    def account_or_empty(self, address: bytes) -> Account:
        return self.get_account(address) or Account()

    def set_account(self, address: bytes, acc: Account) -> None:
        if len(address) != 20:
            raise ValueError("地址必须为 20 字节")
        if meets_account_pruning_rule(acc):
            # 规范 §19.3：满足回收条件的账户必须**从状态树移除键**（而非写空值），
            # 否则残留空叶子会让状态根依赖写入历史，破坏跨实现确定性（BUG-34 同源）。
            self.accounts.delete(address)
        else:
            self.accounts.put(address, acc.to_rlp())
        self._dirty = True

    def _credit_neutral(self, address: bytes, amount: int) -> None:
        """**中性入账**：给账户增加余额，**不改变** `total_supply`。

        语义红线：它只允许用于**已经存在于账上的钱**——即同一笔金额刚刚
        被从某个真实资金科目扣走，本调用只是把它**重新指派**给别的持有者。
        合规调用点（全部经过审计，已逐一核对）：

        | 调用点 | 钱的来源（已被扣走） |
        |---|---|
        | 创世构建（§32.2） | 创世分配本身计入 `INITIAL_SUPPLY`，不是发行 |
        | 提案者份额、见证池、优先费池（§28.2/§28.4） | 本块 `mint` 的区块奖励 |
        | 交易 `value` 入账（§16.4） | 发送者余额已在同一函数内扣走 |
        | 罚没奖励给证据提交者（§15.4） | 被罚没者已被扣走全额 `amt` |
        | 不活跃/罚没把验证者退出时退还质押（§28.6） | 记录里的质押被清零 |

        **违规使用的后果**：凭空造币且 `total_supply` 不变 ⇒ 守恒等式立刻失衡，
        且攻击者可无中生有。因此本方法**不得**被用于"发行"或"奖励"等新钱来源，
        那些场景 **MUST** 走 `mint()`。

        实现注意事项：`amount == 0` 时**必须提前返回**。否则会给不存在的账户
        写入一条 `balance = 0` 的记录，使状态根依赖调用历史，破坏跨实现确定性
        （规范 §19.3 的账户回收规则要求零余额账户**不得**留在状态树中）。
        """
        if amount < 0:
            raise ValueError("金额必须非负")
        if amount == 0:
            return
        acc = self.account_or_empty(address)
        acc.balance += amount
        self.set_account(address, acc)

    def mint(self, address: bytes, amount: int, reason: str = "") -> None:
        """**发行**：增加余额**并且**增加 `total_supply`（规范 §28 的区块奖励等）。

        这是唯一可以增加供应量的入口。任何其它路径都不允许改变 `total_supply`。
        """
        if amount < 0:
            raise ValueError("mint 金额必须非负")
        if amount == 0:
            return
        acc = self.account_or_empty(address)
        acc.balance += amount
        self._system.total_supply += amount
        self.set_account(address, acc)

    def burn(self, address: bytes, amount: int, category: str) -> None:
        """**销毁**：扣减余额**并且**扣减 `total_supply`。

        `category ∈ {basefee, annual, slash, dust}` —— 规范 §29 要求四类销毁分账记账。
        """
        if amount < 0:
            raise ValueError("burn 金额必须非负")
        if amount == 0:
            return
        acc = self.account_or_empty(address)
        if acc.balance < amount:
            raise ValueError(f"销毁额超过余额：{amount} > {acc.balance}")
        acc.balance -= amount
        self._system.total_supply -= amount
        attr = f"total_burned_{category}"
        if not hasattr(self._system, attr):
            raise ValueError(f"非法的销毁科目：{category}")
        setattr(self._system, attr, getattr(self._system, attr) + amount)
        self.set_account(address, acc)

    def deduct(self, address: bytes, amount: int, purpose: str = "") -> None:
        """**扣费**：从账户余额扣出一笔钱，暂不计入销毁、也不转给他人。

        与其它三个入口的区别（这是本模块的全部资金操作，缺一不可）：

        | 入口 | 余额 | total_supply | 用途 |
        |---|---|---|---|
        | `mint`        | +   | + | 发行（区块奖励） |
        | `burn`        | −   | − | 从某账户收回并销毁 |
        | `burn_supply` | 不变 | − | 系统级销毁（年度计划销毁） |
        | `transfer`    | −/+ | 不变 | 账户间移动 |
        | `deduct`      | −   | 不变 | **先收费后分配**（gas 预留的中间步骤） |

        `deduct` 存在的意义：费用**必须先从发送者扣出，再决定它的去向**
        （销毁 / 给提案者 / 进见证池）。若直接用 `burn` 扣，就会把"尚未分配的
        费用"提前记成销毁，导致销毁分账虚高、供应量对不上。
        """
        if amount < 0:
            raise ValueError("扣费额必须非负")
        if amount == 0:
            return
        acc = self.account_or_empty(address)
        if acc.balance < amount:
            raise ValueError(f"{purpose or 'deduct'}：余额不足 {amount} > {acc.balance}")
        acc.balance -= amount
        self.set_account(address, acc)

    def burn_supply(self, amount: int, category: str, unbacked: bool = False) -> None:
        """**记账销毁**：把 `amount` 从 `total_supply` 中销去。

        有两个调用场景，**必须**用 `unbacked` 明确区分（否则守恒检查会误报）：

        **① 结算扣款（`unbacked=False`，默认）** —— 纪元结算的不活跃惩罚与罚没。
        调用契约：调用方 **MUST** 在调用前**已经**把这笔钱从某个真实资金科目
        扣走（`settle_epoch` 从 `effective_stake`／`unbonding_balance`／`balance` 扣）。
        此时 `counted` 侧已因调用方的扣减而下降，本方法让 `total_supply` 侧
        同步下降，等式 `counted == total_supply + total_burned_unbacked` 自动保持。
        本方法**绝不会**再去动任何账户余额或质押池。

        **② 年度销毁（`unbacked=True`）** —— §28.5 的单边销毁。
        它不扣任何余额或质押，直接把 `floor(total_supply × 5%)` 从供应量里抽走。
        这种情况下 `counted` 侧**不会**下降，因此必须把金额累加到
        `total_burned_unbacked`，守恒等式右侧补上它才配平。

        对比 `burn(账户, …)`：用于**同一步内**完成"扣真实账户余额 + 减总量"
        的销毁（基础费、账户级罚没），两侧同减，不影响等式。
        """
        if amount < 0:
            raise ValueError("销毁额必须非负")
        if amount == 0:
            return
        if amount > self._system.total_supply:
            raise ValueError(f"销毁额 {amount} 超过总供应量 {self._system.total_supply}")
        attr = f"total_burned_{category}"
        if not hasattr(self._system, attr):
            raise ValueError(f"非法的销毁科目：{category}")
        self._system.total_supply -= amount                  # ① 总供应量减少
        if unbacked:
            # ② 仅**单边**销毁（年度销毁）才计入单边销毁累计——它参与守恒等式。
            #    结算扣款必须先由调用方扣钱，故 unbacked=False，不在此累加。
            self._system.total_burned_unbacked += amount
        setattr(self._system, attr, getattr(self._system, attr) + amount)
        self._dirty = True

    def system_burned_total(self) -> int:
        """**单边销毁累计**：不归属任何真实资金科目的那部分已销毁供应量。

        唯一来源是年度销毁（§28.5）。守恒等式右侧必须加回它。"""
        return self._system.total_burned_unbacked

    def transfer(self, src: bytes, dst: bytes, amount: int) -> None:
        """**转账**：账户之间中性移动，**不改变** `total_supply`。

        余额不足时抛错；调用方本应在交易校验阶段（规范 §16.4.2 第 10 项）已拒绝该交易，
        因此这里的异常属于实现缺陷而非正常路径。
        """
        if amount < 0:
            raise ValueError("transfer 金额必须非负")
        if amount == 0:
            self._ensure_touched(dst)
            return
        s = self.account_or_empty(src)
        if s.balance < amount:
            raise ValueError(f"余额不足：需要 {amount}，实际 {s.balance}")
        s.balance -= amount
        self.set_account(src, s)
        d = self.account_or_empty(dst)
        d.balance += amount
        self.set_account(dst, d)

    def _ensure_touched(self, address: bytes) -> None:
        """零额转账的确定性处理：账户已存在则不动；不存在则**不创建**。

        规范 §33.0 要求"金额为 0 时不创建账户"，否则两个实现的状态根会不一致。
        """
        return

    # 兼容性别名：**仅供创世构建使用**（创世时余额本来就计入 INITIAL_SUPPLY，
    # 不通过 mint 增加 total_supply）。其它任何地方都不得使用。
    def credit(self, address: bytes, amount: int) -> None:
        raise RuntimeError(
            "State.credit 已移除：它会凭空造币而不改变 total_supply，破坏守恒不变量。\n"
            "请改用 mint()（发行）/ burn()（销毁）/ transfer()（转账）。")

    def debit(self, address: bytes, amount: int) -> None:
        raise RuntimeError(
            "State.debit 已移除：请改用 burn()（销毁）或 transfer()（转账）。")

    # ── 验证者 ──────────────────────────────────────────────────────
    def get_validator(self, address: bytes) -> Optional[ValidatorRecord]:
        return self.validators.get(address)

    def set_validator(self, address: bytes, rec: ValidatorRecord) -> None:
        """写入验证者记录，并同步账户的 `validator_key`（规范 §19.2）。"""
        if len(address) != 20:
            raise ValueError("地址必须为 20 字节")
        self.validators[address] = rec
        acc = self.account_or_empty(address)
        acc.validator_key = rec.rlp_hash() if rec.status != STATUS_UNBONDED or \
            rec.effective_stake or rec.unbonding_balance else b""
        self.set_account(address, acc)

    def check_validator_key(self, address: bytes) -> bool:
        """断言账户的 `validator_key` 与其验证者记录一致（完整性自检）。"""
        rec = self.validators.get(address)
        acc = self.get_account(address)
        if rec is None:
            return acc is None or not acc.validator_key
        return bool(acc and acc.validator_key == rec.rlp_hash())

    # ── 系统状态 ────────────────────────────────────────────────────
    @property
    def system(self) -> SystemState:
        return self._system

    def flush_system(self) -> None:
        """把 SystemState 的承诺写入系统账户（规范 §19.5）。"""
        acc = self.account_or_empty(P.SYSTEM_ADDRESS)
        acc.system_key = self._system.rlp_hash()
        self.set_account(P.SYSTEM_ADDRESS, acc)

    # ── 根与承诺 ────────────────────────────────────────────────────
    @property
    def state_root(self) -> bytes:
        """规范 §19.1：`state_root := MPT_root`（不做二次哈希）。"""
        return self.accounts.root

    def validator_set_commitment(self) -> bytes:
        return validator_set_commitment(list(self.validators.values()))

    # ── 一致性自检 ──────────────────────────────────────────────────
    def check_supply_conservation(self) -> Tuple[bool, int, int]:
        """守恒等式（唯一权威形式，经全部销毁路径实测确定）：

        ```
        counted  ==  total_supply + total_burned_unbacked
        ```

        `counted` 包含全部真实资金科目：所有账户 `balance`，以及验证者的
        `effective_stake` / `unbonding_balance` / `pending_stake` / `pending_unbond`。

        两类销毁对等式的影响不同：

        | 销毁路径 | 余额之和 | total_supply | system_burned |
        |---|---|---|---|
        | `burn(账户, …)`（基础费、账户级罚没） | ↓ | ↓ | 不变 |
        | `burn_supply(…)`（年度销毁、结算扣款） | 不变 | ↓ | ↑ |

        第一类"从真实账户收走并销毁"，两侧同减；
        第二类销毁的是不属于任何账户余额的供应量（结算时从 `effective_stake`
        扣走、年度计划销毁），因此等式左侧必须补上 `system_burned` 才配平。

        本等式在 `tests/test_state.py`、`tests/test_block.py`、
        `tests/test_tx.py` 与 `tools/agora_vectors.py` 中被强制校验。
        """
        counted = 0
        sys_key = secure_key(P.SYSTEM_ADDRESS)
        for hashed_key, raw in self.accounts.items():
            # **排除系统账户**：它是"销毁出口"，其余额在发生系统级销毁后为负，
            # 若计入会造成销毁量被重复计算（这正是本实现此前长期失衡的根因）。
            # 系统账户不持有任何真实资金：它的 `system_key` 只承诺链级状态。
            if hashed_key == sys_key:
                continue
            counted += Account.from_rlp(raw).balance
        for rec in self.validators.values():
            counted += (rec.effective_stake + rec.unbonding_balance
                        + rec.pending_stake + rec.pending_unbond)
        # 守恒等式（**唯一权威形式**，全部销毁路径实测确定）：
        #
        #     counted == total_supply + total_burned_unbacked
        #
        # `counted` = 全部账户 `balance`（**不含** SYSTEM_ADDRESS）
        #           + Σ(`effective_stake + unbonding_balance + pending_stake + pending_unbond`)
        #
        # 两条销毁路径的差别是**实现阻塞级**的，必须分清：
        #
        # | 销毁路径 | counted | total_supply | system_burned |
        # |---|---|---|---|
        # | `burn(账户, x)`（基础费、账户级） | ↓ x（余额减少） | ↓ x | 不变 |
        # | `burn_supply(x, …)`（年度销毁） | **不变** | ↓ x | **↑ x** |
        #
        # · 第一类"从真实账户收走并销毁"：两侧同减，等式不受影响；
        # · 第二类"单边销毁"：年度销毁（§28.5）不扣任何余额或质押，
        #   直接把 5% 从总供应量里抽走，因此左侧必须补上 `total_burned_unbacked` 才配平。
        #
        # **结算扣款不属于第二类**：`settle_epoch` 先从不活跃/被罚没者的
        # `effective_stake`／`unbonding_balance`／`balance` 扣钱，左侧已随之下降，
        # 再调 `burn_supply` 把 `total_supply` 拉下来——语义与第一类相同。
        # 若把结算扣款也按"左侧不变"处理，`total_supply` 会比真实资金合计多出
        # 全部惩罚额，任何做守恒自检的诚实节点都会拒绝合法区块。
        #
        # **排除 SYSTEM_ADDRESS**：它是优先费池的中转站，块内净额为零；
        # 若计入，销毁量会被重复计算（这正是本实现此前长期失衡的根因之一）。
        #
        # 曾长期失衡的其他根因（均已修复，勿再引入）：
        #   ① `burn_supply` 曾被写成 "mint 到系统账户再 burn" ⇒ 系统账户留下余额；
        #   ② 罚没曾把全额 `amt` 记为销毁，而其中 20% 是给证据提交者的**再分配**
        #      （只有 `amt − reward` 离开供应量）。
        #
        # 注：`airdrop_pending` 是金库账户余额的**只读镜像**，**不得**计入 `counted`
        # （否则空投金额被重复计算：金库余额已经是某个账户的 `balance`）。
        sys_burned = self._system.total_burned_unbacked
        return (counted == self._system.total_supply + sys_burned,
                counted, self._system.total_supply + sys_burned)


@dataclass
class GenesisAllocation:
    """创世配置：`validators`/`balances` 为 `(pubkey, amount)`，`airdrop` 为条目列表。

    创世 **MUST** 满足规范 §32.2 的金额闭合约束，校验见 `validate_genesis_closure`。
    """
    validators: List[Tuple[bytes, int]]
    balances: List[Tuple[bytes, int]] = field(default_factory=list)
    airdrop: List["AirdropEntry"] = field(default_factory=list)
    genesis_timestamp: int = P.GENESIS_TIMESTAMP


def validate_genesis_closure(alloc: GenesisAllocation,
                            allow_unsafe: bool = False) -> List[str]:
    """规范 §32.2 的创世闭合校验。返回错误列表（空列表 = 通过）。

    `allow_unsafe=True` 时跳过**仅供公开网络**的两条约束
    （验证者数 ≥ 4、单人质押 < 总量/3），用于 < 4 个验证者的
    编码 / 状态机 / 传输层联调。**绝不可**用于任何公开网络：
    此时单个验证者即可独自达成法定数，安全性（无分叉）不再成立。
    """
    from .crypto_backend import address_from_pubkey

    errs: List[str] = []
    n = len(alloc.validators)
    total_stake = sum(a for _, a in alloc.validators)
    if n < P.GENESIS_VALIDATOR_COUNT:
        msg = f"创始验证者必须 ≥ {P.GENESIS_VALIDATOR_COUNT} 名（当前 {n}）"
        if allow_unsafe:
            errs.append(f"[已豁免/仅供联调] {msg} —— 单人即可达成法定数，"
                        f"不得用于公开网络")
        else:
            errs.append(msg)
    for pk, amount in alloc.validators:
        if len(pk) != 32:
            errs.append(f"验证者公钥必须为 32 字节（实际 {len(pk)}）")
        if amount < P.MIN_VALIDATOR_STAKE:
            errs.append(f"{pk.hex()[:16]}… 质押低于最低值 "
                        f"{P.MIN_VALIDATOR_STAKE // P.ATOM_PER_AGORA} AGORA")
        if total_stake and amount * 3 >= total_stake:
            msg = f"{pk.hex()[:16]}… 质押 ≥ 权益总量 1/3（可单独达成法定数，禁止）"
            if allow_unsafe:
                errs.append(f"[已豁免/仅供联调] {msg}")
            else:
                errs.append(msg)
    if len({address_from_pubkey(pk) for pk, _ in alloc.validators}) != n:
        errs.append("创始验证者存在重复地址")

    airdrop_total = sum(e.amount for e in alloc.airdrop)
    if airdrop_total > P.AIRDROP_MAX_SHARE:
        errs.append(f"空投总额 {airdrop_total} 超过上限 {P.AIRDROP_MAX_SHARE}")
    gas_allowance_total = sum(e.gas_allowance for e in alloc.airdrop)

    counted = (total_stake + sum(a for _, a in alloc.balances)
               + airdrop_total + gas_allowance_total)
    if counted != P.INITIAL_SUPPLY:
        diff = counted - P.INITIAL_SUPPLY
        errs.append(f"创世金额不闭合：统计 {counted}，应为 {P.INITIAL_SUPPLY}，"
                    f"差额 {diff:+d} atom")
    # GenesisTimestamp：**主网必须等于规范冻结值**；测试网可自定，便于立刻启动。
    #
    # 规范 §32.2 冻结的是**主网**创世时间戳。DEPLOYMENT_PLAN.md §6 明确列出测试网与
    # 主网只允许两处不同，`GenesisTimestamp` 正是其中之一（另一处是 `chain_id`）。
    # 此前本校验对**所有**网络都强制主网时间戳，使测试网根本无法构建创世 ——
    # 这是"把主网规则套到测试网"的一类实现阻塞（BUG-62）。
    net = P.network_name()
    if net == "mainnet" and alloc.genesis_timestamp != P.GENESIS_TIMESTAMP:
        errs.append(f"主网 GenesisTimestamp 应为 {P.GENESIS_TIMESTAMP}"
                    f"（2026-10-01 00:00:00 UTC），实际 {alloc.genesis_timestamp}")
    if net != "mainnet" and alloc.genesis_timestamp <= 0:
        errs.append(f"{net} 的 GenesisTimestamp 必须为正整数，实际 "
                    f"{alloc.genesis_timestamp}")
    return errs


@dataclass
class AirdropEntry:
    """规范 §32.5（BUG-41 修正后）：创世分配表条目。

    条目为 `(pubkey, amount, gas_allowance, note)`；
    叶子哈希 = `Hash(CHAIN("AGORA/AIRDROP/v0.2.2", pubkey, u256(amount), u256(gas_allowance)))`

    `gas_allowance` 必须计入叶子：它在创世时直接记入受益人余额
    （否则受益人付不起首次领取交易的 gas 费，形成死锁），因此必须可被第三方审计。
    """
    pubkey: bytes
    amount: int
    gas_allowance: int = 0
    note: str = ""
    # 规范 §32.5（BUG-87，MUST）：`index` **必须**是叶子的组成部分。
    # 旧叶子不含 index ⇒ Merkle 证明与该条目**并非一一对应** ⇒ 同一份权益可以
    # 换一个 index 反复领取（唯一性判据是 `(from, index)`，而 index 由提交者自选），
    # 只要受益人知道自己的证明，就能把**整个金库**（含他人的份额）领空。
    # 实测：A（应领 1000）用同一份证明依次以 index=1/2 领取，把 2000 的金库领到 0。
    # `index` 由分配表给定（建议取"按叶子哈希升序后的位置"），实现 **MUST NOT**
    # 自行推导或忽略它。
    index: int = 0

    def __post_init__(self) -> None:
        if len(self.pubkey) != 32:
            raise ValueError(f"空投条目公钥必须为 32 字节，实际 {len(self.pubkey)}")
        for name, v in (("amount", self.amount), ("gas_allowance", self.gas_allowance)):
            if not isinstance(v, int) or isinstance(v, bool):
                raise TypeError(
                    f"{name} 必须为整数 atom（实际 {type(v).__name__}: {v!r}）。"
                    f"注意 AirdropEntry 的字段顺序是 (pubkey, amount, gas_allowance, note) —— "
                    f"按位置传参时极易把 note 传到 gas_allowance。")
            if not (0 <= v < 2 ** 256):
                raise ValueError(f"{name} 必须在 [0, 2^256)")
        if self.amount == 0 and self.gas_allowance == 0:
            raise ValueError("空投条目的 amount 与 gas_allowance 不能同时为 0")

    def leaf(self) -> bytes:
        # 标签**必须前置**（规范 §20.1：标签 ASCII 无长度前缀），
        # 且宽度按 §32.5 显式声明：u64(index), u256(amount), u256(gas_allowance)。
        # `index` 在**第一位**、且必须是叶子的一部分（BUG-87，见字段注释）。
        return keccak256(P.TAG_AIRDROP + chain(
            ("u64", self.index), self.pubkey,
            ("u256", self.amount), ("u256", self.gas_allowance)))


def airdrop_gas_allowance_total(entries: Sequence[AirdropEntry]) -> int:
    """规范 §32.5（BUG-41）：全部条目的 `gas_allowance` 之和。

    这部分**不进金库**，而是在创世时直接记入各受益人余额，使其付得起首次领取的 gas 费。
    """
    return sum(e.gas_allowance for e in entries)


def airdrop_merkle_proof(entries: Sequence[AirdropEntry], target_index: int) -> Tuple[bytes, int]:
    """生成 `target_index` 条目的 Merkle 证明。

    返回 `(proof, sorted_index)`。其中 `sorted_index` 是**按叶子哈希升序**后该条目的位置，
    它才是规范 §32.6 第 ④ 项去重键 `(address, index)` 中的 `index` —— 使用排序后位置
    可以让索引与"分配表的物理存储顺序"解耦，从而与插入顺序无关（确定性要求）。
    """
    if not entries:
        raise ValueError("空分配表的条目下标越界")
    if not 0 <= target_index < len(entries):
        raise ValueError(f"条目下标越界：{target_index}")
    leaves = sorted(e.leaf() for e in entries)
    target = entries[target_index].leaf()
    idx = leaves.index(target)
    sorted_index = idx
    level = leaves
    proof: list = []
    while len(level) > 1:
        if idx % 2 == 0 and idx + 1 < len(level):
            proof.append(level[idx + 1])
        elif idx % 2 == 1:
            proof.append(level[idx - 1])
        nxt = []
        for j in range(0, len(level) - 1, 2):
            a, b = sorted((level[j], level[j + 1]))
            nxt.append(keccak256(b"\x01" + a + b))
        if len(level) % 2:
            nxt.append(level[-1])
        level, idx = nxt, idx // 2
    return tuple(proof), sorted_index


def airdrop_verify(entries_or_root, pubkey: bytes, amount: int,
                   gas_allowance: int, proof: Sequence[bytes], root: bytes,
                   index: int = 0) -> bool:
    """校验 Merkle 证明（规范 §32.6 第 ① 项）。

    `index` **必须**与分配表里的条目一致（BUG-87）：它是叶子的一部分，
    换一个 index 就无法复现该叶子 ⇒ 同一份权益无法被重复领取。
    """
    h = keccak256(P.TAG_AIRDROP + chain(
        ("u64", index),
        pubkey, ("u256", amount), ("u256", gas_allowance)))
    for sib in proof:
        if len(sib) != 32:
            return False
        a, b = (h, sib) if h <= sib else (sib, h)
        h = keccak256(b"\x01" + a + b)
    return h == root


def airdrop_merkle_root(entries: Sequence[AirdropEntry]) -> bytes:
    """规范 §32.5 的 `airdrop_root`（内部节点按字典序连接 + 域分隔前缀）。"""
    if not entries:
        return b"\x00" * 32
    level = sorted(e.leaf() for e in entries)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            a, b = sorted((level[i], level[i + 1]))
            nxt.append(keccak256(b"\x01" + a + b))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def build_genesis_state(alloc: GenesisAllocation,
                        strict: bool = True,
                        allow_unsafe: bool = False) -> Tuple[State, List[str]]:
    """由创世配置构建初始状态。返回 `(state, 错误列表)`。

    `strict=True` 时若存在闭合错误则抛 `ValueError`（主网必须如此）。
    """
    from .crypto_backend import address_from_pubkey

    errs = validate_genesis_closure(alloc, allow_unsafe=allow_unsafe)
    if errs and strict:
        raise ValueError("创世配置不合法：\n  - " + "\n  - ".join(errs))

    st = State()
    st.system.epoch_current = P.epoch_of(0)          # 创世块 claimed_slot = 0
    st.system.year_start_slot = 0
    st.system.total_supply = P.INITIAL_SUPPLY

    # 创始验证者：写入验证者记录与账户
    for pk, amount in alloc.validators:
        addr = address_from_pubkey(pk)
        rec = ValidatorRecord(pubkey=pk, effective_stake=amount,
                              status=STATUS_BONDED, is_founder=1)
        st.set_validator(addr, rec)

    # 普通余额（创世余额本就包含在 INITIAL_SUPPLY 内，**不**走 mint）
    for pk, amount in alloc.balances:
        st._credit_neutral(address_from_pubkey(pk), amount)

    # 空投：金额存入金库（规范 §32.5），根写入系统状态
    airdrop_total = sum(e.amount for e in alloc.airdrop)
    st.system.airdrop_root = airdrop_merkle_root(alloc.airdrop)
    st.system.airdrop_pending = airdrop_total
    st._credit_neutral(P.AIRDROP_VAULT_ADDRESS, airdrop_total)
    # BUG-41：gas_allowance 直接记入受益人余额（否则他们付不起领取交易的 gas 费）
    for e in alloc.airdrop:
        if e.gas_allowance:
            st._credit_neutral(address_from_pubkey(e.pubkey), e.gas_allowance)

    # 创世集合快照 = 创始验证者集合（规范 §7.1 的 E₀ 情形）
    import copy as _copy
    snap = SnapshotSet(
        membership=sorted(address_from_pubkey(pk) for pk, _ in alloc.validators),
        voting_power=sorted(((address_from_pubkey(pk), amount)
                             for pk, amount in alloc.validators), key=lambda kv: kv[0]),
        staked_supply=sum(a for _, a in alloc.validators),
        records=[st.get_validator(address_from_pubkey(pk)).to_rlp()
                 for pk, _ in alloc.validators])
    st.system.snapshot = snap          # __post_init__ 会统一排序

    st.flush_system()
    return st, errs


def genesis_hash(state: State, alloc: GenesisAllocation) -> bytes:
    """创世块哈希（规范 §32.4）：由创世状态根与配置确定推导，不得人工填写。"""
    payload = chain(
        P.TAG_GENESIS,
        P.CHAIN_ID_BYTES,
        alloc.genesis_timestamp,
        state.state_root,
        state.validator_set_commitment(),
    )
    return keccak256(payload)
