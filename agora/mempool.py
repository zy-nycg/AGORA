# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 交易池（mempool）
================================

**最重要的一句话：交易池不是共识。**
-------------------------------------
链上有效的区块只由 §22 的 12 项谓词定义：**只要区块里的交易逐笔通过 §16.4.2、
同块 nonce 严格递增、累计 gas 不超限，它就是有效区块** —— 与"本节点自己的交易池里
有什么"**毫无关系**。规范 §16.4.3 明确：验证者 **MUST NOT** 因为"排序不符"
或"疑似漏掉某交易"而拒绝区块。

因此本模块只做两件事，且都**不影响**区块有效性判定：

1. **暂存**：把收到的、当前看起来合法的交易存起来（准入校验只是"尽力而为"：
   状态会变，真正的判定发生在打包与执行时）；
2. **挑选**：提案者出块时按**确定性规则**选出一批交易塞进区块。

为什么必须"确定性"
------------------
提案者可能在同一高度、同一轮里被调用多次（重试、超时重发）。若每次选出的
交易集合或顺序不同，它就会对**不同的区块哈希**投票，把全网投票打散
（这正是 BUG-46 的形态）。因此：

* 选择规则是**纯函数**：`(池内容, 状态, base_fee, 槽) → 交易列表`；
* 排序键完全指定：**优先费单价降序 → 交易哈希升序**（哈希作为最终 tie-break，
  保证"同价"时也有唯一顺序）；
* 同一发送者的交易 **MUST** 按 nonce 升序排列（否则区块自身违反 §22 第 10 项）。

准入规则（哪条不满足就**不进池**）
----------------------------------
| 规则 | 理由 |
|---|---|
| 已在池中（同 `tx_hash`） | 去重；也用于切断广播回路 |
| 已在链上（`nonce < account.nonce`） | 重放；§16.4.2 第 9 项本来会拒 |
| `nonce` 出现"空洞"（`> account.nonce + 池内连续段`） | 前面那笔没到，先存着会让提案者选到它却执行失败 ⇒ 整个区块被判无效。**这是最容易踩的坑**：入池时必须维护"连续段"，否则一次乱序到达就能让提案者的区块被全网拒绝 |
| §16.4.2 全流水线不通过（当前状态、当前基础费下） | 明显无效的交易不占地方 |
| 池已满 | 按"优先费单价最低者先淘汰"（同价则哈希大者先淘汰）——同样必须确定性，否则两个节点对"谁被淘汰"的结论不同（虽然不影响共识，但会让重试行为不可预测） |

出块时还会再校验一遍：那是**唯一**真正作数的校验（`apply_block`/`prepare_block`）。

已知边界（如实登记）
--------------------
* **重启即丢**：交易池不落盘。节点重启后池中的交易消失，需要钱包重发
  （测试网可接受；主网若要求"重启不丢"需另做持久化，属后续加固项）；
* **不做手续费市场**：当前没有"按价拍卖、动态基础费"的完整策略，
  只有"按优先费单价排序 + 满了淘汰最低价"，够用且确定；
* **不做跨节点同步追赶**：只广播一次（加去重）。若交易在广播途中丢了，
  只有提交它的钱包重发才会再次传播（重发是幂等的，因为 `tx_hash` 去重）。
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from . import params as P
from .crypto_backend import keccak256
from .tx import CheckResult, Transaction, validate_tx

__all__ = ["TxPool", "PoolStats", "PoolReject"]

# 默认容量（可按节点配置）。**有界**是硬要求：无界的池就是一条内存耗尽路径。
DEFAULT_MAX_TXS: int = 4096
DEFAULT_MAX_BYTES: int = 8 * 1024 * 1024

# 允许"超前"多少个 nonce（相对本发送者已连续到的那一笔）。
# **必须有这个上界**：否则任何人都能拿一串天文数字的 nonce 把池子塞满（每个都合法、
# 每个都永远不会被选中）。128 对钱包场景足够（同一账户待处理的交易不会这么多）。
MAX_NONCE_GAP: int = 128

# 交易在池中的存活上限（槽）。**必须有过期**：否则"前序交易永远不到"的孤儿交易
# （例如某人拿 nonce=99 提交了一笔、前 99 笔从不出现）会永久占位，
# 把有界容量慢慢吃光 —— 这是"没有 TTL 的池"必然出现的慢性病。
TTL_SLOTS: int = 2_000


class PoolReject(Exception):
    """入池被拒（带可读原因；调用方据此回给钱包）。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class PoolStats:
    """池的可观测统计（节点报告与会话排障都用它）。"""

    def __init__(self) -> None:
        self.accepted = 0          # 成功入池
        self.rejected = 0          # 被拒
        self.dropped_full = 0      # 因容量上限被淘汰
        self.evicted_stale = 0     # 上链/失效后被清理
        self.gossiped = 0          # 转发出去的次数
        self.received = 0          # 从对端收到的次数
        self.last_reject = ""

    def __repr__(self) -> str:                          # pragma: no cover
        return (f"PoolStats(accepted={self.accepted} rejected={self.rejected} "
                f"dropped_full={self.dropped_full} evicted={self.evicted_stale})")


class TxPool:
    """有界、确定性的交易池。**不是共识状态**（见模块文档）。"""

    def __init__(self, max_txs: int = DEFAULT_MAX_TXS,
                 max_bytes: int = DEFAULT_MAX_BYTES):
        self.max_txs = max(1, int(max_txs))
        self.max_bytes = max(1024, int(max_bytes))
        self.stats = PoolStats()
        # 主存储：tx_hash → Transaction（**不依赖插入顺序**：一切顺序都由排序函数给出）
        self._txs: Dict[bytes, Transaction] = {}
        # 入池槽号（用于 TTL 过期；见 TTL_SLOTS 的说明）
        self._added_slot: Dict[bytes, int] = {}
        self._bytes = 0
        # 发送者 → 该发送者在池中的 nonce 集合（用于"连续段"判定）
        self._by_sender: Dict[bytes, set] = {}

    # ── 只读视图 ──
    def __len__(self) -> int:
        return len(self._txs)

    def __contains__(self, tx_hash: bytes) -> bool:
        return tx_hash in self._txs

    @property
    def size_bytes(self) -> int:
        return self._bytes

    def hashes(self) -> List[bytes]:
        return sorted(self._txs.keys())

    def get(self, tx_hash: bytes) -> Optional[Transaction]:
        return self._txs.get(tx_hash)

    # ── 入池 ──
    def add(self, tx: Transaction, state, base_fee: Optional[int] = None,
            current_slot: Optional[int] = None) -> Tuple[bool, str]:
        """尝试入池。返回 `(是否接受, 原因)`；**不抛异常**（便于网络路径直接调用）。

        准入校验针对**当前**状态：状态稍后会变，因此"进得来"不代表"一定能上链"。
        真正作数的校验在打包与执行时（§22 第 10 项）。
        """
        h = tx.tx_hash()
        if h in self._txs:
            # 去重：既不拒也不重复占位（广播回路靠它切断）
            return False, "duplicate"
        sender = tx.sender
        try:
            acc = state.get_account(sender)
        except Exception:                                # noqa: BLE001
            acc = None
        chain_nonce = acc.nonce if acc is not None else 0

        # ① 已在链上（重放）——§16.4.2 第 9 项本来也会拒，这里早退省地方
        if tx.nonce < chain_nonce:
            self.stats.rejected += 1
            self.stats.last_reject = f"nonce {tx.nonce} 低于链上 {chain_nonce}（重放）"
            return False, self.stats.last_reject

        # ② 前瞻上界：允许"后序交易先到"（网络乱序是常态），但**必须有上界**，
        #    否则一串天文数字的 nonce 就能把池子塞满（全都合法、全都永远不会被选中）。
        #    ⚠ 注意：**不能**在这里套用 §16.4.2 第 9 项（`nonce == 账户 nonce`）——
        #    那是**执行**时的规则；交易池是"待处理队列"，同一发送者的第 2、3 笔
        #    本来就该能先排队（首版误用了第 9 项，导致每个发送者只能存一笔，
        #    钱包连发两笔时第二笔永远进不来）。
        contig = self.contiguous_upto(sender, chain_nonce)
        if tx.nonce > contig + MAX_NONCE_GAP:
            self.stats.rejected += 1
            self.stats.last_reject = (
                f"nonce 过于超前：链上 {chain_nonce}、池内连续到 {contig}，"
                f"来的是 {tx.nonce}（上限 +{MAX_NONCE_GAP}）")
            return False, self.stats.last_reject

        # ③ 全流水线（当前状态 + 当前基础费）；第 17 项（累计 gas）在入池阶段不适用。
        #    基础费**由调用方显式给出**（节点知道下一块的基础费；早期版本靠
        #    "状态上的提示属性"，那既隐式又容易忘设，属于自找的坑）。
        #    `sender_nonce=tx.nonce`：见上面②的说明 —— 第 9 项在**打包/执行**时才真正作数，
        #    这里把它当作"排队序号"而不是"当前 nonce"。
        bf = P.INITIAL_BASE_FEE if base_fee is None else int(base_fee)
        res: CheckResult = validate_tx(tx, state, bf, 0, sender_nonce=tx.nonce,
                                       current_slot=current_slot)
        if not res.ok:
            self.stats.rejected += 1
            self.stats.last_reject = f"第 {res.failed_at} 项失败：{res.reason}"
            return False, self.stats.last_reject

        # ④ 容量：先淘汰再放入（淘汰规则必须确定性，见模块文档）
        self._evict_for(keccak256(tx.to_rlp()), len(tx.to_rlp()))
        self._txs[h] = tx
        self._added_slot[h] = int(current_slot or 0)
        self._bytes += len(tx.to_rlp())
        self._by_sender.setdefault(sender, set()).add(tx.nonce)
        self.stats.accepted += 1
        return True, "accepted"

    # ── 清理 ──
    def remove(self, tx_hashes: Sequence[bytes]) -> int:
        """移除指定交易（上链后调用）。返回实际移除数量。"""
        n = 0
        for h in tx_hashes:
            tx = self._txs.pop(h, None)
            if tx is None:
                continue
            self._added_slot.pop(h, None)
            n += 1
            self._bytes -= len(tx.to_rlp())
            s = self._by_sender.get(tx.sender)
            if s is not None:
                s.discard(tx.nonce)
                if not s:
                    self._by_sender.pop(tx.sender, None)
        return n

    def reap(self, state, base_fee: Optional[int] = None,
             current_slot: Optional[int] = None) -> int:
        """清理"已经不可能再上链"的交易：nonce 已被链上越过，或已无法通过校验。

        调用时机：每个区块最终化之后。**必须做**，否则池里会长期堆积
        已经上链或已失效的交易，既占地方又会在下次出块时反复被选中又跳过。

        ⚠ `current_slot` **必须**传（节点传的是 `estimated_slot`）：
        空投领取与提现的校验需要它；缺槽时本函数**不做**基于校验的清理 ——
        "无法判定"不等于"无效"（曾经的写法在这里漏传槽，导致合法交易被静默清掉）。
        """
        gone: List[bytes] = []
        bf = P.INITIAL_BASE_FEE if base_fee is None else int(base_fee)
        for h, tx in self._txs.items():
            acc = state.get_account(tx.sender)
            chain_nonce = acc.nonce if acc is not None else 0
            if tx.nonce < chain_nonce:
                gone.append(h)
                continue
            # 清理三类：
            #   ① 链上已越过（重放）；
            #   ② 已经在结构上不可能上链（前瞻超出上界）；
            #   ③ 其它校验失败（余额不够了、签名后来被判无效等）。
            # ① TTL：等太久的交易一律清掉（"前序永远不到"的孤儿交易必须能被回收）
            if current_slot is not None:
                added = self._added_slot.get(h, int(current_slot))
                if int(current_slot) - added > TTL_SLOTS:
                    gone.append(h)
                    continue
            if tx.nonce > self.contiguous_upto(tx.sender, chain_nonce) + MAX_NONCE_GAP:
                gone.append(h)
                continue
            if current_slot is None:
                # **拿不到当前槽就不做"基于校验"的清理（BUG-96）。**
                # 空投领取（§32.6 时间窗）与提现（§14.2 解绑期）的校验**必须**知道
                # 当前槽；缺槽时它们会以"第 16 项：缺少当前槽"失败 ——
                # 那是**无法判定**，不是**无效**。把两者混为一谈会把合法交易
                # 静默清出池子，表现为"提交后有时能上链、有时永远不上链"
                # （取决于提交与下一个区块之间是否恰好发生过一次 reap）。
                # 实测：本机集群上第二个空投领取就这么消失了。
                continue
            res = validate_tx(tx, state, bf, 0, sender_nonce=tx.nonce,
                              current_slot=int(current_slot))
            if not res.ok and res.failed_at != 17:
                gone.append(h)
        n = self.remove(gone)
        self.stats.evicted_stale += n
        return n

    # ── 出块挑选（纯函数式：只看池内容与传入状态）──
    def select(self, state, base_fee: int, current_slot: int,
               max_gas: Optional[int] = None) -> List[Transaction]:
        """按确定性规则挑选可入块的交易。

        **三条硬约束**（每条都对应一次真实故障）：
        1. **同一发送者的交易必须按 nonce 升序、且从链上 nonce 起连续**
           （§22 第 10 项：同块 nonce 严格递增）——断档之后的一律不选；
        2. **累计 gas ≤ `MAX_GAS_PER_BLOCK`**（§16.4.2 第 17 项）——
           且必须是**逐笔**累计（`gas_used` 取决于该笔是否新建账户）；
        3. **结果必须确定**：同一（池, 状态, base_fee, 槽）两次调用给出逐字节相同的列表
           （否则同一提案者会给出两个区块，把全网投票打散 —— BUG-46 的形态）。

        做法：**先按发送者排队，再按费用序合并**。
        为什么不是"把所有交易按费用排一遍、扫一趟"——那**选不出同一发送者的第 2 笔**：
        第 2 笔在第 1 笔被选中之前看到的前序 nonce 对不上，会被跳过，
        而单趟扫描不会回头再看它（首版就是这么写的：钱包连发两笔，第二笔永远不上链）。

        排序键：优先费单价降序 → `tx_hash` 升序（tie-break 保证唯一顺序）。
        """
        limit = P.MAX_GAS_PER_BLOCK if max_gas is None else max_gas

        # ── ① 每个发送者一条队列（nonce 升序，只保留从链上 nonce 起的连续前缀）──
        per_sender: Dict[bytes, List[Transaction]] = {}
        for tx in self._txs.values():
            per_sender.setdefault(tx.sender, []).append(tx)
        queues: Dict[bytes, List[Transaction]] = {}
        budgets: Dict[bytes, int] = {}
        for sender, lst in per_sender.items():
            lst.sort(key=lambda t: t.nonce)
            acc = state.get_account(sender)
            chain_nonce = acc.nonce if acc is not None else 0
            budgets[sender] = acc.balance if acc is not None else 0
            q: List[Transaction] = []
            expect = chain_nonce
            for t in lst:
                if t.nonce < expect:
                    continue                    # 已被链上越过（等 reap 清）
                if t.nonce != expect:
                    break                       # 断档：后面的先不排（选了会让整块无效）
                q.append(t)
                expect += 1
            if q:
                queues[sender] = q

        # ── ② 合并：每次取"各队列队首中费用最优"的那一笔 ──
        import heapq
        heap: List[Tuple[Tuple[int, bytes], bytes]] = []
        for sender, q in queues.items():
            heapq.heappush(heap, (self._order_key(q[0], base_fee), sender))

        chosen: List[Transaction] = []
        gas = 0
        will_create: set = set()
        cursor: Dict[bytes, int] = {s: 0 for s in queues}
        exhausted: set = set()
        while heap and gas < limit:
            _key, sender = heapq.heappop(heap)
            q = queues[sender]
            i = cursor[sender]
            tx = q[i]
            # 余额门槛（保守：按最坏情况 `gas_limit×max_fee + value` 扣，
            # 保证"选进来的交易在执行时也付得起"，避免整块被 §16.4.2 第 10 项否掉）
            upfront = tx.gas_limit * tx.max_fee_per_gas + tx.value
            if budgets.get(sender, 0) < upfront:
                exhausted.add(sender)
                continue
            creates = (bool(tx.to) and state.get_account(tx.to) is None
                       and tx.value > 0 and tx.to not in will_create)
            gu = tx.gas_used(creates)
            if gas + gu > limit:
                # 这一笔塞不下：**该发送者的后续交易也不能选**（nonce 会断档），
                # 但其它发送者继续（确定性：同一输入必然给出同一结果）
                exhausted.add(sender)
                continue
            res = validate_tx(tx, state, base_fee, gas,
                              sender_nonce=tx.nonce, current_slot=current_slot)
            if not res.ok:
                # 这一笔无效 ⇒ 该发送者后续也不能选（会断档）
                exhausted.add(sender)
                continue
            chosen.append(tx)
            gas += gu
            budgets[sender] = budgets.get(sender, 0) - upfront
            if creates:
                will_create.add(tx.to)
            cursor[sender] = i + 1
            if cursor[sender] < len(q) and sender not in exhausted:
                heapq.heappush(heap, (self._order_key(q[cursor[sender]], base_fee), sender))
        return chosen

    @staticmethod
    def _order_key(tx: Transaction, base_fee: int) -> Tuple[int, bytes]:
        """排序键：优先费单价降序（取负）→ 交易哈希升序。"""
        rate = max(0, min(tx.max_priority_fee_per_gas, tx.max_fee_per_gas - base_fee))
        return (-rate, tx.tx_hash())

    # ── 内部 ──
    def contiguous_upto(self, sender: bytes, chain_nonce: int) -> int:
        """池内从 `chain_nonce` 起连续到哪一个 nonce（不含）。

        公开它是因为**它决定了"这个发送者现在能装哪些交易"**：
        `select()` 只会在连续段内挑选（断档之后的一律跳过），
        因此"池里有没有那笔"与"能不能被打包"是两件事。
        """
        s = self._by_sender.get(sender)
        if not s:
            return chain_nonce
        n = chain_nonce
        while n in s:
            n += 1
        return n

    def _evict_for(self, _h: bytes, extra_bytes: int) -> None:
        """腾出空间（确定性淘汰：优先费单价最低者先出局；同价则哈希大者先出局）。"""
        while self._txs and (len(self._txs) + 1 > self.max_txs
                             or self._bytes + extra_bytes > self.max_bytes):
            # 淘汰**优先费单价最低**的那笔（同价时淘汰哈希最大者，保证确定性）。
            # ⚠ 首版写成了 `max(...)`：于是池满时被扔掉的偏偏是**出价最高**的交易，
            #   与"价高者优先"完全相反 —— 这类"符号反了"的错误不会报错，只会让
            #   用户的交易莫名其妙进不去。
            cheapest = min(self._fee_rate_static(t) for t in self._txs.values())
            victims = [h for h, t in self._txs.items()
                       if self._fee_rate_static(t) == cheapest]
            victim = max(victims)              # 同价：哈希大者先出局
            self.remove([victim])
            self.stats.dropped_full += 1

    def _fee_rate_static(self, tx: Transaction) -> int:
        return max(0, tx.max_priority_fee_per_gas)

    def summary(self) -> str:
        return (f"池内 {len(self._txs)} 笔 / {self._bytes}B "
                f"（收 {self.stats.accepted} 拒 {self.stats.rejected} "
                f"满淘汰 {self.stats.dropped_full} 过期清理 {self.stats.evicted_stale} "
                f"转发 {self.stats.gossiped} 收到 {self.stats.received}）")
