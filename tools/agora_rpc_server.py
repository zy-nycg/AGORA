# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — **只读查询接口**（HTTP + JSON，供移动端钱包取数）
================================================================

为什么要有它
------------
节点之间说的是 P2P 二进制协议（长度前缀帧 + RLP + §6.7.1 签名握手），
那套东西给**钱包**用是错的：钱包只需要"某地址余额多少""高度多少"这类查询，
而 P2P 协议里**根本没有**这类消息。所以这里提供一个最小、只读的 HTTP JSON 接口，
钱包用普通 HTTP 客户端取数即可（移动端最省事、最省电、也最容易被审计）。

设计纪律（每一条都对应一类真实事故）
------------------------------------
1. **默认只读、默认只听回环。** 只有 `POST /v1/tx` 会改变节点状态，
   且目前它会**明确返回 501**（节点还没有交易池，见 §"已知缺口"）。
   `--bind` 默认 `127.0.0.1`；要对外提供服务必须显式指定并自行承担风险。
2. **金额一律是十进制字符串，绝不是 JSON number。**
   1 AGORA = 10^18 atom，初始供应 ≈ 2.05×10^25 atom。
   JS/Dart 的 JSON number 是 IEEE-754 双精度（安全整数上限 2^53 ≈ 9×10^15），
   直接把 atom 当 number 解析会**静默丢精度** —— 钱包显示"余额正确"却转错钱。
   因此：凡是金额/权益/供应量，字段名以 `_atom` 结尾且类型为 **string**；
   高度、槽号、nonce、gas_used 这类小整数才是 number。
3. **哈希与地址是定长十六进制串**（`0x` + 小写；哈希 32 字节、地址 20 字节）。
4. **每个响应都带 `chain_id`、`genesis_hash`、`height`**，钱包必须核对
   （`genesis_hash` 不同 ⇒ 连错了链；`height` 落后 ⇒ 数据是旧的）。
   注意：这是**字符串比对**，不是密码学证明 —— 想"不信任服务器"需要客户端自行
   复算承诺（本轮**未**要求，故如实标注为信任假设）。
5. **错误有明确结构和状态码**：400 参数错、404 查不到、501 未实现、503 数据不可用。
   响应体统一为 `{"error": {"code": ..., "message": ..., "detail": ...}}`。
6. **快照一致性**：所有查询都在同一把锁下读取节点状态，
   避免读到"半个区块"的状态（节点在它自己的线程里改状态）。

端点一览
--------
    GET  /healthz                     存活探测（不含状态）
    GET  /v1/params                   协议参数（钱包不该硬编码这些）
    GET  /v1/status                   链状态：高度/链头/状态根/当前槽/空投窗口
    GET  /v1/account/{address}        账户：余额、nonce、验证者信息
    GET  /v1/block/{height|hash}      区块头 + 交易 + 回执（`latest` 亦可）
    GET  /v1/tx/{tx_hash}             交易及其所在区块与回执
    GET  /v1/airdrop/{address}        空投资格 + **Merkle 证明** + 领取状态
    GET  /v1/validator/{address}      单个验证者
    GET  /v1/validators               验证者列表
    POST /v1/tx                       提交已签名交易（**当前返回 501**，见下）

交易提交的语义（§16.5，**钱包必须知道**）
-----------------------------------------
* `POST /v1/tx` 接收**已签名**交易的 RLP（`{"tx_rlp": "0x…"}`）：
  解码 → 入池 → 广播给对端 → **返回 202 + `tx_hash`**；
* **202 只表示"本节点已受理并转发"，不表示一定上链。** 权威结论只能来自
  `GET /v1/tx/{tx_hash}`（`found=true` + 所在区块 + 回执）。钱包界面应当
  在查到区块之前显示"已提交，等待上链"，而不是"转账成功"；
* **重复提交是安全的**（返回 `status=duplicate`，HTTP 200）：钱包重试不需要去重逻辑；
* 交易本身不合法时返回 **400**，`detail` 里带 §16.4.2 的**项号**
  （例如"第 9 项失败：nonce 不匹配"），钱包可直接展示给用户；
* 交易池**有界且不落盘**：节点重启后池内交易消失，需要钱包重发
  （已在 §16.5 登记为已知边界）。

已知边界（**如实告知钱包开发者**）
----------------------------------
* 交易池是**本地**的、非共识的：验证者 **MUST NOT** 因为"本节点池里没有这笔交易"
  而拒绝区块（规范 §16.4.3）。因此**没有**"交易池同步"这类机制，
  广播只做一次尽力而为（丢包靠钱包重发）。
* 第二实现（Node.js）目前没有这套 HTTP 接口，也没有交易池：
  接口与交易池都只有单实现（GATE-7 的已知缺口）。
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote, urlparse

from agora import params as P
from agora.crypto_backend import address_from_pubkey
from agora.state import (airdrop_merkle_proof, airdrop_merkle_root,
                         airdrop_gas_allowance_total)

__all__ = ["AgoraRpcServer", "serve_in_thread", "NodeProvider"]

API_VERSION = "v1"


# ══════════════════════════════════════════════════════════════════════
# 编码助手（钱包契约的唯一实现）
# ══════════════════════════════════════════════════════════════════════

def hx(b: bytes) -> str:
    """字节 → `0x` + 小写十六进制。"""
    return "0x" + bytes(b).hex()


def atom(v: int) -> str:
    """金额 → **十进制字符串**（绝不用 JSON number，见模块文档第 2 条）。"""
    return str(int(v))


def _addr_bytes(text: str) -> bytes:
    raw = text.strip().lower().removeprefix("0x")
    if len(raw) != 40:
        raise ValueError(f"地址必须为 20 字节（40 位十六进制），实际 {len(raw)} 位")
    return bytes.fromhex(raw)


class RpcError(Exception):
    def __init__(self, status: int, code: str, message: str, detail: str = ""):
        super().__init__(message)
        self.status, self.code, self.message, self.detail = status, code, message, detail


# ══════════════════════════════════════════════════════════════════════
# 数据源
# ══════════════════════════════════════════════════════════════════════

class NodeProvider:
    """把**运行中的节点**包装成查询数据源。

    `lock` 由运行器与节点主循环共用：所有会改状态的调用都在锁内进行，
    因此这里的读操作看到的是"某个区块边界上的完整状态"，而不是半个区块。
    """

    def __init__(self, node, genesis_hash: bytes, genesis_cfg: Optional[dict] = None,
                 airdrop_table: Optional[dict] = None,
                 lock: Optional[threading.RLock] = None,
                 genesis_block=None):
        self.node = node
        self.genesis_hash = genesis_hash
        # `node.blockchain` **不含创世块**（节点把创世放在 `head` 的起点），
        # 但钱包要能按高度 0 取到创世块（对账用），因此这里显式保存一份。
        self.genesis_block = genesis_block
        self.genesis_cfg = genesis_cfg or {}
        self.lock = lock or threading.RLock()
        self.airdrop_table = airdrop_table
        self._airdrop_by_addr: Dict[bytes, int] = {}
        self._airdrop_root_ok: Optional[bool] = None
        self._airdrop_note = ""
        if airdrop_table:
            self._prepare_airdrop(airdrop_table)

    # ── 空投分配表（链上只存根，证明必须来自分配表）──
    def _prepare_airdrop(self, table: dict) -> None:
        entries = table.get("entries", [])
        self._airdrop_entries = entries
        for i, e in enumerate(entries):
            pk = bytes.fromhex(str(e["pubkey_hex"]).removeprefix("0x"))
            self._airdrop_by_addr[address_from_pubkey(pk)] = i
        declared = str(table.get("airdrop_root", "")).removeprefix("0x").lower()
        try:
            from agora.state import AirdropEntry
            ents = [AirdropEntry(pubkey=bytes.fromhex(str(e["pubkey_hex"]).removeprefix("0x")),
                                 amount=int(e.get("amount_atom", e.get("amount"))),
                                 gas_allowance=int(e.get("gas_allowance_atom",
                                                        e.get("gas_allowance", 0)) or 0),
                                 index=int(e.get("index", 0) or 0))
                    for e in entries]
            computed = airdrop_merkle_root(ents).hex()
        except Exception as exc:                       # noqa: BLE001
            self._airdrop_root_ok, self._airdrop_note = False, f"分配表解析失败：{exc}"
            return
        onchain = getattr(self.node.state.system, "airdrop_root", b"")
        self._airdrop_root_ok = (computed == declared
                                 and (not onchain or onchain.hex() == declared))
        if not self._airdrop_root_ok:
            # **绝不给钱包一份通不过链上校验的证明**：宁可明确拒绝服务。
            self._airdrop_note = (
                f"分配表的根（{computed[:16]}…）与链上 airdrop_root"
                f"（{(onchain.hex()[:16] + '…') if onchain else '（无）'}）不一致 —— "
                "拒绝提供证明（否则钱包构造的领取交易必然被 §16.4.2 第 16 项拒绝）")

    # ── 只读视图 ──
    @property
    def height(self) -> int:
        return self.node.height

    @property
    def head(self):
        return self.node.head

    @property
    def state(self):
        return self.node.state

    def block_by_height(self, height: int):
        for b in self.node.blockchain:
            if b.header.height == height:
                return b
        return None

    def blocks(self) -> Sequence:
        return list(self.node.blockchain)

    def all_blocks(self) -> List:
        """含创世块（`node.blockchain` 不含创世）。"""
        out = list(self.node.blockchain)
        g = self.genesis_block
        if g is not None and (not out or out[0].header.height > 0):
            out = [g] + out
        return out

    def height_of_max(self) -> int:
        chain = self.all_blocks()
        return chain[-1].header.height if chain else -1


# ══════════════════════════════════════════════════════════════════════
# 业务处理
# ══════════════════════════════════════════════════════════════════════

class AgoraRpcServer:
    """把 Provider 暴露成 HTTP JSON 接口。"""

    def __init__(self, provider: NodeProvider):
        self.p = provider

    # ── 通用信封 ──
    def _envelope(self, extra: Dict[str, Any]) -> Dict[str, Any]:
        with self.p.lock:
            h = self.p.height
            head = self.p.head
            return {
                "chain_id": P.CHAIN_ID,
                "protocol_version": P.PROTOCOL_VERSION,
                "genesis_hash": hx(self.p.genesis_hash),
                "height": h,                                  # 小整数 ⇒ number
                "head_hash": hx(head.block_hash()) if head is not None else None,
                "state_root": hx(self.p.state.state_root),
                **extra,
            }

    def get_params(self) -> Dict[str, Any]:
        """协议参数。**同样带信封**（`genesis_hash`/`height`/`state_root`）。

        踩过的坑：`/v1/params` 起初只回参数、不回 `genesis_hash`，
        于是"钱包先取参数、再核对链身份"这条最自然的调用顺序直接失败 ——
        而且报出来的是"链身份不符（期望 …，实际 空）"，看起来像连错了链。
        **凡是能被客户端逐条核对的端点，都必须带齐信封。**（`/healthz` 例外：
        它本来就不该返回链信息。）
        """
        return self._envelope({
            "chain_id": P.CHAIN_ID,
            "protocol_version": P.PROTOCOL_VERSION,
            "atom_per_agora": str(P.ATOM_PER_AGORA),
            "slot_time_seconds": P.SLOT_TIME,
            "epoch_length_slots": P.EPOCH_LENGTH,
            "genesis_timestamp": P.GENESIS_TIMESTAMP,
            "airdrop_window": {"start_slot": P.AIRDROP_START_SLOT,
                               "end_slot": P.AIRDROP_END_SLOT},
            "unbonding_period_slots": P.UNBONDING_PERIOD_SLOTS,
            "min_gas_price": str(P.MIN_BASE_FEE),
            "initial_base_fee_per_gas": str(P.INITIAL_BASE_FEE),
            "max_gas_per_block": str(P.MAX_GAS_PER_BLOCK),
            "tx_type_codes": {"TRANSFER": 1, "BOND": 2, "UNBOND": 3, "REBOND": 4,
                              "WITHDRAW": 5, "EVIDENCE": 6, "AIRDROP_CLAIM": 7},
            "note": "金额字段一律是十进制字符串（atom）；不要用 JSON number 解析",
        })

    def get_status(self) -> Dict[str, Any]:
        with self.p.lock:
            head = self.p.head
            est_slot = getattr(self.p.node, "estimated_slot", 0)
            claimed = len(self.p.state.system.airdrop_claimed)
            return self._envelope({
                "chain_length": len(self.p.node.blockchain),
                "estimated_current_slot": est_slot,
                "head_claimed_slot": head.header.claimed_slot if head is not None else None,
                "head_timestamp": head.header.timestamp if head is not None else None,
                "base_fee_per_gas": str(head.header.base_fee_per_gas) if head is not None else None,
                "supply_atom": atom(P.INITIAL_SUPPLY),
                "airdrop_pending_atom": atom(self.p.state.system.airdrop_pending),
                "airdrop_claimed_count": claimed,
                "airdrop_root": hx(self.p.state.system.airdrop_root),
                "airdrop_proofs_available": bool(self.p._airdrop_root_ok),
                "airdrop_proofs_note": self.p._airdrop_note,
                "trust_model": ("数据由本节点提供，未做客户端密码学校验；"
                                "钱包应核对 genesis_hash 与 chain_id"),
            })

    def get_account(self, address_text: str) -> Dict[str, Any]:
        addr = _addr_bytes(address_text)
        with self.p.lock:
            acc = self.p.state.get_account(addr)
            rec = self.p.state.get_validator(addr)
            data: Dict[str, Any] = {
                "address": hx(addr),
                "exists": acc is not None,
                "balance_atom": atom(acc.balance if acc else 0),
                "nonce": acc.nonce if acc else 0,
                "next_nonce": acc.nonce if acc else 0,
                "is_validator": rec is not None,
                "validator": self._validator_json(addr, rec) if rec else None,
            }
            return self._envelope(data)

    def _validator_json(self, addr: bytes, rec) -> Dict[str, Any]:
        return {
            "address": hx(addr),
            "pubkey": hx(rec.pubkey) if rec.pubkey else None,
            "effective_stake_atom": atom(rec.effective_stake),
            "pending_stake_atom": atom(rec.pending_stake),
            "unbonding_balance_atom": atom(rec.unbonding_balance),
            "pending_unbond_atom": atom(rec.pending_unbond),
            "status": int(rec.status),
            "unbond_request_slot": int(rec.unbond_request_slot),
            "unbond_complete_slot": int(rec.unbond_complete_slot),
            "last_slashable_slot": int(rec.last_slashable_slot),
            "inactivity_streak": int(rec.inactivity_streak),
            "slashed_total_atom": atom(rec.slashed_total),
            "is_founder": bool(rec.is_founder),
        }

    def get_validators(self) -> Dict[str, Any]:
        with self.p.lock:
            snap = self.p.state.system.snapshot
            out = []
            for a in sorted(snap.membership):
                rec = self.p.state.get_validator(a)
                if rec is None:
                    continue
                j = self._validator_json(a, rec)
                # 快照的 voting_power 是 `[(地址, 投票权)]`（按地址升序，§19.5），
                # 不是 dict —— 用 `snap.vp_of()` 取，别猜字段类型。
                j["voting_power_atom"] = atom(snap.vp_of(a))
                out.append(j)
            # QUORUM = ceil(2 * S / 3)，S 取**本纪元快照**的有效质押之和（§7.1/§9.2）
            s_total = snap.staked_supply
            return self._envelope({"validators": out,
                                   "staked_supply_atom": atom(s_total),
                                   "quorum_atom": atom(-(-2 * s_total // 3))})

    # ── 区块与交易 ──
    def _receipts_for(self, blk) -> List[Dict[str, Any]]:
        """本块回执：**优先用执行侧记录的精确值**，拿不到才退化并明确标注。

        为什么不能靠重算：`gas_used` 取决于"这笔交易是否**新建账户**"（+25,000 gas），
        而那要看**执行该区块时的父状态**。节点记录的是执行时刻的真实回执
        （`Node.receipts`），所以：

        * 索引里有 ⇒ `receipt_exact: true`（与 `receipt_root` 一致）；
        * 索引里没有（例如节点刚重启、该块比索引容量更旧）⇒ 用当前状态**近似重算**，
          并把 `receipt_exact` 置 false、附原因 —— **绝不**把近似值伪装成精确值
          （钱包会据此显示错误的手续费）。
        """
        node = getattr(self.p, "node", None)
        out = []
        for tx in blk.transactions:
            h = tx.tx_hash()
            rec = node.receipt_for(h) if node is not None else None
            if rec is not None:
                out.append({
                    "tx_hash": hx(h), "status": int(rec["status"]),
                    "gas_used": int(rec["gas_used"]),
                    "effective_gas_price": rec["effective_gas_price"],
                    "creates_account": bool(rec.get("creates_account", False)),
                    "receipt_exact": True,
                })
                continue
            creates = bool(tx.to) and tx.value > 0 and \
                self.p.state.get_account(tx.to) is None
            q = tx.fee_quote(blk.header.base_fee_per_gas, creates_account=creates)
            out.append({
                "tx_hash": hx(h), "status": 1,
                "gas_used": int(q.gas_used),
                "effective_gas_price": str(q.effective_gas_price),
                "creates_account": bool(creates),
                "receipt_exact": False,
                "receipt_note": ("本节点没有该区块执行时的回执记录（可能是重启后的旧块）"
                                 "⇒ 此处为按当前状态的**近似值**；"
                                 "权威值是区块头里的 receipt_root"),
            })
        return out

    def _block_json(self, blk, with_txs: bool = True) -> Dict[str, Any]:
        h = blk.header
        p = h.parent_commit
        data: Dict[str, Any] = {
            "height": int(h.height),
            "round": int(h.round),
            "claimed_slot": int(h.claimed_slot),
            "timestamp": int(h.timestamp),
            "block_hash": hx(blk.block_hash()),
            "parent_hash": hx(h.parent_hash),
            "state_root": hx(h.state_root),
            "tx_root": hx(h.tx_root),
            "receipt_root": hx(h.receipt_root),
            "gas_used": int(h.gas_used),
            "base_fee_per_gas": str(h.base_fee_per_gas),
            "proposer": hx(h.proposer) if getattr(h, "proposer", None) else None,
            "parent_commit": {
                "height": int(p.height),
                "round": int(p.round),
                "block_hash": hx(p.block_hash),
                "signature_count": len(p.signatures),
            },
            "tx_count": len(blk.transactions),
        }
        if with_txs:
            data["transactions"] = [{
                "tx_hash": hx(tx.tx_hash()),
                "tx_type": int(tx.tx_type),
                "from": hx(tx.sender),
                "to": hx(tx.to) if tx.to else None,
                "value_atom": atom(tx.value),
                "nonce": int(tx.nonce),
                "gas_limit": int(tx.gas_limit),
                "max_fee_per_gas": str(tx.max_fee_per_gas),
                "envelope_rlp": hx(tx.to_rlp()),
            } for tx in blk.transactions]
            data["receipts"] = self._receipts_for(blk)
        return data

    def get_block(self, key: str) -> Dict[str, Any]:
        with self.p.lock:
            chain = self.p.all_blocks()
            if not chain:
                raise RpcError(503, "no_chain", "该节点还没有任何区块")
            if key in ("latest", "head"):
                blk = chain[-1]
            elif key.isdigit():
                n = int(key)
                blk = next((b for b in chain if b.header.height == n), None)
                if blk is None:
                    # 报"最高高度"而不是 `len(chain)-1`：后者在含创世时是对的、
                    # 在链为空或创世缺失时会给出误导性的数字。
                    raise RpcError(404, "block_not_found",
                                   f"没有高度 {n} 的区块"
                                   f"（本节点最高高度 {chain[-1].header.height}）")
            else:
                want = key.strip().lower().removeprefix("0x")
                if len(want) != 64:
                    raise RpcError(400, "bad_block_hash",
                                   "区块标识必须是高度数字或 32 字节十六进制哈希")
                blk = next((b for b in chain if b.block_hash().hex() == want), None)
                if blk is None:
                    raise RpcError(404, "block_not_found", f"找不到区块 {key}")
            return self._envelope({"block": self._block_json(blk)})

    def get_tx(self, tx_hash_text: str) -> Dict[str, Any]:
        want = tx_hash_text.strip().lower().removeprefix("0x")
        if len(want) != 64:
            raise RpcError(400, "bad_tx_hash", "交易哈希必须是 32 字节十六进制")
        with self.p.lock:
            for blk in self.p.all_blocks():
                for idx, tx in enumerate(blk.transactions):
                    if tx.tx_hash().hex() == want:
                        recs = self._receipts_for(blk)
                        return self._envelope({
                            "found": True,
                            # 顶层 `tx_hash` **必须**始终存在（无论找到与否）：
                            # 它既是查询键也是客户端对账依据。**踩过的坑**：
                            # found=true 的分支曾漏掉它，Dart 客户端解析直接抛异常 ——
                            # 而单元测试当时只断言了 found/receipt，没断言这个字段。
                            "tx_hash": hx(tx.tx_hash()),
                            "block_height": int(blk.header.height),
                            "block_hash": hx(blk.block_hash()),
                            "index_in_block": idx,
                            "confirmations": max(0, self.p.height - int(blk.header.height)),
                            "transaction": {
                                "tx_hash": hx(tx.tx_hash()),
                                "tx_type": int(tx.tx_type),
                                "from": hx(tx.sender),
                                "to": hx(tx.to) if tx.to else None,
                                "value_atom": atom(tx.value),
                                "nonce": int(tx.nonce),
                                "envelope_rlp": hx(tx.to_rlp()),
                            },
                            "receipt": recs[idx] if idx < len(recs) else None,
                        })
            return self._envelope({"found": False, "tx_hash": hx(bytes.fromhex(want))})

    # ── 空投 ──
    def get_airdrop(self, address_text: str) -> Dict[str, Any]:
        addr = _addr_bytes(address_text)
        with self.p.lock:
            onchain_root = self.p.state.system.airdrop_root
            claimed = [(a, i) for a, i in self.p.state.system.airdrop_claimed]
            window_open = (P.AIRDROP_START_SLOT
                           <= getattr(self.p.node, "estimated_slot", 0)
                           <= P.AIRDROP_END_SLOT)
            base = {
                "address": hx(addr),
                "airdrop_root": hx(onchain_root),
                "claim_window": {"start_slot": P.AIRDROP_START_SLOT,
                                 "end_slot": P.AIRDROP_END_SLOT,
                                 "open": bool(window_open)},
                "vault_balance_atom": atom(
                    (self.p.state.get_account(P.AIRDROP_VAULT_ADDRESS).balance
                     if self.p.state.get_account(P.AIRDROP_VAULT_ADDRESS) else 0)),
            }
            if not self.p.airdrop_table:
                return self._envelope({**base, "eligible": False,
                                       "reason": "本节点未加载空投分配表，无法提供证明",
                                       "proof_available": False})
            if not self.p._airdrop_root_ok:
                return self._envelope({**base, "eligible": False,
                                       "reason": self.p._airdrop_note,
                                       "proof_available": False})
            pos = self.p._airdrop_by_addr.get(addr)
            if pos is None:
                return self._envelope({**base, "eligible": False,
                                       "reason": "该地址不在空投分配表中",
                                       "proof_available": True})
            e = self.p._airdrop_entries[pos]
            idx = int(e.get("index", 0) or 0)
            proof, _sorted_idx = airdrop_merkle_proof(self._airdrop_entries_as_entries(), pos)
            already = (addr, idx) in claimed
            return self._envelope({
                **base,
                "eligible": bool(not already),
                "proof_available": True,
                "index": idx,
                "amount_atom": atom(int(e.get("amount_atom", e.get("amount")))),
                "gas_allowance_atom": atom(int(e.get("gas_allowance_atom",
                                                    e.get("gas_allowance", 0)) or 0)),
                "claimed": already,
                "claimed_entries_for_address": [i for a, i in claimed if a == addr],
                "merkle_proof": [hx(x) for x in proof],
                "note_field": e.get("note", ""),
            })

    def _airdrop_entries_as_entries(self) -> list:
        from agora.state import AirdropEntry
        return [AirdropEntry(pubkey=bytes.fromhex(str(e["pubkey_hex"]).removeprefix("0x")),
                             amount=int(e.get("amount_atom", e.get("amount"))),
                             gas_allowance=int(e.get("gas_allowance_atom",
                                                    e.get("gas_allowance", 0)) or 0),
                             index=int(e.get("index", 0) or 0))
                for e in self.p.airdrop_table.get("entries", [])]

    # ── 提交交易（§16.5）──
    def post_tx(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """接收一笔**已签名**交易：解码 → 入池 → 广播 → 返回交易哈希。

        语义要点（钱包必须知道）：
        * **202 语义**：返回成功只表示"本节点已受理并转发"，**不表示一定上链**。
          钱包应当用 `GET /v1/tx/{hash}` 查询最终结果（这才是权威）；
        * **幂等**：同一笔交易重复提交返回 `status=duplicate`（HTTP 200），
          钱包重试是安全的；
        * **被拒**（HTTP 400）：交易本身不合法，`detail` 里给出**§16.4.2 的项号**，
          钱包可以直接展示"第 9 项：nonce 不匹配"这类可读原因。
        """
        raw = body.get("tx_rlp") or body.get("raw")
        if not raw:
            raise RpcError(400, "missing_tx_rlp",
                           "请求体需要 {\"tx_rlp\": \"0x...\"}（已签名交易的 RLP）")
        node = getattr(self.p, "node", None)
        if node is None or not hasattr(node, "submit_tx"):
            raise RpcError(501, "no_mempool", "本节点没有交易池（只读模式）")
        hexs = str(raw).strip()
        if hexs.startswith(("0x", "0X")):
            hexs = hexs[2:]
        if len(hexs) % 2 or not hexs or any(c not in "0123456789abcdefABCDEF" for c in hexs):
            raise RpcError(400, "bad_tx_rlp", "tx_rlp 必须是偶数长度的十六进制字符串")
        if len(hexs) > 2 * MAX_BODY:
            raise RpcError(400, "tx_too_large", f"交易超过 {MAX_BODY} 字节上限")
        from agora.codec import RLPDecodeError
        from agora.tx import Transaction
        try:
            tx = Transaction.from_rlp(bytes.fromhex(hexs))
        except (RLPDecodeError, ValueError, TypeError) as e:
            raise RpcError(400, "bad_tx_rlp", f"交易 RLP 解码失败：{e}")
        # 入池与广播**在锁内**：池与状态都由节点线程改动
        with self.p.lock:
            ok, why = node.submit_tx(tx)
            pool_size = len(node.pool)
        h = tx.tx_hash()
        env = {"chain_id": P.CHAIN_ID, "height": self.p.height}
        if ok:
            return {"accepted": True, "status": "queued", "tx_hash": hx(h),
                    "pool_size": pool_size, **env,
                    "note": "已受理并转发；是否上链请查 GET /v1/tx/{hash}"}
        if why == "duplicate":
            return {"accepted": False, "status": "duplicate", "tx_hash": hx(h),
                    "pool_size": pool_size, **env,
                    "note": "该交易已在池中（重复提交是安全的）"}
        raise RpcError(400, "tx_rejected", f"交易未通过校验：{why}",
                       "原因里的「第 N 项」对应规范 §16.4.2 的 19 项校验表")


# ══════════════════════════════════════════════════════════════════════
# HTTP 层
# ══════════════════════════════════════════════════════════════════════

MAX_BODY = 512 * 1024


def _envelope_hint(app) -> Dict[str, Any]:
    """提交响应也带上链身份，便于钱包核对"我提交给了哪条链"。"""
    try:
        return {"chain_id": P.CHAIN_ID, "height": app.p.height}
    except Exception:                                    # noqa: BLE001
        return {}


class _Handler(BaseHTTPRequestHandler):
    server_version = "agora-rpc/0.1"
    app: AgoraRpcServer = None                        # type: ignore[assignment]

    def log_message(self, fmt, *args):                # noqa: A003
        pass                                          # 静默：由调用方决定是否记日志

    # ── 工具 ──
    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Agora-Api", API_VERSION)
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, e: RpcError) -> None:
        self._send(e.status, {"error": {"code": e.code, "message": e.message,
                                        "detail": e.detail}})

    # ── 路由 ──
    def do_GET(self) -> None:                         # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        parts = [unquote(x) for x in path.split("/") if x]
        try:
            if path == "/healthz":
                return self._send(200, {"ok": True})
            if path == "/":
                return self._send(200, {"api": API_VERSION,
                                        "endpoints": [
                                            "/healthz", "/v1/params", "/v1/status",
                                            "/v1/account/{address}",
                                            "/v1/block/{height|hash|latest}",
                                            "/v1/tx/{tx_hash}",
                                            "/v1/airdrop/{address}",
                                            "/v1/validators", "POST /v1/tx"]})
            if parts[:1] != ["v1"]:
                raise RpcError(404, "not_found", f"未知路径 {path}")
            if len(parts) == 2 and parts[1] == "params":
                return self._send(200, self.app.get_params())
            if len(parts) == 2 and parts[1] == "status":
                return self._send(200, self.app.get_status())
            if len(parts) == 2 and parts[1] == "validators":
                return self._send(200, self.app.get_validators())
            if len(parts) == 3 and parts[1] == "account":
                return self._send(200, self.app.get_account(parts[2]))
            if len(parts) == 3 and parts[1] == "block":
                return self._send(200, self.app.get_block(parts[2]))
            if len(parts) == 3 and parts[1] == "tx":
                return self._send(200, self.app.get_tx(parts[2]))
            if len(parts) == 3 and parts[1] == "airdrop":
                return self._send(200, self.app.get_airdrop(parts[2]))
            if len(parts) == 3 and parts[1] == "validator":
                addr = _addr_bytes(parts[2])
                with self.app.p.lock:
                    rec = self.app.p.state.get_validator(addr)
                if rec is None:
                    raise RpcError(404, "not_validator", "该地址不是验证者")
                return self._send(200, self.app._envelope(
                    {"validator": self.app._validator_json(addr, rec)}))
            raise RpcError(404, "not_found", f"未知路径 {path}")
        except RpcError as e:
            self._fail(e)
        except ValueError as e:
            self._fail(RpcError(400, "bad_request", str(e)))
        except Exception as e:                        # noqa: BLE001
            # 内部错误也不泄栈：只回一句可读的错误码/信息
            self._fail(RpcError(500, "internal_error", type(e).__name__, str(e)[:200]))

    def do_POST(self) -> None:                        # noqa: N802
        path = urlparse(self.path).path.rstrip("/")
        try:
            if path != "/v1/tx":
                raise RpcError(404, "not_found", f"未知路径 {path}")
            ln = int(self.headers.get("Content-Length") or 0)
            if ln <= 0 or ln > MAX_BODY:
                raise RpcError(400, "bad_body", f"请求体长度必须为 1..{MAX_BODY} 字节")
            try:
                body = json.loads(self.rfile.read(ln).decode("utf-8"))
            except Exception as e:                    # noqa: BLE001
                raise RpcError(400, "bad_json", f"请求体不是合法 JSON：{e}")
            # 受理成功 → 202（语义是"已受理"，**不是**"已上链"）。
            # 钱包必须随后用 `GET /v1/tx/{hash}` 查询最终结果 —— 链上确认才是权威。
            # 扁平返回：与其他端点一致（`{"accepted":…, "tx_hash":…}`）。
            # 前期版本把它包在 `{"tx": …}` 里，客户端就得多剥一层 ——
            # Dart 侧第一版就是这么错的（读不到 accepted，于是把成功当成了失败）。
            return self._send(202, self.app.post_tx(body))
        except RpcError as e:
            self._fail(e)
        except ValueError as e:
            self._fail(RpcError(400, "bad_request", str(e)))
        except Exception as e:                        # noqa: BLE001
            self._fail(RpcError(500, "internal_error", type(e).__name__, str(e)[:200]))


class _Server(ThreadingHTTPServer):
    daemon_threads = True


def serve_in_thread(provider: NodeProvider, host: str = "127.0.0.1",
                    port: int = 8645, quiet: bool = False) -> Tuple[_Server, threading.Thread]:
    """启动 HTTP 服务（后台线程）。返回 `(server, thread)`；调用方负责 `shutdown()`。"""
    app = AgoraRpcServer(provider)
    handler = type("_BoundHandler", (_Handler,), {"app": app})
    srv = _Server((host, port), handler)
    th = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.2},
                          daemon=True, name="agora-rpc")
    th.start()
    if not quiet:
        print(f"── 查询接口已启动 ──")
        print(f"  监听 : http://{host}:{port}")
        print(f"  只读：GET /v1/{{params,status,account/*,block/*,tx/*,airdrop/*,validators}}")
        print(f"  提交：POST /v1/tx —— 受理后返回 202 + tx_hash；"
              f"**是否上链请查 GET /v1/tx/{{hash}}**")
        if host not in ("127.0.0.1", "localhost", "::1"):
            print("  ⚠ 已对外绑定：接口**没有鉴权**，请自行用防火墙/隧道限制来源；"
                  "不要直接暴露到公网")
    return srv, th
