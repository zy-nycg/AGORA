# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 链上持久化（区块存储 + 状态快照）
=================================================

用途
----
让节点**重启后继续跑**，而不是从创世重来。这是长时间测试网（`TESTNET_RUNBOOK.md`
阶段 D）与主网运营的硬前置：没有它，"24 小时稳定性"根本无从谈起。

设计（三条硬规则，每条都有理由）
--------------------------------
1. **只持久化"输入"，不持久化派生结构。**
   账户 MPT 的内部节点是**派生**的（叶子由 `(nonce, balance, key…)` 决定、
   形态由规范化规则决定），把树直接落盘等于把"某次实现的中间形态"当成真相 ——
   版本一升级就会读出两套语义。本模块存的是：
     `accounts` 的原始条目、`validators` 的 RLP、`SystemState` 的 RLP、以及
     这些输入所承诺的 `state_root`。加载时**重新构建**状态并**复算根**。

2. **加载时必须与链上承诺对账，不一致就拒绝启动。**
   快照里记录的 `state_root` **必须**等于该高度区块头里的 `state_root`
   （区块头是被全网签名的，是唯一权威）。任何不一致 ⇒ 抛 `StoreCorruption`
   ⇒ 节点**拒绝启动**并打印原因。宁可不启动，也不能带着错状态跑 ——
   那会产生一个只有自己认的链。

3. **崩溃安全：追加写 + 校验和 + 尾巴截断。**
   区块文件是"长度前缀 + 载荷 + Keccak 校验和"的追加流。写入中途掉电会留下
   半条记录：加载时校验和不符或长度不足的记录**在末尾**时被**安全丢弃**
   （并记录一条警告）；出现在**中间**时则判定为文件损坏、拒绝启动。
   快照文件用"写临时文件 + 原子 rename"落盘，因此要么是旧版本、要么是新版本。

数据结构
--------
```
blocks.bin    : [u32 长度][区块 RLP][keccak256(区块 RLP) 32B]  重复
state.bin     : [u32 长度][快照 RLP][keccak256(快照 RLP) 32B]
快照 RLP      = RLP([ version, chain_id, protocol_version,
                      height, head_block_hash, state_root,
                      accounts:[[address(20), nonce, balance,
                                 validator_key(32), system_key(32)], …],
                      validators:[[address(20), record_rlp:bytes], …],
                      system_state_rlp:bytes ])
```

用法
----
    from agora.store import ChainStore
    st = ChainStore("runs/node1")
    state, blocks = st.load(genesis_state, genesis_block)      # 或从头开始
    st.append_block(blk)                                       # 每最终化一块
    st.save_state(state, height, head_hash)                    # 每 N 块 / 停机时
"""

from __future__ import annotations

import os
import struct
from typing import List, Optional, Sequence, Tuple

from . import params as P
from .codec import decode, encode
from .crypto_backend import keccak256
from .state import (Account, State, SystemState, ValidatorRecord)

__all__ = ["StoreCorruption", "BlockStore", "ChainStore", "encode_snapshot",
           "decode_snapshot", "SNAPSHOT_VERSION"]

SNAPSHOT_VERSION = 2
_MAX_RECORD = 64 * 1024 * 1024          # 单条记录上限（防损坏文件导致的巨大分配）


class StoreCorruption(Exception):
    """持久化数据不可信 —— 调用方**必须**拒绝启动，而不是猜。"""


# ══════════════════════════════════════════════════════════════════════
# 1. 追加式区块存储
# ══════════════════════════════════════════════════════════════════════

class BlockStore:
    """`blocks.bin`：按高度追加的最终化区块。

    **只追加、不修改**：链的最终化历史是不可变的（§6.4），因此用追加流即可，
    不需要 B 树或数据库。索引在内存里建立（高度 → 文件偏移），
    加载时**逐个校验校验和与父哈希链**。
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._offsets: List[int] = []        # 第 i 项的记录起始偏移
        self._blocks: List = []
        self._dirty = False

    # ── 读 ──────────────────────────────────────────────────────────
    def load(self) -> List:
        """读取全部区块；末尾的**半条**记录被安全丢弃，中间损坏则报错。"""
        from .block import Block

        self._offsets, self._blocks = [], []
        if not os.path.exists(self.path):
            return []
        size = os.path.getsize(self.path)
        with open(self.path, "rb") as f:
            while f.tell() < size:
                off = f.tell()
                head = f.read(4)
                if len(head) < 4:
                    self._truncate_to(off, "记录头不完整")
                    break
                (n,) = struct.unpack(">I", head)
                if n == 0 or n > _MAX_RECORD:
                    raise StoreCorruption(
                        f"{self.path}: 偏移 {off} 处的记录长度 {n} 非法（文件已损坏）")
                payload = f.read(n)
                if len(payload) < n:
                    self._truncate_to(off, "记录体不完整")
                    break
                csum = f.read(32)
                if len(csum) < 32:
                    self._truncate_to(off, "校验和不完整")
                    break
                if keccak256(payload) != csum:
                    raise StoreCorruption(
                        f"{self.path}: 偏移 {off} 处的区块记录校验和不符")
                self._offsets.append(off)
                self._blocks.append(Block.from_rlp(payload))

        self._verify_chain()
        return list(self._blocks)

    def _truncate_to(self, off: int, why: str) -> None:
        """丢弃末尾的残缺记录（崩溃中止的写入），并打印警告。

        只允许对**文件末尾**这样做：中间的残缺说明数据真的坏了，那不叫崩溃恢复。
        """
        print(f"⚠ {self.path}: 检测到未完成的写入（{why}），"
              f"已安全丢弃末尾 {os.path.getsize(self.path) - off} 字节")
        with open(self.path, "r+b") as f:
            f.truncate(off)

    def _verify_chain(self) -> None:
        """校验高度连续与父哈希链 —— 磁盘上的链**必须**自洽，否则拒绝使用。"""
        prev = None
        for i, blk in enumerate(self._blocks):
            if blk.header.height != i:
                raise StoreCorruption(
                    f"{self.path}: 第 {i} 条的 height={blk.header.height}，应为 {i}")
            if prev is not None and blk.header.parent_hash != prev.block_hash():
                raise StoreCorruption(
                    f"{self.path}: 第 {i} 条的 parent_hash 与上一条的 block_hash 不符")
            prev = blk

    # ── 写 ──────────────────────────────────────────────────────────
    def ensure_genesis(self, genesis_block) -> None:
        """空文件时把**创世块**写成第 0 条记录（高度 == 下标这一不变量由此成立）。

        为什么把创世块也存进来：① 让"高度 == 记录下标"成为可校验的不变量；
        ② 数据目录因此**自带链身份**，加载时可以判定"这个目录属于哪条链"
        （避免拿 A 链的数据去启动 B 链）。
        """
        # **必须先读文件**：`_blocks` 只是内存缓存，重启时它是空的，
        # 若直接判空就会把创世块**再追加一次**（实测：重启后第 768 条记录变成
        # 高度 0 的创世块 ⇒ 链自洽性检查当场失败）。这类错误单测很难覆盖，
        # 因为单测通常先 `load()` 再写 —— 正是端到端重启测出来的。
        if not self._blocks and os.path.exists(self.path):
            self.load()
        if self._blocks:
            if self._blocks[0].block_hash() != genesis_block.block_hash():
                raise StoreCorruption(
                    "数据目录里的创世块与当前创世不符 —— 拒绝启动")
            return
        self.append(genesis_block)

    def append(self, block) -> None:
        """追加一条记录；**每条都 fsync**，使"已落盘"与"已最终化"一致。"""
        payload = block.to_rlp()
        if len(payload) > _MAX_RECORD:
            raise ValueError(f"区块过大：{len(payload)} 字节")
        if self._blocks and block.header.parent_hash != self._blocks[-1].block_hash():
            raise ValueError("只能按父哈希顺序追加最终化区块")
        # 高度必须等于下标（第 0 条是创世块）—— 这条不变量让"块高 == 文件位置"
        # 可被校验，也让加载时的快照对账不需要额外的映射表。
        if block.header.height != len(self._blocks):
            raise ValueError(
                f"只能按高度顺序追加（期望高度 {len(self._blocks)}，实际 {block.header.height}）")
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        off = os.path.getsize(self.path) if os.path.exists(self.path) else 0
        with open(self.path, "ab") as f:
            f.write(struct.pack(">I", len(payload)))
            f.write(payload)
            f.write(keccak256(payload))
            f.flush()
            os.fsync(f.fileno())
        self._offsets.append(off)
        self._blocks.append(block)

    def __len__(self) -> int:
        return len(self._blocks)

    def blocks(self) -> Sequence:
        return list(self._blocks)

    def head(self):
        return self._blocks[-1] if self._blocks else None


# ══════════════════════════════════════════════════════════════════════
# 2. 状态快照（存"输入"，加载时复算根）
# ══════════════════════════════════════════════════════════════════════

def encode_snapshot(state: State, height: int, head_hash: bytes,
                    head_commit_rlp: bytes = b"") -> bytes:
    """把状态的**输入**编码成确定性 RLP（不含 MPT 内部节点）。"""
    accounts = []
    for hashed_key, raw in sorted(state.accounts.items(), key=lambda kv: kv[0]):
        acc = Account.from_rlp(raw)
        # 地址由 trie 的**已哈希键**无法反推（那是 Keccak(地址)）⇒ 直接存叶子内容，
        # 加载时按"已哈希键 → 叶子"回填，不依赖地址反推。
        accounts.append([hashed_key, acc.nonce, acc.balance,
                         acc.validator_key or b"", acc.system_key or b""])
    validators = [[addr, rec.to_rlp()]
                  for addr, rec in sorted(state.validators.items(), key=lambda kv: kv[0])]
    return encode([
        SNAPSHOT_VERSION,
        P.CHAIN_ID_BYTES,
        P.PROTOCOL_VERSION.encode(),
        height,
        head_hash,
        state.state_root,
        accounts,
        validators,
        state.system.to_rlp(),
        # 第 10 项：**使链头最终化的那个 Commit**。
        # 为什么快照必须带上它：下一个区块的 `parent_commit` 必须是一份能证明
        # "父块已最终化"的法定数证书（§6.4 / §22 第 6 项）。链头的证书**不在**
        # 任何已落盘的区块里（每个区块携带的是**它父亲**的证书），若不单独保存，
        # 重启后节点只能拿空提交去提案 —— 对端一律以"parent_commit 非法"拒收，
        # **链就此停摆**。实测：4 节点重启后停在恢复时的高度，45 秒几乎零进展。
        head_commit_rlp,
    ])


def decode_snapshot(payload: bytes) -> Tuple[State, int, bytes, bytes]:
    """由快照重建 `State`，并**复算 `state_root`**（调用方负责与链上承诺对账）。"""
    it = decode(payload)
    if not isinstance(it, list) or len(it) != 10:
        raise StoreCorruption("快照必须为 10 项列表（含链头 Commit）")
    version = int.from_bytes(it[0], "big") if isinstance(it[0], (bytes, bytearray)) else it[0]
    if version != SNAPSHOT_VERSION:
        raise StoreCorruption(f"快照版本 {version} 不受支持（本实现支持 {SNAPSHOT_VERSION}）")
    if bytes(it[1]) != P.CHAIN_ID_BYTES:
        raise StoreCorruption("快照的 chain_id 与本节点当前链身份不符")
    if bytes(it[2]) != P.PROTOCOL_VERSION.encode():
        raise StoreCorruption("快照的 protocol_version 与当前协议版本不符")

    height = int.from_bytes(it[3], "big") if isinstance(it[3], (bytes, bytearray)) else it[3]
    head_hash = bytes(it[4])
    declared_root = bytes(it[5])

    st = State()
    for row in it[6]:
        hashed_key, nonce, balance = bytes(row[0]), _int(row[1]), _int(row[2])
        vk, sk = bytes(row[3]), bytes(row[4])
        # **必须**用规范的账户编码器重建叶子（而不是手写 `encode([...])`）：
        # "无此键"在叶子里的唯一形态是 `Hash("")`（32 字节），手写时若写成 0 长度
        # 就会得到**另一个叶子** ⇒ 复算出的状态根与链上承诺不符。
        # 这正是本模块"加载必须对账"想要抓住的那类错误 —— 它当场抓住了我自己。
        st.accounts.put_raw_hashed(
            hashed_key,
            Account(nonce=nonce, balance=balance,
                    validator_key=vk, system_key=sk).to_rlp())
    for row in it[7]:
        addr, rec_rlp = bytes(row[0]), bytes(row[1])
        st.validators[addr] = ValidatorRecord.from_rlp(rec_rlp)
    st._system = SystemState.from_rlp(bytes(it[8]))
    st._dirty = False

    if st.state_root != declared_root:
        raise StoreCorruption(
            f"快照复算的状态根与文件声明不符："
            f"复算 {st.state_root.hex()[:16]}… ≠ 声明 {declared_root.hex()[:16]}…")
    return st, height, head_hash, bytes(it[9])


def _int(v) -> int:
    return int.from_bytes(v, "big") if isinstance(v, (bytes, bytearray)) else int(v)


# ══════════════════════════════════════════════════════════════════════
# 3. 组合入口
# ══════════════════════════════════════════════════════════════════════

class ChainStore:
    """一个节点的数据目录：`blocks.bin` + `state.bin`。

    加载顺序：区块流 → 快照 → **与链上承诺对账** →（若快照落后）重放剩余区块。
    """

    def __init__(self, data_dir: str, snapshot_every: int = 1000) -> None:
        self.dir = data_dir
        self.blocks = BlockStore(os.path.join(data_dir, "blocks.bin"))
        self.state_path = os.path.join(data_dir, "state.bin")
        self.snapshot_every = max(1, snapshot_every)
        self._since_snapshot = 0

    # ── 加载 ────────────────────────────────────────────────────────
    def load(self, genesis_state: State, genesis_block, replays=None):
        """返回 `(状态, 区块列表)`。空目录时返回创世。

        `replays(state, block) -> State` 用于把快照之后、链头之前的区块补算回来。
        调用方通常传 `functools.partial(apply_block, finalize_header=False, in_place=True)`。
        缺失时若快照落后于链头，直接报错（**不猜**）。
        """
        blocks = self.blocks.load()
        if not blocks:
            return genesis_state, [], None

        # ① 第 0 条记录必须**就是**当前创世块：数据目录自带链身份，
        #    否则说明拿的是另一条链的数据目录（会静默跑出两条链）。
        if blocks[0].block_hash() != genesis_block.block_hash():
            raise StoreCorruption(
                "数据目录里的创世块与当前创世不符 —— 拒绝启动："
                "这可能是另一条链的数据目录")

        # ② 快照（可选）。快照高度是**区块高度**；由于"高度 == 下标"，
        #    它同时就是 `blocks` 的下标。
        snap_state, snap_height, snap_head, snap_commit = None, 0, None, b""
        if os.path.exists(self.state_path):
            snap_state, snap_height, snap_head, snap_commit = self._read_snapshot()

        # ③ **与链上承诺对账**：快照高度处区块头里的 state_root 必须等于快照的根
        if snap_state is not None:
            if snap_height >= len(blocks):
                raise StoreCorruption(
                    f"快照高度 {snap_height} 超过已持久化的链长 {len(blocks)}")
            committed = blocks[snap_height].header.state_root
            if snap_state.state_root != committed:
                raise StoreCorruption(
                    f"快照的 state_root 与高度 {snap_height} 区块头的承诺不符："
                    f"{snap_state.state_root.hex()[:16]}… ≠ {committed.hex()[:16]}…"
                    " —— 拒绝启动")
            if snap_head != blocks[snap_height].block_hash():
                raise StoreCorruption(
                    f"快照记录的链头 {snap_head.hex()[:16]}… 与高度 {snap_height} "
                    f"的区块哈希不符 —— 拒绝启动")
            # 链头的 Commit **必须**是能使该高度最终化的那份法定数证书：
            # 它会被下一个区块当作 `parent_commit` 提交给全网（§6.4），
            # 若存错了，节点重启后会持续产出"父块最终性证明非法"的提案 ⇒ 停摆。
            if snap_commit:
                from .block import Commit, verify_commit
                try:
                    commit = Commit.from_rlp(snap_commit)
                except Exception as e:                    # noqa: BLE001
                    raise StoreCorruption(f"快照里的链头 Commit 无法解码：{e}")
                if not commit.is_empty:
                    ok_c, why, _p = verify_commit(
                        commit, snap_state.system.snapshot,
                        expect_height=snap_height,
                        expect_hash=blocks[snap_height].block_hash())
                    if not ok_c:
                        raise StoreCorruption(
                            f"快照里的链头 Commit 不是有效的法定数证书：{why} —— 拒绝启动")

        # ④ 从快照处重放到链头。注意 `blocks[0]` 是**创世块**，它不需要被"应用"
        #    （创世状态就是它的结果），因此没有快照时从下标 1 开始重放。
        start = snap_height + 1 if snap_state is not None else 1
        st = snap_state if snap_state is not None else _clone(genesis_state)
        for blk in blocks[start:]:
            if replays is None:
                raise StoreCorruption(
                    f"需要重放 {len(blocks) - start} 个区块（快照落后），但未提供重放函数")
            st = replays(st, blk)
        # ⑤ 重放结果**必须**与链头承诺一致
        if st.state_root != blocks[-1].header.state_root:
            raise StoreCorruption(
                f"重放得到的状态根与链头承诺不符："
                f"{st.state_root.hex()[:16]}… ≠ {blocks[-1].header.state_root.hex()[:16]}…"
                " —— 拒绝启动")
        return st, blocks, (Commit_from_rlp(snap_commit) if snap_commit else None)

    def _read_snapshot(self):
        with open(self.state_path, "rb") as f:
            raw = f.read()
        if len(raw) < 4:
            raise StoreCorruption(f"{self.state_path}: 文件过短")
        (n,) = struct.unpack(">I", raw[:4])
        if len(raw) < 4 + n + 32:
            raise StoreCorruption(f"{self.state_path}: 文件被截断")
        payload = raw[4:4 + n]
        if keccak256(payload) != raw[4 + n:4 + n + 32]:
            raise StoreCorruption(f"{self.state_path}: 快照校验和不符")
        return decode_snapshot(payload)

    # ── 写入 ────────────────────────────────────────────────────────
    def append_block(self, block) -> None:
        self.blocks.append(block)
        self._since_snapshot += 1

    def save_state(self, state: State, height: int, head_hash: bytes,
                   head_commit=None) -> None:
        """原子写快照（临时文件 + rename）：要么旧版本、要么新版本，不存在半份。"""
        payload = encode_snapshot(state, height, head_hash,
                                  head_commit.to_rlp() if head_commit is not None else b"")
        tmp = self.state_path + ".tmp"
        os.makedirs(self.dir, exist_ok=True)
        with open(tmp, "wb") as f:
            f.write(struct.pack(">I", len(payload)))
            f.write(payload)
            f.write(keccak256(payload))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)
        self._since_snapshot = 0

    def maybe_snapshot(self, state: State, height: int, head_hash: bytes,
                       head_commit=None) -> bool:
        if self._since_snapshot >= self.snapshot_every:
            self.save_state(state, height, head_hash, head_commit)
            return True
        return False


def Commit_from_rlp(raw: bytes):
    from .block import Commit
    return Commit.from_rlp(raw)


def _clone(state: State) -> State:
    import copy
    return copy.deepcopy(state)
