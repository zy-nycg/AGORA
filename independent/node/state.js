/*
 * AGORA v0.2.2 — 独立实现（Node.js）· 链级状态（SystemState）
 * ==========================================================
 *
 * 依据规范 §19.5 独立编写。16 个字段，顺序即编码顺序：
 *
 *   0  epoch_current:u64
 *   1  year_index:u16
 *   2  year_start_slot:u64
 *   3  total_supply:u256
 *   4  total_burned_basefee:u256
 *   5  total_burned_annual:u256
 *   6  total_burned_slash:u256
 *   7  total_burned_dust:u256
 *   8  total_burned_inactivity:u256
 *   9  total_burned_unbacked:u256        ← 唯一参与守恒等式的销毁科目
 *  10  epoch_set_vp:[[address(20), vp:u256]]
 *  11  epoch_set_membership:[address(20)]
 *  12  pending_slashes:[PendingSlash]
 *  13  settled_slashes:[[offender(20), class:u8, offense_slot:u64]]
 *  14  airdrop_root:hash32
 *  15  airdrop_claimed:[[address(20), index:u64]]
 *
 * **为什么必须独立实现**：系统账户的 `system_key = Keccak(RLP(SystemState))`，
 * 而 `system_key` 进状态树 ⇒ 任何字段顺序/宽度理解不同都会改变**状态根**，
 * 即链分叉。本模块让第二实现能自己算出 `system_key` 并与参考实现比对。
 *
 * 快照（`epoch_set_vp` / `epoch_set_membership`）的编码见 `snapshotRlp`：
 *   两者都取自同一个 `SnapshotSet`，其中 `records` 是**已 RLP 编码的字节串列表**
 *   （在 SystemState 的 RLP 里它们是"字节串项"，会被再包一层长度前缀）。
 */

'use strict';

const { encode } = require('./primitives.js');

/** 快照：`RLP([membership, voting_power, staked_supply, records])` */
function snapshotRlp(snap) {
  return encode([
    snap.membership.map((a) => Buffer.from(a, 'hex')),
    snap.voting_power.map(([a, v]) => [Buffer.from(a, 'hex'), BigInt(v)]),
    BigInt(snap.staked_supply),
    snap.records.map((r) => Buffer.from(r, 'hex')),   // 已是 RLP 字节串
  ]);
}

/** §19.5 的 16 项 SystemState */
function systemStateRlp(sys) {
  const snap = sys.snapshot;
  return encode([
    sys.epoch_current,                       //  0
    sys.year_index,                          //  1
    sys.year_start_slot,                     //  2
    BigInt(sys.total_supply),                //  3
    BigInt(sys.total_burned_basefee),        //  4
    BigInt(sys.total_burned_annual),         //  5
    BigInt(sys.total_burned_slash),          //  6
    BigInt(sys.total_burned_dust),           //  7
    BigInt(sys.total_burned_inactivity),     //  8
    BigInt(sys.total_burned_unbacked),       //  9
    // 10 = RLP(SnapshotSet) 的**字节串**（一层嵌套编码；**不得**摊平为两个顶层字段）
    snapshotRlp(snap),
    sys.pending_slashes.map(pendingSlashRlp),                                // 11
    sys.settled_slashes.map(([o, cls, slot]) =>
      [Buffer.from(o, 'hex'), cls, BigInt(slot)]),                           // 12
    Buffer.from(sys.airdrop_root, 'hex'),                                    // 13
    BigInt(sys.airdrop_pending),                                             // 14
    sys.airdrop_claimed.map(([a, i]) => [Buffer.from(a, 'hex'), BigInt(i)]),  // 15
  ]);
}

/**
 * `PendingSlash`：`RLP([offender(20), class:u8, offense_slot:u64, recorded_base:u256, submitter(20)])`
 *
 * 注意：它作为 SystemState 列表里的**一项字节串**出现，因此这里返回**已编码的 RLP**，
 * 由外层的 `encode` 再包一层长度前缀（与 `records` 的处理一致）。
 * 这是 RLP 嵌套最容易写错的地方：返回"字段列表"会让外层把 5 个元素摊平进父列表，
 * 编码完全不同而**长度只差几字节**，极难靠肉眼发现。
 */
function pendingSlashRlp(p) {
  return encode([
    Buffer.from(p.offender, 'hex'),
    p.class_code,
    BigInt(p.offense_slot),
    BigInt(p.recorded_base),
    Buffer.from(p.submitter, 'hex'),
  ]);
}

module.exports = { snapshotRlp, systemStateRlp, pendingSlashRlp };
