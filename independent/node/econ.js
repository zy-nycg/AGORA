/*
 * AGORA v0.2.2 — 独立实现（Node.js）· 经济与费用函数
 * ==================================================
 *
 * 依据规范 §17.4（基础费）、§15.4（罚没）、§28.2（分配）、§28.4（发行曲线）独立编写。
 *
 * 为什么这些**纯函数**也必须跨实现一致：
 *   · **基础费**决定每个区块是否有效（§16.4 第 9 项）。两个实现算出不同基础费，
 *     就会互相拒绝对方的区块 —— 分叉；
 *   · **罚没额**决定从验证者扣多少钱，分歧会让状态根不同；
 *   · **发行曲线**决定每块铸币量，分歧同样直接改变状态根。
 * 三者都是纯整数算式，因此"照抄规范文本"是唯一正确的做法 ——
 * 尤其**不得**依赖实现的取整行为（本次已因宽度/取整差异踩过两次坑）。
 */

'use strict';

/** §17.4 基础费：**唯一权威整数形式**。 */
function baseFeeNext(baseFee, gasUsed, targetGas, maxGas, divisor, minBaseFee) {
  if (gasUsed > maxGas) throw new Error(`gas_used 超出上限 ${maxGas}`);
  if (baseFee < minBaseFee) throw new Error('基础费低于地板价');
  if (gasUsed === targetGas) return baseFee;

  if (gasUsed > targetGas) {
    const delta0 = (baseFee * BigInt(gasUsed - targetGas)) / divisor;
    const delta = delta0 < 1n ? 1n : delta0;             // 下限 1（避免停滞）
    return baseFee + delta;
  }
  // 下降：ceil(base_fee × Δ / divisor)，且不低于 MIN_BASE_FEE
  const num = baseFee * BigInt(targetGas - gasUsed);
  const delta = (num + divisor - 1n) / divisor;          // ceil
  const out = baseFee - delta;
  return out < minBaseFee ? minBaseFee : out;
}

/** §28.4 发行曲线（**恒定部分**）：clamp(floor(NUMERATOR / S), MIN, MAX) */
function curveBlockReward(stakedSupply, numerator, minReward, maxReward) {
  if (stakedSupply < 0n) throw new Error('质押总量必须非负');
  if (stakedSupply === 0n) return maxReward;             // 链此时应已 halt（§7.7）
  const raw = numerator / stakedSupply;
  if (raw < minReward) return minReward;
  if (raw > maxReward) return maxReward;
  return raw;
}

/**
 * §28.4 + §28.4.1 区块发行额（含过渡期奖励地板）。
 *
 * 关键点：`slot` **必须**是本块头部里被签名的 `claimed_slot`（§5.4.1）。
 * 若实现改用本地时间、父块槽或高度，窗口边界的取值就会与另一实现不同，
 * 直接表现为状态根分叉 —— 因此本函数**不提供默认值**，漏传即抛错。
 *
 * @param {bigint} stakedSupply 纪元快照的质押总量
 * @param {bigint} slot 本块 `claimed_slot`
 * @param {{numerator: bigint, minReward: bigint, maxReward: bigint,
 *          transitionEndSlot: bigint, transitionFloor: bigint}} ctx
 * @returns {bigint} atom
 */
function blockReward(stakedSupply, slot, ctx) {
  if (slot === undefined || ctx === undefined) {
    throw new Error('blockReward 需要 (stakedSupply, slot, ctx)：槽不可省略（§28.4.1）');
  }
  if (slot < 0n) throw new Error('slot 必须非负');
  const base = curveBlockReward(stakedSupply, ctx.numerator,
                                ctx.minReward, ctx.maxReward);
  if (slot < ctx.transitionEndSlot) {
    return base > ctx.transitionFloor ? base : ctx.transitionFloor;
  }
  return base;
}

/** §28.2 提案者 20% / 见证池 80%，**余数归提案者**（避免尘埃） */
function splitProposerAttestation(amount, poolPpm) {
  const pool = (amount * BigInt(poolPpm)) / 1000000n;
  return [amount - pool, pool];
}

/** §15.4 罚没额：floor(recorded_base × rate / 6,000,000) */
function slashAmount(recordedBase, ratePpm, denominator) {
  return (recordedBase * BigInt(ratePpm)) / denominator;
}

/**
 * §28.2 见证池按投票权分配，**每人取整、余数为尘埃**。
 * @param {bigint} pool 池子总额
 * @param {Array<[Buffer, bigint]>} signers `(address, vp)`
 * @param {bigint} totalWeight
 * @returns {{per_signer: Array, total_paid: bigint, dust: bigint}}
 */
function payPool(pool, signers, totalWeight) {
  if (totalWeight === 0n) return { per_signer: [], total_paid: 0n, dust: pool };
  const ordered = signers.slice().sort((a, b) => Buffer.compare(a[0], b[0]));
  let paid = 0n;
  const per = ordered.map(([addr, vp]) => {
    const share = (pool * vp) / totalWeight;
    paid += share;
    return [addr, share];
  });
  return { per_signer: per, total_paid: paid, dust: pool - paid };
}

module.exports = { baseFeeNext, blockReward, curveBlockReward,
                   splitProposerAttestation, slashAmount, payPool };
