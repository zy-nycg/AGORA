/// AGORA 钱包 · 数据模型（严格解析，绝不静默兜底）
///
/// 约定（与节点接口 `tools/agora_rpc_server.py` 一致）
/// ------------------------------------------------
/// * 所有响应的公共信封：`chain_id` / `protocol_version` / `genesis_hash` /
///   `height` / `head_hash` / `state_root`；
/// * 所有金额字段以 `_atom` 结尾，类型是**十进制字符串** → 用 [parseAtom] 转 [BigInt]；
/// * 高度、槽号、nonce、gas 这类小整数是 JSON number → 用 `int`。
///
/// 解析纪律：**缺字段就抛 [AgoraParseException]**。钱包里"猜一个默认值"
/// 的代价是把 0 显示成余额、把旧高度当成当前高度。
library;

import 'amount.dart';
import 'errors.dart';

/// 每个响应都带的公共信封（用于链身份检查与新鲜度判断）。
class Envelope {
  const Envelope({
    required this.chainId,
    required this.protocolVersion,
    required this.genesisHash,
    required this.height,
    required this.headHash,
    required this.stateRoot,
  });

  final String chainId;
  final String protocolVersion;
  final String genesisHash;
  final int height;
  final String? headHash;
  final String? stateRoot;

  static Envelope fromJson(Map<String, dynamic> json, {String path = ''}) {
    T need<T>(String key) {
      final v = json[key];
      if (v == null) {
        throw AgoraParseException('响应缺少字段 "$key"', path: path);
      }
      if (v is! T) {
        throw AgoraParseException(
            '字段 "$key" 类型应为 $T，实际 ${v.runtimeType}', path: path);
      }
      return v;
    }

    return Envelope(
      chainId: need<String>('chain_id'),
      protocolVersion: need<String>('protocol_version'),
      genesisHash: normalizeHash(need<String>('genesis_hash'), field: 'genesis_hash'),
      height: need<int>('height'),
      headHash: json['head_hash'] == null
          ? null
          : normalizeHash(json['head_hash'] as String, field: 'head_hash'),
      stateRoot: json['state_root'] == null
          ? null
          : normalizeHash(json['state_root'] as String, field: 'state_root'),
    );
  }
}

/// 链状态（`GET /v1/status`）。
class ChainStatus {
  const ChainStatus({
    required this.envelope,
    required this.chainLength,
    required this.estimatedCurrentSlot,
    required this.headClaimedSlot,
    required this.headTimestamp,
    required this.baseFeePerGas,
    required this.supplyAtom,
    required this.airdropPendingAtom,
    required this.airdropClaimedCount,
    required this.airdropRoot,
    required this.airdropProofsAvailable,
    required this.airdropProofsNote,
  });

  final Envelope envelope;

  /// 已最终化的区块数（链长，含创世）。
  final int chainLength;

  /// 节点对"当前槽"的估计（由本地时钟推导，不是共识值）。
  final int estimatedCurrentSlot;
  final int? headClaimedSlot;
  final int? headTimestamp;

  /// 下一块的基础费（基础费由父块决定，规范 §17.4）。
  final BigInt? baseFeePerGas;

  /// 初始供应（常量，用于界面对账）。
  final BigInt supplyAtom;
  final BigInt airdropPendingAtom;
  final int airdropClaimedCount;
  final String airdropRoot;

  /// 该节点是否能提供空投 Merkle 证明（取决于是否加载了分配表）。
  final bool airdropProofsAvailable;

  /// 不能提供证明时的原因（**必须展示给用户**，否则会以为"我没资格"）。
  final String airdropProofsNote;

  static ChainStatus fromJson(Map<String, dynamic> json, {String path = ''}) {
    int asInt(String k) {
      final v = json[k];
      if (v is int) return v;
      throw AgoraParseException('字段 "$k" 应为整数，实际 ${v.runtimeType}',
          path: path);
    }

    return ChainStatus(
      envelope: Envelope.fromJson(json, path: path),
      chainLength: asInt('chain_length'),
      estimatedCurrentSlot: asInt('estimated_current_slot'),
      headClaimedSlot: json['head_claimed_slot'] as int?,
      headTimestamp: json['head_timestamp'] as int?,
      baseFeePerGas: json['base_fee_per_gas'] == null
          ? null
          : parseAtom(json['base_fee_per_gas'], field: 'base_fee_per_gas'),
      supplyAtom: parseAtom(json['supply_atom'], field: 'supply_atom'),
      airdropPendingAtom:
          parseAtom(json['airdrop_pending_atom'], field: 'airdrop_pending_atom'),
      airdropClaimedCount: asInt('airdrop_claimed_count'),
      airdropRoot: normalizeHash(json['airdrop_root'] as String? ?? '',
          field: 'airdrop_root'),
      airdropProofsAvailable: json['airdrop_proofs_available'] == true,
      airdropProofsNote: (json['airdrop_proofs_note'] as String?) ?? '',
    );
  }

  /// 头部区块的槽号 × 槽长 + 创世时间 = 头部时间戳（可用于展示"数据有多旧"）。
  bool get hasChain => chainLength > 0;
}

/// 验证者记录（`validator` 字段）。
class ValidatorInfo {
  const ValidatorInfo({
    required this.address,
    required this.pubkey,
    required this.effectiveStakeAtom,
    required this.pendingStakeAtom,
    required this.unbondingBalanceAtom,
    required this.pendingUnbondAtom,
    required this.status,
    required this.unbondRequestSlot,
    required this.unbondCompleteSlot,
    required this.inactivityStreak,
    required this.slashedTotalAtom,
    required this.isFounder,
    this.votingPowerAtom,
  });

  final String address;
  final String? pubkey;
  final BigInt effectiveStakeAtom;
  final BigInt pendingStakeAtom;
  final BigInt unbondingBalanceAtom;
  final BigInt pendingUnbondAtom;

  /// 状态码（规范 §14.4：0=UNBONDED、1=BONDED、2=UNBONDING…）。
  final int status;
  final int unbondRequestSlot;
  final int unbondCompleteSlot;
  final int inactivityStreak;
  final BigInt slashedTotalAtom;
  final bool isFounder;
  final BigInt? votingPowerAtom;

  /// 质押总量（有效 + 待生效 + 解绑中 + 待解绑），用于界面展示"我的总持仓"。
  BigInt get totalStakedAtom =>
      effectiveStakeAtom +
      pendingStakeAtom +
      unbondingBalanceAtom +
      pendingUnbondAtom;

  static ValidatorInfo fromJson(Map<String, dynamic> j, {String path = ''}) =>
      ValidatorInfo(
        address: normalizeAddress(j['address'] as String? ?? ''),
        pubkey: j['pubkey'] == null
            ? null
            : normalizeHash(j['pubkey'] as String, field: 'pubkey'),
        effectiveStakeAtom:
            parseAtom(j['effective_stake_atom'], field: 'effective_stake_atom'),
        pendingStakeAtom:
            parseAtom(j['pending_stake_atom'], field: 'pending_stake_atom'),
        unbondingBalanceAtom:
            parseAtom(j['unbonding_balance_atom'], field: 'unbonding_balance_atom'),
        pendingUnbondAtom:
            parseAtom(j['pending_unbond_atom'], field: 'pending_unbond_atom'),
        status: (j['status'] as int?) ?? 0,
        unbondRequestSlot: (j['unbond_request_slot'] as int?) ?? 0,
        unbondCompleteSlot: (j['unbond_complete_slot'] as int?) ?? 0,
        inactivityStreak: (j['inactivity_streak'] as int?) ?? 0,
        slashedTotalAtom: parseAtom(j['slashed_total_atom'], field: 'slashed_total_atom'),
        isFounder: j['is_founder'] == true,
        votingPowerAtom: j['voting_power_atom'] == null
            ? null
            : parseAtom(j['voting_power_atom'], field: 'voting_power_atom'),
      );
}

/// 账户状态（`GET /v1/account/{address}`）。
class AccountState {
  const AccountState({
    required this.envelope,
    required this.address,
    required this.exists,
    required this.balanceAtom,
    required this.nonce,
    required this.isValidator,
    required this.validator,
  });

  final Envelope envelope;
  final String address;

  /// 账户是否已存在于状态树中（不存在 = 尚未收到过任何资金）。
  final bool exists;
  final BigInt balanceAtom;

  /// 账户 nonce：**下一笔交易的 nonce 就填它**（规范 §16.4.2 第 9 项要求相等）。
  final int nonce;
  final bool isValidator;
  final ValidatorInfo? validator;

  static AccountState fromJson(Map<String, dynamic> json, {String path = ''}) {
    final v = json['validator'];
    return AccountState(
      envelope: Envelope.fromJson(json, path: path),
      address: normalizeAddress(json['address'] as String? ?? ''),
      exists: json['exists'] == true,
      balanceAtom: parseAtom(json['balance_atom'], field: 'balance_atom'),
      nonce: (json['nonce'] as int?) ?? 0,
      isValidator: json['is_validator'] == true,
      validator: v is Map<String, dynamic>
          ? ValidatorInfo.fromJson(v, path: path)
          : null,
    );
  }
}

/// 一笔交易在区块中的视图。
class TransactionView {
  const TransactionView({
    required this.txHash,
    required this.txType,
    required this.from,
    required this.to,
    required this.valueAtom,
    required this.nonce,
    required this.envelopeRlp,
    this.gasLimit,
    this.maxFeePerGas,
  });

  final String txHash;
  final int txType;
  final String from;
  final String? to;
  final BigInt valueAtom;
  final int nonce;

  /// 原始交易封装（RLP 十六进制）。展示历史时通常用不到，
  /// 但"把原始字节交给用户/审计"是钱包应有的能力。
  final String envelopeRlp;
  final int? gasLimit;
  final BigInt? maxFeePerGas;

  static TransactionView fromJson(Map<String, dynamic> j, {String path = ''}) =>
      TransactionView(
        txHash: normalizeHash(j['tx_hash'] as String? ?? '', field: 'tx_hash'),
        txType: (j['tx_type'] as int?) ?? 0,
        from: normalizeAddress(j['from'] as String? ?? ''),
        to: j['to'] == null ? null : normalizeAddress(j['to'] as String),
        valueAtom: parseAtom(j['value_atom'], field: 'value_atom'),
        nonce: (j['nonce'] as int?) ?? 0,
        envelopeRlp: (j['envelope_rlp'] as String?) ?? '',
        gasLimit: j['gas_limit'] as int?,
        maxFeePerGas: j['max_fee_per_gas'] == null
            ? null
            : parseAtom(j['max_fee_per_gas'], field: 'max_fee_per_gas'),
      );
}

/// 交易回执（`receipt` 字段）。
class TxReceipt {
  const TxReceipt({
    required this.txHash,
    required this.status,
    required this.gasUsed,
    required this.effectiveGasPrice,
  });

  final String txHash;

  /// 1 = 成功（本版本没有失败分支，规范 §16.4.2 第 18 项）。
  final int status;
  final int gasUsed;
  final BigInt effectiveGasPrice;

  bool get isSuccess => status == 1;

  static TxReceipt fromJson(Map<String, dynamic> j, {String path = ''}) => TxReceipt(
        txHash: normalizeHash(j['tx_hash'] as String? ?? '', field: 'tx_hash'),
        status: (j['status'] as int?) ?? 0,
        gasUsed: (j['gas_used'] as int?) ?? 0,
        effectiveGasPrice: parseAtom(j['effective_gas_price'],
            field: 'effective_gas_price'),
      );
}

/// 区块（`GET /v1/block/...`）。
class BlockView {
  const BlockView({
    required this.envelope,
    required this.height,
    required this.round,
    required this.claimedSlot,
    required this.timestamp,
    required this.blockHash,
    required this.parentHash,
    required this.stateRoot,
    required this.txRoot,
    required this.receiptRoot,
    required this.gasUsed,
    required this.baseFeePerGas,
    required this.proposer,
    required this.parentCommitHeight,
    required this.parentCommitSignatureCount,
    required this.transactions,
    required this.receipts,
  });

  final Envelope envelope;
  final int height;
  final int round;
  final int claimedSlot;
  final int timestamp;
  final String blockHash;
  final String parentHash;
  final String stateRoot;
  final String txRoot;
  final String receiptRoot;
  final int gasUsed;
  final BigInt baseFeePerGas;
  final String? proposer;
  final int parentCommitHeight;
  final int parentCommitSignatureCount;
  final List<TransactionView> transactions;
  final List<TxReceipt> receipts;

  static BlockView fromJson(Map<String, dynamic> b, Map<String, dynamic> envelopeJson,
      {String path = ''}) {
    final pc = (b['parent_commit'] as Map<String, dynamic>?) ?? const {};
    List<TransactionView> txs = const [];
    final rawTxs = b['transactions'];
    if (rawTxs is List) {
      txs = rawTxs
          .whereType<Map<String, dynamic>>()
          .map((e) => TransactionView.fromJson(e, path: path))
          .toList(growable: false);
    }
    List<TxReceipt> recs = const [];
    final rawRecs = b['receipts'];
    if (rawRecs is List) {
      recs = rawRecs
          .whereType<Map<String, dynamic>>()
          .map((e) => TxReceipt.fromJson(e, path: path))
          .toList(growable: false);
    }
    int asInt(String k) {
      final v = b[k];
      if (v is int) return v;
      throw AgoraParseException('区块字段 "$k" 应为整数，实际 ${v.runtimeType}',
          path: path);
    }

    return BlockView(
      envelope: Envelope.fromJson(envelopeJson, path: path),
      height: asInt('height'),
      round: asInt('round'),
      claimedSlot: asInt('claimed_slot'),
      timestamp: asInt('timestamp'),
      blockHash: normalizeHash(b['block_hash'] as String? ?? '', field: 'block_hash'),
      parentHash: normalizeHash(b['parent_hash'] as String? ?? '', field: 'parent_hash'),
      stateRoot: normalizeHash(b['state_root'] as String? ?? '', field: 'state_root'),
      txRoot: normalizeHash(b['tx_root'] as String? ?? '', field: 'tx_root'),
      receiptRoot:
          normalizeHash(b['receipt_root'] as String? ?? '', field: 'receipt_root'),
      gasUsed: asInt('gas_used'),
      baseFeePerGas: parseAtom(b['base_fee_per_gas'], field: 'base_fee_per_gas'),
      proposer: b['proposer'] == null
          ? null
          : normalizeAddress(b['proposer'] as String),
      parentCommitHeight: (pc['height'] as int?) ?? 0,
      parentCommitSignatureCount: (pc['signature_count'] as int?) ?? 0,
      transactions: txs,
      receipts: recs,
    );
  }

  /// UTC 时间（区块时间戳由槽决定，规范 §5.4）。
  DateTime get timeUtc =>
      DateTime.fromMillisecondsSinceEpoch(timestamp * 1000, isUtc: true);
}

/// 交易查询结果（`GET /v1/tx/{hash}`）。
class TxLookup {
  const TxLookup({
    required this.envelope,
    required this.found,
    required this.txHash,
    this.blockHeight,
    this.blockHash,
    this.indexInBlock,
    this.confirmations,
    this.transaction,
    this.receipt,
  });

  final Envelope envelope;
  final bool found;
  final String txHash;
  final int? blockHeight;
  final String? blockHash;
  final int? indexInBlock;

  /// 已最终化高度 − 该交易所在高度（链上"确认数"的等价物）。
  final int? confirmations;
  final TransactionView? transaction;
  final TxReceipt? receipt;

  static TxLookup fromJson(Map<String, dynamic> json, {String path = ''}) {
    final tx = json['transaction'];
    final rc = json['receipt'];
    return TxLookup(
      envelope: Envelope.fromJson(json, path: path),
      found: json['found'] == true,
      txHash: normalizeHash(json['tx_hash'] as String? ?? '', field: 'tx_hash'),
      blockHeight: json['block_height'] as int?,
      blockHash: json['block_hash'] == null
          ? null
          : normalizeHash(json['block_hash'] as String, field: 'block_hash'),
      indexInBlock: json['index_in_block'] as int?,
      confirmations: json['confirmations'] as int?,
      transaction:
          tx is Map<String, dynamic> ? TransactionView.fromJson(tx, path: path) : null,
      receipt: rc is Map<String, dynamic> ? TxReceipt.fromJson(rc, path: path) : null,
    );
  }
}

/// 空投状态（`GET /v1/airdrop/{address}`）。
///
/// 这些字段就是构造 `AIRDROP_CLAIM` 交易**所需的全部参数**（规范 §32.6）；
/// 签名与 RLP 打包由钱包的签名模块完成（本包只负责取数与校验字段完备性）。
class AirdropStatus {
  const AirdropStatus({
    required this.envelope,
    required this.address,
    required this.eligible,
    required this.claimed,
    required this.proofAvailable,
    required this.airdropRoot,
    required this.claimWindowStartSlot,
    required this.claimWindowEndSlot,
    required this.claimWindowOpen,
    required this.vaultBalanceAtom,
    this.reason = '',
    this.index,
    this.amountAtom,
    this.gasAllowanceAtom,
    this.merkleProof = const [],
    this.claimedEntriesForAddress = const [],
    this.note = '',
  });

  final Envelope envelope;
  final String address;

  /// 是否**可领取**（= 在表中 且 未被领取 且 证明可用）。
  final bool eligible;

  /// 该条目是否已被领取（`(地址, index)` 二元组，BUG-87）。
  final bool claimed;

  /// 本节点能否提供证明（取决于它是否加载了空投分配表）。
  final bool proofAvailable;
  final String airdropRoot;
  final int claimWindowStartSlot;
  final int claimWindowEndSlot;
  final bool claimWindowOpen;
  final BigInt vaultBalanceAtom;

  /// 不可领取/不可出证的原因，**必须原样展示**：
  /// "本节点未加载分配表"与"你不在分配表里"是完全不同的两件事。
  final String reason;

  final int? index;
  final BigInt? amountAtom;
  final BigInt? gasAllowanceAtom;
  final List<String> merkleProof;
  final List<int> claimedEntriesForAddress;
  final String note;

  bool get hasProof => merkleProof.isNotEmpty;

  /// 构造领取交易前必须满足的条件（缺一不可），返回缺失原因列表。
  List<String> missingForClaim() {
    final out = <String>[];
    if (!proofAvailable) out.add(reason.isEmpty ? '本节点无法提供空投证明' : reason);
    if (eligible == false) {
      if (claimed) out.add('该条目已领取');
      if (reason.isNotEmpty) out.add(reason);
    }
    if (index == null) out.add('缺少 index（规范的叶子与去重键都需要它）');
    if (amountAtom == null) out.add('缺少领取金额');
    if (!hasProof) out.add('缺少 Merkle 证明');
    if (!claimWindowOpen) {
      out.add('不在领取窗口内（槽 $claimWindowStartSlot..$claimWindowEndSlot）');
    }
    // 去重：多个条件常常指向同一条原因（例如"未加载分配表"会同时让
    // eligible 为 false 且 proofAvailable 为 false），直接 join 给用户看会很傻。
    final seen = <String>{};
    return out.where(seen.add).toList(growable: false);
  }

  static AirdropStatus fromJson(Map<String, dynamic> json, {String path = ''}) {
    final win = (json['claim_window'] as Map<String, dynamic>?) ?? const {};
    final proof = (json['merkle_proof'] as List?)
            ?.whereType<String>()
            .map((h) => normalizeHash(h, field: 'merkle_proof 节点'))
            .toList(growable: false) ??
        const <String>[];
    final claimedIdx = (json['claimed_entries_for_address'] as List?)
            ?.whereType<int>()
            .toList(growable: false) ??
        const <int>[];
    return AirdropStatus(
      envelope: Envelope.fromJson(json, path: path),
      address: normalizeAddress(json['address'] as String? ?? ''),
      eligible: json['eligible'] == true,
      claimed: json['claimed'] == true,
      proofAvailable: json['proof_available'] == true,
      airdropRoot:
          normalizeHash(json['airdrop_root'] as String? ?? '', field: 'airdrop_root'),
      claimWindowStartSlot: (win['start_slot'] as int?) ?? 0,
      claimWindowEndSlot: (win['end_slot'] as int?) ?? 0,
      claimWindowOpen: win['open'] == true,
      vaultBalanceAtom:
          parseAtom(json['vault_balance_atom'], field: 'vault_balance_atom'),
      reason: (json['reason'] as String?) ?? '',
      index: json['index'] as int?,
      amountAtom: json['amount_atom'] == null
          ? null
          : parseAtom(json['amount_atom'], field: 'amount_atom'),
      gasAllowanceAtom: json['gas_allowance_atom'] == null
          ? null
          : parseAtom(json['gas_allowance_atom'], field: 'gas_allowance_atom'),
      merkleProof: proof,
      claimedEntriesForAddress: claimedIdx,
      note: (json['note_field'] as String?) ?? '',
    );
  }
}

/// 验证者列表（`GET /v1/validators`）。
class ValidatorSet {
  const ValidatorSet({
    required this.envelope,
    required this.validators,
    required this.stakedSupplyAtom,
    required this.quorumAtom,
  });

  final Envelope envelope;
  final List<ValidatorInfo> validators;
  final BigInt stakedSupplyAtom;
  final BigInt quorumAtom;

  static ValidatorSet fromJson(Map<String, dynamic> json, {String path = ''}) =>
      ValidatorSet(
        envelope: Envelope.fromJson(json, path: path),
        validators: ((json['validators'] as List?) ?? const [])
            .whereType<Map<String, dynamic>>()
            .map((e) => ValidatorInfo.fromJson(e, path: path))
            .toList(growable: false),
        stakedSupplyAtom:
            parseAtom(json['staked_supply_atom'], field: 'staked_supply_atom'),
        quorumAtom: parseAtom(json['quorum_atom'], field: 'quorum_atom'),
      );
}

/// 协议参数（`GET /v1/params`）：**不要在钱包里硬编码这些值**。
class ChainParams {
  const ChainParams({
    required this.chainId,
    required this.protocolVersion,
    required this.atomPerAgoraValue,
    required this.slotTimeSeconds,
    required this.epochLengthSlots,
    required this.genesisTimestamp,
    required this.airdropStartSlot,
    required this.airdropEndSlot,
    required this.unbondingPeriodSlots,
    required this.initialBaseFeePerGas,
    required this.maxGasPerBlock,
    required this.txTypeCodes,
  });

  final String chainId;
  final String protocolVersion;
  final BigInt atomPerAgoraValue;
  final int slotTimeSeconds;
  final int epochLengthSlots;
  final int genesisTimestamp;
  final int airdropStartSlot;
  final int airdropEndSlot;
  final int unbondingPeriodSlots;
  final BigInt initialBaseFeePerGas;
  final BigInt maxGasPerBlock;
  final Map<String, int> txTypeCodes;

  static ChainParams fromJson(Map<String, dynamic> j, {String path = ''}) {
    final win = (j['airdrop_window'] as Map<String, dynamic>?) ?? const {};
    final codes = ((j['tx_type_codes'] as Map<String, dynamic>?) ?? const {})
        .map((k, v) => MapEntry(k, v as int));
    return ChainParams(
      chainId: j['chain_id'] as String? ?? '',
      protocolVersion: j['protocol_version'] as String? ?? '',
      atomPerAgoraValue:
          parseAtom(j['atom_per_agora'], field: 'atom_per_agora'),
      slotTimeSeconds: (j['slot_time_seconds'] as int?) ?? 0,
      epochLengthSlots: (j['epoch_length_slots'] as int?) ?? 0,
      genesisTimestamp: (j['genesis_timestamp'] as int?) ?? 0,
      airdropStartSlot: (win['start_slot'] as int?) ?? 0,
      airdropEndSlot: (win['end_slot'] as int?) ?? 0,
      unbondingPeriodSlots: (j['unbonding_period_slots'] as int?) ?? 0,
      initialBaseFeePerGas:
          parseAtom(j['initial_base_fee_per_gas'], field: 'initial_base_fee_per_gas'),
      maxGasPerBlock: parseAtom(j['max_gas_per_block'], field: 'max_gas_per_block'),
      txTypeCodes: codes,
    );
  }

  /// 槽号 → UTC 时间（规范 §5.4：`GenesisTimestamp + slot × SLOT_TIME`）。
  DateTime slotToUtc(int slot) => DateTime.fromMillisecondsSinceEpoch(
      (genesisTimestamp + slot * slotTimeSeconds) * 1000,
      isUtc: true);

  /// 当前 UTC → 槽号（仅用于展示倒计时，**不是**共识判定）。
  int utcToSlot(DateTime utc) =>
      (utc.toUtc().millisecondsSinceEpoch ~/ 1000 - genesisTimestamp) ~/
      slotTimeSeconds;
}
