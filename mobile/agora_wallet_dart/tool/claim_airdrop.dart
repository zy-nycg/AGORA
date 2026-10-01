// AGORA 钱包 · **空投领取**（Dart 端到端验收脚本）
//
// 空投领取是钱包里"签名"最复杂的一种：一笔交易要**两处签名**
//  ① 载荷里的**绑定签名**：把 公钥 ↔ 地址 ↔ index 钉在一起（规范 §32.6 第 ③ 项）
//  ② 交易本身的签名（对所有交易都一样）
// 两者都错不了：任何一处不对，节点会以第 16 项（空投专属检查）或第 5 项拒绝。
//
// 用法（先跑 wallet/prep_airdrop_demo.sh 准备带空投的链并起集群）：
//
//   bash wallet/prep_airdrop_demo.sh wallet/runs/airdrop-demo
//   AIRDROP_TABLE=wallet/runs/airdrop-demo/table.json RPC_BASE=8700 \
//     bash wallet/run_local_cluster.sh wallet/runs/airdrop-demo/genesis.json 200 ad 0 \
//       wallet/runs/devkeys wallet/runs/airdrop-demo/nodes &
//   dart run tool/claim_airdrop.dart --base-url http://127.0.0.1:8700 \
//     --seed-file ../../wallet/runs/airdrop-demo/beneficiary1.seed
//
// 判据：链上查到该交易 + 受益人余额增加 + 金库余额减少（§32.5 是中性转账）。

import 'dart:convert';
import 'dart:io';

import 'package:agora_wallet/agora_wallet.dart';

Future<void> main(List<String> args) async {
  final opts = _parseArgs(args);
  final baseUrl = opts['base-url'] ?? 'http://127.0.0.1:8700';
  final seedPath = opts['seed-file'] ?? '../../wallet/runs/airdrop-demo/beneficiary1.seed';
  final timeout = int.tryParse(opts['timeout'] ?? '40') ?? 40;

  print('═' * 74);
  print('AGORA 钱包 · 空投领取（Dart 双签名 + 端到端）');
  print('  节点   : $baseUrl');
  print('  受益人 : $seedPath');
  print('═' * 74);

  final client = AgoraHttpClient(
      [AgoraNode(baseUrl, label: '被测节点')],
      config: const AgoraClientConfig(timeout: Duration(seconds: 10)));
  final api = AgoraApi(client);
  final repo = WalletRepository(api: api);

  try {
    final st = await api.status();
    final chainId = utf8.encode(st.envelope.chainId);
    print('链身份     : ${st.envelope.chainId}  高度 ${st.envelope.height}');

    final seed = hexToBytes(
        File(seedPath).readAsStringSync().trim().replaceFirst('0x', ''));
    final pubkey = await ed25519PublicKey(seed);
    final me = bytesToHex0x(keccak256(pubkey).sublist(12));

    // ① 向节点要"资格 + 金额 + index + Merkle 证明"
    //    ⚠ 证明只能来自**分配表**：链上只存 airdrop_root（§32.5）。
    //      节点没加载分配表时，接口会给出可读原因 —— 那不是"你没资格"。
    final ad = await api.airdrop(me);
    print('收款地址   : $me');
    print('空投资格   : eligible=${ad.eligible} claimed=${ad.claimed} '
        '证明可用=${ad.proofAvailable}');
    if (ad.reason.isNotEmpty) print('  说明     : ${ad.reason}');
    if (!ad.proofAvailable || ad.index == null || ad.amountAtom == null) {
      print('✗ 无法构造领取交易：${ad.missingForClaim().join("；")}');
      exitCode = 2;
      return;
    }
    print('  条目     : index=${ad.index} 金额=${formatAgora(ad.amountAtom!)} '
        'gas_allowance=${formatAgora(ad.gasAllowanceAtom ?? BigInt.zero, decimals: 9)}');
    print('  证明节点 : ${ad.merkleProof.length} 个');

    final acc = await api.account(me);
    print('余额       : ${formatAgora(acc.balanceAtom, decimals: 9)} AGORA '
        '（gas_allowance 已在创世记入，因此付得起领取的 gas）');

    // ② 组装载荷 + **绑定签名**
    var claim = AirdropClaim(
      index: ad.index!,
      amount: ad.amountAtom!,
      gasAllowance: ad.gasAllowanceAtom ?? BigInt.zero,
      pubkey: pubkey,
      merkleProof: ad.merkleProof,
    );
    claim = await claim.bind(seed, chainId, hexToBytes(me));
    final bindOk = await claim.verifyBinding(chainId, hexToBytes(me));
    print('绑定签名   : ${bindOk ? "✅ 本地验签通过" : "★ 失败"} '
        '(${bytesToHex0x(claim.bindingSignature).substring(0, 18)}…)');
    if (!bindOk) {
      print('✗ 绑定签名自检失败 —— 不提交');
      exitCode = 3;
      return;
    }

    // ③ 交易 + 交易签名（第二处签名）
    final baseFee = st.baseFeePerGas ?? BigInt.from(1000000000);
    var tx = AgoraTransaction.airdropClaim(
      nonce: acc.nonce,
      claim: claim,
      pubkey: pubkey,
      gasLimit: 100000,
      maxFeePerGas: (baseFee * BigInt.two).toInt(),
    );
    tx = await tx.sign(seed, chainId);
    print('已签名交易 : ${tx.txHashHex}');
    if (!await tx.verifySignature(chainId)) {
      print('✗ 交易签名自检失败 —— 不提交');
      exitCode = 3;
      return;
    }

    // ④ 提交并等上链
    final r = await api.submitRawTx(tx.toHexEnvelope());
    print('提交结果   : accepted=${r.accepted} status=${r.status} pool=${r.poolSize}');
    if (!r.isPending) {
      print('✗ 节点未受理：${r.note}');
      exitCode = 4;
      return;
    }
    print('等待进块（最多 $timeout 秒）…');
    TxLookup? found;
    final t0 = DateTime.now();
    while (DateTime.now().difference(t0).inSeconds < timeout) {
      final look = await api.tx(tx.txHashHex);
      if (look.found) {
        found = look;
        break;
      }
      await Future<void>.delayed(const Duration(milliseconds: 500));
    }
    if (found == null) {
      print('✗ 超时未上链');
      exitCode = 5;
      return;
    }

    // ⑤ 结果核对：余额增加 + 该条目在链上被标记为已领取
    final after = await api.account(me);
    final afterAd = await api.airdrop(me);
    final delta = after.balanceAtom - acc.balanceAtom;
    print('\n★ 领取成功');
    print('  所在区块 : 高度 ${found.blockHeight}  确认数 ${found.confirmations}');
    final rec = found.receipt;
    var fee = BigInt.zero;
    if (rec != null) {
      fee = rec.effectiveGasPrice * BigInt.from(rec.gasUsed);
      print('  回执     : status=${rec.status} gas_used=${rec.gasUsed} '
          'effective_gas_price=${rec.effectiveGasPrice}');
      print('  手续费   : ${formatAgora(fee, decimals: 9)} AGORA');
    }
    print('  余额     : ${formatAgora(acc.balanceAtom, decimals: 9)} → '
        '${formatAgora(after.balanceAtom, decimals: 9)} AGORA');
    print('  链上状态 : claimed=${afterAd.claimed}（该 index 已被记录）');

    // ⚠ **余额增量必须把手续费算进去**：领取金额进账、手续费出账，
    //   因此"增量 == 金额 − 手续费"。只断言"增量 ≥ 金额"会永远失败
    //   （首版就是这么写的，结果把一个**完全正确**的领取判成了失败）。
    //   这类"断言少算了一项"的错误在余额核对里极常见：
    //   之前还有一次是收款方被当成验证者、于是多出了出块奖励。
    final expected = ad.amountAtom! - fee;
    if (delta == expected && afterAd.claimed) {
      print('\n结果：✅ 空投领取闭环成功（Dart 双签名 → 进块 → '
          '余额增量 == 金额 − 手续费，且链上标记已领取）');
    } else {
      print('\n结果：★ 结果不符：增量 $delta，期望 $expected'
          '（金额 ${ad.amountAtom} − 手续费 $fee）；claimed=${afterAd.claimed}');
      exitCode = 6;
    }
  } on AgoraApiException catch (e) {
    print('✗ 节点拒绝：HTTP ${e.statusCode} ${e.code}\n  ${e.message}'
        '${e.detail.isEmpty ? '' : '\n  ${e.detail}'}');
    exitCode = 7;
  } on AgoraTransportException catch (e) {
    print('✗ 网络不可达：$e');
    exitCode = 8;
  } finally {
    repo.dispose();
    client.close();
  }
}

Map<String, String> _parseArgs(List<String> args) {
  final out = <String, String>{};
  for (var i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      final key = args[i].substring(2);
      out[key] = (i + 1 < args.length && !args[i + 1].startsWith('--'))
          ? args[++i]
          : 'true';
    }
  }
  return out;
}
