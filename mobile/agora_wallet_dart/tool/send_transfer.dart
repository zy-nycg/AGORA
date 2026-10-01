// AGORA 钱包 · 用 Dart **签名并提交**一笔转账（端到端验收脚本）
//
// 这是"钱包能真正转账"的完整闭环，全部由 Dart 完成：
//
//   读链状态 → 取 nonce/余额 → 构造交易 → **Ed25519 签名**（Dart）
//     → 本地验签 → POST /v1/tx → 轮询 GET /v1/tx/{hash} → 打印回执
//
// 用法（先起集群并开查询接口）：
//
//   RPC_BASE=8645 bash wallet/run_local_cluster.sh wallet/runs/dev-genesis.json 60 tx dart 0 \
//       wallet/runs/devkeys wallet/runs/tx-dart &
//   dart run tool/send_transfer.dart \
//       --seed-file ../../wallet/runs/devkeys/key1.seed \
//       --to 0x5a436e0d668518b3298a04c7d4f0f89d3540603a --amount 1
//
// 判据：`found=true` + 回执 + 收款方余额增加。**只看到"已受理"不算成功。**

import 'dart:convert';
import 'dart:io';

import 'package:agora_wallet/agora_wallet.dart';

Future<void> main(List<String> args) async {
  final opts = _parseArgs(args);
  final baseUrl = opts['base-url'] ?? 'http://127.0.0.1:8645';
  final amountAgora = opts['amount'] ?? '1';
  final seedPath = opts['seed-file'] ?? '../../wallet/runs/devkeys/key1.seed';
  final toArg = opts['to'];
  final timeout = int.tryParse(opts['timeout'] ?? '30') ?? 30;

  print('═' * 74);
  print('AGORA 钱包 · Dart 签名并提交转账');
  print('  节点   : $baseUrl');
  print('  私钥   : $seedPath');
  print('  金额   : $amountAgora AGORA');
  print('═' * 74);

  final client = AgoraHttpClient(
      [AgoraNode(baseUrl, label: '被测节点')],
      config: const AgoraClientConfig(timeout: Duration(seconds: 10)));
  final api = AgoraApi(client);
  final repo = WalletRepository(api: api);

  try {
    // ① 链身份：**必须先确定链，再签名**（chain_id 参与签名载荷；签错链会被节点按第 5 项拒收）
    final st = await api.status();
    final chainId = st.envelope.chainId;
    print('链身份     : $chainId（创世 ${st.envelope.genesisHash.substring(0, 18)}…）');
    print('当前高度   : ${st.envelope.height}');
    final chainIdBytes = utf8.encode(chainId);

    // ② 密钥与账户状态
    final seedHex = File(seedPath).readAsStringSync().trim().replaceFirst('0x', '');
    final seed = hexToBytes(seedHex);
    final pubkey = await ed25519PublicKey(seed);
    final sender = _addressFromPubkey(pubkey);
    final acc = await api.account(sender);
    print('付款方     : $sender');
    print('余额       : ${formatAgora(acc.balanceAtom, decimals: 6)} AGORA'
        '   nonce=${acc.nonce}');
    if (!acc.exists) {
      print('✗ 该账户在链上不存在（先给它转点钱）');
      exitCode = 2;
      return;
    }

    // ③ 收款方
    final to = toArg ?? '0x5a436e0d668518b3298a04c7d4f0f89d3540603a';
    final before = await api.account(to);
    final beforeBal = before.exists ? before.balanceAtom : BigInt.zero;
    print('收款方     : $to（当前 ${formatAgora(beforeBal, decimals: 6)} AGORA）');

    // ④ 构造交易（gas 与费用上限：max_fee 取基础费的 2 倍，足够覆盖正常波动）
    final baseFee = st.baseFeePerGas ?? BigInt.from(1000000000);
    final maxFee = baseFee * BigInt.two;
    final value = parseAgoraToAtom(amountAgora);
    var tx = AgoraTransaction.transfer(
      nonce: acc.nonce,
      to: to,
      value: value,
      pubkey: pubkey,
      gasLimit: 100000,                       // 转账（新建账户）46,000 gas，留足余量
      maxFeePerGas: maxFee.toInt(),
      maxPriorityFeePerGas: 0,
    );
    print('未签名载荷 : ${bytesToHex0x(tx.toContentRlp()).substring(0, 24)}…'
        '（${tx.toContentRlp().length} 字节）');

    // ⑤ **Dart 侧签名 + 本地自检**（本地先验一遍，能省一次往返与一次被拒）
    tx = await tx.sign(seed, chainIdBytes);
    final selfOk = await tx.verifySignature(chainIdBytes);
    print('已签名交易 : ${tx.txHashHex}');
    print('本地验签   : ${selfOk ? "✅ 通过" : "★ 失败"}');
    if (!selfOk) {
      print('✗ 本地验签失败 —— 不提交（说明签名模块或链身份有问题）');
      exitCode = 3;
      return;
    }

    // ⑥ 提交（受理 ≠ 上链）
    final r = await api.submitRawTx(tx.toHexEnvelope());
    print('提交结果   : accepted=${r.accepted} status=${r.status} '
        'pool=${r.poolSize}');
    if (!r.isPending) {
      print('✗ 节点未受理：${r.note}');
      exitCode = 4;
      return;
    }

    // ⑦ 等上链（**权威判定**）
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
      print('✗ 超时未上链（交易可能仍在池中，或提案者未被轮询到）');
      exitCode = 5;
      return;
    }

    print('\n★ 已上链');
    print('  高度     : ${found.blockHeight}  '
        'hash=${found.blockHash!.substring(0, 20)}…');
    print('  确认数   : ${found.confirmations}');
    final rec = found.receipt;
    if (rec != null) {
      print('  回执     : status=${rec.status} gas_used=${rec.gasUsed} '
          'effective_gas_price=${rec.effectiveGasPrice}');
      final fee = rec.effectiveGasPrice * BigInt.from(rec.gasUsed);
      print('  手续费   : ${formatAgora(fee, decimals: 9)} AGORA');
    }
    final after = await api.account(to);
    final afterBal = after.exists ? after.balanceAtom : BigInt.zero;
    final delta = afterBal - beforeBal;
    print('  收款方   : ${formatAgora(beforeBal, decimals: 6)} → '
        '${formatAgora(afterBal, decimals: 6)} AGORA（+${formatAgora(delta, decimals: 6)}）');
    if (delta == value) {
      print('\n结果：✅ 转账闭环成功（Dart 签名 → 节点受理 → 进块 → 余额正确）');
    } else {
      print('\n结果：★ 余额增量与转账额不符（$delta ≠ $value）');
      exitCode = 6;
    }
  } on AgoraChainMismatchException catch (e) {
    print('✗ 链身份不符：${e.reason}');
    exitCode = 7;
  } on AgoraApiException catch (e) {
    print('✗ 节点拒绝：HTTP ${e.statusCode} ${e.code}\n  ${e.message}'
        '${e.detail.isEmpty ? '' : '\n  ${e.detail}'}');
    exitCode = 8;
  } on AgoraTransportException catch (e) {
    print('✗ 网络不可达：$e');
    exitCode = 9;
  } finally {
    repo.dispose();
    client.close();
  }
}

String _addressFromPubkey(List<int> pubkey) =>
    bytesToHex0x(keccak256(pubkey).sublist(12));

Map<String, String> _parseArgs(List<String> args) {
  final out = <String, String>{};
  for (var i = 0; i < args.length; i++) {
    final a = args[i];
    if (a.startsWith('--')) {
      final key = a.substring(2);
      final next = (i + 1 < args.length && !args[i + 1].startsWith('--'))
          ? args[++i]
          : 'true';
      out[key] = next;
    }
  }
  return out;
}
