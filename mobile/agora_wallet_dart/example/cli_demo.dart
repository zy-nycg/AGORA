// AGORA 钱包数据层 · 可运行的命令行示例（纯 Dart，无 Flutter 依赖）
//
// 用途：验证"包能跑通"，也是移植到 Flutter 之前的**最小可用样例**。
// 跑法（先起节点：bash wallet/run_rpc_demo.sh）：
//
//     dart run example/cli_demo.dart http://127.0.0.1:8645
//
// Flutter 里的写法与这里**完全一样**，区别只是把 `print` 换成 setState/StreamBuilder
// （见 docs/FLUTTER_INTEGRATION.md）。

import 'dart:async';
import 'dart:io';

import 'package:agora_wallet/agora_wallet.dart';

Future<void> main(List<String> args) async {
  // 地址：真机上要换成你节点的内网 IP（如 http://192.168.1.10:8645）
  final baseUrl = args.isNotEmpty ? args.first : 'http://127.0.0.1:8645';
  // 要查询的地址：不给就用"链上第一个验证者"（方便第一次跑通）
  final wanted = args.length > 1 ? args[1] : null;

  final client = AgoraHttpClient(
    [AgoraNode(baseUrl, label: '本机节点')],
    config: const AgoraClientConfig(
      // ⚠ 生产环境**必须**填这两个：否则等于接受"任意节点说它是什么链就是什么链"。
      //    值从创世文件抄（wallet/genesis.testnet.json 的 chain_id / genesis_hash）。
      expectedChainId: 'agora-testnet-1',
      expectedGenesisHash: '0x56c6819fe377e54e142cf15add68fa600c322e976ca27f3d973c31f95d2060bc',
      timeout: Duration(seconds: 8),
      maxRetries: 2,
    ),
  );
  final repo = WalletRepository(api: AgoraApi(client));

  try {
    print('── 1) 协议参数（不要在 App 里硬编码这些）──');
    final p = await repo.params();
    print('  chain_id        : ${p.chainId}');
    print('  槽长 / 纪元      : ${p.slotTimeSeconds}s / ${p.epochLengthSlots} 槽');
    print('  原子精度         : 1 AGORA = ${p.atomPerAgoraValue} atom');
    print('  空投窗口         : 槽 ${p.airdropStartSlot} .. ${p.airdropEndSlot}');
    print('  解绑期           : ${p.unbondingPeriodSlots} 槽');
    print('  交易类型码       : ${p.txTypeCodes}');

    print('\n── 2) 链状态 ──');
    final st = await repo.status(refresh: true);
    print('  高度             : ${st.envelope.height}（链长 ${st.chainLength}）');
    print('  链头哈希         : ${st.envelope.headHash}');
    print('  状态根           : ${st.envelope.stateRoot}');
    print('  当前槽（节点估计）: ${st.estimatedCurrentSlot}');
    print('  头部时间         : '
        '${p.slotToUtc(st.headClaimedSlot ?? 0).toIso8601String()}');
    print('  供应量           : ${formatAgora(st.supplyAtom, decimals: 0)} AGORA');
    print('  空投待领         : ${formatAgora(st.airdropPendingAtom, decimals: 0)} AGORA'
        '（已领 ${st.airdropClaimedCount} 个条目）');
    if (!st.airdropProofsAvailable && st.airdropProofsNote.isNotEmpty) {
      print('  ⚠ 空投证明不可用 : ${st.airdropProofsNote}');
    }

    print('\n── 3) 账户（余额 + nonce）──');
    final vs = await repo.validators(refresh: true);
    final address = wanted ?? vs.validators.first.address;
    final acc = await repo.account(address, refresh: true);
    print('  地址             : ${acc.address}');
    print('  存在             : ${acc.exists}');
    // 注意：金额是 BigInt，显示用 formatAgora；**任何计算都不要转 double**
    print('  余额             : ${formatAgora(acc.balanceAtom, decimals: 6)} AGORA');
    print('  余额（atom，精确）: ${acc.balanceAtom}');
    print('  下一笔 nonce     : ${acc.nonce}   ← 转账时 nonce 必须填这个值');
    if (acc.validator != null) {
      final v = acc.validator!;
      print('  验证者           : 状态=${v.status} 有效质押='
          '${formatAgora(v.effectiveStakeAtom, decimals: 2)} '
          '解绑中=${formatAgora(v.unbondingBalanceAtom, decimals: 2)}');
      if (v.unbondCompleteSlot > 0) {
        print('  解绑完成槽       : ${v.unbondCompleteSlot}（'
            '${p.slotToUtc(v.unbondCompleteSlot).toIso8601String()}）');
      }
    }

    print('\n── 4) 最近 3 个区块 ──');
    final latest = await repo.api.latestBlock();
    for (var h = latest.height; h > latest.height - 3 && h >= 0; h--) {
      final b = await repo.api.block('$h');
      print('  #${b.height} 槽=${b.claimedSlot} '
          '${b.timeUtc.toIso8601String()} tx=${b.transactions.length} '
          'hash=${b.blockHash.substring(0, 18)}…');
    }

    print('\n── 5) 空投状态 ──');
    final ad = await repo.airdrop(address, refresh: true);
    print('  可领取           : ${ad.eligible}');
    if (ad.proofAvailable) {
      print('  index/金额       : ${ad.index} / '
          '${ad.amountAtom == null ? "-" : formatAgora(ad.amountAtom!)}');
      print('  证明节点数       : ${ad.merkleProof.length}');
    } else {
      // 「本节点未加载分配表」与「你不在分配表里」是两件完全不同的事，必须分开显示
      print('  原因             : ${ad.reason}');
    }
    final missing = ad.missingForClaim();
    if (missing.isNotEmpty) {
      print('  还不能构造领取交易 : ${missing.join("；")}');
    }

    print('\n── 6) 实时刷新（轮询流，界面用 StreamBuilder 接）──');
    var n = 0;
    final sub = repo.watchAccount(address).listen(
      (a) {
        n++;
        print('  [$n] 高度=${a.envelope.height} 余额='
            '${formatAgora(a.balanceAtom, decimals: 6)} nonce=${a.nonce}');
      },
      onError: (Object e) => print('  [错误，但流仍然活着] $e'),
    );
    await Future<void>.delayed(const Duration(seconds: 6));
    await sub.cancel();
    print('  收到 $n 次推送（同高度会去重：省电，也避免界面无谓重建）');

    print('\n── 7) 交易提交（当前节点会明确拒绝，界面据此提示）──');
    try {
      await repo.api.submitRawTx('0x00');
      print('  节点接受了交易（说明交易池已实现）');
    } on AgoraApiException catch (e) {
      print('  HTTP ${e.statusCode} ${e.code}');
      print('  说明：${e.message}');
      if (e.detail.isNotEmpty) print('  缺什么：${e.detail}');
      print('  ⇒ App 里应显示"该功能尚不可用"，**不要**显示"已提交"');
    }
  } on AgoraChainMismatchException catch (e) {
    // 连错链是**必须让用户看到**的错误，不能吞掉
    print('✗ 链身份不符：${e.reason}');
    print('  ⇒ 请检查节点地址是否指向目标网络（测试网/主网/自建链）');
    exitCode = 2;
  } on AgoraTransportException catch (e) {
    print('✗ 网络不可达：$e');
    print('  ⇒ 手机与节点是否在同一网段？节点是否用 --rpc-bind 0.0.0.0 起了？');
    exitCode = 3;
  } on AgoraApiException catch (e) {
    print('✗ 节点返回错误：$e');
    exitCode = 4;
  } on AgoraParseException catch (e) {
    print('✗ 数据不符合契约：$e');
    exitCode = 5;
  } finally {
    repo.dispose();
    client.close();
  }
}
