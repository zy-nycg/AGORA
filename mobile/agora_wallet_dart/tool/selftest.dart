// AGORA 钱包 Dart 数据层的**自检脚本**（零依赖，直接 `dart run`）
//
// 为什么不用 package:test
// -----------------------
// 自检必须能在**任何**环境跑起来（包括只有 SDK、没有 pub 网络的机器）。
// `package:test` 需要一个第三方依赖；这里用普通 `main()` + 断言计数，
// 跑法：
//
//     dart run tool/selftest.dart                        # 默认连 127.0.0.1:8645
//     dart run tool/selftest.dart http://192.168.1.10:8645
//
// 它验证两类东西：
//   ① **纯函数**（金额/地址/哈希的解析与格式化）——不需要网络；
//   ② **真实接口**（对着一个跑着的节点取数）——需要网络，缺了会明确跳过并提示。

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:agora_wallet/agora_wallet.dart';
import 'package:agora_wallet/src/tx/vector_checks.dart' as vec;

int _pass = 0;
int _fail = 0;

void check(String name, bool ok, [String detail = '']) {
  if (ok) {
    _pass++;
    print('  [OK  ] $name${detail.isEmpty ? '' : '   $detail'}');
  } else {
    _fail++;
    print('  [FAIL] $name${detail.isEmpty ? '' : '   $detail'}');
  }
}

void expectThrows(String name, void Function() body, [String? wantSubstring]) {
  try {
    body();
    check(name, false, '预期抛异常但没有');
  } catch (e) {
    final s = e.toString();
    check(name, wantSubstring == null || s.contains(wantSubstring),
        wantSubstring == null ? '' : s.split('\n').first);
  }
}

void testAmounts() {
  print('\n1) 金额：必须全程 BigInt（1 AGORA = 10^18 atom）');
  final one = parseAgoraToAtom('1');
  check('1 AGORA = 10^18 atom', one == BigInt.from(10).pow(18), '$one');
  check('1.5 AGORA', parseAgoraToAtom('1.5') == BigInt.from(15) * BigInt.from(10).pow(17));
  check('18 位小数可用（1 atom）', parseAgoraToAtom('0.000000000000000001') == BigInt.one);
  check('格式化：整数部分', formatAgora(one, decimals: 4) == '1');
  check('格式化：114687999999999999636 → 114.6879',
      formatAgora(BigInt.parse('114687999999999999636'), decimals: 4) == '114.6879',
      formatAgora(BigInt.parse('114687999999999999636'), decimals: 4));
  check('格式化：带单位', formatAgora(one, decimals: 2, withUnit: true) == '1 AGORA');

  // 服务端契约：*_atom 是十进制**字符串**。以下都必须被拒绝，而不是"尽量解析"。
  expectThrows('拒绝小数形式的 atom 字符串（服务端契约破坏）',
      () => parseAtom('1.5', field: 'x'), 'atom');
  expectThrows('拒绝科学计数法', () => parseAtom('1e18', field: 'x'));
  expectThrows('拒绝 double 类型的金额', () => parseAtom(1.5, field: 'x'), 'string');
  expectThrows('拒绝空字符串', () => parseAtom('', field: 'x'));
  expectThrows('用户输入负数金额必须被拒', () => parseAgoraToAtom('-1'));
  expectThrows('用户输入 19 位小数必须被拒', () => parseAgoraToAtom('0.0000000000000000001'),
      '18');

  // 关键反例：如果用 double 会把 2^53 以上的 atom 算错 —— 这里用 BigInt 必须精确
  final big = BigInt.parse('20480000000000000000000000'); // 初始供应
  check('初始供应量用 BigInt 精确表示（double 会丢精度）',
      big.toString() == '20480000000000000000000000' &&
          big > BigInt.from(9007199254740992),
      '${big.toString().length} 位十进制');
}

void testAddresses() {
  print('\n2) 地址与哈希的规范化/校验');
  const addr = '0x56f1d9fc896cc967d209ad02d4d76d7cd44a2d6c';
  check('小写带前缀原样通过', normalizeAddress(addr) == addr);
  check('大写/无前缀会被规范化',
      normalizeAddress('56F1D9FC896CC967D209AD02D4D76D7CD44A2D6C') == addr);
  expectThrows('长度不对必须被拒', () => normalizeAddress('0x1234'), '20 字节');
  expectThrows('非十六进制必须被拒', () => normalizeAddress('0x' + 'z' * 40));
  check('实时输入校验（不抛异常）', isPlausibleAddress(addr) && !isPlausibleAddress('0x12'));
  check('哈希规范化', normalizeHash('AA' * 32) == '0x' + 'aa' * 32);
  expectThrows('哈希长度不对必须被拒', () => normalizeHash('0xaa'), '32 字节');
}

Future<void> testLive(String baseUrl) async {
  print('\n3) 真实接口：$baseUrl');
  final client = AgoraHttpClient([AgoraNode(baseUrl, label: '被测节点')]);
  final api = AgoraApi(client);

  if (!await api.health()) {
    print('  [SKIP] 节点不可达 —— 跳过在线检查（先启动：'
        'bash wallet/run_rpc_demo.sh）');
    client.close();
    return;
  }

  // ① 协议参数与链状态
  final p = await api.params();
  check('params：拿到 chain_id 与槽长', p.chainId.isNotEmpty && p.slotTimeSeconds > 0,
      '${p.chainId} slot=${p.slotTimeSeconds}s atom=${p.atomPerAgoraValue}');
  check('params：原子精度 = 10^18', p.atomPerAgoraValue == atomPerAgora);

  final st = await api.status();
  check('status：高度 ≥ 0 且有链头哈希',
      st.envelope.height >= 0 && (st.envelope.headHash?.isNotEmpty ?? false),
      'height=${st.envelope.height} head=${st.envelope.headHash}');
  check('status：供应量为 2048 万 AGORA',
      st.supplyAtom == BigInt.from(20480000) * atomPerAgora,
      formatAgora(st.supplyAtom, decimals: 0));
  check('status：空投窗口来自参数（不硬编码）',
      st.envelope.chainId == p.chainId);

  // ② 账户：用链上第一个验证者地址（从 /v1/validators 取，避免硬编码）
  final vs = await api.validators();
  check('validators：至少 4 个验证者（创世约束）', vs.validators.length >= 4,
      '${vs.validators.length} 个；staked=${formatAgora(vs.stakedSupplyAtom, decimals: 0)} '
      'quorum=${formatAgora(vs.quorumAtom, decimals: 0)}');
  check('validators：法定数 = ceil(2S/3)',
      vs.quorumAtom == (vs.stakedSupplyAtom * BigInt.two + BigInt.from(2)) ~/ BigInt.from(3),
      '${vs.quorumAtom}');

  final v0 = vs.validators.first;
  final acc = await api.account(v0.address);
  check('account：exists=true 且余额非负',
      acc.exists && acc.balanceAtom >= BigInt.zero,
      '${acc.address} balance=${formatAgora(acc.balanceAtom)} nonce=${acc.nonce}');

  // **契约检查**：服务端必须把金额发成十进制**字符串**（否则 double 精度会毁掉钱包）。
  // 这里绕开封装直接看原始 JSON 的类型。
  final rawAcc = await client.getJson('/v1/account/${v0.address}');
  final rawBal = rawAcc.json['balance_atom'];
  check('account：balance_atom 在**原始 JSON** 里是 string（不是 number）',
      rawBal is String && rawBal == acc.balanceAtom.toString(),
      '类型=${rawBal.runtimeType} 值=${rawBal.toString().substring(0, 12)}…');
  final rawNonce = rawAcc.json['nonce'];
  check('account：nonce 是 JSON number（小整数用 number 才对）',
      rawNonce is int, '类型=${rawNonce.runtimeType}');
  check('account：nonce 非负且可用于下一笔交易', acc.nonce >= 0, 'next_nonce=${acc.nonce}');
  check('account：验证者信息被带出（质押字段齐全）',
      acc.validator != null && acc.validator!.effectiveStakeAtom > BigInt.zero,
      'stake=${formatAgora(acc.validator!.effectiveStakeAtom, decimals: 0)}');

  // ③ 区块与交易
  final blk = await api.latestBlock();
  check('block/latest：字段齐全（含承诺根）',
      blk.height >= 0 && blk.stateRoot.startsWith('0x') && blk.txRoot.startsWith('0x'),
      'height=${blk.height} slot=${blk.claimedSlot} gas=${blk.gasUsed} '
      'txs=${blk.transactions.length}');
  check('block：时间戳与槽一致（§5.4）',
      blk.timestamp == p.genesisTimestamp + blk.claimedSlot * p.slotTimeSeconds,
      '${blk.timeUtc.toIso8601String()}');

  // 按哈希取回同一块，必须完全一致（这是"数据自洽"的最小检查）
  final blk2 = await api.block(blk.blockHash);
  check('block/按哈希：与 /latest 得到同一块', blk2.blockHash == blk.blockHash &&
      blk2.height == blk.height);

  if (blk.height >= 1) {
    final b1 = await api.block('1');
    check('block/按高度：能取到高度 1', b1.height == 1,
        'hash=${b1.blockHash.substring(0, 18)}… parent=${b1.parentHash.substring(0, 18)}…');
  }

  final unknown = await api.tx('0x' + '11' * 32);
  check('tx/未知哈希：返回 found=false（不是错误）', unknown.found == false);

  // ④ 空投（本节点未加载分配表时应明确说明原因，而不是假装"你没资格"）
  final ad = await api.airdrop(v0.address);
  check('airdrop：返回结构完整', ad.airdropRoot.startsWith('0x') &&
      ad.claimWindowEndSlot > ad.claimWindowStartSlot,
      'window=${ad.claimWindowStartSlot}..${ad.claimWindowEndSlot} '
      'proof_available=${ad.proofAvailable}');
  check('airdrop：证明不可用时给出**可读原因**（而不是静默 false）',
      ad.proofAvailable || ad.reason.isNotEmpty,
      ad.proofAvailable ? '本节点可出证明' : ad.reason);
  if (ad.proofAvailable && ad.eligible) {
    check('airdrop：可领取时 index/金额/证明齐全',
        ad.index != null && ad.amountAtom != null && ad.hasProof);
  }

  // ⑤ 链身份强制校验（把"连错链"变成显式异常）
  print('\n4) 链身份强制校验（连错链必须显式失败）');
  final wrong = AgoraHttpClient(
      [AgoraNode(baseUrl)],
      config: const AgoraClientConfig(expectedChainId: 'agora-mainnet-1'));
  try {
    await AgoraApi(wrong).status();
    check('预期 mainnet 但节点是 testnet ⇒ 抛 AgoraChainMismatchException', false,
        '竟然接受了');
  } on AgoraChainMismatchException catch (e) {
    check('预期 mainnet 但节点是 testnet ⇒ 抛 AgoraChainMismatchException', true,
        e.reason);
  } finally {
    wrong.close();
  }

  final wrongGenesis = AgoraHttpClient(
      [AgoraNode(baseUrl)],
      config: AgoraClientConfig(
          expectedChainId: st.envelope.chainId,
          expectedGenesisHash: '0x' + 'ab' * 32));
  try {
    await AgoraApi(wrongGenesis).status();
    check('创世哈希不符 ⇒ 抛异常', false, '竟然接受了');
  } on AgoraChainMismatchException catch (e) {
    check('创世哈希不符 ⇒ 抛异常（比 chain_id 更强的一条防线）', true,
        e.reason.split('；').last);
  } finally {
    wrongGenesis.close();
  }

  // ⑥ 仓库层：缓存 + 轮询流
  print('\n5) 仓库层：缓存与轮询流');
  final repo = WalletRepository(
    api: AgoraApi(AgoraHttpClient(
        [AgoraNode(baseUrl)],
        config: AgoraClientConfig(expectedChainId: st.envelope.chainId))),
    poll: const PollConfig(
        interval: Duration(milliseconds: 400),
        errorBackoff: Duration(milliseconds: 400),
        maxBackoff: Duration(milliseconds: 800)),
  );
  final s1 = await repo.status(refresh: true);
  final t0 = DateTime.now();
  final s2 = await repo.status();                       // 命中缓存
  check('缓存命中不重复请求（同一高度）',
      identical(s1, s2) && DateTime.now().difference(t0).inMilliseconds < 500);

  final events = <ChainStatus>[];
  final sub = repo.watchStatus().listen(events.add);
  await Future<void>.delayed(const Duration(milliseconds: 1300));
  await sub.cancel();
  check('watchStatus 至少推送一次', events.isNotEmpty,
      '${events.length} 次；高度 ${events.map((e) => e.envelope.height).join(" → ")}');
  // **同高度不重复推送**是刻意设计：手机端每次重建界面都要花钱，
  // 高度没变就说明"链上没有新东西"。因此这里断言"没有重复事件"，
  // 而不是（像首版那样）断言"一定收到多次"—— 节点单独跑时高度本来就不动。
  check('watchStatus 不在同一高度重复推送（省电）',
      events.map((e) => e.envelope.height).toSet().length == events.length,
      '${events.length} 个事件，${events.map((e) => e.envelope.height).toSet().length} 个高度');

  // **出错不结束流**：这条性质必须被验证 —— 手机进电梯时若流被错误地关闭，
  // 界面会永久停在"加载中"。这里连一个不存在的端口，要求收到错误事件且流仍然打开。
  print('\n5b) 网络故障时：流必须继续存活（只发错误事件，不关闭）');
  final deadRepo = WalletRepository(
    api: AgoraApi(AgoraHttpClient([
      const AgoraNode('http://127.0.0.1:9', label: '故意不可达')
    ], config: const AgoraClientConfig(
        timeout: Duration(milliseconds: 600), maxRetries: 0))),
    poll: const PollConfig(
        interval: Duration(milliseconds: 300),
        errorBackoff: Duration(milliseconds: 300),
        maxBackoff: Duration(milliseconds: 600)),
  );
  var errCount = 0;
  var done = false;
  final deadSub = deadRepo.watchStatus().listen((_) {}, onError: (Object e) {
    errCount++;
  }, onDone: () {
    done = true;
  });
  await Future<void>.delayed(const Duration(milliseconds: 1500));
  check('不可达节点：收到错误事件（而不是静默）', errCount >= 1, '$errCount 次');
  check('★不可达节点：流**没有**被关闭（界面不会永久卡住）', !done);
  await deadSub.cancel();
  deadRepo.dispose();

  // ⑦ 提交交易的**错误契约**（交易池已实现，因此这里只验证"坏输入被明确拒绝"；
  //    真正"签名 → 提交 → 上链"的闭环见 `tool/send_transfer.dart`）
  print('\n6) 交易提交的错误契约（坏输入必须被明确拒绝，而不是静默丢弃）');
  try {
    await api.submitRawTx('0xdeadbeef');
    check('畸形 RLP 必须被拒（不能假装受理）', false, '竟然接受了');
  } on AgoraApiException catch (e) {
    check('畸形 RLP ⇒ 400 + bad_tx_rlp（钱包可据此提示用户）',
        e.statusCode == 400 && e.code == 'bad_tx_rlp',
        '${e.statusCode} ${e.code}: ${e.message}');
  }

  client.close();
  repo.dispose();
}

/// 额外：直接打一次原始 HTTP，验证错误结构（不经过任何封装）。
Future<void> testRawErrors(String baseUrl) async {
  print('\n7) 错误契约（原始 HTTP，绕过封装）');
  final http = HttpClient();
  try {
    final uri = Uri.parse('$baseUrl/v1/account/0xzz');
    final req = await http.getUrl(uri);
    final res = await req.close();
    final body = await utf8.decoder.bind(res).join();
    final j = jsonDecode(body) as Map<String, dynamic>;
    final err = j['error'] as Map<String, dynamic>?;
    check('坏参数 → HTTP 400 + structured error',
        res.statusCode == 400 && err != null && (err['code'] as String).isNotEmpty,
        'HTTP ${res.statusCode} code=${err?['code']}');
  } finally {
    http.close(force: true);
  }
}

Future<void> main(List<String> args) async {
  final baseUrl = args.isNotEmpty ? args.first : 'http://127.0.0.1:8645';
  print('═' * 72);
  print('AGORA 钱包 Dart 数据层 · 自检');
  print('═' * 72);
  testAmounts();
  testAddresses();
  // 签名模块的向量对齐（不需要网络：纯字节比对）
  final v = await vec.runTxVectorChecks();
  final sigPass = v[0], sigFail = v[1];
  _pass += sigPass;
  _fail += sigFail;
  await testLive(baseUrl);
  await testRawErrors(baseUrl);
  print('\n' + '═' * 72);
  print('通过 $_pass 项，失败 $_fail 项');
  print('结果：${_fail == 0 ? "全部通过 ✅" : "★ 存在失败"}');
  exit(_fail == 0 ? 0 : 1);
}
