# AGORA 钱包 · Dart 数据层（`agora_wallet`）

移动端钱包的**取数模块**：只读查询 + 严格校验。零第三方依赖（只用 `dart:io` / `dart:convert` / `dart:async`）。

```dart
import 'package:agora_wallet/agora_wallet.dart';

final client = AgoraHttpClient(
  [const AgoraNode('http://192.168.1.10:8645', label: '本机节点')],
  config: const AgoraClientConfig(
    expectedChainId: 'agora-testnet-1',
    expectedGenesisHash: '0x56c6819f…',   // 从创世文件抄，别猜
  ),
);
final repo = WalletRepository(api: AgoraApi(client));

final st  = await repo.status(refresh: true);   // 高度 / 链头 / 当前槽 / 空投窗口
final acc = await repo.account('0x56f1…');      // 余额（atom，BigInt）+ nonce
print('${displayBalance(acc.balanceAtom)}  next_nonce=${acc.nonce}');

await for (final a in repo.watchAccount('0x56f1…')) {   // 界面持续刷新
  print('余额 ${displayBalance(a.balanceAtom)}');
}
```

---

## 模块一览

| 文件 | 作用 |
|---|---|
| `lib/src/amount.dart` | **金额与地址的唯一处理入口**：atom ↔ AGORA、`BigInt` 解析/格式化、地址与哈希规范化 |
| `lib/src/errors.dart` | 错误分类：网络 / 服务端 / 解析 / **链身份不符**（界面要给出不同提示，见下） |
| `lib/src/models.dart` | 类型化模型：`ChainStatus`、`AccountState`、`BlockView`、`TxLookup`、`AirdropStatus`、`ValidatorSet`、`ChainParams` |
| `lib/src/http_client.dart` | 传输层：多节点故障转移、超时、GET 重试、**强制链身份校验** |
| `lib/src/agora_api.dart` | 端点 → 类型化方法（`status()` / `account()` / `block()` / `tx()` / `airdrop()` / `validators()` / `submitRawTx()`） |
| `lib/src/wallet_repository.dart` | 缓存 + 轮询流（`watchStatus` / `watchAccount` / `watchAirdrop`），**出错不结束流** |
| `lib/src/crypto/rlp.dart` | RLP 编码（§20.2，最小字节串规则） |
| `lib/src/crypto/keccak.dart` | Keccak-256 + `CHAIN()` 定宽连接（§20.1） |
| `lib/src/crypto/ed25519.dart` | Ed25519 签名/验签（RFC 8032，§2.1） |
| `lib/src/tx/transaction.dart` | 交易构造、签名载荷、`tx_hash`、签名 |
| `lib/src/tx/vector_checks.dart` | **向量对齐**：RLP/CHAIN/TXBLOCK 逐字节比对 |
| `tool/selftest.dart` | 自检：**70 项**（含向量对齐 + 对着真实节点取数） |
| `tool/send_transfer.dart` | **端到端**：Dart 签名一笔转账 → 提交 → 等进块 → 打回执 |

**依赖（不再是"零依赖"）**：`cryptography`（Ed25519）+ `pointycastle`（Keccak-256）。
理由：**钱包里手写椭圆曲线运算不可接受** —— 一个进位错误就可能泄露私钥，
而且这类错误不会在测试里"看起来不对"（签名照样自洽）。
取数层（`http_client`/`models`/`repository`）仍然只用 `dart:io`。

## 🚀 移植到你的 Flutter 项目

见 **`docs/FLUTTER_INTEGRATION.md`**（路径依赖 / 拷贝两种方式、Android 的
`INTERNET`+明文 HTTP、iOS 的 ATS、Web 的替代方案、`StreamBuilder` 与省电写法、
移植后的验收清单）。可运行示例：**`example/cli_demo.dart`**（`dart run example/cli_demo.dart`）。

## 签名并发送一笔转账（完整示例）

```dart
final st = await api.status();                       // ① 先确认链身份
final chainId = utf8.encode(st.envelope.chainId);    //    （它参与签名载荷）

final pubkey = await ed25519PublicKey(seed);         // ② 由种子推导公钥
final me = await api.account(bytesToHex0x(keccak256(pubkey).sublist(12)));
final tx0 = AgoraTransaction.transfer(
  nonce: me.nonce,                                   //    ← 必须是**刚取到的** nonce
  to: '0x5a43…', value: parseAgoraToAtom('1.5'), pubkey: pubkey,
  gasLimit: 100000, maxFeePerGas: (st.baseFeePerGas! * BigInt.two).toInt());

final tx = await tx0.sign(seed, chainId);            // ③ Dart 侧签名（本地先自检）
if (!await tx.verifySignature(chainId)) throw StateError('签名自检失败');

final r = await api.submitRawTx(tx.toHexEnvelope()); // ④ 提交（202 = 已受理，≠ 上链）
for (var i = 0; i < 60; i++) {                       // ⑤ 权威判定：查到才算成功
  final look = await api.tx(tx.txHashHex);
  if (look.found) { /* 显示"已上链，高度 ${look.blockHeight}" */ break; }
  await Future.delayed(const Duration(milliseconds: 500));
}
```

实测（真 4 节点集群）：Dart 签名 → 提交 → **高度 491 进块** → 回执
`gas_used=46000 / effective_gas_price=1e9`（手续费 0.000046 AGORA）→ 收款方 +1.5 AGORA。

## 三条硬纪律（都是真金白银的教训）

1. **金额永远是 `BigInt`，服务端的 `*_atom` 永远是字符串。**
   1 AGORA = 10^18 atom，初始供应 ≈ 2.048×10²⁵ atom，远超 double 的安全整数上限（2⁵³）与 Dart `int` 的 64 位。
   把 atom 解析成 `double`/`int` 会**静默丢精度**：界面显示正常，转账金额算错。
   `parseAtom()` 只接受十进制整数字符串，其他一律抛异常；**绝不用 0 兜底**
   （那会让"解析失败"看起来像"余额 0"）。
2. **链身份强制核对。** `expectedChainId` / `expectedGenesisHash` 与响应不符即抛
   `AgoraChainMismatchException`。这只是字符串比对（不是密码学证明），但它拦住的是最常见的
   灾难：手机连到了另一条链，余额显示成 0 或凭空多出余额。**未设置这两个字段等于放弃这条保护。**
3. **不静默兜底。** 缺字段、类型不对、金额不是字符串 ⇒ 抛 `AgoraParseException`。
   坏数据必须显式暴露，不能猜。

## 错误分类与界面提示（照抄即可）

| 异常 | 含义 | 界面应该说什么 |
|---|---|---|
| `AgoraTransportException` | 连不上/超时 | "网络异常，正在重试"（可重试） |
| `AgoraChainMismatchException` | 连错链/连错创世 | "当前节点不是目标链，已拒绝使用其数据"（**必须换节点**） |
| `AgoraApiException.isNotFound` | 查不到（如交易未上链） | "暂无记录"（**不是错误**） |
| `AgoraApiException` (`tx_rejected`) | 交易不合法（含 §16.4.2 项号） | 直接展示 `message`（例如"第 9 项：nonce 不匹配"） |
| `AgoraParseException` | 节点返回的数据不符合契约 | "节点数据异常"，记录日志，考虑换节点 |

## 如何跑起来（本机联调）

```bash
# ① 起一个带查询接口的节点（复用已有链数据，立刻有数据可查）
bash wallet/run_rpc_demo.sh wallet/runs/drill-final/node4 300 8645

# ② Dart 自检（含真实取数）
cd mobile/agora_wallet_dart
dart pub get --offline
dart analyze                       # 应输出 No issues found!
dart run tool/selftest.dart http://127.0.0.1:8645
```

## 接口契约（服务端：`tools/agora_rpc_server.py`）

* 全部 `GET`；`POST /v1/tx` 是唯一的写操作。
* 每个响应都带信封：`chain_id`、`protocol_version`、`genesis_hash`、`height`、`head_hash`、`state_root`。
* 金额字段以 `_atom` 结尾且是**十进制字符串**；高度/槽/nonce/gas 是小整数（JSON number）。
* 哈希 `0x` + 64 位十六进制；地址 `0x` + 40 位十六进制。
* 错误：`{"error": {"code", "message", "detail"}}`，状态码 400 / 404 / 501 / 503。

| 端点 | 说明 |
|---|---|
| `GET /healthz` | 存活探测（不含链信息） |
| `GET /v1/params` | 协议参数（槽长、原子精度、空投窗口、交易类型码…）——**别在钱包里硬编码这些** |
| `GET /v1/status` | 高度、链头、状态根、当前槽、空投窗口与"能否出证明" |
| `GET /v1/account/{address}` | 余额、nonce（**下一笔交易的 nonce 就是它**）、验证者信息 |
| `GET /v1/block/{height\|hash\|latest}` | 区块头 + 交易 + 回执 + 三个承诺根 |
| `GET /v1/tx/{tx_hash}` | 所在区块、块内位置、确认数、回执 |
| `GET /v1/airdrop/{address}` | 资格、金额、`index`、**Merkle 证明**、领取状态、窗口 |
| `GET /v1/validators` | 验证者集合 + 质押总量 + 法定数阈值 |
| `POST /v1/tx` | 提交已签名交易（`{"tx_rlp":"0x…"}`）→ **202 + tx_hash**；`duplicate` 幂等；不合法返回 400 + 项号 |

## 交易提交（已可用，但签名在钱包侧）

服务端现在有**交易池 + 交易广播 + 出块打包**（规范 §16.5），因此
`POST /v1/tx` 会真正把你的交易送进区块。语义务必按这个写界面：

```dart
final r = await repo.api.submitRawTx('0x' + signedRlpHex);
if (r.isPending) {
  // ⚠ 这**不是**"转账成功"，只是"节点已受理并转发"
  showBanner('已提交，等待上链…');
  // 权威结论只能来自查询：
  final look = await repo.api.tx(r.txHash!);
  if (look.found) showSuccess('已上链，高度 ${look.blockHeight}');
}
```

* `status=queued`（新受理）或 `duplicate`（已在池中）—— 两者都继续等上链，且**重复提交是安全的**；
* 被拒时抛 `AgoraApiException`（HTTP 400 / `code=tx_rejected`），`message` 里带
  §16.4.2 的**项号**（例如"第 9 项失败：nonce 不匹配"），可直接展示；
* **签名不在本包内**：`submitRawTx` 收的是**已签名交易的 RLP**。
  RLP + Keccak-256 + Ed25519 的签名模块见 `docs/FLUTTER_INTEGRATION.md` 的"下一步"。
* **没有客户端密码学校验。** 本包信任节点返回的数据（只做了链身份字符串比对）。
  要做到"不信任服务器"，需要在 Dart 侧复算 Keccak-256/RLP 校验区块哈希与承诺 ——
  这是可以后加的（`BlockView` 已经把 `tx_root` / `receipt_root` / `state_root` 都带出来了）。
* **回执的 `gas_used` 有边界精度问题**：它取决于"该交易是否新建账户"（+25,000 gas），
  而这一判断需要执行该区块时的父状态。区块头里的 `receipt_root` 才是权威值。

## 下一步（要真正"转账"，还差什么）

1. **节点侧**：交易池 + 广播 + 打包（上面那三件事），以及 `POST /v1/tx` 的真实实现。
2. **Dart 侧签名模块**（本包刻意不含）：需要
   * RLP 编码（规范 §20.2）；
   * Keccak-256（`tx_hash` / `chain_id_hash` / 叶子哈希都要）；
   * Ed25519 签名（RFC 8032，严格模式）；
   * 交易签名载荷：`CHAIN(chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, payload, pubkey)` 的**定宽**规则（规范 §20.1/§20.3）。
   建议用 `pointycastle`（Keccak）+ `cryptography`/`ed25519_edwards`（Ed25519），并用
   `tools/agora_vectors.py` 的 `TXBLOCK` 向量做**逐字节**对齐（那是唯一能证明"你的 RLP/签名与链上一致"的东西）。
3. **空投领取**：`AirdropStatus` 已经给出 `index` / `amount` / `gas_allowance` / `merkle_proof`；
   签名模块就位后即可构造 `AIRDROP_CLAIM`。构造前请调用 `missingForClaim()`，
   它会明确告诉你还差什么（例如"本节点未加载分配表"与"你不在分配表里"是两回事）。

## Web 平台

本包用 `dart:io` 的 `HttpClient`，**Flutter Web 不支持**。
若需要 Web，把 `http_client.dart` 里的 `HttpClient` 换成 `package:http` 的 `Client`
（其余代码不动：模型、仓库、错误分类都与传输实现解耦）。
