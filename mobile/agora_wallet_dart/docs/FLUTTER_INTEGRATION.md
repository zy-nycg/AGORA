# 把 `agora_wallet` 移植进你的 Flutter 项目

这份文档只讲一件事：**怎么在你的 App 里把它跑起来**（含安卓/iOS 上最容易卡住的三处配置）。

---

## 0. 一分钟版本

```bash
# 1) 把包放进你的仓库（或与 App 并列）
cp -r /path/to/AGORA/mobile/agora_wallet_dart  <你的仓库>/packages/agora_wallet

# 2) 在 App 的 pubspec.yaml 里加路径依赖
```
```yaml
dependencies:
  flutter:
    sdk: flutter
  agora_wallet:
    path: packages/agora_wallet        # 相对你的 App 根目录
```
```bash
flutter pub get
```
```dart
import 'package:agora_wallet/agora_wallet.dart';   // 唯一的 import

final client = AgoraHttpClient(
  [const AgoraNode('http://192.168.1.10:8645', label: '本机节点')],
  config: const AgoraClientConfig(
    expectedChainId: 'agora-testnet-1',
    expectedGenesisHash: '0x56c6819f…',   // wallet/genesis.testnet.json 里的值
  ),
);
final repo = WalletRepository(api: AgoraApi(client));
final acc  = await repo.account('0x56f1…');
print(displayBalance(acc.balanceAtom));   // "110.2507 AGORA"
```

它是**纯 Dart 包**（零第三方依赖、不含 Flutter 依赖），所以：

* 任何状态管理方案都能用（setState / Provider / Riverpod / Bloc 都行）；
* 桌面端与命令行也能用（`dart run example/cli_demo.dart`）；
* **Flutter Web 不行**（用了 `dart:io`），见第 5 节。

---

## 1. 两种移植方式，怎么选

| 方式 | 适合 | 代价 |
|---|---|---|
| **A. 路径依赖（推荐）** | 你会持续跟上游更新；团队多人协作 | 多一个目录，需在 `pubspec.yaml` 声明 |
| **B. 直接把 `lib/` 拷进 App** | 你只想要这一份代码、不打算更新 | 必须改 import：`package:agora_wallet/agora_wallet.dart` → 相对路径；以后升级要手工合并 |

**方式 A 的分包建议**：把 `packages/agora_wallet/` 放在你自己的仓库里（不要引用我这里的绝对路径），
这样 CI 与同事克隆都能跑。

**方式 B 的注意事项**（很容易踩）：

```dart
// 原：import 'package:agora_wallet/agora_wallet.dart';
import 'wallet/agora_wallet.dart';          // 改成你项目内的相对路径
```
然后 `lib/src/*.dart` 里的相对 import（`import 'amount.dart';` 这类）**不用改**（它们本来就是相对的）。
`tool/selftest.dart` 与 `example/cli_demo.dart` 用的是 `package:` 形式，如果你保留它们要一并改。

---

## 2. 最小可用接线（一个页面）

```dart
// lib/agora_service.dart —— 全 App 只创建**一份** client（连接池与故障转移都在它里面）
import 'package:agora_wallet/agora_wallet.dart';

class AgoraService {
  AgoraService._(this.client, this.repo);

  final AgoraHttpClient client;
  final WalletRepository repo;

  factory AgoraService.production() {
    final client = AgoraHttpClient(
      const [
        AgoraNode('http://192.168.1.10:8645', label: '主节点'),
        AgoraNode('http://192.168.1.11:8645', label: '备用节点'),   // 多填几个更稳
      ],
      config: const AgoraClientConfig(
        expectedChainId: 'agora-testnet-1',
        expectedGenesisHash: '0x56c6819fe377e54e142cf15add68fa600c322e976ca27f3d973c31f95d2060bc',
        timeout: Duration(seconds: 8),
      ),
    );
    return AgoraService._(client, WalletRepository(api: AgoraApi(client)));
  }

  void dispose() {
    repo.dispose();
    client.close();
  }
}
```

> ⚠ **不要在每次 `build()` 或每个页面里 `new` 一个 `AgoraHttpClient`**：
> 每个实例自带连接池；反复创建会导致连接泄漏与"偶发超时"。

---

## 3. 在界面上用（StreamBuilder）

余额与高度是**持续变化**的数据，用仓库的 `watch*` 流最省事：

```dart
class BalanceCard extends StatefulWidget {
  const BalanceCard({super.key, required this.svc, required this.address});
  final AgoraService svc;
  final String address;
  @override
  State<BalanceCard> createState() => _BalanceCardState();
}

class _BalanceCardState extends State<BalanceCard> {
  late Stream<AccountState> _stream;

  @override
  void initState() {
    super.initState();
    _stream = widget.svc.repo.watchAccount(widget.address);
  }

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<AccountState>(
      stream: _stream,
      builder: (context, snap) {
        // ① 有数据就显示（即使正在重试，也**保留上一次的数据**，不要闪成空白）
        final acc = snap.data;
        if (acc != null) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(displayBalance(acc.balanceAtom),        // "110.2507 AGORA"
                  style: Theme.of(context).textTheme.headlineMedium),
              Text('高度 ${acc.envelope.height} · nonce ${acc.nonce}',
                  style: Theme.of(context).textTheme.bodySmall),
            ],
          );
        }
        // ② 还没有任何数据：区分"正在连"与"出错了"
        if (snap.hasError) return _errorWidget(context, snap.error!);
        return const Center(child: CircularProgressIndicator());
      },
    );
  }

  Widget _errorWidget(BuildContext context, Object e) {
    // 错误分类直接决定提示语，别用一句"加载失败"糊过去
    if (e is AgoraChainMismatchException) {
      return Text('当前节点不是目标链，已拒绝使用其数据\n${e.reason}');
    }
    if (e is AgoraTransportException) {
      return const Text('网络异常，正在自动重试…');   // 流不会关闭，恢复后自动继续
    }
    if (e is AgoraApiException && e.isNotFound) {
      return const Text('该地址暂无记录');
    }
    return Text('数据异常：$e');
  }
}
```

**要点**：`watch*` 在出错时**只发一个错误事件、不结束流**（已用测试钉住），
所以界面写法是"有错误事件也继续等下一次" —— 不要 `snap.hasError` 就 `return` 空页面，
那样网络恢复后用户还得手动重进。

---

## 4. 三处平台配置（不吃这一次亏就会吃第二次）

### 4.1 Android

**① INTERNET 权限**：Flutter 模板只在 `debug`/`profile` 的 manifest 里加了它，
**release 包会没有**，表现为"调试正常、上线全连不上"。在
`android/app/src/main/AndroidManifest.xml` 里显式加上：

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET"/>   <!-- ← 加这行 -->
    <application ...>
```

**② 明文 HTTP**：Android 9（API 28）起默认**禁止** `http://`（只允许 https）。
测试网节点通常是内网 `http://192.168.x.x:8645`，所以要么全局放行（仅开发用）：

```xml
<application
    android:usesCleartextTraffic="true"   <!-- 仅开发/内网；上线请换成下面的白名单 -->
    ... >
```

要么更稳妥地做白名单（推荐，避免上线时整包放行）：

```xml
<!-- android/app/src/main/res/xml/network_security_config.xml -->
<network-security-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">192.168.1.10</domain>
  </domain-config>
</network-security-config>
```
```xml
<!-- AndroidManifest.xml 的 <application> 上引用它 -->
<application android:networkSecurityConfig="@xml/network_security_config" ... >
```

### 4.2 iOS

ATS 默认禁止明文 HTTP。内网联调时在 `ios/Runner/Info.plist` 里加：

```xml
<key>NSAppTransportSecurity</key>
<dict>
  <!-- 允许访问本机/局域网地址（比 NSAllowsArbitraryLoads 更收敛） -->
  <key>NSAllowsLocalNetworking</key><true/>
</dict>
```

若节点在公网（且你还没上 TLS），才需要 `NSAllowsArbitraryLoads`；**上线前务必换回 https**。

### 4.3 真机连不上？先按这个顺序查

1. 手机与节点**是否同一网段**（4G 下连内网 IP 必然不通）；
2. 节点是否对外监听：默认只绑 `127.0.0.1`，要加 `--rpc-bind 0.0.0.0`
   （并在日志里确认它打印了"⚠ 已对外绑定"）；
3. 电脑防火墙是否放行该端口；
4. 用手机浏览器打开 `http://<节点IP>:8645/healthz` —— 能看到 `{"ok":true}` 就说明网络没问题，
   问题在 App 侧（多半是第 4.1/4.2 节的配置）；
5. 报 `AgoraChainMismatchException` ⇒ 连到了别的链（不是网络问题）。

---

## 5. Flutter Web 怎么办

本包用 `dart:io` 的 `HttpClient`，**Web 上编译不过**。要支持 Web，只需替换传输层
（其余代码——模型、仓库、错误分类——都与传输实现解耦）：

1. `pubspec.yaml` 加 `http: ^1.2.0`；
2. 复制 `lib/src/http_client.dart` 为 `http_client_web.dart`，把 `HttpClient` 调用换成
   `package:http` 的 `Client.get/post`，**保持两个方法的语义不变**：
   * `Future<AgoraResponse> getJson(String path, {Map<String,String>? query})`
   * `Future<AgoraResponse> postJson(String path, Map<String,dynamic> body)`
   * 非 2xx 时抛 `AgoraApiException(statusCode, code, message, detail, path)`；
   * 成功时先做**链身份校验**（`_checkChainIdentity` 的逻辑照搬）。
3. 用条件导入选择实现：
   ```dart
   export 'src/http_client_io.dart'
       if (dart.library.js_interop) 'src/http_client_web.dart';
   ```

---

## 6. 移植后的验收清单（照做即可）

```bash
# ① 静态检查必须干净
flutter analyze

# ② 保持 tool/selftest.dart 在项目里，对着你的节点跑一次（48 项）
#    它同时验证"纯函数"与"真实取数"，是移植是否成功的唯一客观判据
dart run tool/selftest.dart http://<你的节点>:8645

# ③ 示例程序跑一遍，肉眼过一遍输出
dart run example/cli_demo.dart http://<你的节点>:8645
```

CLI 没问题、App 里连不上 ⇒ 一定是第 4 节的平台配置，不是代码。

---

## 6b. 省电：App 退到后台时应当暂停轮询

`watch*` 是一个自驱的定时轮询（默认 5 秒一次）。App 退到后台后如果不停，
手机会持续联网取数 —— 对钱包来说这是可观察的电量与流量浪费。
标准做法是用 `WidgetsBindingObserver` 在不可见时取消订阅、回到前台再订阅：

```dart
class _BalanceCardState extends State<BalanceCard> with WidgetsBindingObserver {
  StreamSubscription<AccountState>? _sub;
  AccountState? _acc;
  Object? _err;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _resubscribe();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState s) {
    if (s == AppLifecycleState.resumed) {
      _resubscribe();                       // 回前台：重新订阅（会立刻拉一次）
    } else {
      _sub?.cancel();                       // 退后台：停止轮询
      _sub = null;
    }
  }

  void _resubscribe() {
    if (_sub != null) return;
    _sub = widget.svc.repo.watchAccount(widget.address).listen(
      (a) => setState(() { _acc = a; _err = null; }),
      onError: (Object e) => setState(() => _err = e),
    );
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _sub?.cancel();
    super.dispose();
  }
}
```

（`_acc`/`_err` 用字段保存而不是 `StreamBuilder`，就是因为"退后台取消订阅"之后
`StreamBuilder` 会丢掉 `snapshot.data`，界面会闪成空白。）

---

## 7. 写业务时最容易犯的三个错

1. **把金额转成 `double`**。`displayBalance()` 只用于显示；任何计算（转账金额、手续费、
   余额比较）都必须留在 `BigInt` 上。用户输入用 `parseAgoraToAtom('1.5')`，
   它会拒绝超过 18 位小数与负号 —— 别自己写 `double.parse`。
2. **用缓存里的 `nonce` 直接发交易**。转账前必须
   `await repo.account(addr, refresh: true)` 重新取一次：
   `nonce` 与余额是写操作的前置条件，用缓存值会被链上按 §16.4.2 第 9 项拒绝。
3. **把"受理"当成"上链"**。`submitRawTx` 返回 202 只表示节点已受理并转发；
   必须再查 `GET /v1/tx/{hash}`，确认 `found=true` 且拿到回执，
   才能显示"转账成功"（否则用户会以为钱已经到账）。

---

## 8. 还缺什么（要真正"转账"的完整路径）

| 环节 | 现状 |
|---|---|
| 取数（余额/nonce/区块/回执/空投/验证者） | ✅ 本包已可用 |
| 链身份防护 | ✅ `expectedChainId` + `expectedGenesisHash` |
| 交易签名（RLP + Keccak-256 + Ed25519） | ✅ **已实现**（`lib/src/crypto/`、`lib/src/tx/`）：与 `TXBLOCK` 黄金向量**逐字节一致**，且"用同一种子重签"得到与 Python 完全相同的 64 字节签名；RFC 8032 TEST 1 通过 |
| 交易进块（交易池 + 广播 + 打包） | ✅ **已实现**（规范 §16.5）：`POST /v1/tx` 返回 202，实测 0.5 秒进块、四节点同高度哈希一致 |

**两项前置都已完成。** 现在钱包可以完整走通"构造 → 签名 → 提交 → 进块 → 查回执"。

跑一遍端到端（对着运行中的集群）：

```bash
RPC_BASE=8680 bash wallet/run_local_cluster.sh wallet/runs/dev-genesis.json 200 tx 0 \
    wallet/runs/devkeys wallet/runs/tx-dart &
cd mobile/agora_wallet_dart
dart run tool/send_transfer.dart --base-url http://127.0.0.1:8681 \
    --seed-file ../../wallet/runs/devkeys/key1.seed --to 0x5a43… --amount 1.5
```

⚠ 两个"签名侧"的坑（都由向量测试钉住了）：
① `protocol_version_hash` 是 `Keccak("AGORA/v0.2.2")`，**不是** `Keccak(chain_id)`；
② 签名载荷 = `"AGORA/TX/v0.2.2" ‖ CHAIN(chain_id, TxContent)`，**不含签名字段**，
且标签写在 `CHAIN` **之外**。
