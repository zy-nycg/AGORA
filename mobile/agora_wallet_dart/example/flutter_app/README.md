# AGORA 钱包 · Flutter 示例

演示如何把 `agora_wallet` 数据层接进一个 Flutter App。

```bash
cd example/flutter_app
flutter pub get
flutter analyze          # 应无 issue
flutter run              # 真机/模拟器；先按 docs/FLUTTER_INTEGRATION.md 配好网络权限
```

示例里能做什么：导入种子 → 看余额/nonce（轮询刷新）→ 转一笔 AGORA →
查询并领取空投（含两处签名）→ 查看链参数。

**逻辑全在包里**：本目录的 `main.dart` 只做"渲染 + 转发输入 + 把错误翻译成人话"。
链上逻辑（取数的链身份校验、金额的 BigInt 处理、RLP/Keccak/Ed25519 签名、
提交与回执查询）都在 `agora_wallet` 中，那部分有 70+ 项自检与黄金向量逐字节对齐。

⚠ 两点必须自己改掉才能上生产：

1. **私钥**：示例把种子放在内存变量里。真实 App 必须用 `flutter_secure_storage`
   （Keychain / Keystore），并且不要把助记词直接当种子用（应先经 KDF 派生 32 字节）；
2. **网络配置**：Android 需要 `INTERNET` 权限（release manifest 也要有！）
   并且 Android 9+ 默认禁止明文 `http://`；iOS 需要 ATS 例外。
   见 `docs/FLUTTER_INTEGRATION.md` 第 4 节。
