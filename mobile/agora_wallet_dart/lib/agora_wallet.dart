/// AGORA 钱包 · Dart 数据层（`library agora_wallet`）
///
/// 用法（三步）
/// ------------
/// ```dart
/// import 'package:agora_wallet/agora_wallet.dart';
///
/// final client = AgoraHttpClient(
///   [const AgoraNode('http://192.168.1.10:8645', label: '本机节点')],
///   config: const AgoraClientConfig(
///     expectedChainId: 'agora-testnet-1',
///     expectedGenesisHash: '0x56c6819f…',   // 从创世文件抄，别猜
///   ),
/// );
/// final repo = WalletRepository(api: AgoraApi(client));
///
/// final st = await repo.status(refresh: true);          // 高度/链头/当前槽
/// final acc = await repo.account('0x56f1…');            // 余额 + nonce
/// print('${displayBalance(acc.balanceAtom)}  nonce=${acc.nonce}');
///
/// await for (final a in repo.watchAccount('0x56f1…')) {  // 界面持续刷新
///   print('余额 ${displayBalance(a.balanceAtom)}');
/// }
/// ```
///
/// 这个包**只负责取数与校验**，不负责：
/// * 私钥保管与签名（请放在你的安全模块/`flutter_secure_storage` 里）；
/// * 交易构造与 RLP 编码（需要 Keccak-256 与 Ed25519，见 README 的"下一步"）。
///
/// 取数纪律（三条，都是真金白银的教训）
/// ------------------------------------
/// 1. **金额永远是 [BigInt]**：节点把 `*_atom` 当十进制字符串返回，
///    因为 1 AGORA = 10^18 atom，用 `double` 解析会静默丢精度（见 `amount.dart`）；
/// 2. **链身份强制核对**：`expectedChainId` / `expectedGenesisHash` 不符即抛异常，
///    避免"连到另一条链却显示 0 余额"；
/// 3. **绝不静默兜底**：缺字段、类型不对一律抛 [AgoraParseException]，
///    而不是给一个 0 —— 把解析失败伪装成"余额 0"是钱包最危险的行为。
library;

export 'src/agora_api.dart' show AgoraApi, TxSubmitResult;
export 'src/amount.dart'
    show
        addressBytes,
        atomPerAgora,
        formatAgora,
        hashBytes,
        isPlausibleAddress,
        normalizeAddress,
        normalizeHash,
        parseAgoraToAtom,
        parseAtom;
export 'src/errors.dart'
    show
        AgoraApiException,
        AgoraChainMismatchException,
        AgoraException,
        AgoraParseException,
        AgoraStaleDataException,
        AgoraTransportException;
export 'src/http_client.dart'
    show AgoraClientConfig, AgoraHttpClient, AgoraNode, AgoraResponse;
export 'src/models.dart';
// ── 交易构造与签名（`docs/FLUTTER_INTEGRATION.md` 的"下一步"在此落地）──
export 'src/crypto/ed25519.dart' show ed25519PublicKey, ed25519Sign, ed25519Verify;
export 'src/crypto/keccak.dart'
    show ChainField, chain, chainWidths, keccak256;
export 'src/crypto/rlp.dart'
    show RlpException, bytesToHex, bytesToHex0x, hexToBytes, rlpEncode;
export 'src/tx/payloads.dart' show AgoraPayloads, AirdropClaim, hexListToBytes;
export 'src/tx/transaction.dart'
    show AgoraTransaction, AgoraTxType, agoraProtocolVersion, tagTx;
export 'src/wallet_repository.dart'
    show Cached, PollConfig, WalletRepository, displayBalance;
