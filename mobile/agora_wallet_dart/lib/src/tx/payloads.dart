/// AGORA 钱包 · 各交易类型的**载荷编码**（规范 §16.2 / §32.6）
///
/// 载荷是"类型专属的已编码字节"（`payload` 字段本身也就是 RLP 编码结果），
/// **错一个字节**节点就会在 §16.4.2 第 13 项（类型前置条件）或第 1 项（解码）拒绝，
/// 而报错常常指向别处。因此本文件与 `vectors/agora_v0.2.2_vectors.json` 的
/// `TXPAYLOADS` 族逐字节对齐（见 `lib/src/tx/vector_checks.dart`）。
///
/// 各类型的载荷形式（**这是最容易记错的地方**）：
///
/// | 类型 | 载荷 | 说明 |
/// |---|---|---|
/// | `TRANSFER` | 空 | — |
/// | `BOND` | `RLP(公钥32字节)` = `0xa0‖pubkey` | **不是** `CHAIN(pubkey)` —— CHAIN 是哈希原像编码，其输出通常不是合法 RLP |
/// | `UNBOND` / `REBOND` | `RLP(金额)` = 最小字节串 | 金额按无符号大端最小编码 |
/// | `WITHDRAW` | 空 | 提取全部可提取额 |
/// | `AIRDROP_CLAIM` | `RLP([index, amount, gas_allowance, pubkey, [证明…], 绑定签名])` | 见下 |
/// | `EVIDENCE` | 见规范 §16.3 | **本包未实现**（钱包不提交罚没证据，见文件末尾说明） |
library;

import 'dart:typed_data';

import '../crypto/ed25519.dart';
import '../crypto/keccak.dart';
import '../crypto/rlp.dart';

/// 空投领取载荷（规范 §32.6）。
///
/// ```
/// payload = RLP([ index, amount, gas_allowance, pubkey, [merkle_proof…],
///                 binding_signature ])
/// 绑定签名 = Ed25519( TAG_AIRDROP ‖ CHAIN(chain_id, pubkey, sender, u64(index)) )
/// ```
///
/// 三个要点：
/// 1. `gas_allowance` **必须**带上 —— 它是创世分配表叶子的一部分，缺了就无法重算叶子；
/// 2. `index` 也**必须**是分配表给的那个（叶子含 `u64(index)`，换一个就复现不出叶子）；
/// 3. 绑定签名把"公钥 ↔ 地址 ↔ index"钉在一起（§32.6 第 ③ 项），
///    因此它签的内容里同时有 `pubkey`、`sender` 与 `index`。
class AirdropClaim {
  AirdropClaim({
    required this.index,
    required this.amount,
    required this.gasAllowance,
    required List<int> pubkey,
    required List<String> merkleProof,
    List<int> bindingSignature = const [],
  })  : pubkey = Uint8List.fromList(pubkey),
        merkleProof = List.unmodifiable(merkleProof),
        bindingSignature = Uint8List.fromList(bindingSignature);

  final int index;
  final BigInt amount;
  final BigInt gasAllowance;
  final Uint8List pubkey;

  /// Merkle 证明节点（每个 32 字节，`0x` 前缀十六进制）。
  final List<String> merkleProof;
  final Uint8List bindingSignature;

  /// 绑定签名的载荷（§32.6 第 ③ 项）。
  static Uint8List bindingMessage(
      List<int> chainId, List<int> pubkey, List<int> sender, int index) {
    final tag = Uint8List.fromList('AGORA/AIRDROP/v0.2.2'.codeUnits);
    return Uint8List.fromList([
      ...tag,
      ...chain([
        ChainField.bytes(Uint8List.fromList(chainId)),
        ChainField.bytes(Uint8List.fromList(pubkey)),   // 32 字节：原样
        ChainField.bytes(Uint8List.fromList(sender)),   // 20 字节：原样
        ChainField.u('u64', BigInt.from(index)),
      ]),
    ]);
  }

  /// 用私钥生成绑定签名，返回**已绑定**的新载荷。
  Future<AirdropClaim> bind(List<int> seed, List<int> chainId,
      List<int> sender) async {
    final msg = bindingMessage(chainId, pubkey, sender, index);
    final sig = await ed25519Sign(seed, msg);
    return AirdropClaim(
      index: index,
      amount: amount,
      gasAllowance: gasAllowance,
      pubkey: pubkey,
      merkleProof: merkleProof,
      bindingSignature: sig,
    );
  }

  /// 校验绑定签名（本地自检，省一次被节点拒绝的往返）。
  Future<bool> verifyBinding(List<int> chainId, List<int> sender) async {
    if (bindingSignature.length != 64) return false;
    return ed25519Verify(
        pubkey, bindingMessage(chainId, pubkey, sender, index), bindingSignature);
  }

  /// `RLP([index, amount, gas_allowance, pubkey, [证明…], 绑定签名])`。
  Uint8List toRlp() => rlpEncode([
        index,
        amount,
        gasAllowance,
        pubkey,
        merkleProof.map(hexToBytes).toList(growable: false),
        bindingSignature,
      ]);

  bool get isBound => bindingSignature.length == 64;
}

/// 载荷构造器（每种交易类型一个入口，集中在一处避免各写一份）。
class AgoraPayloads {
  /// `TRANSFER`：无载荷。
  static Uint8List transfer() => Uint8List(0);

  /// `BOND`：`RLP(公钥)`。
  ///
  /// 注意：这里编码的是 **32 字节公钥本身**（`RLP` 会加上 `0xa0` 前缀），
  /// 而不是 `CHAIN(pubkey)` —— 后者是哈希原像编码，通常不是合法 RLP，
  /// 节点会报"尾随字节"这类看起来莫名其妙的错。
  static Uint8List bond(List<int> validatorPubkey) {
    if (validatorPubkey.length != 32) {
      throw ArgumentError('BOND 的验证者公钥必须为 32 字节');
    }
    return rlpEncode(validatorPubkey);
  }

  /// `UNBOND` / `REBOND`：`RLP(金额)`（无符号大端最小字节串）。
  static Uint8List amount(BigInt value) {
    if (value <= BigInt.zero) {
      throw ArgumentError('解绑/复投金额必须为正');
    }
    return rlpEncode(value);
  }

  /// `WITHDRAW`：无载荷（提取当前可提取的全部）。
  static Uint8List withdraw() => Uint8List(0);

  /// `AIRDROP_CLAIM`：见 [AirdropClaim]。
  static Uint8List airdropClaim(AirdropClaim claim) => claim.toRlp();

  /// `EVIDENCE`：**本包不提供构造**。
  ///
  /// 理由（如实说明）：罚没证据是"举报他人作恶"的机制，需要把两条互相冲突的
  /// 已签名投票打包成 `Evidence` 对象（规范 §16.3），属于高级/运维功能；
  /// 钱包不应提供普通用户入口（误提交会牵涉他人罚没）。若确实需要，
  /// 照 `AgoraTransaction` 的写法补一个构造器即可，向量族的框架已经在了。
  static Uint8List evidenceUnsupported() => throw UnsupportedError(
      'EVIDENCE 载荷未在本包实现（罚没证据属运维功能，钱包不提供入口）');
}

/// 把十六进制串列表转成字节列表（供 `AirdropClaim.toRlp` 用）。
List<Uint8List> hexListToBytes(List<String> hexes) =>
    hexes.map(hexToBytes).toList(growable: false);
