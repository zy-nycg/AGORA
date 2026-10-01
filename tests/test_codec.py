# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 参考实现 · 编码与密码学测试
==========================================

测试依据：规范 §33.0「强制的基础原语已知答案向量」

本文件覆盖三类**曾经真实出错**的缺陷：
  · Ed25519 群运算坐标形式 / 基点取根错误  → 只有 RFC 8032 向量能发现
  · RLP 长度前缀与解码严格性错误          → 只有边界样本能发现
  · Keccak 原始填充与 SHA-3 填充混淆      → 只有已知摘要能发现

运行：python3 -m tests.test_codec
"""

from __future__ import annotations

import sys

from agora.codec import (
    EMPTY_TRIE_ROOT, RLPDecodeError, decode, encode, MerklePatriciaTrie, secure_key,
)
from agora.crypto import (
    BASE_POINT, CURVE_L, address_from_pubkey, chain, keccak256,
    publickey_from_seed, sign, verify, BASEPOINT_X_EXPECTED,
)

_fail = 0
_pass = 0


def chk(name, cond, detail=""):
    global _fail, _pass
    if cond:
        _pass += 1
        print(f"  [OK  ] {name}" + (f"   {detail}" if detail else ""))
    else:
        _fail += 1
        print(f"  [FAIL] {name}" + (f"   {detail}" if detail else ""))


def test_keccak():
    print("\n1) Keccak-256（规范 §33.0 向量）")
    chk("Keccak256('') 已知摘要",
        keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    chk("Keccak256('abc') 已知摘要",
        keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    chk("与 SHA-3 不同（防填充混淆）",
        keccak256(b"abc").hex() != __import__("hashlib").sha3_256(b"abc").hexdigest())
    chk("输出长度 = 32 字节", len(keccak256(b"agora")) == 32)


def test_ed25519():
    print("\n2) Ed25519（RFC 8032 §7.1 TEST 1）")
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk_expect = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    sig_expect = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                  "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    pk = publickey_from_seed(seed)
    sig = sign(seed, b"")
    chk("公钥与 RFC 8032 一致", pk.hex() == pk_expect)
    chk("签名与 RFC 8032 一致", sig.hex() == sig_expect)
    chk("基点 x = 规范期望值", BASE_POINT[0] == BASEPOINT_X_EXPECTED,
        f"Bx = {BASE_POINT[0]}")
    chk("验证通过", verify(pk, b"", sig))
    chk("篡改消息被拒", not verify(pk, b"x", sig))
    chk("篡改签名被拒", not verify(pk, b"", sig[:-1] + bytes([sig[-1] ^ 1])))
    chk("S >= L 被拒", not verify(pk, b"", sig[:32] + (CURVE_L).to_bytes(32, "little")))
    chk("单位元公钥被拒", not verify(b"\x01" + b"\x00" * 31, b"", sig))
    chk("非规范公钥（y >= p）被拒", not verify(b"\xff" * 32, b"", sig))
    # RFC 8032 TEST 2
    seed2 = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    pk2 = publickey_from_seed(seed2)
    sig2 = sign(seed2, bytes.fromhex("72"))
    chk("RFC 8032 TEST 2 公钥",
        pk2.hex() == "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    chk("RFC 8032 TEST 2 签名验证通过", verify(pk2, bytes.fromhex("72"), sig2))


def test_rlp():
    print("\n3) RLP（规范 §33.0 向量）")
    chk("encode(0) = 80", encode(0) == bytes.fromhex("80"))
    chk("encode(127) = 7f", encode(127) == bytes.fromhex("7f"))
    chk("encode('dog') = 83646f67", encode("dog") == bytes.fromhex("83646f67"))
    chk("encode([1,2,[3]]) = c40102c103", encode([1, 2, [3]]) == bytes.fromhex("c40102c103"))
    long60 = encode(b"x" * 60)
    chk("encode('x'*60) 长形式头 = b83c",
        long60[:2] == bytes.fromhex("b83c") and long60[2:] == b"x" * 60)
    chk("encode(b'') = 80", encode(b"") == bytes.fromhex("80"))
    big = encode(2 ** 256 - 1)
    chk("encode(u256 最大值) 可往返", decode(big) == b"\xff" * 32)
    # 互逆性（规范 §33.0 强制）
    for v in (0, 1, 127, 128, 255, 65535, 2 ** 64 - 1):
        assert decode(encode(v)) == (b"" if v == 0 else v.to_bytes((v.bit_length() + 7) // 8, "big"))
    chk("decode(encode(x)) 对整数往返恒等", True)
    chk("解码器返回字节串（非整数）", decode(bytes.fromhex("7f")) == b"\x7f")
    # 结构层的非规范编码：解码器必须拒绝
    for bad, why in ((b"\xb8\x01\x41", "长形式编码短负载"),
                     (b"\x81\x80\x00", "尾随字节"),
                     (b"\xc3\x01\x02", "列表长度声明超出实际内容"),
                     (b"\xc2\x01", "列表内容不足声明长度")):
        try:
            decode(bad)
            chk(f"拒绝：{why}", False, f"未拒绝 {bad.hex()}")
        except RLPDecodeError:
            chk(f"拒绝：{why}", True)

    # 整数层的非规范编码（BUG-29 / BUG-49）：**解码器不拒绝**（它不掌握 schema，
    # 无法区分整数字段与字节串字段），由 require_canonical_int 在解释为整数时拒绝。
    # 这一点至关重要：地址 0x00…00、32 字节哈希等合法字节串都可能以 0x00 开头。
    from agora.codec import require_canonical_int
    for bad, why in ((b"\x81\x00", "单字节整数加长度前缀（编码为 81 00）"),
                     (b"\x82\x00\x7f", "整数前导零（编码为 82 00 7f）")):
        raw = decode(bad)                      # 结构合法 ⇒ 解码通过
        chk(f"解码器接受（结构合法）：{why}", raw == (b"\x00" if len(bad) == 2 else b"\x00\x7f"))
        try:
            require_canonical_int(raw, "测试字段")
            chk(f"整数解释时拒绝：{why}", False, f"未拒绝 {bad.hex()}")
        except RLPDecodeError:
            chk(f"整数解释时拒绝：{why}", True)
    # 合法字节串即便是 0x00 开头也必须解码成功（防止过度严格——这正是 BUG-49）
    chk("接受以 0x00 开头的合法字节串（地址/哈希）",
        decode(encode(b"\x00" * 20)) == b"\x00" * 20)
    chk("最小字节串整数解释正常",
        require_canonical_int(decode(encode(12345))) == 12345)
    chk("零的规范编码是空串",
        require_canonical_int(decode(encode(0))) == 0)
    # 这些是【合法】编码，必须接受（防止过度严格）
    for good, why in ((b"\xc1\xc0", "列表内含空列表"),
                      (b"\xc0", "空列表"),
                      (b"\x80", "空串"),
                      (b"\xc2\x80\x80", "含两个空串的列表")):
        try:
            decode(good)
            chk(f"接受合法编码：{why}", True)
        except RLPDecodeError as e:
            chk(f"接受合法编码：{why}", False, str(e))


def _str_rejected() -> bool:
    try:
        chain("AGORA/TX/v0.2.2")
        return False
    except TypeError:
        return True


def test_chain():
    print("\n4) CHAIN 原像编码（规范 §20.1）")
    chk("定宽整数：1 字节", chain(1) == b"\x01")
    chk("定宽整数：u64", chain(2 ** 40) == (2 ** 40).to_bytes(8, "big"))
    chk("20 字节地址原样（无长度前缀）", chain(b"\xaa" * 20) == b"\xaa" * 20)
    chk("32 字节哈希原样（无长度前缀）", chain(b"\xbb" * 32) == b"\xbb" * 32)
    chk("变长字节串加 u32 长度前缀", chain(b"abc") == (3).to_bytes(4, "big") + b"abc")
    chk("标签以 bytes 传入时按普通字节串加 u32 前缀（故标签须写在 chain 之外）",
        chain(b"AGORA/TX/v0.2.2") == len(b"AGORA/TX/v0.2.2").to_bytes(4, "big")
        + b"AGORA/TX/v0.2.2")
    chk("str 参数已被禁止（防止标签处理不一致）", _str_rejected())
    chk("字段顺序敏感", chain(1, 2) != chain(2, 1))
    chk("CHAIN 与 RLP 不同（禁止混用）", chain(b"abc") != encode(b"abc"))
    try:
        chain(-1)
        chk("拒绝负整数", False)
    except ValueError:
        chk("拒绝负整数", True)


def test_address():
    print("\n5) 地址（规范 §3）")
    seed = bytes(range(32))
    pk = publickey_from_seed(seed)
    addr = address_from_pubkey(pk)
    chk("地址长度 20 字节", len(addr) == 20)
    chk("地址 = Keccak(pubkey) 末 20 字节", addr == keccak256(pk)[-20:])
    chk("公钥-地址绑定可校验", address_from_pubkey(pk) == addr)
    chk("不同公钥得到不同地址", address_from_pubkey(publickey_from_seed(bytes(32))) != addr)


def test_mpt():
    print("\n6) MPT 状态根（规范 §19.1）")
    chk("空 trie 根 = Keccak(RLP(''))", MerklePatriciaTrie().root == EMPTY_TRIE_ROOT)
    chk("空 trie 根已知值",
        EMPTY_TRIE_ROOT.hex() == "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
    # 键集合相同 -> 根相同（与插入顺序无关）
    items = [(bytes([i]) * 20, b"value-%d" % i) for i in range(50)]
    t1 = MerklePatriciaTrie.from_items(items)
    t2 = MerklePatriciaTrie.from_items(list(reversed(items)))
    chk("同一键值集合的根与插入顺序无关", t1.root == t2.root, f"root = {t1.root.hex()[:16]}…")
    # 单键
    t3 = MerklePatriciaTrie()
    t3.put(bytes(20), b"v")
    chk("单键 trie 根非空且稳定", t3.root != EMPTY_TRIE_ROOT and t3.get(bytes(20)) == b"v")
    # 读写与删除
    t4 = MerklePatriciaTrie.from_items(items)
    for k, v in items:
        assert t4.get(k) == v, k
    chk("全部键可读回", True)
    for k, _ in items[:20]:
        t4.delete_raw_hashed(secure_key(k))
    for k, _ in items[:20]:
        assert t4.get(k) is None
    for k, v in items[20:]:
        assert t4.get(k) == v
    chk("删除后其余键完好", True)
    t5 = MerklePatriciaTrie.from_items(items[20:])
    chk("删除 20 个键后与直接构建等价", t4.root == t5.root)
    # 值变化 -> 根变化
    items2 = list(items)
    items2[0] = (items2[0][0], b"changed")
    chk("值变化导致根变化", MerklePatriciaTrie.from_items(items2).root != t1.root)
    # 导出可往返（必须用 from_hashed_items：导出项是已哈希键）
    chk("items() 导出可重建同一根",
        MerklePatriciaTrie.from_hashed_items(t1.items()).root == t1.root)
    chk("误用 from_items 重建会得到不同的根（防二次哈希陷阱）",
        MerklePatriciaTrie.from_items(t1.items()).root != t1.root)


# ── N. MPT 规范化（BUG-65 回归）────────────────────────────────────

def test_mpt_canonical():
    """BUG-65 回归：状态根 **MUST** 只取决于键值集合，且树中 **MUST NOT**
    出现非规范节点（空路径扩展、单子分支）。

    **为什么必须用 20/50 叶这样的普通规模测试：** 该缺陷在 ≤10 叶时完全不出现
    （实测 5/10 叶的空扩展数为 0，20 叶起为 1–2）。只测小规模的用例会给出
    虚假的安全感 —— 这正是它长期未被发现的原因。
    """
    print("\nN) MPT 规范化（BUG-65 回归）")
    import random
    from agora.codec import MerklePatriciaTrie, _deref

    def scan_noncanonical(node, path="", depth=0):
        """返回树中的非规范节点列表。"""
        bad = []
        if node is None or depth > 40:
            return bad
        kind = node[0]
        if kind == "leaf":
            if len(node[1]) == 0:
                bad.append(f"{path}: 空路径叶")
        elif kind == "ext":
            if len(node[1]) == 0:
                bad.append(f"{path}: 空路径扩展")
            bad += scan_noncanonical(_deref(node[2]), path + "E", depth + 1)
        else:
            kids = [i for i, c in enumerate(node[1]) if c is not None]
            if len(kids) == 1 and not node[2]:
                bad.append(f"{path}: 单子分支（应塌缩）")
            for i, c in enumerate(node[1]):
                if c is not None:
                    bad += scan_noncanonical(_deref(c), path + format(i, "x"), depth + 1)
        return bad

    for n in (5, 10, 20, 50):
        items = [(bytes([i % 256]) * 20, b"value-%d" % i) for i in range(n)]
        t = MerklePatriciaTrie.from_items(items)
        # 检查**规范化后**的树 —— 它才是决定状态根的那棵树。
        # 增量插入过程中可能短暂存在非规范中间节点（规范化是**按需 + 记忆化**的，
        # 见 `codec._canonical`），但只要"对外可观测的形态"是规范的，跨实现一致
        # 就有保证。断言点必须对准可观测形态，否则会误报（本次即如此）。
        _ = t.root
        bad = scan_noncanonical(t._root)
        chk(f"{n} 叶：树中无非规范节点（空扩展 / 单子分支）", not bad,
            "; ".join(bad[:3]))

    # 插入顺序无关（20 与 50 叶，各 30 次乱序）
    for n in (20, 50):
        items = [(bytes([i % 256]) * 20, b"value-%d" % i) for i in range(n)]
        base = MerklePatriciaTrie.from_items(items).root
        diffs = 0
        for trial in range(30):
            sh = items[:]
            random.Random(trial).shuffle(sh)
            if MerklePatriciaTrie.from_items(sh).root != base:
                diffs += 1
        chk(f"{n} 叶：30 次乱序得到同一根", diffs == 0, f"不同根 {diffs} 次")

    # 插入→删除→再插入 必须回到同一根（删除路径与写入路径的塌缩规则一致）
    items = [(bytes([i % 256]) * 20, b"value-%d" % i) for i in range(30)]
    t_plain = MerklePatriciaTrie.from_items(items)
    t_churn = MerklePatriciaTrie()
    for k, v in items:
        t_churn.put(k, v)
    for k, _ in items[:15]:                     # 删掉一半再放回
        t_churn.delete_raw_hashed(secure_key(k))
    for k, v in items[:15]:
        t_churn.put(k, v)
    chk("插入→删除→再插入 回到同一根（读写路径塌缩规则一致）",
        t_churn.root == t_plain.root,
        f"{t_churn.root.hex()[:16]}… vs {t_plain.root.hex()[:16]}…")

    # 全部删除后必须回到空 trie 根
    t_empty = MerklePatriciaTrie.from_items(items)
    for k, _ in items:
        t_empty.delete_raw_hashed(secure_key(k))
    chk("全部删除后回到空 trie 根",
        t_empty.root == EMPTY_TRIE_ROOT, t_empty.root.hex()[:16] + "…")


def main():
    print("═" * 72)
    print("AGORA v0.2.2 参考实现 · 编码与密码学测试")
    print("═" * 72)
    test_keccak()
    test_ed25519()
    test_rlp()
    test_chain()
    test_address()
    test_mpt()
    test_mpt_canonical()
    print("\n" + "═" * 72)
    print(f"通过 {_pass} 项，失败 {_fail} 项")
    print("结果：" + ("全部通过 ✅" if _fail == 0 else "★ 存在失败"))
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
