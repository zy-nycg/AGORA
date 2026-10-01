# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 名字↔连接的**签名握手**（规范 §6.7）
====================================================

要解决的问题
------------
帧头里的"发送者名"是对端**自述**的。此前实现只把它与本节点的对端表比对，
因此一个能连上端口的进程只要**冒用对端表内的名字**，就能以该名字投递消息
（消息内容仍受签名与 §22 约束，无法据此伪造区块，但它足以做垃圾投递、
污染日志与"谁在说话"的判断）。规范 §6.7 把这一点登记为**主网前必须补齐**的项。

握手做什么
----------
每次建立 TCP 连接时，双方都要**证明自己持有某个 Ed25519 私钥**，并把这个
密钥与"自述名字"绑定到**这一条连接**上。此后该连接上的所有帧，其自述名字
**必须**等于握手绑定的名字，否则丢弃。于是"名字"从一个可任意自述的字符串，
变成"必须由私钥持有者证明"的身份。

三方消息（**每次连接一轮**）

```
I ──HELLO( name_i, pubkey_i, nonce_i )──────────────────────────────► R
     不签名：此时还没有任何可验证的材料（它的作用只是开启挑战）

I ◄─CHALLENGE( name_r, pubkey_r, nonce_r, sig_r )────────────────── R
     sig_r = Sign(sk_r, 原像(角色=2, name_r, pubkey_r, nonce_i, nonce_r))

I ──AUTH( sig_i )──────────────────────────────────────────────────► R
     sig_i = Sign(sk_i, 原像(角色=3, name_i, pubkey_i, nonce_i, nonce_r))
```

原像（**MUST**，独立实现据此校验）

```
原像 = TAG_HANDSHAKE ‖ CHAIN( chain_id, u8(role), utf8(name), pubkey, nonce_i, nonce_r )

TAG_HANDSHAKE = "AGORA/HANDSHAKE/v0.2.2"        # ASCII，**前置在 CHAIN 之外**（§20.1）
role          = 2（CHALLENGE）或 3（AUTH）        # 域分隔：两种签名不可互换
utf8(name)    = CHAIN 的 bytes 规则：u32(len) ‖ name（长度 20/32 时原样的例外**不适用**
                —— 名字按普通 bytes 处理，见 §20.1 的"除非恰为 20 或 32 字节"）
chain_id      = 链身份字节，按 §20.1 的 bytes 规则：20/32 字节**原样**，
                其余长度加 `u32(len)` 前缀（`agora-testnet-1` 为 15 字节 ⇒ 带前缀）
pubkey        = 32 字节，原样
nonce_i/nonce_r = 各 32 字节，原样，**顺序恒为（发起方, 响应方）**
```

为什么两个 nonce 都要签名、且顺序固定：

* `nonce_i` 让响应方能确认"这次挑战确实是针对本次连接"（否则一段录下来的
  CHALLENGE 可以被重放给另一个发起者）；
* `nonce_r` 让发起方能确认"对端是**现在**活的"（否则一段录下来的 AUTH 可以被
  重放给另一个响应方）；
* 两者都进签名 ⇒ 任一边的旧消息在新连接上都验不过（**无需**维护重放窗口）；
* 角色字节让 CHALLENGE 与 AUTH 的签名**不可互换**（否则可以把 AUTH 当 CHALLENGE 回送，
  形成反射攻击）。

未配置身份时的行为（**仅供本机联调，生产 MUST NOT 依赖**）
---------------------------------------------------------
`pubkey` 全零 = "无身份"。此时握手仍会进行，但对端只能得到"**未验证**"这一结论：
本实现把它计入 `unverified_conns` 并在收尾时打印；`strict_identity=True` 时
**直接拒绝**该连接。运行器 `tools/agora_run_node.py` 默认 `strict`，
并强制要求每个 `--peer` 都给出公钥。
"""

from __future__ import annotations

from typing import Optional

# **MUST** 走 `crypto_backend`（BUG-61）：直接从纯 Python 实现导入会绕过
# C 后端接线，使生产路径静默退回纯 Python（守卫测试会扫描本目录里的导入语句，
# 因此连注释里也不能出现那种写法）。
from .crypto_backend import chain, keccak256, sign, verify

# 域标签（前置在 CHAIN 之外，§20.1）
TAG_HANDSHAKE: bytes = b"AGORA/HANDSHAKE/v0.2.2"

ROLE_CHALLENGE: int = 2
ROLE_AUTH: int = 3

NONCE_LEN: int = 32
PUBKEY_LEN: int = 32
SIG_LEN: int = 64

# "无身份"哨兵：全零公钥 / 全零签名。**必须在规范里写明**，
# 否则独立实现会把它们当作格式错误（而不是"未验证"）。
NIL_PUBKEY: bytes = bytes(PUBKEY_LEN)
NIL_SIG: bytes = bytes(SIG_LEN)


class HandshakeError(Exception):
    """握手失败（消息格式错、公钥不符、签名无效、对端未配置身份等）。"""


def handshake_payload(role: int, chain_id: bytes, name: str,
                      pubkey: bytes, nonce_i: bytes,
                      nonce_r: bytes) -> bytes:
    """握手签名原像（规范 §6.7，`MUST` 的唯一实现）。

    宽度**必须**显式声明（§20.1，BUG-64 的教训）：`u8(role)`；
    `pubkey` 为 32 字节 ⇒ 按 CHAIN 规则**原样**；`chain_id` 按同一 bytes 规则
    （20/32 字节原样，其余长度加 `u32(len)` 前缀）；
    `name` 为普通 bytes ⇒ `u32(len) ‖ name`。
    """
    if role not in (ROLE_CHALLENGE, ROLE_AUTH):
        raise HandshakeError(f"未知握手角色：{role}")
    # ⚠ `chain_id` **不是**定宽字段：它按 CHAIN 的 bytes 规则编码，即
    # 20/32 字节原样、其余长度加 `u32(len)` 前缀。实际上 `agora-testnet-1`
    # 为 15 字节 ⇒ **带 4 字节长度前缀**（首版按"20 字节"写，一跑就报错；
    # 这条正是独立实现最容易对不上的地方，故在规范里逐字节写明）。
    if not chain_id or len(chain_id) > 255:
        raise HandshakeError(f"chain_id 长度非法：{len(chain_id)}")
    if len(pubkey) != PUBKEY_LEN:
        raise HandshakeError(f"pubkey 必须为 {PUBKEY_LEN} 字节，实际 {len(pubkey)}")
    if len(nonce_i) != NONCE_LEN or len(nonce_r) != NONCE_LEN:
        raise HandshakeError("nonce 必须各为 32 字节")
    nb = name.encode("utf-8")
    if not nb or len(nb) > 255:
        raise HandshakeError(f"节点名长度非法：{len(nb)} 字节（1..255）")
    return TAG_HANDSHAKE + chain(chain_id, ("u8", role), nb, pubkey, nonce_i, nonce_r)


def make_challenge_sig(seed: bytes, chain_id: bytes, name: str, pubkey: bytes,
                       nonce_i: bytes, nonce_r: bytes) -> bytes:
    """响应方对挑战签名。"""
    return sign(seed, handshake_payload(ROLE_CHALLENGE, chain_id, name, pubkey,
                                        nonce_i, nonce_r))


def make_auth_sig(seed: bytes, chain_id: bytes, name: str, pubkey: bytes,
                  nonce_i: bytes, nonce_r: bytes) -> bytes:
    """发起方对确认消息签名。"""
    return sign(seed, handshake_payload(ROLE_AUTH, chain_id, name, pubkey,
                                        nonce_i, nonce_r))


def check_challenge_sig(pubkey: bytes, sig: bytes, chain_id: bytes, name: str,
                        nonce_i: bytes, nonce_r: bytes) -> bool:
    """校验响应方的挑战签名（发起方用）。

    全零签名表示"对端未配置身份"，**不是**校验通过 —— 调用方必须先处理
    `NIL_SIG`，不得把它当作有效签名（否则等于给了攻击者一个免签后门）。
    """
    if sig == NIL_SIG or pubkey == NIL_PUBKEY:
        return False
    try:
        return bool(verify(pubkey, handshake_payload(ROLE_CHALLENGE, chain_id, name,
                                                     pubkey, nonce_i, nonce_r), sig))
    except Exception:                                 # noqa: BLE001
        return False


def check_auth_sig(pubkey: bytes, sig: bytes, chain_id: bytes, name: str,
                   nonce_i: bytes, nonce_r: bytes) -> bool:
    """校验发起方的确认签名（响应方用）。"""
    if sig == NIL_SIG or pubkey == NIL_PUBKEY:
        return False
    try:
        return bool(verify(pubkey, handshake_payload(ROLE_AUTH, chain_id, name,
                                                     pubkey, nonce_i, nonce_r), sig))
    except Exception:                                 # noqa: BLE001
        return False


def chain_mismatch_hint(pubkey: bytes, sig: bytes, role: int, name: str,
                        nonce_i: bytes, nonce_r: bytes,
                        current_chain_id: bytes) -> str:
    """验签失败时，判断"是不是链身份配错了"，并给出可读的诊断。

    **为什么值得单独做这一步：** `chain_id` 进了签名原像（§6.7.1），因此
    两边链身份不一致时握手会失败 —— 这与"被篡改/被重放"在**错误信息上完全一样**，
    而它们的处置方式截然不同（一个是配置问题，一个是攻击）。实测踩过：
    探测工具忘了先切链身份，对着真实节点报的就是"挑战签名无效"。
    这里用其它已知链身份再验一次：若能验通，就说明是**链身份不一致**。
    """
    from . import params as P
    for net, cid in sorted(P.ALLOWED_NETWORKS.items()):
        cb = cid.encode("ascii")
        if cb == current_chain_id:
            continue
        try:
            payload = handshake_payload(role, cb, name, pubkey, nonce_i, nonce_r)
            if verify(pubkey, payload, sig):
                return (f"；但它在链身份 {cid!r} 下验签通过 ⇒ "
                        f"对端与本机的**链身份不一致**"
                        f"（本方 {current_chain_id.decode('ascii', 'replace')!r}）"
                        f"—— 请核对两边的创世配置与 network")
        except Exception:                             # noqa: BLE001
            continue
    return ""


def identity_fingerprint(pubkey: Optional[bytes]) -> str:
    """证书指纹：用于日志（**不打印完整公钥之外的任何秘密材料**）。"""
    if not pubkey or pubkey == NIL_PUBKEY:
        return "（无身份）"
    return keccak256(pubkey).hex()[:16] + "…"
