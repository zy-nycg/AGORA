# -*- coding: utf-8 -*-
"""
AGORA v0.2.2 — 规范条款 ↔ 测试证据 的**可追溯性矩阵**（GATE-0/GATE-7 的证据基础）
================================================================================

用法
----
    PYTHONPATH=. python3 tools/agora_coverage.py            # 打印报告
    PYTHONPATH=. python3 tools/agora_coverage.py --strict    # 有"无证据"项时非零退出
    PYTHONPATH=. python3 tools/agora_coverage.py --md > COVERAGE.md

它做什么（以及**刻意不做什么**）
--------------------------------
做什么：

1. 从 `AGORA_v0.2.2_SPEC.md` 里**程序化提取**两组编号条款：
   * §16.4.2 的 19 项逐项后果表；
   * §22 的 12 项区块验证谓词；
2. 在 `tests/` 与 `independent/` 里查找每一项的**证据引用**，并区分证据强度：
   * `断言级` —— 有 `failed_at == N`、`第 N 项`、`item N` 之类的**定位断言**；
   * `引用级` —— 只出现了编号（可能只是注释里提到）；
   * `无证据` —— 两者皆无；
3. 逐节统计"含 MUST 的章节"是否被任何测试文件引用（粗粒度，见下方*局限*）。

**刻意不做什么：不做"语义正确性"判断。** 本工具只回答"这一条有没有被指向过"，
它**不能**回答"测的是不是这一条的意思"。这正是 PROJECT_REVIEW.md §4 记录的那类
结构性问题：以前的证据基础是"人肉记忆 + 覆盖率数字"，本工具把它变成**可复核的清单**，
但仍然需要人逐条核对语义。

局限（必须写明）
----------------
* "引用级"证据**可能只是注释**里提到了编号 —— 因此本工具把它与"断言级"分开统计，
  并且**只有断言级才计入通过**（`--strict` 亦按此判定）；
* 章节级引用统计是**粗粒度**的：某一节被引用不等于该节的每条 MUST 都被测到。
  它只用来发现"整节从未被任何测试提及"这种空洞，而不是用来宣称"全部覆盖"。
"""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SPEC = os.path.join(ROOT, "AGORA_v0.2.2_SPEC.md")

_pass = 0
_fail = 0
_warn: list[str] = []


def load(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def _test_sources() -> dict[str, str]:
    """所有测试与独立实现的源码，按 `相对路径 → 文本` 返回。"""
    out: dict[str, str] = {}
    for d in ("tests", "independent", "tools"):
        base = os.path.join(ROOT, d)
        for dirpath, _dirs, files in os.walk(base):
            for fn in sorted(files):
                if not fn.endswith((".py", ".js")):
                    continue
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, ROOT)
                try:
                    out[rel] = load(p)
                except OSError:                     # pragma: no cover
                    pass
    return out


# 两组编号条款各自有**不同的定位写法**，因此证据必须按组匹配：
#   §16.4.2 → 断言靠 `failed_at == N`（校验流水线的失败位置）
#   §22     → 断言靠 `§22 第 N 项` 与 `第 N 项失败`（谓词失败消息）
# 若不分文件地按 `第 N 项` 一锅搜，§16.4.2 的第 1 项会把自己算成 §22 的第 1 项 ——
# 那正是本工具要消灭的"看起来覆盖了"的假证据，所以按**组标记 + 文件共现**限定范围。
GROUP_MARK = {
    "§16.4.2": re.compile(r"§\s*16\.4\.2|校验流水线|validate_tx"),
    # §22 的标记**不能**用"谓词"这种泛词：它出现在几乎所有测试文件里，
    # 会让 §22 的每一项都"看起来有证据"（首版就是这个假阳性）。
    "§22": re.compile(r"§\s*22|validate_block_header"),
}


def _evidence_for(item: int, sources: dict[str, str], group: str) -> tuple[list[str], list[str]]:
    """返回 `(断言级证据, 引用级证据)`，元素为 `文件:行`。"""
    asserted: list[str] = []
    referenced: list[str] = []
    mark = GROUP_MARK[group]
    if group == "§16.4.2":
        pats_assert = (
            re.compile(rf"failed_at\s*==\s*{item}\b"),
            re.compile(rf"§\s*16\.4\.2\s*第\s*{item}\s*项"),
            re.compile(rf"第\s*{item}\s*项"),
        )
    else:
        # `BlockError.check == N` 与 §22 的编号**一一对应**（`agora/block.py` 在
        # 抛错时带上 `check=`），因此它是与 §16.4.2 的 `failed_at == N` 等价的
        # 定位断言 —— 首版漏了它，导致"其实已经测过"的项被误报为无证据。
        pats_assert = (
            re.compile(rf"§\s*22\s*第\s*{item}\s*项"),
            re.compile(rf"第\s*{item}\s*项失败"),
            re.compile(rf"check\s*==\s*{item}\b"),
            re.compile(rf"check={item}\b"),
            re.compile(rf"第\s*{item}\s*项"),
        )
    for rel, text in sources.items():
        if rel.endswith(("agora_coverage.py",)):
            continue                                # 不把自己当证据
        if not mark.search(text):
            continue                                # 该文件根本不涉及这一组条款
        lines = text.splitlines()
        for ln, line in enumerate(lines, 1):
            if any(p.search(line) for p in pats_assert):
                asserted.append(f"{rel}:{ln}")
            elif item >= 10 and re.search(rf"\b{item}\b", line):
                # 单数字编号（1..9）在源码里到处都是（数组下标、端口…），
                # 因此只对两位数编号做"裸引用"统计，避免噪声淹没结论。
                # 仅当**附近**（±5 行）真的有一条断言时，才把它算作证据：
                # 否则"编号出现过"和"这条被验证过"是两件完全不同的事。
                lo, hi = max(0, ln - 6), min(len(lines), ln + 5)
                near = "\n".join(lines[lo:hi])
                if re.search(r"\bchk\(|\bassert\b|failed_at\s*==", near):
                    asserted.append(f"{rel}:{ln}（邻近断言）")
                else:
                    referenced.append(f"{rel}:{ln}")
    return asserted, referenced


def _parse_table_items(spec: str, heading_re: str, col_name: str) -> list[tuple[int, str]]:
    """从 `| N | 检查内容 | … |` 形式的表里取出 `(编号, 检查内容)`。"""
    lines = spec.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.search(heading_re, line):
            start = i
            break
    if start is None:
        return []
    items: list[tuple[int, str]] = []
    for line in lines[start:start + 80]:
        m = re.match(r"\|\s*(\d+)\s*\|\s*(.+?)\s*\|", line)
        if m:
            n = int(m.group(1))
            if any(x[0] == n for x in items):
                continue
            items.append((n, m.group(2)))
        elif items and line.startswith("**"):
            break                                   # 表结束（表后紧跟说明段）
    return items


def _parse_numbered_items(spec: str, heading: str, limit: int = 20) -> list[tuple[int, str]]:
    """从 `N. 正文` 形式的编号列表里取出 `(编号, 正文)`（支持跨行的续行）。"""
    lines = spec.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() == heading:
            start = i
            break
    if start is None:
        return []
    items: list[tuple[int, str]] = []
    cur_n = None
    buf: list[str] = []
    for line in lines[start + 1:start + 200]:
        # 遇到下一个一级标题即停止：否则会把后面章节的编号列表一起吃掉
        # （首版就把 §9.4 的编号项当成了 §22 的第 1、2 项 —— 那会直接制造假证据）。
        if re.match(r"^#\s", line):
            break
        m = re.match(r"^(\d+)\.\s+(.*)$", line)
        if m:
            if cur_n is not None:
                items.append((cur_n, " ".join(buf).strip()))
            cur_n = int(m.group(1))
            buf = [m.group(2)]
            if len(items) >= limit:
                break
        elif cur_n is not None and line.strip() and not line.startswith(("**", "---", "#")):
            buf.append(line.strip())
        elif cur_n is not None and (line.startswith("**") or line.startswith("---")):
            items.append((cur_n, " ".join(buf).strip()))
            cur_n = None
            buf = []
    if cur_n is not None:
        items.append((cur_n, " ".join(buf).strip()))
    return [(n, t) for n, t in items if t]


def main() -> int:
    global _pass, _fail
    strict = "--strict" in sys.argv
    as_md = "--md" in sys.argv
    spec = load(SPEC)
    sources = _test_sources()

    print("═" * 78)
    print("AGORA v0.2.2 · 规范条款 ↔ 测试证据 追溯矩阵")
    print("═" * 78)

    groups = [
        ("§16.4.2", "§16.4.2 交易校验流水线（19 项）",
         _parse_table_items(spec, r"^###\s*16\.4\.2", "检查")),
        ("§22", "§22 区块验证谓词（12 项）",
         _parse_numbered_items(spec, "# 22. 区块验证")),
    ]

    unmapped: list[str] = []
    for group, title, items in groups:
        print(f"\n{title}")
        if not items:
            _warn.append(f"{title}：解析不到编号条款（规范结构变了？）")
            print("  ★ 解析不到编号条款 —— 规范结构可能已变，请检查解析正则")
            continue
        for n, text in items:
            asserted, referenced = _evidence_for(n, sources, group)
            if asserted:
                strength = "断言级"
                ev = asserted[:3]
                _pass += 1
            elif referenced:
                strength = "引用级"
                ev = referenced[:3]
                _warn.append(f"{title} 第 {n} 项仅有引用级证据（可能只是注释）")
            else:
                strength = "无证据"
                ev = []
                unmapped.append(f"{title} 第 {n} 项：{text[:60]}")
                _fail += 1
            tail = "" if len(ev) < 4 else f" …（共 {len(asserted) + len(referenced)} 处）"
            print(f"  [{strength:4}] 第 {n:>2} 项  {text[:52]:<52} {' '.join(ev)}{tail}")

    # ── 章节级：含 MUST 的章节是否被任何测试文件提及（粗粒度空洞检查）──
    print("\n含 MUST 的章节 × 是否被测试提及（粗粒度，仅用于发现「整节从未被提及」）")
    must_sections: list[tuple[str, int]] = []
    cur = None
    counts: dict[str, int] = {}
    for line in spec.splitlines():
        m = re.match(r"^(#{1,3})\s+(\d+(?:\.\d+)*)[\.\s]", line)
        if m:
            cur = m.group(2)
        if cur and "MUST" in line:
            counts[cur] = counts.get(cur, 0) + line.count("MUST")
    for sec, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        must_sections.append((sec, n))
    all_src = "\n".join(sources.values())
    never = [s for s, _ in must_sections if f"§{s}" not in all_src]
    mentioned = len(must_sections) - len(never)
    print(f"  含 MUST 的章节 {len(must_sections)} 个，被测试提及 {mentioned} 个，"
          f"**从未被提及** {len(never)} 个")
    if never:
        print("  从未被提及的章节（需要人工确认是否本该有测试）：")
        for s in never[:20]:
            print(f"    §{s}（{counts[s]} 处 MUST）")
        _warn.append(f"{len(never)} 个含 MUST 的章节从未被任何测试提及")
    else:
        _pass += 1

    print("\n" + "═" * 78)
    print(f"编号条款：有断言级证据 {_pass} 项；**无任何证据** {_fail} 项")
    if unmapped:
        print("无证据清单（必须逐条处理：补测试，或在规范里说明为何不需要）：")
        for u in unmapped:
            print(f"  · {u}")
    if _warn:
        print(f"\n提示 {len(_warn)} 条（不影响退出码，但需要人看一眼）：")
        for w in _warn[:20]:
            print(f"  ! {w}")
    print("\n**本工具只做「有没有被指向」的可追溯性，不判断语义是否正确。**")
    print("局限：引用级证据可能只是注释；章节级统计是粗粒度的。")
    ok = (_fail == 0) or not strict
    print("结果：" + ("全部编号条款均有断言级证据 ✅" if _fail == 0
                    else ("存在无证据条款 ★" if strict else "存在无证据条款（--strict 下会失败）★")))
    print("═" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
