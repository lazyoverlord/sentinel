"""Source code (SPEC §6, Should): comments, docstrings and string literals -> `comment` channel.

Python uses the stdlib tokenizer; other languages use a regex scanner per comment/string style.
Extracted items (>= 3 chars) are removed from the code: comments are dropped and strings become
"" so the remaining code (one visible segment) never repeats them. Escapes inside literals are
left as written - decoding them is the obfuscation layer's job.

Order: comments/strings (by line) come first and the whole-file code segment last, so that the
MAX_TEXT_CHARS cap cuts the code rather than silently dropping every comment of a big file.
"""
from __future__ import annotations

import bisect
import io
import os
import re
import tokenize
from dataclasses import dataclass

from .base import Out, ParseContext, RawSeg, decode_text

MIN_CHARS = 3

LANG_BY_EXT: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
    ".java": "c", ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".cxx": "c", ".hpp": "c", ".hh": "c", ".cs": "c",
    ".go": "go", ".rb": "ruby", ".php": "php", ".sh": "sh", ".bash": "sh", ".zsh": "sh",
    ".rs": "rust", ".kt": "kotlin", ".kts": "kotlin", ".swift": "kotlin", ".sql": "sql",
}
LANG_BY_TYPE: dict[str, str] = {
    "text/x-python": "python", "application/x-python": "python", "text/x-script.python": "python",
    "text/javascript": "js", "application/javascript": "js", "application/x-javascript": "js",
    "text/ecmascript": "js", "application/typescript": "js", "text/typescript": "js", "text/x-typescript": "js",
    "text/x-java": "c", "text/x-java-source": "c", "text/x-c": "c", "text/x-csrc": "c", "text/x-chdr": "c",
    "text/x-c++": "c", "text/x-c++src": "c", "text/x-csharp": "c",
    "text/x-go": "go", "text/x-ruby": "ruby", "application/x-ruby": "ruby",
    "text/x-php": "php", "application/x-php": "php", "application/x-httpd-php": "php",
    "application/x-sh": "sh", "text/x-sh": "sh", "text/x-shellscript": "sh", "application/x-shellscript": "sh",
    "text/x-rust": "rust", "text/rust": "rust", "text/x-kotlin": "kotlin", "text/x-swift": "kotlin",
    "application/sql": "sql", "text/x-sql": "sql",
}

# --- regex building blocks (comment patterns go in group "c", string patterns in group "s")
_BLOCK = r"/\*[\s\S]*?(?:\*/|\Z)"
_SLASH = r"//[^\n]*"
_HASH_WORD = r"(?:(?<=\s)|^)#[^\n]*"        # shell/ruby/php: '#' only at a word start ($# is not a comment)
_HASH = r"#[^\n]*"
_DASH = r"--[^\n]*"
_RUBY_BLOCK = r"^=begin\b[\s\S]*?(?:^=end\b[^\n]*|\Z)"
_DQ = r'"(?:\\.|[^"\\\n])*"'
_DQ_ML = r'"(?:\\.|[^"\\])*"'                # strings that may span lines
_SQ = r"'(?:\\.|[^'\\\n])*'"
_SQ_ML = r"'(?:\\.|[^'\\])*'"
_BT = r"`(?:\\.|[^`\\])*`"
_TDQ = r'"""[\s\S]*?(?:"""|\Z)'
_SQL_SQ = r"'(?:''|[^'])*'"
_RUST_RAW = r'b?r(?P<h>#*)"[\s\S]*?"(?P=h)'
_RUST_CHAR = r"'(?:\\(?:u\{[0-9a-fA-F]{1,6}\}|.)|[^'\\\n])'"   # 'a' - not lifetimes like 'a
_PY_PREFIX = r"(?:[rRbBuUfFtT]{1,2})?"
_PY_TRIPLE = _PY_PREFIX + r"(?:'''[\s\S]*?(?:'''|\Z)|\"\"\"[\s\S]*?(?:\"\"\"|\Z))"
_PY_SINGLE = _PY_PREFIX + r"(?:" + _DQ + "|" + _SQ + ")"

_LANGS: dict[str, tuple[list[str], list[str]]] = {   # language -> (comment patterns, string patterns)
    "c": ([_BLOCK, _SLASH], [_DQ, _SQ]),
    "js": ([_BLOCK, _SLASH], [_DQ, _SQ, _BT]),
    "go": ([_BLOCK, _SLASH], [_DQ, _SQ, _BT]),
    "kotlin": ([_BLOCK, _SLASH], [_TDQ, _DQ, _SQ]),
    "rust": ([_BLOCK, _SLASH], [_RUST_RAW, _DQ_ML, _RUST_CHAR]),
    "php": ([_BLOCK, _SLASH, _HASH_WORD], [_DQ_ML, _SQ_ML]),
    "sh": ([_HASH_WORD], [_DQ_ML, _SQ_ML]),
    "ruby": ([_RUBY_BLOCK, _HASH_WORD], [_DQ_ML, _SQ_ML]),
    "sql": ([_BLOCK, _DASH], [_SQL_SQ, _DQ]),
    "python": ([_HASH], [_PY_TRIPLE, _PY_SINGLE]),
}
_SCANNERS: dict[str, re.Pattern[str]] = {
    lang: re.compile(f"(?P<c>{'|'.join(cs)})|(?P<s>{'|'.join(ss)})", re.MULTILINE)
    for lang, (cs, ss) in _LANGS.items()
}
_STRING_BODY = re.compile(r"^(?:[A-Za-z]{0,2})(#*)(\"\"\"|'''|\"|'|`)([\s\S]*?)(?:\2\1)?$")


@dataclass
class _Item:
    kind: str           # "c" comment | "s" string
    start: int          # absolute character offsets into the source
    end: int
    line: int           # 1-based start line
    full_line: bool = False   # comment is the only thing on its line


def language_for(filename: str | None, content_type: str | None) -> str:
    if filename:
        lang = LANG_BY_EXT.get(os.path.splitext(filename.lower())[1])
        if lang:
            return lang
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    return LANG_BY_TYPE.get(ct, "c")


def _python_items(src: str, line_starts: list[int], ctx: ParseContext) -> list[_Item]:
    """Comments and string literals via tokenize (f-/t-strings kept whole)."""
    fstart = {getattr(tokenize, n) for n in ("FSTRING_START", "TSTRING_START") if hasattr(tokenize, n)}
    fend = {getattr(tokenize, n) for n in ("FSTRING_END", "TSTRING_END") if hasattr(tokenize, n)}
    items: list[_Item] = []
    depth, open_at = 0, (0, 0)

    def off(pos: tuple[int, int]) -> int:
        return line_starts[pos[0] - 1] + pos[1]

    for n, tok in enumerate(tokenize.generate_tokens(io.StringIO(src).readline)):
        if n % 5000 == 0:
            ctx.checkpoint()
        if tok.type in fstart:
            if depth == 0:
                open_at = tok.start
            depth += 1
        elif tok.type in fend:
            depth -= 1
            if depth == 0:
                items.append(_Item("s", off(open_at), off(tok.end), open_at[0]))
        elif depth:
            continue                                    # tokens inside an f-string's {...}
        elif tok.type == tokenize.COMMENT:
            items.append(_Item("c", off(tok.start), off(tok.end), tok.start[0],
                               full_line=not tok.line[: tok.start[1]].strip()))
        elif tok.type == tokenize.STRING:
            items.append(_Item("s", off(tok.start), off(tok.end), tok.start[0]))
    return items


def _regex_items(src: str, lang: str, line_starts: list[int]) -> list[_Item]:
    items: list[_Item] = []
    for m in _SCANNERS[lang].finditer(src):
        kind = "c" if m.group("c") is not None else "s"
        line = bisect.bisect_right(line_starts, m.start())
        line_start = line_starts[line - 1]
        items.append(_Item(kind, m.start(), m.end(), line,
                           full_line=kind == "c" and not src[line_start:m.start()].strip()))
    return items


def _comment_body(raw: str) -> str:
    if raw.startswith("/*"):
        body = raw[2:-2] if raw.endswith("*/") else raw[2:]
        return "\n".join(line.strip().lstrip("*").strip() for line in body.splitlines())
    if raw.startswith("=begin"):
        return "\n".join(raw.splitlines()[1:-1])
    if raw.startswith("//"):
        return raw[2:].lstrip("/!").strip()           # also /// and //! doc comments
    if raw.startswith("--"):
        return raw[2:].strip()
    return raw.lstrip("#").strip()


def _string_body(raw: str) -> str:
    m = _STRING_BODY.match(raw)
    return m.group(3) if m else raw


def parse(data: bytes, ctx: ParseContext, *, filename: str | None = None,
          content_type: str | None = None) -> list[RawSeg]:
    src = decode_text(data)
    lang = language_for(filename, content_type)
    line_starts = [0] + [m.end() for m in re.finditer("\n", src)]
    items: list[_Item]
    if lang == "python":
        try:
            items = _python_items(src, line_starts, ctx)
        except (tokenize.TokenError, SyntaxError, ValueError, IndexError):
            items = _regex_items(src, "python", line_starts)     # broken Python: best effort
    else:
        items = _regex_items(src, lang, line_starts)
    ctx.checkpoint()

    out = Out(ctx)
    kept: list[str] = []            # code with extracted items removed
    cursor = 0
    prev_comment: tuple[RawSeg, int] | None = None     # (segment, end offset) of the last full-line comment
    for it in items:
        raw = src[it.start:it.end]
        body = _comment_body(raw) if it.kind == "c" else _string_body(raw)
        if len(body.strip()) < MIN_CHARS:
            continue                                    # tiny literal/comment stays in the code
        kept.append(src[cursor:it.start])
        kept.append('""' if it.kind == "s" else "")
        cursor = it.end
        if it.kind == "s":
            out.add(body, "comment", f"line {it.line}", "code_string")
            prev_comment = None
            continue
        gap = src[prev_comment[1]:it.start] if prev_comment else ""
        if prev_comment and it.full_line and not gap.strip() and gap.count("\n") == 1:
            seg = prev_comment[0]                       # consecutive full-line comments => one segment
            seg.text += "\n" + body.strip()
            out.ctx.shared.chars += len(body)
            prev_comment = (seg, it.end)
            continue
        seg = out.add(body.strip(), "comment", f"line {it.line}", "code_comment")
        prev_comment = (seg, it.end) if seg is not None and it.full_line else None
    kept.append(src[cursor:])
    code = "\n".join(line.rstrip() for line in "".join(kept).splitlines())
    out.add(re.sub(r"\n{3,}", "\n\n", code), "visible", "line 1")   # removed comments leave blank runs
    return out.segs
