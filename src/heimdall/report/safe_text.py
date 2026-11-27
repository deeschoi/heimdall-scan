"""Make untrusted text safe to print to a terminal or embed in Markdown.

Everything a report carries can come from someone other than the operator:
response bodies and OpenAPI path keys come from the scanned target, route
strings and file names from a scanned source tree, and a whole report file can
be handed over by someone else. None of it may drive the operator's terminal
(ANSI/OSC escape sequences) or restructure a rendered Markdown report.
"""

from __future__ import annotations

import re

# Bidirectional overrides and isolates can reorder what a reader sees.
_BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}


def _escape_char(ch: str) -> str:
    code = ord(ch)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}"


def _is_control(ch: str, keep_newlines: bool) -> bool:
    code = ord(ch)
    if keep_newlines and ch in "\n\t":
        return False
    return code < 0x20 or 0x7F <= code <= 0x9F or code in _BIDI


def terminal_safe(text: object, *, keep_newlines: bool = True) -> str:
    """Escape C0/C1 control characters (ESC, CSI, BEL ...) and bidi overrides.

    Newlines and tabs are kept unless ``keep_newlines`` is false. The result
    shows each removed character as a visible ``\\xNN`` / ``\\uNNNN`` escape.
    """
    s = "" if text is None else str(text)
    if not any(_is_control(ch, keep_newlines) for ch in s):
        return s
    return "".join(_escape_char(ch) if _is_control(ch, keep_newlines) else ch for ch in s)


def one_line(text: object) -> str:
    """:func:`terminal_safe` with newlines escaped too, for single-line fields."""
    return terminal_safe(text, keep_newlines=False)


def _longest_backtick_run(s: str) -> int:
    runs = re.findall(r"`+", s)
    return max((len(r) for r in runs), default=0)


def md_code(text: object, *, in_table: bool = False) -> str:
    """An inline code span that ``text`` cannot close early.

    In a table cell, ``|`` is escaped as well so it cannot start a new cell.
    """
    s = one_line(text)
    if in_table:
        s = s.replace("|", "\\|")
    ticks = "`" * (_longest_backtick_run(s) + 1)
    pad = " " if s.startswith("`") or s.endswith("`") or not s else ""
    return f"{ticks}{pad}{s}{pad}{ticks}"


def md_text(text: object, *, in_table: bool = False) -> str:
    """Free text for a Markdown line: no raw HTML, no control characters."""
    s = terminal_safe(text)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if in_table:
        s = s.replace("|", "\\|").replace("\n", " ")
    return s


def md_fence(content: object, info: str = "") -> list[str]:
    """Lines of a fenced code block that ``content`` cannot break out of."""
    body = terminal_safe(content)
    fence = "`" * max(3, _longest_backtick_run(body) + 1)
    return [f"{fence}{info}", body, fence]
