"""Neutralise sample-derived text before it reaches a terminal or a Markdown viewer.

A sample controls its section names, import names, strings and decoded texts. Shown
raw, they could move the cursor, recolour or clear the terminal (ESC sequences),
create terminal hyperlinks (OSC 8), reorder what the reader sees (Unicode bidi
controls) or inject links, images and HTML into Markdown. Every such character is
replaced by a visible escape, and the backslash itself is escaped so an escape can
never be confused with sample text that merely looks like one.
"""

import re

_INVISIBLE = {
    0x00AD,  # soft hyphen
    0x061C,  # Arabic letter mark
    0x180E,
    0x200B,
    0x200C,
    0x200D,
    0x200E,
    0x200F,
    0x2028,
    0x2029,
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2060,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
    0xFEFF,
}


def _escape(char: str) -> str:
    code = ord(char)
    if char == "\\":
        return "\\\\"
    if code < 0x20 or 0x7F <= code <= 0x9F:
        return f"\\x{code:02x}"
    if code in _INVISIBLE or 0xD800 <= code <= 0xDFFF or 0xE000 <= code <= 0xF8FF:
        return f"\\u{code:04x}"
    if code > 0xFFFF:
        return f"\\U{code:08x}"
    return char


def visible(text: str) -> str:
    """Printable, inert text: control, bidi and invisible characters become escapes."""
    return "".join(_escape(char) for char in text)


def code_span(text: str) -> str:
    """A Markdown code span that nothing inside can close or turn into markup."""
    value = visible(text)
    run = max((len(match) for match in re.findall(r"`+", value)), default=0)
    fence = "`" * (run + 1)
    if value.startswith(("`", " ")) or value.endswith(("`", " ")):
        value = f" {value} "
    return f"{fence}{value}{fence}"


_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+\-.!|~])")


def markdown_text(text: str) -> str:
    """Trusted prose (no sample data) with Markdown punctuation made literal."""
    return _MARKDOWN_SPECIAL.sub(r"\\\1", visible(text))
