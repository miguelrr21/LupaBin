"""Neutralise untrusted text before it reaches a terminal or a Markdown viewer.

A sample controls its section names, import names, strings and decoded texts, and
third parties control what VirusTotal returns. Shown raw, such text could move the
cursor, recolour or clear the terminal (ESC sequences), create terminal hyperlinks
(OSC 8), reorder what the reader sees (Unicode bidi controls), hide characters, or
inject links, images and HTML into Markdown. Every such character is replaced by a
visible marker such as ⟨U+001B⟩. Backslashes are left alone, so Windows paths read
naturally; the marker cannot be produced by a control character.
"""

import re

_INVISIBLE = {
    0x00AD,  # soft hyphen
    0x034F,  # combining grapheme joiner
    0x061C,  # Arabic letter mark
    0x115F,
    0x1160,
    0x180E,
    0x2028,
    0x2029,
    0x3164,
    0xFEFF,
    0xFFA0,
}
_INVISIBLE_RANGES = (
    (0x200B, 0x200F),  # zero-width characters and directional marks
    (0x202A, 0x202E),  # bidi embeddings and overrides
    (0x2060, 0x206F),  # word joiner, bidi isolates, invisible operators
    (0xD800, 0xDFFF),  # lone surrogates
    (0xE000, 0xF8FF),  # private use
    (0xFE00, 0xFE0F),  # variation selectors
    (0xFFF0, 0xFFFB),  # specials and interlinear annotation
    (0xE0000, 0xE007F),  # tag characters
    (0xE0100, 0xE01EF),  # variation selectors supplement
    (0xF0000, 0x10FFFF),  # supplementary private use
)


def _dangerous(code: int) -> bool:
    if code < 0x20 or 0x7F <= code <= 0x9F:
        return True
    return code in _INVISIBLE or any(low <= code <= high for low, high in _INVISIBLE_RANGES)


def visible(text: str) -> str:
    """Printable, inert text: control, bidi and invisible characters become ⟨U+XXXX⟩."""
    return "".join(f"⟨U+{ord(c):04X}⟩" if _dangerous(ord(c)) else c for c in text)


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
