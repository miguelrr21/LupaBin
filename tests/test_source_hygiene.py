from pathlib import Path

ROOT = Path(__file__).parents[1]
# Bidi controls and invisible characters can make reviewed code or text read
# differently from what it does ("Trojan Source"); write them as escapes instead.
FORBIDDEN = {
    *range(0x200B, 0x2010),
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
    0x061C,
    0xFEFF,
}


def test_no_literal_bidi_or_invisible_characters():
    paths = [
        path
        for pattern in ("src/**/*.py", "src/**/*.toml", "src/**/*.json", "tests/**/*.py", "*.md")
        for path in ROOT.glob(pattern)
    ] + list((ROOT / "docs").rglob("*.md"))
    found = [
        (str(path.relative_to(ROOT)), hex(ord(char)))
        for path in paths
        for char in set(path.read_text(encoding="utf-8"))
        if ord(char) in FORBIDDEN
    ]
    assert not found
