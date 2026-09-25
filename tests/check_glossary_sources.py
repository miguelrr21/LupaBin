"""Manual check that every glossary source URL still answers (needs network).

    uv run python -m tests.check_glossary_sources

It proves that each page exists and, for URLs with a fragment, that the page has an
element with that id. Whether the page supports the entry is checked by a reviewer
when writing or revising it, and recorded in `verified_on`. Not part of CI, which has
no network by design.
"""

import re
import sys
import urllib.error
import urllib.request

from lupabin.glossary.catalog import load_glossary

TIMEOUT = 20
MAX_PAGE = 8 * 1024 * 1024


def fetch(url: str) -> tuple[str, str]:
    if not url.startswith("https://"):  # the entry model already requires it
        return "error: not https", ""
    agent = {"User-Agent": "lupabin-glossary-check/1"}
    request = urllib.request.Request(url, headers=agent)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
            body = response.read(MAX_PAGE).decode("utf-8", "replace")
            return str(response.status), body
    except urllib.error.HTTPError as error:
        return str(error.code), ""
    except (urllib.error.URLError, TimeoutError) as error:
        return f"error: {error}", ""


def main() -> None:
    glossary = load_glossary()
    urls = sorted({s.url for e in glossary.entries.values() for s in e.sources if s.url})
    pages: dict[str, tuple[str, str]] = {}
    failures = 0
    for url in urls:
        base, _, fragment = url.partition("#")
        if base not in pages:
            pages[base] = fetch(base)
        result, body = pages[base]
        ok = result.startswith("2")
        if ok and fragment:
            ids = set(re.findall(r"""\bid=["']([^"']+)["']""", body))
            if fragment not in ids:
                ok, result = False, "#?"
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {result:>5} {url}")
    print(f"{len(urls)} sources, {failures} failing")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
