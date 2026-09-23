"""Manual check that every glossary source URL still answers (needs network).

    uv run python -m tests.check_glossary_sources

It only proves that each page exists. Whether the page supports the entry is checked
by a reviewer when writing or revising it, and recorded in `verified_on`. Not part of
CI, which has no network by design.
"""

import sys
import urllib.error
import urllib.request

from dissect.glossary.catalog import load_glossary

TIMEOUT = 20


def status(url: str) -> str:
    base = url.split("#", 1)[0]
    if not base.startswith("https://"):  # the entry model already requires it
        return "error: not https"
    agent = {"User-Agent": "dissect-glossary-check/1"}
    request = urllib.request.Request(base, headers=agent)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
            return str(response.status)
    except urllib.error.HTTPError as error:
        return str(error.code)
    except (urllib.error.URLError, TimeoutError) as error:
        return f"error: {error}"


def main() -> None:
    glossary = load_glossary()
    urls = sorted({s.url for e in glossary.entries.values() for s in e.sources})
    failures = 0
    for url in urls:
        result = status(url)
        ok = result.startswith("2")
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {result:>5} {url}")
    print(f"{len(urls)} sources, {failures} failing")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
