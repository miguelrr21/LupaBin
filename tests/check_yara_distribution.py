import hashlib
import tarfile
import zipfile
from pathlib import Path

from lupabin import __version__
from lupabin.glossary.catalog import default_root, load_glossary
from lupabin.rules.catalog import load_catalog


def main():
    root = Path(__file__).resolve().parents[1]
    catalog = load_catalog().info
    expected = {f"lupabin/rules/yara/{rule.filename}": rule.source_sha256 for rule in catalog.rules}
    expected["lupabin/rules/yara/manifest.json"] = catalog.manifest_sha256
    glossary = load_glossary()
    entries = Path(str(default_root()))
    for path in [*entries.glob("*.toml"), entries / "manifest.json"]:
        expected[f"lupabin/glossary/entries/{path.name}"] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    wheel = root / "dist" / f"lupabin-{__version__}-py3-none-any.whl"
    sdist = root / "dist" / f"lupabin-{__version__}.tar.gz"
    with zipfile.ZipFile(wheel) as archive:
        for name, digest in expected.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != digest:
                raise ValueError(f"wheel resource differs: {name}")
        if "lupabin/rules/YARA-LICENSE.txt" not in archive.namelist():
            raise ValueError("YARA license missing from wheel")
    with tarfile.open(sdist) as archive:
        for name, digest in expected.items():
            member = archive.extractfile(f"lupabin-{__version__}/src/{name}")
            if member is None or hashlib.sha256(member.read()).hexdigest() != digest:
                raise ValueError(f"sdist resource differs: {name}")
    print(
        f"Verified {len(expected)} catalog resources in wheel and sdist; "
        f"ruleset={catalog.ruleset_sha256} glossary={glossary.info.digest}"
    )


if __name__ == "__main__":
    main()
