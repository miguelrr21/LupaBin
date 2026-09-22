import json

import pytest

from dissect.evidence.primitives import YaraLimits
from dissect.evidence.yara import ScanResult, validate_scan
from dissect.rules.catalog import load_catalog
from dissect.rules.native import scan


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(sample_sha256="0" * 64),
        lambda d: d.update(sample_size=1),
        lambda d: d["matches"][0].update(source_sha256="0" * 64),
        lambda d: d["matches"][0].update(package_version="invented"),
        lambda d: d["matches"][0].update(instances=[]),
        lambda d: d["matches"][0]["instances"][0].update(offset=1000),
        lambda d: d["matches"][0]["instances"][0].update(raw_hex="00" * 16),
        lambda d: d["matches"][0]["instances"][0].update(captured_length=1),
        lambda d: d["matches"][0]["instances"][0].update(string_id="$invented"),
        lambda d: d["matches"].append(d["matches"][0]),
        lambda d: d.update(scan_ok=False, reason="yara_timeout"),
        lambda d: d["matches"][0].update(instances_status="partial"),
    ],
)
def test_invalid_native_responses_are_rejected(mutate):
    data = b"DISSECT PRACTICE"
    payload = json.loads(scan(data).model_dump_json())
    mutate(payload)
    with pytest.raises(ValueError):
        result = ScanResult.model_validate_json(json.dumps(payload))
        validate_scan(result, data, load_catalog().info, YaraLimits())


def test_valid_native_response_is_bound_to_input_and_catalog():
    data = b"DISSECT PRACTICE"
    result = scan(data)
    validate_scan(result, data, load_catalog().info, YaraLimits())
    assert result.matches[0].omitted_instances == 0
