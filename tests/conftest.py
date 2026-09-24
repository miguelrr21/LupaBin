import pytest


@pytest.fixture(autouse=True)
def no_default_virustotal(monkeypatch):
    """The CLI consults VirusTotal by default; tests never reach the network, even when
    the developer has a key configured. Tests of that path pass --virustotal and a fake."""
    monkeypatch.setenv("DISSECT_VIRUSTOTAL", "off")
