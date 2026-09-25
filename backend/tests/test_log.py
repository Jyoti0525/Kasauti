from kasauti.log import REDACTED, redact_secrets


def test_secret_fields_are_masked() -> None:
    event = {
        "event": "parsed",
        "password": "hunter2",
        "snmp_community": "public",
        "enable_secret": "x",
        "psk": "y",
        "api_key": "z",
        "hostname": "r1",
    }
    out = redact_secrets(None, "info", event)
    assert out["hostname"] == "r1"
    assert out["event"] == "parsed"
    for name in ("password", "snmp_community", "enable_secret", "psk", "api_key"):
        assert out[name] == REDACTED
