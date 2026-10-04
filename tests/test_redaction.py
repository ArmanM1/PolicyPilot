from policypilot.redaction import REDACTED, contains_known_secret, redact, redact_string


def test_sensitive_key_is_redacted():
    clean, fields = redact({"api_key": "synthetic", "safe": "visible"})
    assert clean == {"api_key": REDACTED, "safe": "visible"}
    assert fields == ["api_key"]


def test_nested_values_and_lists_are_redacted():
    clean, fields = redact({"request": [{"password": "synthetic"}]})
    assert clean["request"][0]["password"] == REDACTED
    assert fields == ["request[0].password"]


def test_bearer_token_is_redacted_from_command():
    clean, changed = redact_string("curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz' example.invalid")
    assert changed is True
    assert "abcdefghijklmnopqrstuvwxyz" not in clean


def test_openai_shaped_synthetic_token_is_redacted():
    clean, fields = redact({"command": "use sk-abcdefghijklmnopqrstuvwxyz123456"})
    assert REDACTED in clean["command"]
    assert fields == ["command"]


def test_github_shaped_synthetic_token_is_redacted():
    clean, fields = redact({"value": "ghp_abcdefghijklmnopqrstuvwxyz123456"})
    assert REDACTED in clean["value"]
    assert fields


def test_url_credentials_are_redacted():
    clean, fields = redact({"url": "https://fixture-user:fixture-pass@example.invalid"})
    assert "fixture-pass" not in clean["url"]
    assert fields == ["url"]


def test_input_is_not_mutated():
    original = {"token": "synthetic"}
    redact(original)
    assert original == {"token": "synthetic"}


def test_contains_known_secret_is_bounded_detector():
    assert contains_known_secret("Bearer abcdefghijklmnopqrstuvwxyz")
    assert not contains_known_secret("ordinary fixture text")
