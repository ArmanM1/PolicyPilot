from __future__ import annotations

import re
from copy import deepcopy
from typing import Any


REDACTED = "[REDACTED]"
SENSITIVE_KEYS = re.compile(
    r"(?:password|passwd|passphrase|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)(https?://)[^\s/:]+:[^\s/@]+@"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


def redact_string(value: str) -> tuple[str, bool]:
    changed = False
    result = value
    for pattern in SECRET_PATTERNS:
        result, count = pattern.subn(REDACTED, result)
        changed = changed or count > 0
    return result, changed


def redact(value: Any) -> tuple[Any, list[str]]:
    """Deep-copy and irreversibly redact known synthetic secret forms."""

    redacted_fields: list[str] = []

    def walk(item: Any, path: str) -> Any:
        if isinstance(item, dict):
            output: dict[str, Any] = {}
            for key, child in item.items():
                child_path = f"{path}.{key}" if path else str(key)
                if SENSITIVE_KEYS.search(str(key)):
                    output[key] = REDACTED
                    redacted_fields.append(child_path)
                else:
                    output[key] = walk(child, child_path)
            return output
        if isinstance(item, list):
            return [walk(child, f"{path}[{index}]") for index, child in enumerate(item)]
        if isinstance(item, tuple):
            return [walk(child, f"{path}[{index}]") for index, child in enumerate(item)]
        if isinstance(item, str):
            clean, changed = redact_string(item)
            if changed:
                redacted_fields.append(path or "$value")
            return clean
        return item

    return walk(deepcopy(value), ""), sorted(set(redacted_fields))


def contains_known_secret(value: Any) -> bool:
    text = str(value)
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)
