from __future__ import annotations

import secrets
import string

MIN_GENERATED_LENGTH = 4
MAX_GENERATED_LENGTH = 128
DEFAULT_GENERATED_LENGTH = 16

CHARSETS: dict[str, str] = {
    "uppercase": string.ascii_uppercase,
    "lowercase": string.ascii_lowercase,
    "numbers": string.digits,
    "special": "!@#$%^&*()-_=+[]{}<>?/|~",
}


def _secure_shuffle(items: list[str]) -> None:
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def generate_password(
    length: int,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    special: bool = True,
) -> str:
    selected = [
        name
        for name, enabled in (
            ("uppercase", uppercase),
            ("lowercase", lowercase),
            ("numbers", numbers),
            ("special", special),
        )
        if enabled
    ]
    if not MIN_GENERATED_LENGTH <= length <= MAX_GENERATED_LENGTH:
        raise ValueError(
            f"Length must be between {MIN_GENERATED_LENGTH} and {MAX_GENERATED_LENGTH}."
        )
    if not selected:
        raise ValueError("At least one character set must be enabled.")
    pool = "".join(CHARSETS[name] for name in selected)
    guaranteed = [secrets.choice(CHARSETS[name]) for name in selected]
    remaining = [secrets.choice(pool) for _ in range(length - len(guaranteed))]
    chars = guaranteed + remaining
    _secure_shuffle(chars)
    return "".join(chars)
