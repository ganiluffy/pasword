from __future__ import annotations

import math
import re

MIN_RECOMMENDED_LENGTH = 8
STRONG_RECOMMENDED_LENGTH = 12
MAX_INPUT_LENGTH = 1024
ENTROPY_LENGTH_CAP = 1024

_UPPER_POOL = 26
_LOWER_POOL = 26
_DIGIT_POOL = 10
_SPECIAL_POOL = 32
_NON_ASCII_POOL = 100
_ENTROPY_SCALE_BITS = 128.0

_STRENGTH_BANDS: tuple[tuple[float, str], ...] = (
    (28.0, "Very Weak"),
    (36.0, "Weak"),
    (60.0, "Moderate"),
    (112.0, "Strong"),
    (math.inf, "Very Strong"),
)

_COMMON_PASSWORDS = frozenset(
    {
        "password", "password1", "password123", "passw0rd", "passwd",
        "123456", "1234567", "12345678", "123456789", "1234567890",
        "1234", "12345", "123123", "111111", "000000", "121212", "654321",
        "qwerty", "qwerty123", "qwertyuiop", "azerty",
        "abc123", "abcd1234", "admin", "admin123", "administrator",
        "login", "welcome", "welcome1", "letmein", "iloveyou",
        "monkey", "dragon", "sunshine", "princess", "football",
        "baseball", "superman", "batman", "trustno1", "master",
        "shadow", "michael", "jennifer", "jordan", "harley",
        "ranger", "hunter", "buster", "soccer", "hockey",
        "killer", "george", "andrew", "charlie", "thomas",
        "robert", "access", "secret", "money", "computer",
        "internet", "samsung", "google", "facebook", "youtube",
        "amazon", "netflix", "starwars", "whatever", "freedom",
    }
)

_KEYBOARD_RUNS = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "qwer", "wert", "erty", "asdf", "sdfg", "dfgh",
    "zxcv", "xcvb", "cvbn",
    "1234567890",
    "1qaz2wsx", "2wsx3edc", "!qaz2wsx", "qazwsx", "wsxedc",
)

_PATTERN_WORDS = frozenset(
    {
        "password", "passwd", "passwort", "admin", "qwerty", "welcome",
        "letmein", "iloveyou", "monkey", "dragon", "sunshine",
        "princess", "master", "shadow", "superman", "football",
        "baseball", "login", "user", "secret", "hello", "world",
        "summer", "winter", "spring", "autumn", "freedom", "whatever",
    }
)

_PATTERN_WORD_DIGITS_RE = re.compile(r"([a-z]{3,})\d{1,4}$")
_REPEAT_RUN_RE = re.compile(r"(.)\1{2,}")

_PENALTIES = {
    "common_password": 30.0,
    "common_pattern": 10.0,
    "sequential_characters": 12.0,
    "repeated_characters": 12.0,
    "only_letters": 4.0,
    "only_numbers": 6.0,
    "too_short": 10.0,
}


def _char_stats(password: str) -> dict[str, int]:
    upper = lower = digits = special = non_ascii = 0
    for ch in password:
        if ch.isupper():
            upper += 1
        elif ch.islower():
            lower += 1
        elif ch.isdigit():
            digits += 1
        else:
            special += 1
        if ord(ch) > 127:
            non_ascii += 1
    return {
        "length": len(password),
        "uppercase": upper,
        "lowercase": lower,
        "digits": digits,
        "special": special,
        "non_ascii": non_ascii,
    }


def _has_repeated_run(password: str) -> bool:
    return _REPEAT_RUN_RE.search(password) is not None


def _has_ordinal_sequence(password: str, min_run: int = 4) -> bool:
    text = password.lower()
    if len(text) < min_run:
        return False
    run = 1
    for prev, cur in zip(text, text[1:]):
        delta = ord(cur) - ord(prev)
        if delta in (1, -1):
            run += 1
            if run >= min_run:
                return True
        else:
            run = 1
    return False


def _has_keyboard_sequence(password: str) -> bool:
    text = password.lower()
    return any(run in text or run[::-1] in text for run in _KEYBOARD_RUNS)


def _contains_common_password(password: str) -> bool:
    text = password.lower()
    if text in _COMMON_PASSWORDS:
        return True
    return any(cp in text for cp in _COMMON_PASSWORDS if len(cp) >= 4)


def _matches_common_pattern(password: str) -> bool:
    match = _PATTERN_WORD_DIGITS_RE.search(password.lower())
    return bool(match and match.group(1) in _PATTERN_WORDS)


def _estimate_entropy_bits(stats: dict[str, int]) -> float:
    pool = 0
    if stats["uppercase"]:
        pool += _UPPER_POOL
    if stats["lowercase"]:
        pool += _LOWER_POOL
    if stats["digits"]:
        pool += _DIGIT_POOL
    if stats["special"]:
        pool += _SPECIAL_POOL
    if stats["non_ascii"]:
        pool += _NON_ASCII_POOL
    if pool == 0:
        return 0.0
    effective_length = min(stats["length"], ENTROPY_LENGTH_CAP)
    return effective_length * math.log2(pool)


def _classify_strength(effective_entropy: float) -> tuple[str, int]:
    for index, (threshold, label) in enumerate(_STRENGTH_BANDS):
        if effective_entropy < threshold:
            return label, index
    label, index = _STRENGTH_BANDS[-1][1], len(_STRENGTH_BANDS) - 1
    return label, index


def analyze_password(password: str) -> dict:
    stats = _char_stats(password)
    length = stats["length"]

    checks = {
        "too_short": length < MIN_RECOMMENDED_LENGTH,
        "only_letters": length > 0 and (stats["uppercase"] + stats["lowercase"]) == length,
        "only_numbers": length > 0 and stats["digits"] == length,
        "repeated_characters": _has_repeated_run(password),
        "sequential_characters": (
            _has_ordinal_sequence(password) or _has_keyboard_sequence(password)
        ),
        "common_password": _contains_common_password(password),
        "common_pattern": _matches_common_pattern(password),
    }

    entropy = round(_estimate_entropy_bits(stats), 1)
    penalty = sum(weight for key, weight in _PENALTIES.items() if checks[key])
    effective = max(0.0, entropy - penalty)
    if password.lower() in _COMMON_PASSWORDS:
        effective = min(effective, 10.0)

    label, level = _classify_strength(effective)
    score = round(min(effective, _ENTROPY_SCALE_BITS) / _ENTROPY_SCALE_BITS * 100, 1)

    problems: list[str] = []
    if length == 0:
        problems.append("Enter a password to analyze.")
    if checks["too_short"]:
        problems.append(
            f"Too short - use at least {MIN_RECOMMENDED_LENGTH} characters "
            f"({STRONG_RECOMMENDED_LENGTH}+ recommended)."
        )
    if checks["only_letters"]:
        problems.append("Contains only letters - mix in numbers and symbols.")
    if checks["only_numbers"]:
        problems.append("Contains only numbers - mix in letters and symbols.")
    if checks["repeated_characters"]:
        problems.append("Contains repeated characters (e.g. 'aaa').")
    if checks["sequential_characters"]:
        problems.append("Contains sequential characters (e.g. 'abcd', '1234', 'qwer').")
    if checks["common_password"]:
        problems.append("Matches or contains a well-known common password.")
    if checks["common_pattern"]:
        problems.append("Follows a predictable pattern such as a dictionary word followed by digits (e.g. 'Password123').")

    return {
        "stats": {
            "length": length,
            "uppercase": stats["uppercase"],
            "lowercase": stats["lowercase"],
            "digits": stats["digits"],
            "special": stats["special"],
            "entropy_bits": entropy,
        },
        "strength": {"label": label, "level": level, "score": score},
        "checks": checks,
        "problems": problems,
    }
