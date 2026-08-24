import string

import pytest
from pydantic import ValidationError

from backend.generator import CHARSETS, generate_password


def test_default_generation_returns_requested_length():
    password = generate_password(length=24)
    assert len(password) == 24


@pytest.mark.parametrize("length", [4, 8, 16, 32, 64, 128])
def test_various_lengths(length):
    assert len(generate_password(length=length)) == length


def test_all_charsets_represented():
    password = generate_password(length=64)
    assert any(c.isupper() for c in password)
    assert any(c.islower() for c in password)
    assert any(c.isdigit() for c in password)
    assert any(c in CHARSETS["special"] for c in password)


def test_only_lowercase_when_others_disabled():
    password = generate_password(length=40, uppercase=False, numbers=False, special=False)
    assert all(c in string.ascii_lowercase for c in password)


def test_only_uppercase_and_digits():
    password = generate_password(
        length=30, lowercase=False, special=False, uppercase=True, numbers=True
    )
    allowed = set(string.ascii_uppercase + string.digits)
    assert all(c in allowed for c in password)
    assert any(c.isdigit() for c in password)
    assert any(c.isupper() for c in password)


def test_minimum_length_equals_number_of_sets():
    password = generate_password(length=4)
    assert len(password) == 4
    assert any(c.isupper() for c in password)
    assert any(c.islower() for c in password)
    assert any(c.isdigit() for c in password)
    assert any(c in CHARSETS["special"] for c in password)


def test_generation_is_nondeterministic():
    pool = {generate_password(length=32) for _ in range(20)}
    assert len(pool) > 1


def test_rejects_length_below_minimum():
    with pytest.raises(ValueError):
        generate_password(length=3)


def test_request_model_rejects_out_of_range_lengths():
    with pytest.raises(ValidationError):
        GenerateRequestFactory(length=3)
    with pytest.raises(ValidationError):
        GenerateRequestFactory(length=129)


def test_request_model_requires_at_least_one_charset():
    with pytest.raises(ValidationError):
        GenerateRequestFactory(uppercase=False, lowercase=False, numbers=False, special=False)


def test_module_does_not_use_insecure_randomness():
    import inspect

    from backend import generator

    source = inspect.getsource(generator)
    assert "import random" not in source
    assert "random." not in source.replace("secrets.", "")
    assert "secrets" in source


class GenerateRequestFactory:
    def __init__(self, **kwargs):
        from backend.schemas import GenerateRequest

        defaults = dict(
            length=16, uppercase=True, lowercase=True, numbers=True, special=True
        )
        defaults.update(kwargs)
        self._model = GenerateRequest(**defaults)

    def __getattr__(self, name):
        return getattr(self._model, name)
