import pytest

from backend.analyzer import analyze_password


def stats_of(result):
    return result["stats"]


def checks_of(result):
    return result["checks"]


class TestVeryWeak:
    def test_short_numeric_password(self):
        result = analyze_password("1234")
        assert result["strength"]["label"] == "Very Weak"
        assert checks_of(result)["too_short"] is True
        assert checks_of(result)["only_numbers"] is True
        assert checks_of(result)["common_password"] is True
        assert any("Too short" in p for p in result["problems"])
        assert any("only numbers" in p for p in result["problems"])

    def test_common_password_is_very_weak_even_if_long_pool(self):
        result = analyze_password("password")
        assert result["strength"]["label"] == "Very Weak"
        assert checks_of(result)["common_password"] is True


class TestStrong:
    def test_long_mixed_password_is_very_strong(self):
        result = analyze_password("Tr0ub4dor&3xK#9mQzV")
        assert result["strength"]["label"] in ("Strong", "Very Strong")
        assert checks_of(result)["common_password"] is False
        assert checks_of(result)["sequential_characters"] is False
        assert checks_of(result)["repeated_characters"] is False
        assert result["problems"] == []

    def test_entropy_grows_with_length_and_charset(self):
        weak = analyze_password("abc")
        strong = analyze_password("AbCdEf9#")
        assert (
            stats_of(strong)["entropy_bits"] > stats_of(weak)["entropy_bits"]
        )


class TestEmptyInput:
    def test_empty_string(self):
        result = analyze_password("")
        assert stats_of(result)["length"] == 0
        assert stats_of(result)["entropy_bits"] == 0.0
        assert result["strength"]["label"] == "Very Weak"
        assert checks_of(result)["too_short"] is True
        assert checks_of(result)["only_letters"] is False
        assert checks_of(result)["only_numbers"] is False


class TestVeryLongInput:
    def test_huge_password_does_not_break_analysis(self):
        password = "aB3!" * 300
        result = analyze_password(password)
        assert stats_of(result)["length"] == 1200
        assert result["strength"]["label"] == "Very Strong"

    def test_entropy_is_capped_for_extreme_lengths(self):
        huge = "xY3$" * 5000
        capped = "xY3$"
        assert (
            stats_of(analyze_password(huge))["entropy_bits"]
            >= stats_of(analyze_password(capped))["entropy_bits"]
        )
        assert stats_of(analyze_password(huge))["entropy_bits"] <= 128.0 * 8 + 1e6


class TestCharacterCounts:
    def test_counts_each_class(self):
        result = analyze_password("Abc123!@#")
        stats = stats_of(result)
        assert stats["length"] == 9
        assert stats["uppercase"] == 1
        assert stats["lowercase"] == 2
        assert stats["digits"] == 3
        assert stats["special"] == 3

    def test_spaces_counted_as_special(self):
        result = analyze_password("a b c")
        assert stats_of(result)["special"] == 2


class TestRepeatedCharacters:
    def test_three_in_a_row_detected(self):
        result = analyze_password("Zqaaa!9xLm")
        assert checks_of(result)["repeated_characters"] is True

    def test_two_in_a_row_not_flagged(self):
        result = analyze_password("Zqaa!9xLm2B")
        assert checks_of(result)["repeated_characters"] is False


class TestSequentialCharacters:
    def test_alphabet_sequence(self):
        assert checks_of(analyze_password("Xyabcd!7Qz"))["sequential_characters"] is True

    def test_numeric_sequence(self):
        assert checks_of(analyze_password("Zt91234!aB"))["sequential_characters"] is True

    def test_descending_sequence(self):
        assert checks_of(analyze_password("X9876abQ!"))["sequential_characters"] is True

    def test_keyboard_row(self):
        assert checks_of(analyze_password("Mmqwerty5!Z"))["sequential_characters"] is True

    def test_random_text_not_flagged(self):
        assert checks_of(analyze_password("Tzq9!mL4Xp"))["sequential_characters"] is False


class TestCommonPasswordsAndPatterns:
    @pytest.mark.parametrize(
        "password",
        ["password", "123456", "qwerty", "admin", "letmein", "iloveyou"],
    )
    def test_exact_common_passwords(self, password):
        assert checks_of(analyze_password(password))["common_password"] is True

    def test_common_password_as_substring(self):
        assert checks_of(analyze_password("MyAdmin2026!"))["common_password"] is True

    def test_word_plus_digits_pattern(self):
        result = analyze_password("Password123")
        assert checks_of(result)["common_pattern"] is True
        assert checks_of(result)["common_password"] is True

    def test_unrelated_mixed_password_not_flagged(self):
        result = analyze_password("Gv7$kPq2#Wzn")
        assert checks_of(result)["common_password"] is False
        assert checks_of(result)["common_pattern"] is False


class TestUnicode:
    def test_unicode_characters_analyzed(self):
        result = analyze_password("Pässwörd€✓Ünïcode9")
        stats = stats_of(result)
        assert stats["length"] == len("Pässwörd€✓Ünïcode9")
        assert stats["entropy_bits"] > 0
        assert result["strength"]["level"] >= 3

    def test_cjk_characters_do_not_crash(self):
        result = analyze_password("密码测试123456")
        assert stats_of(result)["length"] == 10
        assert isinstance(result["strength"]["score"], float)


class TestOnlyLettersAndNumbers:
    def test_only_letters(self):
        result = analyze_password("abcdefghij")
        assert checks_of(result)["only_letters"] is True
        assert any("Contains only letters" in p for p in result["problems"])

    def test_mixed_not_flagged_as_only_letters(self):
        result = analyze_password("abcdefghi1")
        assert checks_of(result)["only_letters"] is False
