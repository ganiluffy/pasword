from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from backend.analyzer import MAX_INPUT_LENGTH
from backend.generator import (
    DEFAULT_GENERATED_LENGTH,
    MAX_GENERATED_LENGTH,
    MIN_GENERATED_LENGTH,
)


class AnalyzeRequest(BaseModel):
    password: str = Field(
        ...,
        max_length=MAX_INPUT_LENGTH,
        description="Password to analyze. Never logged or persisted.",
    )


class StrengthInfo(BaseModel):
    label: str
    level: int
    score: float


class PasswordStats(BaseModel):
    length: int
    uppercase: int
    lowercase: int
    digits: int
    special: int
    entropy_bits: float


class SecurityChecks(BaseModel):
    too_short: bool
    only_letters: bool
    only_numbers: bool
    repeated_characters: bool
    sequential_characters: bool
    common_password: bool
    common_pattern: bool


class AnalysisResponse(BaseModel):
    stats: PasswordStats
    strength: StrengthInfo
    checks: SecurityChecks
    problems: list[str]


class GenerateRequest(BaseModel):
    length: int = Field(
        DEFAULT_GENERATED_LENGTH,
        ge=MIN_GENERATED_LENGTH,
        le=MAX_GENERATED_LENGTH,
    )
    uppercase: bool = True
    lowercase: bool = True
    numbers: bool = True
    special: bool = True

    @model_validator(mode="after")
    def _require_at_least_one_charset(self) -> "GenerateRequest":
        if not (self.uppercase or self.lowercase or self.numbers or self.special):
            raise ValueError("At least one character set must be enabled.")
        return self


class GeneratedPasswordResponse(BaseModel):
    password: str
    length: int


class HealthResponse(BaseModel):
    status: str
