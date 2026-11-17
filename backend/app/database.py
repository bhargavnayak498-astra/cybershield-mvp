from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=5, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url_input(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("URL is required.")
        return value


class ScanResult(BaseModel):
    id: str
    url: str
    normalized_url: str
    redacted_url: str
    hash: str
    score: int
    verdict: Literal["Safe", "Suspicious", "Phishing", "Unknown"]
    reasons: list[str]
    model_status: dict[str, Any]
    source: str = "manual"
    timestamp: str


class ScanListResponse(BaseModel):
    items: list[ScanResult]
    total: int
    page: int
    limit: int


class FeedbackRequest(BaseModel):
    scan_id: str
    label: Literal["false_positive", "false_negative", "helpful"]
    note: str | None = None
