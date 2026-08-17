"""Common provider interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Provider(ABC):
    name: str
    weight: float

    def __init__(self, api_key: str, timeout: float = 10.0) -> None:
        self.api_key = api_key
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    @abstractmethod
    def lookup(self, ip: str) -> dict[str, Any]:
        """Return provider data including a normalized score from 0 to 100."""

    def disabled_result(self) -> dict[str, Any]:
        return {"status": "not_configured", "provider": self.name}


