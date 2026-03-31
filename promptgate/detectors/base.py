from __future__ import annotations

from abc import ABC, abstractmethod

from promptgate.result import ScanResult


class BaseDetector(ABC):
    @abstractmethod
    def scan(self, text: str) -> ScanResult: ...
