from __future__ import annotations

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True)
class ScanResult:
    is_safe: bool
    risk_score: float
    threats: Tuple[str, ...] = field(default_factory=tuple)
    explanation: str = ""
    detector_used: str = ""
    latency_ms: float = 0.0

    def __post_init__(self) -> None:
        if not isinstance(self.threats, tuple):
            object.__setattr__(self, "threats", tuple(self.threats))
