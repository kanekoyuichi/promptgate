from dataclasses import dataclass, field


@dataclass
class ScanResult:
    is_safe: bool
    risk_score: float
    threats: list[str] = field(default_factory=list)
    explanation: str = ""
    detector_used: str = ""
    latency_ms: float = 0.0
