from __future__ import annotations

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True)
class ScanResult:
    """Result returned by PromptGate.scan() and related methods.

    Attributes:
        is_safe:      True when risk_score is strictly below the sensitivity threshold
                      (low=0.8, medium=0.5, high=0.3).  False means the input should
                      be treated as a potential attack.

        risk_score:   Aggregate risk score in [0.0, 1.0], calculated in three tiers:
                      Tier 1 — immediate block: if a critical threat (direct_injection,
                        jailbreak) exceeds immediate_block_score (default 0.85), the
                        raw detector score is returned immediately without further
                        aggregation.
                      Tier 2 — severity-adjusted max: each detector's score is
                        multiplied by the highest threat-severity coefficient among its
                        detected threats (direct_injection=1.0, jailbreak=0.95, …,
                        prompt_leaking=0.75), then the maximum across all detectors is
                        taken as the base score.
                      Tier 3 — corroboration boost: when two or more detectors
                        independently detect the same threat type, a boost of 0.08 per
                        additional detector is added (capped at +0.15).

        threats:      Tuple of detected threat category labels, e.g.
                      ("direct_injection",), ("jailbreak", "data_exfiltration").
                      Threat labels: direct_injection, jailbreak, data_exfiltration,
                      indirect_injection, prompt_leaking, prompt_injection (classifier
                      binary label), credential_leak, pii_leak, system_prompt_leak.

        explanation:  Human-readable summary of the scan result.  Format varies by
                      detector:
                      rule     — "Threats detected: direct_injection (score=0.80)"
                      embedding — "Embedding similarity 0.78 to exemplar …"
                      classifier — "Attack probability: 0.91"
                      llm_judge — free-form reason from the LLM
                      Multiple detectors are joined with " / ".

        detector_used: Name(s) of the detector(s) that contributed to the result,
                      joined with "+", e.g. "rule", "rule+embedding",
                      "rule+embedding+llm_judge".  An empty string means no detectors
                      ran (e.g. empty input).

        latency_ms:   End-to-end scan latency in milliseconds, measured from the
                      start of scan() / scan_async() to the returned result.
    """

    is_safe: bool
    risk_score: float
    threats: Tuple[str, ...] = field(default_factory=tuple)
    explanation: str = ""
    detector_used: str = ""
    latency_ms: float = 0.0

    def __post_init__(self) -> None:
        if not isinstance(self.threats, tuple):
            object.__setattr__(self, "threats", tuple(self.threats))
