from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any, Dict, List, Optional

REQUIRED_FIELDS = ("id", "source", "title", "severity")


@dataclass
class NormalizedAlert:
    # Identity & core
    id: str
    source: str
    title: str
    severity: str
    description: str = ""
    timestamp: Optional[str] = None
    link: Optional[str] = None
    hostname: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    # Source extras
    code: Optional[str] = None
    score: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Enrichment
    playbook_url: Optional[str] = None
    host_context: Optional[Dict[str, Any]] = None
    enrichment_context: Optional[Dict[str, Any]] = None

    # Ticket tracking
    ticket_id: Optional[str] = None
    ticket_url: Optional[str] = None
    assignee: Optional[str] = None
    enriched: bool = False
    enrichment_attempted_at: Optional[str] = None

    # AI analysis
    ai_analyzed: bool = False
    ai_severity: Optional[str] = None
    ai_false_positive_score: Optional[float] = None
    ai_recommendation: Optional[str] = None
    ai_summary: Optional[str] = None
    ai_questions_for_soc: List[str] = field(default_factory=list)
    ai_iocs: List[str] = field(default_factory=list)
    ai_model: Optional[str] = None
    ai_cost_usd: Optional[float] = None

    # Investigation agent
    investigation_attempted: bool = False
    investigation_disposition: Optional[str] = None
    investigation_confidence: Optional[float] = None
    investigation_summary: Optional[str] = None
    investigation_recommendation: Optional[str] = None
    investigation_evidence: List[str] = field(default_factory=list)
    investigation_iocs: List[str] = field(default_factory=list)
    investigation_tools_used: List[str] = field(default_factory=list)
    investigation_cost_usd: Optional[float] = None
    investigation_iterations: Optional[int] = None

    def __post_init__(self) -> None:
        missing = [name for name in REQUIRED_FIELDS if not getattr(self, name)]
        if missing:
            raise ValueError(f"NormalizedAlert missing required fields: {missing}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_store_dict(self) -> Dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NormalizedAlert":
        known = {f.name for f in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})

    def enrich_with_playbook(self, playbook_url: Optional[str]) -> "NormalizedAlert":
        if playbook_url:
            self.playbook_url = playbook_url
        return self
