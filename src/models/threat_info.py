from datetime import datetime
from typing import Dict, List, Any, Optional

class ThreatInfo:
    """
    Represents threat intelligence information for a network entity.
    Holds data from various threat intelligence sources.
    """
    
    def __init__(
        self,
        entity_id: str,
        entity_value: str,
        entity_type: str
    ):
        """
        Initialize threat intelligence information
        
        Args:
            entity_id: ID of the associated entity
            entity_value: Value of the associated entity (IP, domain, etc.)
            entity_type: Type of the associated entity
        """
        self.entity_id = entity_id
        self.entity_value = entity_value
        self.entity_type = entity_type
        self.query_time = datetime.now()
        self.last_updated = self.query_time
        
        # Threat intelligence data
        self.sources: Dict[str, Dict[str, Any]] = {}
        self.malicious_votes: int = 0
        self.total_votes: int = 0
        self.categories: List[str] = []
        self.tags: List[str] = []
        self.risk_score: float = 0.0  # 0.0 to 1.0
        self.verdict: str = "unknown"  # unknown, clean, suspicious, malicious
        self.summary: str = ""
    
    def add_source_data(self, source_name: str, data: Dict[str, Any]) -> None:
        """
        Add data from a threat intelligence source
        
        Args:
            source_name: Name of the source (e.g., "virustotal")
            data: Source-specific data
        """
        self.sources[source_name] = data
        self.last_updated = datetime.now()
        
        # Update aggregated stats if available in data
        if "malicious" in data:
            self.malicious_votes = data.get("malicious", 0)
        if "total" in data:
            self.total_votes = data.get("total", 0)
        if "categories" in data:
            self.categories.extend([c for c in data.get("categories", []) 
                                   if c not in self.categories])
        if "tags" in data:
            self.tags.extend([t for t in data.get("tags", []) 
                             if t not in self.tags])
    
    def set_risk_score(self, score: float) -> None:
        """
        Set risk score between 0.0 and 1.0
        
        Args:
            score: Risk score (0.0 = safe, 1.0 = high risk)
        """
        self.risk_score = max(0.0, min(1.0, score))
        self.last_updated = datetime.now()
    
    def set_verdict(self, verdict: str) -> None:
        """
        Set verdict based on risk assessment
        
        Args:
            verdict: Risk verdict (unknown, clean, suspicious, malicious)
        """
        valid_verdicts = ["unknown", "clean", "suspicious", "malicious"]
        self.verdict = verdict.lower() if verdict.lower() in valid_verdicts else "unknown"
        self.last_updated = datetime.now()
    
    def set_summary(self, summary: str) -> None:
        """
        Set summary of threat intelligence findings
        
        Args:
            summary: Text summary of findings
        """
        self.summary = summary
        self.last_updated = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert threat info to dictionary for serialization"""
        return {
            "entity_id": self.entity_id,
            "entity_value": self.entity_value,
            "entity_type": self.entity_type,
            "query_time": self.query_time.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "sources": self.sources,
            "malicious_votes": self.malicious_votes,
            "total_votes": self.total_votes,
            "categories": self.categories,
            "tags": self.tags,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "summary": self.summary,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatInfo':
        """Create threat info from dictionary"""
        info = cls(
            entity_id=data["entity_id"],
            entity_value=data["entity_value"],
            entity_type=data["entity_type"]
        )
        
        info.query_time = datetime.fromisoformat(data["query_time"])
        info.last_updated = datetime.fromisoformat(data["last_updated"])
        info.sources = data.get("sources", {})
        info.malicious_votes = data.get("malicious_votes", 0)
        info.total_votes = data.get("total_votes", 0)
        info.categories = data.get("categories", [])
        info.tags = data.get("tags", [])
        info.risk_score = data.get("risk_score", 0.0)
        info.verdict = data.get("verdict", "unknown")
        info.summary = data.get("summary", "")
        
        return info