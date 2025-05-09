from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any
import uuid


@dataclass
class Event:
    """Unified event object used across Net4 (packets, logs, alerts)."""

    timestamp: datetime
    source: str  # subsystem that produced event (pcap, log, correlation)
    category: str  # e.g., network, auth, anomaly
    description: str
    data: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @classmethod
    def from_packet(cls, packet: Dict[str, Any]) -> "Event":
        """Create Event from a decoded packet dictionary."""
        ts = packet.get("timestamp", datetime.now())
        proto = packet.get("protocol", "")
        src = packet.get("src_ip", "?")
        dst = packet.get("dst_ip", "?")
        desc = f"{src} → {dst} [{proto}]"
        return cls(timestamp=ts, source="pcap", category="network", description=desc, data=packet)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "category": self.category,
            "description": self.description,
            "data": self.data,
        } 