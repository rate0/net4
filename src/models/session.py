import os
import json
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Set

from .network_entity import NetworkEntity
from .threat_info import ThreatInfo

class Session:
    """
    Represents an analysis session in Net4.
    Contains all data related to the current analysis, including
    loaded files, extracted entities, and analysis results.
    """
    
    def __init__(self, name: Optional[str] = None):
        """Initialize a new analysis session"""
        self.id = str(uuid.uuid4())
        self.name = name or f"Session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.created_at = datetime.now()
        self.last_modified = self.created_at
        
        # Source files
        self.files: Dict[str, Dict[str, Any]] = {}
        
        # Analysis data
        self.network_entities: Dict[str, NetworkEntity] = {}
        self.connections: List[Dict[str, Any]] = []
        self.packets: List[Dict[str, Any]] = []
        self.timeline_events: List[Dict[str, Any]] = []
        
        # Analysis results
        self.ai_insights: List[Dict[str, Any]] = []
        self.threat_intelligence: Dict[str, ThreatInfo] = {}
        self.anomalies: List[Dict[str, Any]] = []
        
        # Session metadata
        self.metadata: Dict[str, Any] = {
            "packet_count": 0,
            "start_time": None,
            "end_time": None,
            "duration": None,
            "protocols": set(),
            "top_talkers": {},
        }
    
    def add_file(self, file_path: str, file_type: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Add a file to the session
        
        Args:
            file_path: Path to the file
            file_type: Type of file (pcap, log, etc.)
            metadata: Additional file metadata
            
        Returns:
            str: File ID
        """
        file_id = str(uuid.uuid4())
        self.files[file_id] = {
            "id": file_id,
            "path": file_path,
            "name": os.path.basename(file_path),
            "type": file_type,
            "added_at": datetime.now(),
            "metadata": metadata or {},
        }
        self.last_modified = datetime.now()
        return file_id
    
    def add_network_entity(self, entity: NetworkEntity) -> None:
        """Add a network entity to the session"""
        self.network_entities[entity.id] = entity
        self.last_modified = datetime.now()
    
    def add_connection(self, connection: Dict[str, Any]) -> None:
        """Add a network connection to the session"""
        self.connections.append(connection)
        self.last_modified = datetime.now()
    
    def add_packet(self, packet: Dict[str, Any]) -> None:
        """Add a packet to the session"""
        self.packets.append(packet)
        self.metadata["packet_count"] += 1
        
        # Update session time range
        timestamp = packet.get("timestamp")
        if timestamp:
            if not self.metadata["start_time"] or timestamp < self.metadata["start_time"]:
                self.metadata["start_time"] = timestamp
            if not self.metadata["end_time"] or timestamp > self.metadata["end_time"]:
                self.metadata["end_time"] = timestamp
        
        # Update protocols
        protocol = packet.get("protocol")
        if protocol:
            self.metadata["protocols"].add(protocol)
        
        # Update timeline
        self.add_timeline_event({
            "timestamp": packet.get("timestamp"),
            "type": "packet",
            "packet_id": len(self.packets) - 1,
            "description": f"{packet.get('src_ip', 'Unknown')} -> {packet.get('dst_ip', 'Unknown')} [{packet.get('protocol', 'Unknown')}]"
        })
        
        self.last_modified = datetime.now()
    
    def add_timeline_event(self, event: Dict[str, Any]) -> None:
        """Add an event to the timeline"""
        self.timeline_events.append(event)
        self.last_modified = datetime.now()
    
    def add_ai_insight(self, insight: Dict[str, Any]) -> None:
        """Add an AI-generated insight to the session"""
        self.ai_insights.append(insight)
        self.last_modified = datetime.now()
    
    def add_threat_intel(self, entity_id: str, threat_info: ThreatInfo) -> None:
        """Add threat intelligence information for an entity"""
        self.threat_intelligence[entity_id] = threat_info
        self.last_modified = datetime.now()
    
    def add_anomaly(self, anomaly: Dict[str, Any]) -> None:
        """Add a detected anomaly to the session"""
        self.anomalies.append(anomaly)
        self.last_modified = datetime.now()
    
    def update_metadata(self) -> None:
        """Update session metadata"""
        if self.metadata["start_time"] and self.metadata["end_time"]:
            self.metadata["duration"] = (
                self.metadata["end_time"] - self.metadata["start_time"]
            ).total_seconds()
            
        # Convert set to list for serialization
        self.metadata["protocols"] = list(self.metadata["protocols"])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for serialization"""
        self.update_metadata()
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "last_modified": self.last_modified.isoformat(),
            "files": list(self.files.values()),
            "network_entities": {k: v.to_dict() for k, v in self.network_entities.items()},
            "connections": self.connections,
            "timeline_events": self.timeline_events,
            "ai_insights": self.ai_insights,
            "threat_intelligence": {k: v.to_dict() for k, v in self.threat_intelligence.items()},
            "anomalies": self.anomalies,
            "metadata": self.metadata,
        }
    
    def save(self, path: str) -> None:
        """Save session to file"""
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load(cls, path: str) -> 'Session':
        """Load session from file"""
        with open(path, 'r') as f:
            data = json.load(f)
        
        session = cls(data.get("name"))
        session.id = data.get("id")
        session.created_at = datetime.fromisoformat(data.get("created_at"))
        session.last_modified = datetime.fromisoformat(data.get("last_modified"))
        
        # Load files
        session.files = {f["id"]: f for f in data.get("files", [])}
        
        # Load network entities
        for entity_id, entity_data in data.get("network_entities", {}).items():
            session.network_entities[entity_id] = NetworkEntity.from_dict(entity_data)
        
        # Load connections
        session.connections = data.get("connections", [])
        
        # Load timeline events
        session.timeline_events = data.get("timeline_events", [])
        
        # Load AI insights
        session.ai_insights = data.get("ai_insights", [])
        
        # Load threat intelligence
        for entity_id, ti_data in data.get("threat_intelligence", {}).items():
            session.threat_intelligence[entity_id] = ThreatInfo.from_dict(ti_data)
        
        # Load anomalies
        session.anomalies = data.get("anomalies", [])
        
        # Load metadata
        session.metadata = data.get("metadata", {})
        
        # Convert protocols back to set
        if "protocols" in session.metadata:
            session.metadata["protocols"] = set(session.metadata["protocols"])
        
        return session