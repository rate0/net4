import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Literal

class NetworkEntity:
    """
    Represents a network entity discovered during analysis.
    This can be an IP address, domain, URL, hash, etc.
    """
    
    # Valid entity types
    ENTITY_TYPES = Literal[
        "ip", "domain", "url", "hash", "email", "file", "user", "process", "other"
    ]
    
    def __init__(
        self, 
        entity_type: ENTITY_TYPES,
        value: str,
        name: Optional[str] = None,
        entity_id: Optional[str] = None
    ):
        """
        Initialize a network entity
        
        Args:
            entity_type: Type of the entity (ip, domain, etc.)
            value: Entity value (e.g., IP address, domain name)
            name: Optional display name
            entity_id: Optional ID (generated if not provided)
        """
        self.id = entity_id or str(uuid.uuid4())
        self.type = entity_type
        self.value = value
        self.name = name or value
        self.created_at = datetime.now()
        self.modified_at = self.created_at
        
        # Analysis data
        self.attributes: Dict[str, Any] = {}
        self.related_entities: List[str] = []  # IDs of related entities
        self.tags: List[str] = []
        self.threat_level: str = "unknown"  # unknown, safe, suspicious, malicious
        self.confidence: float = 0.0  # 0.0 to 1.0
        self.notes: str = ""
        
        # Temporal data
        self.first_seen: datetime = self.created_at
        self.last_seen: datetime = self.created_at
    
    def add_attribute(self, key: str, value: Any) -> None:
        """Add or update an entity attribute"""
        self.attributes[key] = value
        self.modified_at = datetime.now()
    
    def add_related_entity(self, entity_id: str) -> None:
        """Add a related entity by ID"""
        if entity_id not in self.related_entities:
            self.related_entities.append(entity_id)
            self.modified_at = datetime.now()
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to the entity"""
        if tag not in self.tags:
            self.tags.append(tag)
            self.modified_at = datetime.now()
    
    def set_threat_level(self, level: str, confidence: float = 0.0) -> None:
        """
        Set threat level with confidence score
        
        Args:
            level: Threat level (unknown, safe, suspicious, malicious)
            confidence: Confidence score (0.0 to 1.0)
        """
        self.threat_level = level.lower()
        self.confidence = max(0.0, min(1.0, confidence))  # Clamp to 0.0-1.0
        self.modified_at = datetime.now()
    
    def set_notes(self, notes: str) -> None:
        """Set notes for the entity"""
        self.notes = notes
        self.modified_at = datetime.now()
    
    def update_seen_time(self, timestamp: Optional[datetime] = None) -> None:
        """
        Update the last_seen time for this entity and 
        update first_seen if earlier than current value
        
        Args:
            timestamp: Timestamp to use (current time if None)
        """
        if timestamp is None:
            timestamp = datetime.now()
            
        self.last_seen = timestamp
        
        # Update first_seen if this is earlier
        if self.first_seen > timestamp:
            self.first_seen = timestamp
            
        self.modified_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entity to dictionary for serialization"""
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "modified_at": self.modified_at.isoformat(),
            "attributes": self.attributes,
            "related_entities": self.related_entities,
            "tags": self.tags,
            "threat_level": self.threat_level,
            "confidence": self.confidence,
            "notes": self.notes,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NetworkEntity':
        """Create entity from dictionary"""
        entity = cls(
            entity_type=data["type"],
            value=data["value"],
            name=data.get("name"),
            entity_id=data.get("id")
        )
        
        entity.created_at = datetime.fromisoformat(data["created_at"])
        entity.modified_at = datetime.fromisoformat(data["modified_at"])
        entity.attributes = data.get("attributes", {})
        entity.related_entities = data.get("related_entities", [])
        entity.tags = data.get("tags", [])
        entity.threat_level = data.get("threat_level", "unknown")
        entity.confidence = data.get("confidence", 0.0)
        entity.notes = data.get("notes", "")
        
        # Set temporal data if available
        if "first_seen" in data:
            entity.first_seen = datetime.fromisoformat(data["first_seen"])
        if "last_seen" in data:
            entity.last_seen = datetime.fromisoformat(data["last_seen"])
        
        return entity