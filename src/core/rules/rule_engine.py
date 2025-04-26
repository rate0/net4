import re
import os
import yaml
import json
from typing import Dict, List, Any, Optional, Union, Pattern
from datetime import datetime
import ipaddress

from ...utils.logger import Logger
from ...models.session import Session


class Rule:
    """
    Represents a detection rule for network traffic analysis.
    Similar to Suricata/Snort rule format but simplified and optimized for Net4.
    """
    
    def __init__(self, 
                 rule_id: str,
                 name: str,
                 description: str,
                 severity: str = "medium",
                 conditions: Dict[str, Any] = None,
                 actions: Dict[str, Any] = None,
                 enabled: bool = True,
                 category: str = "custom",
                 tags: List[str] = None):
        """
        Initialize rule
        
        Args:
            rule_id: Unique identifier
            name: Rule name
            description: Rule description
            severity: Severity level (low, medium, high)
            conditions: Conditions for rule to match
            actions: Actions to take when rule matches
            enabled: Whether rule is enabled
            category: Rule category
            tags: List of tags
        """
        self.id = rule_id
        self.name = name
        self.description = description
        self.severity = severity.lower()
        self.conditions = conditions or {}
        self.actions = actions or {}
        self.enabled = enabled
        self.category = category
        self.tags = tags or []
        self.created_at = datetime.now()
        self.modified_at = self.created_at
        self.last_match = None
        self.match_count = 0
        
        # Compiled patterns for performance
        self._compiled_patterns: Dict[str, Pattern] = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance"""
        for field, condition in self.conditions.items():
            if isinstance(condition, dict) and condition.get('regex'):
                try:
                    pattern = condition.get('regex')
                    self._compiled_patterns[field] = re.compile(pattern, re.IGNORECASE)
                except Exception as e:
                    Logger().get_logger().error(f"Error compiling regex pattern for rule {self.id}: {e}")
    
    def match(self, data: Dict[str, Any]) -> bool:
        """
        Check if data matches rule conditions
        
        Args:
            data: Data to check against rule conditions
            
        Returns:
            True if data matches rule conditions, False otherwise
        """
        if not self.enabled:
            return False
        
        # Check all conditions
        for field, condition in self.conditions.items():
            # Handle nested fields (e.g., "http.host")
            field_value = self._get_nested_field(data, field)
            
            # Skip if field doesn't exist in data
            if field_value is None:
                return False
            
            # Process different condition types
            if isinstance(condition, dict):
                # Regex condition
                if 'regex' in condition:
                    pattern = self._compiled_patterns.get(field)
                    if not pattern:
                        try:
                            pattern = re.compile(condition['regex'], re.IGNORECASE)
                            self._compiled_patterns[field] = pattern
                        except Exception:
                            return False
                    
                    if isinstance(field_value, str):
                        if not pattern.search(field_value):
                            return False
                    else:
                        return False
                
                # Numeric comparison
                elif any(op in condition for op in ['eq', 'neq', 'lt', 'lte', 'gt', 'gte']):
                    if not self._check_numeric_condition(field_value, condition):
                        return False
                
                # IP address conditions
                elif any(op in condition for op in ['ip_in_range', 'ip_in_subnet']):
                    if not self._check_ip_condition(field_value, condition):
                        return False
                
                # List membership
                elif 'in' in condition:
                    if field_value not in condition['in']:
                        return False
                
                # List exclusion
                elif 'not_in' in condition:
                    if field_value in condition['not_in']:
                        return False
            
            # Simple equality check
            elif field_value != condition:
                return False
        
        # If we get here, all conditions have matched
        self.match_count += 1
        self.last_match = datetime.now()
        return True
    
    def _get_nested_field(self, data: Dict[str, Any], field_path: str) -> Any:
        """
        Get value from nested dictionary using dot notation
        
        Args:
            data: Dictionary to extract value from
            field_path: Field path with dot notation (e.g., "http.host")
            
        Returns:
            Field value or None if not found
        """
        parts = field_path.split('.')
        current = data
        
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        
        return current
    
    def _check_numeric_condition(self, value: Union[int, float], condition: Dict[str, Any]) -> bool:
        """
        Check numeric conditions
        
        Args:
            value: Value to check
            condition: Condition dictionary
            
        Returns:
            True if condition is met, False otherwise
        """
        if not isinstance(value, (int, float)):
            try:
                value = float(value)
            except (ValueError, TypeError):
                return False
        
        if 'eq' in condition and value != condition['eq']:
            return False
        if 'neq' in condition and value == condition['neq']:
            return False
        if 'lt' in condition and value >= condition['lt']:
            return False
        if 'lte' in condition and value > condition['lte']:
            return False
        if 'gt' in condition and value <= condition['gt']:
            return False
        if 'gte' in condition and value < condition['gte']:
            return False
        
        return True
    
    def _check_ip_condition(self, value: str, condition: Dict[str, Any]) -> bool:
        """
        Check IP address conditions
        
        Args:
            value: IP address to check
            condition: Condition dictionary
            
        Returns:
            True if condition is met, False otherwise
        """
        if not isinstance(value, str):
            return False
        
        try:
            ip_obj = ipaddress.ip_address(value)
            
            if 'ip_in_range' in condition:
                range_start, range_end = condition['ip_in_range']
                start_ip = ipaddress.ip_address(range_start)
                end_ip = ipaddress.ip_address(range_end)
                return start_ip <= ip_obj <= end_ip
            
            if 'ip_in_subnet' in condition:
                subnet = ipaddress.ip_network(condition['ip_in_subnet'])
                return ip_obj in subnet
            
        except ValueError:
            return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary for serialization"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "conditions": self.conditions,
            "actions": self.actions,
            "enabled": self.enabled,
            "category": self.category,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            "modified_at": self.modified_at.isoformat(),
            "match_count": self.match_count,
            "last_match": self.last_match.isoformat() if self.last_match else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Rule':
        """Create rule from dictionary"""
        rule = cls(
            rule_id=data["id"],
            name=data["name"],
            description=data["description"],
            severity=data["severity"],
            conditions=data.get("conditions", {}),
            actions=data.get("actions", {}),
            enabled=data.get("enabled", True),
            category=data.get("category", "custom"),
            tags=data.get("tags", [])
        )
        
        if "created_at" in data:
            rule.created_at = datetime.fromisoformat(data["created_at"])
        
        if "modified_at" in data:
            rule.modified_at = datetime.fromisoformat(data["modified_at"])
        
        rule.match_count = data.get("match_count", 0)
        
        if "last_match" in data and data["last_match"]:
            rule.last_match = datetime.fromisoformat(data["last_match"])
        
        return rule


class RuleEngine:
    """
    Engine for loading, managing, and evaluating network detection rules.
    """
    
    def __init__(self, rules_dir: str = None):
        """
        Initialize rule engine
        
        Args:
            rules_dir: Directory containing rule files (YAML/JSON)
        """
        self.logger = Logger().get_logger()
        self.rules_dir = rules_dir or os.path.join(os.path.expanduser("~"), ".net4", "rules")
        self.rules: Dict[str, Rule] = {}
        self.default_rules_loaded = False
        
        # Ensure rules directory exists
        os.makedirs(self.rules_dir, exist_ok=True)
    
    def load_rules(self) -> None:
        """Load all rules from rules directory"""
        # First load default rules if not loaded yet
        if not self.default_rules_loaded:
            self._load_default_rules()
            self.default_rules_loaded = True
        
        # Then load user rules
        rule_files = []
        for ext in ['.yml', '.yaml', '.json']:
            rule_files.extend([f for f in os.listdir(self.rules_dir) if f.endswith(ext)])
        
        for filename in rule_files:
            file_path = os.path.join(self.rules_dir, filename)
            self._load_rule_file(file_path)
            
        self.logger.info(f"Loaded {len(self.rules)} rules")
    
    def _load_default_rules(self) -> None:
        """Load default built-in rules"""
        # Define some default rules programmatically
        default_rules = [
            Rule(
                rule_id="default:scanner:port_scan",
                name="Port Scanning Detection",
                description="Detects potential port scanning activity",
                severity="medium",
                conditions={
                    "src_ip": {"exists": True},
                    "dst_port_count": {"gt": 10}
                },
                actions={
                    "add_entity_tag": "scanner",
                    "set_threat_level": "suspicious"
                },
                category="reconnaissance",
                tags=["scanner", "reconnaissance"]
            ),
            Rule(
                rule_id="default:malware:c2_beacon",
                name="Potential C2 Beaconing Activity",
                description="Detects regular communication patterns indicative of C2 beaconing",
                severity="high",
                conditions={
                    "timing_pattern": {"eq": "regular"},
                    "interval_variance": {"lt": 0.1},
                    "connection_count": {"gt": 5}
                },
                actions={
                    "add_entity_tag": "c2_beacon",
                    "set_threat_level": "malicious",
                    "alert": True
                },
                category="command_and_control",
                tags=["malware", "c2", "beacon"]
            ),
            Rule(
                rule_id="default:exfil:large_transfer",
                name="Large Data Transfer",
                description="Detects unusually large data transfers that could indicate exfiltration",
                severity="medium",
                conditions={
                    "byte_count": {"gt": 10000000},  # 10 MB
                    "duration": {"lt": 60}  # Less than 60 seconds
                },
                actions={
                    "add_entity_tag": "data_exfil",
                    "add_anomaly": {
                        "type": "data_exfiltration",
                        "subtype": "large_transfer"
                    }
                },
                category="exfiltration",
                tags=["exfiltration", "data_loss"]
            ),
            Rule(
                rule_id="default:policy:dns_over_tcp",
                name="DNS Over Non-standard Port",
                description="Detects DNS traffic over non-standard ports, potential DNS tunneling",
                severity="medium",
                conditions={
                    "protocol": "DNS",
                    "dst_port": {"not_in": [53, 853]}
                },
                actions={
                    "add_entity_tag": "dns_tunneling",
                    "add_anomaly": {
                        "type": "dns_anomaly",
                        "subtype": "non_standard_port"
                    }
                },
                category="command_and_control",
                tags=["dns", "tunneling", "evasion"]
            )
        ]
        
        # Add default rules to rule set
        for rule in default_rules:
            self.rules[rule.id] = rule
    
    def _load_rule_file(self, file_path: str) -> None:
        """
        Load rules from a file
        
        Args:
            file_path: Path to rule file (YAML/JSON)
        """
        try:
            with open(file_path, 'r') as f:
                if file_path.endswith(('.yml', '.yaml')):
                    rules_data = yaml.safe_load(f)
                else:  # JSON
                    rules_data = json.load(f)
            
            # Handle single rule or list of rules
            if isinstance(rules_data, list):
                for rule_data in rules_data:
                    try:
                        rule = Rule.from_dict(rule_data)
                        self.rules[rule.id] = rule
                    except Exception as e:
                        self.logger.error(f"Error loading rule from {file_path}: {e}")
            elif isinstance(rules_data, dict):
                try:
                    rule = Rule.from_dict(rules_data)
                    self.rules[rule.id] = rule
                except Exception as e:
                    self.logger.error(f"Error loading rule from {file_path}: {e}")
            
        except Exception as e:
            self.logger.error(f"Error loading rules from {file_path}: {e}")
    
    def save_rule(self, rule: Rule) -> bool:
        """
        Save a rule to file
        
        Args:
            rule: Rule to save
            
        Returns:
            True if saved successfully, False otherwise
        """
        # Update rule
        rule.modified_at = datetime.now()
        self.rules[rule.id] = rule
        
        # Save to file
        try:
            file_path = os.path.join(self.rules_dir, f"{rule.id.replace(':', '_')}.yaml")
            with open(file_path, 'w') as f:
                yaml.dump(rule.to_dict(), f, default_flow_style=False)
            return True
        except Exception as e:
            self.logger.error(f"Error saving rule {rule.id}: {e}")
            return False
    
    def delete_rule(self, rule_id: str) -> bool:
        """
        Delete a rule
        
        Args:
            rule_id: ID of rule to delete
            
        Returns:
            True if deleted successfully, False otherwise
        """
        if rule_id not in self.rules:
            return False
        
        # Remove from memory
        rule = self.rules.pop(rule_id)
        
        # Remove file if it's a user rule
        if not rule_id.startswith("default:"):
            try:
                file_path = os.path.join(self.rules_dir, f"{rule_id.replace(':', '_')}.yaml")
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                self.logger.error(f"Error deleting rule file for {rule_id}: {e}")
                # Still return True since the rule was removed from memory
        
        return True
    
    def get_rules(self, category: Optional[str] = None, enabled_only: bool = False) -> List[Rule]:
        """
        Get rules, optionally filtered
        
        Args:
            category: Filter by category
            enabled_only: Only return enabled rules
            
        Returns:
            List of rules
        """
        filtered_rules = list(self.rules.values())
        
        if category:
            filtered_rules = [r for r in filtered_rules if r.category == category]
        
        if enabled_only:
            filtered_rules = [r for r in filtered_rules if r.enabled]
        
        return filtered_rules
    
    def evaluate_connection(self, connection: Dict[str, Any]) -> List[Rule]:
        """
        Evaluate connection against all rules
        
        Args:
            connection: Connection data
            
        Returns:
            List of rules that matched
        """
        matches = []
        
        for rule in self.get_rules(enabled_only=True):
            if rule.match(connection):
                matches.append(rule)
                
                # Apply actions
                if rule.actions.get("set_threat_level"):
                    # This would need to be handled by the caller
                    pass
                
                if rule.actions.get("add_entity_tag"):
                    # This would need to be handled by the caller
                    pass
        
        return matches
    
    def evaluate_session(self, session: Session) -> Dict[str, List[Dict[str, Any]]]:
        """
        Evaluate all connections in a session against rules
        
        Args:
            session: Analysis session
            
        Returns:
            Dictionary of rule matches by connection
        """
        results = {
            "matches": [],
            "stats": {
                "total_connections": len(session.connections),
                "connections_matched": 0,
                "total_matches": 0,
                "rules_triggered": set()
            }
        }
        
        # Process each connection
        for conn in session.connections:
            conn_matches = self.evaluate_connection(conn)
            
            if conn_matches:
                results["stats"]["connections_matched"] += 1
                results["stats"]["total_matches"] += len(conn_matches)
                
                for rule in conn_matches:
                    results["stats"]["rules_triggered"].add(rule.id)
                    
                    # Add match details
                    match_info = {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "severity": rule.severity,
                        "connection": {
                            "src_ip": conn.get("src_ip"),
                            "dst_ip": conn.get("dst_ip"),
                            "src_port": conn.get("src_port"),
                            "dst_port": conn.get("dst_port"),
                            "protocol": conn.get("protocol"),
                            "timestamp": conn.get("timestamp").isoformat() if conn.get("timestamp") else None
                        },
                        "actions": rule.actions,
                        "matched_at": datetime.now().isoformat()
                    }
                    
                    results["matches"].append(match_info)
                    
                    # Add match to session
                    session.add_rule_match(match_info)
                    
                    # Apply actions
                    self._apply_rule_actions(rule, conn, session)
        
        # Convert stats rule_triggered to list for serialization
        results["stats"]["rules_triggered"] = list(results["stats"]["rules_triggered"])
        results["stats"]["unique_rules_triggered"] = len(results["stats"]["rules_triggered"])
        
        return results
    
    def _apply_rule_actions(self, rule: Rule, connection: Dict[str, Any], session: Session) -> None:
        """
        Apply rule actions to the session
        
        Args:
            rule: Rule that matched
            connection: Connection data
            session: Session to apply actions to
        """
        actions = rule.actions
        
        # Set threat level for entities
        if "set_threat_level" in actions:
            threat_level = actions["set_threat_level"]
            confidence = 0.8  # High confidence for rule-based detection
            
            # Apply to relevant entities
            for entity_type in ["src_ip", "dst_ip", "domain"]:
                entity_value = connection.get(entity_type)
                if entity_value:
                    # Find entity in session
                    for entity in session.network_entities.values():
                        if entity.value == entity_value:
                            entity.set_threat_level(threat_level, confidence)
        
        # Add tags to entities
        if "add_entity_tag" in actions:
            tags = actions["add_entity_tag"]
            if isinstance(tags, str):
                tags = [tags]
            
            # Apply to relevant entities
            for entity_type in ["src_ip", "dst_ip", "domain"]:
                entity_value = connection.get(entity_type)
                if entity_value:
                    # Find entity in session
                    for entity in session.network_entities.values():
                        if entity.value == entity_value:
                            for tag in tags:
                                entity.add_tag(tag)
        
        # Add anomaly to session
        if "add_anomaly" in actions:
            anomaly_data = actions["add_anomaly"]
            if isinstance(anomaly_data, dict):
                # Add connection details to anomaly
                anomaly = anomaly_data.copy()
                anomaly.update({
                    "source_ip": connection.get("src_ip"),
                    "destination_ip": connection.get("dst_ip"),
                    "protocol": connection.get("protocol"),
                    "timestamp": datetime.now(),
                    "severity": rule.severity,
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "description": rule.description
                })
                
                # Add anomaly to session
                session.add_anomaly(anomaly)