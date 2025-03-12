import re
import ipaddress
from typing import Dict, List, Any, Set, Optional

from ...models.session import Session
from ...models.network_entity import NetworkEntity
from ...utils.logger import Logger

class ThreatClassifier:
    """
    Classifies network entities based on various criteria and
    assigns risk levels based on threat intelligence data and
    heuristic rules.
    """
    
    # Risk levels
    RISK_LEVELS = {
        "malicious": 3,    # Confirmed threat
        "suspicious": 2,    # Potential threat
        "safe": 1,          # Likely benign
        "unknown": 0        # Not enough information
    }
    
    def __init__(self, session: Session):
        """
        Initialize threat classifier
        
        Args:
            session: Analysis session
        """
        self.session = session
        self.logger = Logger().get_logger()
        
        # Load known safe resources
        self.safe_domains: Set[str] = set()
        self.safe_ips: Set[str] = set()
        
        # Load known malicious resources
        self.malicious_domains: Set[str] = set()
        self.malicious_ips: Set[str] = set()
        
        # Initialize with some common safe domains
        self._init_safe_resources()
    
    def _init_safe_resources(self) -> None:
        """Initialize with common safe resources"""
        
        # Common safe domains
        common_safe = [
            # Common cloud providers
            "amazonaws.com", "azure.com", "microsoft.com", "office.com", "googleusercontent.com",
            "googleapis.com", "gstatic.com", "google.com", "gvt1.com", "gvt2.com", 
            "cloudfront.net", "akamai.net", "akamaized.net", "fastly.net", "cloudflare.com",
            
            # Common CDNs and services
            "jquery.com", "jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "bootstrap.com",
            
            # Common update services
            "windowsupdate.com", "update.microsoft.com", "apple.com", "digicert.com", "verisign.com",
            
            # Common NTP services
            "pool.ntp.org", "time.windows.com", "time.apple.com"
        ]
        
        self.safe_domains.update(common_safe)
        
        # Common safe IPs
        # (deliberately leaving this empty as IP reputation is more volatile)
    
    def add_safe_resource(self, value: str, resource_type: str) -> None:
        """
        Add a resource to the safe list
        
        Args:
            value: Resource value (domain or IP)
            resource_type: Resource type ('domain' or 'ip')
        """
        if resource_type == "domain":
            self.safe_domains.add(value)
        elif resource_type == "ip":
            self.safe_ips.add(value)
    
    def add_malicious_resource(self, value: str, resource_type: str) -> None:
        """
        Add a resource to the malicious list
        
        Args:
            value: Resource value (domain or IP)
            resource_type: Resource type ('domain' or 'ip')
        """
        if resource_type == "domain":
            self.malicious_domains.add(value)
        elif resource_type == "ip":
            self.malicious_ips.add(value)
    
    def classify_session_entities(self) -> Dict[str, Any]:
        """
        Classify all entities in the session
        
        Returns:
            Summary of classification results
        """
        results = {
            "total": 0,
            "classified": 0,
            "risk_levels": {
                "malicious": 0,
                "suspicious": 0,
                "safe": 0,
                "unknown": 0
            }
        }
        
        for entity_id, entity in self.session.network_entities.items():
            # Skip already classified entities with high confidence
            if entity.threat_level in ["malicious", "safe"] and entity.confidence > 0.7:
                results["risk_levels"][entity.threat_level] += 1
                results["total"] += 1
                results["classified"] += 1
                continue
            
            # Apply classification rules
            risk_level, confidence = self._classify_entity(entity)
            
            # Update entity threat level if confidence is higher
            if confidence > entity.confidence:
                entity.set_threat_level(risk_level, confidence)
            
            # Update results
            results["total"] += 1
            results["classified"] += 1
            results["risk_levels"][risk_level] += 1
        
        return results
    
    def _classify_entity(self, entity: NetworkEntity) -> tuple:
        """
        Classify a network entity
        
        Args:
            entity: Network entity to classify
            
        Returns:
            Tuple of (risk_level, confidence)
        """
        # Check if we have threat intelligence data
        if entity.id in self.session.threat_intelligence:
            ti_data = self.session.threat_intelligence[entity.id]
            # Return TI verdict if available
            if ti_data.verdict != "unknown":
                return ti_data.verdict, ti_data.risk_score
        
        # Apply heuristic rules based on entity type
        if entity.type == "ip":
            return self._classify_ip(entity)
        elif entity.type == "domain":
            return self._classify_domain(entity)
        elif entity.type == "url":
            return self._classify_url(entity)
        elif entity.type == "hash":
            return self._classify_hash(entity)
        else:
            return "unknown", 0.0
    
    def _classify_ip(self, entity: NetworkEntity) -> tuple:
        """
        Classify an IP address
        
        Args:
            entity: IP entity to classify
            
        Returns:
            Tuple of (risk_level, confidence)
        """
        ip = entity.value
        
        # Check against known lists
        if ip in self.malicious_ips:
            return "malicious", 0.9
        if ip in self.safe_ips:
            return "safe", 0.8
        
        # Check if private/reserved IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                return "safe", 0.7
        except ValueError:
            # Invalid IP format
            return "suspicious", 0.3
        
        # Check for unusual connections
        connections = [
            conn for conn in self.session.connections
            if conn.get("src_ip") == ip or conn.get("dst_ip") == ip
        ]
        
        # Look for signs of scanning behavior
        if self._detect_scanning(ip, connections):
            return "suspicious", 0.6
        
        # Check for data exfiltration patterns
        if self._detect_exfiltration(ip, connections):
            return "suspicious", 0.7
        
        # Check if IP is a destination for many sources
        if len(set(conn.get("src_ip") for conn in connections if conn.get("dst_ip") == ip)) > 10:
            return "suspicious", 0.3
        
        # No obvious issues
        return "unknown", 0.1
    
    def _classify_domain(self, entity: NetworkEntity) -> tuple:
        """
        Classify a domain
        
        Args:
            entity: Domain entity to classify
            
        Returns:
            Tuple of (risk_level, confidence)
        """
        domain = entity.value.lower()
        
        # Check against known lists
        if domain in self.malicious_domains:
            return "malicious", 0.9
            
        # Check if this is a subdomain of a known safe domain
        for safe_domain in self.safe_domains:
            if domain.endswith("." + safe_domain) or domain == safe_domain:
                return "safe", 0.7
        
        # Check for suspicious domain characteristics
        
        # Very long domain name
        if len(domain) > 50:
            return "suspicious", 0.5
        
        # High entropy (potentially DGA generated)
        if self._calculate_entropy(domain) > 4.0 and len(domain) > 10:
            return "suspicious", 0.6
        
        # Excessive subdomains
        if domain.count('.') > 4:
            return "suspicious", 0.4
        
        # Look for suspicious patterns (hex strings, random-looking)
        if re.search(r'[a-f0-9]{10,}', domain):
            return "suspicious", 0.5
        
        # Domain with unusual TLD
        unusual_tlds = [".xyz", ".top", ".club", ".pw", ".tk", ".ml", ".ga", ".cf"]
        if any(domain.endswith(tld) for tld in unusual_tlds):
            return "suspicious", 0.4
        
        # Common legitimate TLDs
        common_tlds = [".com", ".org", ".net", ".edu", ".gov", ".io", ".co", ".info"]
        if any(domain.endswith(tld) for tld in common_tlds):
            return "safe", 0.3
        
        # No obvious issues
        return "unknown", 0.1
    
    def _classify_url(self, entity: NetworkEntity) -> tuple:
        """
        Classify a URL
        
        Args:
            entity: URL entity to classify
            
        Returns:
            Tuple of (risk_level, confidence)
        """
        url = entity.value.lower()
        
        # Extract domain from URL
        domain_match = re.search(r'https?://([^:/]+)', url)
        if domain_match:
            domain = domain_match.group(1)
            
            # Check domain part against our domain classifier
            domain_entity = NetworkEntity("domain", domain)
            risk_level, confidence = self._classify_domain(domain_entity)
            
            # Adjust confidence slightly down since we're only checking the domain part
            return risk_level, max(0.0, confidence - 0.1)
        
        # Look for suspicious URL patterns
        
        # IP address in URL
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            return "suspicious", 0.5
        
        # URL with suspicious keywords
        suspicious_keywords = [
            "login", "account", "security", "bank", "verify", "update", "payment",
            "confirm", "paypal", "password", "credential"
        ]
        
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            return "suspicious", 0.4
        
        # URL with encoded characters
        if '%' in url and re.search(r'%[0-9A-Fa-f]{2}', url):
            return "suspicious", 0.3
        
        # No obvious issues
        return "unknown", 0.1
    
    def _classify_hash(self, entity: NetworkEntity) -> tuple:
        """
        Classify a file hash
        
        Args:
            entity: Hash entity to classify
            
        Returns:
            Tuple of (risk_level, confidence)
        """
        # Without external threat intelligence, we have limited ability
        # to classify file hashes based on the value alone
        
        # We can only provide a meaningful classification if we have TI data
        # or if the hash is in our attributes
        
        # Check for TI classification
        if entity.id in self.session.threat_intelligence:
            ti_data = self.session.threat_intelligence[entity.id]
            if ti_data.verdict != "unknown":
                return ti_data.verdict, ti_data.risk_score
        
        # Check entity attributes for context
        file_type = entity.attributes.get("file_type", "")
        file_name = entity.attributes.get("file_name", "")
        
        # Check for suspicious file extensions
        if file_name:
            suspicious_extensions = [
                ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".jar", ".pif", ".scr"
            ]
            if any(file_name.lower().endswith(ext) for ext in suspicious_extensions):
                return "suspicious", 0.3
        
        # Without more context, we can't really classify
        return "unknown", 0.1
    
    def _detect_scanning(self, ip: str, connections: List[Dict[str, Any]]) -> bool:
        """
        Detect if an IP is performing scanning behavior
        
        Args:
            ip: IP address to check
            connections: List of connections involving the IP
            
        Returns:
            True if scanning behavior detected
        """
        # Skip if too few connections
        if len(connections) < 5:
            return False
        
        # Count unique destination ports when this IP is the source
        dst_ports = set()
        dst_ips = set()
        
        for conn in connections:
            if conn.get("src_ip") == ip:
                dst_ports.add(conn.get("dst_port", 0))
                dst_ips.add(conn.get("dst_ip", ""))
        
        # Many ports to one or few IPs indicates vertical port scanning
        if len(dst_ports) >= 10 and len(dst_ips) <= 3:
            return True
        
        # Many IPs on same/few ports indicates horizontal scanning
        if len(dst_ips) >= 10 and len(dst_ports) <= 3:
            return True
        
        return False
    
    def _detect_exfiltration(self, ip: str, connections: List[Dict[str, Any]]) -> bool:
        """
        Detect if an IP is involved in data exfiltration
        
        Args:
            ip: IP address to check
            connections: List of connections involving the IP
            
        Returns:
            True if exfiltration behavior detected
        """
        # Skip if too few connections
        if len(connections) < 3:
            return False
        
        # Calculate bytes transferred from internal to this IP
        bytes_transferred = 0
        
        for conn in connections:
            # Only consider if this IP is the destination
            if conn.get("dst_ip") == ip:
                bytes_transferred += conn.get("byte_count", 0)
        
        # Large data transfer could indicate exfiltration
        if bytes_transferred > 1000000:  # More than 1MB
            return True
        
        return False
    
    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        Args:
            text: Input string
            
        Returns:
            Entropy value
        """
        import math
        from collections import Counter
        
        if not text:
            return 0
            
        entropy = 0.0
        text_length = len(text)
        
        # Count character frequencies
        char_counts = Counter(text)
        
        # Calculate entropy
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * math.log2(probability)
        
        return entropy