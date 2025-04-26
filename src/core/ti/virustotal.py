import time
import threading
import requests
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime

from ...models.session import Session
from ...models.network_entity import NetworkEntity
from ...models.threat_info import ThreatInfo
from ...utils.logger import Logger
from ...utils.config import Config

class VirusTotalClient:
    """
    Client for the VirusTotal API to lookup threat intelligence information
    about network entities such as IPs, domains, and file hashes.
    """
    
    # Base API URLs
    API_V3_URL = "https://www.virustotal.com/api/v3"
    
    # Rate limiting (free API: 4 requests per minute)
    DEFAULT_RATE_LIMIT = 4  # requests per minute
    
    def __init__(self, config: Config):
        """
        Initialize the VirusTotal client
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.logger = Logger().get_logger()
        
        # Get API key from config
        self.api_key = self.config.get("api.virustotal.api_key")
        self.timeout = self.config.get("api.virustotal.timeout", 30)
        
        # Rate limiting
        self.request_count = 0
        self.rate_limit = self.DEFAULT_RATE_LIMIT
        self.last_request_time = 0
        
        # Track processed entities to avoid duplicates
        self.processed_entities = set()
        
        # Flag for stopping batch processing
        self.stop_processing = False
    
    def set_api_key(self, api_key: str) -> None:
        """Set the VirusTotal API key"""
        self.config.set("api.virustotal.api_key", api_key)
        self.api_key = api_key
    
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Lookup information about an IP address
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dictionary with threat intelligence data
        """
        if not self.api_key:
            raise ValueError("VirusTotal API key not configured")
        
        self._rate_limit()
        
        try:
            url = f"{self.API_V3_URL}/ip_addresses/{ip}"
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            return self._format_ip_response(data)
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error looking up IP {ip}: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response content: {e.response.content}")
            raise
    
    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Lookup information about a domain
        
        Args:
            domain: Domain name to lookup
            
        Returns:
            Dictionary with threat intelligence data
        """
        if not self.api_key:
            raise ValueError("VirusTotal API key not configured")
        
        self._rate_limit()
        
        try:
            url = f"{self.API_V3_URL}/domains/{domain}"
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            return self._format_domain_response(data)
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error looking up domain {domain}: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response content: {e.response.content}")
            raise
    
    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Lookup information about a file hash
        
        Args:
            file_hash: File hash to lookup (MD5, SHA-1, SHA-256)
            
        Returns:
            Dictionary with threat intelligence data
        """
        if not self.api_key:
            raise ValueError("VirusTotal API key not configured")
        
        self._rate_limit()
        
        try:
            url = f"{self.API_V3_URL}/files/{file_hash}"
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            return self._format_file_response(data)
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error looking up hash {file_hash}: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response content: {e.response.content}")
            raise
    
    def lookup_url(self, url: str) -> Dict[str, Any]:
        """
        Lookup information about a URL
        
        Args:
            url: URL to lookup
            
        Returns:
            Dictionary with threat intelligence data
        """
        if not self.api_key:
            raise ValueError("VirusTotal API key not configured")
        
        self._rate_limit()
        
        try:
            # For URLs, we need to submit a URL for analysis first
            url_id = self._get_url_id(url)
            
            api_url = f"{self.API_V3_URL}/urls/{url_id}"
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            response = requests.get(api_url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            return self._format_url_response(data)
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error looking up URL {url}: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response content: {e.response.content}")
            raise
    
    def process_entity(self, entity: NetworkEntity) -> Optional[ThreatInfo]:
        """
        Process a network entity for threat intelligence
        
        Args:
            entity: Network entity to process
            
        Returns:
            ThreatInfo object or None if processing fails
        """
        # Skip if already processed
        if entity.id in self.processed_entities:
            return None
        
        self.processed_entities.add(entity.id)
        
        try:
            # Initialize threat info
            threat_info = ThreatInfo(
                entity_id=entity.id,
                entity_value=entity.value,
                entity_type=entity.type
            )
            
            # Lookup based on entity type
            if entity.type == "ip":
                # Check if value is actually an IP (some entities might be incorrectly classified)
                import re
                ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
                if ip_pattern.match(entity.value):
                    data = self.lookup_ip(entity.value)
                    threat_info.add_source_data("virustotal", data)
                else:
                    self.logger.warning(f"Entity {entity.value} marked as IP but doesn't match IP format")
                    return None
                
            elif entity.type == "domain":
                # Check if value is actually a domain (not an IP address)
                import re
                ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
                if ip_pattern.match(entity.value):
                    # This is actually an IP, not a domain
                    self.logger.warning(f"Entity {entity.value} marked as domain but is actually an IP. Processing as IP.")
                    data = self.lookup_ip(entity.value)
                    threat_info.add_source_data("virustotal", data)
                else:
                    data = self.lookup_domain(entity.value)
                    threat_info.add_source_data("virustotal", data)
                
            elif entity.type == "hash":
                data = self.lookup_hash(entity.value)
                threat_info.add_source_data("virustotal", data)
                
            elif entity.type == "url":
                data = self.lookup_url(entity.value)
                threat_info.add_source_data("virustotal", data)
                
            else:
                self.logger.warning(f"Unsupported entity type for VirusTotal: {entity.type}")
                return None
            
            # Calculate risk score and set verdict
            self._calculate_risk(threat_info)
            
            # Generate summary
            self._generate_summary(threat_info)
            
            # Update entity threat level
            entity.set_threat_level(
                level=threat_info.verdict,
                confidence=threat_info.risk_score
            )
            
            return threat_info
            
        except Exception as e:
            self.logger.error(f"Error processing entity {entity.value}: {str(e)}")
            return None
    
    def process_session_entities(
        self, 
        session: Session,
        entity_types: Optional[List[str]] = None,
        max_entities: int = 50,
        progress_callback: Optional[Callable[[int, int, Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
        """
        Process entities in a session
        
        Args:
            session: Analysis session
            entity_types: List of entity types to process (defaults to ["ip", "domain"])
            max_entities: Maximum number of entities to process
            progress_callback: Callback for progress updates
            
        Returns:
            Dictionary with processing results
        """
        if not self.api_key:
            raise ValueError("VirusTotal API key not configured")
        
        # Default to IP and domain entities
        if entity_types is None:
            entity_types = ["ip", "domain"]
        
        # Reset processing state
        self.processed_entities = set()
        self.stop_processing = False
        
        # Collect entities to process
        entities_to_process = []
        
        for entity_id, entity in session.network_entities.items():
            if entity.type in entity_types:
                entities_to_process.append(entity)
                if len(entities_to_process) >= max_entities:
                    break
        
        total_entities = len(entities_to_process)
        processed_count = 0
        success_count = 0
        failure_count = 0
        
        # Process entities
        for i, entity in enumerate(entities_to_process):
            if self.stop_processing:
                break
            
            try:
                # Update progress
                if progress_callback:
                    progress_callback(i, total_entities, {
                        "entity_value": entity.value,
                        "entity_type": entity.type,
                        "processed": processed_count,
                        "success": success_count,
                        "failure": failure_count
                    })
                
                # Process entity
                threat_info = self.process_entity(entity)
                
                if threat_info:
                    # Add to session
                    session.add_threat_intel(entity.id, threat_info)
                    success_count += 1
                else:
                    failure_count += 1
                
                processed_count += 1
                
            except Exception as e:
                self.logger.error(f"Error in batch processing entity {entity.value}: {str(e)}")
                failure_count += 1
                processed_count += 1
        
        # Final progress update
        if progress_callback:
            progress_callback(total_entities, total_entities, {
                "entity_value": "complete",
                "entity_type": "",
                "processed": processed_count,
                "success": success_count,
                "failure": failure_count
            })
        
        return {
            "total": total_entities,
            "processed": processed_count,
            "success": success_count,
            "failure": failure_count
        }
    
    def process_session_entities_async(
        self, 
        session: Session,
        entity_types: Optional[List[str]] = None,
        max_entities: int = 50,
        progress_callback: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
        completion_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> threading.Thread:
        """
        Process entities in a session asynchronously
        
        Args:
            session: Analysis session
            entity_types: List of entity types to process
            max_entities: Maximum number of entities to process
            progress_callback: Callback for progress updates
            completion_callback: Callback when processing completes
            
        Returns:
            Thread object for the processing task
        """
        def task():
            try:
                # Create a deep copy of the session to avoid threading issues
                # This is a workaround - we'll pass the session directly but be careful with modifications
                result = None
                
                try:
                    # Process entities
                    result = self.process_session_entities(
                        session, entity_types, max_entities, progress_callback
                    )
                except Exception as inner_e:
                    self.logger.error(f"Error processing session entities: {str(inner_e)}")
                    if completion_callback:
                        completion_callback({"error": str(inner_e)})
                    return
                
                # Call completion callback with a copy of the result to ensure thread safety
                if completion_callback:
                    # Make sure to return a new dictionary to avoid thread safety issues
                    safe_result = result.copy() if result else {"error": "Processing failed"}
                    completion_callback(safe_result)
                    
            except Exception as e:
                self.logger.error(f"Async entity processing error: {str(e)}")
                if completion_callback:
                    completion_callback({"error": str(e)})
        
        # Create and start the thread
        thread = threading.Thread(target=task, name="VirusTotalThread")
        thread.daemon = True
        thread.start()
        return thread
    
    def stop(self) -> None:
        """Stop ongoing processing"""
        self.stop_processing = True
    
    def _rate_limit(self) -> None:
        """
        Implement rate limiting for API requests
        """
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        # If less than a minute since last request, check rate limit
        if time_since_last < 60 and self.request_count >= self.rate_limit:
            # Sleep until a minute has passed
            sleep_time = 60 - time_since_last
            self.logger.info(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
            self.request_count = 0
            self.last_request_time = time.time()
        elif time_since_last >= 60:
            # If more than a minute has passed, reset counter
            self.request_count = 0
            self.last_request_time = current_time
        
        # Increment request counter
        self.request_count += 1
    
    def _get_url_id(self, url: str) -> str:
        """
        Get URL identifier for VirusTotal API
        
        Args:
            url: URL to get ID for
            
        Returns:
            URL identifier
        """
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    def _format_ip_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format VirusTotal API response for IP address
        
        Args:
            data: Raw API response
            
        Returns:
            Formatted data dictionary
        """
        formatted = {
            "type": "ip",
            "raw_data": None  # Don't store raw data to save space
        }
        
        try:
            attributes = data.get("data", {}).get("attributes", {})
            
            # Last analysis stats
            stats = attributes.get("last_analysis_stats", {})
            formatted["malicious"] = stats.get("malicious", 0)
            formatted["suspicious"] = stats.get("suspicious", 0)
            formatted["harmless"] = stats.get("harmless", 0)
            formatted["undetected"] = stats.get("undetected", 0)
            formatted["total"] = sum(stats.values())
            
            # Country and ASN info
            formatted["country"] = attributes.get("country")
            formatted["continent"] = attributes.get("continent")
            formatted["asn"] = attributes.get("asn")
            formatted["as_owner"] = attributes.get("as_owner")
            
            # Reputation
            formatted["reputation"] = attributes.get("reputation", 0)
            
            # Categories
            formatted["categories"] = []
            for engine, category in attributes.get("categories", {}).items():
                if category not in formatted["categories"]:
                    formatted["categories"].append(category)
            
            # Last analysis results
            engines = attributes.get("last_analysis_results", {})
            formatted["detections"] = []
            
            for engine_name, result in engines.items():
                if result.get("category") in ["malicious", "suspicious"]:
                    formatted["detections"].append({
                        "engine": engine_name,
                        "category": result.get("category"),
                        "result": result.get("result", "")
                    })
            
            # Tags/behaviors
            formatted["tags"] = attributes.get("tags", [])
            
        except Exception as e:
            self.logger.error(f"Error formatting IP response: {str(e)}")
        
        return formatted
    
    def _format_domain_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format VirusTotal API response for domain
        
        Args:
            data: Raw API response
            
        Returns:
            Formatted data dictionary
        """
        formatted = {
            "type": "domain",
            "raw_data": None  # Don't store raw data to save space
        }
        
        try:
            attributes = data.get("data", {}).get("attributes", {})
            
            # Last analysis stats
            stats = attributes.get("last_analysis_stats", {})
            formatted["malicious"] = stats.get("malicious", 0)
            formatted["suspicious"] = stats.get("suspicious", 0)
            formatted["harmless"] = stats.get("harmless", 0)
            formatted["undetected"] = stats.get("undetected", 0)
            formatted["total"] = sum(stats.values())
            
            # Domain info
            formatted["creation_date"] = attributes.get("creation_date")
            formatted["registrar"] = attributes.get("registrar")
            formatted["last_dns_records_date"] = attributes.get("last_dns_records_date")
            
            # Categories
            formatted["categories"] = []
            for engine, category in attributes.get("categories", {}).items():
                if category not in formatted["categories"]:
                    formatted["categories"].append(category)
            
            # Last analysis results
            engines = attributes.get("last_analysis_results", {})
            formatted["detections"] = []
            
            for engine_name, result in engines.items():
                if result.get("category") in ["malicious", "suspicious"]:
                    formatted["detections"].append({
                        "engine": engine_name,
                        "category": result.get("category"),
                        "result": result.get("result", "")
                    })
            
            # Tags/behaviors
            formatted["tags"] = attributes.get("tags", [])
            
            # WHOIS info
            formatted["whois"] = attributes.get("whois", "")
            
            # Resolutions (IP history)
            formatted["resolutions"] = []
            for resolution in attributes.get("resolutions", [])[:10]:  # Limit to 10
                formatted["resolutions"].append({
                    "ip_address": resolution.get("ip_address"),
                    "date": resolution.get("date")
                })
            
            # Subdomains
            formatted["subdomains"] = attributes.get("subdomains", [])
            
        except Exception as e:
            self.logger.error(f"Error formatting domain response: {str(e)}")
        
        return formatted
    
    def _format_file_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format VirusTotal API response for file hash
        
        Args:
            data: Raw API response
            
        Returns:
            Formatted data dictionary
        """
        formatted = {
            "type": "file",
            "raw_data": None  # Don't store raw data to save space
        }
        
        try:
            attributes = data.get("data", {}).get("attributes", {})
            
            # Last analysis stats
            stats = attributes.get("last_analysis_stats", {})
            formatted["malicious"] = stats.get("malicious", 0)
            formatted["suspicious"] = stats.get("suspicious", 0)
            formatted["harmless"] = stats.get("harmless", 0)
            formatted["undetected"] = stats.get("undetected", 0)
            formatted["total"] = sum(stats.values())
            
            # File info
            formatted["name"] = attributes.get("meaningful_name", "")
            formatted["size"] = attributes.get("size", 0)
            formatted["type"] = attributes.get("type_description", "")
            formatted["md5"] = attributes.get("md5", "")
            formatted["sha1"] = attributes.get("sha1", "")
            formatted["sha256"] = attributes.get("sha256", "")
            
            # Last analysis results
            engines = attributes.get("last_analysis_results", {})
            formatted["detections"] = []
            
            for engine_name, result in engines.items():
                if result.get("category") in ["malicious", "suspicious"]:
                    formatted["detections"].append({
                        "engine": engine_name,
                        "category": result.get("category"),
                        "result": result.get("result", "")
                    })
            
            # Tags/behaviors
            formatted["tags"] = attributes.get("tags", [])
            
            # Submission names
            formatted["submission_names"] = attributes.get("submission_names", [])
            
        except Exception as e:
            self.logger.error(f"Error formatting file response: {str(e)}")
        
        return formatted
    
    def _format_url_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format VirusTotal API response for URL
        
        Args:
            data: Raw API response
            
        Returns:
            Formatted data dictionary
        """
        formatted = {
            "type": "url",
            "raw_data": None  # Don't store raw data to save space
        }
        
        try:
            attributes = data.get("data", {}).get("attributes", {})
            
            # Last analysis stats
            stats = attributes.get("last_analysis_stats", {})
            formatted["malicious"] = stats.get("malicious", 0)
            formatted["suspicious"] = stats.get("suspicious", 0)
            formatted["harmless"] = stats.get("harmless", 0)
            formatted["undetected"] = stats.get("undetected", 0)
            formatted["total"] = sum(stats.values())
            
            # URL info
            formatted["url"] = attributes.get("url", "")
            formatted["final_url"] = attributes.get("final_url", "")
            formatted["last_http_response_code"] = attributes.get("last_http_response_code", 0)
            formatted["last_analysis_date"] = attributes.get("last_analysis_date", 0)
            
            # Last analysis results
            engines = attributes.get("last_analysis_results", {})
            formatted["detections"] = []
            
            for engine_name, result in engines.items():
                if result.get("category") in ["malicious", "suspicious"]:
                    formatted["detections"].append({
                        "engine": engine_name,
                        "category": result.get("category"),
                        "result": result.get("result", "")
                    })
            
            # Categories
            formatted["categories"] = []
            for engine, category in attributes.get("categories", {}).items():
                if category not in formatted["categories"]:
                    formatted["categories"].append(category)
            
            # Tags/behaviors
            formatted["tags"] = attributes.get("tags", [])
            
        except Exception as e:
            self.logger.error(f"Error formatting URL response: {str(e)}")
        
        return formatted
    
    def _calculate_risk(self, threat_info: ThreatInfo) -> None:
        """
        Calculate risk score and set verdict for threat info
        
        Args:
            threat_info: ThreatInfo object to update
        """
        # Get VirusTotal data
        vt_data = threat_info.sources.get("virustotal", {})
        if not vt_data:
            return
        
        # Calculate risk score
        risk_score = 0.0
        
        # Based on malicious/suspicious votes
        malicious = vt_data.get("malicious", 0)
        suspicious = vt_data.get("suspicious", 0)
        total = vt_data.get("total", 0)
        
        if total > 0:
            # Weight malicious higher than suspicious
            weighted_score = (malicious * 1.0 + suspicious * 0.5) / total
            risk_score = max(risk_score, weighted_score)
        
        # Adjust based on tags
        tags = vt_data.get("tags", [])
        malicious_tags = ["malware", "phishing", "malicious", "suspicious", "spam", 
                          "known distributor", "command and control", "botnet"]
        
        for tag in tags:
            if any(m_tag in tag.lower() for m_tag in malicious_tags):
                risk_score = max(risk_score, 0.7)
                break
        
        # Set risk score
        threat_info.set_risk_score(risk_score)
        
        # Set verdict based on risk score
        if risk_score >= 0.7:
            verdict = "malicious"
        elif risk_score >= 0.3:
            verdict = "suspicious"
        elif risk_score >= 0.05:
            verdict = "suspicious"
        else:
            verdict = "clean"
        
        threat_info.set_verdict(verdict)
    
    def _generate_summary(self, threat_info: ThreatInfo) -> None:
        """
        Generate text summary for threat info
        
        Args:
            threat_info: ThreatInfo object to update
        """
        # Get VirusTotal data
        vt_data = threat_info.sources.get("virustotal", {})
        if not vt_data:
            return
        
        entity_type = threat_info.entity_type
        entity_value = threat_info.entity_value
        
        # Generate summary based on entity type and verdict
        if threat_info.verdict == "malicious":
            if entity_type == "ip":
                country = vt_data.get("country", "unknown location")
                detections = len(vt_data.get("detections", []))
                categories = vt_data.get('categories', [])[:3]
                category_text = ", ".join(categories) if categories else "unknown"
                summary = (f"Malicious IP address from {country}. "
                          f"Detected by {detections} security vendors. "
                          f"Categories: {category_text}.")
                
            elif entity_type == "domain":
                detections = len(vt_data.get("detections", []))
                categories = vt_data.get('categories', [])[:3]
                category_text = ", ".join(categories) if categories else "unknown"
                summary = (f"Malicious domain detected by {detections} security vendors. "
                          f"Categories: {category_text}.")
                
            elif entity_type == "hash":
                name = vt_data.get("name", "Unknown file")
                detections = len(vt_data.get("detections", []))
                tags = vt_data.get('tags', [])[:3]
                tags_text = ", ".join(tags) if tags else "unknown"
                summary = (f"Malicious file '{name}' detected by {detections} security vendors. "
                          f"Tags: {tags_text}.")
                
            elif entity_type == "url":
                detections = len(vt_data.get("detections", []))
                categories = vt_data.get('categories', [])[:3]
                category_text = ", ".join(categories) if categories else "unknown"
                summary = (f"Malicious URL detected by {detections} security vendors. "
                          f"Categories: {category_text}.")
                
            else:
                summary = f"Malicious {entity_type}: {entity_value}"
            
        elif threat_info.verdict == "suspicious":
            if entity_type == "ip":
                country = vt_data.get("country", "unknown location")
                suspicious_count = vt_data.get('suspicious', 0)
                summary = (f"Suspicious IP address from {country}. "
                          f"Flagged by {suspicious_count} security vendors.")
                
            elif entity_type == "domain":
                suspicious_count = vt_data.get('suspicious', 0)
                summary = (f"Suspicious domain. Flagged by {suspicious_count} "
                          f"security vendors.")
                
            elif entity_type == "hash":
                name = vt_data.get("name", "Unknown file")
                suspicious_count = vt_data.get('suspicious', 0)
                summary = (f"Suspicious file '{name}'. Flagged by {suspicious_count} "
                          f"security vendors.")
                
            elif entity_type == "url":
                suspicious_count = vt_data.get('suspicious', 0)
                summary = (f"Suspicious URL. Flagged by {suspicious_count} "
                          f"security vendors.")
                
            else:
                summary = f"Suspicious {entity_type}: {entity_value}"
            
        elif threat_info.verdict == "clean":
            summary = f"No security vendors flagged this {entity_type} as malicious."
            
        else:  # unknown
            summary = f"Insufficient data to determine the risk level of this {entity_type}."
        
        threat_info.set_summary(summary)