import os
import re
import csv
import time
import threading
from typing import Dict, List, Any, Optional, Callable, Pattern
from datetime import datetime

from ...models.session import Session
from ...models.network_entity import NetworkEntity
from ...utils.logger import Logger

class LogParser:
    """
    Parses various network device logs and extracts relevant information.
    Supports common log formats from firewalls, IDS/IPS, web servers, etc.
    """
    
    # Log format patterns
    LOG_FORMATS = {
        "apache_common": {
            "pattern": r'(\S+) \S+ \S+ \[([^]]+)\] "(\S+) (\S+) ([^"]+)" (\d+) (\d+|\-)',
            "fields": ["client_ip", "timestamp", "method", "path", "protocol", "status", "bytes"]
        },
        "apache_combined": {
            "pattern": r'(\S+) \S+ \S+ \[([^]]+)\] "(\S+) (\S+) ([^"]+)" (\d+) (\d+|\-) "([^"]*)" "([^"]*)"',
            "fields": ["client_ip", "timestamp", "method", "path", "protocol", "status", "bytes", "referrer", "user_agent"]
        },
        "nginx": {
            "pattern": r'(\S+) - \S+ \[([^]]+)\] "(\S+) (\S+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"',
            "fields": ["client_ip", "timestamp", "method", "path", "protocol", "status", "bytes", "referrer", "user_agent"]
        },
        "syslog": {
            "pattern": r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s+(.*)',
            "fields": ["timestamp", "hostname", "process", "message"]
        },
        "csv": None  # Special case, handled separately
    }
    
    def __init__(self, session: Session):
        """
        Initialize log parser
        
        Args:
            session: Session to store extracted data
        """
        self.session = session
        self.logger = Logger().get_logger()
        self.stop_processing = False
        self.compiled_patterns = {
            format_name: re.compile(format_info["pattern"]) 
            for format_name, format_info in self.LOG_FORMATS.items() 
            if format_info and "pattern" in format_info
        }
    
    def process_file(
        self, 
        file_path: str,
        format_name: Optional[str] = None,
        custom_pattern: Optional[str] = None,
        custom_fields: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        timestamp_format: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Process a log file and extract data
        
        Args:
            file_path: Path to log file
            format_name: Name of predefined format or 'custom'
            custom_pattern: Custom regex pattern (if format_name is 'custom')
            custom_fields: Field names for custom pattern
            progress_callback: Callback function for progress updates
            timestamp_format: Format string for parsing timestamps
            
        Returns:
            Dict containing summary of processed data
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        self.logger.info(f"Processing log file: {file_path}")
        
        # Add file to session
        file_id = self.session.add_file(file_path, "log")
        
        # Determine file format
        pattern = None
        fields = None
        
        if format_name == "csv":
            # Handle CSV separately
            return self._process_csv_file(file_path, file_id, progress_callback)
        elif format_name == "custom" and custom_pattern and custom_fields:
            # Compile custom pattern
            pattern = re.compile(custom_pattern)
            fields = custom_fields
        elif format_name in self.LOG_FORMATS and self.LOG_FORMATS[format_name]:
            # Use predefined pattern
            pattern = self.compiled_patterns[format_name]
            fields = self.LOG_FORMATS[format_name]["fields"]
        else:
            # Auto-detect format
            format_name, pattern, fields = self._detect_format(file_path)
            if not pattern:
                raise ValueError(f"Unable to detect log format for: {file_path}")
        
        # Process log file
        start_time = time.time()
        total_lines = self._count_lines(file_path)
        
        processed_lines = 0
        matched_lines = 0
        
        # Entities for tracking
        ip_entities = {}
        domain_entities = {}
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if self.stop_processing:
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                processed_lines += 1
                
                # Parse line with pattern
                match = pattern.match(line)
                if match:
                    matched_lines += 1
                    
                    # Extract data from match
                    data = dict(zip(fields, match.groups()))
                    
                    # Process timestamp if present
                    if "timestamp" in data and data["timestamp"] and timestamp_format:
                        try:
                            data["timestamp"] = datetime.strptime(data["timestamp"], timestamp_format)
                        except ValueError:
                            # Try common formats if provided format fails
                            for fmt in [
                                "%d/%b/%Y:%H:%M:%S %z",  # Apache/Nginx
                                "%Y-%m-%d %H:%M:%S",      # ISO-like
                                "%b %d %H:%M:%S"          # Syslog
                            ]:
                                try:
                                    data["timestamp"] = datetime.strptime(data["timestamp"], fmt)
                                    break
                                except ValueError:
                                    pass
                    
                    # Add data as timeline event
                    event_data = {
                        "type": "log_entry",
                        "source": os.path.basename(file_path),
                        "line_number": line_num,
                        "raw_data": line,
                        "parsed_data": data
                    }
                    
                    if isinstance(data.get("timestamp"), datetime):
                        event_data["timestamp"] = data["timestamp"]
                    else:
                        event_data["timestamp"] = datetime.now()
                    
                    self.session.add_timeline_event(event_data)
                    
                    # Extract entities
                    self._extract_entities(data, ip_entities, domain_entities)
                
                # Update progress every 1000 lines
                if line_num % 1000 == 0 and progress_callback:
                    progress_callback(line_num, total_lines)
        
        # Final progress update
        if progress_callback:
            progress_callback(processed_lines, total_lines)
        
        # Update file metadata
        file_metadata = {
            "format": format_name,
            "total_lines": total_lines,
            "processed_lines": processed_lines,
            "matched_lines": matched_lines,
            "processing_time": time.time() - start_time,
            "ip_entities": len(ip_entities),
            "domain_entities": len(domain_entities)
        }
        
        self.session.files[file_id]["metadata"] = file_metadata
        
        self.logger.info(f"Log processing complete: {matched_lines}/{processed_lines} lines matched")
        
        return {
            "file_id": file_id,
            "format": format_name,
            "total_lines": total_lines,
            "processed_lines": processed_lines,
            "matched_lines": matched_lines,
            "ip_entities": len(ip_entities),
            "domain_entities": len(domain_entities)
        }
    
    def process_file_async(
        self, 
        file_path: str,
        format_name: Optional[str] = None,
        custom_pattern: Optional[str] = None,
        custom_fields: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        timestamp_format: Optional[str] = None,
        completion_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> threading.Thread:
        """
        Process a log file asynchronously
        
        Args:
            file_path: Path to log file
            format_name: Name of predefined format or 'custom'
            custom_pattern: Custom regex pattern (if format_name is 'custom')
            custom_fields: Field names for custom pattern
            progress_callback: Callback function for progress updates
            timestamp_format: Format string for parsing timestamps
            completion_callback: Callback function when processing completes
            
        Returns:
            Thread object for the processing task
        """
        def task():
            try:
                result = self.process_file(
                    file_path, format_name, custom_pattern, custom_fields,
                    progress_callback, timestamp_format
                )
                if completion_callback:
                    completion_callback(result)
            except Exception as e:
                self.logger.error(f"Async log processing error: {str(e)}")
                if completion_callback:
                    completion_callback({"error": str(e)})
        
        thread = threading.Thread(target=task)
        thread.daemon = True
        thread.start()
        return thread
    
    def stop(self) -> None:
        """Stop ongoing processing"""
        self.stop_processing = True
    
    def _process_csv_file(
        self, 
        file_path: str, 
        file_id: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Process a CSV log file
        
        Args:
            file_path: Path to CSV file
            file_id: ID of the file in the session
            progress_callback: Callback function for progress updates
            
        Returns:
            Dict containing summary of processed data
        """
        start_time = time.time()
        total_lines = self._count_lines(file_path) - 1  # Subtract header
        
        processed_lines = 0
        ip_entities = {}
        domain_entities = {}
        
        with open(file_path, 'r', newline='', encoding='utf-8', errors='ignore') as f:
            # Try to detect dialect
            sample = f.read(4096)
            f.seek(0)
            
            try:
                dialect = csv.Sniffer().sniff(sample)
                has_header = csv.Sniffer().has_header(sample)
            except:
                dialect = csv.excel
                has_header = True
            
            reader = csv.reader(f, dialect)
            
            # Read header
            header = next(reader) if has_header else []
            fields = [f.lower().replace(' ', '_') for f in header]
            
            # Process rows
            for row_num, row in enumerate(reader, 1):
                if self.stop_processing:
                    break
                
                if len(row) == 0:
                    continue
                
                processed_lines += 1
                
                # Convert row to dict
                if fields and len(fields) == len(row):
                    data = dict(zip(fields, row))
                else:
                    data = {f"field_{i}": val for i, val in enumerate(row)}
                
                # Try to parse timestamp fields
                for field in data:
                    if any(time_field in field for time_field in ["time", "date", "timestamp"]):
                        for fmt in [
                            "%Y-%m-%d %H:%M:%S",
                            "%Y/%m/%d %H:%M:%S",
                            "%d/%m/%Y %H:%M:%S",
                            "%m/%d/%Y %H:%M:%S",
                            "%Y-%m-%dT%H:%M:%S",
                            "%Y-%m-%d"
                        ]:
                            try:
                                data[field] = datetime.strptime(data[field], fmt)
                                break
                            except (ValueError, TypeError):
                                pass
                
                # Add data as timeline event
                timestamp = None
                for field, value in data.items():
                    if isinstance(value, datetime):
                        timestamp = value
                        break
                
                event_data = {
                    "type": "csv_entry",
                    "source": os.path.basename(file_path),
                    "row_number": row_num,
                    "parsed_data": data
                }
                
                if timestamp:
                    event_data["timestamp"] = timestamp
                else:
                    event_data["timestamp"] = datetime.now()
                
                self.session.add_timeline_event(event_data)
                
                # Extract entities
                self._extract_entities(data, ip_entities, domain_entities)
                
                # Update progress every 1000 rows
                if row_num % 1000 == 0 and progress_callback:
                    progress_callback(row_num, total_lines)
        
        # Final progress update
        if progress_callback:
            progress_callback(processed_lines, total_lines)
        
        # Update file metadata
        file_metadata = {
            "format": "csv",
            "total_lines": total_lines + 1,  # Include header
            "processed_lines": processed_lines,
            "fields": fields,
            "processing_time": time.time() - start_time,
            "ip_entities": len(ip_entities),
            "domain_entities": len(domain_entities)
        }
        
        self.session.files[file_id]["metadata"] = file_metadata
        
        self.logger.info(f"CSV processing complete: {processed_lines} rows processed")
        
        return {
            "file_id": file_id,
            "format": "csv",
            "total_lines": total_lines + 1,
            "processed_lines": processed_lines,
            "fields": fields,
            "ip_entities": len(ip_entities),
            "domain_entities": len(domain_entities)
        }
    
    def _detect_format(self, file_path: str) -> tuple:
        """
        Attempt to detect log file format
        
        Args:
            file_path: Path to log file
            
        Returns:
            Tuple of (format_name, pattern, fields)
        """
        # Check if it's a CSV file first
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            sample = f.read(4096)
            try:
                if csv.Sniffer().sniff(sample) and ',' in sample:
                    return "csv", None, None
            except:
                pass
        
        # Try each pattern on the first few lines
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [f.readline().strip() for _ in range(10) if f.readline().strip()]
        
        for format_name, pattern_info in self.LOG_FORMATS.items():
            if not pattern_info or format_name == "csv":
                continue
            
            pattern = self.compiled_patterns[format_name]
            matches = 0
            
            for line in lines:
                if pattern.match(line):
                    matches += 1
            
            # If more than 60% of lines match, choose this format
            if matches / len(lines) > 0.6:
                return format_name, pattern, pattern_info["fields"]
        
        # No format detected
        return None, None, None
    
    def _count_lines(self, file_path: str) -> int:
        """Count lines in a file"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    
    def _extract_entities(
        self, 
        data: Dict[str, Any],
        ip_entities: Dict[str, str],
        domain_entities: Dict[str, str]
    ) -> None:
        """
        Extract network entities from parsed data
        
        Args:
            data: Parsed data dictionary
            ip_entities: Dictionary of IP entities (for tracking)
            domain_entities: Dictionary of domain entities (for tracking)
        """
        # IP address pattern
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        
        # Domain pattern (simplified)
        domain_pattern = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)')
        
        # Check all fields for IPs and domains
        for field, value in data.items():
            if not isinstance(value, str):
                continue
            
            # Extract IPs
            for ip in ip_pattern.findall(value):
                ip = ip[0] if isinstance(ip, tuple) else ip
                if ip not in ip_entities:
                    entity = NetworkEntity(
                        entity_type="ip",
                        value=ip,
                        name=f"IP: {ip}"
                    )
                    self.session.add_network_entity(entity)
                    ip_entities[ip] = entity.id
            
            # Extract domains
            for domain in domain_pattern.findall(value):
                domain = domain[0] if isinstance(domain, tuple) else domain
                # Skip if it's an IP address
                if ip_pattern.match(domain):
                    continue
                
                if domain not in domain_entities:
                    entity = NetworkEntity(
                        entity_type="domain",
                        value=domain,
                        name=f"Domain: {domain}"
                    )
                    self.session.add_network_entity(entity)
                    domain_entities[domain] = entity.id
        
        # Check specific fields known to contain IPs
        for ip_field in ["client_ip", "ip", "source_ip", "destination_ip", "src_ip", "dst_ip"]:
            if ip_field in data and isinstance(data[ip_field], str):
                ip = data[ip_field]
                if ip_pattern.match(ip) and ip not in ip_entities:
                    entity = NetworkEntity(
                        entity_type="ip",
                        value=ip,
                        name=f"IP: {ip}"
                    )
                    self.session.add_network_entity(entity)
                    ip_entities[ip] = entity.id
        
        # Check specific fields known to contain domains
        for domain_field in ["host", "domain", "hostname", "url", "referrer"]:
            if domain_field in data and isinstance(data[domain_field], str):
                domain = data[domain_field]
                # Extract domain from URL if needed
                if domain.startswith("http"):
                    domain_match = re.search(r'https?://([^:/]+)', domain)
                    if domain_match:
                        domain = domain_match.group(1)
                
                if domain_pattern.match(domain) and domain not in domain_entities:
                    entity = NetworkEntity(
                        entity_type="domain",
                        value=domain,
                        name=f"Domain: {domain}"
                    )
                    self.session.add_network_entity(entity)
                    domain_entities[domain] = entity.id