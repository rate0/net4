import os
import json
import csv
import threading
from typing import Dict, List, Any, Optional, Callable, Set, TextIO, Union

from ...models.session import Session
from ...utils.logger import Logger

class DataExporter:
    """
    Provides functionality to export session data in various formats
    such as JSON, CSV, and more.
    """
    
    def __init__(self):
        """Initialize data exporter"""
        self.logger = Logger().get_logger()
        self.stop_processing = False
    
    def export_to_json(
        self, 
        session: Session,
        output_path: str,
        data_types: Optional[List[str]] = None,
        pretty_print: bool = True,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> bool:
        """
        Export session data to JSON format
        
        Args:
            session: Analysis session
            output_path: Output file path
            data_types: Types of data to export (default: all)
            pretty_print: Whether to format JSON for readability
            progress_callback: Callback for progress updates
            
        Returns:
            True if successful
        """
        if progress_callback:
            progress_callback("Preparing data for export", 0.1)
        
        try:
            # Default data types
            if data_types is None:
                data_types = [
                    "metadata", "entities", "connections", "packets", 
                    "timeline", "anomalies", "threat_intel"
                ]
            
            # Prepare export data
            export_data = {"session_info": {
                "id": session.id,
                "name": session.name,
                "created_at": session.created_at.isoformat(),
                "last_modified": session.last_modified.isoformat()
            }}
            
            # Files information
            export_data["files"] = list(session.files.values())
            
            # Add each requested data type
            current_progress = 0.2
            progress_step = 0.7 / len(data_types)
            
            for data_type in data_types:
                if self.stop_processing:
                    if progress_callback:
                        progress_callback("Export cancelled", 1.0)
                    return False
                
                if progress_callback:
                    progress_callback(f"Exporting {data_type}", current_progress)
                
                if data_type == "metadata":
                    # Convert sets to lists for JSON serialization
                    metadata = session.metadata.copy()
                    for key, value in metadata.items():
                        if isinstance(value, set):
                            metadata[key] = list(value)
                    export_data["metadata"] = metadata
                
                elif data_type == "entities":
                    export_data["entities"] = {
                        entity_id: entity.to_dict() 
                        for entity_id, entity in session.network_entities.items()
                    }
                
                elif data_type == "connections":
                    export_data["connections"] = session.connections
                
                elif data_type == "packets":
                    # For packets, convert datetime objects to ISO format strings
                    packets_data = []
                    for packet in session.packets:
                        packet_copy = packet.copy()
                        if "timestamp" in packet_copy and packet_copy["timestamp"]:
                            packet_copy["timestamp"] = packet_copy["timestamp"].isoformat()
                        packets_data.append(packet_copy)
                    export_data["packets"] = packets_data
                
                elif data_type == "timeline":
                    # For timeline events, convert datetime objects to ISO format strings
                    timeline_data = []
                    for event in session.timeline_events:
                        event_copy = event.copy()
                        if "timestamp" in event_copy and event_copy["timestamp"]:
                            event_copy["timestamp"] = event_copy["timestamp"].isoformat()
                        timeline_data.append(event_copy)
                    export_data["timeline"] = timeline_data
                
                elif data_type == "anomalies":
                    # For anomalies, convert datetime objects to ISO format strings
                    anomalies_data = []
                    for anomaly in session.anomalies:
                        anomaly_copy = anomaly.copy()
                        if "timestamp" in anomaly_copy and anomaly_copy["timestamp"]:
                            anomaly_copy["timestamp"] = anomaly_copy["timestamp"].isoformat()
                        anomalies_data.append(anomaly_copy)
                    export_data["anomalies"] = anomalies_data
                
                elif data_type == "threat_intel":
                    export_data["threat_intel"] = {
                        entity_id: ti_data.to_dict() 
                        for entity_id, ti_data in session.threat_intelligence.items()
                    }
                
                elif data_type == "ai_insights":
                    export_data["ai_insights"] = session.ai_insights
                
                current_progress += progress_step
            
            if progress_callback:
                progress_callback("Writing data to file", 0.9)
            
            # Write to file
            with open(output_path, 'w') as f:
                if pretty_print:
                    json.dump(export_data, f, indent=2)
                else:
                    json.dump(export_data, f)
            
            if progress_callback:
                progress_callback("Export complete", 1.0)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {str(e)}")
            if progress_callback:
                progress_callback(f"Error: {str(e)}", 1.0)
            return False
    
    def export_to_json_async(
        self, 
        session: Session,
        output_path: str,
        data_types: Optional[List[str]] = None,
        pretty_print: bool = True,
        progress_callback: Optional[Callable[[str, float], None]] = None,
        completion_callback: Optional[Callable[[bool], None]] = None
    ) -> threading.Thread:
        """
        Export session data to JSON format asynchronously
        
        Args:
            session: Analysis session
            output_path: Output file path
            data_types: Types of data to export
            pretty_print: Whether to format JSON for readability
            progress_callback: Callback for progress updates
            completion_callback: Callback when export completes
            
        Returns:
            Thread object for the export task
        """
        def task():
            try:
                result = self.export_to_json(
                    session, output_path, data_types, pretty_print, progress_callback
                )
                if completion_callback:
                    completion_callback(result)
            except Exception as e:
                self.logger.error(f"Async JSON export error: {str(e)}")
                if completion_callback:
                    completion_callback(False)
        
        thread = threading.Thread(target=task)
        thread.daemon = True
        thread.start()
        return thread
    
    def export_to_csv(
        self, 
        session: Session,
        output_dir: str,
        data_types: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> Dict[str, str]:
        """
        Export session data to CSV format
        
        Args:
            session: Analysis session
            output_dir: Output directory for CSV files
            data_types: Types of data to export (default: connections, entities, anomalies)
            progress_callback: Callback for progress updates
            
        Returns:
            Dictionary mapping data types to output file paths
        """
        if progress_callback:
            progress_callback("Preparing data for export", 0.1)
        
        # Default data types for CSV export
        if data_types is None:
            data_types = ["connections", "entities", "anomalies"]
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        output_files = {}
        
        try:
            current_progress = 0.1
            progress_step = 0.8 / len(data_types)
            
            # Export each data type to a separate CSV file
            for data_type in data_types:
                if self.stop_processing:
                    if progress_callback:
                        progress_callback("Export cancelled", 1.0)
                    return output_files
                
                if progress_callback:
                    progress_callback(f"Exporting {data_type} to CSV", current_progress)
                
                output_path = os.path.join(output_dir, f"{session.name}_{data_type}.csv")
                
                if data_type == "connections":
                    self._export_connections_to_csv(session, output_path)
                    output_files["connections"] = output_path
                
                elif data_type == "entities":
                    self._export_entities_to_csv(session, output_path)
                    output_files["entities"] = output_path
                
                elif data_type == "anomalies":
                    self._export_anomalies_to_csv(session, output_path)
                    output_files["anomalies"] = output_path
                
                elif data_type == "timeline":
                    self._export_timeline_to_csv(session, output_path)
                    output_files["timeline"] = output_path
                
                elif data_type == "packets":
                    # Packets can be large, so export a summary
                    self._export_packets_to_csv(session, output_path)
                    output_files["packets"] = output_path
                
                elif data_type == "threat_intel":
                    self._export_threat_intel_to_csv(session, output_path)
                    output_files["threat_intel"] = output_path
                
                current_progress += progress_step
            
            if progress_callback:
                progress_callback("Export complete", 1.0)
            
            return output_files
            
        except Exception as e:
            self.logger.error(f"Error exporting to CSV: {str(e)}")
            if progress_callback:
                progress_callback(f"Error: {str(e)}", 1.0)
            return output_files
    
    def export_to_csv_async(
        self, 
        session: Session,
        output_dir: str,
        data_types: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, float], None]] = None,
        completion_callback: Optional[Callable[[Dict[str, str]], None]] = None
    ) -> threading.Thread:
        """
        Export session data to CSV format asynchronously
        
        Args:
            session: Analysis session
            output_dir: Output directory for CSV files
            data_types: Types of data to export
            progress_callback: Callback for progress updates
            completion_callback: Callback when export completes
            
        Returns:
            Thread object for the export task
        """
        def task():
            try:
                result = self.export_to_csv(
                    session, output_dir, data_types, progress_callback
                )
                if completion_callback:
                    completion_callback(result)
            except Exception as e:
                self.logger.error(f"Async CSV export error: {str(e)}")
                if completion_callback:
                    completion_callback({})
        
        thread = threading.Thread(target=task)
        thread.daemon = True
        thread.start()
        return thread
    
    def stop(self) -> None:
        """Stop ongoing export operations"""
        self.stop_processing = True
    
    def _export_connections_to_csv(self, session: Session, output_path: str) -> None:
        """
        Export connections to CSV
        
        Args:
            session: Analysis session
            output_path: Output file path
        """
        with open(output_path, 'w', newline='') as f:
            # Find common fields in connections
            fields = self._get_common_fields(session.connections, [
                "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                "first_seen", "last_seen", "packet_count", "byte_count"
            ])
            
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            
            for conn in session.connections:
                # Convert datetime objects to strings
                conn_copy = conn.copy()
                if "first_seen" in conn_copy and conn_copy["first_seen"]:
                    conn_copy["first_seen"] = conn_copy["first_seen"].isoformat()
                if "last_seen" in conn_copy and conn_copy["last_seen"]:
                    conn_copy["last_seen"] = conn_copy["last_seen"].isoformat()
                
                # Extract only the fields we want
                row = {field: conn_copy.get(field, "") for field in fields}
                writer.writerow(row)
    
    def _export_entities_to_csv(self, session: Session, output_path: str) -> None:
        """
        Export network entities to CSV
        
        Args:
            session: Analysis session
            output_path: Output file path
        """
        with open(output_path, 'w', newline='') as f:
            # Required fields
            fields = ["id", "type", "value", "name", "threat_level", "confidence", "notes"]
            
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            
            for entity_id, entity in session.network_entities.items():
                row = {
                    "id": entity.id,
                    "type": entity.type,
                    "value": entity.value,
                    "name": entity.name,
                    "threat_level": entity.threat_level,
                    "confidence": entity.confidence,
                    "notes": entity.notes
                }
                writer.writerow(row)
    
    def _export_anomalies_to_csv(self, session: Session, output_path: str) -> None:
        """
        Export anomalies to CSV
        
        Args:
            session: Analysis session
            output_path: Output file path
        """
        with open(output_path, 'w', newline='') as f:
            # Find common fields in anomalies
            fields = self._get_common_fields(session.anomalies, [
                "type", "subtype", "severity", "timestamp", "description"
            ])
            
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            
            for anomaly in session.anomalies:
                # Convert datetime objects to strings
                anomaly_copy = anomaly.copy()
                if "timestamp" in anomaly_copy and anomaly_copy["timestamp"]:
                    anomaly_copy["timestamp"] = anomaly_copy["timestamp"].isoformat()
                
                # Extract only the fields we want
                row = {field: anomaly_copy.get(field, "") for field in fields}
                writer.writerow(row)
    
    def _export_timeline_to_csv(self, session: Session, output_path: str) -> None:
        """
        Export timeline events to CSV
        
        Args:
            session: Analysis session
            output_path: Output file path
        """
        with open(output_path, 'w', newline='') as f:
            # Find common fields in timeline events
            fields = self._get_common_fields(session.timeline_events, [
                "timestamp", "type", "source", "description"
            ])
            
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            
            for event in session.timeline_events:
                # Convert datetime objects to strings
                event_copy = event.copy()
                if "timestamp" in event_copy and event_copy["timestamp"]:
                    event_copy["timestamp"] = event_copy["timestamp"].isoformat()
                
                # Flatten nested structures and extract basic fields
                for key, value in event.items():
                    if isinstance(value, dict) and key not in fields:
                        for sub_key, sub_value in value.items():
                            # Add flattened key if it's not too nested
                            flat_key = f"{key}_{sub_key}"
                            if flat_key not in fields and not isinstance(sub_value, (dict, list)):
                                event_copy[flat_key] = sub_value
                
                # Create description if not exists
                if "description" not in event_copy:
                    event_type = event_copy.get("type", "event")
                    event_copy["description"] = f"{event_type.capitalize()} at {event_copy.get('timestamp', '')}"
                
                # Extract only the fields we want
                row = {field: event_copy.get(field, "") for field in fields}
                writer.writerow(row)
    
    def _export_packets_to_csv(self, session: Session, output_path: str) -> None:
        """
        Export packets to CSV
        
        Args:
            session: Analysis session
            output_path: Output file path
        """
        with open(output_path, 'w', newline='') as f:
            # Find common fields in packets
            fields = self._get_common_fields(session.packets, [
                "frame_number", "timestamp", "length", "protocol",
                "src_ip", "dst_ip", "src_port", "dst_port"
            ])
            
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            
            # Limit to first 10000 packets to avoid overly large files
            packet_limit = min(10000, len(session.packets))
            
            for i, packet in enumerate(session.packets):
                if i >= packet_limit:
                    break
                    
                # Convert datetime objects to strings
                packet_copy = packet.copy()
                if "timestamp" in packet_copy and packet_copy["timestamp"]:
                    packet_copy["timestamp"] = packet_copy["timestamp"].isoformat()
                
                # Extract nested TCP/UDP flags
                if "tcp_flags" in packet_copy and isinstance(packet_copy["tcp_flags"], dict):
                    for flag_name, flag_value in packet_copy["tcp_flags"].items():
                        packet_copy[f"tcp_{flag_name}"] = flag_value
                
                # Extract only the fields we want
                row = {field: packet_copy.get(field, "") for field in fields}
                writer.writerow(row)
    
    def _export_threat_intel_to_csv(self, session: Session, output_path: str) -> None:
        """
        Export threat intelligence data to CSV
        
        Args:
            session: Analysis session
            output_path: Output file path
        """
        with open(output_path, 'w', newline='') as f:
            fields = [
                "entity_id", "entity_value", "entity_type", "risk_score", 
                "verdict", "malicious_votes", "total_votes", "summary"
            ]
            
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            
            for entity_id, ti_data in session.threat_intelligence.items():
                row = {
                    "entity_id": ti_data.entity_id,
                    "entity_value": ti_data.entity_value,
                    "entity_type": ti_data.entity_type,
                    "risk_score": ti_data.risk_score,
                    "verdict": ti_data.verdict,
                    "malicious_votes": ti_data.malicious_votes,
                    "total_votes": ti_data.total_votes,
                    "summary": ti_data.summary
                }
                writer.writerow(row)
    
    def _get_common_fields(
        self, 
        items: List[Dict[str, Any]], 
        default_fields: List[str]
    ) -> List[str]:
        """
        Get common fields from a list of dictionaries
        
        Args:
            items: List of dictionaries
            default_fields: Default fields to include
            
        Returns:
            List of common fields
        """
        if not items:
            return default_fields
            
        # Get all fields from the first few items
        all_fields: Set[str] = set()
        for item in items[:min(100, len(items))]:
            all_fields.update(item.keys())
        
        # Ensure default fields are included
        all_fields.update(default_fields)
        
        # Sort fields, putting default fields first
        sorted_fields = sorted(list(all_fields), key=lambda f: (f not in default_fields, f))
        
        return sorted_fields