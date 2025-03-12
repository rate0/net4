import math
import time
import threading
import numpy as np
from collections import Counter, defaultdict
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta

from ...models.session import Session
from ...utils.logger import Logger

class AnomalyDetector:
    """
    Detects anomalies in network traffic based on various algorithms
    and heuristics.
    """
    
    # Anomaly types
    ANOMALY_TYPES = [
        "volume_spike",        # Unusual traffic volume
        "rare_port",           # Uncommon port usage
        "connection_burst",    # Many connections in short time
        "scan_activity",       # Port/network scanning
        "unusual_protocol",    # Rare/unexpected protocol
        "timing_pattern",      # Regular/irregular timing patterns
        "data_exfiltration",   # Possible data exfiltration
        "beaconing",           # Regular beaconing communication
        "dns_anomaly",         # Unusual DNS activity
        "http_anomaly"         # Unusual HTTP activity
    ]
    
    def __init__(self, session: Session):
        """
        Initialize anomaly detector
        
        Args:
            session: Analysis session
        """
        self.session = session
        self.logger = Logger().get_logger()
        self.stop_processing = False
        
        # Detection thresholds
        self.thresholds = {
            "volume_threshold": 3.0,       # Standard deviations for volume spikes
            "rare_port_threshold": 0.01,   # Frequency below this is considered rare
            "scan_threshold": 5,           # Min ports to consider a scan
            "burst_threshold": 10,         # Min connections per second for burst
            "timing_var_threshold": 0.1,   # Coefficient of variation for timing
            "exfil_threshold": 1000000,    # Bytes threshold for potential exfiltration
            "beaconing_max_jitter": 0.1,   # Max timing jitter for beaconing
            "dns_query_threshold": 100     # Unusual number of DNS queries
        }
    
    def detect_anomalies(
        self, 
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Detect anomalies in session data
        
        Args:
            progress_callback: Callback function for progress updates
            
        Returns:
            List of detected anomalies
        """
        if len(self.session.packets) == 0:
            return []
        
        anomalies = []
        
        # Initialize progress
        if progress_callback:
            progress_callback("Starting anomaly detection", 0.0)
        
        try:
            # Volume-based anomalies (traffic spikes)
            if progress_callback:
                progress_callback("Detecting volume anomalies", 0.1)
            
            volume_anomalies = self._detect_volume_anomalies()
            anomalies.extend(volume_anomalies)
            
            # Port-based anomalies (rare ports, scanning)
            if progress_callback:
                progress_callback("Detecting port anomalies", 0.2)
            
            port_anomalies = self._detect_port_anomalies()
            anomalies.extend(port_anomalies)
            
            # Connection burst anomalies
            if progress_callback:
                progress_callback("Detecting connection bursts", 0.3)
            
            burst_anomalies = self._detect_connection_bursts()
            anomalies.extend(burst_anomalies)
            
            # Protocol anomalies
            if progress_callback:
                progress_callback("Detecting protocol anomalies", 0.4)
            
            protocol_anomalies = self._detect_protocol_anomalies()
            anomalies.extend(protocol_anomalies)
            
            # Timing pattern anomalies
            if progress_callback:
                progress_callback("Detecting timing patterns", 0.5)
            
            timing_anomalies = self._detect_timing_patterns()
            anomalies.extend(timing_anomalies)
            
            # Data exfiltration
            if progress_callback:
                progress_callback("Detecting potential data exfiltration", 0.6)
            
            exfil_anomalies = self._detect_data_exfiltration()
            anomalies.extend(exfil_anomalies)
            
            # Beaconing detection
            if progress_callback:
                progress_callback("Detecting beaconing activity", 0.7)
            
            beacon_anomalies = self._detect_beaconing()
            anomalies.extend(beacon_anomalies)
            
            # DNS anomalies
            if progress_callback:
                progress_callback("Detecting DNS anomalies", 0.8)
            
            dns_anomalies = self._detect_dns_anomalies()
            anomalies.extend(dns_anomalies)
            
            # HTTP anomalies
            if progress_callback:
                progress_callback("Detecting HTTP anomalies", 0.9)
            
            http_anomalies = self._detect_http_anomalies()
            anomalies.extend(http_anomalies)
            
            # Add detected anomalies to session
            for anomaly in anomalies:
                self.session.add_anomaly(anomaly)
            
            if progress_callback:
                progress_callback(f"Anomaly detection complete. Found {len(anomalies)} anomalies.", 1.0)
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Error during anomaly detection: {str(e)}")
            if progress_callback:
                progress_callback(f"Error: {str(e)}", 1.0)
            raise
    
    def detect_anomalies_async(
        self, 
        progress_callback: Optional[Callable[[str, float], None]] = None,
        completion_callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None
    ) -> threading.Thread:
        """
        Detect anomalies asynchronously
        
        Args:
            progress_callback: Callback for progress updates
            completion_callback: Callback when analysis completes
            
        Returns:
            Thread object for the detection task
        """
        def task():
            try:
                result = self.detect_anomalies(progress_callback)
                if completion_callback:
                    completion_callback(result)
            except Exception as e:
                self.logger.error(f"Async anomaly detection error: {str(e)}")
                if completion_callback:
                    completion_callback([{"error": str(e)}])
        
        thread = threading.Thread(target=task)
        thread.daemon = True
        thread.start()
        return thread
    
    def stop(self) -> None:
        """Stop ongoing detection"""
        self.stop_processing = True
    
    def _detect_volume_anomalies(self) -> List[Dict[str, Any]]:
        """
        Detect volume-based anomalies (traffic spikes)
        
        Returns:
            List of volume anomalies
        """
        anomalies = []
        
        # Skip if not enough packets
        if len(self.session.packets) < 10:
            return anomalies
        
        # Get time range
        start_time = self.session.metadata.get("start_time")
        end_time = self.session.metadata.get("end_time")
        
        if not start_time or not end_time:
            return anomalies
        
        # Calculate time window based on session duration
        duration = (end_time - start_time).total_seconds()
        if duration <= 60:
            window_size = 1  # 1-second windows for short sessions
        elif duration <= 3600:
            window_size = 60  # 1-minute windows
        else:
            window_size = 300  # 5-minute windows
        
        # Count packets per time window
        packet_counts = defaultdict(int)
        byte_counts = defaultdict(int)
        
        for packet in self.session.packets:
            if self.stop_processing:
                return anomalies
                
            timestamp = packet.get("timestamp")
            if not timestamp:
                continue
                
            # Calculate window index
            window_index = int((timestamp - start_time).total_seconds() / window_size)
            packet_counts[window_index] += 1
            byte_counts[window_index] += packet.get("length", 0)
        
        # Calculate statistics
        if not packet_counts:
            return anomalies
            
        packet_values = list(packet_counts.values())
        byte_values = list(byte_counts.values())
        
        packet_mean = np.mean(packet_values)
        packet_std = np.std(packet_values)
        byte_mean = np.mean(byte_values)
        byte_std = np.std(byte_values)
        
        # Detect spikes (values above threshold standard deviations)
        threshold = self.thresholds["volume_threshold"]
        
        for window_index, count in packet_counts.items():
            if self.stop_processing:
                return anomalies
                
            packet_z_score = (count - packet_mean) / max(packet_std, 1)
            byte_z_score = (byte_counts[window_index] - byte_mean) / max(byte_std, 1)
            
            # Check if either packet count or byte count is anomalous
            if packet_z_score > threshold or byte_z_score > threshold:
                window_start = start_time + timedelta(seconds=window_index * window_size)
                window_end = window_start + timedelta(seconds=window_size)
                
                anomaly = {
                    "type": "volume_spike",
                    "subtype": "packet_count" if packet_z_score > byte_z_score else "byte_count",
                    "severity": "medium" if max(packet_z_score, byte_z_score) > threshold * 1.5 else "low",
                    "timestamp": window_start,
                    "window_start": window_start.isoformat(),
                    "window_end": window_end.isoformat(),
                    "packet_count": count,
                    "byte_count": byte_counts[window_index],
                    "packet_z_score": float(packet_z_score),
                    "byte_z_score": float(byte_z_score),
                    "description": f"Traffic spike detected between {window_start.isoformat()} and {window_end.isoformat()}. "
                                  f"Packet count: {count} (z-score: {packet_z_score:.2f}), "
                                  f"Byte count: {byte_counts[window_index]} (z-score: {byte_z_score:.2f})."
                }
                
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_port_anomalies(self) -> List[Dict[str, Any]]:
        """
        Detect port-based anomalies (rare ports, scanning)
        
        Returns:
            List of port anomalies
        """
        anomalies = []
        
        # Skip if no connections
        if not self.session.connections:
            return anomalies
        
        # Count port usage
        src_ports = Counter()
        dst_ports = Counter()
        port_connections = defaultdict(set)  # port -> set of IPs
        host_ports = defaultdict(set)  # ip -> set of ports
        
        for conn in self.session.connections:
            if self.stop_processing:
                return anomalies
                
            src_ip = conn.get("src_ip")
            dst_ip = conn.get("dst_ip")
            src_port = conn.get("src_port", 0)
            dst_port = conn.get("dst_port", 0)
            
            if src_port > 0:
                src_ports[src_port] += 1
            
            if dst_port > 0:
                dst_ports[dst_port] += 1
                port_connections[dst_port].add(src_ip)
                host_ports[src_ip].add(dst_port)
        
        # Get total connection count
        total_conns = len(self.session.connections)
        
        # Detect rare destination ports
        for port, count in dst_ports.items():
            if self.stop_processing:
                return anomalies
                
            # Skip common ports
            if port in [80, 443, 53, 22, 25, 587, 993, 995, 143, 21, 23]:
                continue
                
            frequency = count / total_conns
            
            if frequency < self.thresholds["rare_port_threshold"] and count > 1:
                # Check if this port is contacted by multiple sources
                if len(port_connections[port]) > 1:
                    severity = "medium"
                else:
                    severity = "low"
                
                connections_for_port = [
                    conn for conn in self.session.connections 
                    if conn.get("dst_port") == port
                ]
                first_seen = min([conn.get("first_seen") for conn in connections_for_port])
                
                anomaly = {
                    "type": "rare_port",
                    "severity": severity,
                    "timestamp": first_seen,
                    "port": port,
                    "connection_count": count,
                    "source_ips": list(port_connections[port]),
                    "frequency": frequency,
                    "description": f"Uncommon port {port} used by {len(port_connections[port])} source(s) "
                                 f"in {count} connection(s) ({frequency:.2%} of all connections)."
                }
                
                anomalies.append(anomaly)
        
        # Detect scanning activity
        for ip, ports in host_ports.items():
            if self.stop_processing:
                return anomalies
                
            if len(ports) >= self.thresholds["scan_threshold"]:
                # Get minimum timestamp for this IP
                ip_connections = [
                    conn for conn in self.session.connections 
                    if conn.get("src_ip") == ip
                ]
                first_seen = min([conn.get("first_seen") for conn in ip_connections])
                
                # Sequential ports increase suspicion
                sequential_ports = 0
                sorted_ports = sorted(ports)
                for i in range(1, len(sorted_ports)):
                    if sorted_ports[i] == sorted_ports[i-1] + 1:
                        sequential_ports += 1
                
                # Determine severity
                if len(ports) > 20 or sequential_ports > 5:
                    severity = "high"
                elif len(ports) > 10 or sequential_ports > 3:
                    severity = "medium"
                else:
                    severity = "low"
                
                anomaly = {
                    "type": "scan_activity",
                    "subtype": "port_scan" if sequential_ports > 3 else "port_sweep",
                    "severity": severity,
                    "timestamp": first_seen,
                    "source_ip": ip,
                    "port_count": len(ports),
                    "sequential_ports": sequential_ports,
                    "scanned_ports": sorted(ports),
                    "description": f"Potential scanning activity from {ip}. "
                                 f"Accessed {len(ports)} unique ports with {sequential_ports} sequential ports."
                }
                
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_connection_bursts(self) -> List[Dict[str, Any]]:
        """
        Detect connection burst anomalies
        
        Returns:
            List of connection burst anomalies
        """
        anomalies = []
        
        # Skip if too few connections
        if len(self.session.connections) < 10:
            return anomalies
        
        # Group connections by 1-second intervals
        conn_times = defaultdict(list)
        
        for conn in self.session.connections:
            if self.stop_processing:
                return anomalies
                
            first_seen = conn.get("first_seen")
            if not first_seen:
                continue
                
            # Group by second
            second_key = first_seen.replace(microsecond=0)
            conn_times[second_key].append(conn)
        
        # Find bursts exceeding threshold
        burst_threshold = self.thresholds["burst_threshold"]
        
        for second, conns in conn_times.items():
            if self.stop_processing:
                return anomalies
                
            if len(conns) >= burst_threshold:
                # Group by source IP
                sources = Counter()
                for conn in conns:
                    sources[conn.get("src_ip")] += 1
                
                # Get most active source
                if sources:
                    most_common_source, source_count = sources.most_common(1)[0]
                    
                    # Calculate severity
                    if len(conns) > burst_threshold * 3:
                        severity = "high"
                    elif len(conns) > burst_threshold * 2:
                        severity = "medium"
                    else:
                        severity = "low"
                    
                    anomaly = {
                        "type": "connection_burst",
                        "severity": severity,
                        "timestamp": second,
                        "connection_count": len(conns),
                        "top_source": most_common_source,
                        "top_source_count": source_count,
                        "source_distribution": dict(sources.most_common(5)),
                        "description": f"Connection burst at {second.isoformat()}: {len(conns)} connections in 1 second. "
                                     f"Top source: {most_common_source} ({source_count} connections)."
                    }
                    
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_protocol_anomalies(self) -> List[Dict[str, Any]]:
        """
        Detect protocol-based anomalies
        
        Returns:
            List of protocol anomalies
        """
        anomalies = []
        
        # Skip if too few packets
        if len(self.session.packets) < 10:
            return anomalies
        
        # Count protocols
        protocols = Counter()
        for packet in self.session.packets:
            if self.stop_processing:
                return anomalies
                
            protocol = packet.get("protocol")
            if protocol:
                protocols[protocol] += 1
        
        # Calculate protocol frequency
        total_packets = len(self.session.packets)
        protocol_frequencies = {p: count/total_packets for p, count in protocols.items()}
        
        # Common protocols
        common_protocols = {"TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "TLS"}
        
        # Find uncommon protocols
        for protocol, frequency in protocol_frequencies.items():
            if self.stop_processing:
                return anomalies
                
            if frequency < 0.05 and protocol not in common_protocols:
                # Find example packets
                example_packets = []
                for i, packet in enumerate(self.session.packets):
                    if packet.get("protocol") == protocol:
                        packet_data = packet.copy()
                        packet_data["packet_index"] = i
                        example_packets.append(packet_data)
                        if len(example_packets) >= 5:
                            break
                
                # Get earliest timestamp
                timestamps = [p.get("timestamp") for p in example_packets if p.get("timestamp")]
                first_seen = min(timestamps) if timestamps else None
                
                anomaly = {
                    "type": "unusual_protocol",
                    "severity": "low",
                    "timestamp": first_seen,
                    "protocol": protocol,
                    "packet_count": protocols[protocol],
                    "frequency": frequency,
                    "example_packets": example_packets,
                    "description": f"Unusual protocol {protocol} detected in {protocols[protocol]} packets "
                                 f"({frequency:.2%} of all packets)."
                }
                
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_timing_patterns(self) -> List[Dict[str, Any]]:
        """
        Detect timing pattern anomalies
        
        Returns:
            List of timing pattern anomalies
        """
        anomalies = []
        
        # Skip if too few connections
        if len(self.session.connections) < 10:
            return anomalies
        
        # Group connections by (src_ip, dst_ip) pairs
        connection_pairs = defaultdict(list)
        
        for conn in self.session.connections:
            if self.stop_processing:
                return anomalies
                
            src_ip = conn.get("src_ip")
            dst_ip = conn.get("dst_ip")
            
            if src_ip and dst_ip:
                pair_key = (src_ip, dst_ip)
                connection_pairs[pair_key].append(conn)
        
        # Analyze timing patterns for each pair with enough connections
        for pair, conns in connection_pairs.items():
            if self.stop_processing:
                return anomalies
                
            if len(conns) < 5:
                continue
                
            # Sort by timestamp
            conns.sort(key=lambda x: x.get("first_seen"))
            
            # Calculate time deltas between connections
            deltas = []
            for i in range(1, len(conns)):
                if conns[i].get("first_seen") and conns[i-1].get("first_seen"):
                    delta = (conns[i]["first_seen"] - conns[i-1]["first_seen"]).total_seconds()
                    deltas.append(delta)
            
            if not deltas:
                continue
                
            # Analyze time deltas
            mean_delta = np.mean(deltas)
            std_delta = np.std(deltas)
            
            # Calculate coefficient of variation (lower value = more regular)
            if mean_delta > 0:
                cv = std_delta / mean_delta
                
                # Regular timing patterns (potential beaconing/C2)
                if cv < self.thresholds["timing_var_threshold"] and len(deltas) >= 5:
                    anomaly = {
                        "type": "timing_pattern",
                        "subtype": "regular_timing",
                        "severity": "medium",
                        "timestamp": conns[0].get("first_seen"),
                        "source_ip": pair[0],
                        "destination_ip": pair[1],
                        "connection_count": len(conns),
                        "mean_interval": mean_delta,
                        "coefficient_variation": cv,
                        "description": f"Regular timing pattern detected between {pair[0]} and {pair[1]}. "
                                     f"{len(conns)} connections with mean interval {mean_delta:.2f} seconds (CV: {cv:.4f})."
                    }
                    
                    anomalies.append(anomaly)
                
                # Very irregular timing (potential human interaction or evasion)
                elif cv > 1.5 and len(deltas) >= 10:
                    anomaly = {
                        "type": "timing_pattern",
                        "subtype": "irregular_timing",
                        "severity": "low",
                        "timestamp": conns[0].get("first_seen"),
                        "source_ip": pair[0],
                        "destination_ip": pair[1],
                        "connection_count": len(conns),
                        "mean_interval": mean_delta,
                        "coefficient_variation": cv,
                        "description": f"Highly irregular timing pattern detected between {pair[0]} and {pair[1]}. "
                                     f"{len(conns)} connections with mean interval {mean_delta:.2f} seconds (CV: {cv:.4f})."
                    }
                    
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_data_exfiltration(self) -> List[Dict[str, Any]]:
        """
        Detect potential data exfiltration
        
        Returns:
            List of data exfiltration anomalies
        """
        anomalies = []
        
        # Skip if too few connections
        if len(self.session.connections) < 5:
            return anomalies
        
        # Group connections by (src_ip, dst_ip) and calculate total bytes transferred
        pair_bytes = defaultdict(int)
        pair_packets = defaultdict(int)
        pair_conns = defaultdict(list)
        
        for conn in self.session.connections:
            if self.stop_processing:
                return anomalies
                
            src_ip = conn.get("src_ip")
            dst_ip = conn.get("dst_ip")
            
            if src_ip and dst_ip:
                pair_key = (src_ip, dst_ip)
                pair_bytes[pair_key] += conn.get("byte_count", 0)
                pair_packets[pair_key] += conn.get("packet_count", 0)
                pair_conns[pair_key].append(conn)
        
        # Check for large data transfers
        for pair, total_bytes in pair_bytes.items():
            if self.stop_processing:
                return anomalies
                
            if total_bytes > self.thresholds["exfil_threshold"]:
                # Calculate packet-to-byte ratio (higher ratio could indicate larger packets)
                packet_count = pair_packets[pair]
                if packet_count > 0:
                    bytes_per_packet = total_bytes / packet_count
                else:
                    bytes_per_packet = 0
                
                # Get connection timestamps
                conns = pair_conns[pair]
                timestamps = [conn.get("first_seen") for conn in conns if conn.get("first_seen")]
                first_seen = min(timestamps) if timestamps else None
                last_seen = max(timestamps) if timestamps else None
                
                # Calculate transfer rate
                transfer_rate = 0
                if first_seen and last_seen:
                    duration = (last_seen - first_seen).total_seconds()
                    if duration > 0:
                        transfer_rate = total_bytes / duration  # bytes per second
                
                # Determine severity
                if total_bytes > self.thresholds["exfil_threshold"] * 10:
                    severity = "high"
                elif total_bytes > self.thresholds["exfil_threshold"] * 3:
                    severity = "medium"
                else:
                    severity = "low"
                
                anomaly = {
                    "type": "data_exfiltration",
                    "severity": severity,
                    "timestamp": first_seen,
                    "source_ip": pair[0],
                    "destination_ip": pair[1],
                    "total_bytes": total_bytes,
                    "packet_count": packet_count,
                    "bytes_per_packet": bytes_per_packet,
                    "transfer_rate": transfer_rate,
                    "first_seen": first_seen.isoformat() if first_seen else None,
                    "last_seen": last_seen.isoformat() if last_seen else None,
                    "description": f"Large data transfer detected from {pair[0]} to {pair[1]}: "
                                 f"{total_bytes} bytes in {packet_count} packets "
                                 f"({bytes_per_packet:.1f} bytes/packet, {transfer_rate:.1f} bytes/sec)."
                }
                
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_beaconing(self) -> List[Dict[str, Any]]:
        """
        Detect beaconing activity (regular communication patterns)
        
        Returns:
            List of beaconing anomalies
        """
        anomalies = []
        
        # Skip if too few connections
        if len(self.session.connections) < 5:
            return anomalies
        
        # Group connections by (src_ip, dst_ip, dst_port) for more precise detection
        conn_groups = defaultdict(list)
        
        for conn in self.session.connections:
            if self.stop_processing:
                return anomalies
                
            src_ip = conn.get("src_ip")
            dst_ip = conn.get("dst_ip")
            dst_port = conn.get("dst_port", 0)
            
            if src_ip and dst_ip:
                group_key = (src_ip, dst_ip, dst_port)
                conn_groups[group_key].append(conn)
        
        # Analyze timing for each group
        for group_key, conns in conn_groups.items():
            if self.stop_processing:
                return anomalies
                
            if len(conns) < 5:
                continue
                
            # Sort by timestamp
            conns.sort(key=lambda x: x.get("first_seen"))
            
            # Calculate time deltas between connections
            deltas = []
            for i in range(1, len(conns)):
                if conns[i].get("first_seen") and conns[i-1].get("first_seen"):
                    delta = (conns[i]["first_seen"] - conns[i-1]["first_seen"]).total_seconds()
                    deltas.append(delta)
            
            if len(deltas) < 4:
                continue
                
            # Check for regular intervals
            mean_delta = np.mean(deltas)
            std_delta = np.std(deltas)
            
            # Calculate jitter (variation relative to mean)
            jitter = std_delta / mean_delta if mean_delta > 0 else float('inf')
            
            # Low jitter indicates regular beaconing
            if jitter < self.thresholds["beaconing_max_jitter"] and mean_delta > 5:
                # Determine severity based on regularity and number of events
                if jitter < 0.05 and len(deltas) >= 10:
                    severity = "high"
                elif jitter < 0.07 and len(deltas) >= 7:
                    severity = "medium"
                else:
                    severity = "low"
                
                anomaly = {
                    "type": "beaconing",
                    "severity": severity,
                    "timestamp": conns[0].get("first_seen"),
                    "source_ip": group_key[0],
                    "destination_ip": group_key[1],
                    "destination_port": group_key[2],
                    "connection_count": len(conns),
                    "interval": mean_delta,
                    "jitter": jitter,
                    "description": f"Potential beaconing activity detected from {group_key[0]} to "
                                 f"{group_key[1]}:{group_key[2]}. {len(conns)} connections with interval "
                                 f"{mean_delta:.2f} seconds (jitter: {jitter:.4f})."
                }
                
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_dns_anomalies(self) -> List[Dict[str, Any]]:
        """
        Detect DNS-related anomalies
        
        Returns:
            List of DNS anomalies
        """
        anomalies = []
        
        # Count DNS queries per domain
        dns_queries = defaultdict(list)
        domain_ip_mappings = defaultdict(set)
        ip_domain_mappings = defaultdict(set)
        
        for packet in self.session.packets:
            if self.stop_processing:
                return anomalies
                
            if "dns" in packet:
                dns_data = packet.get("dns", {})
                if "domains" in dns_data:
                    for domain in dns_data["domains"]:
                        # Add to queries list with timestamp
                        dns_queries[domain].append({
                            "timestamp": packet.get("timestamp"),
                            "src_ip": packet.get("src_ip"),
                            "query_type": dns_data.get("query_type")
                        })
                        
                        # For responses, map domains to IPs
                        if dns_data.get("query_type") == "response" and "src_ip" in packet and "dst_ip" in packet:
                            domain_ip_mappings[domain].add(packet.get("dst_ip"))
                            ip_domain_mappings[packet.get("dst_ip")].add(domain)
        
        # Analyze DNS queries
        for domain, queries in dns_queries.items():
            if self.stop_processing:
                return anomalies
                
            # Skip if too few queries
            if len(queries) < 3:
                continue
                
            # Check for high query volume
            if len(queries) > self.thresholds["dns_query_threshold"]:
                # Get timestamps
                timestamps = [q.get("timestamp") for q in queries if q.get("timestamp")]
                first_seen = min(timestamps) if timestamps else None
                
                # Count unique source IPs
                sources = {q.get("src_ip") for q in queries if q.get("src_ip")}
                
                anomaly = {
                    "type": "dns_anomaly",
                    "subtype": "high_query_volume",
                    "severity": "medium",
                    "timestamp": first_seen,
                    "domain": domain,
                    "query_count": len(queries),
                    "unique_sources": len(sources),
                    "description": f"High DNS query volume for domain {domain}: "
                                 f"{len(queries)} queries from {len(sources)} unique source(s)."
                }
                
                anomalies.append(anomaly)
                
            # Check for unusual domain patterns
            domain_parts = domain.split('.')
            
            # Check for very long domain names (potential DGA)
            if len(domain) > 50:
                # Get timestamps
                timestamps = [q.get("timestamp") for q in queries if q.get("timestamp")]
                first_seen = min(timestamps) if timestamps else None
                
                anomaly = {
                    "type": "dns_anomaly",
                    "subtype": "unusual_domain_length",
                    "severity": "medium",
                    "timestamp": first_seen,
                    "domain": domain,
                    "domain_length": len(domain),
                    "query_count": len(queries),
                    "description": f"Unusually long domain name: {domain} ({len(domain)} characters)."
                }
                
                anomalies.append(anomaly)
            
            # Check for high entropy domain names (potential DGA)
            if len(domain) >= 10:
                # Calculate entropy
                entropy = self._calculate_entropy(domain)
                
                if entropy > 4.0:  # High entropy threshold
                    # Get timestamps
                    timestamps = [q.get("timestamp") for q in queries if q.get("timestamp")]
                    first_seen = min(timestamps) if timestamps else None
                    
                    anomaly = {
                        "type": "dns_anomaly",
                        "subtype": "high_entropy_domain",
                        "severity": "medium",
                        "timestamp": first_seen,
                        "domain": domain,
                        "entropy": entropy,
                        "query_count": len(queries),
                        "description": f"High entropy domain name (possible DGA): {domain} (entropy: {entropy:.2f})."
                    }
                    
                    anomalies.append(anomaly)
        
        # Check for IP addresses with many domain mappings (potential hosting infrastructure)
        for ip, domains in ip_domain_mappings.items():
            if self.stop_processing:
                return anomalies
                
            if len(domains) > 20:  # Threshold for suspicious number of domains
                anomaly = {
                    "type": "dns_anomaly",
                    "subtype": "ip_many_domains",
                    "severity": "low",
                    "timestamp": None,  # No specific timestamp
                    "ip_address": ip,
                    "domain_count": len(domains),
                    "domains": list(domains)[:10],  # Limit to 10 examples
                    "description": f"IP address {ip} is associated with {len(domains)} different domains."
                }
                
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_http_anomalies(self) -> List[Dict[str, Any]]:
        """
        Detect HTTP-related anomalies
        
        Returns:
            List of HTTP anomalies
        """
        anomalies = []
        
        # Collect HTTP requests and responses
        http_data = []
        
        for packet in self.session.packets:
            if self.stop_processing:
                return anomalies
                
            if "http" in packet:
                http_info = packet.get("http", {})
                if http_info:
                    http_data.append({
                        "timestamp": packet.get("timestamp"),
                        "src_ip": packet.get("src_ip"),
                        "dst_ip": packet.get("dst_ip"),
                        "http": http_info,
                        "packet_index": self.session.packets.index(packet)
                    })
        
        # Skip if too few HTTP packets
        if len(http_data) < 5:
            return anomalies
        
        # Group by host
        host_requests = defaultdict(list)
        
        for data in http_data:
            if self.stop_processing:
                return anomalies
                
            http_info = data.get("http", {})
            host = http_info.get("host")
            
            if host:
                host_requests[host].append(data)
        
        # Analyze unusual HTTP methods
        unusual_methods = ["PUT", "DELETE", "CONNECT", "TRACE", "PATCH"]
        
        for data in http_data:
            if self.stop_processing:
                return anomalies
                
            http_info = data.get("http", {})
            method = http_info.get("method")
            
            if method in unusual_methods:
                anomaly = {
                    "type": "http_anomaly",
                    "subtype": "unusual_method",
                    "severity": "medium",
                    "timestamp": data.get("timestamp"),
                    "source_ip": data.get("src_ip"),
                    "destination_ip": data.get("dst_ip"),
                    "method": method,
                    "uri": http_info.get("uri"),
                    "host": http_info.get("host"),
                    "packet_index": data.get("packet_index"),
                    "description": f"Unusual HTTP method {method} from {data.get('src_ip')} to "
                                 f"{data.get('dst_ip')} for {http_info.get('host')}{http_info.get('uri', '')}."
                }
                
                anomalies.append(anomaly)
        
        # Analyze HTTP status codes
        for data in http_data:
            if self.stop_processing:
                return anomalies
                
            http_info = data.get("http", {})
            response_code = http_info.get("response_code")
            
            # Check for error status codes
            if response_code and (response_code >= 400):
                severity = "low"
                
                # Higher severity for certain codes
                if response_code == 407:  # Proxy Authentication Required
                    severity = "medium"
                elif response_code == 401:  # Unauthorized
                    severity = "medium"
                elif response_code == 403:  # Forbidden
                    severity = "medium"
                
                anomaly = {
                    "type": "http_anomaly",
                    "subtype": "error_status",
                    "severity": severity,
                    "timestamp": data.get("timestamp"),
                    "source_ip": data.get("src_ip"),
                    "destination_ip": data.get("dst_ip"),
                    "status_code": response_code,
                    "host": http_info.get("host"),
                    "packet_index": data.get("packet_index"),
                    "description": f"HTTP error status code {response_code} from {data.get('dst_ip')} "
                                 f"to {data.get('src_ip')} for {http_info.get('host')}."
                }
                
                anomalies.append(anomaly)
        
        # Analyze user agents
        user_agents = defaultdict(int)
        
        for data in http_data:
            if self.stop_processing:
                return anomalies
                
            http_info = data.get("http", {})
            user_agent = http_info.get("user_agent")
            
            if user_agent:
                user_agents[user_agent] += 1
        
        # Check for unusual user agents
        for user_agent, count in user_agents.items():
            if self.stop_processing:
                return anomalies
                
            # Skip common browsers
            if any(browser in user_agent for browser in ["Mozilla", "Chrome", "Safari", "Firefox", "Edge"]):
                continue
                
            # Check for suspicious patterns
            if (len(user_agent) < 10 or  # Very short UA
                "curl" in user_agent.lower() or
                "wget" in user_agent.lower() or
                "python" in user_agent.lower() or
                "scanners" in user_agent.lower() or
                "nikto" in user_agent.lower()):
                
                # Find example request
                example = None
                for data in http_data:
                    if data.get("http", {}).get("user_agent") == user_agent:
                        example = data
                        break
                
                if example:
                    anomaly = {
                        "type": "http_anomaly",
                        "subtype": "unusual_user_agent",
                        "severity": "medium",
                        "timestamp": example.get("timestamp"),
                        "source_ip": example.get("src_ip"),
                        "destination_ip": example.get("dst_ip"),
                        "user_agent": user_agent,
                        "occurrence_count": count,
                        "host": example.get("http", {}).get("host"),
                        "description": f"Unusual HTTP User-Agent: '{user_agent}' from {example.get('src_ip')} "
                                     f"({count} occurrences)."
                    }
                    
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        Args:
            text: Input string
            
        Returns:
            Entropy value
        """
        if not text:
            return 0
            
        entropy = 0
        text_length = len(text)
        
        # Count character frequencies
        char_counts = Counter(text)
        
        # Calculate entropy
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * math.log2(probability)
        
        return entropy