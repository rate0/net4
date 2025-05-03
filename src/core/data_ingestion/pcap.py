import os
import time
import threading
import sys
import asyncio
import warnings
import platform
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import uuid

# Import scapy for packet processing
import warnings

# Define global vars 
SCAPY_AVAILABLE = False
load_contrib_success = False

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    from scapy.layers.dns import DNS
    from scapy.all import PcapReader, rdpcap, Raw
    
    # Scapy is available
    SCAPY_AVAILABLE = True
    
    # Try to load TLS layer for HTTPS analysis
    try:
        from scapy.layers import tls
        from scapy.layers.tls import TLS
    except ImportError:
        try:
            from scapy.all import load_contrib
            load_contrib("tls")
            from scapy.layers.tls import TLS
        except:
            # TLS layer not available, we'll handle this case later
            pass
    
    # HTTP layer is in contrib package and requires separate loading
    try:
        # Try to load HTTP layer from contrib
        from scapy.contrib import http
        # Check if HTTP layer loaded successfully
        if hasattr(http, 'HTTPRequest'):
            load_contrib_success = True
        else:
            # If class not found, try to load explicitly
            from scapy.all import load_contrib
            load_contrib("http")
            from scapy.contrib import http
            load_contrib_success = True
    except ImportError:
        # If HTTP layer couldn't be loaded, mark this
        load_contrib_success = False
        warnings.warn("Scapy HTTP layer not available. HTTP parsing will be limited.")
    
except ImportError:
    warnings.warn("Scapy is not installed. Please install it with: pip install scapy")

from ...models.session import Session
from ...models.network_entity import NetworkEntity
from ...utils.logger import Logger

class PcapProcessor:
    """
    Processes PCAP files and extracts network entities, connections, and packets.
    Uses Scapy (pure Python) for packet processing without external dependencies.
    Supports HTTP/HTTPS traffic analysis.
    """
    
    def __init__(self, session: Session, debug: bool = False):
        """
        Initialize PCAP processor
        
        Args:
            session: Session to store extracted data
            debug: Enable debug logging
        """
        self.session = session
        self.logger = Logger().get_logger()
        self.stop_processing = False
        self.debug = debug
        
        # Check if Scapy is available
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is not available. Please install it with: pip install scapy")
        
        # Additional check for TLS support
        try:
            # Check if TLS is already defined
            if 'TLS' not in globals():
                # Try to import it
                from scapy.layers.tls import TLS
        except ImportError:
            # TLS not available, we'll work without it
            self.logger.info("TLS layer not available in Scapy, HTTPS analysis will be limited")
            
        # Log availability of HTTP layer
        if load_contrib_success:
            self.logger.info("Scapy HTTP layer available for enhanced HTTP parsing")
        else:
            self.logger.info("Using basic HTTP parsing (Scapy HTTP layer not available)")
        
        self.logger.info("Using Scapy backend for PCAP processing")
    
    
    def process_file(
        self, 
        file_path: str, 
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Process a PCAP file and extract data using Scapy
        
        Args:
            file_path: Path to PCAP file
            progress_callback: Callback function for progress updates
            
        Returns:
            Dict containing summary of processed data
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")
        
        self.logger.info(f"Processing PCAP file: {file_path}")
        
        # Add file to session
        file_id = self.session.add_file(file_path, "pcap")
        
        # Check file size to determine processing strategy
        file_size = os.path.getsize(file_path)
        is_large_file = file_size > 100 * 1024 * 1024  # 100 MB threshold
        
        # Process with the appropriate strategy based on file size
        if is_large_file:
            self.logger.info(f"Large file detected ({file_size / (1024 * 1024):.2f} MB), using streaming mode")
            return self._process_with_scapy_streaming(file_path, file_id, progress_callback)
        else:
            self.logger.info(f"Standard file size ({file_size / (1024 * 1024):.2f} MB), loading into memory")
            return self._process_with_scapy(file_path, file_id, progress_callback)
    
    
    def _process_with_scapy(
        self, 
        file_path: str, 
        file_id: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Process a PCAP file using scapy (no external dependencies)
        
        Args:
            file_path: Path to PCAP file
            file_id: File ID in the session
            progress_callback: Callback function for progress updates
            
        Returns:
            Dict containing summary of processed data
        """
        try:
            self.logger.info("Processing PCAP with scapy (pure Python)")
            
            # Check file size to determine strategy
            file_size = os.path.getsize(file_path)
            is_large_file = file_size > 100 * 1024 * 1024  # 100 MB threshold
            is_very_large_file = file_size > 1024 * 1024 * 1024  # 1 GB threshold
            
            # For very large files, use packet sampling
            packet_sampling = 1  # Default: process every packet
            if is_very_large_file:
                packet_sampling = 10  # Process every 10th packet
                self.logger.info(f"Very large file detected ({file_size / (1024 * 1024 * 1024):.2f} GB), using packet sampling")
            
            # For large files, use PcapReader instead of rdpcap for memory efficiency
            if is_large_file:
                self.logger.info(f"Large file detected ({file_size / (1024 * 1024):.2f} MB), using memory-efficient processing")
                # Estimate packet count based on file size (rough approximation)
                packet_count = int(file_size / 1500)  # Assuming average packet size of 1500 bytes
                self.logger.info(f"Estimated packet count: ~{packet_count}")
                
                # Process packets in streaming mode
                return self._process_with_scapy_streaming(file_path, file_id, packet_count, packet_sampling, progress_callback)
            else:
                # For smaller files, use standard rdpcap
                # Load packets with scapy
                self.logger.info("Loading packets with scapy...")
                packets = scapy.rdpcap(file_path)
                packet_count = len(packets)
                self.logger.info(f"Loaded {packet_count} packets with scapy")
                
                # Process packets
                processed_count = 0
                
                start_time = time.time()
                
                # Entities and connections for tracking unique ones
                ip_entities = {}
                domain_entities = {}
                connections = set()
                
                # Process packets in batches for better performance
                batch_size = 1000
                current_batch = []
                
                for i, packet in enumerate(packets):
                    if self.stop_processing:
                        break
                    
                    # Skip packets based on sampling rate for very large files
                    if is_very_large_file and i % packet_sampling != 0:
                        continue
                    
                    # Extract packet data
                    packet_data = self._extract_packet_data_scapy(packet, i+1)
                    if packet_data:
                        # Instead of adding directly, collect in batch
                        current_batch.append(packet_data)
                        processed_count += 1
                        
                        # Process in batches for better performance
                        if len(current_batch) >= batch_size:
                            # Add packets in batch
                            for p_data in current_batch:
                                self.session.add_packet(p_data)
                                
                                # Extract and add network entities
                                self._process_network_entities(p_data, ip_entities, domain_entities)
                                
                                # Extract and add connections
                                self._process_connections(p_data, connections)
                            
                            # Clear batch
                            current_batch = []
                    
                    # Update progress every 100 packets or every 1000 for very large files
                    progress_interval = 1000 if is_very_large_file else 100
                    if (i+1) % progress_interval == 0 and progress_callback:
                        try:
                            progress_callback(i+1, packet_count)
                        except Exception as e:
                            self.logger.warning(f"Error in progress callback: {str(e)}")
                
                # Process any remaining packets in the last batch
                for p_data in current_batch:
                    self.session.add_packet(p_data)
                    self._process_network_entities(p_data, ip_entities, domain_entities)
                    self._process_connections(p_data, connections)
                
                # Final progress update
                if progress_callback:
                    try:
                        progress_callback(packet_count, packet_count)
                    except Exception as e:
                        self.logger.warning(f"Error in final progress callback: {str(e)}")
                
                # Update file metadata
                file_metadata = {
                    "packet_count": packet_count,
                    "processed_count": processed_count,
                    "processing_time": time.time() - start_time,
                    "entity_count": len(ip_entities) + len(domain_entities),
                    "connection_count": len(connections),
                    "backend": "scapy",
                    "file_size_mb": file_size / (1024 * 1024),
                    "sampling_rate": packet_sampling
                }
                
                self.session.files[file_id]["metadata"] = file_metadata
                
                self.logger.info(f"PCAP processing complete: {processed_count}/{packet_count} packets processed with scapy")
                
                return {
                    "file_id": file_id,
                    "packet_count": packet_count,
                    "processed_count": processed_count,
                    "ip_entities": len(ip_entities),
                    "domain_entities": len(domain_entities),
                    "connections": len(connections),
                    "backend": "scapy",
                    "file_size_mb": file_size / (1024 * 1024),
                    "sampling_rate": packet_sampling
                }
            
        except Exception as e:
            self.logger.error(f"Error processing PCAP file with scapy: {str(e)}")
            raise
    
    def _process_with_scapy_streaming(
        self, 
        file_path: str, 
        file_id: str,
        estimated_packet_count: int,
        packet_sampling: int,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Process a PCAP file using scapy's PcapReader for memory-efficient streaming
        
        Args:
            file_path: Path to PCAP file
            file_id: File ID in the session
            estimated_packet_count: Estimated number of packets
            packet_sampling: Process every Nth packet (for sampling)
            progress_callback: Callback function for progress updates
            
        Returns:
            Dict containing summary of processed data
        """
        try:
            start_time = time.time()
            
            # Entities and connections for tracking unique ones
            ip_entities = {}
            domain_entities = {}
            connections = set()
            
            # Periodic state saving
            last_state_save_time = time.time()
            state_save_interval = 60  # Save state every 60 seconds
            
            # Process packets in batches for better performance
            batch_size = 1000
            current_batch = []
            
            packet_count = 0
            processed_count = 0
            
            # Use PcapReader for streaming processing (memory efficient)
            with scapy.PcapReader(file_path) as pcap_reader:
                for packet in pcap_reader:
                    if self.stop_processing:
                        break
                    
                    packet_count += 1
                    
                    # Skip packets based on sampling rate
                    if packet_sampling > 1 and packet_count % packet_sampling != 0:
                        continue
                    
                    # Extract packet data
                    packet_data = self._extract_packet_data_scapy(packet, packet_count)
                    if packet_data:
                        # Instead of adding directly, collect in batch
                        current_batch.append(packet_data)
                        processed_count += 1
                        
                        # Process in batches for better performance
                        if len(current_batch) >= batch_size:
                            # Add packets in batch
                            for p_data in current_batch:
                                self.session.add_packet(p_data)
                                
                                # Extract and add network entities
                                self._process_network_entities(p_data, ip_entities, domain_entities)
                                
                                # Extract and add connections
                                self._process_connections(p_data, connections)
                            
                            # Clear batch
                            current_batch = []
                    
                    # Update progress every 1000 packets
                    if packet_count % 1000 == 0 and progress_callback:
                        try:
                            # For sampled processing, adjust the progress reporting
                            if packet_sampling > 1:
                                progress_callback(packet_count // packet_sampling, estimated_packet_count // packet_sampling)
                            else:
                                progress_callback(packet_count, estimated_packet_count)
                        except Exception as e:
                            self.logger.warning(f"Error in progress callback: {str(e)}")
                    
                    # Periodically save state to prevent memory issues
                    if time.time() - last_state_save_time > state_save_interval:
                        self.logger.info(f"Periodic state save after processing {packet_count} packets")
                        # Force garbage collection
                        import gc
                        gc.collect()
                        last_state_save_time = time.time()
            
            # Process any remaining packets in the last batch
            for p_data in current_batch:
                self.session.add_packet(p_data)
                self._process_network_entities(p_data, ip_entities, domain_entities)
                self._process_connections(p_data, connections)
            
            # Final progress update
            if progress_callback:
                try:
                    if packet_sampling > 1:
                        progress_callback(packet_count // packet_sampling, estimated_packet_count // packet_sampling)
                    else:
                        progress_callback(packet_count, packet_count)  # Use actual count for final update
                except Exception as e:
                    self.logger.warning(f"Error in final progress callback: {str(e)}")
            
            # Calculate file size
            file_size = os.path.getsize(file_path)
            
            # Update file metadata
            file_metadata = {
                "packet_count": packet_count,
                "processed_count": processed_count,
                "processing_time": time.time() - start_time,
                "entity_count": len(ip_entities) + len(domain_entities),
                "connection_count": len(connections),
                "backend": "scapy-streaming",
                "file_size_mb": file_size / (1024 * 1024),
                "sampling_rate": packet_sampling
            }
            
            self.session.files[file_id]["metadata"] = file_metadata
            
            self.logger.info(f"PCAP processing complete: {processed_count}/{packet_count} packets processed with scapy streaming")
            
            return {
                "file_id": file_id,
                "packet_count": packet_count,
                "processed_count": processed_count,
                "ip_entities": len(ip_entities),
                "domain_entities": len(domain_entities),
                "connections": len(connections),
                "backend": "scapy-streaming",
                "file_size_mb": file_size / (1024 * 1024),
                "sampling_rate": packet_sampling
            }
            
        except Exception as e:
            self.logger.error(f"Error processing PCAP file with scapy streaming: {str(e)}")
            raise
    
    
    def _extract_packet_data_scapy(self, packet, frame_number) -> Optional[Dict[str, Any]]:
        """
        Extract relevant data from a scapy packet with enhanced HTTP/HTTPS support
        
        Args:
            packet: scapy packet object
            frame_number: Frame number (position in capture)
            
        Returns:
            Dictionary with packet data or None if packet should be skipped
        """
        try:
            # Basic packet data
            packet_data = {
                "frame_number": frame_number,
                "timestamp": datetime.fromtimestamp(float(packet.time)),
                "length": len(packet),
                "protocol": None
            }
            
            # Extract IP layer data if present
            if IP in packet:
                packet_data.update({
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "ip_version": packet[IP].version,
                    "ttl": packet[IP].ttl
                })
                
                # Determine protocol
                if TCP in packet:
                    packet_data["protocol"] = "TCP"
                    packet_data.update({
                        "src_port": packet[TCP].sport,
                        "dst_port": packet[TCP].dport,
                        "tcp_flags": {
                            "syn": 1 if packet[TCP].flags & 0x02 else 0,  # SYN flag
                            "ack": 1 if packet[TCP].flags & 0x10 else 0,  # ACK flag
                            "fin": 1 if packet[TCP].flags & 0x01 else 0,  # FIN flag
                            "rst": 1 if packet[TCP].flags & 0x04 else 0   # RST flag
                        },
                        "tcp_seq": packet[TCP].seq,
                        "tcp_ack": packet[TCP].ack,
                        "window_size": packet[TCP].window
                    })
                elif UDP in packet:
                    packet_data["protocol"] = "UDP"
                    packet_data.update({
                        "src_port": packet[UDP].sport,
                        "dst_port": packet[UDP].dport,
                        "udp_length": len(packet[UDP])
                    })
                elif ICMP in packet:
                    packet_data["protocol"] = "ICMP"
                    packet_data.update({
                        "icmp_type": packet[ICMP].type,
                        "icmp_code": packet[ICMP].code
                    })
            
            # Extract DNS data if present
            if packet.haslayer(DNS):
                dns_pkt = packet[DNS]
                dns_data = {"query_type": "unknown", "domains": []}
                
                try:
                    # Check if it's a query or response
                    if hasattr(dns_pkt, 'qr'):
                        if dns_pkt.qr == 0:
                            dns_data["query_type"] = "query"
                            if hasattr(dns_pkt, 'qd') and dns_pkt.qd:
                                try:
                                    if hasattr(dns_pkt.qd, 'qname'):
                                        qname = dns_pkt.qd.qname
                                        if isinstance(qname, bytes):
                                            domain = qname.decode('utf-8', errors='ignore').rstrip('.')
                                        else:
                                            domain = str(qname).rstrip('.')
                                        if domain:
                                            dns_data["domains"].append(domain)
                                except Exception as e:
                                    if self.debug:
                                        self.logger.debug(f"Error parsing DNS query name: {str(e)}")
                        else:
                            dns_data["query_type"] = "response"
                            # Extract query name
                            if hasattr(dns_pkt, 'qd') and dns_pkt.qd:
                                try:
                                    if hasattr(dns_pkt.qd, 'qname'):
                                        qname = dns_pkt.qd.qname
                                        if isinstance(qname, bytes):
                                            domain = qname.decode('utf-8', errors='ignore').rstrip('.')
                                        else:
                                            domain = str(qname).rstrip('.')
                                        if domain:
                                            dns_data["domains"].append(domain)
                                except Exception as e:
                                    if self.debug:
                                        self.logger.debug(f"Error parsing DNS response query name: {str(e)}")
                            
                            # Extract answer names
                            if hasattr(dns_pkt, 'an') and dns_pkt.an:
                                try:
                                    an_count = dns_pkt.ancount if hasattr(dns_pkt, 'ancount') else len(dns_pkt.an)
                                    for i in range(an_count):
                                        if i < len(dns_pkt.an) and hasattr(dns_pkt.an[i], 'rrname'):
                                            rrname = dns_pkt.an[i].rrname
                                            if isinstance(rrname, bytes):
                                                name = rrname.decode('utf-8', errors='ignore').rstrip('.')
                                            else:
                                                name = str(rrname).rstrip('.')
                                            if name and name not in dns_data["domains"]:
                                                dns_data["domains"].append(name)
                                except Exception as e:
                                    if self.debug:
                                        self.logger.debug(f"Error parsing DNS answer names: {str(e)}")
                
                    # Add DNS data only if we found domains
                    if dns_data["domains"]:
                        packet_data["dns"] = dns_data
                except Exception as e:
                    if self.debug:
                        self.logger.debug(f"Error processing DNS packet: {str(e)}")
            
            # HTTP/HTTPS Traffic Analysis
            http_data = {}
            http_layer_detected = False
            https_detected = False
            
            # Check if Scapy HTTP layer is available
            if 'load_contrib_success' in globals() and load_contrib_success:
                # Use HTTP layer API if available
                if packet.haslayer(http.HTTPRequest):
                    http_req = packet[http.HTTPRequest]
                    http_layer_detected = True
                    
                    # Extract method
                    if hasattr(http_req, 'Method'):
                        method_bytes = http_req.Method
                        http_data["method"] = method_bytes.decode('utf-8', errors='ignore') if isinstance(method_bytes, bytes) else str(method_bytes)
                    
                    # Extract URI
                    if hasattr(http_req, 'Path'):
                        path_bytes = http_req.Path
                        http_data["uri"] = path_bytes.decode('utf-8', errors='ignore') if isinstance(path_bytes, bytes) else str(path_bytes)
                    
                    # Extract host
                    if hasattr(http_req, 'Host'):
                        host_bytes = http_req.Host
                        http_data["host"] = host_bytes.decode('utf-8', errors='ignore') if isinstance(host_bytes, bytes) else str(host_bytes)
                    
                    # Extract User-Agent
                    if hasattr(http_req, 'User_Agent'):
                        ua_bytes = http_req.User_Agent
                        http_data["user_agent"] = ua_bytes.decode('utf-8', errors='ignore') if isinstance(ua_bytes, bytes) else str(ua_bytes)
                    
                    # Mark as web traffic
                    packet_data["web_traffic"] = True
                    packet_data["is_https"] = False
                
                elif packet.haslayer(http.HTTPResponse):
                    http_resp = packet[http.HTTPResponse]
                    http_layer_detected = True
                    
                    # Extract response code
                    if hasattr(http_resp, 'Status_Code'):
                        status_code = http_resp.Status_Code
                        try:
                            if isinstance(status_code, bytes):
                                http_data["response_code"] = int(status_code.decode('utf-8', errors='ignore'))
                            else:
                                http_data["response_code"] = int(str(status_code))
                        except ValueError:
                            pass
                    
                    # Mark as web traffic
                    packet_data["web_traffic"] = True
                    packet_data["is_https"] = False
            
            # Check for TLS/HTTPS traffic
            try:
                has_tls_layer = False
                # Check if TLS is defined and if the packet has a TLS layer
                if 'TLS' in globals():
                    has_tls_layer = packet.haslayer(TLS)
                
                # Detect HTTPS traffic either by TLS layer or port 443
                if has_tls_layer or (TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443)):
                    https_detected = True
                    packet_data["web_traffic"] = True
                    packet_data["is_https"] = True
                    packet_data["protocol_app"] = "HTTPS"
                    
                    # Try to extract SNI (Server Name Indication) for HTTPS connections if TLS layer is available
                    if has_tls_layer:
                        try:
                            # Extract ClientHello messages which contain the SNI
                            if hasattr(packet[TLS], 'type') and packet[TLS].type == 1:  # ClientHello
                                if hasattr(packet[TLS], 'msg') and hasattr(packet[TLS].msg[0], 'ext'):
                                    for ext in packet[TLS].msg[0].ext:
                                        # Extension 0 is SNI (Server Name Indication)
                                        if hasattr(ext, 'type') and ext.type == 0:
                                            if hasattr(ext, 'servernames'):
                                                for sn in ext.servernames:
                                                    if hasattr(sn, 'servername'):
                                                        name = sn.servername
                                                        if isinstance(name, bytes):
                                                            http_data["host"] = name.decode('utf-8', errors='ignore')
                                                        else:
                                                            http_data["host"] = str(name)
                        except Exception as e:
                            if self.debug:
                                self.logger.debug(f"Error extracting SNI from TLS: {str(e)}")
            except Exception as e:
                if self.debug:
                    self.logger.debug(f"Error detecting HTTPS traffic: {str(e)}")
            
            # Alternative HTTP detection based on ports and content analysis
            if not http_layer_detected and not https_detected and TCP in packet:
                tcp_packet = packet[TCP]
                web_ports = [80, 8000, 8080, 8888, 8443]
                
                if tcp_packet.dport in web_ports or tcp_packet.sport in web_ports:
                    # This may be HTTP traffic based on ports
                    if packet.haslayer(Raw):
                        try:
                            raw_data = packet[Raw].load
                            if isinstance(raw_data, bytes):
                                # Decode with a liberal approach to handle binary data
                                raw_text = raw_data.decode('utf-8', errors='ignore')
                                
                                # Check for HTTP request patterns
                                if any(raw_text.startswith(method) for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ']):
                                    # Process HTTP request
                                    lines = raw_text.split('\r\n')
                                    if lines:
                                        # Parse request line
                                        req_line = lines[0].split(' ')
                                        if len(req_line) >= 3:
                                            http_data["method"] = req_line[0]
                                            http_data["uri"] = req_line[1]
                                            http_data["version"] = req_line[2]
                                            
                                            # Parse headers
                                            for header_line in lines[1:]:
                                                if not header_line or header_line.isspace():
                                                    break
                                                
                                                if ':' in header_line:
                                                    header_name, header_value = header_line.split(':', 1)
                                                    header_name = header_name.strip().lower()
                                                    header_value = header_value.strip()
                                                    
                                                    if header_name == 'host':
                                                        http_data["host"] = header_value
                                                    elif header_name == 'user-agent':
                                                        http_data["user_agent"] = header_value
                                                    elif header_name == 'content-type':
                                                        http_data["content_type"] = header_value
                                                    elif header_name == 'content-length':
                                                        try:
                                                            http_data["content_length"] = int(header_value)
                                                        except ValueError:
                                                            pass
                                    
                                    # Mark as web traffic
                                    packet_data["web_traffic"] = True
                                    packet_data["is_https"] = False
                                    packet_data["protocol_app"] = "HTTP"
                                
                                # Check for HTTP response patterns
                                elif raw_text.startswith('HTTP/'):
                                    # Process HTTP response
                                    lines = raw_text.split('\r\n')
                                    if lines:
                                        # Parse status line
                                        status_line = lines[0].split(' ', 2)
                                        if len(status_line) >= 3:
                                            try:
                                                http_data["version"] = status_line[0]
                                                http_data["response_code"] = int(status_line[1])
                                                http_data["status_message"] = status_line[2]
                                            except (ValueError, IndexError):
                                                pass
                                            
                                            # Parse headers
                                            for header_line in lines[1:]:
                                                if not header_line or header_line.isspace():
                                                    break
                                                
                                                if ':' in header_line:
                                                    header_name, header_value = header_line.split(':', 1)
                                                    header_name = header_name.strip().lower()
                                                    header_value = header_value.strip()
                                                    
                                                    if header_name == 'server':
                                                        http_data["server"] = header_value
                                                    elif header_name == 'content-type':
                                                        http_data["content_type"] = header_value
                                                    elif header_name == 'content-length':
                                                        try:
                                                            http_data["content_length"] = int(header_value)
                                                        except ValueError:
                                                            pass
                                    
                                    # Mark as web traffic
                                    packet_data["web_traffic"] = True
                                    packet_data["is_https"] = False
                                    packet_data["protocol_app"] = "HTTP"
                        except Exception as e:
                            if self.debug:
                                self.logger.debug(f"Error parsing raw HTTP data: {str(e)}")
            
            # Add HTTP data if we found any
            if http_data:
                packet_data["http"] = http_data
            
            return packet_data
        
        except Exception as e:
            self.logger.warning(f"Error extracting packet data with scapy: {str(e)}")
            return None
    
    def _process_network_entities(
        self, 
        packet_data: Dict[str, Any],
        ip_entities: Dict[str, str],
        domain_entities: Dict[str, str]
    ) -> None:
        """
        Process and add network entities from packet data
        
        Args:
            packet_data: Extracted packet data
            ip_entities: Dictionary of IP entities (for tracking)
            domain_entities: Dictionary of domain entities (for tracking)
        """
        try:
            # Get timestamp from packet data
            timestamp = packet_data.get("timestamp", datetime.now())
            
            # Process IP addresses
            for ip_type in ["src_ip", "dst_ip"]:
                if ip_type in packet_data:
                    ip = packet_data[ip_type]
                    if ip:
                        if ip not in ip_entities:
                            try:
                                entity = NetworkEntity(
                                    entity_type="ip",
                                    value=ip,
                                    name=f"IP: {ip}"
                                )
                                # Set timestamp when entity is first seen
                                entity.update_seen_time(timestamp)
                                self.session.add_network_entity(entity)
                                ip_entities[ip] = entity.id
                            except Exception as e:
                                self.logger.warning(f"Error adding IP entity {ip}: {str(e)}")
                        else:
                            # Update timestamp for existing entity
                            try:
                                entity_id = ip_entities[ip]
                                entity = self.session.get_network_entity(entity_id)
                                if entity:
                                    entity.update_seen_time(timestamp)
                            except Exception as e:
                                self.logger.warning(f"Error updating timestamp for IP entity {ip}: {str(e)}")
            
            # Process domains from DNS
            if "dns" in packet_data and "domains" in packet_data["dns"]:
                for domain in packet_data["dns"]["domains"]:
                    if domain:
                        if domain not in domain_entities:
                            try:
                                entity = NetworkEntity(
                                    entity_type="domain",
                                    value=domain,
                                    name=f"Domain: {domain}"
                                )
                                # Set timestamp when entity is first seen
                                entity.update_seen_time(timestamp)
                                self.session.add_network_entity(entity)
                                domain_entities[domain] = entity.id
                            except Exception as e:
                                self.logger.warning(f"Error adding DNS domain entity {domain}: {str(e)}")
                        else:
                            # Update timestamp for existing entity
                            try:
                                entity_id = domain_entities[domain]
                                entity = self.session.get_network_entity(entity_id)
                                if entity:
                                    entity.update_seen_time(timestamp)
                            except Exception as e:
                                self.logger.warning(f"Error updating timestamp for domain entity {domain}: {str(e)}")
            
            # Process domains from HTTP
            if "http" in packet_data and "host" in packet_data["http"]:
                host = packet_data["http"]["host"]
                if host:
                    if host not in domain_entities:
                        try:
                            entity = NetworkEntity(
                                entity_type="domain",
                                value=host,
                                name=f"Domain: {host}"
                            )
                            # Set timestamp when entity is first seen
                            entity.update_seen_time(timestamp)
                            self.session.add_network_entity(entity)
                            domain_entities[host] = entity.id
                        except Exception as e:
                            self.logger.warning(f"Error adding HTTP host entity {host}: {str(e)}")
                    else:
                        # Update timestamp for existing entity
                        try:
                            entity_id = domain_entities[host]
                            entity = self.session.get_network_entity(entity_id)
                            if entity:
                                entity.update_seen_time(timestamp)
                        except Exception as e:
                            self.logger.warning(f"Error updating timestamp for HTTP host entity {host}: {str(e)}")
        except Exception as e:
            self.logger.warning(f"Error processing network entities: {str(e)}")
    
    def _process_connections(
        self, 
        packet_data: Dict[str, Any],
        connections: set
    ) -> None:
        """
        Process and add network connections from packet data
        
        Args:
            packet_data: Extracted packet data
            connections: Set of connection tuples (for tracking unique connections)
        """
        try:
            if all(k in packet_data for k in ["src_ip", "dst_ip"]):
                src_ip = packet_data["src_ip"]
                dst_ip = packet_data["dst_ip"]
                
                src_port = packet_data.get("src_port", 0)
                dst_port = packet_data.get("dst_port", 0)
                protocol = packet_data.get("protocol", "UNKNOWN")
                
                # Проверка валидности данных
                if not src_ip or not dst_ip:
                    return
                
                # Create connection key
                conn_key = (src_ip, src_port, dst_ip, dst_port, protocol)
                
                # Only add if this is a new connection
                if conn_key not in connections:
                    connections.add(conn_key)
                    
                    connection = {
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "first_seen": packet_data["timestamp"],
                        "last_seen": packet_data["timestamp"],
                        "packet_count": 1,
                        "byte_count": packet_data["length"]
                    }
                    
                    try:
                        self.session.add_connection(connection)
                    except Exception as e:
                        self.logger.warning(f"Error adding connection: {str(e)}")
                else:
                    # Update existing connection
                    try:
                        for conn in self.session.connections:
                            if (conn["src_ip"] == src_ip and 
                                conn["src_port"] == src_port and
                                conn["dst_ip"] == dst_ip and 
                                conn["dst_port"] == dst_port and
                                conn["protocol"] == protocol):
                                
                                conn["last_seen"] = packet_data["timestamp"]
                                conn["packet_count"] += 1
                                conn["byte_count"] += packet_data["length"]
                                break
                    except Exception as e:
                        self.logger.warning(f"Error updating connection: {str(e)}")
        except Exception as e:
            self.logger.warning(f"Error processing connections: {str(e)}")
    
    def process_file_async(
        self, 
        file_path: str, 
        progress_callback: Optional[Callable[[int, int], None]] = None,
        completion_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> threading.Thread:
        """
        Process a PCAP file asynchronously using Scapy
        
        Args:
            file_path: Path to PCAP file
            progress_callback: Callback function for progress updates
            completion_callback: Callback function when processing completes
            
        Returns:
            Thread object for the processing task
        """
        def task():
            # Create and set an event loop for this thread if needed
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            try:
                self.logger.info(f"Starting async PCAP processing for: {file_path}")
                result = self.process_file(file_path, progress_callback)
                
                # Call completion callback with results if provided
                if completion_callback:
                    try:
                        self.logger.info(f"PCAP processing complete, calling completion callback")
                        completion_callback(result)
                    except Exception as e:
                        self.logger.error(f"Error in completion callback: {str(e)}")
            except Exception as e:
                self.logger.error(f"Async PCAP processing error: {str(e)}")
                if completion_callback:
                    try:
                        completion_callback({"error": str(e), "file_path": file_path})
                    except Exception as callback_err:
                        self.logger.error(f"Error in error callback: {str(callback_err)}")
        
        # Create and start the thread
        thread = threading.Thread(target=task, name="ScapyPcapProcessorThread")
        thread.daemon = True
        thread.start()
        
        self.logger.info(f"Started async PCAP processing thread for: {file_path}")
        return thread
    
    def stop(self) -> None:
        """Stop ongoing processing"""
        self.stop_processing = True
        
    def capture_live(
        self, 
        interface: str, 
        filter_str: Optional[str] = None,
        packet_count: Optional[int] = None,
        timeout: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        packet_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> threading.Thread:
        """
        Capture packets from a live interface using Scapy
        
        Args:
            interface: Network interface to capture from
            filter_str: BPF filter string (e.g. "tcp port 80")
            packet_count: Number of packets to capture (None for unlimited)
            timeout: Timeout in seconds (None for no timeout)
            progress_callback: Callback function for progress updates
            packet_callback: Callback function for each processed packet
            
        Returns:
            Thread object for the capture task
        """
        # Reset stop flag
        self.stop_processing = False
        
        def capture_task():
            try:
                # Create and set an event loop for this thread
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                
                self.logger.info(f"Starting live capture on interface: {interface}")
                if filter_str:
                    self.logger.info(f"Using filter: {filter_str}")
                
                # Set up counters
                processed_count = 0
                
                # Create unique file ID for this capture session
                capture_id = f"live-{uuid.uuid4()}"
                
                # Add capture to session
                file_id = self.session.add_file(f"Live capture on {interface}", "live-capture")
                
                # Entities and connections for tracking unique ones
                ip_entities = {}
                domain_entities = {}
                connections = set()
                
                # Define packet handler
                def packet_handler(packet):
                    nonlocal processed_count
                    
                    if self.stop_processing:
                        return
                    
                    try:
                        # Extract packet data
                        packet_data = self._extract_packet_data_scapy(packet, processed_count + 1)
                        if packet_data:
                            # Add packet to session
                            self.session.add_packet(packet_data)
                            
                            # Extract and add network entities
                            self._process_network_entities(packet_data, ip_entities, domain_entities)
                            
                            # Extract and add connections
                            self._process_connections(packet_data, connections)
                            
                            # Increment counter
                            processed_count += 1
                            
                            # Call packet callback if provided
                            if packet_callback:
                                try:
                                    packet_callback(packet_data)
                                except Exception as e:
                                    self.logger.warning(f"Error in packet callback: {str(e)}")
                            
                            # Update progress occasionally
                            if processed_count % 10 == 0 and progress_callback:
                                try:
                                    # For live capture we use processed packets as progress
                                    # and desired count (or 0 for unlimited) as total
                                    progress_callback(processed_count, packet_count or 0)
                                except Exception as e:
                                    self.logger.warning(f"Error in progress callback: {str(e)}")
                    
                    except Exception as e:
                        self.logger.warning(f"Error processing live packet: {str(e)}")
                
                # Start the live capture
                try:
                    self.logger.info("Starting Scapy sniffer...")
                    
                    # Set capture parameters
                    sniff_kwargs = {
                        "iface": interface,
                        "prn": packet_handler,
                        "store": False  # Don't store packets in memory
                    }
                    
                    # Add filter if provided
                    if filter_str:
                        sniff_kwargs["filter"] = filter_str
                    
                    # Add count if provided
                    if packet_count:
                        sniff_kwargs["count"] = packet_count
                    
                    # Add timeout if provided
                    if timeout:
                        sniff_kwargs["timeout"] = timeout
                    
                    # Start sniffing
                    self.logger.info(f"Sniffing with params: {sniff_kwargs}")
                    scapy.sniff(**sniff_kwargs)
                    
                    self.logger.info("Live capture completed or stopped")
                    
                except KeyboardInterrupt:
                    self.logger.info("Live capture interrupted by user")
                except Exception as e:
                    self.logger.error(f"Error in live capture: {str(e)}")
                
                # Update file metadata
                file_metadata = {
                    "interface": interface,
                    "filter": filter_str,
                    "processed_count": processed_count,
                    "entity_count": len(ip_entities) + len(domain_entities),
                    "connection_count": len(connections),
                    "backend": "scapy-live"
                }
                
                self.session.files[file_id]["metadata"] = file_metadata
                
                self.logger.info(f"Live capture processed {processed_count} packets")
            
            except Exception as e:
                self.logger.error(f"Error in capture task: {str(e)}")
                if completion_callback:
                    try:
                        completion_callback({"error": str(e), "file_path": interface})
                    except Exception as callback_err:
                        self.logger.error(f"Error in error callback: {str(callback_err)}")
        
        # Create and start the thread
        thread = threading.Thread(target=capture_task, name="LiveCaptureThread")
        thread.daemon = True
        thread.start()
        
        self.logger.info(f"Started live capture thread on interface: {interface}")
        return thread