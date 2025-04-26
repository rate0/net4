import os
import time
import threading
import asyncio
import sys
import subprocess
import platform
import warnings
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime

# Пытаемся импортировать pyshark, но обрабатываем ошибки импорта
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    warnings.warn("pyshark not installed. Fallback to scapy will be used.")

# Добавляем fallback на scapy
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.dns import DNS
    
    # HTTP слой находится в contrib пакете и требует отдельной загрузки
    try:
        # Пытаемся загрузить HTTP слой из contrib
        load_contrib_success = False
        from scapy.contrib import http
        # Проверяем, успешно ли загружен слой HTTP
        if hasattr(http, 'HTTPRequest'):
            load_contrib_success = True
        else:
            # Если класс не найден, пробуем загрузить явно
            from scapy.all import load_contrib
            load_contrib("http")
            from scapy.contrib import http
            load_contrib_success = True
    except ImportError:
        # Если не смогли загрузить HTTP слой, отмечаем это
        load_contrib_success = False
        warnings.warn("Scapy HTTP layer not available. HTTP parsing will be limited.")
    
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    if not PYSHARK_AVAILABLE:
        warnings.warn("Neither pyshark nor scapy are installed. Please install at least one: pip install scapy")

from ...models.session import Session
from ...models.network_entity import NetworkEntity
from ...utils.logger import Logger

class PcapProcessor:
    """
    Processes PCAP files and extracts network entities, connections, and packets.
    Can use either pyshark (which requires Wireshark/tshark) or scapy (pure Python).
    """
    
    def __init__(self, session: Session, tshark_path: Optional[str] = None, force_scapy: bool = False, debug: bool = False):
        """
        Initialize PCAP processor
        
        Args:
            session: Session to store extracted data
            tshark_path: Optional custom path to the tshark executable
            force_scapy: Force using scapy even if pyshark is available
            debug: Enable debug logging
        """
        self.session = session
        self.logger = Logger().get_logger()
        self.stop_processing = False
        self.tshark_path = tshark_path
        self.force_scapy = force_scapy
        self.debug = debug
        
        # Показываем обнаруженные бэкенды
        self.logger.info(f"Available backends: {'pyshark' if PYSHARK_AVAILABLE else ''}{' and ' if PYSHARK_AVAILABLE and SCAPY_AVAILABLE else ''}{'' if PYSHARK_AVAILABLE and not SCAPY_AVAILABLE else 'scapy' if SCAPY_AVAILABLE else 'none'}")
        
        # Если установлена scapy, но нет load_contrib_success, установим значение по умолчанию
        if SCAPY_AVAILABLE and 'load_contrib_success' not in globals():
            global load_contrib_success
            load_contrib_success = False
            
        # Determine which backend to use
        self.use_scapy = force_scapy or not PYSHARK_AVAILABLE
        
        if not self.use_scapy:
            # If using pyshark, try to find tshark
            if self.tshark_path and not os.path.exists(self.tshark_path):
                self.logger.warning(f"Provided TShark path does not exist: {self.tshark_path}")
                self.tshark_path = None
            
            # Try to auto-find TShark if not provided
            if not self.tshark_path:
                self._find_tshark()
                if not self.tshark_path and SCAPY_AVAILABLE:
                    self.logger.info("TShark not found, falling back to scapy")
                    self.use_scapy = True
        
        # Final check if we have any backend available
        if self.use_scapy and not SCAPY_AVAILABLE:
            raise ImportError("Neither pyshark with tshark nor scapy is available. Please install scapy: pip install scapy")
        
        # Log which backend we're using
        self.logger.info(f"Using {'scapy' if self.use_scapy else 'pyshark'} backend for PCAP processing")
    
    def _find_tshark(self) -> Optional[str]:
        """Find TShark executable and set path if found"""
        # Try to find TShark based on platform
        if platform.system() == "Windows":
            # Standard Wireshark installation paths on Windows
            possible_paths = [
                os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Wireshark', 'tshark.exe'),
                os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Wireshark', 'tshark.exe'),
                # Additional common locations
                'C:\\Wireshark\\tshark.exe'
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    self.logger.info(f"Found TShark at: {path}")
                    self.tshark_path = path
                    return path
            
            self.logger.warning("TShark not found in standard locations.")
        
        elif platform.system() in ["Linux", "Darwin"]:  # Linux or macOS
            # Try to find tshark in PATH
            try:
                # Check if tshark is in PATH using 'which'
                command = "which"
                result = subprocess.run([command, "tshark"], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        text=True)
                if result.returncode == 0:
                    path = result.stdout.strip()
                    self.logger.info(f"Found TShark in PATH at: {path}")
                    self.tshark_path = path
                    return path
            except Exception as e:
                self.logger.warning(f"Error finding TShark in PATH: {str(e)}")
                
            # Check common Unix locations
            unix_paths = [
                "/usr/bin/tshark",
                "/usr/local/bin/tshark",
                "/opt/wireshark/bin/tshark"
            ]
            
            for path in unix_paths:
                if os.path.exists(path):
                    self.logger.info(f"Found TShark at: {path}")
                    self.tshark_path = path
                    return path
            
            self.logger.warning("TShark not found in standard locations.")
        
        # Return None if not found
        return None
    
    def process_file(
        self, 
        file_path: str, 
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Process a PCAP file and extract data
        
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
        
        # Process with appropriate backend
        if self.use_scapy:
            return self._process_with_scapy(file_path, file_id, progress_callback)
        else:
            return self._process_with_pyshark(file_path, file_id, progress_callback)
    
    def _process_with_pyshark(
        self, 
        file_path: str, 
        file_id: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Process a PCAP file using pyshark
        
        Args:
            file_path: Path to PCAP file
            file_id: File ID in the session
            progress_callback: Callback function for progress updates
            
        Returns:
            Dict containing summary of processed data
        """
        # Create capture parameters
        capture_params = {}
        if self.tshark_path and os.path.exists(self.tshark_path):
            capture_params['tshark_path'] = self.tshark_path
        
        # Add optimized capture parameters for large files
        capture_params['keep_packets'] = False  # Don't keep packets in memory
        capture_params['include_raw'] = False   # Don't include raw packet data
        
        # Check file size to determine strategy
        file_size = os.path.getsize(file_path)
        is_large_file = file_size > 100 * 1024 * 1024  # 100 MB threshold
        is_very_large_file = file_size > 1024 * 1024 * 1024  # 1 GB threshold
        
        # For very large files, use packet sampling
        packet_sampling = 1  # Default: process every packet
        if is_very_large_file:
            packet_sampling = 10  # Process every 10th packet
            self.logger.info(f"Very large file detected ({file_size / (1024 * 1024 * 1024):.2f} GB), using packet sampling")
        
        try:
            # Create the capture with custom params if provided
            self.logger.info(f"Creating file capture with params: {capture_params}")
            cap = pyshark.FileCapture(file_path, **capture_params)
            
            # For large files, avoid counting packets upfront
            if is_large_file:
                self.logger.info(f"Large file detected ({file_size / (1024 * 1024):.2f} MB), estimating packet count")
                # Estimate packet count based on file size (rough approximation)
                cap_len = int(file_size / 1500)  # Assuming average packet size of 1500 bytes
                self.logger.info(f"Estimated packet count: ~{cap_len}")
            else:
                # Get packet count for progress reporting
                self.logger.info("Counting packets in file...")
                try:
                    cap_len = sum(1 for _ in cap)
                    self.logger.info(f"Found {cap_len} packets")
                except Exception as e:
                    self.logger.warning(f"Error counting packets: {str(e)}. Progress reporting may be inaccurate.")
                    cap_len = int(file_size / 1500)  # Estimate based on file size
                finally:
                    cap.close()
                
                # Reset capture for processing
                cap = pyshark.FileCapture(file_path, **capture_params)
            
            # Process packets
            packet_count = 0
            processed_count = 0
            
            start_time = time.time()
            
            # Entities and connections for tracking unique ones
            ip_entities = {}
            domain_entities = {}
            connections = set()
            
            # Periodic state saving for large files
            last_state_save_time = time.time()
            state_save_interval = 60  # Save state every 60 seconds for large files
            
            # Process packets in batches for better performance
            batch_size = 1000
            current_batch = []
            
            for packet in cap:
                if self.stop_processing:
                    break
                
                packet_count += 1
                
                # Skip packets based on sampling rate for very large files
                if is_very_large_file and packet_count % packet_sampling != 0:
                    continue
                
                # Extract packet data
                packet_data = self._extract_packet_data_pyshark(packet)
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
                if packet_count % progress_interval == 0 and progress_callback:
                    try:
                        # For sampled processing, adjust the progress reporting
                        if is_very_large_file:
                            # Show progress based on estimated completion percentage
                            progress_callback(packet_count // packet_sampling, cap_len // packet_sampling)
                        else:
                            progress_callback(packet_count, cap_len)
                    except Exception as e:
                        self.logger.warning(f"Error in progress callback: {str(e)}")
                
                # For large files, periodically save state to prevent memory issues
                if is_large_file and time.time() - last_state_save_time > state_save_interval:
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
            
            # Close capture
            cap.close()
            
            # Final progress update
            if progress_callback:
                try:
                    if is_very_large_file:
                        progress_callback(packet_count // packet_sampling, cap_len // packet_sampling)
                    else:
                        progress_callback(packet_count, cap_len)
                except Exception as e:
                    self.logger.warning(f"Error in final progress callback: {str(e)}")
            
            # Update file metadata
            file_metadata = {
                "packet_count": packet_count,
                "processed_count": processed_count,
                "processing_time": time.time() - start_time,
                "entity_count": len(ip_entities) + len(domain_entities),
                "connection_count": len(connections),
                "backend": "pyshark",
                "file_size_mb": file_size / (1024 * 1024),
                "sampling_rate": packet_sampling
            }
            
            self.session.files[file_id]["metadata"] = file_metadata
            
            self.logger.info(f"PCAP processing complete: {processed_count}/{packet_count} packets processed with pyshark")
            
            return {
                "file_id": file_id,
                "packet_count": packet_count,
                "processed_count": processed_count,
                "ip_entities": len(ip_entities),
                "domain_entities": len(domain_entities),
                "connections": len(connections),
                "backend": "pyshark",
                "file_size_mb": file_size / (1024 * 1024),
                "sampling_rate": packet_sampling
            }
            
        except Exception as e:
            error_msg = str(e)
            if "TShark not found" in error_msg and SCAPY_AVAILABLE:
                self.logger.warning(f"TShark not found error: {error_msg}. Falling back to scapy.")
                # Fall back to scapy if TShark is not found
                self.use_scapy = True
                return self._process_with_scapy(file_path, file_id, progress_callback)
            else:
                self.logger.error(f"Error processing PCAP file with pyshark: {error_msg}")
                raise
    
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
    
    def _extract_packet_data_pyshark(self, packet) -> Optional[Dict[str, Any]]:
        """
        Extract relevant data from a pyshark packet
        
        Args:
            packet: pyshark packet object
            
        Returns:
            Dictionary with packet data or None if packet should be skipped
        """
        try:
            # Basic packet data
            packet_data = {
                "frame_number": int(packet.frame_info.number),
                "timestamp": datetime.fromtimestamp(float(packet.frame_info.time_epoch)),
                "length": int(packet.length),
                "protocol": packet.transport_layer if hasattr(packet, 'transport_layer') else None
            }
            
            # Extract IP layer data if present
            if hasattr(packet, 'ip'):
                packet_data.update({
                    "src_ip": packet.ip.src,
                    "dst_ip": packet.ip.dst,
                    "ip_version": int(packet.ip.version),
                    "ttl": int(packet.ip.ttl) if hasattr(packet.ip, 'ttl') else None
                })
            
            # Extract transport layer data if present
            if hasattr(packet, 'tcp'):
                # Helper function to safely convert TCP flag values that might be strings
                def safe_flag_convert(flag_value):
                    if not flag_value:
                        return 0
                    if isinstance(flag_value, bool) or flag_value in ('True', 'true', '1'):
                        return 1
                    if flag_value in ('False', 'false', '0'):
                        return 0
                    try:
                        return int(flag_value)
                    except (ValueError, TypeError):
                        return 0
                
                packet_data.update({
                    "src_port": int(packet.tcp.srcport),
                    "dst_port": int(packet.tcp.dstport),
                    "tcp_flags": {
                        "syn": safe_flag_convert(packet.tcp.flags_syn) if hasattr(packet.tcp, 'flags_syn') else 0,
                        "ack": safe_flag_convert(packet.tcp.flags_ack) if hasattr(packet.tcp, 'flags_ack') else 0,
                        "fin": safe_flag_convert(packet.tcp.flags_fin) if hasattr(packet.tcp, 'flags_fin') else 0,
                        "rst": safe_flag_convert(packet.tcp.flags_reset) if hasattr(packet.tcp, 'flags_reset') else 0
                    },
                    "tcp_seq": int(packet.tcp.seq) if hasattr(packet.tcp, 'seq') else None,
                    "tcp_ack": int(packet.tcp.ack) if hasattr(packet.tcp, 'ack') else None,
                    "window_size": int(packet.tcp.window_size) if hasattr(packet.tcp, 'window_size') else None
                })
            elif hasattr(packet, 'udp'):
                packet_data.update({
                    "src_port": int(packet.udp.srcport),
                    "dst_port": int(packet.udp.dstport),
                    "udp_length": int(packet.udp.length) if hasattr(packet.udp, 'length') else None
                })
            
            # Extract DNS data if present
            if hasattr(packet, 'dns'):
                dns_data = {"query_type": "unknown", "domains": []}
                
                # Check if it's a query or response
                if hasattr(packet.dns, 'flags_response'):
                    dns_data["query_type"] = "response" if int(packet.dns.flags_response) == 1 else "query"
                
                # Extract domain names
                if hasattr(packet.dns, 'qry_name'):
                    dns_data["domains"].append(packet.dns.qry_name)
                
                # If it's a response with answers
                if dns_data["query_type"] == "response" and hasattr(packet.dns, 'resp_name'):
                    if isinstance(packet.dns.resp_name, list):
                        dns_data["domains"].extend(packet.dns.resp_name)
                    else:
                        dns_data["domains"].append(packet.dns.resp_name)
                
                packet_data["dns"] = dns_data
            
            # Extract HTTP data if present
            if hasattr(packet, 'http'):
                http_data = {}
                
                if hasattr(packet.http, 'request_method'):
                    http_data["method"] = packet.http.request_method
                
                if hasattr(packet.http, 'request_uri'):
                    http_data["uri"] = packet.http.request_uri
                
                if hasattr(packet.http, 'host'):
                    http_data["host"] = packet.http.host
                
                if hasattr(packet.http, 'response_code'):
                    http_data["response_code"] = int(packet.http.response_code)
                
                if hasattr(packet.http, 'user_agent'):
                    http_data["user_agent"] = packet.http.user_agent
                
                packet_data["http"] = http_data
            
            return packet_data
        
        except Exception as e:
            self.logger.warning(f"Error extracting packet data with pyshark: {str(e)}")
            return None
    
    def _extract_packet_data_scapy(self, packet, frame_number) -> Optional[Dict[str, Any]]:
        """
        Extract relevant data from a scapy packet
        
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
                
                    # Добавляем DNS данные только если нашли домены
                    if dns_data["domains"]:
                        packet_data["dns"] = dns_data
                except Exception as e:
                    if self.debug:
                        self.logger.debug(f"Error processing DNS packet: {str(e)}")
            
            # Извлечение HTTP данных - более надежная реализация
            http_data = {}
            http_layer_detected = False
            
            # Проверка, доступен ли HTTP слой в scapy
            if 'load_contrib_success' in globals() and load_contrib_success:
                # Если HTTP слой доступен, используем его API
                if packet.haslayer(http.HTTPRequest):
                    http_req = packet[http.HTTPRequest]
                    http_layer_detected = True
                    
                    # Извлекаем метод
                    if hasattr(http_req, 'Method'):
                        http_data["method"] = http_req.Method.decode('utf-8', errors='ignore')
                    
                    # Извлекаем URI
                    if hasattr(http_req, 'Path'):
                        http_data["uri"] = http_req.Path.decode('utf-8', errors='ignore')
                    
                    # Извлекаем хост
                    if hasattr(http_req, 'Host'):
                        http_data["host"] = http_req.Host.decode('utf-8', errors='ignore')
                    
                    # Извлекаем User-Agent
                    if hasattr(http_req, 'User_Agent'):
                        http_data["user_agent"] = http_req.User_Agent.decode('utf-8', errors='ignore')
                
                elif packet.haslayer(http.HTTPResponse):
                    http_resp = packet[http.HTTPResponse]
                    http_layer_detected = True
                    
                    # Извлекаем код ответа
                    if hasattr(http_resp, 'Status_Code'):
                        try:
                            http_data["response_code"] = int(http_resp.Status_Code.decode('utf-8', errors='ignore'))
                        except ValueError:
                            pass
            
            # Альтернативный метод обнаружения HTTP (порт 80 или 8080)
            if not http_layer_detected:
                if TCP in packet:
                    if packet[TCP].dport == 80 or packet[TCP].dport == 8080 or packet[TCP].sport == 80 or packet[TCP].sport == 8080:
                        # Предполагаем, что это HTTP на основе порта
                        if packet.haslayer(scapy.Raw):
                            try:
                                raw_data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                                
                                # Проверяем, похоже ли это на HTTP запрос
                                if raw_data.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')):
                                    # Это HTTP запрос
                                    first_line = raw_data.split('\r\n')[0]
                                    method = first_line.split(' ')[0]
                                    path = first_line.split(' ')[1]
                                    
                                    http_data["method"] = method
                                    http_data["uri"] = path
                                    
                                    # Ищем хост в заголовках
                                    headers = raw_data.split('\r\n')
                                    for header in headers:
                                        if header.lower().startswith('host:'):
                                            http_data["host"] = header.split(':', 1)[1].strip()
                                        elif header.lower().startswith('user-agent:'):
                                            http_data["user_agent"] = header.split(':', 1)[1].strip()
                                
                                # Проверяем, похоже ли это на HTTP ответ
                                elif raw_data.startswith('HTTP/'):
                                    # Это HTTP ответ
                                    first_line = raw_data.split('\r\n')[0]
                                    try:
                                        status_code = int(first_line.split(' ')[1])
                                        http_data["response_code"] = status_code
                                    except (IndexError, ValueError):
                                        pass
                            except Exception as e:
                                # Игнорируем ошибки при разборе HTTP
                                pass
            
            # Добавляем данные HTTP только если что-то нашли
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
        Process a PCAP file asynchronously
        
        Args:
            file_path: Path to PCAP file
            progress_callback: Callback function for progress updates
            completion_callback: Callback function when processing completes
            
        Returns:
            Thread object for the processing task
        """
        def task():
            # Create and set an event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                result = self.process_file(file_path, progress_callback)
                if completion_callback:
                    try:
                        completion_callback(result)
                    except Exception as e:
                        self.logger.error(f"Error in completion callback: {str(e)}")
            except Exception as e:
                self.logger.error(f"Async PCAP processing error: {str(e)}")
                if completion_callback:
                    try:
                        completion_callback({"error": str(e)})
                    except Exception as callback_err:
                        self.logger.error(f"Error in error callback: {str(callback_err)}")
        
        thread = threading.Thread(target=task, name="PcapProcessorThread")
        thread.daemon = True
        thread.start()
        return thread
    
    def stop(self) -> None:
        """Stop ongoing processing"""
        self.stop_processing = True