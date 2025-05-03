"""
Dialog for setting up and starting live network capture using Scapy.
Provides network interface selection and filters for capturing traffic.
"""

import sys
import re
import threading
import traceback
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, 
    QLineEdit, QCheckBox, QPushButton, QFormLayout, QSpinBox,
    QGroupBox, QProgressBar, QMessageBox, QTextEdit, QTabWidget,
    QWidget, QRadioButton, QButtonGroup, QGridLayout
)

class CaptureWorkerSignals(QObject):
    """Custom signals for the capture worker thread"""
    capture_started = pyqtSignal()
    capture_stopped = pyqtSignal()
    packet_received = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)
    capture_complete = pyqtSignal(dict)
    error = pyqtSignal(str)

class LiveCaptureDialog(QDialog):
    """Dialog for live packet capture using Scapy"""
    
    def __init__(self, parent=None, pcap_processor=None):
        """Initialize the live capture dialog
        
        Args:
            parent: Parent widget
            pcap_processor: PcapProcessor instance to use for capturing
        """
        super().__init__(parent)
        self.pcap_processor = pcap_processor
        self.capture_thread = None
        self.capture_running = False
        self.signals = CaptureWorkerSignals()
        self.packet_count = 0
        self.packets_processed = 0
        self.start_time = None
        
        self.setWindowTitle("Live Network Capture")
        self.resize(600, 500)
        
        self._init_ui()
        self._connect_signals()
        self._populate_interfaces()
    
    def _init_ui(self):
        """Initialize the user interface"""
        main_layout = QVBoxLayout(self)
        
        # Create tab widget for organized layout
        tab_widget = QTabWidget()
        
        # Add a note about admin privileges
        admin_note = QLabel(
            "<b>Note:</b> Live packet capture requires administrator privileges. "
            "If capture fails, try running the application with 'sudo python main.py'."
        )
        admin_note.setStyleSheet("color: red; padding: 5px; background-color: lightyellow; border: 1px solid orange;")
        admin_note.setWordWrap(True)
        main_layout.addWidget(admin_note)
        
        # Setup tab
        setup_widget = QWidget()
        setup_layout = QVBoxLayout(setup_widget)
        
        # Interface selection group
        interface_group = QGroupBox("Network Interface")
        interface_layout = QVBoxLayout(interface_group)
        
        interface_form = QFormLayout()
        self.interface_combo = QComboBox()
        interface_form.addRow("Select Interface:", self.interface_combo)
        
        self.refresh_interfaces_button = QPushButton("Refresh Interfaces")
        interface_layout.addLayout(interface_form)
        interface_layout.addWidget(self.refresh_interfaces_button)
        
        setup_layout.addWidget(interface_group)
        
        # Capture options group
        capture_options_group = QGroupBox("Capture Options")
        options_layout = QFormLayout(capture_options_group)
        
        # BPF filter
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("e.g., 'tcp port 80' or 'host 192.168.1.1'")
        options_layout.addRow("BPF Filter:", self.filter_edit)
        
        # Common filters
        filter_examples_layout = QHBoxLayout()
        filter_examples_layout.addWidget(QLabel("Common Filters:"))
        
        self.http_filter_btn = QPushButton("HTTP")
        self.https_filter_btn = QPushButton("HTTPS")
        self.dns_filter_btn = QPushButton("DNS")
        
        filter_examples_layout.addWidget(self.http_filter_btn)
        filter_examples_layout.addWidget(self.https_filter_btn)
        filter_examples_layout.addWidget(self.dns_filter_btn)
        filter_examples_layout.addStretch()
        
        options_layout.addRow("", filter_examples_layout)
        
        # Packet limit
        self.limit_packets_check = QCheckBox("Limit number of packets")
        options_layout.addRow("", self.limit_packets_check)
        
        self.packet_limit_spin = QSpinBox()
        self.packet_limit_spin.setRange(1, 1000000)
        self.packet_limit_spin.setValue(1000)
        self.packet_limit_spin.setEnabled(False)
        options_layout.addRow("Packet Limit:", self.packet_limit_spin)
        
        # Time limit
        self.limit_time_check = QCheckBox("Limit capture time")
        options_layout.addRow("", self.limit_time_check)
        
        self.time_limit_spin = QSpinBox()
        self.time_limit_spin.setRange(1, 3600)
        self.time_limit_spin.setValue(60)
        self.time_limit_spin.setSuffix(" seconds")
        self.time_limit_spin.setEnabled(False)
        options_layout.addRow("Time Limit:", self.time_limit_spin)
        
        setup_layout.addWidget(capture_options_group)
        
        # Add setup tab
        tab_widget.addTab(setup_widget, "Capture Setup")
        
        # Statistics tab
        stats_widget = QWidget()
        stats_layout = QVBoxLayout(stats_widget)
        
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        stats_layout.addWidget(self.stats_text)
        
        tab_widget.addTab(stats_widget, "Statistics")
        
        main_layout.addWidget(tab_widget)
        
        # Progress bar showing packet count
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%v / %m packets captured")
        main_layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Capture")
        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.setEnabled(False)
        self.close_button = QPushButton("Close")
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addStretch()
        button_layout.addWidget(self.close_button)
        
        main_layout.addLayout(button_layout)
    
    def _connect_signals(self):
        """Connect signals and slots"""
        # UI controls
        self.refresh_interfaces_button.clicked.connect(self._populate_interfaces)
        self.limit_packets_check.toggled.connect(self.packet_limit_spin.setEnabled)
        self.limit_time_check.toggled.connect(self.time_limit_spin.setEnabled)
        
        # Filter buttons
        self.http_filter_btn.clicked.connect(lambda: self.filter_edit.setText("tcp port 80"))
        self.https_filter_btn.clicked.connect(lambda: self.filter_edit.setText("tcp port 443"))
        self.dns_filter_btn.clicked.connect(lambda: self.filter_edit.setText("udp port 53"))
        
        # Control buttons
        self.start_button.clicked.connect(self._start_capture)
        self.stop_button.clicked.connect(self._stop_capture)
        self.close_button.clicked.connect(self.close)
        
        # Worker signals
        self.signals.capture_started.connect(self._on_capture_started)
        self.signals.capture_stopped.connect(self._on_capture_stopped)
        self.signals.packet_received.connect(self._on_packet_received)
        self.signals.progress_update.connect(self._on_progress_update)
        self.signals.capture_complete.connect(self._on_capture_complete)
        self.signals.error.connect(self._on_capture_error)
    
    def _populate_interfaces(self):
        """Populate the network interfaces dropdown"""
        self.interface_combo.clear()
        
        try:
            # Get available interfaces using Scapy
            from scapy.all import get_if_list, conf
            
            interfaces = get_if_list()
            
            # Add interfaces to combo box
            if interfaces:
                for iface in interfaces:
                    self.interface_combo.addItem(iface)
                
                # Set default interface
                if conf.iface in interfaces:
                    index = interfaces.index(conf.iface)
                    self.interface_combo.setCurrentIndex(index)
            else:
                self.status_label.setText("No network interfaces found")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to get network interfaces: {str(e)}")
            self.status_label.setText("Error: Failed to get network interfaces")
    
    def _start_capture(self):
        """Start packet capture"""
        if not self.pcap_processor:
            QMessageBox.warning(self, "Error", "PcapProcessor not available")
            return
        
        # Get capture parameters
        interface = self.interface_combo.currentText()
        if not interface:
            QMessageBox.warning(self, "Error", "Please select a network interface")
            return
        
        filter_str = self.filter_edit.text().strip()
        
        # Get limits
        packet_count = None
        if self.limit_packets_check.isChecked():
            packet_count = self.packet_limit_spin.value()
            # Update progress bar max
            self.progress_bar.setMaximum(packet_count)
        else:
            # Set indefinite progress
            self.progress_bar.setMaximum(0)
        
        timeout = None
        if self.limit_time_check.isChecked():
            timeout = self.time_limit_spin.value()
        
        # Reset counters
        self.packet_count = 0
        self.packets_processed = 0
        self.start_time = datetime.now()
        self.stats_text.clear()
        
        # Define callbacks that will emit our signals
        def progress_callback(current, total):
            self.signals.progress_update.emit(current, total)
            
        def packet_callback(packet_data):
            self.signals.packet_received.emit(packet_data)
            
        def completion_callback(result):
            self.signals.capture_complete.emit(result)
        
        try:
            # Start capture in background thread
            self.capture_thread = self.pcap_processor.capture_live(
                interface=interface,
                filter_str=filter_str if filter_str else None,
                packet_count=packet_count,
                timeout=timeout,
                progress_callback=progress_callback,
                packet_callback=packet_callback
            )
            
            self.capture_running = True
            self.signals.capture_started.emit()
            
            # Update statistics periodically
            self._update_statistics()
            
        except Exception as e:
            error_msg = str(e)
            self.signals.error.emit(error_msg)
            QMessageBox.critical(self, "Error", f"Failed to start capture: {error_msg}")
            self.status_label.setText(f"Error: {error_msg}")
    
    def _stop_capture(self):
        """Stop packet capture"""
        if self.pcap_processor and self.capture_running:
            self.pcap_processor.stop()
            self.status_label.setText("Stopping capture...")
            self.capture_running = False
            self.signals.capture_stopped.emit()
    
    def _progress_callback(self, current, total):
        """Callback for capture progress updates"""
        self.signals.progress_update.emit(current, total)
    
    def _packet_callback(self, packet_data):
        """Callback for each captured packet"""
        self.signals.packet_received.emit(packet_data)
    
    def _on_capture_started(self):
        """Handle capture started signal"""
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.interface_combo.setEnabled(False)
        self.filter_edit.setEnabled(False)
        self.limit_packets_check.setEnabled(False)
        self.limit_time_check.setEnabled(False)
        self.packet_limit_spin.setEnabled(False)
        self.time_limit_spin.setEnabled(False)
        
        self.status_label.setText("Capturing packets...")
    
    def _on_capture_stopped(self):
        """Handle capture stopped signal"""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.interface_combo.setEnabled(True)
        self.filter_edit.setEnabled(True)
        self.limit_packets_check.setEnabled(True)
        self.limit_time_check.setEnabled(True)
        
        # Re-enable limit controls based on checkboxes
        self.packet_limit_spin.setEnabled(self.limit_packets_check.isChecked())
        self.time_limit_spin.setEnabled(self.limit_time_check.isChecked())
        
        self.status_label.setText(f"Capture stopped. Captured {self.packet_count} packets.")
    
    def _on_packet_received(self, packet_data):
        """Handle packet received signal"""
        self.packet_count += 1
        
        # Update status every 10 packets to avoid UI freezing
        if self.packet_count % 10 == 0:
            self.status_label.setText(f"Capturing packets... ({self.packet_count} captured)")
    
    def _on_progress_update(self, current, total):
        """Handle progress update signal"""
        if total > 0:
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(current)
        else:
            # Just show the current count for unlimited capture
            self.progress_bar.setMaximum(current + 100)
            self.progress_bar.setValue(current)
    
    def _on_capture_complete(self, result):
        """Handle capture complete signal"""
        self.capture_running = False
        self._on_capture_stopped()
        
        # Show summary
        if "error" in result:
            QMessageBox.warning(self, "Capture Error", result["error"])
            self.status_label.setText(f"Error: {result['error']}")
        else:
            total_time = (datetime.now() - self.start_time).total_seconds()
            self.status_label.setText(
                f"Capture complete. {result.get('processed_count', 0)} packets captured in {total_time:.1f} seconds."
            )
    
    def _on_capture_error(self, error_msg):
        """Handle capture error signal"""
        # Check for common errors and provide helpful messages
        if "Operation not permitted" in error_msg:
            error_msg = (
                "Insufficient permissions to capture packets. Network packet capture typically requires root/administrator privileges.\n\n"
                "Try running the application with elevated privileges (e.g., 'sudo python main.py') or use a pre-recorded PCAP file instead."
            )
            
        QMessageBox.critical(self, "Capture Error", error_msg)
        self.status_label.setText(f"Error: {error_msg}")
        self.capture_running = False
        self._on_capture_stopped()
    
    def _update_statistics(self):
        """Update packet statistics"""
        if not self.capture_running:
            return
        
        # Calculate stats
        duration = (datetime.now() - self.start_time).total_seconds()
        pps = self.packet_count / duration if duration > 0 else 0
        
        # Get protocol distribution from session
        protocols = {}
        http_count = 0
        https_count = 0
        dns_count = 0
        
        # Analyze the last 100 packets at most to avoid performance issues
        packet_limit = 100
        packets_to_analyze = min(packet_limit, len(self.pcap_processor.session.packets))
        
        for i in range(-1, -packets_to_analyze-1, -1):
            if i < -len(self.pcap_processor.session.packets):
                break
                
            packet = self.pcap_processor.session.packets[i]
            protocol = packet.get("protocol", "UNKNOWN")
            
            # Count by protocol
            if protocol not in protocols:
                protocols[protocol] = 0
            protocols[protocol] += 1
            
            # Count application protocols
            if "http" in packet:
                http_count += 1
            
            if packet.get("is_https", False):
                https_count += 1
                
            if "dns" in packet:
                dns_count += 1
        
        # Build stats text
        stats = f"Capture Statistics:\n\n"
        stats += f"Duration: {duration:.1f} seconds\n"
        stats += f"Packets captured: {self.packet_count}\n"
        stats += f"Packets per second: {pps:.1f}\n\n"
        
        # Protocol distribution
        stats += "Protocol Distribution:\n"
        for protocol, count in protocols.items():
            stats += f"  {protocol}: {count} ({count/packets_to_analyze*100:.1f}%)\n"
        
        stats += f"\nHTTP packets: {http_count}\n"
        stats += f"HTTPS packets: {https_count}\n"
        stats += f"DNS packets: {dns_count}\n"
        
        # Update stats text
        self.stats_text.setText(stats)
        
        # Schedule next update
        if self.capture_running:
            QTimer.singleShot(1000, self._update_statistics)
    
    def closeEvent(self, event):
        """Handle dialog close event"""
        if self.capture_running:
            # Ask for confirmation before closing
            reply = QMessageBox.question(
                self, "Confirm Exit",
                "A capture is currently running. Are you sure you want to stop and exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self._stop_capture()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()