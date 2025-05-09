from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QScrollArea, QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QGridLayout, QGroupBox, QLineEdit, QToolBar, QCheckBox,
    QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QColor, QPixmap

from ..widgets.data_table import DataTable
from ..widgets.charts import BarChart, TimeSeriesChart
from ..widgets.threat_badge import ThreatBadge

from ...models.session import Session


class NetworkFlowDashboard(QWidget):
    """
    Dashboard for visualizing and analyzing network flows and connections.
    Provides filtering, sorting, and detailed inspection of network communication.
    """
    
    def __init__(self, session: Session, parent=None):
        """
        Initialize network flow dashboard
        
        Args:
            session: Analysis session
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.session = session
        self.filtered_connections = []
        self.current_filter = {}
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize dashboard UI"""
        # Main layout
        layout = QVBoxLayout(self)
        
        # Toolbar for filters and controls
        toolbar = QToolBar()
        toolbar.setIconSize(QSize(16, 16))
        
        # Filter controls
        filter_label = QLabel("Filter:")
        toolbar.addWidget(filter_label)
        
        self.ip_filter = QLineEdit()
        self.ip_filter.setPlaceholderText("IP address")
        self.ip_filter.setMaximumWidth(150)
        self.ip_filter.textChanged.connect(self._apply_filters)
        toolbar.addWidget(self.ip_filter)
        
        self.port_filter = QLineEdit()
        self.port_filter.setPlaceholderText("Port")
        self.port_filter.setMaximumWidth(80)
        self.port_filter.textChanged.connect(self._apply_filters)
        toolbar.addWidget(self.port_filter)
        
        # Protocol filter
        protocol_label = QLabel("Protocol:")
        toolbar.addWidget(protocol_label)
        
        self.protocol_filter = QComboBox()
        self.protocol_filter.addItem("All")
        self.protocol_filter.setMaximumWidth(100)
        self.protocol_filter.currentTextChanged.connect(self._apply_filters)
        toolbar.addWidget(self.protocol_filter)
        
        toolbar.addSeparator()
        
        # Time range filter
        time_label = QLabel("Time range:")
        toolbar.addWidget(time_label)
        
        self.time_filter = QComboBox()
        self.time_filter.addItems(["All time", "Last hour", "Last 24 hours"])
        self.time_filter.setMaximumWidth(120)
        self.time_filter.currentTextChanged.connect(self._apply_filters)
        toolbar.addWidget(self.time_filter)
        
        toolbar.addSeparator()
        
        # Threat level filter
        threat_label = QLabel("Show only:")
        toolbar.addWidget(threat_label)
        
        self.threat_filter = QComboBox()
        self.threat_filter.addItems(["All", "Malicious", "Suspicious"])
        self.threat_filter.setMaximumWidth(100)
        self.threat_filter.currentTextChanged.connect(self._apply_filters)
        toolbar.addWidget(self.threat_filter)
        
        # Reset filters button
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)
        
        reset_button = QPushButton("Reset Filters")
        reset_button.clicked.connect(self._reset_filters)
        toolbar.addWidget(reset_button)
        
        # Add toolbar to layout
        layout.addWidget(toolbar)
        
        # Main content area
        content_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Connection table
        self.connection_table = DataTable(
            ["Source IP", "Source Port", "Destination IP", "Destination Port", 
             "Protocol", "Packets", "Bytes", "First Seen", "Last Seen"],
            self.get_connections_data()
        )
        self.connection_table.setMinimumHeight(250)
        self.connection_table.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.connection_table.table.selectionModel().selectionChanged.connect(self._connection_selected)
        
        content_splitter.addWidget(self.connection_table)
        
        # Detail panel for selected connection
        self.detail_panel = QScrollArea()
        self.detail_panel.setWidgetResizable(True)
        self.detail_panel.setFrameShape(QFrame.Shape.NoFrame)
        
        self.detail_content = QWidget()
        self.detail_layout = QVBoxLayout(self.detail_content)
        
        # Connection details section
        self.detail_group = QGroupBox("Connection Details")
        self.detail_group.setVisible(False)  # Hide until a connection is selected
        self.detail_grid = QGridLayout(self.detail_group)
        
        # Create detail labels
        detail_labels = [
            ("Source IP:", QLabel("")),
            ("Source Port:", QLabel("")),
            ("Destination IP:", QLabel("")),
            ("Destination Port:", QLabel("")),
            ("Protocol:", QLabel("")),
            ("Packet Count:", QLabel("")),
            ("Byte Count:", QLabel("")),
            ("First Seen:", QLabel("")),
            ("Last Seen:", QLabel("")),
            ("Duration:", QLabel("")),
            ("Source Threat:", QLabel("")),
            ("Destination Threat:", QLabel(""))
        ]
        
        self.detail_label_map = {}
        
        for i, (label_text, value_label) in enumerate(detail_labels):
            row = i // 3
            col = (i % 3) * 2
            
            label = QLabel(label_text)
            label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            font = QFont()
            font.setBold(True)
            label.setFont(font)
            
            self.detail_grid.addWidget(label, row, col)
            self.detail_grid.addWidget(value_label, row, col + 1)
            
            # Store reference to value label
            key = label_text.replace(":", "").lower().replace(" ", "_")
            self.detail_label_map[key] = value_label
        
        self.detail_layout.addWidget(self.detail_group)
        
        # Packet timeline for selected connection
        self.timeline_group = QGroupBox("Packet Timeline")
        self.timeline_group.setVisible(False)  # Hide until a connection is selected
        self.timeline_layout = QVBoxLayout(self.timeline_group)
        
        self.timeline_chart = TimeSeriesChart("Packet Timeline", height=500)
        self.timeline_layout.addWidget(self.timeline_chart)
        
        self.detail_layout.addWidget(self.timeline_group)
        
        # Related connections section
        self.related_group = QGroupBox("Related Connections")
        self.related_group.setVisible(False)  # Hide until a connection is selected
        self.related_layout = QVBoxLayout(self.related_group)
        
        self.related_table = DataTable(
            ["Source IP", "Destination IP", "Protocol", "Packets", "Bytes"],
            []
        )
        self.related_layout.addWidget(self.related_table)
        
        self.detail_layout.addWidget(self.related_group)
        
        # Set detail panel content
        self.detail_panel.setWidget(self.detail_content)
        content_splitter.addWidget(self.detail_panel)
        
        # Set initial splitter sizes
        # More balanced initial split sizes
        content_splitter.setSizes([600, 400])
        
        # Add content splitter to layout
        layout.addWidget(content_splitter)
        
        # Update dashboard with current data
        self.update_dashboard()
    
    def update_dashboard(self):
        """Update dashboard with current session data"""
        # Update protocol filter options
        self._update_protocol_filter()
        
        # Apply current filters to get filtered connections
        self._apply_filters()
        
        # Update connection table
        self.connection_table.update_data(self.get_connections_data())
    
    def filter_by_ip(self, ip_address: str):
        """
        Apply filter for a specific IP address
        
        Args:
            ip_address: IP address to filter for
        """
        self.ip_filter.setText(ip_address)
        self._apply_filters()
    
    def get_connections_data(self) -> List[List[Any]]:
        """
        Get data for connections table
        
        Returns:
            List of connection data rows
        """
        data = []
        
        # Use filtered connections if available, otherwise use all connections
        connections = self.filtered_connections if self.filtered_connections else self.session.connections
        
        for conn in connections:
            src_ip = conn.get("src_ip", "Unknown")
            src_port = str(conn.get("src_port", ""))
            dst_ip = conn.get("dst_ip", "Unknown")
            dst_port = str(conn.get("dst_port", ""))
            protocol = conn.get("protocol", "Unknown")
            packet_count = str(conn.get("packet_count", ""))
            byte_count = self._format_bytes(conn.get("byte_count", 0))
            
            first_seen = conn.get("first_seen")
            first_seen_str = first_seen.strftime("%Y-%m-%d %H:%M:%S") if first_seen else "Unknown"
            
            last_seen = conn.get("last_seen")
            last_seen_str = last_seen.strftime("%Y-%m-%d %H:%M:%S") if last_seen else "Unknown"
            
            data.append([
                src_ip, src_port, dst_ip, dst_port, protocol,
                packet_count, byte_count, first_seen_str, last_seen_str
            ])
        
        # Sort by time (most recent first)
        data.sort(key=lambda x: x[7], reverse=True)
        
        return data
    
    def _update_protocol_filter(self):
        """Update protocol filter options based on available protocols"""
        # Get current selection
        current_text = self.protocol_filter.currentText()
        
        # Get unique protocols
        protocols = set()
        for conn in self.session.connections:
            protocol = conn.get("protocol")
            if protocol:
                protocols.add(protocol)
        
        # Clear and rebuild combo box
        self.protocol_filter.clear()
        self.protocol_filter.addItem("All")
        
        for protocol in sorted(protocols):
            self.protocol_filter.addItem(protocol)
        
        # Restore selection if possible
        index = self.protocol_filter.findText(current_text)
        if index >= 0:
            self.protocol_filter.setCurrentIndex(index)
        else:
            self.protocol_filter.setCurrentIndex(0)  # Default to "All"
    
    def _apply_filters(self):
        """Apply current filters to connections"""
        # Get filter values
        ip_filter = self.ip_filter.text().strip()
        port_filter = self.port_filter.text().strip()
        protocol_filter = self.protocol_filter.currentText()
        time_filter = self.time_filter.currentText()
        threat_filter = self.threat_filter.currentText()
        
        # Calculate time threshold for time filter
        time_threshold = None
        now = datetime.now()
        
        if time_filter == "Last hour":
            time_threshold = now - timedelta(hours=1)
        elif time_filter == "Last 24 hours":
            time_threshold = now - timedelta(hours=24)
        
        # Apply filters
        self.filtered_connections = []
        
        for conn in self.session.connections:
            # IP filter
            if ip_filter:
                src_ip = conn.get("src_ip", "")
                dst_ip = conn.get("dst_ip", "")
                if ip_filter not in src_ip and ip_filter not in dst_ip:
                    continue
            
            # Port filter
            if port_filter:
                src_port = str(conn.get("src_port", ""))
                dst_port = str(conn.get("dst_port", ""))
                if port_filter not in src_port and port_filter not in dst_port:
                    continue
            
            # Protocol filter
            if protocol_filter != "All":
                conn_protocol = conn.get("protocol", "")
                if protocol_filter != conn_protocol:
                    continue
            
            # Time filter
            if time_threshold:
                first_seen = conn.get("first_seen")
                if not first_seen or first_seen < time_threshold:
                    continue
            
            # Threat filter
            if threat_filter != "All":
                src_ip = conn.get("src_ip", "")
                dst_ip = conn.get("dst_ip", "")
                
                # Check if source or destination IP is marked as malicious/suspicious
                src_malicious = self._is_ip_threat_level(src_ip, threat_filter.lower())
                dst_malicious = self._is_ip_threat_level(dst_ip, threat_filter.lower())
                
                if not src_malicious and not dst_malicious:
                    continue
            
            # All filters passed, add to filtered connections
            self.filtered_connections.append(conn)
        
        # Store current filter settings
        self.current_filter = {
            "ip": ip_filter,
            "port": port_filter,
            "protocol": protocol_filter,
            "time": time_filter,
            "threat": threat_filter
        }
        
        # Update connection table with filtered data
        self.connection_table.update_data(self.get_connections_data())
    
    def _reset_filters(self):
        """Reset all filters to default values"""
        self.ip_filter.clear()
        self.port_filter.clear()
        self.protocol_filter.setCurrentIndex(0)  # "All"
        self.time_filter.setCurrentIndex(0)  # "All time"
        self.threat_filter.setCurrentIndex(0)  # "All"
        
        # Clear filtered connections to show all
        self.filtered_connections = []
        self.current_filter = {}
        
        # Update connection table
        self.connection_table.update_data(self.get_connections_data())
    
    def _connection_selected(self):
        """Handle connection selection in table"""
        # Get selected row
        selection = self.connection_table.table.selectionModel().selectedRows()
        if not selection:
            # Hide detail panels if no selection
            self.detail_group.setVisible(False)
            self.timeline_group.setVisible(False)
            self.related_group.setVisible(False)
            return
        
        # Get selected connection data
        row = selection[0].row()
        table_data = self.connection_table.data
        
        if row >= len(table_data):
            return
            
        row_data = table_data[row]
        
        # Find matching connection in session data
        src_ip = row_data[0]
        src_port_str = row_data[1]
        dst_ip = row_data[2]
        dst_port_str = row_data[3]
        protocol = row_data[4]
        
        # Convert port strings to integers
        try:
            src_port = int(src_port_str) if src_port_str else 0
            dst_port = int(dst_port_str) if dst_port_str else 0
        except ValueError:
            src_port = 0
            dst_port = 0
        
        # Find connection in session data
        selected_conn = None
        for conn in self.session.connections:
            if (conn.get("src_ip") == src_ip and 
                conn.get("src_port") == src_port and
                conn.get("dst_ip") == dst_ip and
                conn.get("dst_port") == dst_port and
                conn.get("protocol") == protocol):
                selected_conn = conn
                break
        
        if not selected_conn:
            return
        
        # Update connection details
        self._update_connection_details(selected_conn)
        
        # Update packet timeline
        self._update_packet_timeline(selected_conn)
        
        # Update related connections
        self._update_related_connections(selected_conn)
        
        # Show detail panels
        self.detail_group.setVisible(True)
        self.timeline_group.setVisible(True)
        self.related_group.setVisible(True)
    
    def _update_connection_details(self, conn: Dict[str, Any]):
        """
        Update connection details panel
        
        Args:
            conn: Connection data dictionary
        """
        # Basic connection info
        self.detail_label_map["source_ip"].setText(conn.get("src_ip", "Unknown"))
        self.detail_label_map["source_port"].setText(str(conn.get("src_port", "")))
        self.detail_label_map["destination_ip"].setText(conn.get("dst_ip", "Unknown"))
        self.detail_label_map["destination_port"].setText(str(conn.get("dst_port", "")))
        self.detail_label_map["protocol"].setText(conn.get("protocol", "Unknown"))
        self.detail_label_map["packet_count"].setText(str(conn.get("packet_count", "0")))
        self.detail_label_map["byte_count"].setText(self._format_bytes(conn.get("byte_count", 0)))
        
        # Timestamps
        first_seen = conn.get("first_seen")
        last_seen = conn.get("last_seen")
        
        if first_seen:
            self.detail_label_map["first_seen"].setText(first_seen.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            self.detail_label_map["first_seen"].setText("Unknown")
        
        if last_seen:
            self.detail_label_map["last_seen"].setText(last_seen.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            self.detail_label_map["last_seen"].setText("Unknown")
        
        # Duration
        if first_seen and last_seen:
            duration = (last_seen - first_seen).total_seconds()
            self.detail_label_map["duration"].setText(self._format_duration(duration))
        else:
            self.detail_label_map["duration"].setText("Unknown")
        
        # Threat information
        src_ip = conn.get("src_ip", "")
        dst_ip = conn.get("dst_ip", "")
        
        src_threat = self._get_ip_threat_badge(src_ip)
        dst_threat = self._get_ip_threat_badge(dst_ip)
        
        # Clear old widgets if any
        src_item = self.detail_grid.itemAtPosition(3, 5)
        dst_item = self.detail_grid.itemAtPosition(3, 7)
        
        old_src_widget = src_item.widget() if src_item else None
        old_dst_widget = dst_item.widget() if dst_item else None
        
        if old_src_widget:
            self.detail_grid.removeWidget(old_src_widget)
            old_src_widget.deleteLater()
        
        if old_dst_widget:
            self.detail_grid.removeWidget(old_dst_widget)
            old_dst_widget.deleteLater()
        
        # Add new threat badges
        self.detail_grid.addWidget(src_threat, 3, 5)
        self.detail_grid.addWidget(dst_threat, 3, 7)
    
    def _update_packet_timeline(self, conn: Dict[str, Any]):
        """
        Update packet timeline chart for selected connection
        
        Args:
            conn: Connection data dictionary
        """
        # Find packets matching this connection
        matching_packets = []
        
        src_ip = conn.get("src_ip")
        dst_ip = conn.get("dst_ip")
        src_port = conn.get("src_port")
        dst_port = conn.get("dst_port")
        protocol = conn.get("protocol")
        
        for packet in self.session.packets:
            if (packet.get("src_ip") == src_ip and 
                packet.get("dst_ip") == dst_ip and
                packet.get("src_port") == src_port and
                packet.get("dst_port") == dst_port and
                packet.get("protocol") == protocol):
                matching_packets.append(packet)
        
        # Group packets by time for chart
        packet_times = {}
        for packet in matching_packets:
            timestamp = packet.get("timestamp")
            if timestamp:
                # Round to second
                second = timestamp.replace(microsecond=0)
                packet_times[second] = packet_times.get(second, 0) + 1
        
        # Convert to sorted list of (timestamp, count) tuples
        time_series = [(ts, count) for ts, count in sorted(packet_times.items())]
        
        # Update chart
        if time_series:
            self.timeline_chart.update_data(time_series)
            self.timeline_group.setTitle(f"Packet Timeline ({len(matching_packets)} packets)")
        else:
            self.timeline_chart.clear()
            self.timeline_group.setTitle("Packet Timeline (No packets found)")
    
    def _update_related_connections(self, conn: Dict[str, Any]):
        """
        Update related connections table
        
        Args:
            conn: Connection data dictionary
        """
        # Find connections with same source or destination IP
        related_data = []
        
        src_ip = conn.get("src_ip")
        dst_ip = conn.get("dst_ip")
        
        for related in self.session.connections:
            # Skip the selected connection itself
            if (related.get("src_ip") == src_ip and 
                related.get("dst_ip") == dst_ip and
                related.get("src_port") == conn.get("src_port") and
                related.get("dst_port") == conn.get("dst_port") and
                related.get("protocol") == conn.get("protocol")):
                continue
            
            # Check if related by IP
            related_src = related.get("src_ip")
            related_dst = related.get("dst_ip")
            
            if related_src == src_ip or related_dst == dst_ip or related_src == dst_ip:
                related_protocol = related.get("protocol", "Unknown")
                packet_count = str(related.get("packet_count", "0"))
                byte_count = self._format_bytes(related.get("byte_count", 0))
                
                related_data.append([
                    related_src,
                    related_dst,
                    related_protocol,
                    packet_count,
                    byte_count
                ])
        
        # Sort by packet count
        related_data.sort(key=lambda x: int(x[3]) if x[3].isdigit() else 0, reverse=True)
        
        # Update table
        self.related_table.update_data(related_data[:20])  # Limit to 20 rows
        self.related_group.setTitle(f"Related Connections ({len(related_data)})")
    
    def _get_ip_threat_badge(self, ip: str) -> QWidget:
        """
        Get threat badge for an IP address
        
        Args:
            ip: IP address
            
        Returns:
            QWidget containing threat information
        """
        # Find entity for IP
        entity = None
        for e in self.session.network_entities.values():
            if e.type == "ip" and e.value == ip:
                entity = e
                break
        
        if entity:
            # Create threat badge
            return ThreatBadge(entity.threat_level, entity.confidence)
        else:
            # Unknown entity
            return ThreatBadge("unknown", 0.0)
    
    def _is_ip_threat_level(self, ip: str, level: str) -> bool:
        """
        Check if an IP address has the specified threat level
        
        Args:
            ip: IP address
            level: Threat level to check for
            
        Returns:
            True if IP matches threat level, False otherwise
        """
        # Find entity for IP
        for entity in self.session.network_entities.values():
            if entity.type == "ip" and entity.value == ip:
                if level == "malicious" and entity.threat_level == "malicious":
                    return True
                elif level == "suspicious" and entity.threat_level in ["malicious", "suspicious"]:
                    return True
                return False
        
        return False
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human-readable string"""
        if bytes_value < 1024:
            return f"{bytes_value} B"
        elif bytes_value < 1024 * 1024:
            return f"{bytes_value / 1024:.2f} KB"
        elif bytes_value < 1024 * 1024 * 1024:
            return f"{bytes_value / (1024 * 1024):.2f} MB"
        else:
            return f"{bytes_value / (1024 * 1024 * 1024):.2f} GB"
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in seconds to human-readable string"""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} minutes"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.1f} hours"
        else:
            days = seconds / 86400
            return f"{days:.1f} days"