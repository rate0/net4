"""
HTTP Analysis Dashboard
Provides visualization and analysis of HTTP/HTTPS traffic.
"""

import os
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QSplitter, QTableWidget, QTableWidgetItem, QHeaderView,
    QComboBox, QGroupBox, QScrollArea, QTabWidget, QToolBar,
    QFrame, QTreeWidget, QTreeWidgetItem, QCheckBox, QGridLayout
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, pyqtSlot, QUrl
from PyQt6.QtGui import QIcon, QFont, QColor, QPixmap, QPainter, QBrush

from ..widgets.data_table import DataTable
from ..widgets.threat_badge import ThreatBadge
from ..widgets.charts import TimeSeriesChart, PieChart, ChartWidget

from ...models.session import Session

class HttpDetailsWidget(QWidget):
    """Widget for displaying HTTP request/response details"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self._init_ui()
        self.http_data = None
    
    def _init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout(self)
        
        # Request details section
        self.req_group = QGroupBox("HTTP Request")
        req_layout = QGridLayout(self.req_group)
        
        # Create labels for request details
        req_fields = [
            ("Method:", QLabel()), 
            ("URL:", QLabel()),
            ("Host:", QLabel()),
            ("User-Agent:", QLabel())
        ]
        
        self.req_labels = {}
        
        for i, (label_text, value_label) in enumerate(req_fields):
            label = QLabel(label_text)
            label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            font = QFont()
            font.setBold(True)
            label.setFont(font)
            
            # Make the value label selectable
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            
            req_layout.addWidget(label, i, 0)
            req_layout.addWidget(value_label, i, 1)
            
            # Store label reference
            key = label_text.replace(":", "").lower()
            self.req_labels[key] = value_label
        
        # Add request headers tree
        req_headers_label = QLabel("Headers:")
        req_headers_label.setFont(font)
        req_layout.addWidget(req_headers_label, len(req_fields), 0)
        
        self.req_headers_tree = QTreeWidget()
        self.req_headers_tree.setHeaderLabels(["Name", "Value"])
        self.req_headers_tree.setAlternatingRowColors(True)
        self.req_headers_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.req_headers_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        req_layout.addWidget(self.req_headers_tree, len(req_fields), 1)
        
        # Add request body if available
        req_body_label = QLabel("Body:")
        req_body_label.setFont(font)
        req_layout.addWidget(req_body_label, len(req_fields) + 1, 0)
        
        self.req_body_label = QLabel()
        self.req_body_label.setWordWrap(True)
        self.req_body_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        req_layout.addWidget(self.req_body_label, len(req_fields) + 1, 1)
        
        layout.addWidget(self.req_group)
        
        # Response details section
        self.resp_group = QGroupBox("HTTP Response")
        resp_layout = QGridLayout(self.resp_group)
        
        # Create labels for response details
        resp_fields = [
            ("Status:", QLabel()),
            ("Content-Type:", QLabel()),
            ("Content-Length:", QLabel()),
            ("Server:", QLabel())
        ]
        
        self.resp_labels = {}
        
        for i, (label_text, value_label) in enumerate(resp_fields):
            label = QLabel(label_text)
            label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            font = QFont()
            font.setBold(True)
            label.setFont(font)
            
            # Make the value label selectable
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            
            resp_layout.addWidget(label, i, 0)
            resp_layout.addWidget(value_label, i, 1)
            
            # Store label reference
            key = label_text.replace(":", "").lower()
            self.resp_labels[key] = value_label
        
        # Add response headers tree
        resp_headers_label = QLabel("Headers:")
        resp_headers_label.setFont(font)
        resp_layout.addWidget(resp_headers_label, len(resp_fields), 0)
        
        self.resp_headers_tree = QTreeWidget()
        self.resp_headers_tree.setHeaderLabels(["Name", "Value"])
        self.resp_headers_tree.setAlternatingRowColors(True)
        self.resp_headers_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.resp_headers_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        resp_layout.addWidget(self.resp_headers_tree, len(resp_fields), 1)
        
        # Add response body if available
        resp_body_label = QLabel("Body:")
        resp_body_label.setFont(font)
        resp_layout.addWidget(resp_body_label, len(resp_fields) + 1, 0)
        
        self.resp_body_label = QLabel()
        self.resp_body_label.setWordWrap(True)
        self.resp_body_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        resp_layout.addWidget(self.resp_body_label, len(resp_fields) + 1, 1)
        
        layout.addWidget(self.resp_group)
        
        # Add a spacer at the bottom
        layout.addStretch()
    
    def update_http_data(self, http_data: Dict[str, Any], raw_packet: Dict[str, Any]=None):
        """Update with HTTP data"""
        self.http_data = http_data
        self.raw_packet = raw_packet
        
        # Clear previous data
        for label in self.req_labels.values():
            label.setText("")
        
        for label in self.resp_labels.values():
            label.setText("")
        
        self.req_headers_tree.clear()
        self.resp_headers_tree.clear()
        self.req_body_label.setText("")
        self.resp_body_label.setText("")
        
        # Display request data if available
        if "method" in http_data:
            # This is a request
            self.req_group.setVisible(True)
            
            # Basic request info
            self.req_labels["method"].setText(http_data.get("method", ""))
            
            uri = http_data.get("uri", "")
            self.req_labels["url"].setText(uri)
            
            host = http_data.get("host", "")
            self.req_labels["host"].setText(host)
            
            user_agent = http_data.get("user_agent", "")
            self.req_labels["user-agent"].setText(user_agent)
            
            # Add request headers if available
            if "headers" in http_data:
                for name, value in http_data["headers"].items():
                    item = QTreeWidgetItem([name, value])
                    self.req_headers_tree.addTopLevelItem(item)
            
            # Add request body if available
            if "body" in http_data:
                self.req_body_label.setText(http_data["body"])
            
        else:
            # No request data
            self.req_group.setVisible(False)
        
        # Display response data if available
        if "response_code" in http_data:
            # This is a response
            self.resp_group.setVisible(True)
            
            # Basic response info
            status_code = http_data.get("response_code", "")
            status_msg = http_data.get("status_message", "")
            if status_code and status_msg:
                self.resp_labels["status"].setText(f"{status_code} {status_msg}")
            elif status_code:
                self.resp_labels["status"].setText(f"{status_code}")
            
            content_type = http_data.get("content_type", "")
            self.resp_labels["content-type"].setText(content_type)
            
            content_length = http_data.get("content_length", "")
            if content_length:
                self.resp_labels["content-length"].setText(str(content_length))
            
            server = http_data.get("server", "")
            self.resp_labels["server"].setText(server)
            
            # Add response headers if available
            if "headers" in http_data:
                for name, value in http_data["headers"].items():
                    item = QTreeWidgetItem([name, value])
                    self.resp_headers_tree.addTopLevelItem(item)
            
            # Add response body if available
            if "body" in http_data:
                self.resp_body_label.setText(http_data["body"])
            
        else:
            # No response data
            self.resp_group.setVisible(False)
        
        # Additional raw packet info
        if raw_packet:
            if "timestamp" in raw_packet:
                # Format timestamp
                timestamp = raw_packet["timestamp"]
                if isinstance(timestamp, datetime):
                    timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    timestamp_str = str(timestamp)


class HttpAnalysisDashboard(QWidget):
    """
    Dashboard for analyzing HTTP and HTTPS traffic captured in the session.
    """
    
    def __init__(self, session: Session, parent=None):
        """Initialize the HTTP analysis dashboard"""
        super().__init__(parent)
        self.session = session
        self.http_packets = []
        self.https_packets = []
        self.selected_packet = None
        
        self._init_ui()
        self.check_http_support()
        self.update_dashboard()
        
    def check_http_support(self):
        """Check if HTTP layer is available in Scapy"""
        try:
            from scapy.contrib import http
            return True
        except ImportError:
            # Show error message
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(
                self, "HTTP Support Missing",
                "Scapy HTTP layer is not available. Some features may be limited.\n\n"
                "Use Tools > Check HTTP/HTTPS Support to verify and install if needed."
            )
            return False
    
    def _init_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout(self)
        
        # Add dashboard metrics section at the top
        from ..widgets.metric_card import MetricCardGrid
        from ..widgets.dashboard_card import DashboardCard
        
        # Add metrics grid
        self.metrics_grid = MetricCardGrid(columns=4)
        # Reasonable minimum height for metrics
        self.metrics_grid.setMinimumHeight(100)
        
        # Add HTTP metrics
        self.http_requests_card = self.metrics_grid.add_metric(
            "HTTP Requests", 
            0, 
            icon="assets/icons/http.png",
            color="#2563eb"
        )
        
        self.https_requests_card = self.metrics_grid.add_metric(
            "HTTPS Requests", 
            0, 
            icon="assets/icons/https.png",
            color="#7c3aed"
        )
        
        self.unique_hosts_card = self.metrics_grid.add_metric(
            "Unique Hosts", 
            0, 
            icon="assets/icons/domain.png",
            color="#0891b2"
        )
        
        self.avg_response_card = self.metrics_grid.add_metric(
            "Avg. Response Size", 
            "0 KB", 
            icon="assets/icons/file.png",
            color="#15803d"
        )
        
        # Add metrics to layout
        layout.addWidget(self.metrics_grid)
        
        # Add charts dashboard card
        self.charts_card = DashboardCard("HTTP Traffic Analysis")
        charts_layout = QHBoxLayout()
        
        # Create time series chart for traffic over time
        self.traffic_chart = TimeSeriesChart("HTTP Traffic Over Time", height=350)
        # Charts already have expanding size policy from their base class
        charts_layout.addWidget(self.traffic_chart)
        
        # Create pie chart for HTTP methods
        self.methods_chart = PieChart("HTTP Methods", height=350)
        charts_layout.addWidget(self.methods_chart)
        
        # Add charts to card
        self.charts_card.add_layout(charts_layout)
        self.charts_card.connect_refresh(self.update_charts)
        
        # Add charts card to main layout
        layout.addWidget(self.charts_card)
        
        # Toolbar for filters with better styling
        toolbar_frame = QFrame()
        toolbar_frame.setObjectName("filterToolbar")
        toolbar_frame.setStyleSheet("""
            #filterToolbar {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
                margin-top: 10px;
                margin-bottom: 10px;
            }
        """)
        
        toolbar_layout = QHBoxLayout(toolbar_frame)
        toolbar_layout.setContentsMargins(10, 5, 10, 5)
        toolbar_layout.setSpacing(15)
        
        # Protocol filter
        protocol_layout = QHBoxLayout()
        protocol_label = QLabel("Protocol:")
        protocol_label.setStyleSheet("color: #ffffff; font-weight: bold;")
        protocol_layout.addWidget(protocol_label)
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["All", "HTTP", "HTTPS"])
        self.protocol_combo.setStyleSheet("""
            QComboBox {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                border-radius: 4px;
                padding: 4px 8px;
                min-width: 100px;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: right center;
                width: 20px;
                border-left: 1px solid #414558;
            }
            QComboBox QAbstractItemView {
                background-color: #323242;
                color: #ffffff;
                selection-background-color: #2d74da;
                selection-color: #ffffff;
                border: 1px solid #414558;
            }
        """)
        self.protocol_combo.currentTextChanged.connect(self._filter_changed)
        protocol_layout.addWidget(self.protocol_combo)
        
        toolbar_layout.addLayout(protocol_layout)
        
        # Host filter
        host_layout = QHBoxLayout()
        host_label = QLabel("Host:")
        host_label.setStyleSheet("color: #ffffff; font-weight: bold;")
        host_layout.addWidget(host_label)
        
        self.host_combo = QComboBox()
        self.host_combo.setEditable(True)
        self.host_combo.setMinimumWidth(200)
        self.host_combo.setStyleSheet("""
            QComboBox {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                border-radius: 4px;
                padding: 4px 8px;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: right center;
                width: 20px;
                border-left: 1px solid #414558;
            }
            QComboBox QAbstractItemView {
                background-color: #323242;
                color: #ffffff;
                selection-background-color: #2d74da;
                selection-color: #ffffff;
                border: 1px solid #414558;
            }
        """)
        self.host_combo.currentTextChanged.connect(self._filter_changed)
        host_layout.addWidget(self.host_combo)
        
        toolbar_layout.addLayout(host_layout)
        
        # Method filter
        method_layout = QHBoxLayout()
        method_label = QLabel("Method:")
        method_label.setStyleSheet("color: #ffffff; font-weight: bold;")
        method_layout.addWidget(method_label)
        
        self.method_combo = QComboBox()
        self.method_combo.addItem("All")
        self.method_combo.setStyleSheet("""
            QComboBox {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                border-radius: 4px;
                padding: 4px 8px;
                min-width: 100px;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: right center;
                width: 20px;
                border-left: 1px solid #414558;
            }
            QComboBox QAbstractItemView {
                background-color: #323242;
                color: #ffffff;
                selection-background-color: #2d74da;
                selection-color: #ffffff;
                border: 1px solid #414558;
            }
        """)
        self.method_combo.currentTextChanged.connect(self._filter_changed)
        method_layout.addWidget(self.method_combo)
        
        toolbar_layout.addLayout(method_layout)
        
        # Add spacer to push refresh button to the right
        toolbar_layout.addStretch()
        
        # Add refresh button
        refresh_button = QPushButton("Refresh")
        refresh_button.setIcon(QIcon("assets/icons/refresh.png"))
        refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #2d74da;
                color: #ffffff;
                border-radius: 4px;
                padding: 5px 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3a82f7;
            }
            QPushButton:pressed {
                background-color: #2361b8;
            }
        """)
        refresh_button.clicked.connect(self.update_dashboard)
        toolbar_layout.addWidget(refresh_button)
        
        # Add toolbar to layout
        layout.addWidget(toolbar_frame)
        
        # Main content splitter
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # HTTP packets table with improved styling
        self.http_table = DataTable(
            ["Timestamp", "Host", "Method", "URL", "Status", "Content Type", "Size"],
            []
        )
        self.http_table.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.http_table.table.selectionModel().selectionChanged.connect(self._selection_changed)
        
        # Set column widths
        self.http_table.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Timestamp
        self.http_table.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Host
        self.http_table.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Method
        self.http_table.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)         # URL
        self.http_table.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Status
        self.http_table.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Content Type
        self.http_table.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Size
        
        # Add to splitter
        splitter.addWidget(self.http_table)
        
        # HTTP details widget
        self.http_details = HttpDetailsWidget()
        
        # Wrap in a scroll area with improved styling
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.http_details)
        scroll_area.setStyleSheet("""
            QScrollArea {
                background-color: transparent;
                border: none;
            }
            QScrollBar:vertical {
                background-color: #282838;
                width: 14px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #414558;
                min-height: 20px;
                border-radius: 7px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #2d74da;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        # Add to splitter
        splitter.addWidget(scroll_area)
        
        # Set initial sizes (allocate more space to the table than details)
        splitter.setSizes([700, 500])
        
        # Add splitter to layout
        layout.addWidget(splitter)
        
        # Add status bar with improved styling
        status_frame = QFrame()
        status_frame.setObjectName("statusBar")
        status_frame.setStyleSheet("""
            #statusBar {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                margin-top: 10px;
            }
        """)
        
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(15, 8, 15, 8)
        
        # Status icon
        self.status_icon = QLabel()
        status_icon_pixmap = QPixmap("assets/icons/info.png")
        if not status_icon_pixmap.isNull():
            self.status_icon.setPixmap(status_icon_pixmap.scaled(
                16, 16, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
            ))
        status_layout.addWidget(self.status_icon)
        
        # Status text
        self.status_label = QLabel()
        self.status_label.setStyleSheet("color: #ffffff;")
        status_layout.addWidget(self.status_label)
        
        # Add spacer to push to left
        status_layout.addStretch()
        
        layout.addWidget(status_frame)
    
    def update_dashboard(self):
        """Update the dashboard with current session data"""
        self.http_packets = []
        self.https_packets = []
        
        # Extract HTTP and HTTPS packets from session
        if hasattr(self.session, 'packets'):
            for packet in self.session.packets:
                if "http" in packet:
                    # Is this HTTP or HTTPS?
                    is_https = packet.get("is_https", False)
                    
                    if is_https:
                        self.https_packets.append(packet)
                    else:
                        self.http_packets.append(packet)
        
        # Update metric cards
        self._update_metrics()
        
        # Update status label with more detailed information
        total_packets = len(self.http_packets) + len(self.https_packets)
        self.status_label.setText(f"Total: {total_packets} packets (HTTP: {len(self.http_packets)}, HTTPS: {len(self.https_packets)})")
        
        # Update charts
        self.update_charts()
        
        # Update filter dropdowns
        self._update_filter_options()
        
        # Apply current filters
        self._filter_changed()
    
    def update_charts(self):
        """Update all charts with current data"""
        # Update traffic over time chart
        if hasattr(self, 'traffic_chart'):
            # Extract timestamp data
            time_data = []
            
            # Extract timestamps from all packets and count by time
            from collections import Counter
            from datetime import datetime, timedelta
            
            # Use filtered packets based on the current filter settings
            all_packets = self.http_packets + self.https_packets
            
            # Group timestamps by minute for a meaningful chart
            timestamps = []
            for packet in all_packets:
                if "timestamp" in packet:
                    ts = packet["timestamp"] 
                    if isinstance(ts, datetime):
                        # Round to the nearest minute
                        rounded = ts.replace(second=0, microsecond=0)
                        timestamps.append(rounded)
            
            # Count packets by minute
            counter = Counter(timestamps)
            
            # Sort by timestamp
            time_data = [(ts, count) for ts, count in sorted(counter.items())]
            
            # Update chart with data
            self.traffic_chart.update_data(time_data)
        
        # Update methods chart
        if hasattr(self, 'methods_chart'):
            # Extract HTTP methods data
            methods_counter = Counter()
            
            for packet in self.http_packets + self.https_packets:
                if "http" in packet and "method" in packet["http"]:
                    method = packet["http"]["method"]
                    methods_counter[method] += 1
            
            # Convert to list of tuples for pie chart
            methods_data = [(method, count) for method, count in methods_counter.most_common()]
            
            # Update chart with data
            self.methods_chart.update_data(methods_data)
    
    def _update_metrics(self):
        """Update metric cards with current data"""
        # Update HTTP requests count
        self.http_requests_card.update_value(len(self.http_packets))
        
        # Update HTTPS requests count
        self.https_requests_card.update_value(len(self.https_packets))
        
        # Calculate unique hosts
        hosts = set()
        for packet in self.http_packets + self.https_packets:
            if "http" in packet and "host" in packet["http"]:
                hosts.add(packet["http"]["host"])
        self.unique_hosts_card.update_value(len(hosts))
        
        # Calculate average response size
        total_size = 0
        response_count = 0
        
        for packet in self.http_packets + self.https_packets:
            if "http" in packet and "content_length" in packet["http"]:
                try:
                    content_length = int(packet["http"]["content_length"])
                    total_size += content_length
                    response_count += 1
                except (ValueError, TypeError):
                    pass
        
        if response_count > 0:
            avg_size = total_size / response_count
            # Format size nicely
            if avg_size > 1024 * 1024:
                avg_size_str = f"{avg_size / (1024 * 1024):.1f} MB"
            elif avg_size > 1024:
                avg_size_str = f"{avg_size / 1024:.1f} KB"
            else:
                avg_size_str = f"{avg_size:.0f} B"
            
            self.avg_response_card.update_value(avg_size_str)
    
    def _update_filter_options(self):
        """Update filter dropdown options based on available data"""
        # Collect hosts
        hosts = set()
        for packet in self.http_packets + self.https_packets:
            if "http" in packet and "host" in packet["http"]:
                hosts.add(packet["http"]["host"])
        
        # Update host combo
        current_host = self.host_combo.currentText()
        self.host_combo.clear()
        self.host_combo.addItem("All")
        for host in sorted(hosts):
            self.host_combo.addItem(host)
            
        # Try to restore previous selection
        if current_host:
            index = self.host_combo.findText(current_host)
            if index >= 0:
                self.host_combo.setCurrentIndex(index)
        
        # Collect methods
        methods = set()
        for packet in self.http_packets + self.https_packets:
            if "http" in packet and "method" in packet["http"]:
                methods.add(packet["http"]["method"])
        
        # Update method combo
        current_method = self.method_combo.currentText()
        self.method_combo.clear()
        self.method_combo.addItem("All")
        for method in sorted(methods):
            self.method_combo.addItem(method)
            
        # Try to restore previous selection
        if current_method:
            index = self.method_combo.findText(current_method)
            if index >= 0:
                self.method_combo.setCurrentIndex(index)
    
    def _filter_changed(self):
        """Apply filters and update the table"""
        # Get filter values
        protocol = self.protocol_combo.currentText()
        host = self.host_combo.currentText()
        method = self.method_combo.currentText()
        
        # Filter packets
        filtered_packets = []
        
        # Apply protocol filter
        if protocol == "All":
            packets_to_filter = self.http_packets + self.https_packets
        elif protocol == "HTTP":
            packets_to_filter = self.http_packets
        else:  # HTTPS
            packets_to_filter = self.https_packets
        
        # Apply host and method filters
        for packet in packets_to_filter:
            if "http" not in packet:
                continue
                
            http_data = packet["http"]
            
            # Apply host filter
            if host != "All" and http_data.get("host", "") != host:
                continue
                
            # Apply method filter
            if method != "All" and http_data.get("method", "") != method:
                continue
                
            # Packet passed all filters
            filtered_packets.append(packet)
        
        # Update table data
        table_data = []
        
        for packet in filtered_packets:
            # Extract packet data
            timestamp = packet.get("timestamp", datetime.now())
            if isinstance(timestamp, datetime):
                time_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            else:
                time_str = str(timestamp)
            
            http_data = packet.get("http", {})
            
            host = http_data.get("host", "")
            method = http_data.get("method", "")
            uri = http_data.get("uri", "")
            status = http_data.get("response_code", "")
            content_type = http_data.get("content_type", "")
            content_length = http_data.get("content_length", "")
            
            # Format content length
            if content_length:
                try:
                    length = int(content_length)
                    if length > 1024 * 1024:
                        size_str = f"{length / (1024 * 1024):.1f} MB"
                    elif length > 1024:
                        size_str = f"{length / 1024:.1f} KB"
                    else:
                        size_str = f"{length} B"
                except (ValueError, TypeError):
                    size_str = str(content_length)
            else:
                size_str = ""
            
            # Add to table data
            table_data.append([time_str, host, method, uri, status, content_type, size_str])
        
        # Update table
        self.http_table.update_data(table_data)
        
        # Store filtered packets for selection handling
        self.filtered_packets = filtered_packets
        
        # Update status
        self.status_label.setText(f"Showing {len(filtered_packets)} of {len(self.http_packets) + len(self.https_packets)} packets")
    
    def _selection_changed(self):
        """Handle selection change in the table"""
        # Get selected row
        selection = self.http_table.table.selectionModel().selectedRows()
        if not selection:
            # Clear details if nothing selected
            self.selected_packet = None
            self.http_details.update_http_data({})
            return
            
        # Get the selected packet
        row = selection[0].row()
        if row >= len(self.filtered_packets):
            return
            
        self.selected_packet = self.filtered_packets[row]
        
        # Update details view
        if "http" in self.selected_packet:
            self.http_details.update_http_data(
                self.selected_packet["http"], 
                self.selected_packet
            )