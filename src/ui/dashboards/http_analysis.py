"""
HTTP Analysis Dashboard
Provides visualization and analysis of HTTP/HTTPS traffic.
"""

import os
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QSplitter, QTableView, QHeaderView,
    QComboBox, QGroupBox, QScrollArea, QTabWidget, QToolBar,
    QFrame, QTreeWidget, QTreeWidgetItem, QCheckBox, QGridLayout, QLineEdit, QSizePolicy, QAbstractItemView
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, pyqtSlot, QUrl, QSortFilterProxyModel
from PyQt6.QtGui import QIcon, QFont, QColor, QPixmap, QPainter, QBrush

from ..widgets.threat_badge import ThreatBadge
from ..widgets.charts import TimeSeriesChart, PieChart
from ..widgets.metric_card import MetricCardGrid
from ..widgets.dashboard_card import DashboardCard

from ...models.session import Session
from ..models.http_table_model import HttpTableModel

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
        
        # Placeholder for metric card references (filled in _init_ui)
        self._metric_cards: dict = {}
        
        self._init_ui()
        # Silently verify HTTP layer; UI menu will provide explicit status dialog if user needs it
        self.check_http_support(silent=True)
        self.update_dashboard()
        
    def check_http_support(self, silent: bool = False):
        """Check if HTTP layer is available in Scapy

        Args:
            silent: If True, do not show dialogs when support is available; only warn on missing support.
        """
        try:
            from scapy.contrib import http
            return True
        except ImportError:
            # Show warning only if not silent to avoid popup on every launch
            if not silent:
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
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # --- Toolbar for filters ---
        toolbar_frame = QFrame()
        toolbar_frame.setObjectName("filterToolbar")
        toolbar_frame.setStyleSheet("""
            #filterToolbar {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
                margin-top: 4px;
                margin-bottom: 4px;
            }
        """)
        toolbar_layout = QHBoxLayout(toolbar_frame)
        toolbar_layout.setContentsMargins(8, 2, 8, 2)
        toolbar_layout.setSpacing(8)
        # Protocol filter
        protocol_layout = QHBoxLayout()
        protocol_label = QLabel("Protocol:")
        protocol_label.setStyleSheet("color: #ffffff;")
        protocol_layout.addWidget(protocol_label)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["All", "HTTP", "HTTPS"])
        self.protocol_combo.setFixedHeight(24)
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
        host_label.setStyleSheet("color: #ffffff;")
        host_layout.addWidget(host_label)
        self.host_combo = QComboBox()
        self.host_combo.setEditable(True)
        self.host_combo.setMinimumWidth(200)
        self.host_combo.setFixedHeight(24)
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
        method_label.setStyleSheet("color: #ffffff;")
        method_layout.addWidget(method_label)
        self.method_combo = QComboBox()
        self.method_combo.addItem("All")
        self.method_combo.setFixedHeight(24)
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
        toolbar_layout.addStretch()
        toolbar_frame.setLayout(toolbar_layout)
        layout.addWidget(toolbar_frame)

        # --- Search bar ---
        search_layout = QHBoxLayout()
        search_layout.setSpacing(6)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Type to filter...")
        self.search_input.setMinimumHeight(24)
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                border-radius: 4px;
                padding: 2px 6px;
            }
            QLineEdit:focus { border-color: #2d74da; }
        """)
        self.search_input.textChanged.connect(lambda text: self.http_proxy.setFilterRegularExpression(text))
        search_layout.addWidget(QLabel("🔍"))
        search_layout.addWidget(self.search_input)
        search_widget = QWidget()
        search_widget.setLayout(search_layout)
        layout.addWidget(search_widget)

        # --- Main content splitter: table | details ---
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self._headers = [
            "Timestamp", "Protocol", "Host", "Method", "URL", "Status", "Content Type", "Size"
        ]
        self.http_model = HttpTableModel(self._headers, [])
        self.http_proxy = QSortFilterProxyModel(self)
        self.http_proxy.setSourceModel(self.http_model)
        self.http_proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.http_proxy.setFilterKeyColumn(-1)  # all columns
        self.http_table_view = QTableView()
        self.http_table_view.setModel(self.http_proxy)
        self.http_table_view.verticalHeader().setDefaultSectionSize(20)
        self.http_table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.http_table_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.http_table_view.setAlternatingRowColors(True)
        self.http_table_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.http_table_view.setSortingEnabled(True)
        self.http_table_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        header = self.http_table_view.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        self.http_table_view.selectionModel().selectionChanged.connect(self._selection_changed)
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(0)
        table_layout.addWidget(self.http_table_view)
        table_widget.setMinimumWidth(500)
        splitter.addWidget(table_widget)
        self.http_details = HttpDetailsWidget()
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
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #414558;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #2d74da;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        splitter.addWidget(scroll_area)
        self._main_splitter = splitter
        layout.addWidget(splitter)

        # --- Status bar ---
        status_frame = QFrame()
        status_frame.setObjectName("statusBar")
        status_frame.setStyleSheet("""
            #statusBar {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                margin-top: 6px;
            }
        """)
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(10, 4, 10, 4)
        self.status_icon = QLabel("ℹ️")
        self.status_icon.setStyleSheet("color: #ffffff; font-size: 14px;")
        status_layout.addWidget(self.status_icon)
        self.status_label = QLabel()
        self.status_label.setStyleSheet("color: #ffffff;")
        status_layout.addWidget(self.status_label)
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
                    is_https = packet.get("is_https", False)
                    if is_https:
                        self.https_packets.append(packet)
                    else:
                        self.http_packets.append(packet)
        # Update status label with more detailed information
        total_packets = len(self.http_packets) + len(self.https_packets)
        self.status_label.setText(f"Total: {total_packets} packets (HTTP: {len(self.http_packets)}, HTTPS: {len(self.https_packets)})")
        # Update filter dropdowns
        self._update_filter_options()
        # Apply current filters
        self._filter_changed()
    
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

            protocol = packet.get("protocol", "")
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
            table_data.append([time_str, protocol, host, method, uri, status, content_type, size_str])
        
        # Build list-of-dict rows for the model
        dict_rows = [
            {
                "Timestamp": r[0],
                "Protocol": r[1],
                "Host": r[2],
                "Method": r[3],
                "URL": r[4],
                "Status": r[5],
                "Content Type": r[6],
                "Size": r[7],
            } for r in table_data
        ]

        self.http_model.update(dict_rows)
        
        # Auto-select first row for better UX
        if dict_rows:
            self.http_table_view.selectRow(0)
            # Ensure details reflect selection
            self._selection_changed()
        
        # Store filtered packets for selection handling
        self.filtered_packets = filtered_packets
        
        # Update status
        self.status_label.setText(f"Showing {len(filtered_packets)} of {len(self.http_packets) + len(self.https_packets)} packets")
    
    def _selection_changed(self):
        """Handle selection change in the table"""
        # Get selected row
        selection = self.http_table_view.selectionModel().selectedRows()
        if not selection:
            # Clear details if nothing selected
            self.selected_packet = None
            self.http_details.update_http_data({})
            return
            
        proxy_index = selection[0]
        source_index = self.http_proxy.mapToSource(proxy_index)
        row = source_index.row()
        if row >= len(self.filtered_packets):
            return
            
        self.selected_packet = self.filtered_packets[row]
        
        # Update details view
        if "http" in self.selected_packet:
            self.http_details.update_http_data(
                self.selected_packet["http"], 
                self.selected_packet
            )