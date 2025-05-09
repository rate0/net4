import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QSplitter, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QDialog, QGroupBox, QFormLayout, QSpinBox, QCheckBox,
    QToolBar, QFrame, QSlider, QTimeEdit, QTreeWidget, QTreeWidgetItem, QTableView
)
from PyQt6.QtCore import Qt, pyqtSignal, QDateTime, QTimer, QSize
from PyQt6.QtGui import QIcon, QAction, QFont

import matplotlib.pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
import networkx as nx

from ...models.session import Session
from ...models.network_entity import NetworkEntity
from ..widgets.charts import TimelineChart, NetworkGraph
from ..widgets.global_search import GlobalSearchWidget
from ...utils.logger import Logger
from ..models.generic_table_model import GenericTableModel


class EventAnalysisDashboard(QWidget):
    """
    Combined dashboard for timeline and network graph analysis.
    Provides a comprehensive view of events and their relationships.
    """
    
    def __init__(self, parent=None):
        """
        Initialize event analysis dashboard
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.logger = Logger().get_logger()
        self.session = None
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize dashboard UI"""
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Apply dashboard container style
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e2e;
                color: #ffffff;
            }
        """)
        
        # Controls section - styled as a dashboard card
        controls_frame = QFrame()
        controls_frame.setObjectName("controlsCard")
        controls_frame.setStyleSheet("""
            #controlsCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
                margin-bottom: 10px;
            }
        """)
        controls_layout = QHBoxLayout(controls_frame)
        controls_layout.setSpacing(15)
        
        # Time range controls with improved styling
        time_group = QWidget()
        time_layout = QHBoxLayout(time_group)
        time_layout.setContentsMargins(0, 0, 0, 0)
        
        time_label = QLabel("Time Range:")
        time_label.setStyleSheet("color: #94a3b8; font-weight: bold;")
        time_layout.addWidget(time_label)
        
        self.time_range_combo = QComboBox()
        self.time_range_combo.addItems([
            "All Time", "Last Hour", "Last 12 Hours", "Last 24 Hours", "Custom..."
        ])
        self.time_range_combo.setCurrentText("All Time")
        self.time_range_combo.currentTextChanged.connect(self._update_time_range)
        self.time_range_combo.setStyleSheet("""
            QComboBox {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                border-radius: 4px;
                padding: 4px 8px;
                min-width: 150px;
            }
            QComboBox:hover {
                border-color: #5a6988;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: center right;
                width: 20px;
                border-left: 1px solid #414558;
            }
            QComboBox QAbstractItemView {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                selection-background-color: #2d74da;
            }
        """)
        time_layout.addWidget(self.time_range_combo)
        
        controls_layout.addWidget(time_group)
        
        # Visualization options with improved styling
        view_group = QWidget()
        view_layout = QHBoxLayout(view_group)
        view_layout.setContentsMargins(0, 0, 0, 0)
        
        view_label = QLabel("View:")
        view_label.setStyleSheet("color: #94a3b8; font-weight: bold;")
        view_layout.addWidget(view_label)
        
        self.vis_combo = QComboBox()
        self.vis_combo.addItems([
            "Combined View", "Timeline", "Network Graph", "Search"
        ])
        self.vis_combo.currentTextChanged.connect(self._update_view)
        self.vis_combo.setStyleSheet("""
            QComboBox {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                border-radius: 4px;
                padding: 4px 8px;
                min-width: 150px;
            }
            QComboBox:hover {
                border-color: #5a6988;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: center right;
                width: 20px;
                border-left: 1px solid #414558;
            }
            QComboBox QAbstractItemView {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                selection-background-color: #2d74da;
            }
        """)
        view_layout.addWidget(self.vis_combo)
        
        controls_layout.addWidget(view_group)
        
        # Entity filters with improved styling
        filter_group = QWidget()
        filter_layout = QHBoxLayout(filter_group)
        filter_layout.setContentsMargins(0, 0, 0, 0)
        
        filter_label = QLabel("Entities:")
        filter_label.setStyleSheet("color: #94a3b8; font-weight: bold;")
        filter_layout.addWidget(filter_label)
        
        self.entity_filter_combo = QComboBox()
        self.entity_filter_combo.addItems([
            "All Entities", "Suspicious Only", "Malicious Only", "Custom..."
        ])
        self.entity_filter_combo.currentTextChanged.connect(self._apply_filters)
        self.entity_filter_combo.setStyleSheet("""
            QComboBox {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                border-radius: 4px;
                padding: 4px 8px;
                min-width: 150px;
            }
            QComboBox:hover {
                border-color: #5a6988;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: center right;
                width: 20px;
                border-left: 1px solid #414558;
            }
            QComboBox QAbstractItemView {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                selection-background-color: #2d74da;
            }
        """)
        filter_layout.addWidget(self.entity_filter_combo)
        
        # Correlate button
        self.corr_button = QPushButton("↗ Correlate")
        self.corr_button.setToolTip("Run correlation engine to group related events")
        self.corr_button.setStyleSheet("""
            QPushButton {
                background-color: #2d74da;
                color: #ffffff;
                border-radius: 4px;
                padding: 6px 14px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #3a82f7; }
            QPushButton:pressed { background-color: #2361b8; }
        """)
        self.corr_button.clicked.connect(self._run_correlation)
        filter_layout.addWidget(self.corr_button)
        
        controls_layout.addWidget(filter_group)
        
        # Add refresh button with improved styling
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self._refresh_data)
        refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #2d74da;
                color: #ffffff;
                border-radius: 4px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3a82f7;
            }
            QPushButton:pressed {
                background-color: #2361b8;
            }
        """)
        controls_layout.addWidget(refresh_button)
        
        layout.addWidget(controls_frame)
        
        # Main splitter with styling
        self.main_splitter = QSplitter(Qt.Orientation.Vertical)
        self.main_splitter.setChildrenCollapsible(False)
        self.main_splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #414558;
                height: 2px;
            }
            QSplitter::handle:pressed {
                background-color: #2d74da;
            }
        """)
        
        # Timeline widget with card-like styling
        self.timeline_widget = QFrame()
        self.timeline_widget.setObjectName("timelineCard")
        self.timeline_widget.setStyleSheet("""
            #timelineCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 0px;
            }
        """)
        
        timeline_layout = QVBoxLayout(self.timeline_widget)
        timeline_layout.setContentsMargins(10, 10, 10, 10)
        timeline_layout.setSpacing(10)
        
        # Timeline header
        timeline_header = QLabel("Event Timeline")
        timeline_header.setObjectName("cardHeader")
        timeline_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        timeline_layout.addWidget(timeline_header)
        
        # Timeline chart with improved container
        timeline_chart_container = QFrame()
        timeline_chart_container.setObjectName("chartContainer")
        timeline_chart_container.setStyleSheet("""
            #chartContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        timeline_chart_layout = QVBoxLayout(timeline_chart_container)
        timeline_chart_layout.setContentsMargins(5, 5, 5, 5)
        
        self.timeline_chart = TimelineChart()
        timeline_chart_layout.addWidget(self.timeline_chart)
        
        timeline_layout.addWidget(timeline_chart_container)
        
        # Event details table below timeline with improved styling
        events_frame = QFrame()
        events_frame.setObjectName("eventsContainer")
        events_frame.setStyleSheet("""
            #eventsContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        events_layout = QVBoxLayout(events_frame)
        events_layout.setContentsMargins(5, 5, 5, 5)
        
        events_header = QLabel("Event Details")
        events_header.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; margin-bottom: 5px;")
        events_layout.addWidget(events_header)
        
        self.events_headers = ["Time", "Source", "Destination", "Event Type", "Details"]
        self.events_model = GenericTableModel(self.events_headers, [])
        self.events_table = QTableView()
        self.events_table.setModel(self.events_model)
        header = self.events_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.events_table.setAlternatingRowColors(True)
        self.events_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        events_layout.addWidget(self.events_table)
        
        timeline_layout.addWidget(events_frame)
        timeline_layout.setStretch(0, 0)  # Header - minimum space
        timeline_layout.setStretch(1, 3)  # Timeline - more space
        timeline_layout.setStretch(2, 2)  # Events table - less than timeline but significant
        
        self.main_splitter.addWidget(self.timeline_widget)
        
        # Network graph widget with card-like styling
        self.graph_widget = QFrame()
        self.graph_widget.setObjectName("graphCard")
        self.graph_widget.setStyleSheet("""
            #graphCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 0px;
            }
        """)
        
        graph_layout = QVBoxLayout(self.graph_widget)
        graph_layout.setContentsMargins(10, 10, 10, 10)
        graph_layout.setSpacing(10)
        
        # Network graph header
        graph_header = QLabel("Network Graph")
        graph_header.setObjectName("cardHeader")
        graph_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        graph_layout.addWidget(graph_header)
        
        # Network graph with improved container
        graph_chart_container = QFrame()
        graph_chart_container.setObjectName("networkGraphContainer")
        graph_chart_container.setStyleSheet("""
            #networkGraphContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
                min-height: 400px;
            }
        """)
        graph_chart_layout = QVBoxLayout(graph_chart_container)
        graph_chart_layout.setContentsMargins(5, 5, 5, 5)
        
        self.network_graph = NetworkGraph()
        graph_chart_layout.addWidget(self.network_graph)
        
        graph_layout.addWidget(graph_chart_container)
        
        # Entity details below graph with improved styling
        entity_frame = QFrame()
        entity_frame.setObjectName("entityDetailsContainer")
        entity_frame.setStyleSheet("""
            #entityDetailsContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
            }
        """)
        entity_layout = QVBoxLayout(entity_frame)
        entity_layout.setContentsMargins(5, 5, 5, 5)
        
        entity_header = QLabel("Entity Details")
        entity_header.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; margin-bottom: 5px;")
        entity_layout.addWidget(entity_header)
        
        self.entity_details = QLabel("Select an entity in the graph to see details")
        self.entity_details.setStyleSheet("color: #94a3b8; padding: 10px;")
        self.entity_details.setWordWrap(True)
        entity_layout.addWidget(self.entity_details)
        
        graph_layout.addWidget(entity_frame)
        graph_layout.setStretch(0, 0)  # Header - minimum space
        graph_layout.setStretch(1, 5)  # Graph - most space
        graph_layout.setStretch(2, 1)  # Entity details - less space
        
        self.main_splitter.addWidget(self.graph_widget)
        
        # Search widget with improved styling
        search_frame = QFrame()
        search_frame.setObjectName("searchCard")
        search_frame.setStyleSheet("""
            #searchCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
            }
        """)
        search_layout = QVBoxLayout(search_frame)
        
        search_header = QLabel("Global Search")
        search_header.setObjectName("cardHeader")
        search_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
                margin-bottom: 10px;
            }
        """)
        search_layout.addWidget(search_header)
        
        self.search_widget = GlobalSearchWidget()
        self.search_widget.item_selected.connect(self._on_search_item_selected)
        self.search_widget.setStyleSheet("""
            QLineEdit {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                border-radius: 4px;
                padding: 8px;
                selection-background-color: #2d74da;
            }
            QLineEdit:focus {
                border-color: #2d74da;
            }
            QListView {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                border-radius: 4px;
                padding: 5px;
                selection-background-color: #2d74da;
            }
            QListView::item {
                padding: 8px;
                border-radius: 4px;
            }
            QListView::item:hover {
                background-color: #414558;
            }
            QListView::item:selected {
                background-color: #2d74da;
            }
        """)
        search_layout.addWidget(self.search_widget)
        
        # Start with the search frame hidden
        search_frame.hide()
        
        layout.addWidget(self.main_splitter)
        layout.addWidget(search_frame)
        
        # Set splitter proportions - give more space to visualization elements
        self.main_splitter.setSizes([int(self.height() * 0.7), int(self.height() * 0.3)])
        
        # Connect signals
        self.timeline_chart.point_selected.connect(self._on_timeline_point_selected)
        self.network_graph.node_selected.connect(self._on_graph_node_selected)
        self.events_table.doubleClicked.connect(self._on_event_double_clicked)
        
        # Store the search frame reference for toggling visibility
        self.search_frame = search_frame
    
    def set_session(self, session: Session):
        """
        Set the session data for this dashboard
        
        Args:
            session: Analysis session
        """
        self.session = session
        
        # Update UI with session data
        if session:
            self._refresh_data()
            
            # Set up search widget
            self.search_widget.set_session(session)
    
    def update_dashboard(self):
        """Update dashboard with current session data"""
        if self.session:
            self._refresh_data()
    
    def _refresh_data(self):
        """Refresh data displayed in dashboard"""
        if not self.session:
            return
        
        # Update timeline
        self._update_timeline()
        
        # Update network graph
        self._update_network_graph()
        
        # Update event table
        self._update_events_table()
    
    def _update_timeline(self):
        """Update timeline chart with current session data"""
        if not self.session:
            return
        
        # Get time range
        start_time, end_time = self._get_selected_time_range()
        
        # Prepare timeline data
        events = []
        
        # Add connections
        for conn in self.session.connections:
            timestamp = conn.get("timestamp")
            if timestamp and (start_time is None or start_time <= timestamp) and (end_time is None or timestamp <= end_time):
                events.append({
                    "time": timestamp,
                    "type": "connection",
                    "source": conn.get("src_ip", ""),
                    "destination": conn.get("dst_ip", ""),
                    "details": f"{conn.get('protocol', '')} {conn.get('src_port', '')} → {conn.get('dst_port', '')}",
                    "original": conn
                })
        
        # Add anomalies
        for anomaly in self.session.anomalies:
            timestamp = anomaly.get("timestamp")
            if timestamp and (start_time is None or start_time <= timestamp) and (end_time is None or timestamp <= end_time):
                events.append({
                    "time": timestamp,
                    "type": "anomaly",
                    "source": anomaly.get("source_ip", ""),
                    "destination": anomaly.get("destination_ip", ""),
                    "details": f"{anomaly.get('type', '')} - {anomaly.get('description', '')}",
                    "severity": anomaly.get("severity", "medium"),
                    "original": anomaly
                })
        
        # Add rule matches
        for match in self.session.rule_matches:
            timestamp = match.get("timestamp", datetime.now())
            if (start_time is None or start_time <= timestamp) and (end_time is None or timestamp <= end_time):
                conn = match.get("connection", {})
                events.append({
                    "time": timestamp,
                    "type": "rule_match",
                    "source": conn.get("src_ip", ""),
                    "destination": conn.get("dst_ip", ""),
                    "details": f"Rule: {match.get('rule_name', '')}, Severity: {match.get('severity', 'medium')}",
                    "severity": match.get("severity", "medium"),
                    "original": match
                })
        
        # Update timeline chart
        self.timeline_chart.set_data(events)
    
    def _update_network_graph(self):
        """Update network graph with current session data"""
        if not self.session:
            return
        
        # Get time range
        start_time, end_time = self._get_selected_time_range()
        
        # Prepare graph data
        nodes = []
        edges = []
        
        # Get entity filter
        entity_filter = self.entity_filter_combo.currentText()
        
        # Add entities as nodes
        for entity in self.session.network_entities.values():
            # Apply entity filter
            if entity_filter == "Suspicious Only" and entity.threat_level != "suspicious":
                continue
            elif entity_filter == "Malicious Only" and entity.threat_level != "malicious":
                continue
            elif entity_filter == "Custom..." and not self._custom_entity_filter(entity):
                continue
            
            # Add entity
            if entity.first_seen and (start_time is None or start_time <= entity.first_seen) and \
               (end_time is None or entity.last_seen <= end_time):
                node_type = entity.type
                threat_level = entity.threat_level
                
                nodes.append({
                    "id": entity.value,
                    "type": node_type,
                    "threat_level": threat_level,
                    "tags": entity.tags,
                    "original": entity
                })
        
        # Add connections as edges
        for conn in self.session.connections:
            timestamp = conn.get("timestamp")
            if timestamp and (start_time is None or start_time <= timestamp) and (end_time is None or timestamp <= end_time):
                src = conn.get("src_ip", "")
                dst = conn.get("dst_ip", "")
                
                if src and dst:
                    # Check if nodes exist after filtering
                    src_exists = any(node["id"] == src for node in nodes)
                    dst_exists = any(node["id"] == dst for node in nodes)
                    
                    if src_exists and dst_exists:
                        edges.append({
                            "source": src,
                            "target": dst,
                            "type": conn.get("protocol", ""),
                            "weight": 1,
                            "original": conn
                        })
        
        # Update network graph
        self.network_graph.set_data(nodes, edges)
    
    def _update_events_table(self):
        """Update events table with current session data"""
        if not self.session:
            return
        
        # Get time range
        start_time, end_time = self._get_selected_time_range()
        
        # Collect events
        events = []
        
        # Add connections
        for conn in self.session.connections:
            timestamp = conn.get("timestamp")
            if timestamp and (start_time is None or start_time <= timestamp) and (end_time is None or timestamp <= end_time):
                events.append({
                    "time": timestamp,
                    "type": "Connection",
                    "source": conn.get("src_ip", ""),
                    "destination": conn.get("dst_ip", ""),
                    "details": f"{conn.get('protocol', '')} {conn.get('src_port', '')} → {conn.get('dst_port', '')}",
                    "original": conn
                })
        
        # Add anomalies
        for anomaly in self.session.anomalies:
            timestamp = anomaly.get("timestamp")
            if timestamp and (start_time is None or start_time <= timestamp) and (end_time is None or timestamp <= end_time):
                events.append({
                    "time": timestamp,
                    "type": "Anomaly",
                    "source": anomaly.get("source_ip", ""),
                    "destination": anomaly.get("destination_ip", ""),
                    "details": f"{anomaly.get('type', '')} - {anomaly.get('description', '')}",
                    "original": anomaly
                })
        
        # Add rule matches
        for match in self.session.rule_matches:
            timestamp = match.get("timestamp", datetime.now())
            if (start_time is None or start_time <= timestamp) and (end_time is None or timestamp <= end_time):
                conn = match.get("connection", {})
                events.append({
                    "time": timestamp,
                    "type": "Rule Match",
                    "source": conn.get("src_ip", ""),
                    "destination": conn.get("dst_ip", ""),
                    "details": f"Rule: {match.get('rule_name', '')}, Severity: {match.get('severity', 'medium')}",
                    "original": match
                })
        
        # Sort by time
        events.sort(key=lambda e: e["time"])
        
        # Convert to model-friendly rows
        rows = []
        for ev in events:
            rows.append({
                "Time": ev["time"].strftime("%Y-%m-%d %H:%M:%S"),
                "Source": ev["source"],
                "Destination": ev["destination"],
                "Event Type": ev["type"],
                "Details": ev["details"],
            })

        self.events_model.update(rows)
    
    def _get_selected_time_range(self) -> tuple:
        """
        Get the selected time range based on UI controls
        
        Returns:
            Tuple of (start_time, end_time), either can be None for no limit
        """
        time_range = self.time_range_combo.currentText()
        now = datetime.now()
        
        if time_range == "All Time":
            return None, None
        elif time_range == "Last Hour":
            return now - timedelta(hours=1), now
        elif time_range == "Last 12 Hours":
            return now - timedelta(hours=12), now
        elif time_range == "Last 24 Hours":
            return now - timedelta(hours=24), now
        elif time_range == "Custom...":
            # This would be handled by a dialog in a real implementation
            # For now, return a default range
            return now - timedelta(hours=6), now
        
        return None, None
    
    def _update_time_range(self, range_text: str):
        """
        Handle time range selection change
        
        Args:
            range_text: Selected time range text
        """
        if range_text == "Custom...":
            # Show custom time range dialog
            self._show_custom_time_range_dialog()
        else:
            self._refresh_data()
    
    def _show_custom_time_range_dialog(self):
        """Show dialog for custom time range selection"""
        # This would be implemented with a QDialog in a real implementation
        # For now, just select a default range and refresh
        self.time_range_combo.setCurrentText("Last 12 Hours")
        self._refresh_data()
    
    def _update_view(self, view_text: str):
        """
        Handle view selection change
        
        Args:
            view_text: Selected view text
        """
        if view_text == "Combined View":
            self.timeline_widget.show()
            self.graph_widget.show()
            self.search_frame.hide()
            self.main_splitter.show()
        elif view_text == "Timeline":
            self.timeline_widget.show()
            self.graph_widget.hide()
            self.search_frame.hide()
            self.main_splitter.show()
        elif view_text == "Network Graph":
            self.timeline_widget.hide()
            self.graph_widget.show()
            self.search_frame.hide()
            self.main_splitter.show()
        elif view_text == "Search":
            self.timeline_widget.hide()
            self.graph_widget.hide()
            self.search_frame.show()
            self.main_splitter.hide()
    
    def _custom_entity_filter(self, entity: NetworkEntity) -> bool:
        """
        Apply custom entity filter
        
        Args:
            entity: Entity to check
            
        Returns:
            True if entity passes filter, False otherwise
        """
        # This would be implemented with user-defined criteria
        # For now, accept all entities
        return True
    
    def _apply_filters(self):
        """Apply current filters to the data"""
        self._refresh_data()
    
    def _on_timeline_point_selected(self, point_data: Dict[str, Any]):
        """
        Handle timeline point selection
        
        Args:
            point_data: Data for selected point
        """
        # Update events table to highlight selected event
        for row in range(self.events_table.model().rowCount()):
            index = self.events_table.model().index(row, 0)
            value = self.events_table.model().data(index)
            event_time = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            
            if abs((event_time - point_data["time"]).total_seconds()) < 1:
                self.events_table.selectRow(row)
                self.events_table.scrollTo(index)
                break
    
    def _on_graph_node_selected(self, node_data: Dict[str, Any]):
        """
        Handle network graph node selection
        
        Args:
            node_data: Data for selected node
        """
        # Update entity details with enhanced styling
        entity = node_data.get("original")
        if entity:
            # Create threat badge style based on threat level
            threat_badge_style = ""
            if entity.threat_level == "malicious":
                threat_badge_style = "background-color: #b91c1c; color: #ffffff;"
            elif entity.threat_level == "suspicious":
                threat_badge_style = "background-color: #d97706; color: #ffffff;"
            elif entity.threat_level == "safe":
                threat_badge_style = "background-color: #15803d; color: #ffffff;"
            else:
                threat_badge_style = "background-color: #4b5563; color: #ffffff;"
            
            # Format tags with badge-like styling
            tags_html = ""
            if entity.tags:
                for tag in entity.tags:
                    tags_html += f'<span style="background-color: #323242; color: #ffffff; padding: 2px 6px; border-radius: 3px; margin-right: 4px; font-size: 11px;">{tag}</span>'
            else:
                tags_html = '<span style="color: #94a3b8;">None</span>'
            
            # Create a detailed, well-formatted entity details display
            details = f"""
            <div style="font-family: sans-serif; padding: 10px;">
                <div style="margin-bottom: 15px;">
                    <h3 style="color: #ffffff; margin-bottom: 5px;">{entity.value}</h3>
                    <span style="background-color: #414558; color: #ffffff; padding: 3px 8px; border-radius: 3px; font-size: 12px;">{entity.type.upper()}</span>
                </div>
                
                <div style="margin-bottom: 10px;">
                    <span style="color: #94a3b8; font-weight: bold;">Threat Level:</span>
                    <span style="{threat_badge_style} padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{entity.threat_level.capitalize()}</span>
                </div>
                
                <div style="margin-bottom: 10px;">
                    <span style="color: #94a3b8; font-weight: bold;">First Seen:</span>
                    <span style="color: #ffffff;">{entity.first_seen.strftime('%Y-%m-%d %H:%M:%S')}</span>
                </div>
                
                <div style="margin-bottom: 10px;">
                    <span style="color: #94a3b8; font-weight: bold;">Last Seen:</span>
                    <span style="color: #ffffff;">{entity.last_seen.strftime('%Y-%m-%d %H:%M:%S')}</span>
                </div>
                
                <div style="margin-bottom: 10px;">
                    <span style="color: #94a3b8; font-weight: bold;">Confidence:</span>
                    <span style="color: #ffffff;">{entity.confidence:.2f}</span>
                </div>
                
                <div>
                    <span style="color: #94a3b8; font-weight: bold;">Tags:</span><br>
                    <div style="margin-top: 5px;">
                        {tags_html}
                    </div>
                </div>
            </div>
            """
            
            self.entity_details.setText(details)
    
    def _on_event_double_clicked(self, index):
        """
        Handle double click on event table item
        
        Args:
            index: Clicked item index
        """
        row = index.row()
        model = self.events_table.model()
        
        # Get event details
        time_str = model.data(model.index(row, 0))
        source = model.data(model.index(row, 1))
        destination = model.data(model.index(row, 2))
        event_type = model.data(model.index(row, 3))
        details = model.data(model.index(row, 4))
        
        # Show details dialog
        QMessageBox.information(
            self,
            f"Event Details: {event_type}",
            f"Time: {time_str}\nSource: {source}\nDestination: {destination}\nDetails: {details}"
        )
    
    def _on_search_item_selected(self, item_data: Dict[str, Any]):
        """
        Handle search result item selection
        
        Args:
            item_data: Data for selected item
        """
        # Switch to appropriate view based on item type
        item_type = item_data.get("type", "")
        
        if item_type in ["connection", "anomaly", "rule_match"]:
            # Switch to timeline view
            self.vis_combo.setCurrentText("Timeline")
            
            # Find and select the item in timeline
            self.timeline_chart.select_time_point(item_data.get("time"))
            
        elif item_type == "entity":
            # Switch to network graph view
            self.vis_combo.setCurrentText("Network Graph")
            
            # Find and select the node in graph
            self.network_graph.select_node(item_data.get("value"))
    
    def _run_correlation(self):
        """Execute correlation engine and display clusters in a dialog."""
        if not self.session:
            QMessageBox.warning(self, "No Session", "Load or capture data first.")
            return

        try:
            from ...core.correlation.engine import CorrelationEngine  # lazy import
            engine = CorrelationEngine()
            clusters = engine.correlate(self.session)
        except Exception as e:
            self.logger.error(f"Correlation failed: {e}")
            QMessageBox.critical(self, "Correlation Error", str(e))
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Correlation Results")
        dlg.resize(600, 400)
        vbox = QVBoxLayout(dlg)
        if not clusters:
            vbox.addWidget(QLabel("No related incidents found."))
        else:
            tree = QTreeWidget()
            tree.setHeaderLabels(["IP", "Events"])
            tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

            for cluster in clusters:
                ip = cluster.get("ip")
                events = cluster.get("events", [])
                root = QTreeWidgetItem([ip, str(len(events))])
                for ev in events:
                    ts = ev.get("timestamp", "")
                    desc = ev.get("description", "")
                    child = QTreeWidgetItem([ts, desc])
                    root.addChild(child)
                tree.addTopLevelItem(root)
            vbox.addWidget(tree)

        btn = QPushButton("Close")
        btn.clicked.connect(dlg.accept)
        vbox.addWidget(btn, alignment=Qt.AlignmentFlag.AlignRight)
        dlg.exec()