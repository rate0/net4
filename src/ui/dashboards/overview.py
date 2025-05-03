import os
from datetime import datetime
from typing import Dict, List, Any, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTabWidget,
    QScrollArea, QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QGridLayout, QGroupBox, QTextEdit
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QIcon, QColor

from ..widgets.charts import (
    PieChart, TimeSeriesChart, BarChart, HeatmapChart
)
from ..widgets.data_table import DataTable
from ..widgets.threat_badge import ThreatBadge

from ...models.session import Session


class OverviewDashboard(QWidget):
    """
    Overview dashboard showing summary information and key insights
    about the analysis session.
    """
    
    def __init__(self, session: Session, parent=None):
        """
        Initialize overview dashboard
        
        Args:
            session: Analysis session
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.session = session
        self._init_ui()
    
    def _init_ui(self):
        """Initialize dashboard UI"""
        # Main layout
        layout = QVBoxLayout(self)
        
        # Apply dashboard container style
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e2e;
                color: #ffffff;
            }
        """)
        
        # Header section with dashboard-header style
        header = QFrame()
        header.setObjectName("dashboardHeader")
        header.setStyleSheet("""
            #dashboardHeader {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 15px;
                margin-bottom: 15px;
            }
        """)
        header_layout = QHBoxLayout(header)
        
        # Session information
        info_layout = QVBoxLayout()
        
        # Session title with dashboard-title style
        self.session_label = QLabel(self.session.name)
        self.session_label.setObjectName("dashboardTitle")
        self.session_label.setStyleSheet("""
            #dashboardTitle {
                font-size: 20px;
                font-weight: bold;
                color: #ffffff;
                margin-bottom: 5px;
            }
        """)
        info_layout.addWidget(self.session_label)
        
        # Session metadata with dashboard-subtitle style
        self.metadata_label = QLabel()
        self.metadata_label.setObjectName("dashboardSubtitle")
        self.metadata_label.setStyleSheet("""
            #dashboardSubtitle {
                font-size: 12px;
                color: #94a3b8;
            }
        """)
        info_layout.addWidget(self.metadata_label)
        
        header_layout.addLayout(info_layout)
        header_layout.addStretch()
        
        # Action buttons with improved styling
        action_layout = QVBoxLayout()
        
        self.analyze_button = QPushButton("Run AI Analysis")
        self.analyze_button.setIcon(QIcon("assets/icons/ai.png"))
        self.analyze_button.clicked.connect(self._run_ai_analysis)
        self.analyze_button.setStyleSheet("""
            QPushButton {
                background-color: #2d74da;
                color: #ffffff;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3a82f7;
            }
            QPushButton:pressed {
                background-color: #2361b8;
            }
        """)
        action_layout.addWidget(self.analyze_button)
        
        self.anomaly_button = QPushButton("Detect Anomalies")
        self.anomaly_button.setIcon(QIcon("assets/icons/anomaly.png"))
        self.anomaly_button.clicked.connect(self._detect_anomalies)
        self.anomaly_button.setStyleSheet("""
            QPushButton {
                background-color: #7e22ce;
                color: #ffffff;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #9333ea;
            }
            QPushButton:pressed {
                background-color: #6b21a8;
            }
        """)
        action_layout.addWidget(self.anomaly_button)
        
        header_layout.addLayout(action_layout)
        layout.addWidget(header)
        
        # Create tab widget for dashboard sections with improved styling
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #414558;
                border-radius: 5px;
                background-color: #282838;
                padding: 5px;
            }
            QTabBar::tab {
                background-color: #323242;
                color: #94a3b8;
                border: 1px solid #414558;
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                padding: 8px 15px;
                margin-right: 3px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #2d74da;
                color: #ffffff;
            }
            QTabBar::tab:hover:!selected {
                background-color: #414558;
                color: #ffffff;
            }
        """)
        layout.addWidget(self.tab_widget)
        
        # Summary tab
        self.summary_widget = QWidget()
        self.summary_layout = QVBoxLayout(self.summary_widget)
        self.summary_layout.setContentsMargins(10, 15, 10, 10)
        self._init_summary_tab()
        self.tab_widget.addTab(self.summary_widget, "Summary")
        
        # Traffic tab
        self.traffic_widget = QWidget()
        self.traffic_layout = QVBoxLayout(self.traffic_widget)
        self.traffic_layout.setContentsMargins(10, 15, 10, 10)
        self._init_traffic_tab()
        self.tab_widget.addTab(self.traffic_widget, "Traffic")
        
        # Security tab
        self.security_widget = QWidget()
        self.security_layout = QVBoxLayout(self.security_widget)
        self.security_layout.setContentsMargins(10, 15, 10, 10)
        self._init_security_tab()
        self.tab_widget.addTab(self.security_widget, "Security")
        
        # AI Insights tab
        self.insights_widget = QWidget()
        self.insights_layout = QVBoxLayout(self.insights_widget)
        self.insights_layout.setContentsMargins(10, 15, 10, 10)
        self._init_insights_tab()
        self.tab_widget.addTab(self.insights_widget, "AI Insights")
        
        # Update dashboard with current data
        self.update_dashboard()
    
    def _init_summary_tab(self):
        """Initialize summary tab"""
        # Add content to summary tab
        self.summary_scroll = QScrollArea()
        self.summary_scroll.setWidgetResizable(True)
        self.summary_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.summary_scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
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
                background-color: #5a6988;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        self.summary_content = QWidget()
        self.summary_content_layout = QVBoxLayout(self.summary_content)
        self.summary_content_layout.setSpacing(15)
        
        # Key metrics section - styled as a dashboard card
        metrics_frame = QFrame()
        metrics_frame.setObjectName("metricsCard")
        metrics_frame.setStyleSheet("""
            #metricsCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        
        # Add a header to the metrics card
        metrics_layout = QVBoxLayout(metrics_frame)
        metrics_layout.setSpacing(10)
        
        metrics_header = QLabel("Key Metrics")
        metrics_header.setObjectName("cardHeader")
        metrics_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        metrics_layout.addWidget(metrics_header)
        
        # Create a grid for metrics
        metrics_grid = QWidget()
        grid_layout = QGridLayout(metrics_grid)
        grid_layout.setSpacing(15)
        
        # Use metric-card styling for each metric
        # Packets metric
        packet_card = QFrame()
        packet_card.setObjectName("metricCard")
        packet_card.setStyleSheet("""
            #metricCard {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
            }
        """)
        packet_layout = QVBoxLayout(packet_card)
        packet_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        packet_label = QLabel("Packets")
        packet_label.setObjectName("metricLabel")
        packet_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        packet_layout.addWidget(packet_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.packet_count_label = QLabel("0")
        self.packet_count_label.setObjectName("metricValue")
        self.packet_count_label.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: bold;")
        self.packet_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        packet_layout.addWidget(self.packet_count_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        grid_layout.addWidget(packet_card, 0, 0)
        
        # Connections metric
        connection_card = QFrame()
        connection_card.setObjectName("metricCard")
        connection_card.setStyleSheet("""
            #metricCard {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
            }
        """)
        connection_layout = QVBoxLayout(connection_card)
        connection_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        connection_label = QLabel("Connections")
        connection_label.setObjectName("metricLabel")
        connection_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        connection_layout.addWidget(connection_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.connection_count_label = QLabel("0")
        self.connection_count_label.setObjectName("metricValue")
        self.connection_count_label.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: bold;")
        self.connection_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        connection_layout.addWidget(self.connection_count_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        grid_layout.addWidget(connection_card, 0, 1)
        
        # Entities metric
        entity_card = QFrame()
        entity_card.setObjectName("metricCard")
        entity_card.setStyleSheet("""
            #metricCard {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
            }
        """)
        entity_layout = QVBoxLayout(entity_card)
        entity_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        entity_label = QLabel("Network Entities")
        entity_label.setObjectName("metricLabel")
        entity_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        entity_layout.addWidget(entity_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.entity_count_label = QLabel("0")
        self.entity_count_label.setObjectName("metricValue")
        self.entity_count_label.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: bold;")
        self.entity_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        entity_layout.addWidget(self.entity_count_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        grid_layout.addWidget(entity_card, 0, 2)
        
        # Anomalies metric
        anomaly_card = QFrame()
        anomaly_card.setObjectName("metricCard")
        anomaly_card.setStyleSheet("""
            #metricCard {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
            }
        """)
        anomaly_layout = QVBoxLayout(anomaly_card)
        anomaly_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        anomaly_label = QLabel("Anomalies")
        anomaly_label.setObjectName("metricLabel")
        anomaly_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        anomaly_layout.addWidget(anomaly_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.anomaly_count_label = QLabel("0")
        self.anomaly_count_label.setObjectName("metricValue")
        self.anomaly_count_label.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: bold;")
        self.anomaly_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        anomaly_layout.addWidget(self.anomaly_count_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        grid_layout.addWidget(anomaly_card, 0, 3)
        
        metrics_layout.addWidget(metrics_grid)
        self.summary_content_layout.addWidget(metrics_frame)
        
        # Files section - styled as a dashboard card
        files_frame = QFrame()
        files_frame.setObjectName("filesCard")
        files_frame.setStyleSheet("""
            #filesCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        files_layout = QVBoxLayout(files_frame)
        files_layout.setSpacing(10)
        
        # Add card header
        files_header = QLabel("Analyzed Files")
        files_header.setObjectName("cardHeader")
        files_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        files_layout.addWidget(files_header)
        
        # Add files table with improved styling
        self.files_table = DataTable(
            ["Filename", "Type", "Size", "Status", "Timestamp"],
            self.get_files_data()
        )
        self.files_table.setStyleSheet("""
            QTableView {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                gridline-color: #414558;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #3a3a4a;
                color: #ffffff;
                padding: 6px;
                border: 1px solid #414558;
                font-weight: bold;
            }
            QTableView::item {
                padding: 6px;
                border-bottom: 1px solid #414558;
            }
            QTableView::item:selected {
                background-color: #2d74da;
                color: #ffffff;
            }
            QTableView::item:hover:!selected {
                background-color: #414558;
            }
        """)
        files_layout.addWidget(self.files_table)
        
        self.summary_content_layout.addWidget(files_frame)
        
        # Top entities section - styled as a dashboard card
        entities_frame = QFrame()
        entities_frame.setObjectName("entitiesCard")
        entities_frame.setStyleSheet("""
            #entitiesCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        entities_layout = QVBoxLayout(entities_frame)
        entities_layout.setSpacing(10)
        
        # Add card header
        entities_header = QLabel("Top Entities")
        entities_header.setObjectName("cardHeader")
        entities_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        entities_layout.addWidget(entities_header)
        
        # Add pie charts container with improved styling
        charts_container = QWidget()
        charts_layout = QHBoxLayout(charts_container)
        charts_layout.setSpacing(20)
        
        # IP addresses pie chart container (larger and styled)
        ip_chart_container = QFrame()
        ip_chart_container.setObjectName("pieChartContainer")
        ip_chart_container.setStyleSheet("""
            #pieChartContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
                min-height: 300px;
            }
        """)
        ip_chart_layout = QVBoxLayout(ip_chart_container)
        
        ip_chart_title = QLabel("IP Addresses")
        ip_chart_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ip_chart_title.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; margin-bottom: 5px;")
        ip_chart_layout.addWidget(ip_chart_title)
        
        # Create a much larger pie chart
        self.ip_chart = PieChart("", height=350)  # Removed title as we use a styled QLabel above
        ip_chart_layout.addWidget(self.ip_chart)
        
        charts_layout.addWidget(ip_chart_container)
        
        # Domains pie chart container (larger and styled)
        domain_chart_container = QFrame()
        domain_chart_container.setObjectName("pieChartContainer")
        domain_chart_container.setStyleSheet("""
            #pieChartContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
                min-height: 300px;
            }
        """)
        domain_chart_layout = QVBoxLayout(domain_chart_container)
        
        domain_chart_title = QLabel("Domains")
        domain_chart_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        domain_chart_title.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; margin-bottom: 5px;")
        domain_chart_layout.addWidget(domain_chart_title)
        
        # Create a much larger pie chart
        self.domain_chart = PieChart("", height=350)  # Removed title as we use a styled QLabel above
        domain_chart_layout.addWidget(self.domain_chart)
        
        charts_layout.addWidget(domain_chart_container)
        
        entities_layout.addWidget(charts_container)
        
        # Add table for suspicious entities with improved styling
        suspicious_frame = QFrame()
        suspicious_frame.setObjectName("suspiciousContainer")
        suspicious_frame.setStyleSheet("""
            #suspiciousContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
            }
        """)
        suspicious_layout = QVBoxLayout(suspicious_frame)
        
        suspicious_header = QLabel("Suspicious Entities")
        suspicious_header.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; margin-bottom: 5px;")
        suspicious_layout.addWidget(suspicious_header)
        
        self.suspicious_table = DataTable(
            ["Entity", "Type", "Threat Level", "Confidence"],
            self.get_suspicious_entities()
        )
        self.suspicious_table.setStyleSheet("""
            QTableView {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                gridline-color: #414558;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #3a3a4a;
                color: #ffffff;
                padding: 6px;
                border: 1px solid #414558;
                font-weight: bold;
            }
            QTableView::item {
                padding: 6px;
                border-bottom: 1px solid #414558;
            }
            QTableView::item:selected {
                background-color: #2d74da;
                color: #ffffff;
            }
            QTableView::item:hover:!selected {
                background-color: #414558;
            }
        """)
        suspicious_layout.addWidget(self.suspicious_table)
        
        entities_layout.addWidget(suspicious_frame)
        
        self.summary_content_layout.addWidget(entities_frame)
        
        # Anomalies section - styled as a dashboard card
        anomalies_frame = QFrame()
        anomalies_frame.setObjectName("anomaliesCard")
        anomalies_frame.setStyleSheet("""
            #anomaliesCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        anomalies_layout = QVBoxLayout(anomalies_frame)
        anomalies_layout.setSpacing(10)
        
        # Add card header
        anomalies_header = QLabel("Recent Anomalies")
        anomalies_header.setObjectName("cardHeader")
        anomalies_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        anomalies_layout.addWidget(anomalies_header)
        
        # Add anomalies table with improved styling
        self.anomalies_table = DataTable(
            ["Type", "Severity", "Timestamp", "Description"],
            self.get_anomalies_data()
        )
        self.anomalies_table.setStyleSheet("""
            QTableView {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                gridline-color: #414558;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #3a3a4a;
                color: #ffffff;
                padding: 6px;
                border: 1px solid #414558;
                font-weight: bold;
            }
            QTableView::item {
                padding: 6px;
                border-bottom: 1px solid #414558;
            }
            QTableView::item:selected {
                background-color: #2d74da;
                color: #ffffff;
            }
            QTableView::item:hover:!selected {
                background-color: #414558;
            }
        """)
        anomalies_layout.addWidget(self.anomalies_table)
        
        self.summary_content_layout.addWidget(anomalies_frame)
        
        # Set scroll area widget
        self.summary_scroll.setWidget(self.summary_content)
        self.summary_layout.addWidget(self.summary_scroll)
    
    def _init_traffic_tab(self):
        """Initialize traffic tab"""
        # Add content to traffic tab
        self.traffic_scroll = QScrollArea()
        self.traffic_scroll.setWidgetResizable(True)
        self.traffic_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.traffic_scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
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
                background-color: #5a6988;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        self.traffic_content = QWidget()
        self.traffic_content_layout = QVBoxLayout(self.traffic_content)
        self.traffic_content_layout.setSpacing(15)
        
        # Traffic over time section - styled as a dashboard card
        time_frame = QFrame()
        time_frame.setObjectName("timeSeriesCard")
        time_frame.setStyleSheet("""
            #timeSeriesCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        time_layout = QVBoxLayout(time_frame)
        time_layout.setSpacing(10)
        
        # Add card header
        time_header = QLabel("Traffic Over Time")
        time_header.setObjectName("cardHeader")
        time_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        time_layout.addWidget(time_header)
        
        # Chart container with improved styling
        time_chart_container = QFrame()
        time_chart_container.setObjectName("chartContainer")
        time_chart_container.setStyleSheet("""
            #chartContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
            }
        """)
        time_chart_layout = QVBoxLayout(time_chart_container)
        
        self.time_chart = TimeSeriesChart("", height=350)  # Removed title as we use a styled QLabel above
        time_chart_layout.addWidget(self.time_chart)
        
        time_layout.addWidget(time_chart_container)
        self.traffic_content_layout.addWidget(time_frame)
        
        # Protocol distribution section - styled as a dashboard card
        protocol_frame = QFrame()
        protocol_frame.setObjectName("protocolCard")
        protocol_frame.setStyleSheet("""
            #protocolCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        protocol_layout = QVBoxLayout(protocol_frame)
        protocol_layout.setSpacing(10)
        
        # Add card header
        protocol_header = QLabel("Protocol Distribution")
        protocol_header.setObjectName("cardHeader")
        protocol_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        protocol_layout.addWidget(protocol_header)
        
        # Charts container
        charts_container = QWidget()
        charts_layout = QHBoxLayout(charts_container)
        charts_layout.setSpacing(20)
        
        # Protocol pie chart container
        protocol_chart_container = QFrame()
        protocol_chart_container.setObjectName("pieChartContainer")
        protocol_chart_container.setStyleSheet("""
            #pieChartContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
                min-height: 300px;
            }
        """)
        protocol_chart_layout = QVBoxLayout(protocol_chart_container)
        
        protocol_chart_title = QLabel("Protocol Types")
        protocol_chart_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        protocol_chart_title.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; margin-bottom: 5px;")
        protocol_chart_layout.addWidget(protocol_chart_title)
        
        self.protocol_chart = PieChart("", height=350)  # Removed title as we use a styled QLabel above
        protocol_chart_layout.addWidget(self.protocol_chart)
        
        charts_layout.addWidget(protocol_chart_container)
        
        # Port chart container
        port_chart_container = QFrame()
        port_chart_container.setObjectName("barChartContainer")
        port_chart_container.setStyleSheet("""
            #barChartContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
                min-height: 300px;
            }
        """)
        port_chart_layout = QVBoxLayout(port_chart_container)
        
        port_chart_title = QLabel("Top Ports")
        port_chart_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        port_chart_title.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; margin-bottom: 5px;")
        port_chart_layout.addWidget(port_chart_title)
        
        self.port_chart = BarChart("", height=350)  # Removed title as we use a styled QLabel above
        port_chart_layout.addWidget(self.port_chart)
        
        charts_layout.addWidget(port_chart_container)
        
        protocol_layout.addWidget(charts_container)
        self.traffic_content_layout.addWidget(protocol_frame)
        
        # Top talkers section - styled as a dashboard card
        talkers_frame = QFrame()
        talkers_frame.setObjectName("talkersCard")
        talkers_frame.setStyleSheet("""
            #talkersCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        talkers_layout = QVBoxLayout(talkers_frame)
        talkers_layout.setSpacing(10)
        
        # Add card header
        talkers_header = QLabel("Top Talkers")
        talkers_header.setObjectName("cardHeader")
        talkers_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        talkers_layout.addWidget(talkers_header)
        
        # Add talkers table with improved styling
        self.talkers_table = DataTable(
            ["Source IP", "Destination IP", "Protocol", "Packets", "Bytes"],
            self.get_top_talkers()
        )
        self.talkers_table.setStyleSheet("""
            QTableView {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                gridline-color: #414558;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #3a3a4a;
                color: #ffffff;
                padding: 6px;
                border: 1px solid #414558;
                font-weight: bold;
            }
            QTableView::item {
                padding: 6px;
                border-bottom: 1px solid #414558;
            }
            QTableView::item:selected {
                background-color: #2d74da;
                color: #ffffff;
            }
            QTableView::item:hover:!selected {
                background-color: #414558;
            }
        """)
        talkers_layout.addWidget(self.talkers_table)
        
        self.traffic_content_layout.addWidget(talkers_frame)
        
        # Set scroll area widget
        self.traffic_scroll.setWidget(self.traffic_content)
        self.traffic_layout.addWidget(self.traffic_scroll)
    
    def _init_security_tab(self):
        """Initialize security tab"""
        # Add content to security tab
        self.security_scroll = QScrollArea()
        self.security_scroll.setWidgetResizable(True)
        self.security_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.security_scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
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
                background-color: #5a6988;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        self.security_content = QWidget()
        self.security_content_layout = QVBoxLayout(self.security_content)
        self.security_content_layout.setSpacing(15)
        
        # Threat summary section - styled as a dashboard card
        threat_summary_frame = QFrame()
        threat_summary_frame.setObjectName("threatSummaryCard")
        threat_summary_frame.setStyleSheet("""
            #threatSummaryCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        
        threat_summary_layout = QVBoxLayout(threat_summary_frame)
        threat_summary_layout.setSpacing(10)
        
        # Add card header
        threat_summary_header = QLabel("Threat Summary")
        threat_summary_header.setObjectName("cardHeader")
        threat_summary_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        threat_summary_layout.addWidget(threat_summary_header)
        
        # Add key metrics for threats with card-based design
        metrics_grid = QWidget()
        threat_metrics_layout = QGridLayout(metrics_grid)
        threat_metrics_layout.setSpacing(15)
        
        # Malicious entities metric
        malicious_card = QFrame()
        malicious_card.setObjectName("metricCard")
        malicious_card.setStyleSheet("""
            #metricCard {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
            }
        """)
        malicious_layout = QVBoxLayout(malicious_card)
        malicious_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        malicious_label = QLabel("Malicious Entities")
        malicious_label.setObjectName("metricLabel")
        malicious_label.setStyleSheet("color: #b91c1c; font-size: 12px; font-weight: bold;")
        malicious_layout.addWidget(malicious_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.malicious_count_label = QLabel("0")
        self.malicious_count_label.setObjectName("metricValue")
        self.malicious_count_label.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: bold;")
        self.malicious_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        malicious_layout.addWidget(self.malicious_count_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        threat_metrics_layout.addWidget(malicious_card, 0, 0)
        
        # Suspicious entities metric
        suspicious_card = QFrame()
        suspicious_card.setObjectName("metricCard")
        suspicious_card.setStyleSheet("""
            #metricCard {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
            }
        """)
        suspicious_layout = QVBoxLayout(suspicious_card)
        suspicious_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        suspicious_label = QLabel("Suspicious Entities")
        suspicious_label.setObjectName("metricLabel")
        suspicious_label.setStyleSheet("color: #d97706; font-size: 12px; font-weight: bold;")
        suspicious_layout.addWidget(suspicious_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.suspicious_count_label = QLabel("0")
        self.suspicious_count_label.setObjectName("metricValue")
        self.suspicious_count_label.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: bold;")
        self.suspicious_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        suspicious_layout.addWidget(self.suspicious_count_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        threat_metrics_layout.addWidget(suspicious_card, 0, 1)
        
        # High severity anomalies metric
        anomaly_card = QFrame()
        anomaly_card.setObjectName("metricCard")
        anomaly_card.setStyleSheet("""
            #metricCard {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
            }
        """)
        anomaly_layout = QVBoxLayout(anomaly_card)
        anomaly_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        anomaly_label = QLabel("High Severity Anomalies")
        anomaly_label.setObjectName("metricLabel")
        anomaly_label.setStyleSheet("color: #ef4444; font-size: 12px; font-weight: bold;")
        anomaly_layout.addWidget(anomaly_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.high_anomaly_count_label = QLabel("0")
        self.high_anomaly_count_label.setObjectName("metricValue")
        self.high_anomaly_count_label.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: bold;")
        self.high_anomaly_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        anomaly_layout.addWidget(self.high_anomaly_count_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        threat_metrics_layout.addWidget(anomaly_card, 0, 2)
        
        # Rule match count metric
        rules_card = QFrame()
        rules_card.setObjectName("metricCard")
        rules_card.setStyleSheet("""
            #metricCard {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
            }
        """)
        rules_layout = QVBoxLayout(rules_card)
        rules_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        rules_label = QLabel("Rule Matches")
        rules_label.setObjectName("metricLabel")
        rules_label.setStyleSheet("color: #7e22ce; font-size: 12px; font-weight: bold;")
        rules_layout.addWidget(rules_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.rules_count_label = QLabel("0")
        self.rules_count_label.setObjectName("metricValue")
        self.rules_count_label.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: bold;")
        self.rules_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        rules_layout.addWidget(self.rules_count_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        threat_metrics_layout.addWidget(rules_card, 0, 3)
        
        threat_summary_layout.addWidget(metrics_grid)
        
        # Add chart container
        charts_container = QWidget()
        charts_layout = QHBoxLayout(charts_container)
        charts_layout.setSpacing(20)
        
        # Threat severity pie chart container (larger and styled)
        threat_chart_container = QFrame()
        threat_chart_container.setObjectName("pieChartContainer")
        threat_chart_container.setStyleSheet("""
            #pieChartContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
                min-height: 300px;
            }
        """)
        threat_chart_layout = QVBoxLayout(threat_chart_container)
        
        threat_chart_title = QLabel("Threat Severity Distribution")
        threat_chart_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        threat_chart_title.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; margin-bottom: 5px;")
        threat_chart_layout.addWidget(threat_chart_title)
        
        # Create a much larger pie chart
        self.threat_chart = PieChart("", height=350)  # Removed title as we use a styled QLabel above
        threat_chart_layout.addWidget(self.threat_chart)
        
        charts_layout.addWidget(threat_chart_container)
        
        # Threat types bar chart container
        threat_type_chart_container = QFrame()
        threat_type_chart_container.setObjectName("barChartContainer")
        threat_type_chart_container.setStyleSheet("""
            #barChartContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
                min-height: 300px;
            }
        """)
        threat_type_chart_layout = QVBoxLayout(threat_type_chart_container)
        
        threat_type_chart_title = QLabel("Threat Types")
        threat_type_chart_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        threat_type_chart_title.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; margin-bottom: 5px;")
        threat_type_chart_layout.addWidget(threat_type_chart_title)
        
        # Create a larger bar chart
        self.threat_type_chart = BarChart("", height=350)  # Removed title as we use a styled QLabel above
        threat_type_chart_layout.addWidget(self.threat_type_chart)
        
        charts_layout.addWidget(threat_type_chart_container)
        
        threat_summary_layout.addWidget(charts_container)
        self.security_content_layout.addWidget(threat_summary_frame)
        
        # Malicious entities section - styled as a dashboard card
        malicious_frame = QFrame()
        malicious_frame.setObjectName("maliciousCard")
        malicious_frame.setStyleSheet("""
            #maliciousCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        
        malicious_entities_layout = QVBoxLayout(malicious_frame)
        malicious_entities_layout.setSpacing(10)
        
        # Add card header
        malicious_header = QLabel("Malicious Entities")
        malicious_header.setObjectName("cardHeader")
        malicious_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        malicious_entities_layout.addWidget(malicious_header)
        
        # Add malicious entities table with improved styling
        self.malicious_table = DataTable(
            ["Entity", "Type", "Risk Score", "Tags", "First Seen"],
            self.get_malicious_entities()
        )
        self.malicious_table.setStyleSheet("""
            QTableView {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                gridline-color: #414558;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #3a3a4a;
                color: #ffffff;
                padding: 6px;
                border: 1px solid #414558;
                font-weight: bold;
            }
            QTableView::item {
                padding: 6px;
                border-bottom: 1px solid #414558;
            }
            QTableView::item:selected {
                background-color: #2d74da;
                color: #ffffff;
            }
            QTableView::item:hover:!selected {
                background-color: #414558;
            }
        """)
        malicious_entities_layout.addWidget(self.malicious_table)
        
        self.security_content_layout.addWidget(malicious_frame)
        
        # High severity anomalies section - styled as a dashboard card
        anomalies_frame = QFrame()
        anomalies_frame.setObjectName("anomaliesCard")
        anomalies_frame.setStyleSheet("""
            #anomaliesCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        
        high_anomalies_layout = QVBoxLayout(anomalies_frame)
        high_anomalies_layout.setSpacing(10)
        
        # Add card header
        anomalies_header = QLabel("High Severity Anomalies")
        anomalies_header.setObjectName("cardHeader")
        anomalies_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        high_anomalies_layout.addWidget(anomalies_header)
        
        # Add high severity anomalies table with improved styling
        self.high_anomalies_table = DataTable(
            ["Type", "Description", "Timestamp", "Details"],
            self.get_high_severity_anomalies()
        )
        self.high_anomalies_table.setStyleSheet("""
            QTableView {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                gridline-color: #414558;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #3a3a4a;
                color: #ffffff;
                padding: 6px;
                border: 1px solid #414558;
                font-weight: bold;
            }
            QTableView::item {
                padding: 6px;
                border-bottom: 1px solid #414558;
            }
            QTableView::item:selected {
                background-color: #2d74da;
                color: #ffffff;
            }
            QTableView::item:hover:!selected {
                background-color: #414558;
            }
        """)
        high_anomalies_layout.addWidget(self.high_anomalies_table)
        
        self.security_content_layout.addWidget(anomalies_frame)
        
        # Set scroll area widget
        self.security_scroll.setWidget(self.security_content)
        self.security_layout.addWidget(self.security_scroll)
    
    def _init_insights_tab(self):
        """Initialize AI insights tab"""
        # Add content to insights tab
        self.insights_scroll = QScrollArea()
        self.insights_scroll.setWidgetResizable(True)
        self.insights_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.insights_scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
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
                background-color: #5a6988;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        self.insights_content = QWidget()
        self.insights_content_layout = QVBoxLayout(self.insights_content)
        self.insights_content_layout.setSpacing(15)
        
        # AI analysis summary section - styled as a dashboard card
        ai_summary_frame = QFrame()
        ai_summary_frame.setObjectName("aiSummaryCard")
        ai_summary_frame.setStyleSheet("""
            #aiSummaryCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        
        ai_summary_layout = QVBoxLayout(ai_summary_frame)
        ai_summary_layout.setSpacing(10)
        
        # Add card header
        ai_summary_header = QLabel("AI Analysis Summary")
        ai_summary_header.setObjectName("cardHeader")
        ai_summary_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        ai_summary_layout.addWidget(ai_summary_header)
        
        # Text edit with enhanced styling
        self.ai_summary_text = QTextEdit()
        self.ai_summary_text.setReadOnly(True)
        self.ai_summary_text.setStyleSheet("""
            QTextEdit {
                background-color: #323242;
                color: #ffffff;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
                selection-background-color: #2d74da;
            }
        """)
        ai_summary_layout.addWidget(self.ai_summary_text)
        
        self.insights_content_layout.addWidget(ai_summary_frame)
        
        # Key observations section - styled as a dashboard card
        observations_frame = QFrame()
        observations_frame.setObjectName("observationsCard")
        observations_frame.setStyleSheet("""
            #observationsCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        
        observations_layout = QVBoxLayout(observations_frame)
        observations_layout.setSpacing(10)
        
        # Add card header
        observations_header = QLabel("Key Observations")
        observations_header.setObjectName("cardHeader")
        observations_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        observations_layout.addWidget(observations_header)
        
        # Observations table with improved styling
        self.observations_table = DataTable(
            ["Observation", "Type", "Severity"],
            self.get_ai_observations()
        )
        self.observations_table.setStyleSheet("""
            QTableView {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                gridline-color: #414558;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #3a3a4a;
                color: #ffffff;
                padding: 6px;
                border: 1px solid #414558;
                font-weight: bold;
            }
            QTableView::item {
                padding: 6px;
                border-bottom: 1px solid #414558;
            }
            QTableView::item:selected {
                background-color: #2d74da;
                color: #ffffff;
            }
            QTableView::item:hover:!selected {
                background-color: #414558;
            }
        """)
        observations_layout.addWidget(self.observations_table)
        
        self.insights_content_layout.addWidget(observations_frame)
        
        # Security concerns section - styled as a dashboard card
        concerns_frame = QFrame()
        concerns_frame.setObjectName("concernsCard")
        concerns_frame.setStyleSheet("""
            #concernsCard {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        
        concerns_layout = QVBoxLayout(concerns_frame)
        concerns_layout.setSpacing(10)
        
        # Add card header
        concerns_header = QLabel("Security Concerns")
        concerns_header.setObjectName("cardHeader")
        concerns_header.setStyleSheet("""
            #cardHeader {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                padding-bottom: 5px;
                border-bottom: 1px solid #414558;
            }
        """)
        concerns_layout.addWidget(concerns_header)
        
        # Concerns table with improved styling
        self.concerns_table = DataTable(
            ["Concern", "Impact", "Recommendation"],
            self.get_security_concerns()
        )
        self.concerns_table.setStyleSheet("""
            QTableView {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                gridline-color: #414558;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #3a3a4a;
                color: #ffffff;
                padding: 6px;
                border: 1px solid #414558;
                font-weight: bold;
            }
            QTableView::item {
                padding: 6px;
                border-bottom: 1px solid #414558;
            }
            QTableView::item:selected {
                background-color: #2d74da;
                color: #ffffff;
            }
            QTableView::item:hover:!selected {
                background-color: #414558;
            }
        """)
        concerns_layout.addWidget(self.concerns_table)
        
        # Add recommended actions section
        actions_container = QFrame()
        actions_container.setObjectName("actionsContainer")
        actions_container.setStyleSheet("""
            #actionsContainer {
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 10px;
                margin-top: 10px;
            }
        """)
        actions_layout = QVBoxLayout(actions_container)
        
        actions_label = QLabel("Recommended Actions")
        actions_label.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; margin-bottom: 5px;")
        actions_layout.addWidget(actions_label)
        
        self.actions_text = QTextEdit()
        self.actions_text.setReadOnly(True)
        self.actions_text.setStyleSheet("""
            QTextEdit {
                background-color: #282838;
                color: #ffffff;
                border: none;
                border-radius: 3px;
                padding: 5px;
            }
        """)
        self.actions_text.setMaximumHeight(100)
        actions_layout.addWidget(self.actions_text)
        
        concerns_layout.addWidget(actions_container)
        
        self.insights_content_layout.addWidget(concerns_frame)
        
        # Set scroll area widget
        self.insights_scroll.setWidget(self.insights_content)
        self.insights_layout.addWidget(self.insights_scroll)
    
    def update_dashboard(self):
        """Update dashboard with current session data"""
        # Update session information
        self.session_label.setText(self.session.name)
        
        # Update metadata
        metadata_text = f"Created: {self.session.created_at.strftime('%Y-%m-%d %H:%M:%S')}"
        
        start_time = self.session.metadata.get("start_time")
        end_time = self.session.metadata.get("end_time")
        
        if start_time and end_time:
            duration = (end_time - start_time).total_seconds()
            duration_str = self._format_duration(duration)
            metadata_text += f" | Capture duration: {duration_str}"
        
        self.metadata_label.setText(metadata_text)
        
        # Update key metrics
        packet_count = self.session.metadata.get("packet_count", 0)
        self.packet_count_label.setText(str(packet_count))
        
        connection_count = len(self.session.connections)
        self.connection_count_label.setText(str(connection_count))
        
        entity_count = len(self.session.network_entities)
        self.entity_count_label.setText(str(entity_count))
        
        anomaly_count = len(self.session.anomalies)
        self.anomaly_count_label.setText(str(anomaly_count))
        
        # Update files table
        self.files_table.update_data(self.get_files_data())
        
        # Update IP chart - FIXED: Added "Clean" to the categories
        ip_categories = {"Malicious": 0, "Suspicious": 0, "Safe": 0, "Unknown": 0, "Clean": 0}
        for entity in self.session.network_entities.values():
            if entity.type == "ip":
                # Get the capitalized threat level
                threat_level = entity.threat_level.capitalize()
                # Make sure the category exists before incrementing
                if threat_level in ip_categories:
                    ip_categories[threat_level] += 1
                else:
                    # For any unexpected threat levels, count as Unknown
                    ip_categories["Unknown"] += 1
        
        ip_data = [
            (category, count) for category, count in ip_categories.items() if count > 0
        ]
        self.ip_chart.update_data(ip_data)
        
        # Update domain chart - FIXED: Added "Clean" to the categories
        domain_categories = {"Malicious": 0, "Suspicious": 0, "Safe": 0, "Unknown": 0, "Clean": 0}
        for entity in self.session.network_entities.values():
            if entity.type == "domain":
                # Get the capitalized threat level
                threat_level = entity.threat_level.capitalize()
                # Make sure the category exists before incrementing
                if threat_level in domain_categories:
                    domain_categories[threat_level] += 1
                else:
                    # For any unexpected threat levels, count as Unknown
                    domain_categories["Unknown"] += 1
        
        domain_data = [
            (category, count) for category, count in domain_categories.items() if count > 0
        ]
        self.domain_chart.update_data(domain_data)
        
        # Update suspicious entities table
        self.suspicious_table.update_data(self.get_suspicious_entities())
        
        # Update anomalies table
        self.anomalies_table.update_data(self.get_anomalies_data())
        
        # Update traffic tab data
        self._update_traffic_charts()
        self.talkers_table.update_data(self.get_top_talkers())
        
        # Update security tab data
        self._update_security_charts()
        self.malicious_table.update_data(self.get_malicious_entities())
        self.high_anomalies_table.update_data(self.get_high_severity_anomalies())
        
        # Update AI insights tab
        self._update_ai_insights()
        self.observations_table.update_data(self.get_ai_observations())
        self.concerns_table.update_data(self.get_security_concerns())
    
    def _update_traffic_charts(self):
        """Update traffic charts with current data"""
        # Update time series chart
        if self.session.packets:
            # Group packets by time interval
            time_data = {}
            for packet in self.session.packets:
                timestamp = packet.get("timestamp")
                if timestamp:
                    # Round to minute for display
                    minute = timestamp.replace(second=0, microsecond=0)
                    time_data[minute] = time_data.get(minute, 0) + 1
            
            # Convert to sorted list of (timestamp, count) tuples
            time_series = [(ts, count) for ts, count in sorted(time_data.items())]
            self.time_chart.update_data(time_series)
        else:
            self.time_chart.clear()
        
        # Update protocol chart
        protocol_counts = {}
        for packet in self.session.packets:
            protocol = packet.get("protocol", "Unknown")
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        protocol_data = [
            (protocol, count) for protocol, count in protocol_counts.items() 
            if count > 0
        ]
        protocol_data.sort(key=lambda x: x[1], reverse=True)
        self.protocol_chart.update_data(protocol_data[:10])  # Top 10 protocols
        
        # Update port chart
        port_counts = {}
        for conn in self.session.connections:
            dst_port = conn.get("dst_port", 0)
            if dst_port > 0:
                port_counts[dst_port] = port_counts.get(dst_port, 0) + 1
        
        port_data = [(f"Port {port}", count) for port, count in port_counts.items()]
        port_data.sort(key=lambda x: x[1], reverse=True)
        self.port_chart.update_data(port_data[:10])  # Top 10 ports
    
    def _update_security_charts(self):
        """Update security charts with current data"""
        # Update threat severity chart - FIXED: Added "Clean" to the categories
        threat_levels = {"Malicious": 0, "Suspicious": 0, "Safe": 0, "Unknown": 0, "Clean": 0}
        malicious_count = 0
        suspicious_count = 0
        
        for entity in self.session.network_entities.values():
            # Get the capitalized threat level
            threat_level = entity.threat_level.capitalize()
            # Make sure the category exists before incrementing
            if threat_level in threat_levels:
                threat_levels[threat_level] += 1
                
                # Count malicious and suspicious entities for the metrics
                if threat_level == "Malicious":
                    malicious_count += 1
                elif threat_level == "Suspicious":
                    suspicious_count += 1
            else:
                # For any unexpected threat levels, count as Unknown
                threat_levels["Unknown"] += 1
        
        # Update threat level counts in the metrics
        self.malicious_count_label.setText(str(malicious_count))
        self.suspicious_count_label.setText(str(suspicious_count))
        
        # Count high severity anomalies for the metrics
        high_severity_count = sum(1 for anomaly in self.session.anomalies if anomaly.get("severity") == "high")
        self.high_anomaly_count_label.setText(str(high_severity_count))
        
        # Count rule matches for the metrics
        rule_match_count = len(self.session.rule_matches) if hasattr(self.session, 'rule_matches') else 0
        self.rules_count_label.setText(str(rule_match_count))
        
        # Update threat severity pie chart
        threat_data = [
            (level, count) for level, count in threat_levels.items() if count > 0
        ]
        self.threat_chart.update_data(threat_data)
        
        # Update threat type chart
        threat_types = {}
        
        for entity in self.session.network_entities.values():
            if entity.threat_level in ["malicious", "suspicious"]:
                entity_type = entity.type.capitalize()
                threat_types[entity_type] = threat_types.get(entity_type, 0) + 1
        
        # Also include anomaly types in the threat type chart
        for anomaly in self.session.anomalies:
            if anomaly.get("severity") in ["high", "medium"]:
                anomaly_type = anomaly.get("type", "Unknown").replace("_", " ").title()
                threat_types[anomaly_type] = threat_types.get(anomaly_type, 0) + 1
        
        # Include rule match types
        if hasattr(self.session, 'rule_matches'):
            for rule_match in self.session.rule_matches:
                rule_type = rule_match.get("rule_type", "Unknown Rule").replace("_", " ").title()
                threat_types[rule_type] = threat_types.get(rule_type, 0) + 1
        
        threat_type_data = [
            (type_name, count) for type_name, count in threat_types.items() if count > 0
        ]
        threat_type_data.sort(key=lambda x: x[1], reverse=True)
        self.threat_type_chart.update_data(threat_type_data[:8])  # Show top 8 threat types
    
    def _update_ai_insights(self):
        """Update AI insights tab with current data"""
        # Check if we have any AI insights
        if not self.session.ai_insights:
            self.ai_summary_text.setHtml("<div style='color:#94a3b8; padding:20px; text-align:center;'>"
                         "<h3>No AI Analysis Available</h3>"
                         "<p>Click 'Run AI Analysis' button to analyze this session and get insights.</p>"
                         "</div>")
            self.actions_text.setHtml("<p style='color:#94a3b8; text-align:center;'>No recommendations available</p>")
            return
        
        # Find overview insight
        overview_insight = None
        for insight in self.session.ai_insights:
            if insight.get("type") == "overview" or "summary" in insight:
                overview_insight = insight
                break
        
        # Use the first insight if no overview insight
        if not overview_insight and self.session.ai_insights:
            overview_insight = self.session.ai_insights[0]
        
        if overview_insight:
            # Format summary text with improved styling
            summary_text = "<div style='padding: 10px;'>"
            
            if "summary" in overview_insight:
                summary_text += f"<h3 style='color:#ffffff; margin-bottom:10px;'>Summary</h3>\n"
                summary_text += f"<p style='color:#ffffff; margin-bottom:15px; line-height:1.4;'>{overview_insight['summary']}</p>\n\n"
            
            if "key_observations" in overview_insight:
                summary_text += "<h3 style='color:#ffffff; margin-bottom:10px;'>Key Observations</h3>\n"
                summary_text += "<ul style='margin-left:15px; margin-bottom:15px;'>\n"
                for observation in overview_insight["key_observations"]:
                    summary_text += f"<li style='color:#ffffff; margin-bottom:5px;'>{observation}</li>\n"
                summary_text += "</ul>\n\n"
            
            if "protocol_analysis" in overview_insight:
                summary_text += "<h3 style='color:#ffffff; margin-bottom:10px;'>Protocol Analysis</h3>\n"
                summary_text += "<ul style='margin-left:15px; margin-bottom:15px;'>\n"
                for protocol, analysis in overview_insight["protocol_analysis"].items():
                    summary_text += f"<li style='color:#ffffff; margin-bottom:5px;'><b>{protocol}:</b> {analysis}</li>\n"
                summary_text += "</ul>\n\n"
            
            if "security_concerns" in overview_insight:
                summary_text += "<h3 style='color:#ffffff; margin-bottom:10px;'>Security Concerns</h3>\n"
                summary_text += "<ul style='margin-left:15px; margin-bottom:15px;'>\n"
                for concern in overview_insight["security_concerns"]:
                    summary_text += f"<li style='color:#ff6b6b; margin-bottom:5px;'>{concern}</li>\n"
                summary_text += "</ul>\n\n"
            
            # Add timestamp with better styling
            if "timestamp" in overview_insight:
                try:
                    timestamp = datetime.fromisoformat(overview_insight["timestamp"])
                    summary_text += f"<p style='color:#94a3b8; font-size:12px; margin-top:15px;'><i>Analysis generated: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</i></p>"
                except:
                    pass
            
            summary_text += "</div>"
            self.ai_summary_text.setHtml(summary_text)
            
            # Update the recommended actions text field
            if "recommended_actions" in overview_insight and overview_insight["recommended_actions"]:
                actions_text = "<ul style='margin-left:15px; margin-top:5px;'>\n"
                for action in overview_insight["recommended_actions"]:
                    actions_text += f"<li style='color:#ffffff; margin-bottom:5px;'>{action}</li>\n"
                actions_text += "</ul>\n"
                self.actions_text.setHtml(actions_text)
            else:
                self.actions_text.setHtml("<p style='color:#94a3b8; text-align:center;'>No specific recommendations available</p>")
            
        else:
            self.ai_summary_text.setHtml("<div style='color:#94a3b8; padding:20px; text-align:center;'>"
                         "<h3>No Overview Analysis Available</h3>"
                         "<p>Run a new analysis to generate insights.</p>"
                         "</div>")
            self.actions_text.setHtml("<p style='color:#94a3b8; text-align:center;'>No recommendations available</p>")
    
    def get_files_data(self) -> List[List[Any]]:
        """
        Get data for files table
        
        Returns:
            List of file data rows
        """
        data = []
        
        for file_id, file_info in self.session.files.items():
            name = file_info.get("name", "Unknown")
            file_type = file_info.get("type", "Unknown")
            
            # Extract size from metadata if available
            size = file_info.get("metadata", {}).get("size", "Unknown")
            if isinstance(size, int):
                size = self._format_bytes(size)
            
            # Determine status from metadata
            metadata = file_info.get("metadata", {})
            if metadata:
                if file_type == "pcap":
                    status = f"Processed {metadata.get('processed_count', 0)} packets"
                elif file_type == "log":
                    status = f"Processed {metadata.get('processed_lines', 0)} lines"
                else:
                    status = "Processed"
            else:
                status = "Imported"
            
            # Get timestamp
            timestamp = file_info.get("added_at")
            if timestamp:
                timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            else:
                timestamp_str = "Unknown"
            
            data.append([name, file_type, size, status, timestamp_str])
        
        return data
    
    def get_suspicious_entities(self) -> List[List[Any]]:
        """
        Get data for suspicious entities table
        
        Returns:
            List of suspicious entity data rows
        """
        data = []
        
        for entity_id, entity in self.session.network_entities.items():
            if entity.threat_level in ["malicious", "suspicious"]:
                threat_level = entity.threat_level.capitalize()
                confidence = f"{entity.confidence:.2f}"
                
                data.append([entity.value, entity.type.capitalize(), threat_level, confidence])
        
        # Sort by threat level (malicious first) then confidence
        data.sort(key=lambda x: (0 if x[2] == "Malicious" else 1, -float(x[3])))
        
        return data[:20]  # Return top 20
    
    def get_anomalies_data(self) -> List[List[Any]]:
        """
        Get data for anomalies table
        
        Returns:
            List of anomaly data rows
        """
        data = []
        
        for anomaly in self.session.anomalies:
            anomaly_type = anomaly.get("type", "Unknown")
            subtype = anomaly.get("subtype", "")
            
            if subtype:
                anomaly_type = f"{anomaly_type} ({subtype})"
            
            severity = anomaly.get("severity", "Unknown").capitalize()
            
            timestamp = anomaly.get("timestamp")
            if timestamp:
                timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            else:
                timestamp_str = "Unknown"
            
            description = anomaly.get("description", "No description available")
            
            data.append([anomaly_type.replace("_", " ").title(), severity, timestamp_str, description])
        
        # Sort by severity (high first) then timestamp
        data.sort(key=lambda x: (
            {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}.get(x[1], 4),
            x[2]
        ))
        
        return data[:15]  # Return top 15
    
    def get_top_talkers(self) -> List[List[Any]]:
        """
        Get data for top talkers table
        
        Returns:
            List of top talker data rows
        """
        # Group connections by source-destination pair
        connection_pairs = {}
        
        for conn in self.session.connections:
            src_ip = conn.get("src_ip", "Unknown")
            dst_ip = conn.get("dst_ip", "Unknown")
            protocol = conn.get("protocol", "Unknown")
            
            pair_key = (src_ip, dst_ip, protocol)
            
            if pair_key not in connection_pairs:
                connection_pairs[pair_key] = {
                    "packet_count": 0,
                    "byte_count": 0
                }
            
            connection_pairs[pair_key]["packet_count"] += conn.get("packet_count", 1)
            connection_pairs[pair_key]["byte_count"] += conn.get("byte_count", 0)
        
        # Convert to list of rows
        data = []
        
        for (src_ip, dst_ip, protocol), stats in connection_pairs.items():
            packet_count = stats["packet_count"]
            byte_count = self._format_bytes(stats["byte_count"])
            
            data.append([src_ip, dst_ip, protocol, str(packet_count), byte_count])
        
        # Sort by packet count
        data.sort(key=lambda x: int(x[3]), reverse=True)
        
        return data[:20]  # Return top 20
    
    def get_malicious_entities(self) -> List[List[Any]]:
        """
        Get data for malicious entities table
        
        Returns:
            List of malicious entity data rows
        """
        data = []
        
        for entity_id, entity in self.session.network_entities.items():
            if entity.threat_level != "malicious":
                continue
            
            # Get threat intelligence data if available
            risk_score = "Unknown"
            tags = []
            first_seen = "Unknown"
            
            if entity_id in self.session.threat_intelligence:
                ti_data = self.session.threat_intelligence[entity_id]
                risk_score = f"{ti_data.risk_score:.2f}"
                tags = ti_data.tags[:3]  # Limit to 3 tags
                
                # Try to find first seen timestamp
                for conn in self.session.connections:
                    if entity.type == "ip" and (
                        conn.get("src_ip") == entity.value or 
                        conn.get("dst_ip") == entity.value
                    ):
                        timestamp = conn.get("first_seen")
                        if timestamp:
                            first_seen = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                            break
            
            tags_str = ", ".join(tags) if tags else "None"
            
            data.append([
                entity.value, 
                entity.type.capitalize(), 
                risk_score, 
                tags_str, 
                first_seen
            ])
        
        # Sort by risk score
        data.sort(key=lambda x: 
            float(x[2]) if x[2] != "Unknown" else 0, 
            reverse=True
        )
        
        return data
    
    def get_high_severity_anomalies(self) -> List[List[Any]]:
        """
        Get data for high severity anomalies table
        
        Returns:
            List of high severity anomaly data rows
        """
        data = []
        
        for anomaly in self.session.anomalies:
            if anomaly.get("severity") != "high":
                continue
            
            anomaly_type = anomaly.get("type", "Unknown")
            subtype = anomaly.get("subtype", "")
            
            if subtype:
                anomaly_type = f"{anomaly_type} ({subtype})"
            
            description = anomaly.get("description", "No description available")
            
            timestamp = anomaly.get("timestamp")
            if timestamp:
                timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            else:
                timestamp_str = "Unknown"
            
            # Extract key details
            details = []
            
            if "source_ip" in anomaly:
                details.append(f"Source: {anomaly['source_ip']}")
            
            if "destination_ip" in anomaly:
                details.append(f"Dest: {anomaly['destination_ip']}")
            
            if "connection_count" in anomaly:
                details.append(f"Connections: {anomaly['connection_count']}")
            
            if "packet_count" in anomaly:
                details.append(f"Packets: {anomaly['packet_count']}")
            
            details_str = ", ".join(details)
            
            data.append([
                anomaly_type.replace("_", " ").title(),
                description,
                timestamp_str,
                details_str
            ])
        
        # Sort by timestamp
        data.sort(key=lambda x: x[2])
        
        return data
    
    def get_ai_observations(self) -> List[List[Any]]:
        """
        Get data for AI observations table
        
        Returns:
            List of AI observation data rows
        """
        data = []
        
        for insight in self.session.ai_insights:
            if "key_observations" in insight:
                for observation in insight["key_observations"]:
                    # Attempt to categorize observation
                    category = "General"
                    severity = "Info"
                    
                    # Simple heuristic categorization
                    lower_obs = observation.lower()
                    
                    # Check for security-related keywords
                    security_keywords = [
                        "attack", "malicious", "suspicious", "compromise", "threat",
                        "exploit", "vulnerability", "breach", "malware", "anomaly"
                    ]
                    
                    if any(keyword in lower_obs for keyword in security_keywords):
                        category = "Security"
                        
                        # Determine severity based on language
                        if any(kw in lower_obs for kw in ["critical", "severe", "high risk", "urgent"]):
                            severity = "High"
                        elif any(kw in lower_obs for kw in ["potential", "possible", "may", "could"]):
                            severity = "Medium"
                        else:
                            severity = "Low"
                    
                    # Check for traffic-related keywords
                    traffic_keywords = [
                        "traffic", "bandwidth", "flow", "connection", "packet", 
                        "protocol", "communication"
                    ]
                    
                    if any(keyword in lower_obs for keyword in traffic_keywords):
                        category = "Traffic"
                    
                    data.append([observation, category, severity])
            
            # Also check for security concerns
            if "security_concerns" in insight:
                for concern in insight["security_concerns"]:
                    severity = "Medium"
                    
                    # Determine severity based on language
                    lower_concern = concern.lower()
                    if any(kw in lower_concern for kw in ["critical", "severe", "high risk", "urgent"]):
                        severity = "High"
                    
                    data.append([concern, "Security", severity])
        
        # Sort by severity
        data.sort(key=lambda x: {"High": 0, "Medium": 1, "Low": 2, "Info": 3}.get(x[2], 4))
        
        return data
    
    def get_security_concerns(self) -> List[List[Any]]:
        """
        Get data for security concerns table
        
        Returns:
            List of security concern data rows
        """
        data = []
        
        # Extract concerns from AI insights
        for insight in self.session.ai_insights:
            if "security_concerns" in insight and "recommended_actions" in insight:
                # Match concerns with recommendations where possible
                concerns = insight["security_concerns"]
                recommendations = insight["recommended_actions"]
                
                for i, concern in enumerate(concerns):
                    impact = "Medium"  # Default impact
                    
                    # Determine impact based on language
                    lower_concern = concern.lower()
                    if any(kw in lower_concern for kw in ["critical", "severe", "high risk", "urgent"]):
                        impact = "High"
                    elif any(kw in lower_concern for kw in ["minor", "low", "minimal"]):
                        impact = "Low"
                    
                    # Try to find matching recommendation
                    recommendation = "No specific recommendation"
                    if i < len(recommendations):
                        recommendation = recommendations[i]
                    
                    data.append([concern, impact, recommendation])
            
            # If no structured concerns, extract from anomalies
            elif not data and self.session.anomalies:
                # Get high and medium severity anomalies
                severe_anomalies = [
                    a for a in self.session.anomalies 
                    if a.get("severity") in ["high", "medium"]
                ]
                
                for anomaly in severe_anomalies[:5]:  # Limit to 5
                    anomaly_type = anomaly.get("type", "").replace("_", " ").title()
                    description = anomaly.get("description", "")
                    
                    impact = "High" if anomaly.get("severity") == "high" else "Medium"
                    
                    # Generate generic recommendation
                    recommendation = f"Investigate {anomaly_type} activity"
                    
                    if "scan" in anomaly_type.lower():
                        recommendation = "Block scanning IP and review firewall rules"
                    elif "exfiltration" in anomaly_type.lower():
                        recommendation = "Investigate data transfer and block suspicious IPs"
                    elif "beaconing" in anomaly_type.lower():
                        recommendation = "Check for command and control communication"
                    
                    data.append([description, impact, recommendation])
        
        # Sort by impact
        data.sort(key=lambda x: {"High": 0, "Medium": 1, "Low": 2}.get(x[1], 3))
        
        return data
    
    def _run_ai_analysis(self):
        """Run AI analysis on session data"""
        # Get main window reference
        main_window = self.parent()
        if hasattr(main_window, "_run_ai_analysis"):
            main_window._run_ai_analysis()
    
    def _detect_anomalies(self):
        """Detect anomalies in session data"""
        # Get main window reference
        main_window = self.parent()
        if hasattr(main_window, "_detect_anomalies"):
            main_window._detect_anomalies()
    
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