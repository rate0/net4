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
        
        # Header section
        header_layout = QHBoxLayout()
        
        # Session information
        info_layout = QVBoxLayout()
        
        # Session title
        self.session_label = QLabel(self.session.name)
        font = QFont()
        font.setPointSize(16)
        font.setBold(True)
        self.session_label.setFont(font)
        info_layout.addWidget(self.session_label)
        
        # Session metadata
        self.metadata_label = QLabel()
        info_layout.addWidget(self.metadata_label)
        
        header_layout.addLayout(info_layout)
        header_layout.addStretch()
        
        # Action buttons
        action_layout = QVBoxLayout()
        
        self.analyze_button = QPushButton("Run AI Analysis")
        self.analyze_button.setIcon(QIcon("assets/icons/ai.png"))
        self.analyze_button.clicked.connect(self._run_ai_analysis)
        action_layout.addWidget(self.analyze_button)
        
        self.anomaly_button = QPushButton("Detect Anomalies")
        self.anomaly_button.setIcon(QIcon("assets/icons/anomaly.png"))
        self.anomaly_button.clicked.connect(self._detect_anomalies)
        action_layout.addWidget(self.anomaly_button)
        
        header_layout.addLayout(action_layout)
        layout.addLayout(header_layout)
        
        # Create tab widget for dashboard sections
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Summary tab
        self.summary_widget = QWidget()
        self.summary_layout = QVBoxLayout(self.summary_widget)
        self._init_summary_tab()
        self.tab_widget.addTab(self.summary_widget, "Summary")
        
        # Traffic tab
        self.traffic_widget = QWidget()
        self.traffic_layout = QVBoxLayout(self.traffic_widget)
        self._init_traffic_tab()
        self.tab_widget.addTab(self.traffic_widget, "Traffic")
        
        # Security tab
        self.security_widget = QWidget()
        self.security_layout = QVBoxLayout(self.security_widget)
        self._init_security_tab()
        self.tab_widget.addTab(self.security_widget, "Security")
        
        # AI Insights tab
        self.insights_widget = QWidget()
        self.insights_layout = QVBoxLayout(self.insights_widget)
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
        
        self.summary_content = QWidget()
        self.summary_content_layout = QVBoxLayout(self.summary_content)
        
        # Key metrics section
        metrics_group = QGroupBox("Key Metrics")
        metrics_layout = QGridLayout(metrics_group)
        
        # Create metric labels
        self.packet_count_label = QLabel("0")
        self.packet_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(14)
        font.setBold(True)
        self.packet_count_label.setFont(font)
        
        self.connection_count_label = QLabel("0")
        self.connection_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.connection_count_label.setFont(font)
        
        self.entity_count_label = QLabel("0")
        self.entity_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.entity_count_label.setFont(font)
        
        self.anomaly_count_label = QLabel("0")
        self.anomaly_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.anomaly_count_label.setFont(font)
        
        # Add metric labels to grid
        metrics_layout.addWidget(QLabel("Packets"), 0, 0, Qt.AlignmentFlag.AlignCenter)
        metrics_layout.addWidget(self.packet_count_label, 1, 0)
        
        metrics_layout.addWidget(QLabel("Connections"), 0, 1, Qt.AlignmentFlag.AlignCenter)
        metrics_layout.addWidget(self.connection_count_label, 1, 1)
        
        metrics_layout.addWidget(QLabel("Network Entities"), 0, 2, Qt.AlignmentFlag.AlignCenter)
        metrics_layout.addWidget(self.entity_count_label, 1, 2)
        
        metrics_layout.addWidget(QLabel("Anomalies"), 0, 3, Qt.AlignmentFlag.AlignCenter)
        metrics_layout.addWidget(self.anomaly_count_label, 1, 3)
        
        self.summary_content_layout.addWidget(metrics_group)
        
        # Files section
        files_group = QGroupBox("Analyzed Files")
        files_layout = QVBoxLayout(files_group)
        
        # Add files table
        self.files_table = DataTable(
            ["Filename", "Type", "Size", "Status", "Timestamp"],
            self.get_files_data()
        )
        files_layout.addWidget(self.files_table)
        
        self.summary_content_layout.addWidget(files_group)
        
        # Top entities section
        entities_group = QGroupBox("Top Entities")
        entities_layout = QGridLayout(entities_group)
        
        # Add pie charts for entity types
        self.ip_chart = PieChart("IP Addresses", height=180)
        entities_layout.addWidget(self.ip_chart, 0, 0)
        
        self.domain_chart = PieChart("Domains", height=180)
        entities_layout.addWidget(self.domain_chart, 0, 1)
        
        # Add table for suspicious entities
        self.suspicious_table = DataTable(
            ["Entity", "Type", "Threat Level", "Confidence"],
            self.get_suspicious_entities()
        )
        entities_layout.addWidget(self.suspicious_table, 1, 0, 1, 2)
        
        self.summary_content_layout.addWidget(entities_group)
        
        # Anomalies section
        anomalies_group = QGroupBox("Recent Anomalies")
        anomalies_layout = QVBoxLayout(anomalies_group)
        
        # Add anomalies table
        self.anomalies_table = DataTable(
            ["Type", "Severity", "Timestamp", "Description"],
            self.get_anomalies_data()
        )
        anomalies_layout.addWidget(self.anomalies_table)
        
        self.summary_content_layout.addWidget(anomalies_group)
        
        # Set scroll area widget
        self.summary_scroll.setWidget(self.summary_content)
        self.summary_layout.addWidget(self.summary_scroll)
    
    def _init_traffic_tab(self):
        """Initialize traffic tab"""
        # Add content to traffic tab
        self.traffic_scroll = QScrollArea()
        self.traffic_scroll.setWidgetResizable(True)
        self.traffic_scroll.setFrameShape(QFrame.Shape.NoFrame)
        
        self.traffic_content = QWidget()
        self.traffic_content_layout = QVBoxLayout(self.traffic_content)
        
        # Traffic over time
        time_group = QGroupBox("Traffic Over Time")
        time_layout = QVBoxLayout(time_group)
        
        self.time_chart = TimeSeriesChart("Packet Count Over Time", height=250)
        time_layout.addWidget(self.time_chart)
        
        self.traffic_content_layout.addWidget(time_group)
        
        # Protocol distribution
        protocol_group = QGroupBox("Protocol Distribution")
        protocol_layout = QHBoxLayout(protocol_group)
        
        self.protocol_chart = PieChart("Protocols", height=200)
        protocol_layout.addWidget(self.protocol_chart)
        
        self.port_chart = BarChart("Top Ports", height=200)
        protocol_layout.addWidget(self.port_chart)
        
        self.traffic_content_layout.addWidget(protocol_group)
        
        # Top talkers
        talkers_group = QGroupBox("Top Talkers")
        talkers_layout = QVBoxLayout(talkers_group)
        
        self.talkers_table = DataTable(
            ["Source IP", "Destination IP", "Protocol", "Packets", "Bytes"],
            self.get_top_talkers()
        )
        talkers_layout.addWidget(self.talkers_table)
        
        self.traffic_content_layout.addWidget(talkers_group)
        
        # Set scroll area widget
        self.traffic_scroll.setWidget(self.traffic_content)
        self.traffic_layout.addWidget(self.traffic_scroll)
    
    def _init_security_tab(self):
        """Initialize security tab"""
        # Add content to security tab
        self.security_scroll = QScrollArea()
        self.security_scroll.setWidgetResizable(True)
        self.security_scroll.setFrameShape(QFrame.Shape.NoFrame)
        
        self.security_content = QWidget()
        self.security_content_layout = QVBoxLayout(self.security_content)
        
        # Threat summary
        threat_group = QGroupBox("Threat Summary")
        threat_layout = QHBoxLayout(threat_group)
        
        # Threat severity counts
        self.threat_chart = PieChart("Threat Severity", height=200)
        threat_layout.addWidget(self.threat_chart)
        
        # Threat types
        self.threat_type_chart = BarChart("Threat Types", height=200)
        threat_layout.addWidget(self.threat_type_chart)
        
        self.security_content_layout.addWidget(threat_group)
        
        # Malicious entities
        malicious_group = QGroupBox("Malicious Entities")
        malicious_layout = QVBoxLayout(malicious_group)
        
        self.malicious_table = DataTable(
            ["Entity", "Type", "Risk Score", "Tags", "First Seen"],
            self.get_malicious_entities()
        )
        malicious_layout.addWidget(self.malicious_table)
        
        self.security_content_layout.addWidget(malicious_group)
        
        # High severity anomalies
        high_anomalies_group = QGroupBox("High Severity Anomalies")
        high_anomalies_layout = QVBoxLayout(high_anomalies_group)
        
        self.high_anomalies_table = DataTable(
            ["Type", "Description", "Timestamp", "Details"],
            self.get_high_severity_anomalies()
        )
        high_anomalies_layout.addWidget(self.high_anomalies_table)
        
        self.security_content_layout.addWidget(high_anomalies_group)
        
        # Set scroll area widget
        self.security_scroll.setWidget(self.security_content)
        self.security_layout.addWidget(self.security_scroll)
    
    def _init_insights_tab(self):
        """Initialize AI insights tab"""
        # Add content to insights tab
        self.insights_scroll = QScrollArea()
        self.insights_scroll.setWidgetResizable(True)
        self.insights_scroll.setFrameShape(QFrame.Shape.NoFrame)
        
        self.insights_content = QWidget()
        self.insights_content_layout = QVBoxLayout(self.insights_content)
        
        # AI analysis summary
        self.ai_summary_group = QGroupBox("AI Analysis Summary")
        self.ai_summary_layout = QVBoxLayout(self.ai_summary_group)
        
        self.ai_summary_text = QTextEdit()
        self.ai_summary_text.setReadOnly(True)
        self.ai_summary_layout.addWidget(self.ai_summary_text)
        
        self.insights_content_layout.addWidget(self.ai_summary_group)
        
        # Key observations
        self.observations_group = QGroupBox("Key Observations")
        self.observations_layout = QVBoxLayout(self.observations_group)
        
        self.observations_table = DataTable(
            ["Observation", "Type", "Severity"],
            self.get_ai_observations()
        )
        self.observations_layout.addWidget(self.observations_table)
        
        self.insights_content_layout.addWidget(self.observations_group)
        
        # Security concerns
        self.concerns_group = QGroupBox("Security Concerns")
        self.concerns_layout = QVBoxLayout(self.concerns_group)
        
        self.concerns_table = DataTable(
            ["Concern", "Impact", "Recommendation"],
            self.get_security_concerns()
        )
        self.concerns_layout.addWidget(self.concerns_table)
        
        self.insights_content_layout.addWidget(self.concerns_group)
        
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
        
        for entity in self.session.network_entities.values():
            # Get the capitalized threat level
            threat_level = entity.threat_level.capitalize()
            # Make sure the category exists before incrementing
            if threat_level in threat_levels:
                threat_levels[threat_level] += 1
            else:
                # For any unexpected threat levels, count as Unknown
                threat_levels["Unknown"] += 1
        
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
        
        threat_type_data = [
            (type_name, count) for type_name, count in threat_types.items() if count > 0
        ]
        threat_type_data.sort(key=lambda x: x[1], reverse=True)
        self.threat_type_chart.update_data(threat_type_data)
    
    def _update_ai_insights(self):
        """Update AI insights tab with current data"""
        # Check if we have any AI insights
        if not self.session.ai_insights:
            self.ai_summary_text.setText("No AI analysis has been run yet. Click 'Run AI Analysis' to analyze this session.")
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
            # Format summary text
            summary_text = ""
            
            if "summary" in overview_insight:
                summary_text += f"<h3>Summary</h3>\n<p>{overview_insight['summary']}</p>\n\n"
            
            if "key_observations" in overview_insight:
                summary_text += "<h3>Key Observations</h3>\n<ul>\n"
                for observation in overview_insight["key_observations"]:
                    summary_text += f"<li>{observation}</li>\n"
                summary_text += "</ul>\n\n"
            
            if "protocol_analysis" in overview_insight:
                summary_text += "<h3>Protocol Analysis</h3>\n<ul>\n"
                for protocol, analysis in overview_insight["protocol_analysis"].items():
                    summary_text += f"<li><b>{protocol}:</b> {analysis}</li>\n"
                summary_text += "</ul>\n\n"
            
            if "security_concerns" in overview_insight:
                summary_text += "<h3>Security Concerns</h3>\n<ul>\n"
                for concern in overview_insight["security_concerns"]:
                    summary_text += f"<li>{concern}</li>\n"
                summary_text += "</ul>\n\n"
            
            if "recommended_actions" in overview_insight:
                summary_text += "<h3>Recommended Actions</h3>\n<ul>\n"
                for action in overview_insight["recommended_actions"]:
                    summary_text += f"<li>{action}</li>\n"
                summary_text += "</ul>\n\n"
            
            # Add timestamp
            if "timestamp" in overview_insight:
                try:
                    timestamp = datetime.fromisoformat(overview_insight["timestamp"])
                    summary_text += f"<p><i>Analysis generated: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</i></p>"
                except:
                    pass
            
            self.ai_summary_text.setHtml(summary_text)
        else:
            self.ai_summary_text.setText("No overview analysis available. Run a new analysis to generate insights.")
    
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