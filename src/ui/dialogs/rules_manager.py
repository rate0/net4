import os
from typing import Dict, List, Any, Optional

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget, QLabel, 
    QPushButton, QTableWidget, QTableWidgetItem, QComboBox, QLineEdit,
    QTextEdit, QFormLayout, QCheckBox, QMessageBox, QHeaderView, QMenu,
    QFileDialog, QGroupBox, QSpinBox, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal
from PyQt6.QtGui import QIcon, QColor, QAction

import yaml
import json

from ...core.rules.rule_engine import Rule, RuleEngine
from ...core.rules.suricata_converter import SuricataRuleConverter
from ...utils.logger import Logger


class RuleEditorDialog(QDialog):
    """Dialog for editing a detection rule"""
    
    def __init__(self, rule: Optional[Rule] = None, parent=None):
        """
        Initialize rule editor dialog
        
        Args:
            rule: Rule to edit, or None for a new rule
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.logger = Logger().get_logger()
        self.rule = rule
        self.is_new = rule is None
        
        self._init_ui()
        
        if rule:
            self._load_rule(rule)
        else:
            self._setup_new_rule()
    
    def _init_ui(self):
        """Initialize user interface"""
        # Set window properties
        self.setWindowTitle("Rule Editor")
        self.resize(800, 600)
        
        # Main layout
        layout = QVBoxLayout(self)
        
        # Form layout for rule basics
        form_layout = QFormLayout()
        
        # Rule ID
        self.id_input = QLineEdit()
        self.id_input.setPlaceholderText("Format: custom:category:name")
        form_layout.addRow("Rule ID:", self.id_input)
        
        # Rule name
        self.name_input = QLineEdit()
        form_layout.addRow("Name:", self.name_input)
        
        # Description
        self.description_input = QTextEdit()
        self.description_input.setMaximumHeight(60)
        form_layout.addRow("Description:", self.description_input)
        
        # Severity
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["low", "medium", "high"])
        form_layout.addRow("Severity:", self.severity_combo)
        
        # Category
        self.category_input = QLineEdit()
        form_layout.addRow("Category:", self.category_input)
        
        # Enabled
        self.enabled_checkbox = QCheckBox("Enabled")
        self.enabled_checkbox.setChecked(True)
        form_layout.addRow("", self.enabled_checkbox)
        
        layout.addLayout(form_layout)
        
        # Tab widget for conditions and actions
        tab_widget = QTabWidget()
        
        # Conditions tab
        conditions_widget = QWidget()
        conditions_layout = QVBoxLayout(conditions_widget)
        
        self.conditions_editor = QTextEdit()
        self.conditions_editor.setPlaceholderText("# Define conditions in YAML format\n\nprotocol: \"TCP\"\ndst_port: 22\nconnection_count: {\"gt\": 5}")
        conditions_layout.addWidget(self.conditions_editor)
        
        tab_widget.addTab(conditions_widget, "Conditions")
        
        # Actions tab
        actions_widget = QWidget()
        actions_layout = QVBoxLayout(actions_widget)
        
        self.actions_editor = QTextEdit()
        self.actions_editor.setPlaceholderText("# Define actions in YAML format\n\nset_threat_level: \"suspicious\"\nadd_entity_tag: [\"brute_force\", \"ssh\"]\nadd_anomaly:\n  type: \"attack\"\n  subtype: \"brute_force\"")
        actions_layout.addWidget(self.actions_editor)
        
        tab_widget.addTab(actions_widget, "Actions")
        
        # Tags tab
        tags_widget = QWidget()
        tags_layout = QVBoxLayout(tags_widget)
        
        self.tags_editor = QTextEdit()
        self.tags_editor.setPlaceholderText("# Enter tags, one per line\nssh\nbrute_force\nauthentication")
        tags_layout.addWidget(self.tags_editor)
        
        tab_widget.addTab(tags_widget, "Tags")
        
        layout.addWidget(tab_widget)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        # Help button
        help_button = QPushButton("Help")
        help_button.clicked.connect(self._show_help)
        button_layout.addWidget(help_button)
        
        button_layout.addStretch()
        
        # Test button
        test_button = QPushButton("Validate")
        test_button.clicked.connect(self._validate_rule)
        button_layout.addWidget(test_button)
        
        # Cancel button
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        # Save button
        self.save_button = QPushButton("Save" if self.is_new else "Update")
        self.save_button.clicked.connect(self._save_rule)
        button_layout.addWidget(self.save_button)
        
        layout.addLayout(button_layout)
    
    def _setup_new_rule(self):
        """Setup UI for new rule"""
        # Generate example rule ID
        self.id_input.setText("custom:category:name")
        self.id_input.selectAll()
        
        # Set example conditions
        self.conditions_editor.setPlainText(
            "protocol: \"TCP\"\n"
            "dst_port: 80\n"
            "connection_count: {\"gt\": 10}\n"
        )
        
        # Set example actions
        self.actions_editor.setPlainText(
            "set_threat_level: \"suspicious\"\n"
            "add_entity_tag: [\"scanning\"]\n"
            "add_anomaly:\n"
            "  type: \"reconnaissance\"\n"
            "  subtype: \"scanning\"\n"
        )
        
        # Set example tags
        self.tags_editor.setPlainText("scanning\nhttp\nreconnaissance")
    
    def _load_rule(self, rule: Rule):
        """
        Load rule data into UI
        
        Args:
            rule: Rule to load
        """
        # Set rule ID
        self.id_input.setText(rule.id)
        self.id_input.setReadOnly(True)  # Don't allow editing ID of existing rule
        
        # Set basic info
        self.name_input.setText(rule.name)
        self.description_input.setText(rule.description)
        self.severity_combo.setCurrentText(rule.severity)
        self.category_input.setText(rule.category)
        self.enabled_checkbox.setChecked(rule.enabled)
        
        # Set conditions
        self.conditions_editor.setPlainText(yaml.dump(rule.conditions, default_flow_style=False))
        
        # Set actions
        self.actions_editor.setPlainText(yaml.dump(rule.actions, default_flow_style=False))
        
        # Set tags
        self.tags_editor.setPlainText("\n".join(rule.tags))
    
    def _save_rule(self):
        """Save the rule"""
        try:
            # Get rule ID
            rule_id = self.id_input.text().strip()
            if not rule_id:
                QMessageBox.warning(self, "Validation Error", "Rule ID cannot be empty")
                return
            
            # Get basic info
            name = self.name_input.text().strip()
            if not name:
                QMessageBox.warning(self, "Validation Error", "Rule name cannot be empty")
                return
            
            description = self.description_input.toPlainText().strip()
            severity = self.severity_combo.currentText()
            category = self.category_input.text().strip()
            enabled = self.enabled_checkbox.isChecked()
            
            # Parse conditions
            try:
                conditions_text = self.conditions_editor.toPlainText().strip()
                conditions = yaml.safe_load(conditions_text) if conditions_text else {}
            except Exception as e:
                QMessageBox.warning(self, "YAML Error", f"Error in conditions YAML: {str(e)}")
                return
            
            # Parse actions
            try:
                actions_text = self.actions_editor.toPlainText().strip()
                actions = yaml.safe_load(actions_text) if actions_text else {}
            except Exception as e:
                QMessageBox.warning(self, "YAML Error", f"Error in actions YAML: {str(e)}")
                return
            
            # Parse tags
            tags_text = self.tags_editor.toPlainText().strip()
            tags = [tag.strip() for tag in tags_text.split("\n") if tag.strip()]
            
            # Create or update rule
            if self.is_new:
                rule = Rule(
                    rule_id=rule_id,
                    name=name,
                    description=description,
                    severity=severity,
                    conditions=conditions,
                    actions=actions,
                    enabled=enabled,
                    category=category,
                    tags=tags
                )
            else:
                # Update existing rule
                self.rule.name = name
                self.rule.description = description
                self.rule.severity = severity
                self.rule.conditions = conditions
                self.rule.actions = actions
                self.rule.enabled = enabled
                self.rule.category = category
                self.rule.tags = tags
                
                # Recompile patterns
                self.rule._compile_patterns()
                
                rule = self.rule
            
            # Store rule in dialog
            self.rule = rule
            
            # Accept dialog
            self.accept()
            
        except Exception as e:
            self.logger.error(f"Error saving rule: {str(e)}")
            QMessageBox.critical(self, "Error", f"Error saving rule: {str(e)}")
    
    def _validate_rule(self):
        """Validate the rule syntax"""
        try:
            # Get rule ID
            rule_id = self.id_input.text().strip()
            if not rule_id:
                QMessageBox.warning(self, "Validation Error", "Rule ID cannot be empty")
                return
            
            # Get basic info
            name = self.name_input.text().strip()
            if not name:
                QMessageBox.warning(self, "Validation Error", "Rule name cannot be empty")
                return
            
            description = self.description_input.toPlainText().strip()
            severity = self.severity_combo.currentText()
            category = self.category_input.text().strip()
            enabled = self.enabled_checkbox.isChecked()
            
            # Parse conditions
            try:
                conditions_text = self.conditions_editor.toPlainText().strip()
                conditions = yaml.safe_load(conditions_text) if conditions_text else {}
            except Exception as e:
                QMessageBox.warning(self, "YAML Error", f"Error in conditions YAML: {str(e)}")
                return
            
            # Parse actions
            try:
                actions_text = self.actions_editor.toPlainText().strip()
                actions = yaml.safe_load(actions_text) if actions_text else {}
            except Exception as e:
                QMessageBox.warning(self, "YAML Error", f"Error in actions YAML: {str(e)}")
                return
            
            # Parse tags
            tags_text = self.tags_editor.toPlainText().strip()
            tags = [tag.strip() for tag in tags_text.split("\n") if tag.strip()]
            
            # Validate conditions
            if not isinstance(conditions, dict):
                QMessageBox.warning(self, "Validation Error", "Conditions must be a dictionary/object")
                return
            
            # Validate actions
            if not isinstance(actions, dict):
                QMessageBox.warning(self, "Validation Error", "Actions must be a dictionary/object")
                return
            
            # Show success message
            QMessageBox.information(self, "Validation Successful", "Rule syntax is valid!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Validation error: {str(e)}")
    
    def _show_help(self):
        """Show help dialog"""
        # Create a more comprehensive help dialog
        help_dialog = QDialog(self)
        help_dialog.setWindowTitle("Rule Editor Help")
        help_dialog.resize(800, 600)
        
        layout = QVBoxLayout(help_dialog)
        
        # Create a tab widget for different help sections
        tab_widget = QTabWidget()
        
        # Basic Rules tab
        basics_widget = QWidget()
        basics_layout = QVBoxLayout(basics_widget)
        basics_text = QTextEdit()
        basics_text.setReadOnly(True)
        basics_text.setHtml(
            "<h2>Rule Basics</h2>"
            "<p>Rules are powerful tools to detect patterns in network traffic and take actions when matches are found.</p>"
            
            "<h3>Rule Components</h3>"
            "<ul>"
            "<li><b>Rule ID</b>: Unique identifier, typically in format: <code>custom:category:name</code></li>"
            "<li><b>Name</b>: Short, descriptive name that clearly indicates the rule's purpose</li>"
            "<li><b>Description</b>: Detailed explanation of what the rule detects and why it matters</li>"
            "<li><b>Severity</b>: Impact level - low, medium, or high - based on potential security impact</li>"
            "<li><b>Category</b>: Classification like 'attack', 'reconnaissance', 'command_and_control', etc.</li>"
            "<li><b>Conditions</b>: Criteria that must be met for the rule to trigger (YAML format)</li>"
            "<li><b>Actions</b>: What happens when the rule matches (YAML format)</li>"
            "<li><b>Tags</b>: Keywords for organization and filtering</li>"
            "</ul>"
            
            "<h3>Best Practices</h3>"
            "<ul>"
            "<li><b>Be specific</b>: Create focused rules that target specific behaviors</li>"
            "<li><b>Avoid false positives</b>: Test rules thoroughly before deployment</li>"
            "<li><b>Use descriptive names</b>: Rule names should clearly indicate the detected behavior</li>"
            "<li><b>Document thoroughly</b>: Add detailed descriptions including references if applicable</li>"
            "<li><b>Use appropriate severity</b>: Reserve 'high' for truly critical issues</li>"
            "</ul>"
            
            "<h3>Common Rule Categories</h3>"
            "<table border='1' cellpadding='4' cellspacing='0' style='border-collapse: collapse;'>"
            "<tr><th>Category</th><th>Description</th><th>Examples</th></tr>"
            "<tr><td>attack</td><td>Active exploitation attempts</td><td>SQL injection, buffer overflow</td></tr>"
            "<tr><td>reconnaissance</td><td>Information gathering</td><td>Port scanning, OS fingerprinting</td></tr>"
            "<tr><td>malware</td><td>Malicious software</td><td>C2 traffic, data exfiltration</td></tr>"
            "<tr><td>policy</td><td>Policy violations</td><td>Forbidden protocols, unauthorized access</td></tr>"
            "<tr><td>anomaly</td><td>Unusual behavior</td><td>Odd connection patterns, unusual data volumes</td></tr>"
            "</table>"
        )
        basics_layout.addWidget(basics_text)
        tab_widget.addTab(basics_widget, "Rule Basics")
        
        # Conditions tab
        conditions_widget = QWidget()
        conditions_layout = QVBoxLayout(conditions_widget)
        conditions_text = QTextEdit()
        conditions_text.setReadOnly(True)
        conditions_text.setHtml(
            "<h2>Conditions Format</h2>"
            "<p>Define conditions that must be met for a rule to trigger. Conditions are specified in YAML format.</p>"
            
            "<h3>Simple Field Matching</h3>"
            "<pre>"
            "# Simple equality matching\n"
            "protocol: \"TCP\"          # Match TCP protocol\n"
            "dst_port: 22              # Match destination port 22\n"
            "src_ip: \"192.168.1.100\"   # Match source IP exactly\n"
            "</pre>"
            
            "<h3>Numeric Comparisons</h3>"
            "<pre>"
            "# Compare numeric values\n"
            "connection_count: {\"gt\": 5}     # Greater than 5\n"
            "packet_size: {\"lt\": 100}        # Less than 100 bytes\n"
            "connection_rate: {\"gte\": 10}    # Greater than or equal to 10\n"
            "error_count: {\"lte\": 3}         # Less than or equal to 3\n"
            "port_number: {\"eq\": 443}        # Equal to 443\n"
            "flag_count: {\"neq\": 0}          # Not equal to 0\n"
            "</pre>"
            
            "<h3>Text Pattern Matching</h3>"
            "<pre>"
            "# Match text patterns with regex\n"
            "\"http.user_agent\": {\"regex\": \"(curl|wget)\"}\n"
            "\"dns.query\": {\"regex\": \"\\.com$\"}\n"
            "\"url.path\": {\"regex\": \"admin|login|password\"}\n"
            "</pre>"
            
            "<h3>List Operations</h3>"
            "<pre>"
            "# Check if value is in a list\n"
            "dst_port: {\"in\": [80, 443, 8080]}\n"
            "protocol: {\"in\": [\"HTTP\", \"HTTPS\"]}\n"
            "\n"
            "# Check if value is NOT in a list\n"
            "src_port: {\"not_in\": [1024, 1025]}\n"
            "domain: {\"not_in\": [\"google.com\", \"microsoft.com\"]}\n"
            "</pre>"
            
            "<h3>IP Address Operations</h3>"
            "<pre>"
            "# Check if IP is in a subnet\n"
            "src_ip: {\"ip_in_subnet\": \"192.168.1.0/24\"}\n"
            "dst_ip: {\"ip_in_subnet\": \"10.0.0.0/8\"}\n"
            "\n"
            "# Check if IP is in a range\n"
            "src_ip: {\"ip_in_range\": [\"10.0.0.1\", \"10.0.0.100\"]}\n"
            "dst_ip: {\"ip_in_range\": [\"172.16.0.1\", \"172.16.0.254\"]}\n"
            "</pre>"
            
            "<h3>Combining Conditions</h3>"
            "<p>Multiple conditions are combined with logical AND (all must match).</p>"
            "<pre>"
            "# All of these conditions must match\n"
            "protocol: \"TCP\"\n"
            "dst_port: 80\n"
            "src_ip: {\"ip_in_subnet\": \"192.168.1.0/24\"}\n"
            "</pre>"
            
            "<h3>Available Fields</h3>"
            "<p>Common fields that can be used in conditions:</p>"
            "<ul>"
            "<li><b>protocol</b>: Network protocol (TCP, UDP, ICMP, HTTP, etc.)</li>"
            "<li><b>src_ip</b>: Source IP address</li>"
            "<li><b>dst_ip</b>: Destination IP address</li>"
            "<li><b>src_port</b>: Source port number</li>"
            "<li><b>dst_port</b>: Destination port number</li>"
            "<li><b>packet_size</b>: Size of packet in bytes</li>"
            "<li><b>connection_count</b>: Number of connections</li>"
            "<li><b>http.method</b>: HTTP method (GET, POST, etc.)</li>"
            "<li><b>http.uri</b>: HTTP URI requested</li>"
            "<li><b>http.user_agent</b>: HTTP User-Agent header</li>"
            "<li><b>dns.query</b>: DNS query name</li>"
            "<li><b>dns.response</b>: DNS response data</li>"
            "</ul>"
        )
        conditions_layout.addWidget(conditions_text)
        tab_widget.addTab(conditions_widget, "Conditions")
        
        # Actions tab
        actions_widget = QWidget()
        actions_layout = QVBoxLayout(actions_widget)
        actions_text = QTextEdit()
        actions_text.setReadOnly(True)
        actions_text.setHtml(
            "<h2>Actions Format</h2>"
            "<p>Define what happens when a rule matches. Actions are specified in YAML format.</p>"
            
            "<h3>Working with Threat Levels</h3>"
            "<pre>"
            "# Set threat level for matched entities\n"
            "set_threat_level: \"suspicious\"  # Other options: \"malicious\", \"safe\"\n"
            "\n"
            "# Set threat level with confidence\n"
            "set_threat_level:\n"
            "  level: \"malicious\"\n"
            "  confidence: 0.8  # 0.0 to 1.0\n"
            "</pre>"
            
            "<h3>Adding Tags</h3>"
            "<pre>"
            "# Add tags to matched entities\n"
            "add_entity_tag: \"brute_force\"  # Add a single tag\n"
            "\n"
            "# Add multiple tags\n"
            "add_entity_tag: [\"brute_force\", \"ssh\", \"authentication\"]\n"
            "</pre>"
            
            "<h3>Creating Anomalies</h3>"
            "<pre>"
            "# Add a simple anomaly\n"
            "add_anomaly: \"Suspicious connection detected\"\n"
            "\n"
            "# Add a detailed anomaly\n"
            "add_anomaly:\n"
            "  type: \"attack\"\n"
            "  subtype: \"brute_force\"\n"
            "  description: \"Multiple failed SSH login attempts detected\"\n"
            "  severity: \"medium\"  # low, medium, high\n"
            "  source_ip: \"{{src_ip}}\"  # Use values from match\n"
            "  destination_ip: \"{{dst_ip}}\"\n"
            "  timestamp: \"{{timestamp}}\"\n"
            "</pre>"
            
            "<h3>Alert Generation</h3>"
            "<pre>"
            "# Generate an alert\n"
            "generate_alert: \"SSH brute force attack detected\"\n"
            "\n"
            "# Generate a detailed alert\n"
            "generate_alert:\n"
            "  title: \"SSH Brute Force Attack\"\n"
            "  message: \"Multiple failed SSH login attempts from {{src_ip}}\"\n"
            "  severity: \"high\"\n"
            "  recommended_action: \"Block source IP and investigate\"\n"
            "</pre>"
            
            "<h3>Using Variables</h3>"
            "<p>You can reference matched values using {{variable_name}} syntax:</p>"
            "<pre>"
            "# Reference matched values\n"
            "add_anomaly:\n"
            "  description: \"Suspicious traffic from {{src_ip}} to {{dst_ip}}:{{dst_port}}\"\n"
            "  source_ip: \"{{src_ip}}\"\n"
            "</pre>"
            
            "<h3>Multiple Actions</h3>"
            "<p>You can combine multiple actions in a single rule:</p>"
            "<pre>"
            "# Example with multiple actions\n"
            "set_threat_level: \"malicious\"\n"
            "add_entity_tag: [\"brute_force\", \"attack\"]\n"
            "add_anomaly:\n"
            "  type: \"attack\"\n"
            "  description: \"Brute force attack detected\"\n"
            "generate_alert: \"Brute force attack detected from {{src_ip}}\"\n"
            "</pre>"
        )
        actions_layout.addWidget(actions_text)
        tab_widget.addTab(actions_widget, "Actions")
        
        # Examples tab
        examples_widget = QWidget()
        examples_layout = QVBoxLayout(examples_widget)
        examples_text = QTextEdit()
        examples_text.setReadOnly(True)
        examples_text.setHtml(
            "<h2>Rule Examples</h2>"
            "<p>Here are complete examples of common detection rules:</p>"
            
            "<h3>1. SSH Brute Force Detection</h3>"
            "<pre>"
            "# Rule ID: custom:attack:ssh_brute_force\n"
            "# Name: SSH Brute Force Detection\n"
            "# Description: Detects multiple SSH connection attempts\n"
            "# Severity: medium\n"
            "# Category: attack\n"
            "\n"
            "# Conditions\n"
            "protocol: \"TCP\"\n"
            "dst_port: 22\n"
            "connection_count: {\"gt\": 5}\n"
            "time_window: {\"lt\": 60}  # Connections within 60 seconds\n"
            "\n"
            "# Actions\n"
            "set_threat_level: \"suspicious\"\n"
            "add_entity_tag: [\"brute_force\", \"ssh\"]\n"
            "add_anomaly:\n"
            "  type: \"attack\"\n"
            "  subtype: \"brute_force\"\n"
            "  description: \"Multiple SSH connection attempts detected\"\n"
            "  severity: \"medium\"\n"
            "\n"
            "# Tags\n"
            "# ssh\n"
            "# brute_force\n"
            "# attack\n"
            "</pre>"
            
            "<h3>2. Suspicious DNS Detection</h3>"
            "<pre>"
            "# Rule ID: custom:malware:suspicious_dns\n"
            "# Name: Suspicious DNS Query Pattern\n"
            "# Description: Detects DNS queries with unusual patterns that could indicate malware C2\n"
            "# Severity: medium\n"
            "# Category: malware\n"
            "\n"
            "# Conditions\n"
            "protocol: \"DNS\"\n"
            "\"dns.query\": {\"regex\": \"[a-zA-Z0-9]{25,}\\.(com|net|org)\"}\n"
            "\n"
            "# Actions\n"
            "set_threat_level: \"suspicious\"\n"
            "add_entity_tag: [\"suspicious_dns\", \"possible_c2\"]\n"
            "add_anomaly:\n"
            "  type: \"malware\"\n"
            "  subtype: \"command_and_control\"\n"
            "  description: \"Suspicious DNS query pattern detected\"\n"
            "  severity: \"medium\"\n"
            "\n"
            "# Tags\n"
            "# dns\n"
            "# malware\n"
            "# c2\n"
            "</pre>"
            
            "<h3>3. HTTP Scanner Detection</h3>"
            "<pre>"
            "# Rule ID: custom:reconnaissance:http_scanner\n"
            "# Name: Web Scanner Detection\n"
            "# Description: Detects automated web scanners by user agent\n"
            "# Severity: low\n"
            "# Category: reconnaissance\n"
            "\n"
            "# Conditions\n"
            "protocol: \"HTTP\"\n"
            "\"http.user_agent\": {\"regex\": \"(nmap|nikto|gobuster|dirb|dirbuster|wfuzz|ZAP|burp|scanner)\"}\n"
            "\n"
            "# Actions\n"
            "set_threat_level: \"suspicious\"\n"
            "add_entity_tag: [\"scanner\", \"reconnaissance\"]\n"
            "add_anomaly:\n"
            "  type: \"reconnaissance\"\n"
            "  subtype: \"web_scanning\"\n"
            "  description: \"Web scanning tool detected\"\n"
            "  severity: \"low\"\n"
            "\n"
            "# Tags\n"
            "# scanner\n"
            "# reconnaissance\n"
            "# web\n"
            "</pre>"
            
            "<h3>4. Data Exfiltration Detection</h3>"
            "<pre>"
            "# Rule ID: custom:data_leak:large_upload\n"
            "# Name: Large Data Upload\n"
            "# Description: Detects unusually large uploads that might indicate data exfiltration\n"
            "# Severity: high\n"
            "# Category: data_leak\n"
            "\n"
            "# Conditions\n"
            "protocol: {\"in\": [\"HTTP\", \"HTTPS\"]}\n"
            "\"http.method\": {\"in\": [\"POST\", \"PUT\"]}\n"
            "upload_size: {\"gt\": 10000000}  # More than 10MB\n"
            "dst_ip: {\"not_in_subnet\": \"192.168.0.0/16\"}  # Not internal network\n"
            "\n"
            "# Actions\n"
            "set_threat_level: \"malicious\"\n"
            "add_entity_tag: [\"data_exfiltration\", \"large_upload\"]\n"
            "add_anomaly:\n"
            "  type: \"data_leak\"\n"
            "  subtype: \"large_upload\"\n"
            "  description: \"Unusually large data upload to external server\"\n"
            "  severity: \"high\"\n"
            "generate_alert: \"Possible data exfiltration detected: {{src_ip}} uploaded {{upload_size}} bytes to {{dst_ip}}\"\n"
            "\n"
            "# Tags\n"
            "# data_leak\n"
            "# exfiltration\n"
            "# http\n"
            "</pre>"
        )
        examples_layout.addWidget(examples_text)
        tab_widget.addTab(examples_widget, "Examples")
        
        # Suricata tab
        suricata_widget = QWidget()
        suricata_layout = QVBoxLayout(suricata_widget)
        suricata_text = QTextEdit()
        suricata_text.setReadOnly(True)
        suricata_text.setHtml(
            "<h2>Suricata Rules</h2>"
            "<p>Net4 supports importing Suricata rules for enhanced detection capabilities.</p>"
            
            "<h3>Suricata Rule Format</h3>"
            "<p>Suricata rules use a specific format:</p>"
            "<pre style='background-color: #f8f9fa; padding: 8px;'>"
            "action protocol src_ip src_port direction dst_ip dst_port (options)\n"
            "</pre>"
            "<p>For example:</p>"
            "<pre style='background-color: #f8f9fa; padding: 8px;'>"
            "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:\"ET POLICY curl User-Agent\"; flow:established,to_server; content:\"User-Agent|3A| curl/\"; classtype:policy-violation; sid:2013028; rev:2;)\n"
            "</pre>"
            
            "<h3>Importing Suricata Rules</h3>"
            "<p>To import Suricata rules:</p>"
            "<ol>"
            "<li>Go to Detection > Import Rules</li>"
            "<li>Select 'Import Suricata Rules'</li>"
            "<li>Choose a .rules file</li>"
            "</ol>"
            "<p>The rules will be automatically converted to Net4 format.</p>"
            
            "<h3>Supported Features</h3>"
            "<p>The following Suricata rule features are supported:</p>"
            "<ul>"
            "<li>Basic rule header (protocol, IP, port)</li>"
            "<li>content and pcre matching</li>"
            "<li>flow options</li>"
            "<li>HTTP content modifiers</li>"
            "<li>Threshold settings</li>"
            "<li>Common rule options (msg, classtype, reference, etc.)</li>"
            "</ul>"
            
            "<h3>Conversion Process</h3>"
            "<p>During conversion:</p>"
            "<ul>"
            "<li>Suricata rule is parsed into components</li>"
            "<li>Rule ID is created as 'suricata:classtype:sid'</li>"
            "<li>Conditions are converted to Net4 format</li>"
            "<li>Actions are generated based on Suricata rule action</li>"
            "<li>Tags are created from classtype and keywords</li>"
            "</ul>"
            
            "<h3>Example Conversion</h3>"
            "<p>Suricata rule:</p>"
            "<pre style='background-color: #f8f9fa; padding: 8px;'>"
            "alert tcp any any -> $HOME_NET 22 (msg:\"INDICATOR-SCAN SSH brute force login attempt\"; flow:to_server; threshold: type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:2001219; rev:4;)\n"
            "</pre>"
            "<p>Converted to Net4 rule:</p>"
            "<pre style='background-color: #f8f9fa; padding: 8px;'>"
            "# ID: suricata:attempted-admin:2001219\n"
            "# Name: INDICATOR-SCAN SSH brute force login attempt\n"
            "# Category: attempted-admin\n"
            "\n"
            "# Conditions\n"
            "protocol: \"TCP\"\n"
            "dst_port: 22\n"
            "flow: \"to_server\"\n"
            "connection_count: {\"gt\": 5}\n"
            "time_window: {\"lt\": 60}\n"
            "\n"
            "# Actions\n"
            "set_threat_level: \"suspicious\"\n"
            "add_entity_tag: [\"ssh\", \"brute_force\", \"attempted-admin\"]\n"
            "add_anomaly:\n"
            "  type: \"attack\"\n"
            "  description: \"INDICATOR-SCAN SSH brute force login attempt\"\n"
            "  severity: \"medium\"\n"
            "</pre>"
        )
        suricata_layout.addWidget(suricata_text)
        tab_widget.addTab(suricata_widget, "Suricata Rules")
        
        layout.addWidget(tab_widget)
        
        # Bottom buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(help_dialog.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
        help_dialog.exec()


class RuleManagerDialog(QDialog):
    """Dialog for managing detection rules"""
    
    def __init__(self, parent=None):
        """
        Initialize rule manager dialog
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.logger = Logger().get_logger()
        self.rule_engine = RuleEngine()
        self.rule_engine.load_rules()
        
        self._init_ui()
        self._load_rules()
    
    def _init_ui(self):
        """Initialize user interface"""
        # Set window properties
        self.setWindowTitle("Rule Manager")
        self.resize(1000, 700)
        
        # Main layout
        layout = QVBoxLayout(self)
        
        # Actions toolbar
        toolbar_layout = QHBoxLayout()
        
        # Category filter
        self.category_filter = QComboBox()
        self.category_filter.addItem("All Categories")
        self.category_filter.currentIndexChanged.connect(self._filter_rules)
        toolbar_layout.addWidget(QLabel("Category:"))
        toolbar_layout.addWidget(self.category_filter)
        
        # Search
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search rules...")
        self.search_input.textChanged.connect(self._filter_rules)
        toolbar_layout.addWidget(QLabel("Search:"))
        toolbar_layout.addWidget(self.search_input)
        
        # Only show enabled rules
        self.enabled_only_checkbox = QCheckBox("Enabled Only")
        self.enabled_only_checkbox.stateChanged.connect(self._filter_rules)
        toolbar_layout.addWidget(self.enabled_only_checkbox)
        
        toolbar_layout.addStretch()
        
        # Add button
        add_button = QPushButton("New Rule")
        add_button.clicked.connect(self._add_rule)
        toolbar_layout.addWidget(add_button)
        
        # Import menu button with dropdown
        import_button = QPushButton("Import")
        import_menu = QMenu(self)
        
        import_yaml_action = QAction("Import YAML/JSON Rules", self)
        import_yaml_action.triggered.connect(self._import_rules)
        import_menu.addAction(import_yaml_action)
        
        import_suricata_action = QAction("Import Suricata Rules", self)
        import_suricata_action.triggered.connect(self._import_suricata_rules)
        import_menu.addAction(import_suricata_action)
        
        import_button.setMenu(import_menu)
        toolbar_layout.addWidget(import_button)
        
        layout.addLayout(toolbar_layout)
        
        # Rules table
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(7)
        self.rules_table.setHorizontalHeaderLabels([
            "ID", "Name", "Severity", "Category", "Enabled", "Match Count", "Status"
        ])
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.rules_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.rules_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.rules_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.rules_table.setAlternatingRowColors(True)
        self.rules_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.rules_table.customContextMenuRequested.connect(self._show_context_menu)
        self.rules_table.doubleClicked.connect(self._edit_selected_rule)
        
        layout.addWidget(self.rules_table)
        
        # Rule details
        details_group = QGroupBox("Selected Rule Details")
        details_layout = QVBoxLayout(details_group)
        
        self.rule_details = QTextEdit()
        self.rule_details.setReadOnly(True)
        details_layout.addWidget(self.rule_details)
        
        layout.addWidget(details_group)
        
        # Bottom buttons
        button_layout = QHBoxLayout()
        
        button_layout.addStretch()
        
        # Close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
    
    def _load_rules(self):
        """Load rules from rule engine"""
        # Clear table
        self.rules_table.setRowCount(0)
        
        # Get all rules
        rules = self.rule_engine.get_rules()
        
        # Populate category filter
        self.category_filter.clear()
        self.category_filter.addItem("All Categories")
        
        categories = sorted(set(rule.category for rule in rules))
        for category in categories:
            self.category_filter.addItem(category)
        
        # Populate table
        self._populate_rules_table(rules)
    
    def _populate_rules_table(self, rules: List[Rule]):
        """
        Populate rules table
        
        Args:
            rules: List of rules to display
        """
        # Clear table
        self.rules_table.setRowCount(0)
        
        # Add rules to table
        for row, rule in enumerate(rules):
            self.rules_table.insertRow(row)
            
            # ID
            self.rules_table.setItem(row, 0, QTableWidgetItem(rule.id))
            
            # Name
            self.rules_table.setItem(row, 1, QTableWidgetItem(rule.name))
            
            # Severity
            severity_item = QTableWidgetItem(rule.severity.capitalize())
            severity_color = {
                'high': QColor('#ffcccc'),    # Light red
                'medium': QColor('#fff6cc'),  # Light yellow
                'low': QColor('#ccffcc')      # Light green
            }.get(rule.severity.lower(), QColor('white'))
            severity_item.setBackground(severity_color)
            self.rules_table.setItem(row, 2, severity_item)
            
            # Category
            self.rules_table.setItem(row, 3, QTableWidgetItem(rule.category))
            
            # Enabled
            enabled_item = QTableWidgetItem()
            enabled_item.setCheckState(
                Qt.CheckState.Checked if rule.enabled else Qt.CheckState.Unchecked
            )
            self.rules_table.setItem(row, 4, enabled_item)
            
            # Match Count
            match_count_item = QTableWidgetItem(str(rule.match_count))
            self.rules_table.setItem(row, 5, match_count_item)
            
            # Status
            status = "Default" if rule.id.startswith("default:") else "Custom"
            status_item = QTableWidgetItem(status)
            self.rules_table.setItem(row, 6, status_item)
        
        # Clear rule details
        self.rule_details.clear()
    
    def _filter_rules(self):
        """Filter rules based on search and filter criteria"""
        # Get filter criteria
        category = self.category_filter.currentText()
        search_text = self.search_input.text().lower()
        enabled_only = self.enabled_only_checkbox.isChecked()
        
        # Get all rules
        all_rules = self.rule_engine.get_rules()
        
        # Apply filters
        filtered_rules = []
        for rule in all_rules:
            # Category filter
            if category != "All Categories" and rule.category != category:
                continue
            
            # Enabled filter
            if enabled_only and not rule.enabled:
                continue
            
            # Search filter
            if search_text:
                search_fields = [
                    rule.id.lower(),
                    rule.name.lower(),
                    rule.description.lower(),
                    rule.category.lower(),
                    " ".join(rule.tags).lower()
                ]
                
                if not any(search_text in field for field in search_fields):
                    continue
            
            filtered_rules.append(rule)
        
        # Update table
        self._populate_rules_table(filtered_rules)
    
    def _add_rule(self):
        """Add a new rule"""
        dialog = RuleEditorDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Save rule
            if dialog.rule:
                success = self.rule_engine.save_rule(dialog.rule)
                if success:
                    self._load_rules()
                else:
                    QMessageBox.critical(self, "Error", "Failed to save rule to file")
    
    def _edit_selected_rule(self):
        """Edit the selected rule"""
        # Get selected rule
        selected_rows = self.rules_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        rule_id = self.rules_table.item(row, 0).text()
        
        # Get rule
        rule = next((r for r in self.rule_engine.get_rules() if r.id == rule_id), None)
        if not rule:
            return
        
        # Open editor
        dialog = RuleEditorDialog(rule, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Save rule
            if dialog.rule:
                success = self.rule_engine.save_rule(dialog.rule)
                if success:
                    self._load_rules()
                else:
                    QMessageBox.critical(self, "Error", "Failed to save rule to file")
    
    def _show_context_menu(self, position):
        """
        Show context menu for rule
        
        Args:
            position: Menu position
        """
        # Get selected rule
        selected_rows = self.rules_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        rule_id = self.rules_table.item(row, 0).text()
        
        # Create menu
        menu = QMenu()
        
        # View action
        view_action = QAction("View Details", self)
        view_action.triggered.connect(lambda: self._view_rule_details(rule_id))
        menu.addAction(view_action)
        
        # Edit action
        edit_action = QAction("Edit Rule", self)
        edit_action.triggered.connect(self._edit_selected_rule)
        menu.addAction(edit_action)
        
        # Toggle enabled action
        enabled_item = self.rules_table.item(row, 4)
        if enabled_item.checkState() == Qt.CheckState.Checked:
            toggle_action = QAction("Disable Rule", self)
        else:
            toggle_action = QAction("Enable Rule", self)
        toggle_action.triggered.connect(lambda: self._toggle_rule_enabled(rule_id))
        menu.addAction(toggle_action)
        
        menu.addSeparator()
        
        # Export action
        export_action = QAction("Export Rule", self)
        export_action.triggered.connect(lambda: self._export_rule(rule_id))
        menu.addAction(export_action)
        
        menu.addSeparator()
        
        # Delete action (only for custom rules)
        if not rule_id.startswith("default:"):
            delete_action = QAction("Delete Rule", self)
            delete_action.triggered.connect(lambda: self._delete_rule(rule_id))
            menu.addAction(delete_action)
        
        # Show menu
        menu.exec(self.rules_table.viewport().mapToGlobal(position))
    
    def _view_rule_details(self, rule_id: str):
        """
        View rule details
        
        Args:
            rule_id: ID of rule to view
        """
        # Get rule
        rule = next((r for r in self.rule_engine.get_rules() if r.id == rule_id), None)
        if not rule:
            return
        
        # Show details
        details = (
            f"<h3>{rule.name}</h3>\n"
            f"<p><b>ID:</b> {rule.id}</p>\n"
            f"<p><b>Description:</b> {rule.description}</p>\n"
            f"<p><b>Severity:</b> {rule.severity}</p>\n"
            f"<p><b>Category:</b> {rule.category}</p>\n"
            f"<p><b>Tags:</b> {', '.join(rule.tags)}</p>\n"
            f"<p><b>Enabled:</b> {'Yes' if rule.enabled else 'No'}</p>\n"
            f"<p><b>Match Count:</b> {rule.match_count}</p>\n"
            f"<p><b>Last Match:</b> {rule.last_match.isoformat() if rule.last_match else 'Never'}</p>\n"
            f"<h4>Conditions:</h4>\n"
            f"<pre>{yaml.dump(rule.conditions, default_flow_style=False)}</pre>\n"
            f"<h4>Actions:</h4>\n"
            f"<pre>{yaml.dump(rule.actions, default_flow_style=False)}</pre>\n"
        )
        
        self.rule_details.setHtml(details)
    
    def _toggle_rule_enabled(self, rule_id: str):
        """
        Toggle rule enabled state
        
        Args:
            rule_id: ID of rule to toggle
        """
        # Get rule
        rule = next((r for r in self.rule_engine.get_rules() if r.id == rule_id), None)
        if not rule:
            return
        
        # Toggle enabled state
        rule.enabled = not rule.enabled
        
        # Save rule
        success = self.rule_engine.save_rule(rule)
        if success:
            self._load_rules()
        else:
            QMessageBox.critical(self, "Error", "Failed to save rule to file")
    
    def _delete_rule(self, rule_id: str):
        """
        Delete rule
        
        Args:
            rule_id: ID of rule to delete
        """
        # Confirm deletion
        reply = QMessageBox.question(
            self, "Confirm Deletion",
            f"Are you sure you want to delete the rule '{rule_id}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Delete rule
        success = self.rule_engine.delete_rule(rule_id)
        if success:
            self._load_rules()
        else:
            QMessageBox.critical(self, "Error", f"Failed to delete rule '{rule_id}'")
    
    def _export_rule(self, rule_id: str):
        """
        Export rule to file
        
        Args:
            rule_id: ID of rule to export
        """
        # Get rule
        rule = next((r for r in self.rule_engine.get_rules() if r.id == rule_id), None)
        if not rule:
            return
        
        # Get export path
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Rule",
            f"{rule_id.replace(':', '_')}.yaml",
            "YAML Files (*.yaml *.yml);;JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        # Export rule
        try:
            with open(file_path, 'w') as f:
                if file_path.endswith(('.yaml', '.yml')):
                    yaml.dump(rule.to_dict(), f, default_flow_style=False)
                else:
                    json.dump(rule.to_dict(), f, indent=2)
            
            QMessageBox.information(self, "Export Successful", f"Rule exported to {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error exporting rule: {str(e)}")
            QMessageBox.critical(self, "Export Error", f"Failed to export rule: {str(e)}")
    
    def _import_rules(self):
        """Import rules from file(s)"""
        # Get import path(s)
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, "Import Rules",
            "",
            "Rule Files (*.yaml *.yml *.json);;All Files (*)"
        )
        
        if not file_paths:
            return
        
        # Import rules
        imported_count = 0
        error_count = 0
        
        for file_path in file_paths:
            try:
                # Load rules from file
                with open(file_path, 'r') as f:
                    if file_path.endswith(('.yaml', '.yml')):
                        rules_data = yaml.safe_load(f)
                    else:
                        rules_data = json.load(f)
                
                # Handle single rule or list of rules
                if isinstance(rules_data, list):
                    for rule_data in rules_data:
                        try:
                            rule = Rule.from_dict(rule_data)
                            self.rule_engine.save_rule(rule)
                            imported_count += 1
                        except Exception:
                            error_count += 1
                elif isinstance(rules_data, dict):
                    try:
                        rule = Rule.from_dict(rules_data)
                        self.rule_engine.save_rule(rule)
                        imported_count += 1
                    except Exception:
                        error_count += 1
                
            except Exception as e:
                self.logger.error(f"Error importing rules from {file_path}: {str(e)}")
                error_count += 1
        
        # Reload rules
        self._load_rules()
        
        # Show result
        if error_count == 0:
            QMessageBox.information(
                self, "Import Successful",
                f"Successfully imported {imported_count} rules."
            )
        else:
            QMessageBox.warning(
                self, "Import Completed with Errors",
                f"Imported {imported_count} rules, but {error_count} rules could not be imported."
            )
    
    def _import_suricata_rules(self):
        """Import Suricata rules from .rules files"""
        # Get import path(s)
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, "Import Suricata Rules",
            "",
            "Suricata Rules (*.rules);;All Files (*)"
        )
        
        if not file_paths:
            return
        
        # Show progress dialog
        progress_dialog = QMessageBox(self)
        progress_dialog.setWindowTitle("Importing Suricata Rules")
        progress_dialog.setText("Converting Suricata rules to Net4 format...\nThis may take a moment.")
        progress_dialog.setStandardButtons(QMessageBox.StandardButton.NoButton)
        progress_dialog.show()
        
        # Create converter
        converter = SuricataRuleConverter()
        
        # Import rules
        imported_count = 0
        error_count = 0
        
        for file_path in file_paths:
            try:
                # Convert Suricata rules to Net4 rules
                rules = converter.parse_rule_file(file_path)
                
                # Save rules
                for rule in rules:
                    try:
                        # Avoid ID conflicts by adding a prefix if needed
                        if not rule.id.startswith("suricata:"):
                            rule.id = f"suricata:{rule.id}"
                        
                        # Save rule
                        success = self.rule_engine.save_rule(rule)
                        if success:
                            imported_count += 1
                        else:
                            error_count += 1
                    except Exception as e:
                        self.logger.error(f"Error saving converted rule: {str(e)}")
                        error_count += 1
                
            except Exception as e:
                self.logger.error(f"Error importing Suricata rules from {file_path}: {str(e)}")
                error_count += 1
        
        # Close progress dialog
        progress_dialog.close()
        
        # Reload rules
        self._load_rules()
        
        # Show result
        if error_count == 0:
            QMessageBox.information(
                self, "Import Successful",
                f"Successfully imported {imported_count} Suricata rules."
            )
        else:
            QMessageBox.warning(
                self, "Import Completed with Errors",
                f"Imported {imported_count} Suricata rules, but {error_count} rules could not be imported."
            )