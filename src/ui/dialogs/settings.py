import os
import subprocess
import platform
from typing import Dict, Any, Optional

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QTabWidget, QWidget, QFormLayout, QCheckBox, QFileDialog,
    QGroupBox, QSpinBox, QMessageBox, QDialogButtonBox
)
from PyQt6.QtCore import Qt, QSettings, QSize
from PyQt6.QtGui import QIcon, QFont

from ...utils.config import Config


class SettingsDialog(QDialog):
    """
    Dialog for configuring application settings.
    """
    
    def __init__(self, config: Config, parent=None):
        """
        Initialize settings dialog
        
        Args:
            config: Application configuration
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.config = config
        self.original_values = {}  # Store original values for revert
        self.current_values = {}   # Store current edited values
        
        self._init_ui()
        self._load_settings()
    
    def _init_ui(self):
        """Initialize dialog UI"""
        # Set window properties
        self.setWindowTitle("Net4 Settings")
        self.setMinimumSize(500, 400)
        
        # Main layout
        layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Add tabs
        self.general_tab = self._create_general_tab()
        self.api_tab = self._create_api_tab()
        self.analysis_tab = self._create_analysis_tab()
        self.report_tab = self._create_report_tab()
        self.tools_tab = self._create_tools_tab()
        
        self.tab_widget.addTab(self.general_tab, "General")
        self.tab_widget.addTab(self.api_tab, "API Keys")
        self.tab_widget.addTab(self.analysis_tab, "Analysis")
        self.tab_widget.addTab(self.report_tab, "Reporting")
        self.tab_widget.addTab(self.tools_tab, "Tools")
        
        layout.addWidget(self.tab_widget)
        
        # Add buttons
        button_layout = QHBoxLayout()
        
        # Restore defaults button
        self.defaults_button = QPushButton("Restore Defaults")
        self.defaults_button.clicked.connect(self._restore_defaults)
        button_layout.addWidget(self.defaults_button)
        
        button_layout.addStretch()
        
        # Standard buttons
        self.button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Apply
        )
        self.button_box.accepted.connect(self._save_and_close)
        self.button_box.rejected.connect(self.reject)
        
        # Connect Apply button
        apply_button = self.button_box.button(QDialogButtonBox.StandardButton.Apply)
        apply_button.clicked.connect(self._apply_settings)
        
        button_layout.addWidget(self.button_box)
        
        layout.addLayout(button_layout)
    
    def _create_general_tab(self) -> QWidget:
        """
        Create general settings tab
        
        Returns:
            Tab widget
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Theme settings
        theme_group = QGroupBox("Application Theme")
        theme_layout = QFormLayout(theme_group)
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark", "System"])
        self.theme_combo.currentTextChanged.connect(
            lambda text: self._update_value("app.theme", text.lower())
        )
        theme_layout.addRow("Theme:", self.theme_combo)
        
        layout.addWidget(theme_group)
        
        # Application behavior
        behavior_group = QGroupBox("Application Behavior")
        behavior_layout = QFormLayout(behavior_group)
        
        self.auto_analyze_check = QCheckBox("Automatically analyze imported files")
        self.auto_analyze_check.stateChanged.connect(
            lambda state: self._update_value("analysis.auto_analyze", bool(state))
        )
        behavior_layout.addRow(self.auto_analyze_check)
        
        self.auto_ti_check = QCheckBox("Automatically lookup threat intelligence")
        self.auto_ti_check.stateChanged.connect(
            lambda state: self._update_value("analysis.auto_threat_intel", bool(state))
        )
        behavior_layout.addRow(self.auto_ti_check)
        
        layout.addWidget(behavior_group)
        
        # Directories
        dir_group = QGroupBox("Default Directories")
        dir_layout = QFormLayout(dir_group)
        
        # PCAP directory
        pcap_layout = QHBoxLayout()
        self.pcap_dir_edit = QLineEdit()
        self.pcap_dir_edit.textChanged.connect(
            lambda text: self._update_value("analysis.default_pcap_dir", text)
        )
        pcap_layout.addWidget(self.pcap_dir_edit)
        
        pcap_browse_btn = QPushButton("Browse...")
        pcap_browse_btn.clicked.connect(
            lambda: self._browse_directory(self.pcap_dir_edit, "Select PCAP Directory")
        )
        pcap_layout.addWidget(pcap_browse_btn)
        
        dir_layout.addRow("PCAP Directory:", pcap_layout)
        
        # Export directory
        export_layout = QHBoxLayout()
        self.export_dir_edit = QLineEdit()
        self.export_dir_edit.textChanged.connect(
            lambda text: self._update_value("reporting.default_export_dir", text)
        )
        export_layout.addWidget(self.export_dir_edit)
        
        export_browse_btn = QPushButton("Browse...")
        export_browse_btn.clicked.connect(
            lambda: self._browse_directory(self.export_dir_edit, "Select Export Directory")
        )
        export_layout.addWidget(export_browse_btn)
        
        dir_layout.addRow("Export Directory:", export_layout)
        
        layout.addWidget(dir_group)
        layout.addStretch()
        
        return tab
    
    def _create_api_tab(self) -> QWidget:
        """
        Create API keys tab
        
        Returns:
            Tab widget
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # OpenAI API settings
        openai_group = QGroupBox("OpenAI API")
        openai_layout = QFormLayout(openai_group)
        
        # API key
        self.openai_key_edit = QLineEdit()
        self.openai_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.openai_key_edit.textChanged.connect(
            lambda text: self._update_value("api.openai.api_key", text)
        )
        openai_layout.addRow("API Key:", self.openai_key_edit)
        
        # Model selection
        self.openai_model_combo = QComboBox()
        self.openai_model_combo.addItems([
            "gpt-4", "gpt-3.5-turbo", "gpt-4-turbo-preview"
        ])
        self.openai_model_combo.currentTextChanged.connect(
            lambda text: self._update_value("api.openai.model", text)
        )
        openai_layout.addRow("Model:", self.openai_model_combo)
        
        # Timeout
        self.openai_timeout_spin = QSpinBox()
        self.openai_timeout_spin.setRange(10, 300)
        self.openai_timeout_spin.setSuffix(" seconds")
        self.openai_timeout_spin.valueChanged.connect(
            lambda value: self._update_value("api.openai.timeout", value)
        )
        openai_layout.addRow("Timeout:", self.openai_timeout_spin)
        
        layout.addWidget(openai_group)
        
        # VirusTotal API settings
        vt_group = QGroupBox("VirusTotal API")
        vt_layout = QFormLayout(vt_group)
        
        # API key
        self.vt_key_edit = QLineEdit()
        self.vt_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.vt_key_edit.textChanged.connect(
            lambda text: self._update_value("api.virustotal.api_key", text)
        )
        vt_layout.addRow("API Key:", self.vt_key_edit)
        
        # Timeout
        self.vt_timeout_spin = QSpinBox()
        self.vt_timeout_spin.setRange(10, 300)
        self.vt_timeout_spin.setSuffix(" seconds")
        self.vt_timeout_spin.valueChanged.connect(
            lambda value: self._update_value("api.virustotal.timeout", value)
        )
        vt_layout.addRow("Timeout:", self.vt_timeout_spin)
        
        layout.addWidget(vt_group)
        layout.addStretch()
        
        return tab
    
    def _create_analysis_tab(self) -> QWidget:
        """
        Create analysis settings tab
        
        Returns:
            Tab widget
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Analysis settings
        analysis_group = QGroupBox("Analysis Settings")
        analysis_layout = QFormLayout(analysis_group)
        
        # Max packet display
        self.max_packet_spin = QSpinBox()
        self.max_packet_spin.setRange(1000, 1000000)
        self.max_packet_spin.setSingleStep(1000)
        self.max_packet_spin.valueChanged.connect(
            lambda value: self._update_value("analysis.max_packet_display", value)
        )
        analysis_layout.addRow("Max Packets to Display:", self.max_packet_spin)
        
        # Enable AI
        self.enable_ai_check = QCheckBox()
        self.enable_ai_check.stateChanged.connect(
            lambda state: self._update_value("analysis.enable_ai_analysis", bool(state))
        )
        analysis_layout.addRow("Enable AI Analysis:", self.enable_ai_check)
        
        # Enable TI
        self.enable_ti_check = QCheckBox()
        self.enable_ti_check.stateChanged.connect(
            lambda state: self._update_value("analysis.enable_threat_intelligence", bool(state))
        )
        analysis_layout.addRow("Enable Threat Intelligence:", self.enable_ti_check)
        
        layout.addWidget(analysis_group)
        layout.addStretch()
        
        return tab
    
    def _create_report_tab(self) -> QWidget:
        """
        Create reporting settings tab
        
        Returns:
            Tab widget
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Report metadata
        metadata_group = QGroupBox("Report Metadata")
        metadata_layout = QFormLayout(metadata_group)
        
        # Company name
        self.company_edit = QLineEdit()
        self.company_edit.textChanged.connect(
            lambda text: self._update_value("reporting.company_name", text)
        )
        metadata_layout.addRow("Company Name:", self.company_edit)
        
        # Analyst name
        self.analyst_edit = QLineEdit()
        self.analyst_edit.textChanged.connect(
            lambda text: self._update_value("reporting.analyst_name", text)
        )
        metadata_layout.addRow("Analyst Name:", self.analyst_edit)
        
        # Logo
        logo_layout = QHBoxLayout()
        self.logo_edit = QLineEdit()
        self.logo_edit.textChanged.connect(
            lambda text: self._update_value("reporting.logo_path", text)
        )
        logo_layout.addWidget(self.logo_edit)
        
        logo_browse_btn = QPushButton("Browse...")
        logo_browse_btn.clicked.connect(
            lambda: self._browse_file(self.logo_edit, "Select Logo Image", "Images (*.png *.jpg *.jpeg)")
        )
        logo_layout.addWidget(logo_browse_btn)
        
        metadata_layout.addRow("Logo:", logo_layout)
        
        layout.addWidget(metadata_group)
        layout.addStretch()
        
        return tab
    
    def _create_tools_tab(self) -> QWidget:
        """
        Create tools settings tab
        
        Returns:
            Tab widget
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # TShark settings
        tshark_group = QGroupBox("TShark Settings")
        tshark_layout = QVBoxLayout(tshark_group)
        
        # Path input with label and button
        tshark_path_layout = QHBoxLayout()
        tshark_label = QLabel("TShark Path:")
        self.tshark_path_edit = QLineEdit()
        self.tshark_path_edit.textChanged.connect(
            lambda text: self._update_value("paths.tshark", text)
        )
        tshark_path_layout.addWidget(tshark_label)
        tshark_path_layout.addWidget(self.tshark_path_edit)
        
        tshark_browse_btn = QPushButton("Browse...")
        tshark_browse_btn.clicked.connect(self._browse_tshark_path)
        tshark_path_layout.addWidget(tshark_browse_btn)
        
        tshark_layout.addLayout(tshark_path_layout)
        
        # Auto-detect button
        tshark_detect_btn = QPushButton("Auto-detect TShark")
        tshark_detect_btn.clicked.connect(self._auto_detect_tshark)
        tshark_layout.addWidget(tshark_detect_btn)
        
        # Add description label
        tshark_description = QLabel(
            "TShark is required for PCAP analysis. It is part of the Wireshark package.\n"
            "If TShark is not found, PCAP processing will not work."
        )
        tshark_description.setWordWrap(True)
        tshark_layout.addWidget(tshark_description)
        
        layout.addWidget(tshark_group)
        layout.addStretch()
        
        return tab
    
    def _load_settings(self):
        """Load settings from config"""
        # Store original values for revert
        self.original_values = {
            "app.theme": self.config.get("app.theme", "light"),
            "analysis.auto_analyze": self.config.get("analysis.auto_analyze", True),
            "analysis.auto_threat_intel": self.config.get("analysis.auto_threat_intel", True),
            "analysis.default_pcap_dir": self.config.get("analysis.default_pcap_dir", ""),
            "reporting.default_export_dir": self.config.get("reporting.default_export_dir", ""),
            "api.openai.api_key": self.config.get("api.openai.api_key", ""),
            "api.openai.model": self.config.get("api.openai.model", "gpt-4"),
            "api.openai.timeout": self.config.get("api.openai.timeout", 60),
            "api.virustotal.api_key": self.config.get("api.virustotal.api_key", ""),
            "api.virustotal.timeout": self.config.get("api.virustotal.timeout", 30),
            "analysis.max_packet_display": self.config.get("analysis.max_packet_display", 10000),
            "analysis.enable_ai_analysis": self.config.get("analysis.enable_ai_analysis", True),
            "analysis.enable_threat_intelligence": self.config.get("analysis.enable_threat_intelligence", True),
            "reporting.company_name": self.config.get("reporting.company_name", ""),
            "reporting.analyst_name": self.config.get("reporting.analyst_name", ""),
            "reporting.logo_path": self.config.get("reporting.logo_path", ""),
            "paths.tshark": self.config.get("paths.tshark", ""),
        }
        
        # Initialize current values
        self.current_values = self.original_values.copy()
        
        # Load values into UI
        
        # General tab
        theme = self.original_values["app.theme"]
        self.theme_combo.setCurrentText(theme.capitalize())
        
        self.auto_analyze_check.setChecked(self.original_values["analysis.auto_analyze"])
        self.auto_ti_check.setChecked(self.original_values["analysis.auto_threat_intel"])
        
        self.pcap_dir_edit.setText(self.original_values["analysis.default_pcap_dir"])
        self.export_dir_edit.setText(self.original_values["reporting.default_export_dir"])
        
        # API tab
        self.openai_key_edit.setText(self.original_values["api.openai.api_key"])
        self.openai_model_combo.setCurrentText(self.original_values["api.openai.model"])
        self.openai_timeout_spin.setValue(self.original_values["api.openai.timeout"])
        
        self.vt_key_edit.setText(self.original_values["api.virustotal.api_key"])
        self.vt_timeout_spin.setValue(self.original_values["api.virustotal.timeout"])
        
        # Analysis tab
        self.max_packet_spin.setValue(self.original_values["analysis.max_packet_display"])
        self.enable_ai_check.setChecked(self.original_values["analysis.enable_ai_analysis"])
        self.enable_ti_check.setChecked(self.original_values["analysis.enable_threat_intelligence"])
        
        # Report tab
        self.company_edit.setText(self.original_values["reporting.company_name"])
        self.analyst_edit.setText(self.original_values["reporting.analyst_name"])
        self.logo_edit.setText(self.original_values["reporting.logo_path"])
        
        # Tools tab
        self.tshark_path_edit.setText(self.original_values["paths.tshark"])
    
    def _update_value(self, key: str, value: Any):
        """
        Update a value in the current settings
        
        Args:
            key: Setting key
            value: New value
        """
        # Store in current values
        self.current_values[key] = value
    
    def _apply_settings(self):
        """Apply current settings to config"""
        # Apply all current values to config
        for key, value in self.current_values.items():
            self.config.set(key, value)
        
        # Update original values
        self.original_values = self.current_values.copy()
        
        # Show success message
        QMessageBox.information(self, "Settings Saved", "Settings have been applied successfully.")
    
    def _save_and_close(self):
        """Save settings and close dialog"""
        self._apply_settings()
        self.accept()
    
    def _restore_defaults(self):
        """Restore default settings"""
        # Confirm with user
        reply = QMessageBox.question(
            self, "Restore Defaults",
            "This will reset all settings to default values. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Reset current values to defaults
        # Convert nested dict to dot notation for current_values
        def _flatten_dict(d, parent_key='', sep='.'):
            items = []
            for k, v in d.items():
                new_key = parent_key + sep + k if parent_key else k
                if isinstance(v, dict):
                    items.extend(_flatten_dict(v, new_key, sep=sep).items())
                else:
                    items.append((new_key, v))
            return dict(items)
        
        flat_defaults = _flatten_dict(self.config.DEFAULT_CONFIG)
        self.current_values = flat_defaults
        
        # Update UI with defaults
        
        # General tab
        theme = self.config.DEFAULT_CONFIG["app"]["theme"]
        self.theme_combo.setCurrentText(theme.capitalize())
        
        self.auto_analyze_check.setChecked(True)
        self.auto_ti_check.setChecked(True)
        
        self.pcap_dir_edit.setText("")
        self.export_dir_edit.setText("")
        
        # API tab
        self.openai_key_edit.setText("")
        self.openai_model_combo.setCurrentText("gpt-4")
        self.openai_timeout_spin.setValue(60)
        
        self.vt_key_edit.setText("")
        self.vt_timeout_spin.setValue(30)
        
        # Analysis tab
        self.max_packet_spin.setValue(10000)
        self.enable_ai_check.setChecked(True)
        self.enable_ti_check.setChecked(True)
        
        # Report tab
        self.company_edit.setText("")
        self.analyst_edit.setText("")
        self.logo_edit.setText("")
        
        # Tools tab
        self.tshark_path_edit.setText("")
    
    def _browse_directory(self, line_edit: QLineEdit, title: str):
        """
        Browse for a directory
        
        Args:
            line_edit: Line edit to update with selected path
            title: Dialog title
        """
        # Get current directory (if any)
        current_dir = line_edit.text()
        if not current_dir or not os.path.isdir(current_dir):
            current_dir = os.path.expanduser("~")
        
        # Show directory selection dialog
        directory = QFileDialog.getExistingDirectory(self, title, current_dir)
        
        if directory:
            line_edit.setText(directory)
    
    def _browse_file(self, line_edit: QLineEdit, title: str, filter_str: str):
        """
        Browse for a file
        
        Args:
            line_edit: Line edit to update with selected path
            title: Dialog title
            filter_str: File filter string
        """
        # Get current directory (if any)
        current_path = line_edit.text()
        if not current_path or not os.path.exists(current_path):
            current_dir = os.path.expanduser("~")
        else:
            current_dir = os.path.dirname(current_path)
        
        # Show file selection dialog
        file_path, _ = QFileDialog.getOpenFileName(self, title, current_dir, filter_str)
        
        if file_path:
            line_edit.setText(file_path)
    
    def _browse_tshark_path(self):
        """Browse for TShark executable"""
        caption = "Select TShark Executable"
        file_filter = "Executables (*.exe);;All Files (*)" if os.name == 'nt' else "All Files (*)"
        
        # Get current directory (if any)
        current_path = self.tshark_path_edit.text()
        if not current_path or not os.path.exists(current_path):
            if os.name == 'nt':
                current_dir = os.environ.get('ProgramFiles', 'C:\\Program Files')
                if os.path.exists(os.path.join(current_dir, 'Wireshark')):
                    current_dir = os.path.join(current_dir, 'Wireshark')
            else:
                current_dir = "/usr/bin"
        else:
            current_dir = os.path.dirname(current_path)
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, caption, current_dir, file_filter
        )
        
        if file_path:
            self.tshark_path_edit.setText(file_path)
    
    def _auto_detect_tshark(self):
        """Auto-detect TShark location"""
        paths = []
        
        if platform.system() == "Windows":  # Windows
            paths = [
                os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Wireshark', 'tshark.exe'),
                os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Wireshark', 'tshark.exe'),
                'C:\\Wireshark\\tshark.exe'
            ]
        else:  # Linux/Mac
            paths = [
                "/usr/bin/tshark",
                "/usr/local/bin/tshark",
                "/opt/wireshark/bin/tshark"
            ]
        
        # Check if tshark is in PATH
        try:
            command = "where" if os.name == 'nt' else "which"
            result = subprocess.run([command, "tshark"], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE, 
                              text=True)
            if result.returncode == 0:
                paths.insert(0, result.stdout.strip())
        except Exception:
            pass
        
        # Check paths
        for path in paths:
            if os.path.exists(path):
                self.tshark_path_edit.setText(path)
                self._update_value("paths.tshark", path)
                QMessageBox.information(self, "TShark Found", f"TShark executable found at:\n{path}")
                return
        
        QMessageBox.warning(self, "TShark Not Found", 
                          "TShark was not found in standard locations.\n"
                          "Please install Wireshark from https://www.wireshark.org/download.html\n"
                          "or specify the path manually.")