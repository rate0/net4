import os
import sys
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QSplitter, QMenu, QMenuBar, QToolBar, 
    QStatusBar, QFileDialog, QMessageBox, QApplication, QVBoxLayout, 
    QHBoxLayout, QWidget, QTreeWidget, QTreeWidgetItem, QLabel, 
    QProgressBar, QDockWidget, QDialog, QHeaderView
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QThread, QSettings, QObject, QMetaObject, QTimer
from PyQt6.QtGui import QIcon, QAction, QPixmap, QColor, QFont

from .dashboards.overview import OverviewDashboard
from .dashboards.network_flow import NetworkFlowDashboard
from .dashboards.event_analysis import EventAnalysisDashboard
from .dashboards.ai_insights import AIInsightsDashboard
from .dashboards.http_analysis import HttpAnalysisDashboard
from .widgets.global_search import GlobalSearchWidget
from .dialogs.settings import SettingsDialog
from .dialogs.export import ExportDialog
from .dialogs.rules_manager import RuleManagerDialog
from .dialogs.live_capture import LiveCaptureDialog

from ..models.session import Session
from ..core.data_ingestion.pcap import PcapProcessor
from ..core.analysis.ai_engine import AIEngine
from ..core.analysis.anomaly import AnomalyDetector
from ..core.ti.virustotal import VirusTotalClient
from ..core.ti.classifier import ThreatClassifier
from ..core.rules.rule_engine import RuleEngine
from ..utils.config import Config
from ..utils.logger import Logger

# Thread-safe signal handling for PCAP processing
class PcapSignals(QObject):
    """Signal class for thread-safe PCAP processing callbacks"""
    progress_updated = pyqtSignal(int, int)        # current, total
    processing_complete = pyqtSignal(dict)         # result dictionary

class AISignals(QObject):
    """Signal class for thread-safe AI analysis callbacks"""
    progress_updated = pyqtSignal(str, float)      # message, progress
    analysis_complete = pyqtSignal(dict)

class AIQuestionSignals(QObject):
    """Signal class for thread-safe AI question callbacks"""
    progress_updated = pyqtSignal(str, float)      # message, progress
    answer_complete = pyqtSignal(dict)

class ThreatIntelSignals(QObject):
    """Signal class for thread-safe threat intelligence callbacks"""
    progress_updated = pyqtSignal(int, int, dict)  # current, total, data
    processing_complete = pyqtSignal(dict)

class AnomalySignals(QObject):
    """Signal class for thread-safe anomaly detection callbacks"""
    progress_updated = pyqtSignal(str, float)      # message, progress
    detection_complete = pyqtSignal(list)
    
class RuleSignals(QObject):
    """Signal class for thread-safe rule evaluation callbacks"""
    progress_updated = pyqtSignal(str, float)      # message, progress
    evaluation_complete = pyqtSignal(dict)         # result dictionary

class MainWindow(QMainWindow):
    """
    Main application window for Net4.
    Provides the central interface for network forensic analysis.
    """
    
    def __init__(self, config: Config):
        """
        Initialize main window
        
        Args:
            config: Application configuration
        """
        super().__init__()
        
        self.config = config
        self.logger = Logger().get_logger()
        
        # Current session
        self.session: Optional[Session] = None
        
        # UI components
        self.central_widget = QWidget()
        self.tab_widget = QTabWidget()
        self.entity_dock = QDockWidget("Network Entities", self)
        self.status_bar = QStatusBar()
        self.progress_bar = QProgressBar()
        
        # Signal handlers for thread-safe operations
        self.pcap_signals = PcapSignals()
        self.pcap_signals.progress_updated.connect(self._update_progress)
        self.pcap_signals.processing_complete.connect(self._pcap_processing_complete)
        
        # AI signals
        self.ai_signals = AISignals()
        self.ai_signals.progress_updated.connect(self._update_progress_with_message)
        self.ai_signals.analysis_complete.connect(self._ai_analysis_complete)
        
        # AI Question signals
        self.ai_question_signals = AIQuestionSignals()
        self.ai_question_signals.progress_updated.connect(self._update_progress_with_message)
        self.ai_question_signals.answer_complete.connect(self._ai_question_complete)
        
        # Threat Intelligence signals
        self.threat_signals = ThreatIntelSignals()
        self.threat_signals.progress_updated.connect(
            lambda current, total, data: self._update_progress(current, total)
        )
        self.threat_signals.processing_complete.connect(self._threat_intel_complete)
        
        # Anomaly Detection signals
        self.anomaly_signals = AnomalySignals()
        self.anomaly_signals.progress_updated.connect(self._update_progress_with_message)
        self.anomaly_signals.detection_complete.connect(self._anomaly_detection_complete)
        
        # Rule Engine signals
        self.rule_signals = RuleSignals()
        self.rule_signals.progress_updated.connect(self._update_progress_with_message)
        self.rule_signals.evaluation_complete.connect(self._rule_evaluation_complete)
        
        # Dashboards
        self.overview_dashboard = None
        self.network_flow_dashboard = None
        self.event_analysis_dashboard = None
        self.search_widget = None
        
        # Core components
        self.pcap_processor = None
        self.log_parser = None
        self.ai_engine = AIEngine(self.config)
        self.threat_client = VirusTotalClient(self.config)
        self.threat_classifier = None
        
        # Rule engine setup
        rules_dir = self.config.get("paths.rules_dir", None)
        self.rule_engine = RuleEngine(rules_dir)
        if self.config.get("analysis.enable_custom_rules", True):
            self.rule_engine.load_rules()
        
        # Initialize UI
        self._init_ui()
        
        # Create new session
        self._new_session()
    
    def _init_ui(self):
        """Initialize user interface"""
        # Set window properties
        self.setWindowTitle("Net4 - Network Forensic Analysis")
        self.resize(1200, 800)
        # Allow window to be resized normally
        self.setMinimumSize(800, 600)
        
        # Load and apply the dark theme stylesheet
        try:
            stylesheet_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                                         "assets", "styles", "dark_theme.qss")
            with open(stylesheet_path, "r") as f:
                self.setStyleSheet(f.read())
            self.logger.info("Applied dark theme stylesheet")
        except Exception as e:
            self.logger.error(f"Failed to load stylesheet: {str(e)}")
            # Fallback to basic styling if stylesheet fails to load
            self.setStyleSheet("""
            QWidget { background-color: #1e1e2e; color: #ffffff; }
            QPushButton { background-color: #2d74da; color: #ffffff; padding: 5px; }
            QTabBar::tab { background-color: #2e2e3e; color: #ffffff; padding: 8px 16px; }
            QTabBar::tab:selected { background-color: #2d74da; color: #ffffff; }
            """)
        
        # Set central widget
        self.setCentralWidget(self.central_widget)
        
        # Create layout
        layout = QVBoxLayout(self.central_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Add tab widget
        layout.addWidget(self.tab_widget)
        
        # Setup menu and toolbar
        self._create_menu()
        self._create_toolbar()
        
        # Setup status bar
        self.setStatusBar(self.status_bar)
        self.status_bar.addPermanentWidget(self.progress_bar)
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        
        # Setup entity dock
        self._setup_entity_dock()
        
        # Load window state
        self._load_window_state()
        
        # Ensure window is resizable and has appropriate flags
        self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowMaximizeButtonHint)
        self.setWindowState(self.windowState() & ~Qt.WindowState.WindowFullScreen)
    
    def _create_menu(self):
        """Create application menu"""
        # File menu
        file_menu = self.menuBar().addMenu("&File")
        
        new_action = QAction("🗋 New", self)
        new_action.setShortcut("Ctrl+N")
        new_action.triggered.connect(self._new_session)
        file_menu.addAction(new_action)
        
        open_action = QAction("📂 Open", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._open_session)
        file_menu.addAction(open_action)
        
        save_action = QAction("💾 Save", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self._save_session)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        import_menu = file_menu.addMenu("&Import")
        
        import_pcap_action = QAction("📥 PCAP", self)
        import_pcap_action.triggered.connect(self._import_pcap)
        import_menu.addAction(import_pcap_action)
        
        # Live capture action - text only since we don't have a good icon
        capture_live_action = QAction("&Live Capture", self)
        capture_live_action.triggered.connect(self._start_live_capture)
        import_menu.addAction(capture_live_action)
        
        export_action = QAction(QIcon.fromTheme("document-save-as"), "&Export Data", self)
        export_action.triggered.connect(self._export_data)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction(QIcon.fromTheme("application-exit"), "E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Analysis menu
        analysis_menu = self.menuBar().addMenu("&Analysis")
        
        analyze_ai_action = QAction("🤖 Analyze", self)
        analyze_ai_action.triggered.connect(self._run_ai_analysis)
        analysis_menu.addAction(analyze_ai_action)
        
        ai_chat_action = QAction("AI &Chat Assistant", self)
        ai_chat_action.triggered.connect(self._open_ai_chat)
        analysis_menu.addAction(ai_chat_action)
        
        analysis_menu.addSeparator()
        
        detect_anomalies_action = QAction("Detect &Anomalies", self)
        detect_anomalies_action.triggered.connect(self._detect_anomalies)
        analysis_menu.addAction(detect_anomalies_action)
        
        threat_intel_action = QAction("⚠ Threats", self)
        threat_intel_action.triggered.connect(self._lookup_threat_intel)
        analysis_menu.addAction(threat_intel_action)
        
        # Detection menu (new)
        detection_menu = self.menuBar().addMenu("&Detection")
        
        run_rules_action = QAction("&Evaluate Custom Rules", self)
        run_rules_action.triggered.connect(self._run_rules_evaluation)
        detection_menu.addAction(run_rules_action)
        
        manage_rules_action = QAction("&Manage Custom Rules", self)
        manage_rules_action.triggered.connect(self._open_rules_manager)
        detection_menu.addAction(manage_rules_action)
        
        detection_menu.addSeparator()
        
        import_rules_action = QAction("&Import Rules", self)
        import_rules_action.triggered.connect(self._import_rules)
        detection_menu.addAction(import_rules_action)
        
        # Tools menu
        tools_menu = self.menuBar().addMenu("&Tools")
        
        settings_action = QAction(QIcon.fromTheme("preferences-system"), "&Settings", self)
        settings_action.triggered.connect(self._open_settings)
        tools_menu.addAction(settings_action)
        
        tools_menu.addSeparator()
        
        # HTTP/HTTPS support is now enabled by default during installation
        check_http_support_action = QAction("Check HTTP/HTTPS Support", self)
        check_http_support_action.triggered.connect(self._check_http_support)
        check_http_support_action.setToolTip("Check and verify HTTP/HTTPS packet analysis support")
        tools_menu.addAction(check_http_support_action)
        
        # View menu
        view_menu = self.menuBar().addMenu("&View")
        
        entity_dock_action = self.entity_dock.toggleViewAction()
        entity_dock_action.setText("Show &Entities Panel")
        view_menu.addAction(entity_dock_action)
        
        # Help menu
        help_menu = self.menuBar().addMenu("&Help")
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
    
    def _create_toolbar(self):
        """Create application toolbar with essential actions only"""
        main_toolbar = QToolBar("Main Toolbar", self)
        main_toolbar.setObjectName("mainToolbar")  # Set object name to avoid Qt warning
        main_toolbar.setIconSize(QSize(32, 32))    # Larger icons for better visibility
        main_toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)  # Show text under icons
        self.addToolBar(main_toolbar)
        
        # File actions group
        new_action = QAction("🆕 New", self)
        new_action.triggered.connect(self._new_session)
        main_toolbar.addAction(new_action)
        
        open_action = QAction("📂 Open", self)
        open_action.triggered.connect(self._open_session)
        main_toolbar.addAction(open_action)
        
        save_action = QAction("💾 Save", self)
        save_action.triggered.connect(self._save_session)
        main_toolbar.addAction(save_action)
        
        main_toolbar.addSeparator()
        
        # Import group - primary actions for data import
        import_pcap_action = QAction("📥 PCAP", self)
        import_pcap_action.triggered.connect(self._import_pcap)
        import_pcap_action.setToolTip("Import PCAP file for analysis")
        main_toolbar.addAction(import_pcap_action)
        
        # Live capture action - text only since we don't have a good icon
        live_capture_action = QAction("🐽 Live Capture", self)
        live_capture_action.triggered.connect(self._start_live_capture)
        live_capture_action.setToolTip("Capture live network traffic (requires admin privileges)")
        main_toolbar.addAction(live_capture_action)
        
        main_toolbar.addSeparator()
        
        # Analysis group - most important analysis actions
        ai_action = QAction("🤖 Analyze", self)
        ai_action.triggered.connect(self._run_ai_analysis)
        ai_action.setToolTip("Run automatic AI analysis on data")
        main_toolbar.addAction(ai_action)
        
        # Threat intelligence - key feature
        threat_action = QAction("⚠ Threats", self)
        threat_action.triggered.connect(self._lookup_threat_intel)
        threat_action.setToolTip("Look up potential threats in threat intelligence databases")
        main_toolbar.addAction(threat_action)
    
    def _setup_entity_dock(self):
        """Setup entity dock panel"""
        self.entity_dock.setObjectName("networkEntitiesDock")  # Set object name to avoid Qt warning
        
        # Create container widget to add title and controls
        entity_container = QWidget()
        entity_layout = QVBoxLayout(entity_container)
        entity_layout.setContentsMargins(0, 0, 0, 0)
        
        # Add header label
        header_label = QLabel("Network Entities")
        header_label.setProperty("header", True)  # Use CSS styling
        header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_font = QFont()
        header_font.setBold(True)
        header_font.setPointSize(11)
        header_label.setFont(header_font)
        header_label.setContentsMargins(5, 5, 5, 5)
        entity_layout.addWidget(header_label)
        
        # Create tree widget with modern styling
        self.entity_tree = QTreeWidget()
        self.entity_tree.setHeaderLabels(["Entity", "Type", "Threat Level"])
        self.entity_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.entity_tree.customContextMenuRequested.connect(self._show_entity_context_menu)
        self.entity_tree.setAlternatingRowColors(True)
        self.entity_tree.setAnimated(True)
        self.entity_tree.setUniformRowHeights(True)
        self.entity_tree.setAllColumnsShowFocus(True)
        
        # Configure header
        header = self.entity_tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(False)
        
        entity_layout.addWidget(self.entity_tree)
        
        # Set dock widget
        self.entity_dock.setWidget(entity_container)
        self.entity_dock.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | 
                                        Qt.DockWidgetArea.RightDockWidgetArea)
        
        # Ensure dock can be closed, moved and floated
        self.entity_dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetClosable |
            QDockWidget.DockWidgetFeature.DockWidgetMovable |
            QDockWidget.DockWidgetFeature.DockWidgetFloatable
        )

        # Add dock to main window (left side by default). Users могут перетащить.
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.entity_dock)
    
    def _load_window_state(self):
        """Load window state from settings"""
        settings = QSettings("Net4", "MainWindow")
        
        if settings.contains("geometry"):
            self.restoreGeometry(settings.value("geometry"))
        
        if settings.contains("windowState"):
            self.restoreState(settings.value("windowState"))
    
    def _save_window_state(self):
        """Save window state to settings"""
        settings = QSettings("Net4", "MainWindow")
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("windowState", self.saveState())
    
    def _new_session(self):
        """Create a new analysis session"""
        # Ask to save current session if modified
        if self.session and self._is_session_modified():
            reply = QMessageBox.question(
                self, "Save Current Session",
                "Do you want to save the current session before creating a new one?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
            )
            
            if reply == QMessageBox.StandardButton.Cancel:
                return
            elif reply == QMessageBox.StandardButton.Yes:
                if not self._save_session():
                    return  # Cancel new session if save fails
        
        # Create new session
        self.session = Session()
        
        # Initialize core components
        debug_mode = self.config.get("debug", False)
        self.pcap_processor = PcapProcessor(self.session, debug=debug_mode)
        # Log analysis has been deprecated; focus solely on PCAP and network traffic.
        self.log_parser = None
        
        # Create dashboards
        self._init_dashboards()
        
        # Update UI
        self._update_entity_tree()
        self._update_window_title()
        
        self.status_bar.showMessage("New session created", 3000)
    
    def _open_session(self):
        """Open an existing analysis session"""
        # Ask to save current session if modified
        if self.session and self._is_session_modified():
            reply = QMessageBox.question(
                self, "Save Current Session",
                "Do you want to save the current session before opening a new one?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
            )
            
            if reply == QMessageBox.StandardButton.Cancel:
                return
            elif reply == QMessageBox.StandardButton.Yes:
                if not self._save_session():
                    return  # Cancel open if save fails
        
        # Get session file path
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Session", "",
            "Net4 Session Files (*.n4s);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            # Load session
            self.session = Session.load(file_path)
            
            # Initialize core components with debug mode from config
            debug_mode = self.config.get("debug", False)
            self.pcap_processor = PcapProcessor(self.session, debug=debug_mode)
            # Log analysis deprecated
            self.log_parser = None
            
            # Create dashboards
            self._init_dashboards()
            
            # Update UI
            self._update_entity_tree()
            self._update_window_title()
            
            self.status_bar.showMessage(f"Session loaded: {os.path.basename(file_path)}", 3000)
            
        except Exception as e:
            self.logger.error(f"Error opening session: {str(e)}")
            QMessageBox.critical(
                self, "Error Opening Session",
                f"Could not open session file:\n{str(e)}"
            )
    
    def _save_session(self):
        """
        Save the current analysis session
        
        Returns:
            bool: True if session was saved, False otherwise
        """
        if not self.session:
            return False
        
        # Get session file path
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Session", "",
            "Net4 Session Files (*.n4s);;All Files (*)"
        )
        
        if not file_path:
            return False
        
        # Add extension if missing
        if not file_path.lower().endswith(".n4s"):
            file_path += ".n4s"
        
        try:
            # Save session
            self.session.save(file_path)
            self.status_bar.showMessage(f"Session saved: {os.path.basename(file_path)}", 3000)
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving session: {str(e)}")
            QMessageBox.critical(
                self, "Error Saving Session",
                f"Could not save session file:\n{str(e)}"
            )
            return False
    
    def _import_pcap(self):
        """Import PCAP file for analysis"""
        if not self.session:
            self._new_session()
        
        # Get PCAP file path
        default_dir = self.config.get("analysis.default_pcap_dir", "")
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import PCAP File", default_dir,
            "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        
        if not file_path:
            return
        
        # Update default directory
        self.config.set("analysis.default_pcap_dir", os.path.dirname(file_path))
        
        # Update status
        self.status_bar.showMessage("Processing PCAP file...")
        self.progress_bar.setVisible(True)
        
        # Process PCAP asynchronously with signals for thread safety
        self.pcap_processor.process_file_async(
            file_path,
            progress_callback=self.pcap_signals.progress_updated.emit,
            completion_callback=self.pcap_signals.processing_complete.emit
        )
    
    def _import_log(self):
        """Deprecated: Log analysis has been removed. Show information message."""
        QMessageBox.information(
            self,
            "Log Analysis Disabled",
            "Log file analysis has been removed in the current version.\n"
            "Please use PCAP import or live capture for network traffic analysis."
        )
    
    def _run_ai_analysis(self):
        """Run AI-powered analysis on the session data"""
        if not self.session:
            QMessageBox.warning(
                self, "No Active Session",
                "Please create or open a session before running analysis."
            )
            return
    
        # Check if there's data to analyze
        if not self.session.packets and not self.session.network_entities:
            QMessageBox.warning(
                self, "No Data to Analyze",
                "Please import PCAP data or capture live traffic before running analysis."
            )
            return
    
        # Check API key
        api_key = self.config.get("api.openai.api_key")
        if not api_key:
            reply = QMessageBox.question(
                self, "API Key Required",
                "OpenAI API key is not configured. Open settings to configure it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
        
            if reply == QMessageBox.StandardButton.Yes:
                self._open_settings()
            return
    
        # Update status
        self.status_bar.showMessage("Running AI analysis...")
        self.progress_bar.setVisible(True)
    
        # Run analysis asynchronously with signals for thread safety
        self.ai_engine.analyze_session_async(
            self.session,
            analysis_type="overview",
            progress_callback=self.ai_signals.progress_updated.emit,
            completion_callback=self.ai_signals.analysis_complete.emit
        )
    
    def _open_ai_chat(self):
        """Open AI Chat interface"""
        if not self.session:
            QMessageBox.warning(
                self, "No Active Session",
                "Please create or open a session before using AI chat."
            )
            return
        
        # Check if there's data to analyze
        if not self.session.packets and not self.session.network_entities:
            QMessageBox.warning(
                self, "No Data to Analyze",
                "Please import PCAP data or capture live traffic before using AI chat."
            )
            return
        
        # Check API key
        api_key = self.config.get("api.openai.api_key")
        if not api_key:
            reply = QMessageBox.question(
                self, "API Key Required",
                "OpenAI API key is not configured. Open settings to configure it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self._open_settings()
            return
        
        # Switch to AI Insights tab
        self.tab_widget.setCurrentWidget(self.ai_insights_dashboard)
        
        # Focus on chat input
        self.ai_insights_dashboard.focus_chat_input()
    
    def ask_ai_question(self, question: str):
        """
        Ask a question to the AI assistant
        
        Args:
            question: Question to ask
        """
        if not self.session:
            QMessageBox.warning(
                self, "No Active Session",
                "Please create or open a session before asking questions."
            )
            return
        
        # Check API key
        api_key = self.config.get("api.openai.api_key")
        if not api_key:
            QMessageBox.warning(
                self, "API Key Required",
                "OpenAI API key is not configured. Please configure it in Settings."
            )
            return
        
        # Update status
        self.status_bar.showMessage("Processing your question...")
        self.progress_bar.setVisible(True)
        
        # Process question asynchronously
        self.ai_engine.ask_question_async(
            self.session, 
            question,
            progress_callback=self.ai_question_signals.progress_updated.emit,
            completion_callback=self.ai_question_signals.answer_complete.emit
        )
    
    def _detect_anomalies(self):
        """Run anomaly detection on the session data"""
        if not self.session:
            QMessageBox.warning(
                self, "No Active Session",
                "Please create or open a session before running anomaly detection."
            )
            return
        
        # Check if there's data to analyze
        if not self.session.packets and not self.session.network_entities:
            QMessageBox.warning(
                self, "No Data to Analyze",
                "Please import PCAP data or capture live traffic before running anomaly detection."
            )
            return
        
        # Update status
        self.status_bar.showMessage("Detecting anomalies...")
        self.progress_bar.setVisible(True)
        
        # Create detector
        detector = AnomalyDetector(self.session)
        
        # Run detection asynchronously - FIXED to use signal handlers
        detector.detect_anomalies_async(
            progress_callback=self.anomaly_signals.progress_updated.emit,
            completion_callback=self.anomaly_signals.detection_complete.emit
        )
    
    def _lookup_threat_intel(self):
        """Look up threat intelligence for network entities"""
        if not self.session:
            QMessageBox.warning(
                self, "No Active Session",
                "Please create or open a session before looking up threat intelligence."
            )
            return
        
        # Check if there are entities to look up
        if not self.session.network_entities:
            QMessageBox.warning(
                self, "No Entities Found",
                "No network entities found to look up."
            )
            return
        
        # Check API key
        api_key = self.config.get("api.virustotal.api_key")
        if not api_key:
            reply = QMessageBox.question(
                self, "API Key Required",
                "VirusTotal API key is not configured. Open settings to configure it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self._open_settings()
            return
        
        # Update status
        self.status_bar.showMessage("Looking up threat intelligence...")
        self.progress_bar.setVisible(True)
        
        # Run lookup asynchronously - FIXED to use our signal handlers
        self.threat_client.process_session_entities_async(
            self.session,
            entity_types=["ip", "domain"],
            max_entities=100,
            progress_callback=self.threat_signals.progress_updated.emit,
            completion_callback=self.threat_signals.processing_complete.emit
        )
    
    def _export_data(self):
        """Export session data"""
        if not self.session:
            QMessageBox.warning(
                self, "No Active Session",
                "Please create or open a session before exporting data."
            )
            return
        
        # Open export dialog
        dialog = ExportDialog(self.session, self)
        dialog.exec()
        
    def _start_live_capture(self):
        """Start live packet capture"""
        if not self.session:
            QMessageBox.warning(
                self, "No Active Session",
                "Please create or open a session before starting live capture."
            )
            return
        
        if not self.pcap_processor:
            QMessageBox.warning(
                self, "Error",
                "Packet processor not initialized. Please try restarting the application."
            )
            return
        
        # Open live capture dialog
        dialog = LiveCaptureDialog(self, self.pcap_processor)
        dialog.exec()
        
        # Update entity tree after capture
        self._update_entity_tree()
        
        # Update dashboards
        self._update_dashboards()
        
    def _check_http_support(self, silent=False):
        """Check if HTTP/HTTPS support is properly installed

        Args:
            silent: Если True, не показывать информационные диалоги при успешной проверке.
        """
        # Attempt to import HTTP support from scapy
        http_support_available = False
        try:
            import importlib
            http_module = importlib.import_module("scapy.contrib.http")
            http_support_available = True
        except ImportError:
            pass
        
        if http_support_available and not silent:
            QMessageBox.information(
                self,
                "HTTP/HTTPS Support Status",
                "HTTP/HTTPS packet analysis support is properly installed and available.\n\n"
                "You can analyze HTTP/HTTPS traffic in captured PCAP files."
            )
    
    def _setup_scapy_http(self):
        """Legacy method maintained for compatibility"""
        self._check_http_support(silent=True)
    
    def _open_settings(self):
        """Open settings dialog"""
        dialog = SettingsDialog(self.config, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Update components with new settings
            self.ai_engine = AIEngine(self.config)
            self.threat_client = VirusTotalClient(self.config)
            
            # Update rule engine with new settings
            rules_dir = self.config.get("paths.rules_dir", None)
            if rules_dir:
                self.rule_engine = RuleEngine(rules_dir)
                if self.config.get("analysis.enable_custom_rules", True):
                    self.rule_engine.load_rules()
            
            # Update settings if session exists
            if self.session and self.pcap_processor:
                # Nothing to update dynamically with Scapy-based processor
                pass
    
    def _open_rules_manager(self):
        """Open rules manager dialog"""
        if not self.config.get("analysis.enable_custom_rules", True):
            QMessageBox.information(
                self, "Custom Rules Disabled",
                "Custom rules are disabled in settings. Enable them in Settings > Analysis."
            )
            return
        
        dialog = RuleManagerDialog(self)
        dialog.exec()
        
        # Reload rules after dialog closes
        self.rule_engine.load_rules()
    
    def _import_rules(self):
        """Import rules from file"""
        if not self.config.get("analysis.enable_custom_rules", True):
            QMessageBox.information(
                self, "Custom Rules Disabled",
                "Custom rules are disabled in settings. Enable them in Settings > Analysis."
            )
            return
            
        # Open file dialog
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
                # Add rules file to rules directory
                rules_dir = self.config.get("paths.rules_dir", None) or self.rule_engine.rules_dir
                target_path = os.path.join(rules_dir, os.path.basename(file_path))
                
                # Copy file
                import shutil
                shutil.copy2(file_path, target_path)
                
                imported_count += 1
                
            except Exception as e:
                self.logger.error(f"Error importing rule file {file_path}: {str(e)}")
                error_count += 1
        
        # Reload rules
        self.rule_engine.load_rules()
        
        # Show result
        if error_count == 0:
            QMessageBox.information(
                self, "Import Successful",
                f"Successfully imported {imported_count} rule file(s)."
            )
        else:
            QMessageBox.warning(
                self, "Import Completed with Errors",
                f"Imported {imported_count} rule file(s), but {error_count} file(s) could not be imported."
            )
    
    def _run_rules_evaluation(self):
        """Run rules evaluation on current session"""
        if not self.session:
            QMessageBox.warning(
                self, "No Active Session",
                "Please create or open a session before evaluating rules."
            )
            return
        
        # Check if there's data to analyze
        if not self.session.packets and not self.session.network_entities:
            QMessageBox.warning(
                self, "No Data to Analyze",
                "Please import PCAP data or capture live traffic before evaluating rules."
            )
            return
        
        # Check if rules are enabled
        if not self.config.get("analysis.enable_custom_rules", True):
            QMessageBox.information(
                self, "Custom Rules Disabled",
                "Custom rules are disabled in settings. Enable them in Settings > Analysis."
            )
            return
        
        # Check if rules are loaded
        if not self.rule_engine.rules:
            reply = QMessageBox.question(
                self, "No Rules Loaded",
                "No custom rules are loaded. Would you like to manage rules now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self._open_rules_manager()
            return
        
        # Update status
        self.status_bar.showMessage("Evaluating custom rules...")
        self.progress_bar.setVisible(True)
        
        # Run rules evaluation asynchronously
        def progress_callback(message, progress):
            self.rule_signals.progress_updated.emit(message, progress)
        
        def completion_callback(result):
            self.rule_signals.evaluation_complete.emit(result)
        
        # Run evaluation in a separate thread
        thread = threading.Thread(
            target=self._run_rules_evaluation_thread,
            args=(self.session, progress_callback, completion_callback)
        )
        thread.daemon = True
        thread.start()
    
    def _run_rules_evaluation_thread(self, session, progress_callback, completion_callback):
        """
        Thread function for rules evaluation
        
        Args:
            session: Analysis session
            progress_callback: Progress callback function
            completion_callback: Completion callback function
        """
        try:
            # Update progress
            progress_callback("Evaluating custom rules...", 0.0)
            
            # Evaluate rules
            results = self.rule_engine.evaluate_session(session)
            
            # Update progress
            progress_callback("Rules evaluation complete", 1.0)
            
            # Call completion callback
            completion_callback(results)
            
        except Exception as e:
            self.logger.error(f"Error evaluating rules: {str(e)}")
            completion_callback({"error": str(e)})
    
    def _rule_evaluation_complete(self, results):
        """
        Handle rule evaluation completion
        
        Args:
            results: Evaluation results
        """
        self.progress_bar.setVisible(False)
        
        if "error" in results:
            QMessageBox.critical(
                self, "Error in Rule Evaluation",
                f"An error occurred during rule evaluation:\n{results['error']}"
            )
            self.status_bar.showMessage("Rule evaluation failed", 3000)
            return
        
        # Update UI
        self._update_entity_tree()
        self._update_dashboards()
        
        # Show results
        matches_count = len(results.get("matches", []))
        connections_matched = results.get("stats", {}).get("connections_matched", 0)
        rules_triggered = results.get("stats", {}).get("unique_rules_triggered", 0)
        
        self.status_bar.showMessage(
            f"Rule evaluation complete: {matches_count} matches from {rules_triggered} rules",
            5000
        )
        
        # Show detailed results if matches found
        if matches_count > 0:
            # Group by severity
            severity_counts = {"high": 0, "medium": 0, "low": 0}
            
            for match in results.get("matches", []):
                severity = match.get("severity", "low")
                severity_counts[severity] += 1
            
            message = (
                f"Rules evaluation found {matches_count} rule matches:\n"
                f"• High severity: {severity_counts['high']}\n"
                f"• Medium severity: {severity_counts['medium']}\n"
                f"• Low severity: {severity_counts['low']}\n\n"
                f"Triggered {rules_triggered} unique rules across {connections_matched} connections."
            )
            
            if severity_counts["high"] > 0:
                QMessageBox.warning(self, "Rule Matches Found", message)
            else:
                QMessageBox.information(self, "Rule Matches Found", message)
            
            # Switch to overview dashboard to show results
            self.tab_widget.setCurrentWidget(self.overview_dashboard)
    
    def _show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self, "About Net4",
            f"<h2>Net4 - Network Forensic Analysis</h2>"
            f"<p>Version 1.1.0</p>"
            f"<p>A powerful desktop application for deep forensic analysis "
            f"of network artifacts with AI-powered insights and "
            f"seamless Threat Intelligence integration.</p>"
        )
    
    def _show_entity_context_menu(self, position):
        """Show context menu for entities"""
        if not self.entity_tree.selectedItems():
            return
        
        item = self.entity_tree.selectedItems()[0]
        entity_id = item.data(0, Qt.ItemDataRole.UserRole)
        
        if not entity_id or entity_id not in self.session.network_entities:
            return
        
        entity = self.session.network_entities[entity_id]
        
        # Create context menu
        menu = QMenu()
        
        # Add actions
        lookup_action = menu.addAction("Lookup Threat Intelligence")
        lookup_action.triggered.connect(lambda: self._lookup_entity_threat_intel(entity))
        
        filter_action = menu.addAction("Filter Connections")
        filter_action.triggered.connect(lambda: self._filter_entity_connections(entity))
        
        # Add ask AI action
        ask_ai_action = menu.addAction("Ask AI About This Entity")
        ask_ai_action.triggered.connect(lambda: self._ask_about_entity(entity))
        
        # Add threat level submenu
        threat_menu = menu.addMenu("Set Threat Level")
        
        malicious_action = threat_menu.addAction("Malicious")
        malicious_action.triggered.connect(lambda: self._set_entity_threat_level(entity, "malicious"))
        
        suspicious_action = threat_menu.addAction("Suspicious")
        suspicious_action.triggered.connect(lambda: self._set_entity_threat_level(entity, "suspicious"))
        
        safe_action = threat_menu.addAction("Safe")
        safe_action.triggered.connect(lambda: self._set_entity_threat_level(entity, "safe"))
        
        unknown_action = threat_menu.addAction("Unknown")
        unknown_action.triggered.connect(lambda: self._set_entity_threat_level(entity, "unknown"))
        
        # Show menu
        menu.exec(self.entity_tree.viewport().mapToGlobal(position))
    
    def _lookup_entity_threat_intel(self, entity):
        """
        Lookup threat intelligence for a specific entity
        
        Args:
            entity: Network entity to lookup
        """
        # Check API key
        api_key = self.config.get("api.virustotal.api_key")
        if not api_key:
            reply = QMessageBox.question(
                self, "API Key Required",
                "VirusTotal API key is not configured. Open settings to configure it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self._open_settings()
            return
        
        # Update status
        self.status_bar.showMessage(f"Looking up threat intelligence for {entity.value}...")
        
        try:
            # Process entity
            ti_data = self.threat_client.process_entity(entity)
            
            if ti_data:
                # Add to session
                self.session.add_threat_intel(entity.id, ti_data)
                
                # Update UI
                self._update_entity_tree()
                self._update_dashboards()
                
                # Show result
                QMessageBox.information(
                    self, "Threat Intelligence Result",
                    f"Entity: {entity.value}\n"
                    f"Verdict: {ti_data.verdict.capitalize()}\n"
                    f"Risk Score: {ti_data.risk_score:.2f}\n\n"
                    f"{ti_data.summary}"
                )
            else:
                QMessageBox.warning(
                    self, "Lookup Failed",
                    f"Failed to get threat intelligence for {entity.value}."
                )
            
            self.status_bar.showMessage("Threat intelligence lookup complete", 3000)
            
        except Exception as e:
            self.logger.error(f"Error looking up threat intel: {str(e)}")
            QMessageBox.critical(
                self, "Error",
                f"Error looking up threat intelligence:\n{str(e)}"
            )
            self.status_bar.showMessage("Threat intelligence lookup failed", 3000)
    
    def _ask_about_entity(self, entity):
        """
        Ask AI about a specific entity
        
        Args:
            entity: Network entity to ask about
        """
        # Check API key
        api_key = self.config.get("api.openai.api_key")
        if not api_key:
            reply = QMessageBox.question(
                self, "API Key Required",
                "OpenAI API key is not configured. Open settings to configure it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self._open_settings()
            return
        
        # Switch to AI Insights tab
        self.tab_widget.setCurrentWidget(self.ai_insights_dashboard)
        
        # Set question about entity
        question = f"What can you tell me about {entity.type} {entity.value}? Is it suspicious?"
        self.ai_insights_dashboard.set_question(question)
    
    def _filter_entity_connections(self, entity):
        """
        Filter connections for a specific entity
        
        Args:
            entity: Network entity to filter connections for
        """
        if entity.type != "ip":
            QMessageBox.information(
                self, "Filter Connections",
                f"Filtering is currently only supported for IP entities."
            )
            return
        
        # Switch to Network Flow dashboard
        self.tab_widget.setCurrentWidget(self.network_flow_dashboard)
        
        # Apply filter
        self.network_flow_dashboard.filter_by_ip(entity.value)
    
    def _set_entity_threat_level(self, entity, level):
        """
        Set threat level for an entity
        
        Args:
            entity: Network entity to update
            level: Threat level to set
        """
        # Update entity
        entity.set_threat_level(level, 0.9)  # High confidence for manual setting
        
        # Update classifier lists
        if hasattr(self, 'threat_classifier') and self.threat_classifier:
            if level == "malicious":
                self.threat_classifier.add_malicious_resource(entity.value, entity.type)
            elif level == "safe":
                self.threat_classifier.add_safe_resource(entity.value, entity.type)
        
        # Update UI
        self._update_entity_tree()
        self._update_dashboards()
        
        self.status_bar.showMessage(f"Set {entity.value} threat level to {level}", 3000)
    
    def _init_dashboards(self):
        """Initialize dashboard tabs"""
        # Clear existing tabs
        self.tab_widget.clear()
        
        # Create dashboards
        self.overview_dashboard = OverviewDashboard(self.session, main_window=self, parent=self)
        self.network_flow_dashboard = NetworkFlowDashboard(self.session, self)
        self.event_analysis_dashboard = EventAnalysisDashboard()
        self.http_analysis_dashboard = HttpAnalysisDashboard(self.session, self)
        self.ai_insights_dashboard = AIInsightsDashboard(self.session, self)
        
        # Set dashboard properties
        for dashboard in [self.overview_dashboard, self.network_flow_dashboard, 
                         self.event_analysis_dashboard, self.http_analysis_dashboard,
                         self.ai_insights_dashboard]:
            dashboard.setProperty("dashboard", True)
        
        # Set session data
        if self.session:
            self.event_analysis_dashboard.set_session(self.session)
        
        # Add global search widget to main layout as hidden widget
        self.search_widget = GlobalSearchWidget()
        # Will use the global stylesheet already applied
        if self.session:
            self.search_widget.set_session(self.session)
        self.search_widget.item_selected.connect(self._on_search_result_selected)
        
        # Add dashboard tabs with clear, simple names
        self.tab_widget.addTab(self.overview_dashboard, "Dashboard")
        self.tab_widget.addTab(self.network_flow_dashboard, "Traffic")
        # Removed Events tab as it's often empty
        self.tab_widget.addTab(self.http_analysis_dashboard, "HTTP Analysis")
        self.tab_widget.addTab(self.ai_insights_dashboard, "AI Analysis")
        
        # Add dedicated search button in toolbar
        search_action = QAction("🔍 Search", self)
        search_action.triggered.connect(self._show_global_search)
        
        # Add to main toolbar if it exists
        for toolbar in self.findChildren(QToolBar):
            if toolbar.objectName() == "mainToolbar":
                toolbar.addSeparator()
                toolbar.addAction(search_action)
                break
        
        # Connect signals
        self.tab_widget.currentChanged.connect(self._tab_changed)
    
    def _update_dashboards(self):
        """Update all dashboards with current session data"""
        if self.overview_dashboard:
            self.overview_dashboard.update_dashboard()
            
        if self.network_flow_dashboard:
            self.network_flow_dashboard.update_dashboard()
            
        if self.event_analysis_dashboard:
            self.event_analysis_dashboard.set_session(self.session)
    
    def _show_global_search(self):
        """Show global search dialog"""
        if not self.session:
            QMessageBox.warning(
                self, "No Active Session",
                "Please create or open a session before using search."
            )
            return
        
        # Create search dialog
        search_dialog = QDialog(self)
        search_dialog.setWindowTitle("Global Search")
        search_dialog.resize(800, 600)
        
        layout = QVBoxLayout(search_dialog)
        
        # Add search widget
        if self.search_widget.parent():
            self.search_widget.setParent(None)
        
        layout.addWidget(self.search_widget)
        
        # Make sure session is set
        self.search_widget.set_session(self.session)
        
        # Show dialog
        search_dialog.exec()
    
    def _on_search_result_selected(self, result):
        """
        Handle search result selection
        
        Args:
            result: Selected search result
        """
        # Close search dialog if open
        if self.sender() and self.sender() == self.search_widget:
            parent_dialog = self.search_widget.parent()
            if isinstance(parent_dialog, QDialog):
                parent_dialog.accept()
        
        # Process result based on type
        item_type = result.get("type", "")
        
        if item_type == "packet":
            # Switch to network flow and filter
            self.tab_widget.setCurrentWidget(self.network_flow_dashboard)
            time_field = result.get("time")
            if time_field:
                self.network_flow_dashboard.focus_on_time(time_field)
            
        elif item_type == "entity":
            # Switch to overview and highlight entity
            self.tab_widget.setCurrentWidget(self.event_analysis_dashboard)
            entity_value = result.get("value")
            if entity_value:
                self.event_analysis_dashboard.focus_on_entity(entity_value)
            
        elif item_type in ["connection", "anomaly"]:
            # Switch to event analysis
            self.tab_widget.setCurrentWidget(self.event_analysis_dashboard)
            # Pass result for highlighting
            time_field = result.get("time")
            if time_field:
                self.event_analysis_dashboard.focus_on_time(time_field)
    
    def _update_entity_tree(self):
        """Update entity tree with current session data"""
        self.entity_tree.clear()
        
        if not self.session or not hasattr(self.session, 'network_entities'):
            return
        
        # Group entities by type
        entity_types = {}
        for entity_id, entity in self.session.network_entities.items():
            if entity.type not in entity_types:
                entity_types[entity.type] = []
            entity_types[entity.type].append(entity)
        
        # Add entity type groups
        for entity_type, entities in entity_types.items():
            # Create type group
            type_item = QTreeWidgetItem(self.entity_tree)
            type_item.setText(0, f"{entity_type.capitalize()} ({len(entities)})")
            type_item.setExpanded(False)
            
            # Sort entities by threat level
            entities.sort(key=lambda e: (
                {"malicious": 0, "suspicious": 1, "unknown": 2, "safe": 3}.get(e.threat_level, 4),
                e.value
            ))
            
            # Add entities
            for entity in entities:
                entity_item = QTreeWidgetItem(type_item)
                entity_item.setText(0, entity.value)
                entity_item.setText(1, entity.type)
                entity_item.setText(2, entity.threat_level.capitalize())
                
                # Store entity ID in item data
                entity_item.setData(0, Qt.ItemDataRole.UserRole, entity.id)
                
                # Set item style based on threat level with modern badge-like display
                font = entity_item.font(2)
                font.setBold(True)
                entity_item.setFont(2, font)
                
                # Create modern "badge" appearance for threat level
                if entity.threat_level == "malicious":
                    entity_item.setForeground(2, QColor(255, 255, 255))  # White text
                    entity_item.setBackground(2, QColor(185, 28, 28))    # Bright red background (matches CSS)
                    entity_item.setText(2, "   MALICIOUS   ")  # Add padding for better appearance
                elif entity.threat_level == "suspicious":
                    entity_item.setForeground(2, QColor(255, 255, 255))  # White text
                    entity_item.setBackground(2, QColor(217, 119, 6))    # Bright orange background (matches CSS)
                    entity_item.setText(2, "   SUSPICIOUS   ")
                elif entity.threat_level == "safe":
                    entity_item.setForeground(2, QColor(255, 255, 255))  # White text
                    entity_item.setBackground(2, QColor(21, 128, 61))    # Bright green background (matches CSS)
                    entity_item.setText(2, "   SAFE   ")
                else:  # unknown
                    entity_item.setForeground(2, QColor(255, 255, 255))  # White text
                    entity_item.setBackground(2, QColor(75, 85, 99))     # Gray background (matches CSS)
                    entity_item.setText(2, "   UNKNOWN   ")
        
        # Resize columns to content
        for i in range(self.entity_tree.columnCount()):
            self.entity_tree.resizeColumnToContents(i)
    
    def _update_window_title(self):
        """Update window title with session name"""
        if self.session:
            self.setWindowTitle(f"Net4 - {self.session.name}")
        else:
            self.setWindowTitle("Net4 - Network Forensic Analysis")
    
    def _is_session_modified(self):
        """
        Check if the current session has been modified
        
        Returns:
            bool: True if session is modified, False otherwise
        """
        # This is a simplified check
        # In a real implementation, we'd track modifications more carefully
        if not self.session:
            return False
        
        # Check if session has any data
        has_packets = hasattr(self.session, 'packets') and bool(self.session.packets)
        has_entities = hasattr(self.session, 'network_entities') and bool(self.session.network_entities)
        has_connections = hasattr(self.session, 'connections') and bool(self.session.connections)
        has_anomalies = hasattr(self.session, 'anomalies') and bool(self.session.anomalies)
        has_threat_intel = hasattr(self.session, 'threat_intelligence') and bool(self.session.threat_intelligence)
        
        return has_packets or has_entities or has_connections or has_anomalies or has_threat_intel
    
    def _update_progress(self, current, total):
        """
        Update progress bar
        
        Args:
            current: Current progress value
            total: Total progress value
        """
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)
            self.status_bar.showMessage(f"Processed {current} / {total} packets")
        else:
            # For live capture we only know current count
            self.progress_bar.setMaximum(0)  # Indeterminate mode
            self.status_bar.showMessage(f"Captured {current} packets...")
    
    def _update_progress_with_message(self, message, progress):
        """
        Update progress bar with message
        
        Args:
            message: Status message
            progress: Progress value (0.0 to 1.0)
        """
        self.status_bar.showMessage(message)
        self.progress_bar.setValue(int(progress * 100))
    
    def _pcap_processing_complete(self, result):
        """
        Handle PCAP processing completion
        
        Args:
            result: Processing result
        """
        self.progress_bar.setVisible(False)
        
        if "error" in result:
            QMessageBox.critical(
                self, "Error Processing PCAP",
                f"An error occurred while processing the PCAP file:\n{result['error']}"
            )
            self.status_bar.showMessage("PCAP processing failed", 3000)
            return
        
        # Update UI
        self._update_entity_tree()
        self._update_dashboards()
        
        # Run threat classifier
        self.threat_classifier = ThreatClassifier(self.session)
        self.threat_classifier.classify_session_entities()
        
        # Show result
        self.status_bar.showMessage(
            f"PCAP processing complete: {result.get('processed_count', 0)} packets, "
            f"{result.get('ip_entities', 0)} IPs, {result.get('domain_entities', 0)} domains",
            5000
        )
        
        # Run automatic rules evaluation if enabled
        if (self.config.get("analysis.enable_custom_rules", True) and 
            self.config.get("detection.run_rules_on_import", True) and
            len(self.rule_engine.rules) > 0):
            
            # Show message that rules evaluation is starting
            self.status_bar.showMessage("Running automatic rules evaluation...", 2000)
            
            # Run rules evaluation after a short delay
            QTimer.singleShot(2000, self._run_rules_evaluation)
    
    def _ai_analysis_complete(self, result):
        """
        Handle AI analysis completion
        
        Args:
            result: Analysis result
        """
        self.progress_bar.setVisible(False)
        
        if "error" in result:
            QMessageBox.critical(
                self, "Error in AI Analysis",
                f"An error occurred during AI analysis:\n{result['error']}"
            )
            self.status_bar.showMessage("AI analysis failed", 3000)
            return
        
        # Update UI
        self._update_dashboards()
        
        # Show result
        if "summary" in result or "raw_response" in result:
            self.status_bar.showMessage("AI analysis complete", 3000)
            
            # Switch to AI Insights dashboard
            self.tab_widget.setCurrentWidget(self.ai_insights_dashboard)
        else:
            self.status_bar.showMessage("AI analysis complete, but no summary generated", 3000)
    
    def _ai_question_complete(self, result):
        """
        Handle AI question completion
        
        Args:
            result: Question result
        """
        self.progress_bar.setVisible(False)
        
        if "error" in result:
            QMessageBox.critical(
                self, "Error in AI Response",
                f"An error occurred while processing your question:\n{result['error']}"
            )
            self.status_bar.showMessage("AI question processing failed", 3000)
            return
        
        # Update AI Insights dashboard with answer
        if self.ai_insights_dashboard:
            self.ai_insights_dashboard.add_answer(result)
        
        # Show status
        self.status_bar.showMessage("Question answered", 3000)
    
    def _anomaly_detection_complete(self, anomalies):
        """
        Handle anomaly detection completion
        
        Args:
            anomalies: List of detected anomalies
        """
        self.progress_bar.setVisible(False)
        
        if anomalies and isinstance(anomalies, dict) and "error" in anomalies:
            QMessageBox.critical(
                self, "Error in Anomaly Detection",
                f"An error occurred during anomaly detection:\n{anomalies['error']}"
            )
            self.status_bar.showMessage("Anomaly detection failed", 3000)
            return
        
        # Update UI
        self._update_dashboards()
        
        # Show result
        self.status_bar.showMessage(f"Anomaly detection complete: {len(anomalies)} anomalies found", 3000)
        
        # If anomalies found, show dialog
        if anomalies:
            # Count by severity
            severity_counts = {"high": 0, "medium": 0, "low": 0}
            for anomaly in anomalies:
                severity = anomaly.get("severity", "low")
                severity_counts[severity] += 1
            
            QMessageBox.information(
                self, "Anomaly Detection Results",
                f"Found {len(anomalies)} anomalies:\n"
                f"• High severity: {severity_counts['high']}\n"
                f"• Medium severity: {severity_counts['medium']}\n"
                f"• Low severity: {severity_counts['low']}\n\n"
                f"View details in the Overview dashboard."
            )
            
            # Switch to overview dashboard
            self.tab_widget.setCurrentWidget(self.overview_dashboard)
    
    def _threat_intel_complete(self, result):
        """
        Handle threat intelligence lookup completion
        
        Args:
            result: Lookup result
        """
        self.progress_bar.setVisible(False)
        
        if "error" in result:
            QMessageBox.critical(
                self, "Error in Threat Intelligence Lookup",
                f"An error occurred during threat intelligence lookup:\n{result['error']}"
            )
            self.status_bar.showMessage("Threat intelligence lookup failed", 3000)
            return
        
        # Update UI
        self._update_entity_tree()
        self._update_dashboards()
        
        # Show result
        self.status_bar.showMessage(
            f"Threat intelligence lookup complete: {result.get('success', 0)} entities processed",
            3000
        )
        
        # If malicious entities found, show dialog
        if hasattr(self.session, 'network_entities'):
            malicious_count = len([e for e in self.session.network_entities.values() 
                                  if e.threat_level == "malicious"])
            
            suspicious_count = len([e for e in self.session.network_entities.values() 
                                   if e.threat_level == "suspicious"])
            
            if malicious_count > 0 or suspicious_count > 0:
                QMessageBox.warning(
                    self, "Threat Intelligence Results",
                    f"Found potentially malicious entities:\n"
                    f"• Malicious: {malicious_count}\n"
                    f"• Suspicious: {suspicious_count}\n\n"
                    f"View details in the Overview dashboard."
                )
                
                # Switch to overview dashboard
                self.tab_widget.setCurrentWidget(self.overview_dashboard)
    
    def _tab_changed(self, index):
        """
        Handle tab change event
        
        Args:
            index: New tab index
        """
        # Update current dashboard
        current_dashboard = self.tab_widget.widget(index)
        if current_dashboard:
            current_dashboard.update_dashboard()
    
    def closeEvent(self, event):
        """
        Handle window close event
        
        Args:
            event: Close event
        """
        # Ask to save current session if modified
        if self.session and self._is_session_modified():
            reply = QMessageBox.question(
                self, "Save Session",
                "Do you want to save the current session before exiting?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
            )
            
            if reply == QMessageBox.StandardButton.Cancel:
                event.ignore()
                return
            elif reply == QMessageBox.StandardButton.Yes:
                if not self._save_session():
                    event.ignore()
                    return
        
        # Save window state
        self._save_window_state()
        
        # Accept close event
        event.accept()