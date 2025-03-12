import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional

from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QSplitter, QMenu, QMenuBar, QToolBar, 
    QStatusBar, QFileDialog, QMessageBox, QApplication, QVBoxLayout, 
    QHBoxLayout, QWidget, QTreeWidget, QTreeWidgetItem, QLabel, 
    QProgressBar, QDockWidget, QDialog
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QThread, QSettings, QObject, QMetaObject
from PyQt6.QtGui import QIcon, QAction, QPixmap

from .dashboards.overview import OverviewDashboard
from .dashboards.network_flow import NetworkFlowDashboard
from .dashboards.timeline import TimelineDashboard
from .dashboards.graph_view import GraphViewDashboard
from .dashboards.ai_insights import AIInsightsDashboard  # New import for AI Insights dashboard
from .dialogs.settings import SettingsDialog
from .dialogs.export import ExportDialog

from ..models.session import Session
from ..core.data_ingestion.pcap import PcapProcessor
from ..core.data_ingestion.log_parser import LogParser
from ..core.analysis.ai_engine import AIEngine
from ..core.analysis.anomaly import AnomalyDetector
from ..core.ti.virustotal import VirusTotalClient
from ..core.ti.classifier import ThreatClassifier
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

class LogSignals(QObject):
    """Signal class for thread-safe log processing callbacks"""
    progress_updated = pyqtSignal(int, int)        # current, total
    processing_complete = pyqtSignal(dict)         # result dictionary

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
        
        # Log signals
        self.log_signals = LogSignals()
        self.log_signals.progress_updated.connect(self._update_progress)
        self.log_signals.processing_complete.connect(self._log_processing_complete)
        
        # Dashboards
        self.overview_dashboard = None
        self.network_flow_dashboard = None
        self.timeline_dashboard = None
        self.graph_view_dashboard = None
        self.ai_insights_dashboard = None  # Added AI Insights dashboard
        
        # Core components
        self.pcap_processor = None
        self.log_parser = None
        self.ai_engine = AIEngine(self.config)
        self.threat_client = VirusTotalClient(self.config)
        self.threat_classifier = None
        
        # Initialize UI
        self._init_ui()
        
        # Create new session
        self._new_session()
    
    def _init_ui(self):
        """Initialize user interface"""
        # Set window properties
        self.setWindowTitle("Net4 - Network Forensic Analysis")
        self.resize(1200, 800)
        
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
    
    def _create_menu(self):
        """Create application menu"""
        # File menu
        file_menu = self.menuBar().addMenu("&File")
        
        new_action = QAction(QIcon.fromTheme("document-new"), "&New Session", self)
        new_action.setShortcut("Ctrl+N")
        new_action.triggered.connect(self._new_session)
        file_menu.addAction(new_action)
        
        open_action = QAction(QIcon.fromTheme("document-open"), "&Open Session", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._open_session)
        file_menu.addAction(open_action)
        
        save_action = QAction(QIcon.fromTheme("document-save"), "&Save Session", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self._save_session)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        import_menu = file_menu.addMenu("&Import")
        
        import_pcap_action = QAction("Import &PCAP File", self)
        import_pcap_action.triggered.connect(self._import_pcap)
        import_menu.addAction(import_pcap_action)
        
        import_log_action = QAction("Import &Log File", self)
        import_log_action.triggered.connect(self._import_log)
        import_menu.addAction(import_log_action)
        
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
        
        analyze_ai_action = QAction("AI &Analysis", self)
        analyze_ai_action.triggered.connect(self._run_ai_analysis)
        analysis_menu.addAction(analyze_ai_action)
        
        ai_chat_action = QAction("AI &Chat Assistant", self)
        ai_chat_action.triggered.connect(self._open_ai_chat)
        analysis_menu.addAction(ai_chat_action)
        
        detect_anomalies_action = QAction("Detect &Anomalies", self)
        detect_anomalies_action.triggered.connect(self._detect_anomalies)
        analysis_menu.addAction(detect_anomalies_action)
        
        threat_intel_action = QAction("&Threat Intelligence Lookup", self)
        threat_intel_action.triggered.connect(self._lookup_threat_intel)
        analysis_menu.addAction(threat_intel_action)
        
        # Tools menu
        tools_menu = self.menuBar().addMenu("&Tools")
        
        settings_action = QAction(QIcon.fromTheme("preferences-system"), "&Settings", self)
        settings_action.triggered.connect(self._open_settings)
        tools_menu.addAction(settings_action)
        
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
        """Create application toolbar"""
        main_toolbar = QToolBar("Main Toolbar", self)
        main_toolbar.setObjectName("mainToolbar")  # Set object name to avoid Qt warning
        main_toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(main_toolbar)
        
        # New session
        new_action = QAction(QIcon.fromTheme("document-new", QIcon("assets/icons/new.png")), "New Session", self)
        new_action.triggered.connect(self._new_session)
        main_toolbar.addAction(new_action)
        
        # Open session
        open_action = QAction(QIcon.fromTheme("document-open", QIcon("assets/icons/open.png")), "Open Session", self)
        open_action.triggered.connect(self._open_session)
        main_toolbar.addAction(open_action)
        
        # Save session
        save_action = QAction(QIcon.fromTheme("document-save", QIcon("assets/icons/save.png")), "Save Session", self)
        save_action.triggered.connect(self._save_session)
        main_toolbar.addAction(save_action)
        
        main_toolbar.addSeparator()
        
        # Import PCAP
        import_pcap_action = QAction(QIcon("assets/icons/pcap.png"), "Import PCAP", self)
        import_pcap_action.triggered.connect(self._import_pcap)
        main_toolbar.addAction(import_pcap_action)
        
        # Import log
        import_log_action = QAction(QIcon("assets/icons/log.png"), "Import Log", self)
        import_log_action.triggered.connect(self._import_log)
        main_toolbar.addAction(import_log_action)
        
        main_toolbar.addSeparator()
        
        # AI analysis
        ai_action = QAction(QIcon("assets/icons/ai.png"), "AI Analysis", self)
        ai_action.triggered.connect(self._run_ai_analysis)
        main_toolbar.addAction(ai_action)
        
        # AI chat
        ai_chat_action = QAction(QIcon("assets/icons/chat.png"), "AI Chat", self)
        ai_chat_action.triggered.connect(self._open_ai_chat)
        main_toolbar.addAction(ai_chat_action)
        
        # Anomaly detection
        anomaly_action = QAction(QIcon("assets/icons/anomaly.png"), "Detect Anomalies", self)
        anomaly_action.triggered.connect(self._detect_anomalies)
        main_toolbar.addAction(anomaly_action)
        
        # Threat intelligence
        threat_action = QAction(QIcon("assets/icons/threat.png"), "Threat Intelligence", self)
        threat_action.triggered.connect(self._lookup_threat_intel)
        main_toolbar.addAction(threat_action)
    
    def _setup_entity_dock(self):
        """Setup entity dock panel"""
        self.entity_dock.setObjectName("networkEntitiesDock")  # Set object name to avoid Qt warning
        
        # Create tree widget
        self.entity_tree = QTreeWidget()
        self.entity_tree.setHeaderLabels(["Entity", "Type", "Threat Level"])
        self.entity_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.entity_tree.customContextMenuRequested.connect(self._show_entity_context_menu)
        
        # Set dock widget
        self.entity_dock.setWidget(self.entity_tree)
        self.entity_dock.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | 
                                        Qt.DockWidgetArea.RightDockWidgetArea)
        
        # Add dock to main window
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.entity_dock)
    
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
        
        # Initialize core components with TShark path from config
        tshark_path = self.config.get("paths.tshark", "")
        self.pcap_processor = PcapProcessor(self.session, tshark_path=tshark_path)
        self.log_parser = LogParser(self.session)
        
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
            
            # Initialize core components with TShark path from config
            tshark_path = self.config.get("paths.tshark", "")
            self.pcap_processor = PcapProcessor(self.session, tshark_path=tshark_path)
            self.log_parser = LogParser(self.session)
            
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
        """Import log file for analysis"""
        if not self.session:
            self._new_session()
        
        # Get log file path
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Log File", "",
            "Log Files (*.log *.txt *.csv);;All Files (*)"
        )
        
        if not file_path:
            return
        
        # Update status
        self.status_bar.showMessage("Processing log file...")
        self.progress_bar.setVisible(True)
        
        # Process log asynchronously using our signal handlers
        self.log_parser.process_file_async(
            file_path,
            progress_callback=self.log_signals.progress_updated.emit,
            completion_callback=self.log_signals.processing_complete.emit
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
                "Please import data (PCAP, logs) before running analysis."
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
                "Please import data (PCAP, logs) before using AI chat."
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
                "Please import data (PCAP, logs) before running anomaly detection."
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
    
    def _open_settings(self):
        """Open settings dialog"""
        dialog = SettingsDialog(self.config, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Update components with new settings
            self.ai_engine = AIEngine(self.config)
            self.threat_client = VirusTotalClient(self.config)
            
            # Update TShark path if session exists
            if self.session and self.pcap_processor:
                tshark_path = self.config.get("paths.tshark", "")
                if tshark_path:
                    self.pcap_processor.tshark_path = tshark_path
    
    def _show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self, "About Net4",
            f"<h2>Net4 - Network Forensic Analysis</h2>"
            f"<p>Version 1.0.0</p>"
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
        self.overview_dashboard = OverviewDashboard(self.session, self)
        self.network_flow_dashboard = NetworkFlowDashboard(self.session, self)
        self.timeline_dashboard = TimelineDashboard(self.session, self)
        self.graph_view_dashboard = GraphViewDashboard(self.session, self)
        self.ai_insights_dashboard = AIInsightsDashboard(self.session, self, self)
        
        # Add dashboard tabs
        self.tab_widget.addTab(self.overview_dashboard, "Overview")
        self.tab_widget.addTab(self.network_flow_dashboard, "Network Flow")
        self.tab_widget.addTab(self.timeline_dashboard, "Timeline")
        self.tab_widget.addTab(self.graph_view_dashboard, "Graph View")
        self.tab_widget.addTab(self.ai_insights_dashboard, "AI Assistant")
        
        # Connect signals
        self.tab_widget.currentChanged.connect(self._tab_changed)
    
    def _update_dashboards(self):
        """Update all dashboards with current session data"""
        if self.overview_dashboard:
            self.overview_dashboard.update_dashboard()
            
        if self.network_flow_dashboard:
            self.network_flow_dashboard.update_dashboard()
            
        if self.timeline_dashboard:
            self.timeline_dashboard.update_dashboard()
            
        if self.graph_view_dashboard:
            self.graph_view_dashboard.update_dashboard()
            
        if self.ai_insights_dashboard:
            self.ai_insights_dashboard.update_dashboard()
    
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
                
                # Set item color based on threat level
                if entity.threat_level == "malicious":
                    entity_item.setForeground(2, Qt.GlobalColor.red)
                elif entity.threat_level == "suspicious":
                    entity_item.setForeground(2, Qt.GlobalColor.darkYellow)
                elif entity.threat_level == "safe":
                    entity_item.setForeground(2, Qt.GlobalColor.darkGreen)
        
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
    
    def _log_processing_complete(self, result):
        """
        Handle log processing completion
        
        Args:
            result: Processing result
        """
        self.progress_bar.setVisible(False)
        
        if "error" in result:
            QMessageBox.critical(
                self, "Error Processing Log",
                f"An error occurred while processing the log file:\n{result['error']}"
            )
            self.status_bar.showMessage("Log processing failed", 3000)
            return
        
        # Update UI
        self._update_entity_tree()
        self._update_dashboards()
        
        # Run threat classifier
        self.threat_classifier = ThreatClassifier(self.session)
        self.threat_classifier.classify_session_entities()
        
        # Show result
        self.status_bar.showMessage(
            f"Log processing complete: {result.get('processed_lines', 0)} lines, "
            f"{result.get('matched_lines', 0)} matched, "
            f"{result.get('ip_entities', 0)} IPs, {result.get('domain_entities', 0)} domains",
            5000
        )
    
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