from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton,
    QToolButton, QComboBox, QMenu, QButtonGroup,
    QRadioButton, QCheckBox, QFrame, QDialog, QGridLayout,
    QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtGui import QIcon, QFont, QAction

class DashboardToolbar(QFrame):
    """
    A toolbar with controls for dashboard operations such as
    refresh, time range selection, and view options.
    """
    
    # Signals emitted when toolbar controls are used
    refresh_clicked = pyqtSignal()
    time_range_changed = pyqtSignal(str)
    view_option_changed = pyqtSignal(str)
    export_clicked = pyqtSignal(str)  # Export format
    settings_clicked = pyqtSignal()
    
    def __init__(self, parent=None):
        """
        Initialize dashboard toolbar
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Set frame properties
        self.setObjectName("dashboardToolbar")
        self.setStyleSheet("""
            #dashboardToolbar {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: 5px;
            }
        """)
        self.setMinimumHeight(50)
        self.setMaximumHeight(50)
        
        # Create main layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 0, 10, 0)
        layout.setSpacing(15)
        
        # Add refresh button with text
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setIcon(QIcon("assets/icons/refresh.png"))
        self.refresh_button.setStyleSheet("""
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
        self.refresh_button.clicked.connect(self._refresh_clicked)
        layout.addWidget(self.refresh_button)
        
        # Add time range selector
        self.time_layout = QHBoxLayout()
        
        self.time_label = QLabel("Time Range:")
        self.time_label.setStyleSheet("color: #ffffff;")
        self.time_layout.addWidget(self.time_label)
        
        self.time_selector = QComboBox()
        self.time_selector.setStyleSheet("""
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
            QComboBox::down-arrow {
                image: url(assets/icons/down_arrow.png);
                width: 12px;
                height: 12px;
            }
            QComboBox QAbstractItemView {
                background-color: #323242;
                color: #ffffff;
                selection-background-color: #2d74da;
                selection-color: #ffffff;
                border: 1px solid #414558;
                outline: none;
            }
        """)
        
        # Add time range options
        self.time_selector.addItem("All Time")
        self.time_selector.addItem("Last Hour")
        self.time_selector.addItem("Last 24 Hours")
        self.time_selector.addItem("Last 7 Days")
        self.time_selector.addItem("Last 30 Days")
        self.time_selector.addItem("Custom Range...")
        
        self.time_selector.currentTextChanged.connect(self._time_range_changed)
        self.time_layout.addWidget(self.time_selector)
        
        layout.addLayout(self.time_layout)
        
        # Add view options
        self.view_options_layout = QHBoxLayout()
        
        self.view_label = QLabel("View Mode:")
        self.view_label.setStyleSheet("color: #ffffff;")
        self.view_options_layout.addWidget(self.view_label)
        
        self.view_selector = QComboBox()
        self.view_selector.setStyleSheet("""
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
            QComboBox::down-arrow {
                image: url(assets/icons/down_arrow.png);
                width: 12px;
                height: 12px;
            }
            QComboBox QAbstractItemView {
                background-color: #323242;
                color: #ffffff;
                selection-background-color: #2d74da;
                selection-color: #ffffff;
                border: 1px solid #414558;
                outline: none;
            }
        """)
        
        # Add view options
        self.view_selector.addItem("Default")
        self.view_selector.addItem("Compact")
        self.view_selector.addItem("Detailed")
        self.view_selector.addItem("Charts Only")
        self.view_selector.addItem("Tables Only")
        
        self.view_selector.currentTextChanged.connect(self._view_option_changed)
        self.view_options_layout.addWidget(self.view_selector)
        
        layout.addLayout(self.view_options_layout)
        
        # Add spacer to push export and settings to the right
        layout.addStretch()
        
        # Add export button with menu
        self.export_button = QPushButton("Export")
        self.export_button.setIcon(QIcon("assets/icons/export.png"))
        self.export_button.setStyleSheet("""
            QPushButton {
                background-color: #323242;
                color: #ffffff;
                border-radius: 4px;
                padding: 5px 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #414558;
            }
            QPushButton:pressed {
                background-color: #2d74da;
            }
        """)
        
        # Create export menu
        self.export_menu = QMenu(self)
        self.export_menu.setStyleSheet("""
            QMenu {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                border-radius: 3px;
                padding: 5px;
            }
            QMenu::item {
                padding: 5px 20px 5px 20px;
            }
            QMenu::item:selected {
                background-color: #2d74da;
            }
            QMenu::separator {
                height: 1px;
                background-color: #414558;
                margin: 5px 15px 5px 15px;
            }
        """)
        
        # Add export options
        self.export_menu.addAction("Export as PDF").triggered.connect(
            lambda: self._export_clicked("pdf"))
        self.export_menu.addAction("Export as CSV").triggered.connect(
            lambda: self._export_clicked("csv"))
        self.export_menu.addAction("Export as PNG").triggered.connect(
            lambda: self._export_clicked("png"))
        
        self.export_button.setMenu(self.export_menu)
        layout.addWidget(self.export_button)
        
        # Add settings button
        self.settings_button = QToolButton()
        self.settings_button.setIcon(QIcon("assets/icons/settings.png"))
        self.settings_button.setIconSize(QSize(18, 18))
        self.settings_button.setToolTip("Dashboard Settings")
        self.settings_button.setStyleSheet("""
            QToolButton {
                background-color: transparent;
                border: none;
                padding: 4px;
            }
            QToolButton:hover {
                background-color: #414558;
                border-radius: 3px;
            }
            QToolButton:pressed {
                background-color: #2d74da;
            }
        """)
        self.settings_button.clicked.connect(self._settings_clicked)
        layout.addWidget(self.settings_button)
    
    def _refresh_clicked(self):
        """Handle refresh button click"""
        self.refresh_clicked.emit()
    
    def _time_range_changed(self, time_range):
        """
        Handle time range selection change
        
        Args:
            time_range (str): Selected time range
        """
        if time_range == "Custom Range...":
            # Handle custom range selection through a dialog
            # For now, just emit the signal with the selected range
            self.time_range_changed.emit(time_range)
        else:
            self.time_range_changed.emit(time_range)
    
    def _view_option_changed(self, view_option):
        """
        Handle view option selection change
        
        Args:
            view_option (str): Selected view option
        """
        self.view_option_changed.emit(view_option)
    
    def _export_clicked(self, export_format):
        """
        Handle export option selection
        
        Args:
            export_format (str): Selected export format
        """
        self.export_clicked.emit(export_format)
    
    def _settings_clicked(self):
        """Handle settings button click"""
        self.settings_clicked.emit()
    
    def update_time_range(self, time_range):
        """
        Update time range selection without triggering signals
        
        Args:
            time_range (str): Time range to select
        """
        # Block signals to prevent triggering the change event
        self.time_selector.blockSignals(True)
        
        # Set the current index to match the given time range
        index = self.time_selector.findText(time_range)
        if index >= 0:
            self.time_selector.setCurrentIndex(index)
        
        # Unblock signals
        self.time_selector.blockSignals(False)
    
    def update_view_option(self, view_option):
        """
        Update view option selection without triggering signals
        
        Args:
            view_option (str): View option to select
        """
        # Block signals to prevent triggering the change event
        self.view_selector.blockSignals(True)
        
        # Set the current index to match the given view option
        index = self.view_selector.findText(view_option)
        if index >= 0:
            self.view_selector.setCurrentIndex(index)
        
        # Unblock signals
        self.view_selector.blockSignals(False)
    
    def add_custom_control(self, widget):
        """
        Add a custom control to the toolbar before the export button
        
        Args:
            widget: Widget to add
        """
        # Get index of export button
        export_index = self.layout().indexOf(self.export_button)
        
        # Insert widget before export button
        if export_index >= 0:
            self.layout().insertWidget(export_index, widget)
        else:
            # Fallback: insert before stretch
            stretch_index = -1
            for i in range(self.layout().count()):
                if self.layout().itemAt(i).spacerItem():
                    stretch_index = i
                    break
            
            if stretch_index >= 0:
                self.layout().insertWidget(stretch_index, widget)
            else:
                # Last resort: add at the end
                self.layout().addWidget(widget)