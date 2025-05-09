from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QToolButton, QSizePolicy, QScrollArea
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QIcon, QFont, QColor, QPalette

class DashboardCard(QFrame):
    """
    A collapsible card widget for dashboard sections with a
    title header and content area.
    """
    
    # Signal emitted when the card is collapsed or expanded
    toggle_collapsed = pyqtSignal(bool)  # True when collapsed
    
    def __init__(self, title, parent=None, collapsible=True, collapsed=False, show_refresh=True):
        """
        Initialize the dashboard card
        
        Args:
            title (str): Card title
            parent: Parent widget
            collapsible (bool): Whether the card is collapsible
            collapsed (bool): Initial collapsed state
            show_refresh (bool): Whether to show the refresh button
        """
        super().__init__(parent)
        
        # Store parameters
        self.title_text = title
        self.is_collapsible = collapsible
        self.is_collapsed = collapsed
        
        # Set frame properties with improved styling
        self.setObjectName("dashboardCard")
        self.setStyleSheet("""
            #dashboardCard {
                background-color: #282838;
                border-radius: 8px;
                border: 1px solid #414558;
                margin: 5px;
            }
        """)
        
        # Create layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        
        # Create header with improved styling
        self.header = QFrame()
        self.header.setObjectName("dashboardCardHeader")
        self.header.setStyleSheet("""
            #dashboardCardHeader {
                background-color: #323242;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border-bottom: 1px solid #414558;
                padding: 12px;
            }
        """)
        self.header.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        
        # Create header layout with better spacing
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(12, 6, 12, 6)
        
        # Title label with more prominent styling
        self.title_label = QLabel(title)
        font = QFont()
        font.setBold(True)
        font.setPointSize(12)  # Larger font size
        self.title_label.setFont(font)
        self.title_label.setStyleSheet("color: #ffffff; font-size: 13pt;")
        header_layout.addWidget(self.title_label)
        
        # Add spacer to push controls to the right
        header_layout.addStretch()
        
        # Create header controls
        self.controls_layout = QHBoxLayout()
        self.controls_layout.setSpacing(8)  # More space between buttons
        
        # Add refresh button (optional)
        if show_refresh:
            self.refresh_button = QToolButton()
            self.refresh_button.setText("↻")
            self.refresh_button.setToolTip("Refresh data")
            self.refresh_button.setStyleSheet("""
                QToolButton {
                    background-color: transparent;
                    border: none;
                    padding: 5px;
                }
                QToolButton:hover { background-color: #414558; border-radius: 5px; }
                QToolButton:pressed { background-color: #2d74da; }
            """)
            self.controls_layout.addWidget(self.refresh_button)
        else:
            self.refresh_button = None
        
        # Only add settings button if it's actually needed (simplify UI)
        if False:  # Changed to False to remove rarely used settings button
            self.settings_button = QToolButton()
            self.settings_button.setIcon(QIcon("assets/icons/settings.png"))
            self.settings_button.setIconSize(QSize(18, 18))  # Larger icon
            self.settings_button.setToolTip("Settings")
            self.settings_button.setStyleSheet("""
                QToolButton {
                    background-color: transparent;
                    border: none;
                    padding: 5px;
                }
                QToolButton:hover {
                    background-color: #414558;
                    border-radius: 5px;
                }
                QToolButton:pressed {
                    background-color: #2d74da;
                }
            """)
            self.controls_layout.addWidget(self.settings_button)
        else:
            # Add empty settings button to maintain interface
            self.settings_button = QToolButton()
            self.settings_button.setVisible(False)
        
        # Add collapse button if card is collapsible
        if collapsible:
            self.collapse_button = QToolButton()
            self.collapse_button.setText("▼" if not collapsed else "▲")
            self.collapse_button.setToolTip("Collapse section" if not collapsed else "Expand section")
            self.collapse_button.setStyleSheet("""
                QToolButton {
                    background-color: transparent;
                    border: none;
                    padding: 5px;
                }
                QToolButton:hover {
                    background-color: #414558;
                    border-radius: 5px;
                }
                QToolButton:pressed {
                    background-color: #2d74da;
                }
            """)
            self.collapse_button.clicked.connect(self.toggle_collapse)
            self.controls_layout.addWidget(self.collapse_button)
        
        # Hide controls_layout if empty
        if self.controls_layout.count() == 0:
            self.controls_layout.setParent(None)
        
        # Add controls to header (if not empty)
        header_layout.addLayout(self.controls_layout)
        
        # Add header to main layout
        self.main_layout.addWidget(self.header)
        
        # Create content area with scroll capability and improved styling
        self.scroll_area = QScrollArea()
        self.scroll_area.setObjectName("dashboardCardContent")
        self.scroll_area.setStyleSheet("""
            #dashboardCardContent {
                background-color: transparent;
                border: none;
            }
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QScrollBar:vertical {
                background-color: #282838;
                width: 16px;  /* Wider scrollbar for easier use */
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #414558;
                min-height: 30px;  /* Larger handle for better grip */
                border-radius: 8px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #2d74da;  /* More visible on hover */
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        
        # Create content widget with better styling
        self.content = QWidget()
        self.content.setObjectName("cardContentWidget")
        self.content.setStyleSheet("""
            #cardContentWidget {
                background-color: transparent;
            }
        """)
        
        # Set content layout with more generous spacing
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(20, 20, 20, 20)  # More padding
        self.content_layout.setSpacing(15)  # More space between elements
        
        # Set content widget to scroll area
        self.scroll_area.setWidget(self.content)
        
        # Add scroll area to main layout
        # Set reasonable minimum height but allow resizing
        self.scroll_area.setMinimumHeight(300)
        self.main_layout.addWidget(self.scroll_area)
        
        # Initialize collapsed state
        if collapsed and collapsible:
            self.collapse(animate=False)
    
    def toggle_collapse(self):
        """Toggle the collapsed state of the card"""
        if self.is_collapsed:
            self.expand()
        else:
            self.collapse()
    
    def collapse(self, animate=True):
        """
        Collapse the card
        
        Args:
            animate (bool): Whether to animate the collapse
        """
        if not self.is_collapsible:
            return
        
        if animate:
            # Create animation
            self.animation = QPropertyAnimation(self.scroll_area, b"maximumHeight")
            self.animation.setDuration(300)
            self.animation.setStartValue(self.scroll_area.height())
            self.animation.setEndValue(0)
            self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            self.animation.start()
        else:
            # Just hide immediately
            self.scroll_area.setMaximumHeight(0)
        
        # Update state
        self.is_collapsed = True
        
        # Update button text when collapsed
        if hasattr(self, 'collapse_button'):
            self.collapse_button.setText("▲")
            self.collapse_button.setToolTip("Expand card")
        
        # Emit signal
        self.toggle_collapsed.emit(True)
    
    def expand(self, animate=True):
        """
        Expand the card
        
        Args:
            animate (bool): Whether to animate the expansion
        """
        if not self.is_collapsible:
            return
        
        if animate:
            # Create animation
            self.animation = QPropertyAnimation(self.scroll_area, b"maximumHeight")
            self.animation.setDuration(300)
            self.animation.setStartValue(0)
            # Use a large number to allow content to determine height
            self.animation.setEndValue(16777215)  # QWIDGETSIZE_MAX
            self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            self.animation.start()
        else:
            # Just show immediately
            self.scroll_area.setMaximumHeight(16777215)  # QWIDGETSIZE_MAX
        
        # Update state
        self.is_collapsed = False
        
        # Update button text when expanded
        if hasattr(self, 'collapse_button'):
            self.collapse_button.setText("▼")
            self.collapse_button.setToolTip("Collapse card")
        
        # Emit signal
        self.toggle_collapsed.emit(False)
    
    def set_title(self, title):
        """
        Set the card title
        
        Args:
            title (str): New card title
        """
        self.title_text = title
        self.title_label.setText(title)
    
    def add_widget(self, widget):
        """
        Add a widget to the card content area
        
        Args:
            widget: Widget to add
        """
        self.content_layout.addWidget(widget)
    
    def add_layout(self, layout):
        """
        Add a layout to the card content area
        
        Args:
            layout: Layout to add
        """
        self.content_layout.addLayout(layout)
    
    def clear_content(self):
        """Clear all content from the card"""
        # Remove all widgets from layout
        while self.content_layout.count():
            item = self.content_layout.takeAt(0)
            if item.widget():
                item.widget().setParent(None)
    
    def connect_refresh(self, slot):
        """
        Connect refresh button clicked signal to a slot
        
        Args:
            slot: Function to call when refresh button is clicked
        """
        if self.refresh_button:
            self.refresh_button.clicked.connect(slot)
    
    def connect_settings(self, slot):
        """
        Connect settings button clicked signal to a slot
        
        Args:
            slot: Function to call when settings button is clicked
        """
        self.settings_button.clicked.connect(slot)