from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QSizePolicy
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QColor, QPainter, QBrush, QPen, QFont


class ThreatBadge(QWidget):
    """
    Widget that displays a threat level indicator with color coding
    and confidence level.
    """
    
    def __init__(self, threat_level: str, confidence: float = 1.0, parent=None):
        """
        Initialize threat badge
        
        Args:
            threat_level: Threat level ('malicious', 'suspicious', 'safe', 'unknown')
            confidence: Confidence score (0.0 to 1.0)
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.threat_level = threat_level.lower()
        self.confidence = max(0.0, min(1.0, confidence))  # Clamp to 0.0-1.0
        
        # Set colors for different threat levels
        self.colors = {
            "malicious": QColor(255, 80, 80),    # Red
            "suspicious": QColor(255, 180, 70),  # Orange
            "safe": QColor(100, 200, 100),       # Green
            "unknown": QColor(200, 200, 200)     # Gray
        }
        
        # Set up widget layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        
        # Create indicator label
        self.indicator = QLabel()
        self.indicator.setFixedSize(16, 16)
        self.indicator.setStyleSheet(self._get_indicator_style())
        layout.addWidget(self.indicator)
        
        # Create text label
        self.label = QLabel(self._get_formatted_text())
        layout.addWidget(self.label)
        
        # Configure size policy
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        
        # Set tooltip with more information
        self.setToolTip(self._get_tooltip_text())
    
    def _get_indicator_style(self) -> str:
        """
        Get CSS style for the indicator
        
        Returns:
            CSS style string
        """
        # Get color for current threat level
        color = self.colors.get(self.threat_level, self.colors["unknown"])
        
        # Create CSS style with rounded corners
        return f"""
            background-color: {color.name()};
            border-radius: 8px;
            border: 1px solid {color.darker(120).name()};
        """
    
    def _get_formatted_text(self) -> str:
        """
        Get formatted text for the label
        
        Returns:
            Formatted text with threat level and confidence
        """
        # Format different threat levels
        if self.threat_level == "malicious":
            base_text = "Malicious"
            confidence_text = f" ({int(self.confidence * 100)}%)" if self.confidence < 0.95 else ""
            return f"<b style='color: #d32f2f;'>{base_text}{confidence_text}</b>"
            
        elif self.threat_level == "suspicious":
            base_text = "Suspicious"
            confidence_text = f" ({int(self.confidence * 100)}%)" if self.confidence < 0.95 else ""
            return f"<b style='color: #f57c00;'>{base_text}{confidence_text}</b>"
            
        elif self.threat_level == "safe":
            return f"<span style='color: #388e3c;'>Safe</span>"
            
        else:  # unknown
            return "Unknown"
    
    def _get_tooltip_text(self) -> str:
        """
        Get tooltip text with detailed information
        
        Returns:
            Tooltip text
        """
        # Different tooltip based on threat level
        if self.threat_level == "malicious":
            return f"Malicious entity (Confidence: {int(self.confidence * 100)}%)"
            
        elif self.threat_level == "suspicious":
            return f"Suspicious entity (Confidence: {int(self.confidence * 100)}%)"
            
        elif self.threat_level == "safe":
            return "Safe entity (No known threats)"
            
        else:  # unknown
            return "Unknown entity (Insufficient information)"
    
    def set_threat_level(self, threat_level: str, confidence: float = 1.0):
        """
        Update threat level and confidence
        
        Args:
            threat_level: New threat level
            confidence: New confidence score
        """
        self.threat_level = threat_level.lower()
        self.confidence = max(0.0, min(1.0, confidence))  # Clamp to 0.0-1.0
        
        # Update UI elements
        self.indicator.setStyleSheet(self._get_indicator_style())
        self.label.setText(self._get_formatted_text())
        self.setToolTip(self._get_tooltip_text())
    
    def sizeHint(self) -> QSize:
        """
        Get preferred size
        
        Returns:
            Preferred size
        """
        return QSize(100, 20)