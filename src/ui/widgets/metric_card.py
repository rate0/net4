from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QGraphicsOpacityEffect, QSizePolicy
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QFont, QColor, QPalette, QPixmap
import math, locale

class MetricTrendIndicator(QWidget):
    """Widget that shows a metric trend with an up or down arrow"""
    
    def __init__(self, trend_value=0, parent=None):
        """
        Initialize trend indicator
        
        Args:
            trend_value (float): Trend value (positive = up, negative = down, 0 = neutral)
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Store trend value
        self.trend_value = trend_value
        
        # Create layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        
        # Create arrow icon label
        self.arrow_label = QLabel()
        self.arrow_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Create trend text label
        self.text_label = QLabel()
        self.text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(self.arrow_label)
        layout.addWidget(self.text_label)
        
        # Update the display
        self.update_trend(trend_value)
        
        # Set size policy
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
    
    def update_trend(self, trend_value):
        """
        Update the trend indicator
        
        Args:
            trend_value (float): New trend value
        """
        self.trend_value = trend_value
        
        # Set arrow text and color (Unicode arrows instead of external icons)
        if trend_value > 0:
            arrow_text = "▲"  # Up arrow
            color = "#16a34a"  # Green
        elif trend_value < 0:
            arrow_text = "▼"  # Down arrow
            color = "#dc2626"  # Red
        else:
            arrow_text = "●"  # Bullet
            color = "#94a3b8"  # Gray

        self.arrow_label.setText(arrow_text)
        self.arrow_label.setStyleSheet(f"color: {color}; font-size: 11px;")
        self.text_label.setStyleSheet(f"color: {color}; font-size: 10px;")


class MetricCard(QFrame):
    """Card widget for displaying a metric with label, value, and optional trend"""
    
    def __init__(self, label, value=0, trend=None, icon=None, color=None, parent=None, large=False):
        """
        Initialize metric card
        
        Args:
            label (str): Metric label
            value: Metric value to display
            trend (float, optional): Trend value for indicator (+/- percentage)
            icon (str, optional): Path to icon file
            color (str, optional): Hex color for card highlight
            parent: Parent widget
            large (bool): Whether to use larger sizing for better visibility
        """
        super().__init__(parent)
        
        # Store properties
        self.metric_label = label
        self.metric_value = value
        self.metric_trend = trend
        self.metric_icon = icon
        self.metric_color = color if color else "#323242"  # Default color
        self.is_large = large
        
        # Set frame properties
        self.setObjectName("metricCard")
        self.setStyleSheet(f"""
            #metricCard {{
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                padding: {20 if large else 15}px;
            }}
        """)
        
        # Add subtle left border with metric color
        if color:
            border_width = 5 if large else 3
            self.setStyleSheet(f"""
                #metricCard {{
                    background-color: #323242;
                    border-radius: 5px;
                    border: 1px solid #414558;
                    border-left: {border_width}px solid {color};
                    padding: {20 if large else 15}px;
                }}
            """)
        
        # Create layout
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        self.layout.setSpacing(10 if large else 8)
        
        # Create header with icon and label
        self.header_layout = QHBoxLayout()
        self.header_layout.setContentsMargins(0, 0, 0, 0)
        self.header_layout.setSpacing(5)
        
        # Add icon if provided
        if icon:
            self.icon_label = QLabel()
            pixmap = QPixmap(icon)
            if not pixmap.isNull():
                # Larger icon for large cards
                icon_size = 24 if large else 16
                self.icon_label.setPixmap(pixmap.scaled(
                    icon_size, icon_size, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
                ))
                self.header_layout.addWidget(self.icon_label)
        
        # Add label with larger font if large mode
        self.label_widget = QLabel(label)
        self.label_widget.setObjectName("metricLabel")
        font_size = 14 if large else 12
        self.label_widget.setStyleSheet(f"color: #94a3b8; font-size: {font_size}px;")
        self.header_layout.addWidget(self.label_widget)
        
        # Add spacer to push trend to the right
        self.header_layout.addStretch()
        
        # Add trend indicator if trend is provided
        if trend is not None:
            self.trend_indicator = MetricTrendIndicator(trend)
            self.header_layout.addWidget(self.trend_indicator)
        
        self.layout.addLayout(self.header_layout)
        
        # Add value with larger font if large mode
        formatted_val = str(value)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                locale.setlocale(locale.LC_NUMERIC, '')
                formatted_val = locale.format_string('%d', value, grouping=True)
            except Exception:
                formatted_val = f"{value:,}"

        self.value_widget = QLabel(formatted_val)
        self.value_widget.setObjectName("metricValue")
        value_font_size = 32 if large else 24
        self.value_widget.setStyleSheet(f"color: #ffffff; font-size: {value_font_size}px; font-weight: bold; margin-top: 4px;")
        self.value_widget.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.layout.addWidget(self.value_widget)
        
        # Add bottom spacer
        self.layout.addStretch()
        
        # Set reasonable minimum size but allow resizing
        min_width = 200 if large else 170
        min_height = 120 if large else 100
        self.setMinimumSize(min_width, min_height)
        
        # Set size policy for responsive resizing
        self.setSizePolicy(QSizePolicy.Policy.MinimumExpanding, QSizePolicy.Policy.MinimumExpanding)
    
    def update_value(self, value, trend=None):
        """
        Update the metric value and optionally the trend
        
        Args:
            value: New metric value
            trend (float, optional): New trend value
        """
        # Format numeric values nicely; fallback to str for others
        self.metric_value = value
        if value is None:
            value_str = "0"
        elif isinstance(value, (int, float)):
            if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
                value_str = "0"
            else:
                # Use locale formatting for thousands separator
                try:
                    locale.setlocale(locale.LC_NUMERIC, '')
                    value_str = locale.format_string('%d', value, grouping=True)
                except Exception:
                    value_str = f"{value:,}"
        else:
            value_str = str(value)

        self.value_widget.setText(value_str)
        
        if trend is not None and hasattr(self, 'trend_indicator'):
            self.metric_trend = trend
            self.trend_indicator.update_trend(trend)
    
    def set_color(self, color):
        """
        Set the metric card highlight color
        
        Args:
            color (str): Hex color code
        """
        self.metric_color = color
        
        # Update style with new color
        self.setStyleSheet(f"""
            #metricCard {{
                background-color: #323242;
                border-radius: 5px;
                border: 1px solid #414558;
                border-left: 3px solid {color};
                padding: 15px;
            }}
        """)
    
    def set_icon(self, icon_path):
        """
        Set or update the icon
        
        Args:
            icon_path (str): Path to icon file
        """
        self.metric_icon = icon_path
        
        # If icon label doesn't exist, create it
        if not hasattr(self, 'icon_label'):
            self.icon_label = QLabel()
            self.header_layout.insertWidget(0, self.icon_label)
        
        # Update icon
        pixmap = QPixmap(icon_path)
        if not pixmap.isNull():
            self.icon_label.setPixmap(pixmap.scaled(
                16, 16, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
            ))
            self.icon_label.setVisible(True)
        else:
            self.icon_label.setVisible(False)


class MetricCardGrid(QFrame):
    """Grid of metric cards with consistent sizing and layout"""
    
    def __init__(self, parent=None, columns=4):
        """
        Initialize metric card grid
        
        Args:
            parent: Parent widget
            columns (int): Number of columns in the grid
        """
        super().__init__(parent)
        
        # Store properties
        self.num_columns = columns
        self.cards = []
        
        # Set frame properties
        self.setObjectName("metricCardGrid")
        self.setStyleSheet("""
            #metricCardGrid {
                background-color: transparent;
                border: none;
            }
        """)
        
        # Create grid layout
        from PyQt6.QtWidgets import QGridLayout
        self.layout = QGridLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(20)  # Space between cards
    
    def add_metric(self, label, value=0, trend=None, icon=None, color=None, large=False):
        """
        Add a new metric card to the grid
        
        Args:
            label (str): Metric label
            value: Metric value
            trend (float, optional): Trend value
            icon (str, optional): Path to icon file
            color (str, optional): Hex color for highlight
            large (bool): Whether to use larger sizing for better visibility
            
        Returns:
            MetricCard: The created metric card
        """
        # Create metric card with large option if specified
        card = MetricCard(label, value, trend, icon, color, large=large)
        self.cards.append(card)
        
        # Calculate position in grid
        card_index = len(self.cards) - 1
        row = card_index // self.num_columns
        col = card_index % self.num_columns
        
        # Add to layout
        self.layout.addWidget(card, row, col)
        
        return card
    
    def update_metric(self, index, value, trend=None):
        """
        Update a metric by index
        
        Args:
            index (int): Index of the metric card to update
            value: New value
            trend (float, optional): New trend value
        """
        if 0 <= index < len(self.cards):
            self.cards[index].update_value(value, trend)
    
    def update_metric_by_label(self, label, value, trend=None):
        """
        Update a metric by label
        
        Args:
            label (str): Label of the metric card to update
            value: New value
            trend (float, optional): New trend value
        """
        for card in self.cards:
            if card.metric_label == label:
                card.update_value(value, trend)
                break
    
    def clear(self):
        """Remove all metric cards from the grid"""
        # Clear cards list
        self.cards = []
        
        # Remove all widgets from layout
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                # Detach widget from layout but keep it alive to reuse
                item.widget().setParent(None)
    
    def set_columns(self, columns):
        """
        Change the number of columns in the grid
        
        Args:
            columns (int): New number of columns
        """
        if columns == self.num_columns:
            return
        
        # Store current cards
        current_cards = self.cards.copy()
        
        # Update column count
        self.num_columns = columns
        
        # Clear grid
        self.clear()
        
        # Re-add cards with new layout
        for card in current_cards:
            self.cards.append(card)
            card_index = len(self.cards) - 1
            row = card_index // self.num_columns
            col = card_index % self.num_columns
            self.layout.addWidget(card, row, col)

    def resizeEvent(self, event):
        """Re-layout grid adaptively when parent is resized"""
        super().resizeEvent(event)
        if self.cards:
            # Предполагаем целевую ширину карточки ~230-240 px с учётом spacing
            available_width = self.width()
            target_card_width = 240 + self.layout.spacing()
            # Гарантируем хотя бы одну колонку
            new_cols = max(1, int(available_width / target_card_width))
            if new_cols != self.num_columns:
                self.set_columns(new_cols)