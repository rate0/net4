from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QScrollArea, QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QGridLayout, QGroupBox, QLineEdit, QToolBar, QCheckBox,
    QSlider, QSpinBox, QCalendarWidget, QDialog, QDateTimeEdit, QMenu
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QDateTime, QDate, QTime, QRect
from PyQt6.QtGui import QFont, QIcon, QColor, QPixmap, QPainter, QPen, QBrush, QPainterPath, QPalette

from ..widgets.data_table import DataTable
from ..widgets.threat_badge import ThreatBadge

from ...models.session import Session


class TimelineEvent:
    """Class representing a single timeline event"""
    
    def __init__(
        self, 
        event_id: str, 
        timestamp: datetime, 
        event_type: str, 
        title: str, 
        description: str = "", 
        severity: str = "info"
    ):
        self.id = event_id
        self.timestamp = timestamp
        self.type = event_type
        self.title = title
        self.description = description
        self.severity = severity
        self.selected = False
        self.visible = True
        self.lane = 0  # Lane for rendering (calculated later)


class TimelineView(QWidget):
    """
    Widget for visualizing and interacting with the event timeline
    """
    
    # Signal emitted when an event is selected
    eventSelected = pyqtSignal(TimelineEvent)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.events = []  # List of TimelineEvent objects
        self.visible_events = []  # List of currently visible events
        
        self.start_time = None  # Timeline view start time
        self.end_time = None    # Timeline view end time
        self.time_range = 0     # Timeline view range in seconds
        
        self.num_lanes = 1      # Number of event lanes
        self.lane_height = 30   # Height of each lane in pixels
        self.selected_event = None  # Currently selected event
        
        # Initialize filter attributes
        self.filter_types = None      # Filter by event types
        self.filter_severities = None  # Filter by severity levels
        
        # Mouse interaction
        self.dragging = False
        self.drag_start_x = 0
        self.drag_start_time = None
        
        # Visual settings
        self.header_height = 30
        self.time_tick_height = 10
        self.event_margin = 2
        self.event_min_width = 50
        
        # Initialize widget with larger minimum height
        self.setMinimumHeight(300)
        self.setMouseTracking(True)
        
        # Set color scheme
        self.severity_colors = {
            "high": QColor(255, 100, 100),    # Red
            "medium": QColor(255, 200, 70),   # Orange
            "low": QColor(255, 255, 100),     # Yellow
            "info": QColor(100, 200, 255),    # Blue
            "normal": QColor(150, 200, 150),  # Green
            "unknown": QColor(200, 200, 200)  # Gray
        }
        
        self.type_colors = {
            "packet": QColor(100, 200, 255),     # Blue
            "connection": QColor(150, 200, 150), # Green
            "log_entry": QColor(200, 150, 200),  # Purple
            "anomaly": QColor(255, 100, 100),    # Red
            "threat": QColor(255, 100, 100),     # Red
            "dns": QColor(255, 180, 100),        # Orange
            "http": QColor(100, 200, 200),       # Teal
            "default": QColor(200, 200, 200)     # Gray
        }
        
        # Set background color
        self.setAutoFillBackground(True)
        self.setBackgroundRole(QPalette.ColorRole.Base)
    
    def set_events(self, events: List[TimelineEvent]):
        """
        Set timeline events
        
        Args:
            events: List of TimelineEvent objects
        """
        self.events = events
        
        # Determine time range from events
        if events:
            timestamps = [e.timestamp for e in events]
            self.start_time = min(timestamps)
            self.end_time = max(timestamps)
            
            # Add a margin to the time range
            margin = timedelta(seconds=(self.end_time - self.start_time).total_seconds() * 0.05)
            self.start_time -= margin
            self.end_time += margin
            
            self.time_range = (self.end_time - self.start_time).total_seconds()
        else:
            self.start_time = datetime.now() - timedelta(hours=1)
            self.end_time = datetime.now()
            self.time_range = 3600  # Default to 1 hour
        
        # Apply any filters and layout events
        self._filter_events()
        self._layout_events()
        self.update()
    
    def set_time_range(self, start_time: datetime, end_time: datetime):
        """
        Set visible time range
        
        Args:
            start_time: Start time
            end_time: End time
        """
        self.start_time = start_time
        self.end_time = end_time
        self.time_range = (self.end_time - self.start_time).total_seconds()
        
        # Re-layout events for new time range
        self._filter_events()
        self._layout_events()
        self.update()
    
    def set_filter(self, types: Optional[List[str]] = None, severities: Optional[List[str]] = None):
        """
        Set event filtering
        
        Args:
            types: List of event types to show (None shows all)
            severities: List of severities to show (None shows all)
        """
        # Store filters
        self.filter_types = types
        self.filter_severities = severities
        
        # Apply filters and update
        self._filter_events()
        self._layout_events()
        self.update()
    
    def zoom_in(self):
        """Zoom in on timeline (show shorter time period)"""
        if not self.events:
            return
            
        # Calculate new time range (zoom in by 25%)
        center_time = self.start_time + timedelta(seconds=self.time_range / 2)
        new_range = self.time_range * 0.75
        
        # Calculate new start and end times
        new_start = center_time - timedelta(seconds=new_range / 2)
        new_end = center_time + timedelta(seconds=new_range / 2)
        
        # Update time range
        self.set_time_range(new_start, new_end)
    
    def zoom_out(self):
        """Zoom out on timeline (show longer time period)"""
        if not self.events:
            return
            
        # Calculate new time range (zoom out by 25%)
        center_time = self.start_time + timedelta(seconds=self.time_range / 2)
        new_range = self.time_range * 1.25
        
        # Calculate new start and end times
        new_start = center_time - timedelta(seconds=new_range / 2)
        new_end = center_time + timedelta(seconds=new_range / 2)
        
        # Update time range
        self.set_time_range(new_start, new_end)
    
    def fit_all_events(self):
        """Adjust time range to show all events"""
        if not self.events:
            return
            
        # Find earliest and latest timestamps
        timestamps = [e.timestamp for e in self.events]
        earliest = min(timestamps)
        latest = max(timestamps)
        
        # Add a margin to the time range
        margin = timedelta(seconds=(latest - earliest).total_seconds() * 0.05)
        new_start = earliest - margin
        new_end = latest + margin
        
        # Update time range
        self.set_time_range(new_start, new_end)
    
    def paintEvent(self, event):
        """Paint the timeline view"""
        if not self.events:
            return
            
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Get widget dimensions
        width = self.width()
        height = self.height()
        
        # Draw time header
        self._draw_time_header(painter, width)
        
        # Draw events
        self._draw_events(painter, width, height)
        
        # Draw selection
        if self.selected_event:
            self._draw_selection(painter, width, height)
    
    def _draw_time_header(self, painter: QPainter, width: int):
        """
        Draw the time header with tick marks
        
        Args:
            painter: QPainter object
            width: Widget width
        """
        # Draw header background
        header_rect = QRect(0, 0, width, self.header_height)
        painter.fillRect(header_rect, QColor(240, 240, 240))
        
        # Draw border
        painter.setPen(QPen(QColor(200, 200, 200)))
        painter.drawLine(0, self.header_height, width, self.header_height)
        
        # Calculate appropriate time interval for tick marks
        time_span = (self.end_time - self.start_time).total_seconds()
        
        # Choose tick interval based on time span
        if time_span <= 60:  # <= 1 minute
            interval = 5  # 5 seconds
            format_str = "%H:%M:%S"
        elif time_span <= 300:  # <= 5 minutes
            interval = 30  # 30 seconds
            format_str = "%H:%M:%S"
        elif time_span <= 3600:  # <= 1 hour
            interval = 300  # 5 minutes
            format_str = "%H:%M"
        elif time_span <= 86400:  # <= 1 day
            interval = 3600  # 1 hour
            format_str = "%H:%M"
        elif time_span <= 604800:  # <= 1 week
            interval = 86400  # 1 day
            format_str = "%Y-%m-%d"
        else:  # > 1 week
            interval = 604800  # 1 week
            format_str = "%Y-%m-%d"
        
        # Calculate start time aligned to interval
        start_seconds = int(self.start_time.timestamp())
        aligned_start = start_seconds - (start_seconds % interval)
        
        # Draw tick marks and labels
        painter.setPen(QPen(QColor(100, 100, 100)))
        
        tick_time = datetime.fromtimestamp(aligned_start)
        while tick_time <= self.end_time:
            # Skip if before start time
            if tick_time < self.start_time:
                tick_time = tick_time + timedelta(seconds=interval)
                continue
                
            # Calculate x position
            elapsed = (tick_time - self.start_time).total_seconds()
            x_pos = int(elapsed / self.time_range * width)
            
            # Draw tick mark
            painter.drawLine(x_pos, self.header_height - self.time_tick_height, 
                           x_pos, self.header_height)
            
            # Draw time label
            time_str = tick_time.strftime(format_str)
            painter.drawText(x_pos - 40, 0, 80, self.header_height - self.time_tick_height, 
                           Qt.AlignmentFlag.AlignCenter, time_str)
            
            # Move to next tick
            tick_time = tick_time + timedelta(seconds=interval)
    
    def _draw_events(self, painter: QPainter, width: int, height: int):
        """
        Draw timeline events
        
        Args:
            painter: QPainter object
            width: Widget width
            height: Widget height
        """
        # Set up event drawing
        content_height = height - self.header_height
        
        # Ensure we don't divide by zero - we always have at least one lane
        lane_height = min(self.lane_height, int(content_height / max(1, self.num_lanes)))
        
        # Ensure lane_height is at least 1 pixel
        lane_height = max(1, lane_height)
        
        # Draw each lane background
        for lane in range(self.num_lanes):
            lane_y = self.header_height + lane * lane_height
            lane_rect = QRect(0, lane_y, width, lane_height)
            
            # Alternate lane background colors
            if lane % 2 == 0:
                bg_color = QColor(252, 252, 252)  # Light gray
            else:
                bg_color = QColor(248, 248, 248)  # Lighter gray
                
            painter.fillRect(lane_rect, bg_color)
        
        # Draw visible events
        for event in self.visible_events:
            if not event.visible:
                continue
                
            # Calculate event position and size
            event_x, event_width = self._get_event_rect(event, width)
            event_y = self.header_height + event.lane * lane_height
            
            # Skip if event is outside visible area
            if event_x + event_width < 0 or event_x > width:
                continue
            
            # Determine event color based on type and severity
            if event.severity in ["high", "medium", "low"]:
                color = self.severity_colors.get(event.severity, self.severity_colors["unknown"])
            else:
                color = self.type_colors.get(event.type, self.type_colors["default"])
            
            # Create rounded rectangle for event
            event_rect = QRect(
                event_x, 
                event_y + self.event_margin, 
                max(event_width, self.event_min_width), 
                lane_height - 2 * self.event_margin
            )
            
            # Draw event background
            painter.setPen(QPen(color.darker(120)))
            painter.setBrush(QBrush(color.lighter(110)))
            painter.drawRoundedRect(event_rect, 4, 4)
            
            # Draw event title/label
            text_rect = event_rect.adjusted(5, 2, -5, -2)
            painter.setPen(QPen(QColor(0, 0, 0)))
            
            # Determine if there's enough space for the text
            if event_width > 60:
                # Show title or description
                painter.drawText(text_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, 
                               event.title if event.title else event.type.capitalize())
            else:
                # Just show an icon indicator
                painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, "●")
    
    def _draw_selection(self, painter: QPainter, width: int, height: int):
        """
        Draw selection highlight for selected event
        
        Args:
            painter: QPainter object
            width: Widget width
            height: Widget height
        """
        if not self.selected_event or not self.selected_event.visible:
            return
            
        # Calculate event position and size
        event_x, event_width = self._get_event_rect(self.selected_event, width)
        
        # Ensure we don't divide by zero - FIXED: added max(1, self.num_lanes)
        content_height = height - self.header_height
        lane_height = min(self.lane_height, int(content_height / max(1, self.num_lanes)))
        lane_height = max(1, lane_height)  # Ensure at least 1 pixel
        
        event_y = self.header_height + self.selected_event.lane * lane_height
        
        # Create selection rectangle
        select_rect = QRect(
            event_x - 2, 
            event_y + self.event_margin - 2, 
            max(event_width, self.event_min_width) + 4, 
            lane_height - 2 * self.event_margin + 4
        )
        
        # Draw selection outline
        painter.setPen(QPen(QColor(0, 120, 215), 2, Qt.PenStyle.DashLine))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(select_rect, 6, 6)
    
    def _get_event_rect(self, event: TimelineEvent, width: int) -> Tuple[int, int]:
        """
        Calculate event rectangle position and width
        
        Args:
            event: Timeline event
            width: Widget width
            
        Returns:
            Tuple of (x_position, width)
        """
        # Calculate position based on timestamp
        elapsed = (event.timestamp - self.start_time).total_seconds()
        
        # FIXED: Ensure time_range is not zero
        if self.time_range <= 0:
            return (0, width)
            
        # Calculate x position as proportion of time range
        x_pos = int(elapsed / self.time_range * width)
        
        # For events with a duration, calculate width
        # For now, use a fixed minimum width
        event_width = self.event_min_width
        
        return (x_pos, event_width)
    
    def _filter_events(self):
        """Apply filtering to events"""
        self.visible_events = []
        
        for event in self.events:
            # Apply type filter
            if self.filter_types and event.type not in self.filter_types:
                event.visible = False
                continue
                
            # Apply severity filter
            if self.filter_severities and event.severity not in self.filter_severities:
                event.visible = False
                continue
                
            # Event passes all filters
            event.visible = True
            self.visible_events.append(event)
    
    def _layout_events(self):
        """Calculate event positions and lanes to avoid overlaps"""
        if not self.visible_events:
            self.num_lanes = 1
            return
            
        # Sort events by timestamp
        sorted_events = sorted(self.visible_events, key=lambda e: e.timestamp)
        
        # Assign lanes to avoid overlaps
        lanes = []  # Each lane contains the end position of the last event
        
        # Minimum space between events in pixels
        min_gap = 5
        
        # Calculate screen width for positioning
        width = max(1, self.width())  # FIXED: Ensure width is at least 1
        
        for event in sorted_events:
            # Calculate event position and width
            event_x, event_width = self._get_event_rect(event, width)
            event_end = event_x + max(event_width, self.event_min_width) + min_gap
            
            # Find a lane where this event fits
            lane_found = False
            for i, lane_end in enumerate(lanes):
                if event_x > lane_end:
                    # Event fits in this lane
                    lanes[i] = event_end
                    event.lane = i
                    lane_found = True
                    break
            
            if not lane_found:
                # Add a new lane
                lanes.append(event_end)
                event.lane = len(lanes) - 1
        
        # Update number of lanes
        self.num_lanes = max(1, len(lanes))  # FIXED: Ensure at least 1 lane
    
    def mousePressEvent(self, event):
        """Handle mouse press event"""
        if event.button() == Qt.MouseButton.LeftButton:
            # Start dragging
            self.dragging = True
            # Fixed: Use position().x() instead of x()
            self.drag_start_x = event.position().x()
            self.drag_start_time = self.start_time
            
            # Check if clicked on an event
            # Fixed: Use position().x() and position().y()
            clicked_event = self._find_event_at_position(event.position().x(), event.position().y())
            if clicked_event:
                # Select the clicked event
                self.select_event(clicked_event)
            else:
                # Deselect if clicked on empty space
                self.selected_event = None
                self.eventSelected.emit(None)
                self.update()
            
            event.accept()
        else:
            super().mousePressEvent(event)
    
    def mouseMoveEvent(self, event):
        """Handle mouse move event"""
        if self.dragging and self.drag_start_time:
            # Fixed: Use position().x() instead of x()
            # Calculate time difference based on mouse movement
            dx = self.drag_start_x - event.position().x()
            if dx == 0:
                return
                
            # Convert pixel movement to time delta
            delta_seconds = dx / self.width() * self.time_range
            
            # Calculate new time range
            new_start = self.drag_start_time + timedelta(seconds=delta_seconds)
            new_end = new_start + timedelta(seconds=self.time_range)
            
            # Update time range
            self.start_time = new_start
            self.end_time = new_end
            
            # Update display
            self._layout_events()
            self.update()
            
            event.accept()
        else:
            # Update cursor if over an event
            # Fixed: Use position().x() and position().y()
            hover_event = self._find_event_at_position(event.position().x(), event.position().y())
            if hover_event:
                self.setCursor(Qt.CursorShape.PointingHandCursor)
            else:
                self.setCursor(Qt.CursorShape.ArrowCursor)
            
            super().mouseMoveEvent(event)
    
    def mouseReleaseEvent(self, event):
        """Handle mouse release event"""
        if event.button() == Qt.MouseButton.LeftButton and self.dragging:
            self.dragging = False
            event.accept()
        else:
            super().mouseReleaseEvent(event)
    
    def mouseDoubleClickEvent(self, event):
        """Handle mouse double click event"""
        if event.button() == Qt.MouseButton.LeftButton:
            # Check if clicked on an event
            # Fixed: Use position().x() and position().y()
            clicked_event = self._find_event_at_position(event.position().x(), event.position().y())
            if clicked_event:
                # Center the timeline on this event
                self._center_on_event(clicked_event)
            else:
                # Double click on empty space fits all events
                self.fit_all_events()
            
            event.accept()
        else:
            super().mouseDoubleClickEvent(event)
    
    def wheelEvent(self, event):
        """Handle mouse wheel event for zooming"""
        delta = event.angleDelta().y()
        
        if delta > 0:
            # Zoom in
            self.zoom_in()
        elif delta < 0:
            # Zoom out
            self.zoom_out()
        
        event.accept()
    
    def resizeEvent(self, event):
        """Handle resize event"""
        super().resizeEvent(event)
        
        # Re-layout events for new size
        self._layout_events()
    
    def _find_event_at_position(self, x: int, y: int) -> Optional[TimelineEvent]:
        """
        Find event at the given position
        
        Args:
            x: X coordinate
            y: Y coordinate
            
        Returns:
            Event at position or None
        """
        # Ignore if outside content area
        if y < self.header_height:
            return None
            
        # Calculate which lane was clicked
        content_height = self.height() - self.header_height
        
        # FIXED: Ensure num_lanes is at least 1 and lane_height is at least 1
        lane_height = max(1, min(self.lane_height, int(content_height / max(1, self.num_lanes))))
        
        # Now lane_height can't be 0, so we won't get a division by zero
        lane = int((y - self.header_height) / lane_height)
        
        if lane >= self.num_lanes:
            return None
            
        # Check each visible event in this lane
        width = self.width()
        for event in self.visible_events:
            if event.lane != lane:
                continue
                
            # Get event rectangle
            event_x, event_width = self._get_event_rect(event, width)
            event_width = max(event_width, self.event_min_width)
            
            # Check if click is within event
            if event_x <= x <= event_x + event_width:
                return event
        
        return None
    
    def _center_on_event(self, event: TimelineEvent):
        """
        Center the timeline view on the given event
        
        Args:
            event: Event to center on
        """
        # Calculate new time range centered on the event
        half_range = self.time_range / 2
        new_start = event.timestamp - timedelta(seconds=half_range)
        new_end = event.timestamp + timedelta(seconds=half_range)
        
        # Update time range
        self.set_time_range(new_start, new_end)
    
    def select_event(self, event: TimelineEvent):
        """
        Select an event and emit signal
        
        Args:
            event: Event to select
        """
        # Deselect previous event
        if self.selected_event:
            self.selected_event.selected = False
        
        # Select new event
        self.selected_event = event
        if event:
            event.selected = True
            self.eventSelected.emit(event)
        
        # Update display
        self.update()


class TimelineDashboard(QWidget):
    """
    Dashboard for timeline analysis of network events.
    Provides a chronological view of activity with filtering and inspection.
    """
    
    def __init__(self, session: Session, parent=None):
        """
        Initialize timeline dashboard
        
        Args:
            session: Analysis session
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.session = session
        self.timeline_events = []  # List of TimelineEvent objects
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize dashboard UI"""
        # Main layout
        layout = QVBoxLayout(self)
        
        # Toolbar for filters and controls
        toolbar = QToolBar()
        toolbar.setIconSize(QSize(16, 16))
        
        # Time range controls
        time_label = QLabel("Time range:")
        toolbar.addWidget(time_label)
        
        self.time_range_combo = QComboBox()
        self.time_range_combo.addItems([
            "All time", "Last hour", "Last 24 hours", "Last 7 days", "Custom..."
        ])
        self.time_range_combo.setMaximumWidth(120)
        self.time_range_combo.currentTextChanged.connect(self._time_range_changed)
        toolbar.addWidget(self.time_range_combo)
        
        toolbar.addSeparator()
        
        # Event type filter
        type_label = QLabel("Event types:")
        toolbar.addWidget(type_label)
        
        self.event_types = {}  # Event type checkboxes
        self.type_widget = QWidget()
        self.type_layout = QHBoxLayout(self.type_widget)
        self.type_layout.setContentsMargins(0, 0, 0, 0)
        self.type_layout.setSpacing(5)
        toolbar.addWidget(self.type_widget)
        
        toolbar.addSeparator()
        
        # Zoom controls
        zoom_in_btn = QPushButton()
        zoom_in_btn.setIcon(QIcon.fromTheme("zoom-in", QIcon("assets/icons/zoom-in.png")))
        zoom_in_btn.setToolTip("Zoom In")
        zoom_in_btn.clicked.connect(self._zoom_in)
        toolbar.addWidget(zoom_in_btn)
        
        zoom_out_btn = QPushButton()
        zoom_out_btn.setIcon(QIcon.fromTheme("zoom-out", QIcon("assets/icons/zoom-out.png")))
        zoom_out_btn.setToolTip("Zoom Out")
        zoom_out_btn.clicked.connect(self._zoom_out)
        toolbar.addWidget(zoom_out_btn)
        
        fit_all_btn = QPushButton()
        fit_all_btn.setIcon(QIcon.fromTheme("zoom-fit-best", QIcon("assets/icons/fit-all.png")))
        fit_all_btn.setToolTip("Fit All Events")
        fit_all_btn.clicked.connect(self._fit_all)
        toolbar.addWidget(fit_all_btn)
        
        # Add toolbar to layout
        layout.addWidget(toolbar)
        
        # Main content splitter
        content_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Timeline view
        self.timeline_view = TimelineView()
        self.timeline_view.eventSelected.connect(self._event_selected)
        self.timeline_view.setMinimumHeight(150)
        content_splitter.addWidget(self.timeline_view)
        
        # Events list
        self.events_group = QGroupBox("Event List")
        events_layout = QVBoxLayout(self.events_group)
        
        # Add events table
        self.events_table = DataTable(
            ["Time", "Type", "Description", "Severity"],
            []
        )
        self.events_table.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.events_table.table.selectionModel().selectionChanged.connect(self._table_selection_changed)
        events_layout.addWidget(self.events_table)
        
        content_splitter.addWidget(self.events_group)
        
        # Event details panel
        self.details_group = QGroupBox("Event Details")
        self.details_layout = QVBoxLayout(self.details_group)
        
        # Create details grid
        details_grid = QGridLayout()
        
        detail_labels = [
            ("Time:", QLabel("")),
            ("Type:", QLabel("")),
            ("Source:", QLabel("")),
            ("Severity:", QLabel("")),
        ]
        
        self.detail_label_map = {}
        
        for i, (label_text, value_label) in enumerate(detail_labels):
            row = i // 2
            col = (i % 2) * 2
            
            label = QLabel(label_text)
            label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            font = QFont()
            font.setBold(True)
            label.setFont(font)
            
            details_grid.addWidget(label, row, col)
            details_grid.addWidget(value_label, row, col + 1)
            
            # Store reference to value label
            key = label_text.replace(":", "").lower()
            self.detail_label_map[key] = value_label
        
        self.details_layout.addLayout(details_grid)
        
        # Add description field
        self.description_label = QLabel("Description:")
        font = QFont()
        font.setBold(True)
        self.description_label.setFont(font)
        self.details_layout.addWidget(self.description_label)
        
        self.description_text = QLabel()
        self.description_text.setWordWrap(True)
        self.description_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.details_layout.addWidget(self.description_text)
        
        # Add raw data field for log entries
        self.raw_data_label = QLabel("Raw Data:")
        self.raw_data_label.setFont(font)
        self.raw_data_label.setVisible(False)
        self.details_layout.addWidget(self.raw_data_label)
        
        self.raw_data_text = QLabel()
        self.raw_data_text.setWordWrap(True)
        self.raw_data_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.raw_data_text.setVisible(False)
        self.details_layout.addWidget(self.raw_data_text)
        
        content_splitter.addWidget(self.details_group)
        
        # Set initial splitter sizes
        content_splitter.setSizes([500, 300, 200])
        
        # Add content splitter to layout
        layout.addWidget(content_splitter)
        
        # Update dashboard with current data
        self.update_dashboard()
    
    def update_dashboard(self):
        """Update dashboard with current session data"""
        # Extract and process events from session
        self._process_session_events()
        
        # Update event type checkboxes
        self._update_event_type_checkboxes()
        
        # Update timeline view with events
        self.timeline_view.set_events(self.timeline_events)
        
        # Update events table
        self._update_events_table()
    
    def _process_session_events(self):
        """Process events from session data"""
        self.timeline_events = []
        
        # Process timeline events
        if hasattr(self.session, 'timeline_events'):
            for i, event in enumerate(self.session.timeline_events):
                event_id = f"event_{i}"
                timestamp = event.get("timestamp")
                
                if not timestamp:
                    continue
                    
                event_type = event.get("type", "event")
                
                # Extract title and description
                if event_type == "log_entry" and "parsed_data" in event:
                    parsed = event.get("parsed_data", {})
                    if "message" in parsed:
                        title = parsed["message"][:50] + ("..." if len(parsed["message"]) > 50 else "")
                        description = parsed["message"]
                    else:
                        title = f"Log entry from {event.get('source', 'unknown')}"
                        description = str(parsed)
                elif event_type == "packet" and "parsed_data" in event:
                    parsed = event.get("parsed_data", {})
                    src_ip = parsed.get("src_ip", "unknown")
                    dst_ip = parsed.get("dst_ip", "unknown")
                    protocol = parsed.get("protocol", "unknown")
                    
                    title = f"{src_ip} -> {dst_ip} ({protocol})"
                    description = f"Packet: {src_ip} -> {dst_ip} ({protocol})"
                else:
                    title = f"{event_type.capitalize()} at {timestamp.strftime('%H:%M:%S')}"
                    description = event.get("description", "No description available")
                
                # Determine severity
                severity = "info"  # Default severity
                
                # Create timeline event
                timeline_event = TimelineEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    event_type=event_type,
                    title=title,
                    description=description,
                    severity=severity
                )
                
                # Store reference to original event
                timeline_event.original_event = event
                
                self.timeline_events.append(timeline_event)
        
        # Process anomalies
        if hasattr(self.session, 'anomalies'):
            for i, anomaly in enumerate(self.session.anomalies):
                event_id = f"anomaly_{i}"
                timestamp = anomaly.get("timestamp")
                
                if not timestamp:
                    continue
                    
                anomaly_type = anomaly.get("type", "unknown")
                subtype = anomaly.get("subtype", "")
                
                if subtype:
                    type_display = f"{anomaly_type} ({subtype})"
                else:
                    type_display = anomaly_type
                    
                title = f"{type_display.replace('_', ' ').title()}"
                description = anomaly.get("description", "No description available")
                severity = anomaly.get("severity", "info")
                
                # Create timeline event
                timeline_event = TimelineEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    event_type="anomaly",
                    title=title,
                    description=description,
                    severity=severity
                )
                
                # Store reference to original anomaly
                timeline_event.original_event = anomaly
                
                self.timeline_events.append(timeline_event)
    
    def _update_event_type_checkboxes(self):
        """Update event type filter checkboxes"""
        # Clear existing checkboxes
        for i in reversed(range(self.type_layout.count())):
            widget = self.type_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        
        self.event_types = {}
        
        # Get unique event types
        types = set()
        for event in self.timeline_events:
            types.add(event.type)
        
        # Create checkbox for each type
        for event_type in sorted(types):
            checkbox = QCheckBox(event_type.capitalize())
            checkbox.setChecked(True)
            checkbox.stateChanged.connect(self._event_filters_changed)
            
            self.event_types[event_type] = checkbox
            self.type_layout.addWidget(checkbox)
    
    def _update_events_table(self):
        """Update events table with current events"""
        # Convert timeline events to table data
        table_data = []
        
        for event in sorted(self.timeline_events, key=lambda e: e.timestamp):
            if not event.visible:
                continue
                
            time_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            type_str = event.type.capitalize()
            description = event.title
            severity = event.severity.capitalize()
            
            table_data.append([time_str, type_str, description, severity])
        
        # Update table
        self.events_table.update_data(table_data)
        
        # Update group title
        self.events_group.setTitle(f"Event List ({len(table_data)} events)")
    
    def _time_range_changed(self, range_text: str):
        """
        Handle time range selection change
        
        Args:
            range_text: Selected time range text
        """
        if not self.timeline_events:
            return
            
        # Calculate start and end times based on selection
        end_time = datetime.now()
        
        if range_text == "All time":
            # Find earliest and latest timestamps
            timestamps = [e.timestamp for e in self.timeline_events]
            start_time = min(timestamps)
            end_time = max(timestamps)
            
            # Add margin
            margin = timedelta(seconds=(end_time - start_time).total_seconds() * 0.05)
            start_time -= margin
            end_time += margin
            
        elif range_text == "Last hour":
            start_time = end_time - timedelta(hours=1)
            
        elif range_text == "Last 24 hours":
            start_time = end_time - timedelta(days=1)
            
        elif range_text == "Last 7 days":
            start_time = end_time - timedelta(days=7)
            
        elif range_text == "Custom...":
            # Show custom range dialog
            dialog = QDialog(self)
            dialog.setWindowTitle("Select Time Range")
            dialog_layout = QVBoxLayout(dialog)
            
            # Find earliest and latest timestamps for default range
            timestamps = [e.timestamp for e in self.timeline_events]
            min_time = min(timestamps)
            max_time = max(timestamps)
            
            # Create date/time pickers
            start_label = QLabel("Start time:")
            dialog_layout.addWidget(start_label)
            
            start_picker = QDateTimeEdit(dialog)
            start_picker.setDateTime(min_time)
            start_picker.setCalendarPopup(True)
            dialog_layout.addWidget(start_picker)
            
            end_label = QLabel("End time:")
            dialog_layout.addWidget(end_label)
            
            end_picker = QDateTimeEdit(dialog)
            end_picker.setDateTime(max_time)
            end_picker.setCalendarPopup(True)
            dialog_layout.addWidget(end_picker)
            
            # Add buttons
            button_layout = QHBoxLayout()
            cancel_btn = QPushButton("Cancel")
            apply_btn = QPushButton("Apply")
            apply_btn.setDefault(True)
            
            button_layout.addWidget(cancel_btn)
            button_layout.addWidget(apply_btn)
            dialog_layout.addLayout(button_layout)
            
            # Connect signals
            cancel_btn.clicked.connect(dialog.reject)
            apply_btn.clicked.connect(dialog.accept)
            
            # Show dialog
            if dialog.exec() == QDialog.DialogCode.Accepted:
                start_time = start_picker.dateTime().toPython()
                end_time = end_picker.dateTime().toPython()
            else:
                # User cancelled, revert combo box
                self.time_range_combo.setCurrentText("All time")
                return
        else:
            # Default to all time
            return
        
        # Update timeline view with new time range
        self.timeline_view.set_time_range(start_time, end_time)
    
    def _event_filters_changed(self):
        """Handle event filter changes"""
        # Get selected event types
        selected_types = []
        for event_type, checkbox in self.event_types.items():
            if checkbox.isChecked():
                selected_types.append(event_type)
        
        # Apply filters to timeline view
        self.timeline_view.set_filter(types=selected_types)
        
        # Update events table
        self._update_events_table()
    
    def _zoom_in(self):
        """Zoom in on timeline"""
        self.timeline_view.zoom_in()
    
    def _zoom_out(self):
        """Zoom out on timeline"""
        self.timeline_view.zoom_out()
    
    def _fit_all(self):
        """Fit all events in timeline view"""
        self.timeline_view.fit_all_events()
    
    def _event_selected(self, event: Optional[TimelineEvent]):
        """
        Handle event selection in timeline view
        
        Args:
            event: Selected event or None
        """
        if not event:
            # Clear details panel
            self._clear_event_details()
            return
            
        # Update details panel with event information
        self._update_event_details(event)
        
        # Select corresponding row in table
        self._select_event_in_table(event)
    
    def _table_selection_changed(self):
        """Handle selection change in events table"""
        # Get selected row
        selection = self.events_table.table.selectionModel().selectedRows()
        if not selection:
            return
            
        row = selection[0].row()
        
        # Get event timestamp from table
        time_str = self.events_table.data[row][0]
        event_type = self.events_table.data[row][1].lower()
        
        # Find matching event in timeline events
        for event in self.timeline_events:
            if (event.timestamp.strftime("%Y-%m-%d %H:%M:%S") == time_str and 
                event.type == event_type):
                # Select event in timeline view
                self.timeline_view.select_event(event)
                break
    
    def _select_event_in_table(self, event: TimelineEvent):
        """
        Select event in events table
        
        Args:
            event: Event to select
        """
        # Find row with matching timestamp and type
        time_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        event_type = event.type.capitalize()
        
        for row, data in enumerate(self.events_table.data):
            if data[0] == time_str and data[1] == event_type:
                # Select this row
                self.events_table.table.selectRow(row)
                # Scroll to the row
                self.events_table.table.scrollToItem(
                    self.events_table.table.item(row, 0),
                    QTableWidget.ScrollHint.PositionAtCenter
                )
                break
    
    def _update_event_details(self, event: TimelineEvent):
        """
        Update event details panel with event information
        
        Args:
            event: Event to display
        """
        # Set basic information
        self.detail_label_map["time"].setText(event.timestamp.strftime("%Y-%m-%d %H:%M:%S"))
        self.detail_label_map["type"].setText(event.type.capitalize())
        
        # Set source (if available)
        source = "Unknown"
        if hasattr(event, 'original_event'):
            original = event.original_event
            if "source" in original:
                source = original["source"]
        
        self.detail_label_map["source"].setText(source)
        
        # Set severity
        self.detail_label_map["severity"].setText(event.severity.capitalize())
        
        # Set description
        self.description_text.setText(event.description)
        
        # Show/hide raw data based on event type
        if hasattr(event, 'original_event'):
            original = event.original_event
            
            if event.type == "log_entry" and "raw_data" in original:
                self.raw_data_label.setVisible(True)
                self.raw_data_text.setVisible(True)
                self.raw_data_text.setText(original["raw_data"])
            elif event.type == "packet" and "parsed_data" in original:
                self.raw_data_label.setVisible(True)
                self.raw_data_text.setVisible(True)
                self.raw_data_text.setText(str(original["parsed_data"]))
            else:
                self.raw_data_label.setVisible(False)
                self.raw_data_text.setVisible(False)
        else:
            self.raw_data_label.setVisible(False)
            self.raw_data_text.setVisible(False)
    
    def _clear_event_details(self):
        """Clear event details panel"""
        # Clear all fields
        self.detail_label_map["time"].setText("")
        self.detail_label_map["type"].setText("")
        self.detail_label_map["source"].setText("")
        self.detail_label_map["severity"].setText("")
        self.description_text.setText("")
        self.raw_data_label.setVisible(False)
        self.raw_data_text.setVisible(False)