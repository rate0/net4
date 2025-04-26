import warnings
import matplotlib
# Explicitly set the backend and suppress any warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import matplotlib.patheffects
import numpy as np
from typing import List, Tuple, Dict, Any, Optional
from datetime import datetime

from PyQt6.QtWidgets import QSizePolicy, QVBoxLayout, QWidget, QLabel
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont


def safe_tight_layout(fig, **kwargs):
    """Apply tight_layout safely, suppressing warnings if it fails"""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            # Use more conservative padding to avoid issues
            padding = kwargs.get('pad', 2.0)
            w_pad = kwargs.get('w_pad', 1.5)
            h_pad = kwargs.get('h_pad', 1.5)
            rect = kwargs.get('rect', [0.1, 0.1, 0.9, 0.9])  # More conservative rect
            
            fig.tight_layout(pad=padding, w_pad=w_pad, h_pad=h_pad, rect=rect)
        except Exception:
            # If tight_layout fails, just adjust subplot parameters directly
            fig.subplots_adjust(left=0.15, right=0.85, top=0.85, bottom=0.15)


class BaseChart(FigureCanvas):
    """Base class for all charts"""
    
    def __init__(self, title: str, parent=None, width=5, height=4, dpi=100):
        """
        Initialize base chart
        
        Args:
            title: Chart title
            parent: Parent widget
            width: Figure width in inches
            height: Figure height in inches
            dpi: Figure resolution
        """
        self.title = title
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = self.fig.add_subplot(111)
        
        # Initialize canvas
        super().__init__(self.fig)
        self.setParent(parent)
        
        # Apply safe tight layout
        safe_tight_layout(self.fig)
        
        # Set theme colors matching the main application
        self.fig.patch.set_facecolor('#1e1e2e')  # Match app background
        self.axes.set_facecolor('#282838')       # Match panel background
        
        # Configure text and tick colors with high contrast white
        self.axes.tick_params(colors='#ffffff', labelsize=9)
        self.axes.xaxis.label.set_color('#ffffff')
        self.axes.yaxis.label.set_color('#ffffff')
        
        # Style the title with larger font and bold
        self.axes.title.set_color('#ffffff')
        self.axes.title.set_fontsize(12)
        self.axes.title.set_fontweight('bold')
        
        # Set title
        self.axes.set_title(title)
        
        # Set size policy
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.updateGeometry()
    
    def clear(self):
        """Clear the chart"""
        self.axes.clear()
        self.axes.set_title(self.title)
        self.draw()


class PieChart(BaseChart):
    """Pie chart for showing distribution"""
    
    def __init__(self, title: str, parent=None, height=200, dpi=100):
        """
        Initialize pie chart
        
        Args:
            title: Chart title
            parent: Parent widget
            height: Chart height in pixels
            dpi: Chart resolution
        """
        # Calculate width based on height to maintain aspect ratio
        width_inches = height / dpi
        height_inches = height / dpi * 1.2  # Add 20% more height for labels
        
        super().__init__(title, parent, width_inches, height_inches, dpi)
        
        # Set empty data
        self.data = []
        self.explode = None
        
        # Update display
        self._update_chart()
    
    def update_data(self, data: List[Tuple[str, float]]):
        """
        Update chart with new data
        
        Args:
            data: List of (label, value) tuples
        """
        self.data = data
        self._update_chart()
    
    def _update_chart(self):
        """Update chart with current data"""
        # Clear previous plot
        self.axes.clear()
        
        # Set title
        self.axes.set_title(self.title)
        
        if not self.data:
            self.axes.text(0.5, 0.5, "No data available", 
                         ha='center', va='center', fontsize=12, color='#ffffff')
            self.draw()
            return
        
        # Extract labels and values
        labels = [item[0] for item in self.data]
        values = [item[1] for item in self.data]
        
        # Create explode array (slight separation for first slice)
        self.explode = [0.05] + [0] * (len(values) - 1) if len(values) > 1 else None
        
        # Define custom colors for better visibility in dark themes
        custom_colors = [
            '#3a82f7',  # Blue
            '#00e676',  # Green
            '#ff1744',  # Red
            '#ffab40',  # Orange
            '#9333ea',  # Purple
            '#00bcd4',  # Cyan
            '#d500f9',  # Pink
            '#8bc34a',  # Light Green
            '#ffd600',  # Yellow
            '#607d8b',  # Gray-Blue
        ]
        
        # Ensure we have enough colors
        if len(values) > len(custom_colors):
            # Extend with the standard colormap
            colors = custom_colors + list(plt.cm.tab10.colors[len(custom_colors):len(values)])
        else:
            colors = custom_colors[:len(values)]
        
        # Plot the pie chart with improved visibility for dark theme
        wedges, texts, autotexts = self.axes.pie(
            values, 
            labels=None,  # We'll use a custom legend with better formatting
            explode=self.explode,
            colors=colors,
            autopct='%1.1f%%',  # Always show percentages with improved visibility
            shadow=False,
            startangle=90,
            wedgeprops={'edgecolor': '#323242', 'linewidth': 1},  # Add edge lines for better separation
            textprops={'fontsize': 12, 'color': 'white', 'fontweight': 'bold'}  # Make percentage text larger and white
        )
        
        # Set font size for percentage labels and ensure they're visible
        for autotext in autotexts:
            autotext.set_fontsize(12)
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            # Add light outline for better visibility
            autotext.set_path_effects([
                matplotlib.patheffects.withStroke(linewidth=2, foreground='black')
            ])
        
        # Always use a customized legend with better formatting for dark theme
        self.axes.legend(
            wedges, 
            labels, 
            loc='center left' if len(values) <= 5 else 'lower center',
            bbox_to_anchor=(1, 0.5) if len(values) <= 5 else (0.5, -0.1),
            fontsize=10,
            frameon=True,
            facecolor='#323242',  # Dark background
            edgecolor='#414558',  # Border color
            labelcolor='white',   # White text
            framealpha=0.9,       # Slight transparency
            ncol=2 if len(values) > 5 else 1  # Two columns for many entries
        )
        
        # Equal aspect ratio ensures that pie is drawn as a circle
        self.axes.set_aspect('equal')
        
        # Update the plot with safe tight layout with extra padding for legend
        if len(values) <= 5:
            # Side legend needs more horizontal room
            safe_tight_layout(self.fig, rect=[0, 0, 0.75, 1])
        else:
            # Bottom legend needs more vertical room
            safe_tight_layout(self.fig, rect=[0, 0.1, 1, 0.9])
        
        self.draw()


class BarChart(BaseChart):
    """Bar chart for comparisons"""
    
    def __init__(self, title: str, parent=None, height=200, dpi=100):
        """
        Initialize bar chart
        
        Args:
            title: Chart title
            parent: Parent widget
            height: Chart height in pixels
            dpi: Chart resolution
        """
        # Calculate width based on height to maintain aspect ratio
        width_inches = height / dpi * 1.33  # Wider aspect ratio for bar charts
        height_inches = height / dpi * 1.2  # Add 20% more height for labels
        
        super().__init__(title, parent, width_inches, height_inches, dpi)
        
        # Set empty data
        self.data = []
        
        # Update display
        self._update_chart()
    
    def update_data(self, data: List[Tuple[str, float]]):
        """
        Update chart with new data
        
        Args:
            data: List of (label, value) tuples
        """
        self.data = data
        self._update_chart()
    
    def _update_chart(self):
        """Update chart with current data"""
        # Clear previous plot
        self.axes.clear()
        
        # Set title
        self.axes.set_title(self.title)
        
        if not self.data:
            self.axes.text(0.5, 0.5, "No data available", 
                         ha='center', va='center', fontsize=12, color='#ffffff')
            self.draw()
            return
        
        # Extract labels and values
        labels = [item[0] for item in self.data]
        values = [item[1] for item in self.data]
        
        # Create x-coordinates
        x = np.arange(len(labels))
        
        # Create colors array
        colors = plt.cm.tab10.colors[:len(values)]
        
        # Plot the bar chart
        bars = self.axes.bar(
            x, 
            values,
            color=colors,
            width=0.6,
            align='center'
        )
        
        # Set x-axis labels
        if len(labels) <= 10:
            # Show all labels if 10 or fewer
            self.axes.set_xticks(x)
            self.axes.set_xticklabels(labels, rotation=45 if len(labels) > 5 else 0, ha='right' if len(labels) > 5 else 'center')
        else:
            # Show fewer labels if more than 10
            step = max(1, len(labels) // 10)
            self.axes.set_xticks(x[::step])
            self.axes.set_xticklabels(labels[::step], rotation=45, ha='right')
        
        # Add value labels on top of bars
        if len(values) <= 10:
            for bar in bars:
                height = bar.get_height()
                self.axes.text(
                    bar.get_x() + bar.get_width()/2., 
                    height + 0.02 * max(values),
                    f'{height:.1f}' if isinstance(height, float) else str(height),
                    ha='center', 
                    va='bottom', 
                    fontsize=8
                )
        
        # Configure axes
        self.axes.set_ylim(0, max(values) * 1.15)  # Add 15% headroom
        
        # Update the plot with safe tight layout
        safe_tight_layout(self.fig)
        self.draw()


class TimeSeriesChart(BaseChart):
    """Time series chart for showing data over time"""
    
    def __init__(self, title: str, parent=None, height=200, dpi=100):
        """
        Initialize time series chart
        
        Args:
            title: Chart title
            parent: Parent widget
            height: Chart height in pixels
            dpi: Chart resolution
        """
        # Calculate width based on height to maintain aspect ratio
        width_inches = height / dpi * 1.5  # Wider aspect ratio for time series
        height_inches = height / dpi * 1.2  # Add 20% more height for labels
        
        super().__init__(title, parent, width_inches, height_inches, dpi)
        
        # Set empty data
        self.data = []
        
        # Update display
        self._update_chart()
    
    def update_data(self, data: List[Tuple[datetime, float]]):
        """
        Update chart with new data
        
        Args:
            data: List of (timestamp, value) tuples
        """
        self.data = data
        self._update_chart()
    
    def _update_chart(self):
        """Update chart with current data"""
        # Clear previous plot
        self.axes.clear()
        
        # Set title
        self.axes.set_title(self.title)
        
        if not self.data:
            self.axes.text(0.5, 0.5, "No data available", 
                         ha='center', va='center', fontsize=12, color='#ffffff')
            self.draw()
            return
        
        # Extract timestamps and values
        timestamps = [item[0] for item in self.data]
        values = [item[1] for item in self.data]
        
        # Plot the time series
        self.axes.plot(
            timestamps, 
            values,
            marker='o',
            linestyle='-',
            markersize=3,
            linewidth=1.5,
            color='#5a7d9a'
        )
        
        # Fill area under the curve
        self.axes.fill_between(
            timestamps, 
            values, 
            alpha=0.3, 
            color='#5a7d9a'
        )
        
        # Format x-axis as dates
        self.fig.autofmt_xdate()
        
        # Add grid
        self.axes.grid(True, linestyle='--', alpha=0.7)
        
        # Configure y-axis to start at 0
        self.axes.set_ylim(0, max(values) * 1.1)  # Add 10% headroom
        
        # Update the plot with safe tight layout
        safe_tight_layout(self.fig)
        self.draw()


class HeatmapChart(BaseChart):
    """Heatmap chart for showing 2D data intensity"""
    
    def __init__(self, title: str, parent=None, height=200, dpi=100):
        """
        Initialize heatmap chart
        
        Args:
            title: Chart title
            parent: Parent widget
            height: Chart height in pixels
            dpi: Chart resolution
        """
        # Calculate width based on height to maintain aspect ratio
        width_inches = height / dpi * 1.3  # More width for the colorbar
        height_inches = height / dpi * 1.2  # Add 20% more height for labels
        
        super().__init__(title, parent, width_inches, height_inches, dpi)
        
        # Set empty data
        self.data = None
        self.row_labels = []
        self.col_labels = []
        
        # Update display
        self._update_chart()
    
    def update_data(self, data: np.ndarray, row_labels: List[str], col_labels: List[str]):
        """
        Update chart with new data
        
        Args:
            data: 2D numpy array of values
            row_labels: Labels for rows
            col_labels: Labels for columns
        """
        self.data = data
        self.row_labels = row_labels
        self.col_labels = col_labels
        self._update_chart()
    
    def _update_chart(self):
        """Update chart with current data"""
        # Clear previous plot
        self.axes.clear()
        
        # Set title
        self.axes.set_title(self.title)
        
        if self.data is None or len(self.row_labels) == 0 or len(self.col_labels) == 0:
            self.axes.text(0.5, 0.5, "No data available", 
                         ha='center', va='center', fontsize=12, color='#ffffff')
            self.draw()
            return
        
        # Create the heatmap
        im = self.axes.imshow(self.data, cmap='viridis')
        
        # Add colorbar
        cbar = self.fig.colorbar(im, ax=self.axes)
        cbar.ax.tick_params(labelsize=8)
        
        # Set tick labels
        self.axes.set_xticks(np.arange(len(self.col_labels)))
        self.axes.set_yticks(np.arange(len(self.row_labels)))
        self.axes.set_xticklabels(self.col_labels, rotation=45, ha='right')
        self.axes.set_yticklabels(self.row_labels)
        
        # Set tick label size
        self.axes.tick_params(axis='both', which='major', labelsize=8)
        
        # Add value annotations
        for i in range(len(self.row_labels)):
            for j in range(len(self.col_labels)):
                value = self.data[i, j]
                # Choose text color based on background intensity
                text_color = 'white' if value > (self.data.max() + self.data.min()) / 2 else 'black'
                self.axes.text(j, i, f'{value:.1f}', 
                             ha='center', va='center', color=text_color, fontsize=8)
        
        # Update the plot with safe tight layout
        safe_tight_layout(self.fig)
        self.draw()


class TimelineChart(BaseChart):
    """Interactive timeline chart for events and time series data"""
    
    # Signal when a point on the timeline is selected
    from PyQt6.QtCore import pyqtSignal
    point_selected = pyqtSignal(dict)
    
    def __init__(self, title: str = "Timeline Analysis", parent=None, height=300, dpi=100):
        """
        Initialize timeline chart
        
        Args:
            title: Chart title
            parent: Parent widget
            height: Chart height in pixels
            dpi: Chart resolution
        """
        # Calculate width based on height to maintain aspect ratio
        width_inches = height / dpi * 1.6  # Wider aspect ratio for timelines
        height_inches = height / dpi
        
        super().__init__(title, parent, width_inches, height_inches, dpi)
        
        # Data storage
        self.events = []
        self.event_types = {}  # Maps type to color
        
        # Connect events
        self.fig.canvas.mpl_connect('pick_event', self._on_pick)
        
        # Update display
        self._update_chart()
    
    def set_data(self, events: List[Dict[str, Any]]):
        """
        Set timeline data
        
        Args:
            events: List of event dictionaries with keys:
                - time: datetime object
                - type: event type (string)
                - source: source entity (optional)
                - destination: destination entity (optional)
                - details: event details (optional)
                - severity: event severity (optional)
                - original: original event data object (optional)
        """
        self.events = sorted(events, key=lambda e: e["time"])
        
        # Set event type colors
        self.event_types = {}
        for event in events:
            event_type = event.get("type", "unknown")
            if event_type not in self.event_types:
                # Assign a color based on type
                if event_type == "anomaly":
                    self.event_types[event_type] = "#ff9800"  # Orange for anomalies
                elif event_type == "rule_match":
                    self.event_types[event_type] = "#f44336"  # Red for rule matches
                elif event_type == "connection":
                    self.event_types[event_type] = "#2196f3"  # Blue for connections
                else:
                    # Use a position in the color cycle based on the hash of the type
                    idx = hash(event_type) % len(plt.cm.tab10.colors)
                    self.event_types[event_type] = plt.cm.tab10.colors[idx]
        
        # Update the chart
        self._update_chart()
    
    def select_time_point(self, timestamp):
        """
        Highlight a particular time point
        
        Args:
            timestamp: datetime to select
        """
        # Find the closest event to the timestamp
        if not self.events:
            return
        
        closest_event = min(self.events, key=lambda e: abs((e["time"] - timestamp).total_seconds()))
        self.point_selected.emit(closest_event)
        
        # Update chart to highlight this point
        self._update_chart(highlight_event=closest_event)
    
    def focus_on_time(self, timestamp):
        """
        Adjust the view to focus on a specific time
        
        Args:
            timestamp: datetime to focus on
        """
        if not self.events:
            return
        
        # Select the time point
        self.select_time_point(timestamp)
        
        # Redraw
        self.draw()
    
    def _update_chart(self, highlight_event: Optional[Dict[str, Any]] = None):
        """
        Update chart with current data
        
        Args:
            highlight_event: Event to highlight (optional)
        """
        # Clear the plot
        self.axes.clear()
        
        # Set title
        self.axes.set_title(self.title)
        
        if not self.events:
            self.axes.text(0.5, 0.5, "No events available", 
                         ha='center', va='center', fontsize=12, color='#ffffff')
            self.draw()
            return
        
        # Extract times, types, and event groups
        times = [event["time"] for event in self.events]
        types = [event.get("type", "unknown") for event in self.events]
        
        # Group events by type for display
        event_groups = {}
        for event_type in set(types):
            event_groups[event_type] = [i for i, t in enumerate(types) if t == event_type]
        
        # Plot events as scatter plots by type
        highlight_point = None
        
        for event_type, indices in event_groups.items():
            event_times = [times[i] for i in indices]
            event_y = [1] * len(indices)  # All points at same y-level
            
            # Get color for this type
            color = self.event_types.get(event_type, "#999999")
            
            # Plot points
            points = self.axes.scatter(
                event_times, 
                event_y,
                marker='o',
                s=80,  # Size
                c=color,
                alpha=0.7,
                label=event_type.capitalize(),
                picker=5,  # Enable picking (clicking)
                zorder=10
            )
            
            # Store original events in point data
            points.set_pickradius(5)
            points.set_gid("events")
            
            # If we need to highlight a point, find its index
            if highlight_event:
                for i, event in enumerate(self.events):
                    if event == highlight_event and event.get("type") == event_type:
                        highlight_point = (event_times[event_groups[event_type].index(i)], 1)
        
        # Add connecting line
        self.axes.plot(
            times, 
            [1] * len(times),
            color="#dddddd",
            linewidth=2,
            zorder=5
        )
        
        # Highlight point if specified
        if highlight_point:
            self.axes.scatter(
                [highlight_point[0]], 
                [highlight_point[1]],
                marker='o',
                s=150,  # Larger size for highlight
                facecolors='none',
                edgecolors='black',
                linewidths=2,
                zorder=15
            )
        
        # Format x-axis as dates
        self.fig.autofmt_xdate()
        
        # Hide y-axis
        self.axes.set_yticks([])
        self.axes.set_yticklabels([])
        
        # Add legend
        if len(event_groups) > 1:
            self.axes.legend(loc='upper right')
        
        # Add grid
        self.axes.grid(True, linestyle='--', alpha=0.3, axis='x')
        
        # Update plot
        self.fig.tight_layout(pad=1.5, w_pad=1.0, h_pad=1.0)
        self.draw()
    
    def _on_pick(self, event):
        """
        Handle pick (click) events
        
        Args:
            event: Pick event
        """
        if event.artist.get_gid() == "events":
            # Get the index of the point
            ind = event.ind[0]
            
            # Find the corresponding event
            # We need to map back to the original events list
            points_artist = event.artist
            times = [event["time"] for event in self.events]
            clicked_time = points_artist.get_offsets()[ind][0]
            
            # Find the closest event by time
            event_idx = min(range(len(times)), key=lambda i: abs((times[i] - clicked_time).total_seconds()))
            selected_event = self.events[event_idx]
            
            # Emit signal
            self.point_selected.emit(selected_event)
            
            # Update chart to highlight this point
            self._update_chart(highlight_event=selected_event)


class NetworkGraph(QWidget):
    """Interactive network graph visualization"""
    
    # Signal when a node is selected
    from PyQt6.QtCore import pyqtSignal
    node_selected = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        """
        Initialize network graph
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Data storage
        self.nodes = []
        self.edges = []
        self.graph = None
        self.selected_node = None
        
        # Setup matplotlib
        self.fig = plt.figure(figsize=(6, 5), dpi=100)
        self.canvas = FigureCanvas(self.fig)
        
        # Create layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)
        
        # Connect events
        self.canvas.mpl_connect('button_press_event', self._on_click)
        
        # Initial draw
        self._draw_empty_graph()
    
    def set_data(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        """
        Set graph data
        
        Args:
            nodes: List of node dictionaries with keys:
                - id: node id (string)
                - type: node type (string)
                - threat_level: threat level (string, optional)
                - tags: list of tags (optional)
                - original: original entity data (optional)
            edges: List of edge dictionaries with keys:
                - source: source node id
                - target: target node id
                - type: edge type (string, optional)
                - weight: edge weight (float, optional)
                - original: original connection data (optional)
        """
        self.nodes = nodes
        self.edges = edges
        
        # Initialize node data dictionary
        self.node_data = {}
        for node in nodes:
            if 'id' in node:
                self.node_data[node['id']] = node
        
        # Create networkx graph
        self._create_graph()
        
        # Increase base node size
        self._adjust_node_sizes(scale_factor=2.0)
        
        # Draw graph
        self._draw_graph()
    
    def select_node(self, node_id):
        """
        Select a specific node
        
        Args:
            node_id: ID of node to select
        """
        # Find node with this ID
        for node in self.nodes:
            if node["id"] == node_id:
                self.selected_node = node
                self.node_selected.emit(node)
                self._draw_graph()  # Redraw with highlight
                break
    
    def _adjust_node_sizes(self, scale_factor=2.0):
        """
        Adjust node sizes by a scaling factor
        
        Args:
            scale_factor: Factor to multiply current sizes by
        """
        if hasattr(self, 'graph') and self.graph:
            # Initialize node_sizes if it doesn't exist
            if not hasattr(self, 'node_sizes'):
                self.node_sizes = {}
                
            # Scale all node sizes up
            for node in self.graph.nodes:
                # Get current node size if it exists
                current_size = 300  # Default size
                if hasattr(self, 'node_sizes') and node in self.node_sizes:
                    current_size = self.node_sizes[node]
                
                # Scale up the size
                self.node_sizes[node] = current_size * scale_factor
    
    def focus_on_entity(self, entity_value):
        """
        Focus on a specific entity in the graph
        
        Args:
            entity_value: Entity value to focus on
        """
        self.select_node(entity_value)
    
    def _create_graph(self):
        """Create networkx graph from nodes and edges"""
        import networkx as nx
        
        # Create graph
        self.graph = nx.DiGraph()
        
        # Add nodes
        for node in self.nodes:
            self.graph.add_node(
                node["id"],
                type=node.get("type", "unknown"),
                threat_level=node.get("threat_level", "unknown"),
                tags=node.get("tags", []),
                original=node.get("original")
            )
        
        # Add edges
        for edge in self.edges:
            self.graph.add_edge(
                edge["source"],
                edge["target"],
                type=edge.get("type", ""),
                weight=edge.get("weight", 1.0),
                original=edge.get("original")
            )
    
    def _draw_empty_graph(self):
        """Draw empty graph with message in dark theme"""
        self.fig.clear()
        ax = self.fig.add_subplot(111)
        
        # Set dark theme background with better contrast
        self.fig.patch.set_facecolor('#2d2d2d')
        ax.set_facecolor('#303030')
        
        # Display message with bright white text for better visibility
        ax.text(0.5, 0.5, "No network data available", 
               ha='center', va='center', fontsize=14, color='#ffffff')
               
        # Add a subtle hint message with better contrast
        ax.text(0.5, 0.6, "Import a PCAP file to analyze network connections", 
               ha='center', va='center', fontsize=10, color='#e0e0e0', 
               style='italic')
               
        ax.set_axis_off()
        self.canvas.draw()
    
    def _draw_graph(self):
        """Draw the graph with networkx and matplotlib"""
        if not self.graph or self.graph.number_of_nodes() == 0:
            self._draw_empty_graph()
            return
        
        import networkx as nx
        
        # Clear figure
        self.fig.clear()
        ax = self.fig.add_subplot(111)
        
        # Set dark background for graph
        self.fig.patch.set_facecolor('#2d2d2d')
        ax.set_facecolor('#303030')
        
        # Create positions with spring layout - use much tighter layout
        try:
            # Try to get a nice layout by adjusting k (optimal distance)
            num_nodes = self.graph.number_of_nodes()
            
            # Use very small k value to bring nodes much closer together
            # The smaller the k value, the closer nodes will be
            k_value = 0.5 / (num_nodes ** 0.5)  # Use 0.5 instead of 0.8 for tighter clusters
            
            # Increase iterations for better layout quality
            pos = nx.spring_layout(self.graph, k=k_value, seed=42, iterations=200)
        except Exception:
            # Fallback to default layout but still tight
            pos = nx.spring_layout(self.graph, seed=42, k=0.5, iterations=100)
        
        # Define node colors with highly saturated, vibrant colors for maximum contrast
        node_colors = []
        for node, data in self.graph.nodes(data=True):
            threat_level = data.get("threat_level", "unknown")
            if threat_level == "malicious":
                node_colors.append("#ff1744")  # Vibrant red
            elif threat_level == "suspicious":
                node_colors.append("#ff9100")  # Vibrant orange
            elif threat_level == "safe":
                node_colors.append("#00e676")  # Vibrant green
            else:
                node_colors.append("#2979ff")  # Vibrant blue
        
        # Define node sizes based on centrality or use predefined sizes
        # Use MUCH larger node sizes for better visibility
        try:
            if hasattr(self, 'node_sizes') and self.node_sizes:
                # Use predefined sizes but ensure they're large enough
                node_sizes = [max(self.node_sizes[node], 1000) for node in self.graph.nodes()]
            else:
                # Calculate based on centrality with much larger base size
                centrality = nx.betweenness_centrality(self.graph)
                # Minimum size of 1000, scaling up to 3000 based on centrality
                node_sizes = [1000 + 2000 * (centrality[node] + 0.1) for node in self.graph.nodes()]
        except Exception:
            # Fallback to fixed large size
            node_sizes = [1200] * self.graph.number_of_nodes()
        
        # Define edge colors based on type - brighter for dark theme
        edge_colors = []
        for u, v, data in self.graph.edges(data=True):
            edge_type = data.get("type", "")
            if edge_type.upper() in ["HTTP", "HTTPS"]:
                edge_colors.append("#69f0ae")  # Brighter green for HTTP/HTTPS
            elif edge_type.upper() in ["DNS"]:
                edge_colors.append("#ea80fc")  # Brighter purple for DNS
            elif edge_type.upper() in ["SSH", "SFTP", "SCP"]:
                edge_colors.append("#ffab40")  # Brighter orange for secure protocols
            else:
                edge_colors.append("#e0e0e0")  # Lighter grey
        
        # Draw the graph with highly visible, glossy edges
        nx.draw_networkx_edges(
            self.graph, pos, 
            width=3.5,  # Even thicker edges for maximum visibility
            alpha=1.0,  # Full opacity
            edge_color=edge_colors,
            connectionstyle="arc3,rad=0.15",  # More curved edges for better visibility
            arrows=True,
            arrowstyle='-|>',  # Better arrow style
            arrowsize=30,  # Much larger arrows for better visibility
            node_size=node_sizes,  # Pass node sizes to fix arrow positions
            ax=ax,
            min_source_margin=18,  # Increased margin from source node
            min_target_margin=18   # Increased margin from target node
        )
        
        # Draw nodes with enhanced visibility
        nodes = nx.draw_networkx_nodes(
            self.graph, pos,
            node_color=node_colors,
            node_size=node_sizes,
            alpha=0.95,  # Nearly fully opaque
            edgecolors='white',  # White borders
            linewidths=2.0,  # Thicker borders for better definition
            ax=ax
        )
        
        # Enable node picking (clicking)
        nodes.set_picker(15)  # Even larger picking radius for better interaction
        
        # Draw labels with high contrast white text for dark background
        nx.draw_networkx_labels(
            self.graph, pos,
            font_size=11,  # Larger font for better readability
            font_weight='bold',
            font_color='white',  # White text for dark background
            ax=ax,
            bbox=dict(facecolor='#303030', edgecolor='none', alpha=0.7, pad=2)  # Background for better text contrast
        )
        
        # Highlight selected node if any with enhanced glow effect
        if self.selected_node:
            node_id = self.selected_node["id"]
            if node_id in self.graph.nodes:
                # Draw outer glow
                nx.draw_networkx_nodes(
                    self.graph, pos,
                    nodelist=[node_id],
                    node_color='white',
                    node_size=node_sizes[list(self.graph.nodes).index(node_id)] * 1.5,
                    alpha=0.2,
                    edgecolors='#ffffff',
                    linewidths=6.0,
                    ax=ax
                )
                
                # Draw inner highlight
                nx.draw_networkx_nodes(
                    self.graph, pos,
                    nodelist=[node_id],
                    node_color='white',
                    node_size=node_sizes[list(self.graph.nodes).index(node_id)] * 1.3,
                    alpha=0.3,
                    edgecolors='#e0e0e0',
                    linewidths=3.0,
                    ax=ax
                )
        
        # Turn off axis
        ax.set_axis_off()
        
        # Adjust layout safely
        safe_tight_layout(self.fig, pad=0.5)
        
        # Draw canvas
        self.canvas.draw()
    
    def _on_click(self, event):
        """
        Handle click events
        
        Args:
            event: Click event
        """
        # Check if this is a proper pick event with artists
        if not hasattr(event, 'artist'):
            return
            
        # Check if a node was clicked
        if event.artist and hasattr(event.artist, 'get_offsets'):
            # Make sure the event has an ind attribute
            if not hasattr(event, 'ind') or len(event.ind) == 0:
                return
                
            # Get the index of the selected node
            ind = event.ind[0]
            
            # Safety check for node list
            if not self.graph or not self.graph.nodes or ind >= len(list(self.graph.nodes)):
                return
            
            # Get node id
            node_id = list(self.graph.nodes)[ind]
            
            # Find node data
            for node in self.nodes:
                if node["id"] == node_id:
                    self.selected_node = node
                    self.node_selected.emit(node)
                    self._draw_graph()  # Redraw with highlight
                    break


class ChartWidget(QWidget):
    """Widget that combines a chart with a title and optional description"""
    
    def __init__(self, title: str, chart_type: str, parent=None):
        """
        Initialize chart widget
        
        Args:
            title: Chart title
            chart_type: Type of chart to create ('pie', 'bar', 'time', 'heatmap', 'timeline', 'network')
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Create layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Create title label
        self.title_label = QLabel(title)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setBold(True)
        self.title_label.setFont(font)
        layout.addWidget(self.title_label)
        
        # Create chart based on type
        if chart_type == 'pie':
            self.chart = PieChart(title)
        elif chart_type == 'bar':
            self.chart = BarChart(title)
        elif chart_type == 'time':
            self.chart = TimeSeriesChart(title)
        elif chart_type == 'heatmap':
            self.chart = HeatmapChart(title)
        elif chart_type == 'timeline':
            self.chart = TimelineChart(title)
        elif chart_type == 'network':
            self.chart = NetworkGraph()
        else:
            self.chart = PieChart(title)  # Default to pie chart
        
        layout.addWidget(self.chart)
        
        # Create description label (hidden by default)
        self.description_label = QLabel()
        self.description_label.setWordWrap(True)
        self.description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.description_label.setVisible(False)
        layout.addWidget(self.description_label)
    
    def update_data(self, data):
        """
        Update chart with new data
        
        Args:
            data: Data appropriate for the chart type
        """
        self.chart.update_data(data)
    
    def set_description(self, text: str):
        """
        Set description text
        
        Args:
            text: Description text
        """
        self.description_label.setText(text)
        self.description_label.setVisible(bool(text))
    
    def set_title(self, title: str):
        """
        Set chart title
        
        Args:
            title: New title
        """
        self.title_label.setText(title)
        if hasattr(self.chart, 'title') and hasattr(self.chart, 'axes'):
            self.chart.title = title
            self.chart.axes.set_title(title)
            self.chart.draw()