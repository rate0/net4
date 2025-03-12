import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import numpy as np
from typing import List, Tuple, Dict, Any, Optional
from datetime import datetime

from PyQt6.QtWidgets import QSizePolicy, QVBoxLayout, QWidget, QLabel
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont


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
        
        # Set up figure appearance
        self.fig.set_tight_layout({"pad": 1.5, "w_pad": 1.0, "h_pad": 1.0})
        self.fig.patch.set_facecolor('#f0f0f0')
        self.axes.set_facecolor('#fafafa')
        
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
                         ha='center', va='center', fontsize=10)
            self.draw()
            return
        
        # Extract labels and values
        labels = [item[0] for item in self.data]
        values = [item[1] for item in self.data]
        
        # Create explode array (slight separation for first slice)
        self.explode = [0.05] + [0] * (len(values) - 1) if len(values) > 1 else None
        
        # Create colors array
        colors = plt.cm.tab10.colors[:len(values)]
        
        # Plot the pie chart
        wedges, texts, autotexts = self.axes.pie(
            values, 
            labels=labels if len(values) <= 5 else None,  # Only show labels if 5 or fewer slices
            explode=self.explode,
            colors=colors,
            autopct='%1.1f%%' if len(values) <= 7 else None,  # Only show percentages if 7 or fewer slices
            shadow=False,
            startangle=90,
            textprops={'fontsize': 8}
        )
        
        # Set font size for percentage labels
        for autotext in autotexts:
            autotext.set_fontsize(8)
        
        # Add legend if we have more than 5 slices
        if len(values) > 5:
            self.axes.legend(
                wedges, 
                labels, 
                loc='center left', 
                bbox_to_anchor=(1, 0.5),
                fontsize=8
            )
        
        # Equal aspect ratio ensures that pie is drawn as a circle
        self.axes.set_aspect('equal')
        
        # Update the plot
        self.fig.tight_layout(pad=1.5, w_pad=1.0, h_pad=1.0)
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
                         ha='center', va='center', fontsize=10)
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
        
        # Update the plot
        self.fig.tight_layout(pad=1.5, w_pad=1.0, h_pad=1.0)
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
                         ha='center', va='center', fontsize=10)
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
        
        # Update the plot
        self.fig.tight_layout(pad=1.5, w_pad=1.0, h_pad=1.0)
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
                         ha='center', va='center', fontsize=10)
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
        
        # Update the plot
        self.fig.tight_layout(pad=1.5, w_pad=1.0, h_pad=1.0)
        self.draw()


class ChartWidget(QWidget):
    """Widget that combines a chart with a title and optional description"""
    
    def __init__(self, title: str, chart_type: str, parent=None):
        """
        Initialize chart widget
        
        Args:
            title: Chart title
            chart_type: Type of chart to create ('pie', 'bar', 'time', 'heatmap')
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
        self.chart.title = title
        self.chart.axes.set_title(title)
        self.chart.draw()