import math
from typing import Dict, List, Any, Optional, Set, Tuple

import networkx as nx
import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QScrollArea, QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QGridLayout, QGroupBox, QLineEdit, QToolBar, QCheckBox,
    QSlider, QSpinBox, QSizePolicy, QRadioButton, QButtonGroup, QMessageBox
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QColor

from ..widgets.data_table import DataTable

from ...models.session import Session

# Check if scipy is available
SCIPY_AVAILABLE = True
try:
    import scipy
except ImportError:
    SCIPY_AVAILABLE = False


class NetworkGraphView(FigureCanvas):
    """
    Custom widget for displaying and interacting with network graphs
    """
    
    # Signal emitted when a node is selected
    nodeSelected = pyqtSignal(str, dict)
    
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        """Initialize network graph view"""
        # Create figure and axes
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = self.fig.add_subplot(111)
        
        # Initialize graph data
        self.G = nx.Graph()
        self.pos = {}  # Node positions
        self.node_sizes = {}  # Node sizes
        self.node_colors = {}  # Node colors
        self.node_data = {}  # Additional node data
        
        # Node selection
        self.selected_node = None
        self.hover_node = None
        
        # Initialize canvas
        super().__init__(self.fig)
        self.setParent(parent)
        
        # Set size policy
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.updateGeometry()
        
        # Connect events
        self.mpl_connect('button_press_event', self._on_click)
        self.mpl_connect('motion_notify_event', self._on_hover)
        
        # Set up appearance
        self.fig.subplots_adjust(left=0.05, right=0.95, top=0.95, bottom=0.05)
        self.fig.patch.set_facecolor('#f0f0f0')
        self.axes.set_facecolor('#fafafa')
    
    def set_graph(self, graph: nx.Graph, layout: str = 'spring'):
        """
        Set the graph to display
        
        Args:
            graph: NetworkX graph
            layout: Layout algorithm ('spring', 'circular', 'kamada_kawai', etc.)
        """
        self.G = graph
        
        # Check if graph is empty
        if len(graph) == 0:
            self._draw_graph()
            return
        
        # Calculate layout
        try:
            if layout == 'spring':
                if SCIPY_AVAILABLE:
                    self.pos = nx.spring_layout(graph, k=0.3, iterations=50)
                else:
                    # Fall back to a simpler layout if scipy is not available
                    self.pos = nx.circular_layout(graph)
            elif layout == 'circular':
                self.pos = nx.circular_layout(graph)
            elif layout == 'shell':
                self.pos = nx.shell_layout(graph)
            elif layout == 'kamada_kawai':
                if SCIPY_AVAILABLE:
                    self.pos = nx.kamada_kawai_layout(graph)
                else:
                    # Fall back to a simpler layout if scipy is not available
                    self.pos = nx.circular_layout(graph)
            else:
                self.pos = nx.circular_layout(graph)
        except Exception as e:
            # Fall back to circular layout if any error occurs
            self.pos = nx.circular_layout(graph)
        
        # Calculate node sizes based on degree
        degrees = dict(graph.degree())
        min_degree = max(1, min(degrees.values())) if degrees else 1
        max_degree = max(min_degree, max(degrees.values())) if degrees else 1
        
        if max_degree > min_degree:
            self.node_sizes = {
                node: 100 + 300 * ((degrees[node] - min_degree) / (max_degree - min_degree))
                for node in graph.nodes()
            }
        else:
            self.node_sizes = {node: 200 for node in graph.nodes()}
        
        # Store node data
        self.node_data = {node: data for node, data in graph.nodes(data=True)}
        
        # Draw the graph
        self._draw_graph()
    
    def _draw_graph(self):
        """Draw or redraw the graph"""
        # Clear previous plot
        self.axes.clear()
        
        if not self.G or len(self.G) == 0:
            self.axes.text(0.5, 0.5, "No graph data available", 
                         ha='center', va='center', fontsize=12)
            self.draw()
            return
        
        # Get node colors
        node_colors = [self._get_node_color(node) for node in self.G.nodes()]
        
        # Draw nodes
        nx.draw_networkx_nodes(
            self.G, self.pos,
            ax=self.axes,
            node_size=[self.node_sizes[node] for node in self.G.nodes()],
            node_color=node_colors,
            alpha=0.8,
            linewidths=1,
            edgecolors='black'
        )
        
        # Draw edges
        nx.draw_networkx_edges(
            self.G, self.pos,
            ax=self.axes,
            width=1.0,
            alpha=0.5,
            edge_color='gray'
        )
        
        # Draw labels (for nodes with larger sizes)
        labels = {node: node for node in self.G.nodes() 
                 if self.node_sizes[node] > 150}
        nx.draw_networkx_labels(
            self.G, self.pos,
            ax=self.axes,
            labels=labels,
            font_size=8,
            font_color='black'
        )
        
        # Highlight selected node if any
        if self.selected_node and self.selected_node in self.G:
            nx.draw_networkx_nodes(
                self.G, self.pos,
                ax=self.axes,
                nodelist=[self.selected_node],
                node_size=self.node_sizes[self.selected_node] + 50,
                node_color='none',
                linewidths=3,
                edgecolors='blue'
            )
        
        # Highlight hover node if any
        if self.hover_node and self.hover_node in self.G and self.hover_node != self.selected_node:
            nx.draw_networkx_nodes(
                self.G, self.pos,
                ax=self.axes,
                nodelist=[self.hover_node],
                node_size=self.node_sizes[self.hover_node] + 30,
                node_color='none',
                linewidths=2,
                edgecolors='green'
            )
        
        # Configure axes
        self.axes.set_axis_off()
        self.axes.set_xlim(-1.1, 1.1)
        self.axes.set_ylim(-1.1, 1.1)
        
        # Draw the updated plot
        self.draw()
    
    def _get_node_color(self, node):
        """
        Get color for a node based on its attributes
        
        Args:
            node: Node identifier
            
        Returns:
            Color string or RGBA value
        """
        # Get node data
        data = self.node_data.get(node, {})
        
        # Default color
        color = '#aaaaaa'  # Gray
        
        # Color based on node type
        node_type = data.get('type', 'unknown')
        
        if node_type == 'ip':
            # Color based on threat level
            threat_level = data.get('threat_level', 'unknown')
            
            if threat_level == 'malicious':
                color = '#ff5555'  # Red
            elif threat_level == 'suspicious':
                color = '#ffaa55'  # Orange
            elif threat_level == 'safe':
                color = '#55aa55'  # Green
            elif threat_level == 'clean':  # Added clean to handle this case
                color = '#55aa55'  # Green (same as safe)
            else:
                color = '#5555aa'  # Blue
        
        elif node_type == 'domain':
            color = '#55aaaa'  # Teal
            
            # Color based on threat level
            threat_level = data.get('threat_level', 'unknown')
            
            if threat_level == 'malicious':
                color = '#ff55aa'  # Pink
            elif threat_level == 'suspicious':
                color = '#ffaaaa'  # Light red
            elif threat_level == 'clean':  # Added clean to handle this case
                color = '#55bb99'  # Blue-green
        
        return color
    
    def _on_click(self, event):
        """
        Handle mouse click event
        
        Args:
            event: Matplotlib event
        """
        if event.inaxes != self.axes:
            return
            
        # Find closest node
        node = self._find_nearest_node(event.xdata, event.ydata)
        
        if node:
            # Select this node
            self.selected_node = node
            self._draw_graph()
            
            # Emit signal with node data
            self.nodeSelected.emit(node, self.node_data.get(node, {}))
        else:
            # Deselect current node
            self.selected_node = None
            self._draw_graph()
            
            # Emit signal with None
            self.nodeSelected.emit("", {})
    
    def _on_hover(self, event):
        """
        Handle mouse hover event
        
        Args:
            event: Matplotlib event
        """
        if event.inaxes != self.axes:
            self.hover_node = None
            self._draw_graph()
            return
            
        # Find closest node
        node = self._find_nearest_node(event.xdata, event.ydata)
        
        if node and node != self.hover_node:
            # Update hover node
            self.hover_node = node
            self._draw_graph()
        elif not node and self.hover_node:
            # Reset hover node
            self.hover_node = None
            self._draw_graph()
    
    def _find_nearest_node(self, x, y):
        """
        Find the nearest node to a position
        
        Args:
            x: X coordinate
            y: Y coordinate
            
        Returns:
            Nearest node or None
        """
        if not self.G or len(self.G) == 0:
            return None
            
        # Calculate distances to each node
        distances = {
            node: math.sqrt((self.pos[node][0] - x) ** 2 + (self.pos[node][1] - y) ** 2)
            for node in self.G.nodes()
        }
        
        # Find node with minimum distance
        nearest_node = min(distances, key=distances.get)
        
        # Check if click is within node radius
        node_size = self.node_sizes[nearest_node]
        distance = distances[nearest_node]
        
        # Convert node size to radius in figure coordinates
        radius = math.sqrt(node_size / math.pi) / 100
        
        if distance <= radius:
            return nearest_node
        else:
            return None
    
    def set_node_data(self, node: str, data: Dict[str, Any]):
        """
        Update data for a node
        
        Args:
            node: Node identifier
            data: Node data dictionary
        """
        if node in self.node_data:
            self.node_data[node].update(data)
            self._draw_graph()
    
    def select_node(self, node: str):
        """
        Select a node programmatically
        
        Args:
            node: Node to select
        """
        if node in self.G:
            self.selected_node = node
            self._draw_graph()
            
            # Emit signal with node data
            self.nodeSelected.emit(node, self.node_data.get(node, {}))


class GraphViewDashboard(QWidget):
    """
    Dashboard for graph-based network visualization and exploration.
    Provides interactive graph visualization of network entities and connections.
    """
    
    def __init__(self, session: Session, parent=None):
        """
        Initialize graph view dashboard
        
        Args:
            session: Analysis session
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.session = session
        self.current_graph = None
        self.current_layout = "spring"
        
        # Check if scipy is available
        if not SCIPY_AVAILABLE:
            self.show_scipy_warning()
        
        self._init_ui()
    
    def show_scipy_warning(self):
        """Show a warning message about missing scipy dependency"""
        # This is optional - you can remove this if you don't want to show a warning
        # each time the user opens the dashboard
        QMessageBox.warning(
            self,
            "Missing Dependency",
            "The 'scipy' library is not installed. Some graph layouts will not be available.\n\n"
            "You can install it by running: pip install scipy"
        )
    
    def _init_ui(self):
        """Initialize dashboard UI"""
        # Main layout
        layout = QVBoxLayout(self)
        
        # Toolbar for controls
        toolbar = QToolBar()
        toolbar.setIconSize(QSize(16, 16))
        
        # Graph type selector
        type_label = QLabel("Graph type:")
        toolbar.addWidget(type_label)
        
        self.graph_type = QComboBox()
        self.graph_type.addItems([
            "Entity Relationship", "IP Communication", "Domain Resolution"
        ])
        self.graph_type.setMaximumWidth(150)
        self.graph_type.currentTextChanged.connect(self._rebuild_graph)
        toolbar.addWidget(self.graph_type)
        
        toolbar.addSeparator()
        
        # Layout selector
        layout_label = QLabel("Layout:")
        toolbar.addWidget(layout_label)
        
        self.layout_type = QComboBox()
        layout_options = ["Circular", "Shell"]
        if SCIPY_AVAILABLE:
            layout_options.extend(["Spring", "Kamada-Kawai"])
        self.layout_type.addItems(layout_options)
        self.layout_type.setMaximumWidth(120)
        self.layout_type.currentTextChanged.connect(self._change_layout)
        toolbar.addWidget(self.layout_type)
        
        toolbar.addSeparator()
        
        # Node filter controls
        filter_label = QLabel("Show:")
        toolbar.addWidget(filter_label)
        
        # Entity type filters
        self.filter_ip = QCheckBox("IPs")
        self.filter_ip.setChecked(True)
        self.filter_ip.stateChanged.connect(self._rebuild_graph)
        toolbar.addWidget(self.filter_ip)
        
        self.filter_domain = QCheckBox("Domains")
        self.filter_domain.setChecked(True)
        self.filter_domain.stateChanged.connect(self._rebuild_graph)
        toolbar.addWidget(self.filter_domain)
        
        # Threat level filters
        toolbar.addSeparator()
        
        threat_label = QLabel("Threat:")
        toolbar.addWidget(threat_label)
        
        self.filter_all = QRadioButton("All")
        self.filter_all.setChecked(True)
        toolbar.addWidget(self.filter_all)
        
        self.filter_malicious = QRadioButton("Malicious")
        toolbar.addWidget(self.filter_malicious)
        
        self.filter_suspicious = QRadioButton("Suspicious+")
        toolbar.addWidget(self.filter_suspicious)
        
        # Group threat radio buttons
        self.threat_group = QButtonGroup(self)
        self.threat_group.addButton(self.filter_all)
        self.threat_group.addButton(self.filter_malicious)
        self.threat_group.addButton(self.filter_suspicious)
        self.threat_group.buttonClicked.connect(self._rebuild_graph)
        
        # Add reset button
        toolbar.addSeparator()
        
        reset_button = QPushButton("Reset View")
        reset_button.clicked.connect(self._reset_view)
        toolbar.addWidget(reset_button)
        
        # Add toolbar to layout
        layout.addWidget(toolbar)
        
        # Main content area with splitter
        self.content_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Graph view (left side)
        self.graph_container = QWidget()
        graph_layout = QVBoxLayout(self.graph_container)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create graph canvas
        self.graph_view = NetworkGraphView()
        self.graph_view.nodeSelected.connect(self._node_selected)
        
        # Add matplotlib toolbar
        self.toolbar = NavigationToolbar(self.graph_view, self)
        
        graph_layout.addWidget(self.toolbar)
        graph_layout.addWidget(self.graph_view)
        
        self.content_splitter.addWidget(self.graph_container)
        
        # Entity details panel (right side)
        self.details_widget = QWidget()
        self.details_layout = QVBoxLayout(self.details_widget)
        
        # Node details group
        self.node_details = QGroupBox("Node Details")
        self.node_details.setMinimumWidth(250)
        node_layout = QVBoxLayout(self.node_details)
        
        # Node info panel
        node_info_grid = QGridLayout()
        
        # Node info labels
        label_pairs = [
            ("Value:", QLabel("")),
            ("Type:", QLabel("")),
            ("Threat Level:", QLabel("")),
            ("Connections:", QLabel("")),
        ]
        
        self.node_labels = {}
        
        for i, (label_text, value_label) in enumerate(label_pairs):
            label = QLabel(label_text)
            label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            font = QFont()
            font.setBold(True)
            label.setFont(font)
            
            node_info_grid.addWidget(label, i, 0)
            node_info_grid.addWidget(value_label, i, 1)
            
            # Store reference to value label
            key = label_text.replace(":", "").lower().replace(" ", "_")
            self.node_labels[key] = value_label
        
        node_layout.addLayout(node_info_grid)
        
        # Add a spacer
        node_layout.addSpacing(10)
        
        # Neighbors label
        neighbors_label = QLabel("Connected Nodes:")
        font = QFont()
        font.setBold(True)
        neighbors_label.setFont(font)
        node_layout.addWidget(neighbors_label)
        
        # Neighbors table
        self.neighbors_table = DataTable(
            ["Node", "Type", "Threat Level"],
            []
        )
        node_layout.addWidget(self.neighbors_table)
        
        self.details_layout.addWidget(self.node_details)
        
        # Graph statistics group
        self.graph_stats = QGroupBox("Graph Statistics")
        stats_layout = QVBoxLayout(self.graph_stats)
        
        stats_grid = QGridLayout()
        
        # Stats labels
        stats_pairs = [
            ("Nodes:", QLabel("0")),
            ("Edges:", QLabel("0")),
            ("IP Nodes:", QLabel("0")),
            ("Domain Nodes:", QLabel("0")),
            ("Malicious Nodes:", QLabel("0")),
            ("Suspicious Nodes:", QLabel("0")),
        ]
        
        self.stats_labels = {}
        
        for i, (label_text, value_label) in enumerate(stats_pairs):
            label = QLabel(label_text)
            label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            font = QFont()
            font.setBold(True)
            label.setFont(font)
            
            stats_grid.addWidget(label, i, 0)
            stats_grid.addWidget(value_label, i, 1)
            
            # Store reference to value label
            key = label_text.replace(":", "").lower().replace(" ", "_")
            self.stats_labels[key] = value_label
        
        stats_layout.addLayout(stats_grid)
        
        self.details_layout.addWidget(self.graph_stats)
        self.details_layout.addStretch()
        
        self.content_splitter.addWidget(self.details_widget)
        
        # Set initial splitter sizes (graph view should be larger)
        self.content_splitter.setSizes([700, 300])
        
        # Add content splitter to layout
        layout.addWidget(self.content_splitter)
        
        # Initialize with empty graph
        if not hasattr(self.session, 'network_entities') or not self.session.network_entities:
            # Just create an empty graph if there are no entities
            self.current_graph = nx.Graph()
            self.graph_view.set_graph(self.current_graph, layout="circular")
        else:
            try:
                self._build_entity_graph()
            except Exception as e:
                self.current_graph = nx.Graph()
                self.graph_view.set_graph(self.current_graph, layout="circular")
                print(f"Error building initial graph: {e}")
    
    def update_dashboard(self):
        """Update dashboard with current session data"""
        try:
            # Rebuild current graph with new data
            self._rebuild_graph()
        except Exception as e:
            print(f"Error updating dashboard: {e}")
    
    def _build_entity_graph(self):
        """Build entity relationship graph"""
        G = nx.Graph()
        
        if not hasattr(self.session, 'network_entities'):
            # Just return an empty graph if there are no entities
            self.current_graph = G
            self.graph_view.set_graph(G, layout=self.current_layout.lower())
            self._update_graph_stats()
            return
        
        # Add nodes with attributes
        for entity_id, entity in self.session.network_entities.items():
            # Apply entity type filters
            if entity.type == "ip" and not self.filter_ip.isChecked():
                continue
            if entity.type == "domain" and not self.filter_domain.isChecked():
                continue
            
            # Apply threat level filters
            if self.filter_malicious.isChecked() and entity.threat_level != "malicious":
                continue
            if self.filter_suspicious.isChecked() and entity.threat_level not in ["malicious", "suspicious"]:
                continue
            
            # Add node with attributes
            G.add_node(entity.value, 
                      id=entity.id,
                      type=entity.type, 
                      threat_level=entity.threat_level,
                      confidence=entity.confidence)
        
        # Add edges for related entities
        if hasattr(entity, 'related_entities'):
            for entity_id, entity in self.session.network_entities.items():
                # Skip if entity is filtered out
                if entity.value not in G:
                    continue
                    
                # Add edges to related entities
                for related_id in entity.related_entities:
                    if related_id in self.session.network_entities:
                        related = self.session.network_entities[related_id]
                        
                        # Skip if related entity is filtered out
                        if related.value not in G:
                            continue
                            
                        G.add_edge(entity.value, related.value)
        
        # Add edges from connections
        if hasattr(self.session, 'connections'):
            ip_edges = set()
            for conn in self.session.connections:
                src_ip = conn.get("src_ip")
                dst_ip = conn.get("dst_ip")
                
                if src_ip and dst_ip and src_ip in G and dst_ip in G:
                    # Add edge if not already present
                    ip_edges.add((src_ip, dst_ip))
            
            # Add all IP connection edges
            for src, dst in ip_edges:
                G.add_edge(src, dst)
        
        # Update graph
        self.current_graph = G
        self.graph_view.set_graph(G, layout=self.current_layout.lower())
        
        # Update statistics
        self._update_graph_stats()
    
    def _build_ip_graph(self):
        """Build IP communication graph"""
        G = nx.Graph()
        
        if not hasattr(self.session, 'network_entities'):
            # Just return an empty graph if there are no entities
            self.current_graph = G
            self.graph_view.set_graph(G, layout=self.current_layout.lower())
            self._update_graph_stats()
            return
        
        # Add IP nodes with attributes
        ip_entities = {}
        for entity_id, entity in self.session.network_entities.items():
            if entity.type == "ip":
                # Apply threat level filters
                if self.filter_malicious.isChecked() and entity.threat_level != "malicious":
                    continue
                if self.filter_suspicious.isChecked() and entity.threat_level not in ["malicious", "suspicious"]:
                    continue
                
                # Add node with attributes
                G.add_node(entity.value, 
                          id=entity.id,
                          type=entity.type, 
                          threat_level=entity.threat_level,
                          confidence=entity.confidence)
                          
                ip_entities[entity.value] = entity
        
        # Add edges from connections
        if hasattr(self.session, 'connections'):
            ip_edges = {}
            for conn in self.session.connections:
                src_ip = conn.get("src_ip")
                dst_ip = conn.get("dst_ip")
                
                if src_ip and dst_ip and src_ip in G and dst_ip in G:
                    # Track connection count between IPs
                    edge_key = tuple(sorted([src_ip, dst_ip]))
                    ip_edges[edge_key] = ip_edges.get(edge_key, 0) + 1
            
            # Add edges with weights based on connection counts
            for (src, dst), count in ip_edges.items():
                G.add_edge(src, dst, weight=count)
        
        # Update graph
        self.current_graph = G
        self.graph_view.set_graph(G, layout=self.current_layout.lower())
        
        # Update statistics
        self._update_graph_stats()
    
    def _build_domain_graph(self):
        """Build domain resolution graph"""
        G = nx.Graph()
        
        if not hasattr(self.session, 'network_entities'):
            # Just return an empty graph if there are no entities
            self.current_graph = G
            self.graph_view.set_graph(G, layout=self.current_layout.lower())
            self._update_graph_stats()
            return
        
        # Add domain and IP nodes
        for entity_id, entity in self.session.network_entities.items():
            # Apply entity type filters
            if entity.type == "ip" and not self.filter_ip.isChecked():
                continue
            if entity.type == "domain" and not self.filter_domain.isChecked():
                continue
            
            # Apply threat level filters
            if self.filter_malicious.isChecked() and entity.threat_level != "malicious":
                continue
            if self.filter_suspicious.isChecked() and entity.threat_level not in ["malicious", "suspicious"]:
                continue
            
            # Add to graph
            if entity.type in ["ip", "domain"]:
                G.add_node(entity.value, 
                          id=entity.id,
                          type=entity.type, 
                          threat_level=entity.threat_level,
                          confidence=entity.confidence)
        
        # Look for DNS relationships in packets
        if hasattr(self.session, 'packets'):
            domain_to_ip = {}
            
            for packet in self.session.packets:
                # Look for DNS responses
                if "dns" in packet:
                    dns_data = packet.get("dns", {})
                    
                    if dns_data.get("query_type") == "response":
                        domains = dns_data.get("domains", [])
                        
                        # Extract source/destination IPs
                        src_ip = packet.get("src_ip")
                        dst_ip = packet.get("dst_ip")
                        
                        if domains and (src_ip or dst_ip):
                            for domain in domains:
                                # Add domain-IP relationship
                                if domain in G:
                                    if src_ip and src_ip in G:
                                        domain_to_ip.setdefault(domain, set()).add(src_ip)
                                    if dst_ip and dst_ip in G:
                                        domain_to_ip.setdefault(domain, set()).add(dst_ip)
            
            # Add edges for domain-IP relationships
            for domain, ips in domain_to_ip.items():
                for ip in ips:
                    G.add_edge(domain, ip, relation="resolution")
        
        # Update graph
        self.current_graph = G
        self.graph_view.set_graph(G, layout=self.current_layout.lower())
        
        # Update statistics
        self._update_graph_stats()
    
    def _rebuild_graph(self):
        """Rebuild graph based on current settings"""
        try:
            graph_type = self.graph_type.currentText()
            
            if graph_type == "Entity Relationship":
                self._build_entity_graph()
            elif graph_type == "IP Communication":
                self._build_ip_graph()
            elif graph_type == "Domain Resolution":
                self._build_domain_graph()
        except Exception as e:
            print(f"Error rebuilding graph: {e}")
            # Create an empty graph as fallback
            self.current_graph = nx.Graph()
            self.graph_view.set_graph(self.current_graph, layout="circular")
    
    def _change_layout(self):
        """Change graph layout algorithm"""
        # Get selected layout
        layout_text = self.layout_type.currentText()
        
        # Map display name to layout name
        layout_map = {
            "Spring": "spring",
            "Circular": "circular",
            "Shell": "shell",
            "Kamada-Kawai": "kamada_kawai"
        }
        
        self.current_layout = layout_map.get(layout_text, "circular")
        
        # Check if the layout requires scipy
        if self.current_layout in ["spring", "kamada_kawai"] and not SCIPY_AVAILABLE:
            # Fall back to circular layout
            self.current_layout = "circular"
        
        # Re-draw graph with new layout
        if self.current_graph:
            self.graph_view.set_graph(self.current_graph, layout=self.current_layout)
    
    def _reset_view(self):
        """Reset graph view to defaults"""
        # Reset filters
        self.filter_ip.setChecked(True)
        self.filter_domain.setChecked(True)
        self.filter_all.setChecked(True)
        
        # Reset graph type
        self.graph_type.setCurrentText("Entity Relationship")
        
        # Reset layout to one that doesn't require scipy if not available
        if SCIPY_AVAILABLE:
            self.layout_type.setCurrentText("Spring")
        else:
            self.layout_type.setCurrentText("Circular")
        
        # Rebuild graph
        self._rebuild_graph()
    
    def _node_selected(self, node_id: str, node_data: Dict[str, Any]):
        """
        Handle node selection in graph
        
        Args:
            node_id: Selected node ID or empty string
            node_data: Node data dictionary
        """
        if not node_id:
            # Clear details panel
            self._clear_node_details()
            return
        
        # Update details panel
        self._update_node_details(node_id, node_data)
        
        # Update neighbors table
        self._update_neighbors_table(node_id)
    
    def _update_node_details(self, node_id: str, node_data: Dict[str, Any]):
        """
        Update node details panel
        
        Args:
            node_id: Node ID
            node_data: Node data dictionary
        """
        # Basic node information
        self.node_labels["value"].setText(node_id)
        self.node_labels["type"].setText(node_data.get("type", "Unknown").capitalize())
        
        # Set threat level with color
        threat_level = node_data.get("threat_level", "unknown")
        self.node_labels["threat_level"].setText(threat_level.capitalize())
        
        # Set color based on threat level
        if threat_level == "malicious":
            self.node_labels["threat_level"].setStyleSheet("color: red; font-weight: bold;")
        elif threat_level == "suspicious":
            self.node_labels["threat_level"].setStyleSheet("color: orange; font-weight: bold;")
        elif threat_level in ["safe", "clean"]:  # Handle both safe and clean
            self.node_labels["threat_level"].setStyleSheet("color: green;")
        else:
            self.node_labels["threat_level"].setStyleSheet("")
        
        # Connection count
        if self.current_graph and node_id in self.current_graph:
            degree = self.current_graph.degree(node_id)
            self.node_labels["connections"].setText(str(degree))
        else:
            self.node_labels["connections"].setText("0")
    
    def _update_neighbors_table(self, node_id: str):
        """
        Update neighbors table for the selected node
        
        Args:
            node_id: Node ID
        """
        # Get neighbors from graph
        neighbors_data = []
        
        if self.current_graph and node_id in self.current_graph:
            for neighbor in self.current_graph.neighbors(node_id):
                # Get neighbor data
                n_data = self.graph_view.node_data.get(neighbor, {})
                
                n_type = n_data.get("type", "Unknown").capitalize()
                n_threat = n_data.get("threat_level", "Unknown").capitalize()
                
                neighbors_data.append([neighbor, n_type, n_threat])
            
            # Sort by threat level (malicious first) then by value
            neighbors_data.sort(key=lambda x: (
                0 if x[2] == "Malicious" else (1 if x[2] == "Suspicious" else 2),
                x[0]
            ))
        
        # Update neighbors table
        self.neighbors_table.update_data(neighbors_data)
    
    def _clear_node_details(self):
        """Clear node details panel"""
        self.node_labels["value"].setText("")
        self.node_labels["type"].setText("")
        self.node_labels["threat_level"].setText("")
        self.node_labels["threat_level"].setStyleSheet("")
        self.node_labels["connections"].setText("")
        
        # Clear neighbors table
        self.neighbors_table.update_data([])
    
    def _update_graph_stats(self):
        """Update graph statistics panel"""
        if not self.current_graph:
            return
            
        # Basic graph stats
        self.stats_labels["nodes"].setText(str(self.current_graph.number_of_nodes()))
        self.stats_labels["edges"].setText(str(self.current_graph.number_of_edges()))
        
        # Count node types
        ip_count = 0
        domain_count = 0
        malicious_count = 0
        suspicious_count = 0
        
        for node, data in self.graph_view.node_data.items():
            # Count by type
            if data.get("type") == "ip":
                ip_count += 1
            elif data.get("type") == "domain":
                domain_count += 1
            
            # Count by threat level
            if data.get("threat_level") == "malicious":
                malicious_count += 1
            elif data.get("threat_level") == "suspicious":
                suspicious_count += 1
        
        self.stats_labels["ip_nodes"].setText(str(ip_count))
        self.stats_labels["domain_nodes"].setText(str(domain_count))
        self.stats_labels["malicious_nodes"].setText(str(malicious_count))
        self.stats_labels["suspicious_nodes"].setText(str(suspicious_count))