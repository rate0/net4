from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, 
    QScrollArea, QGridLayout, QSizePolicy
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QColor, QPalette, QPixmap, QIcon

from .threat_badge import ThreatBadge


class ThreatInfoPanel(QWidget):
    """
    A modern, professionally designed panel for displaying threat intelligence 
    information with a focus on clear visualization and actionable insights.
    """
    
    def __init__(self, parent=None):
        """
        Initialize threat information panel
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Store threat data
        self.threat_data = {}
        self.entity_data = {}
        
        # Set up UI
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components"""
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Create header
        header = QFrame()
        header.setObjectName("threatHeader")
        header.setStyleSheet("""
            #threatHeader {
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #3a3a4a;
                padding: 10px;
                margin-bottom: 5px;
            }
        """)
        
        header_layout = QHBoxLayout(header)
        
        # Entity info - left side of header
        self.entity_layout = QVBoxLayout()
        
        # Entity title with larger font
        self.entity_title = QLabel("No Entity Selected")
        self.entity_title.setObjectName("entityTitle")
        self.entity_title.setStyleSheet("""
            #entityTitle {
                color: #ffffff;
                font-size: 18px;
                font-weight: bold;
            }
        """)
        self.entity_layout.addWidget(self.entity_title)
        
        # Entity details (type, first seen, etc.)
        self.entity_details = QLabel("")
        self.entity_details.setStyleSheet("color: #94a3b8; font-size: 12px;")
        self.entity_layout.addWidget(self.entity_details)
        
        header_layout.addLayout(self.entity_layout, 1)  # Give entity info more space
        
        # Threat badge - right side of header
        self.threat_badge_container = QFrame()
        self.threat_badge_container.setFixedWidth(150)
        self.threat_badge_container.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        
        badge_layout = QVBoxLayout(self.threat_badge_container)
        badge_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.badge_label = QLabel("Threat Level")
        self.badge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        badge_layout.addWidget(self.badge_label)
        
        self.threat_badge = ThreatBadge("unknown")
        badge_layout.addWidget(self.threat_badge, 0, Qt.AlignmentFlag.AlignCenter)
        
        badge_layout.addStretch()
        
        header_layout.addWidget(self.threat_badge_container)
        
        layout.addWidget(header)
        
        # Create scrollable content area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("""
            QScrollArea {
                background-color: transparent;
                border: none;
            }
            QScrollBar:vertical {
                background-color: #282838;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #3a3a4a;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #414558;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        content = QWidget()
        self.content_layout = QVBoxLayout(content)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(15)
        
        # Set up content sections
        self._setup_risk_section()
        self._setup_intel_section()
        self._setup_activity_section()
        self._setup_related_section()
        
        scroll.setWidget(content)
        layout.addWidget(scroll)
    
    def _setup_risk_section(self):
        """Set up risk summary section"""
        section = self._create_section("Risk Summary")
        
        # Create grid for risk metrics
        grid = QGridLayout()
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 1)
        
        # Risk score
        self.risk_score_label = QLabel("Risk Score")
        self.risk_score_label.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.risk_score_value = QLabel("--")
        self.risk_score_value.setStyleSheet("color: #ffffff; font-size: 20px; font-weight: bold;")
        
        risk_score_layout = QVBoxLayout()
        risk_score_layout.addWidget(self.risk_score_label, 0, Qt.AlignmentFlag.AlignCenter)
        risk_score_layout.addWidget(self.risk_score_value, 0, Qt.AlignmentFlag.AlignCenter)
        
        grid.addLayout(risk_score_layout, 0, 0)
        
        # Confidence score
        self.confidence_label = QLabel("Confidence")
        self.confidence_label.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.confidence_value = QLabel("--")
        self.confidence_value.setStyleSheet("color: #ffffff; font-size: 20px; font-weight: bold;")
        
        confidence_layout = QVBoxLayout()
        confidence_layout.addWidget(self.confidence_label, 0, Qt.AlignmentFlag.AlignCenter)
        confidence_layout.addWidget(self.confidence_value, 0, Qt.AlignmentFlag.AlignCenter)
        
        grid.addLayout(confidence_layout, 0, 1)
        
        # First/last seen
        self.seen_label = QLabel("First Seen")
        self.seen_label.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.seen_value = QLabel("--")
        self.seen_value.setStyleSheet("color: #ffffff; font-size: 20px; font-weight: bold;")
        
        seen_layout = QVBoxLayout()
        seen_layout.addWidget(self.seen_label, 0, Qt.AlignmentFlag.AlignCenter)
        seen_layout.addWidget(self.seen_value, 0, Qt.AlignmentFlag.AlignCenter)
        
        grid.addLayout(seen_layout, 0, 2)
        
        # Add grid to section
        section.layout().addLayout(grid)
        
        # Risk summary text
        self.risk_summary = QLabel("No risk information available.")
        self.risk_summary.setWordWrap(True)
        self.risk_summary.setStyleSheet("color: #ffffff; padding: 10px;")
        section.layout().addWidget(self.risk_summary)
        
        # Add section to content
        self.content_layout.addWidget(section)
    
    def _setup_intel_section(self):
        """Set up threat intelligence section"""
        section = self._create_section("Threat Intelligence")
        
        # Intel categories grid
        grid = QGridLayout()
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        
        # Create category entries
        self.categories = {}
        categories = ["Malware", "Spam", "Phishing", "C2", "Scanning", "Ransomware"]
        
        for i, category in enumerate(categories):
            row, col = divmod(i, 2)
            
            category_frame = QFrame()
            category_frame.setObjectName(f"category_{category.lower()}")
            category_frame.setStyleSheet(f"""
                #category_{category.lower()} {{
                    background-color: #323242;
                    border-radius: 4px;
                    padding: 5px;
                }}
            """)
            
            category_layout = QHBoxLayout(category_frame)
            category_layout.setContentsMargins(8, 5, 8, 5)
            
            category_label = QLabel(category)
            category_label.setStyleSheet("color: #ffffff; font-weight: bold;")
            category_layout.addWidget(category_label)
            
            category_value = QLabel("No")
            category_value.setStyleSheet("color: #94a3b8;")
            category_layout.addWidget(category_value, 0, Qt.AlignmentFlag.AlignRight)
            
            grid.addWidget(category_frame, row, col, 1, 1)
            
            # Store references
            self.categories[category.lower()] = {
                "frame": category_frame,
                "label": category_label,
                "value": category_value
            }
        
        section.layout().addLayout(grid)
        
        # Tags
        tags_label = QLabel("Tags:")
        tags_label.setStyleSheet("color: #94a3b8; font-weight: bold; margin-top: 10px;")
        section.layout().addWidget(tags_label)
        
        self.tags_container = QFrame()
        self.tags_container.setObjectName("tagsContainer")
        self.tags_container.setStyleSheet("""
            #tagsContainer {
                background-color: #323242;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        
        self.tags_layout = QHBoxLayout(self.tags_container)
        self.tags_layout.setContentsMargins(5, 5, 5, 5)
        self.tags_layout.setSpacing(5)
        
        # Add empty tag placeholder
        self.no_tags_label = QLabel("No tags available")
        self.no_tags_label.setStyleSheet("color: #94a3b8; font-style: italic;")
        self.tags_layout.addWidget(self.no_tags_label)
        
        section.layout().addWidget(self.tags_container)
        
        # Add section to content
        self.content_layout.addWidget(section)
    
    def _setup_activity_section(self):
        """Set up recent activity section"""
        section = self._create_section("Recent Activity")
        
        # Recent connections list
        self.connections_label = QLabel("No recent connections")
        self.connections_label.setWordWrap(True)
        self.connections_label.setStyleSheet("color: #ffffff; padding: 5px;")
        section.layout().addWidget(self.connections_label)
        
        # Add section to content
        self.content_layout.addWidget(section)
    
    def _setup_related_section(self):
        """Set up related entities section"""
        section = self._create_section("Related Entities")
        
        # Related entities grid
        self.related_entities_grid = QGridLayout()
        self.related_entities_grid.setColumnStretch(0, 2)  # Entity column
        self.related_entities_grid.setColumnStretch(1, 1)  # Type column
        self.related_entities_grid.setColumnStretch(2, 1)  # Threat level column
        
        # Add headers
        entity_header = QLabel("Entity")
        entity_header.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.related_entities_grid.addWidget(entity_header, 0, 0)
        
        type_header = QLabel("Type")
        type_header.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.related_entities_grid.addWidget(type_header, 0, 1)
        
        threat_header = QLabel("Threat Level")
        threat_header.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.related_entities_grid.addWidget(threat_header, 0, 2)
        
        # Add placeholder
        self.no_related_label = QLabel("No related entities found")
        self.no_related_label.setStyleSheet("color: #94a3b8; font-style: italic; padding: 10px;")
        self.related_entities_grid.addWidget(self.no_related_label, 1, 0, 1, 3)
        
        section.layout().addLayout(self.related_entities_grid)
        
        # Add section to content
        self.content_layout.addWidget(section)
    
    def _create_section(self, title):
        """
        Create a styled section with title
        
        Args:
            title: Section title
        
        Returns:
            QFrame widget with section styling
        """
        section = QFrame()
        section.setObjectName(f"section_{title.lower().replace(' ', '_')}")
        section.setStyleSheet(f"""
            #section_{title.lower().replace(' ', '_')} {{
                background-color: #282838;
                border-radius: 5px;
                border: 1px solid #3a3a4a;
                padding: 10px;
            }}
        """)
        
        section_layout = QVBoxLayout(section)
        section_layout.setContentsMargins(10, 10, 10, 10)
        section_layout.setSpacing(10)
        
        # Add section title
        title_label = QLabel(title)
        title_label.setObjectName("sectionTitle")
        title_label.setStyleSheet("""
            #sectionTitle {
                color: #ffffff;
                font-size: 16px;
                font-weight: bold;
                padding-bottom: 5px;
                border-bottom: 1px solid #3a3a4a;
            }
        """)
        section_layout.addWidget(title_label)
        
        return section
    
    def _create_tag(self, text, color="#2d74da"):
        """
        Create a tag label
        
        Args:
            text: Tag text
            color: Background color
        
        Returns:
            QLabel styled as a tag
        """
        tag = QLabel(text)
        tag.setStyleSheet(f"""
            background-color: {color};
            color: white;
            border-radius: 10px;
            padding: 3px 10px;
            font-size: 11px;
            font-weight: bold;
        """)
        return tag
    
    def set_entity(self, entity_data):
        """
        Set entity data to display
        
        Args:
            entity_data: Dictionary with entity information
        """
        if not entity_data:
            self._clear_data()
            return
        
        # Store entity data
        self.entity_data = entity_data
        
        # Update entity header
        self.entity_title.setText(entity_data.get("value", "Unknown Entity"))
        
        # Format entity details
        entity_type = entity_data.get("type", "unknown").capitalize()
        first_seen = entity_data.get("first_seen", "Unknown")
        
        details = f"Type: {entity_type}"
        if first_seen != "Unknown":
            details += f" • First seen: {first_seen}"
        
        self.entity_details.setText(details)
        
        # Update threat badge
        threat_level = entity_data.get("threat_level", "unknown")
        confidence = entity_data.get("confidence", 0.0)
        self.threat_badge.set_threat_level(threat_level, confidence)
        
        # Update threat data if available
        if "threat_data" in entity_data:
            self.set_threat_data(entity_data["threat_data"])
        else:
            # Clear threat data
            self._clear_threat_data()
    
    def set_threat_data(self, threat_data):
        """
        Set threat intelligence data
        
        Args:
            threat_data: Dictionary with threat intelligence information
        """
        if not threat_data:
            self._clear_threat_data()
            return
        
        # Store threat data
        self.threat_data = threat_data
        
        # Update risk section
        risk_score = threat_data.get("risk_score", 0)
        self.risk_score_value.setText(f"{risk_score:.1f}")
        
        # Color code risk score
        if risk_score >= 7.5:
            self.risk_score_value.setStyleSheet("color: #ef4444; font-size: 20px; font-weight: bold;")
        elif risk_score >= 5.0:
            self.risk_score_value.setStyleSheet("color: #f97316; font-size: 20px; font-weight: bold;")
        elif risk_score >= 2.5:
            self.risk_score_value.setStyleSheet("color: #eab308; font-size: 20px; font-weight: bold;")
        else:
            self.risk_score_value.setStyleSheet("color: #10b981; font-size: 20px; font-weight: bold;")
        
        # Update confidence
        confidence = threat_data.get("confidence", 0) * 100
        self.confidence_value.setText(f"{confidence:.0f}%")
        
        # Update first seen
        first_seen = threat_data.get("first_seen", "Unknown")
        self.seen_value.setText(first_seen)
        self.seen_label.setText("First Seen")
        
        # Check if last seen is more relevant
        if "last_seen" in threat_data:
            self.seen_label.setText("Last Seen")
            self.seen_value.setText(threat_data["last_seen"])
        
        # Update risk summary
        summary = threat_data.get("summary", "No risk information available.")
        self.risk_summary.setText(summary)
        
        # Update intelligence categories
        categories = threat_data.get("categories", {})
        for category, value in categories.items():
            if category in self.categories:
                # Update category value
                if value:
                    self.categories[category]["value"].setText("Yes")
                    self.categories[category]["value"].setStyleSheet("color: #ef4444; font-weight: bold;")
                    self.categories[category]["frame"].setStyleSheet(f"""
                        #category_{category} {{
                            background-color: rgba(239, 68, 68, 0.15);
                            border-radius: 4px;
                            padding: 5px;
                        }}
                    """)
                else:
                    self.categories[category]["value"].setText("No")
                    self.categories[category]["value"].setStyleSheet("color: #94a3b8;")
                    self.categories[category]["frame"].setStyleSheet(f"""
                        #category_{category} {{
                            background-color: #323242;
                            border-radius: 4px;
                            padding: 5px;
                        }}
                    """)
        
        # Update tags
        self._update_tags(threat_data.get("tags", []))
        
        # Update activity
        self._update_activity(threat_data.get("recent_activity", []))
        
        # Update related entities
        self._update_related_entities(threat_data.get("related_entities", []))
    
    def _update_tags(self, tags):
        """
        Update tag display
        
        Args:
            tags: List of tag strings
        """
        # Clear existing tags
        for i in reversed(range(self.tags_layout.count())):
            item = self.tags_layout.itemAt(i)
            if item.widget():
                item.widget().deleteLater()
        
        if not tags:
            # Show no tags message
            self.no_tags_label = QLabel("No tags available")
            self.no_tags_label.setStyleSheet("color: #94a3b8; font-style: italic;")
            self.tags_layout.addWidget(self.no_tags_label)
            return
        
        # Add new tags
        for tag in tags:
            # Choose color based on tag content
            color = "#2d74da"  # Default blue
            
            # Use color coding for common tag types
            lower_tag = tag.lower()
            if any(kw in lower_tag for kw in ["malware", "virus", "trojan", "ransomware"]):
                color = "#b91c1c"  # Red for malware
            elif any(kw in lower_tag for kw in ["phish", "scam", "fraud"]):
                color = "#d97706"  # Orange for phishing/scams
            elif any(kw in lower_tag for kw in ["spam", "bulk"]):
                color = "#7e22ce"  # Purple for spam
            elif any(kw in lower_tag for kw in ["scanner", "recon", "probe"]):
                color = "#0891b2"  # Teal for scanning activity
            elif any(kw in lower_tag for kw in ["c2", "command", "control", "botnet"]):
                color = "#be185d"  # Pink for C2
            
            tag_label = self._create_tag(tag, color)
            self.tags_layout.addWidget(tag_label)
        
        # Add stretch at the end
        self.tags_layout.addStretch()
    
    def _update_activity(self, activities):
        """
        Update recent activity display
        
        Args:
            activities: List of activity dictionaries
        """
        if not activities:
            self.connections_label.setText("No recent activities recorded")
            return
        
        # Format activities
        activity_text = ""
        for activity in activities[:5]:  # Show the 5 most recent
            timestamp = activity.get("timestamp", "Unknown time")
            description = activity.get("description", "Unknown activity")
            details = activity.get("details", "")
            
            activity_text += f"<p><b>{timestamp}</b>: {description}"
            if details:
                activity_text += f"<br><span style='color: #94a3b8; margin-left: 15px;'>{details}</span>"
            activity_text += "</p>"
        
        self.connections_label.setText(activity_text)
    
    def _update_related_entities(self, entities):
        """
        Update related entities display
        
        Args:
            entities: List of related entity dictionaries
        """
        # Clear existing entities
        for i in reversed(range(self.related_entities_grid.count())):
            item = self.related_entities_grid.itemAt(i)
            if item.widget() and item.widget() != self.no_related_label:
                item.widget().deleteLater()
        
        if not entities:
            self.no_related_label.setVisible(True)
            return
        
        # Hide placeholder
        self.no_related_label.setVisible(False)
        
        # Add header row
        entity_header = QLabel("Entity")
        entity_header.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.related_entities_grid.addWidget(entity_header, 0, 0)
        
        type_header = QLabel("Type")
        type_header.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.related_entities_grid.addWidget(type_header, 0, 1)
        
        threat_header = QLabel("Threat Level")
        threat_header.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.related_entities_grid.addWidget(threat_header, 0, 2)
        
        # Add entities to grid
        for i, entity in enumerate(entities[:10]):  # Show up to 10 related entities
            row = i + 1  # Skip header row
            
            # Entity value
            entity_label = QLabel(entity.get("value", "Unknown"))
            entity_label.setStyleSheet("color: #ffffff;")
            self.related_entities_grid.addWidget(entity_label, row, 0)
            
            # Entity type
            type_label = QLabel(entity.get("type", "unknown").capitalize())
            type_label.setStyleSheet("color: #ffffff;")
            self.related_entities_grid.addWidget(type_label, row, 1)
            
            # Threat level
            threat_level = entity.get("threat_level", "unknown")
            threat_badge = ThreatBadge(threat_level, compact=True)
            self.related_entities_grid.addWidget(threat_badge, row, 2, Qt.AlignmentFlag.AlignCenter)
    
    def _clear_data(self):
        """Clear all displayed data"""
        # Clear entity header
        self.entity_title.setText("No Entity Selected")
        self.entity_details.setText("")
        
        # Clear threat badge
        self.threat_badge.set_threat_level("unknown")
        
        # Clear threat data
        self._clear_threat_data()
    
    def _clear_threat_data(self):
        """Clear threat intelligence data"""
        # Clear risk section
        self.risk_score_value.setText("--")
        self.risk_score_value.setStyleSheet("color: #ffffff; font-size: 20px; font-weight: bold;")
        
        self.confidence_value.setText("--")
        self.seen_value.setText("--")
        self.seen_label.setText("First Seen")
        
        self.risk_summary.setText("No risk information available.")
        
        # Clear intelligence categories
        for category in self.categories.values():
            category["value"].setText("No")
            category["value"].setStyleSheet("color: #94a3b8;")
            category["frame"].setStyleSheet(f"""
                #category_{category['label'].text().lower()} {{
                    background-color: #323242;
                    border-radius: 4px;
                    padding: 5px;
                }}
            """)
        
        # Clear tags
        self._update_tags([])
        
        # Clear activity
        self.connections_label.setText("No recent activities recorded")
        
        # Clear related entities
        self._update_related_entities([])