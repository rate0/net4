import re
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QComboBox, QCheckBox, QHeaderView, QMenu, QDialog, QTabWidget, QMessageBox, QGroupBox, QFormLayout,
    QRadioButton, QButtonGroup, QSplitter, QTextEdit, QFrame, QToolBar, QTableView, QAbstractItemView
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize, QRegularExpression
from PyQt6.QtGui import QIcon, QAction, QFont, QColor, QRegularExpressionValidator

from ...models.session import Session
from ...utils.logger import Logger
from ..models.generic_table_model import GenericTableModel


class QueryParser:
    """Parser for the Net4 search query language"""
    
    # Query language operators
    OPERATORS = {
        "AND": "and",
        "OR": "or",
        "NOT": "not",
        "=": "equals",
        "!=": "not_equals",
        ":": "contains",
        "!:": "not_contains",
        ">": "gt",
        "<": "lt",
        ">=": "gte",
        "<=": "lte",
        "~": "regex",
        "!~": "not_regex"
    }
    
    # Shorthand field mappings
    FIELD_ALIASES = {
        "ip": "src_ip,dst_ip",
        "port": "src_port,dst_port",
        "src": "src_ip",
        "dst": "dst_ip",
        "proto": "protocol",
        "len": "length",
        "type": "entity_type,type",
        "level": "threat_level",
        "time": "timestamp,first_seen,last_seen"
    }
    
    def __init__(self):
        self.query_tokens = []
        self.parsed_query = None
    
    def parse(self, query_text: str) -> Dict:
        """
        Parse a query string into a structured query
        
        Args:
            query_text: Query string to parse
            
        Returns:
            Parsed query structure
        """
        if not query_text.strip():
            return {
                "type": "simple",
                "text": "",
                "field": "all",
                "operator": "contains",
                "case_sensitive": False
            }
        
        # Handle special case of simple text
        if " " not in query_text and ":" not in query_text and "=" not in query_text and ">" not in query_text and "<" not in query_text:
            return {
                "type": "simple",
                "text": query_text,
                "field": "all",
                "operator": "contains",
                "case_sensitive": False
            }
        
        # Check for Advanced Query Language
        if "AND " in query_text or " OR " in query_text or "NOT " in query_text or any(op in query_text for op in ["=", "!=", ":", "!:", ">", "<", ">=", "<=", "~", "!~"]):
            return self._parse_advanced_query(query_text)
        else:
            # Simple query with just text
            return {
                "type": "simple",
                "text": query_text,
                "field": "all",
                "operator": "contains",
                "case_sensitive": False
            }
    
    def _parse_advanced_query(self, query_text: str) -> Dict:
        """
        Parse an advanced query with operators
        
        Args:
            query_text: Advanced query string
            
        Returns:
            Parsed query structure
        """
        # Check for logical operators (AND, OR)
        if " AND " in query_text.upper():
            parts = query_text.split(" AND ", 1)
            return {
                "type": "logical",
                "operator": "and",
                "left": self._parse_advanced_query(parts[0]),
                "right": self._parse_advanced_query(parts[1])
            }
        elif " OR " in query_text.upper():
            parts = query_text.split(" OR ", 1)
            return {
                "type": "logical",
                "operator": "or",
                "left": self._parse_advanced_query(parts[0]),
                "right": self._parse_advanced_query(parts[1])
            }
        
        # Check for NOT operator
        if query_text.upper().startswith("NOT "):
            return {
                "type": "logical",
                "operator": "not",
                "expr": self._parse_advanced_query(query_text[4:])
            }
        
        # Handle comparison operators
        for op in ["!=", ">=", "<=", "!:", "!~", "=", ":", ">", "<", "~"]:
            if op in query_text:
                field, value = query_text.split(op, 1)
                field = field.strip()
                value = value.strip()
                
                # Handle quoted values
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                
                # Map operator to internal type
                operator = self.OPERATORS.get(op, "contains")
                
                # Handle field aliases
                if field in self.FIELD_ALIASES:
                    fields = self.FIELD_ALIASES[field].split(",")
                    if len(fields) > 1:
                        # Multiple fields with OR
                        or_query = None
                        for f in fields:
                            condition = {
                                "type": "comparison",
                                "field": f,
                                "value": value,
                                "operator": operator,
                                "case_sensitive": False
                            }
                            if or_query is None:
                                or_query = condition
                            else:
                                or_query = {
                                    "type": "logical",
                                    "operator": "or",
                                    "left": or_query,
                                    "right": condition
                                }
                        return or_query
                    else:
                        field = fields[0]
                
                return {
                    "type": "comparison",
                    "field": field,
                    "value": value,
                    "operator": operator,
                    "case_sensitive": False
                }
        
        # If no operators found, treat as simple text search
        return {
            "type": "simple",
            "text": query_text,
            "field": "all",
            "operator": "contains",
            "case_sensitive": False
        }


class SearchQuery:
    """Represents a search query with criteria for filtering data"""
    
    def __init__(self, text: str = "", field: str = "all", 
                 use_regex: bool = False, case_sensitive: bool = False):
        """
        Initialize search query
        
        Args:
            text: Search text
            field: Field to search in (or "all" for all fields)
            use_regex: Whether to use regex for matching
            case_sensitive: Whether to match case sensitively
        """
        self.text = text
        self.field = field
        self.use_regex = use_regex
        self.case_sensitive = case_sensitive
        self.compiled_regex = None
        
        # Query parser for advanced queries
        self.parser = QueryParser()
        self.parsed_query = None
        
        # Check if advanced query
        if text and any(op in text.upper() for op in ["AND ", " OR ", "NOT "]) or any(op in text for op in ["=", "!=", ":", "!:", ">", "<", ">=", "<=", "~", "!~"]):
            self.is_advanced = True
            self.parsed_query = self.parser.parse(text)
        else:
            self.is_advanced = False
            # Compile regex if needed
            if use_regex and text:
                try:
                    flags = 0 if case_sensitive else re.IGNORECASE
                    self.compiled_regex = re.compile(text, flags)
                except Exception:
                    self.compiled_regex = None
    
    def matches(self, item: Dict[str, Any]) -> bool:
        """
        Check if item matches this query
        
        Args:
            item: Item to check (dictionary)
            
        Returns:
            True if item matches query, False otherwise
        """
        if not self.text:
            return True
        
        # Use advanced query matching if parsed
        if self.is_advanced and self.parsed_query:
            return self._matches_parsed_query(item, self.parsed_query)
        
        # Simple query matching
        # Check specific field or all fields
        if self.field == "all":
            fields_to_check = item.keys()
        else:
            fields_to_check = [self.field]
        
        for field in fields_to_check:
            # Get field value
            value = item.get(field)
            if value is None:
                continue
            
            # Convert to string if needed
            if not isinstance(value, str):
                value = str(value)
            
            # Perform matching
            if self.use_regex and self.compiled_regex:
                if self.compiled_regex.search(value):
                    return True
            else:
                if self.case_sensitive:
                    if self.text in value:
                        return True
                else:
                    if self.text.lower() in value.lower():
                        return True
        
        return False
    
    def _matches_parsed_query(self, item: Dict[str, Any], query: Dict) -> bool:
        """
        Check if item matches a parsed query structure
        
        Args:
            item: Item to check
            query: Parsed query structure
            
        Returns:
            True if item matches, False otherwise
        """
        query_type = query.get("type")
        
        if query_type == "simple":
            # Simple text search
            field = query.get("field", "all")
            text = query.get("text", "")
            operator = query.get("operator", "contains")
            case_sensitive = query.get("case_sensitive", False)
            
            if field == "all":
                fields_to_check = item.keys()
            else:
                fields_to_check = [field]
            
            for field in fields_to_check:
                # Get field value
                value = item.get(field)
                if value is None:
                    continue
                
                # Convert to string if needed
                if not isinstance(value, str):
                    value = str(value)
                
                # Perform matching based on operator
                if operator == "contains":
                    if not case_sensitive and text.lower() in value.lower():
                        return True
                    elif case_sensitive and text in value:
                        return True
            
            return False
            
        elif query_type == "logical":
            # Logical operation
            operator = query.get("operator")
            
            if operator == "and":
                return self._matches_parsed_query(item, query.get("left")) and self._matches_parsed_query(item, query.get("right"))
            elif operator == "or":
                return self._matches_parsed_query(item, query.get("left")) or self._matches_parsed_query(item, query.get("right"))
            elif operator == "not":
                return not self._matches_parsed_query(item, query.get("expr"))
            
            return False
            
        elif query_type == "comparison":
            # Field comparison
            field = query.get("field")
            value = query.get("value")
            operator = query.get("operator")
            case_sensitive = query.get("case_sensitive", False)
            
            # Get item field value
            field_value = item.get(field)
            if field_value is None:
                return False
            
            # Convert to string for text comparisons
            if isinstance(field_value, (list, dict, tuple)):
                field_value = str(field_value)
            
            # Perform comparison based on operator
            if operator == "equals":
                if isinstance(field_value, (int, float)) and value.isdigit():
                    return float(field_value) == float(value)
                return field_value == value
                
            elif operator == "not_equals":
                if isinstance(field_value, (int, float)) and value.isdigit():
                    return float(field_value) != float(value)
                return field_value != value
                
            elif operator == "contains":
                if isinstance(field_value, str):
                    if case_sensitive:
                        return value in field_value
                    else:
                        return value.lower() in field_value.lower()
                return False
                
            elif operator == "not_contains":
                if isinstance(field_value, str):
                    if case_sensitive:
                        return value not in field_value
                    else:
                        return value.lower() not in field_value.lower()
                return True
                
            elif operator == "gt":
                if isinstance(field_value, (int, float)) and value.replace('.', '', 1).isdigit():
                    return float(field_value) > float(value)
                return False
                
            elif operator == "lt":
                if isinstance(field_value, (int, float)) and value.replace('.', '', 1).isdigit():
                    return float(field_value) < float(value)
                return False
                
            elif operator == "gte":
                if isinstance(field_value, (int, float)) and value.replace('.', '', 1).isdigit():
                    return float(field_value) >= float(value)
                return False
                
            elif operator == "lte":
                if isinstance(field_value, (int, float)) and value.replace('.', '', 1).isdigit():
                    return float(field_value) <= float(value)
                return False
                
            elif operator == "regex":
                try:
                    flags = 0 if case_sensitive else re.IGNORECASE
                    pattern = re.compile(value, flags)
                    return bool(pattern.search(str(field_value)))
                except Exception:
                    return False
                    
            elif operator == "not_regex":
                try:
                    flags = 0 if case_sensitive else re.IGNORECASE
                    pattern = re.compile(value, flags)
                    return not bool(pattern.search(str(field_value)))
                except Exception:
                    return True
        
        return False


class AdvancedSearchDialog(QDialog):
    """Dialog for advanced search configuration"""
    
    def __init__(self, current_query: SearchQuery, available_fields: List[str], parent=None):
        """
        Initialize advanced search dialog
        
        Args:
            current_query: Current search query
            available_fields: List of available field names
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.logger = Logger().get_logger()
        self.current_query = current_query
        self.available_fields = available_fields
        
        self._init_ui()
        self._load_query(current_query)
    
    def _init_ui(self):
        """Initialize dialog UI"""
        # Set window properties
        self.setWindowTitle("Advanced Search")
        self.resize(600, 400)
        
        # Main layout
        layout = QVBoxLayout(self)
        
        # Search criteria form
        form_group = QGroupBox("Search Criteria")
        form_layout = QFormLayout(form_group)
        
        # Search text
        self.search_text = QLineEdit()
        form_layout.addRow("Search Text:", self.search_text)
        
        # Field selection
        self.field_combo = QComboBox()
        self.field_combo.addItem("All Fields", "all")
        for field in sorted(self.available_fields):
            self.field_combo.addItem(field, field)
        form_layout.addRow("Search Field:", self.field_combo)
        
        # Options
        options_layout = QHBoxLayout()
        
        self.regex_check = QCheckBox("Use Regular Expression")
        options_layout.addWidget(self.regex_check)
        
        self.case_check = QCheckBox("Case Sensitive")
        options_layout.addWidget(self.case_check)
        
        form_layout.addRow("Options:", options_layout)
        
        layout.addWidget(form_group)
        
        # Regular expression help
        if self.current_query.use_regex:
            self._add_regex_help(layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        test_button = QPushButton("Test Expression")
        test_button.clicked.connect(self._test_regex)
        button_layout.addWidget(test_button)
        
        button_layout.addStretch()
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        search_button = QPushButton("Search")
        search_button.clicked.connect(self.accept)
        search_button.setDefault(True)
        button_layout.addWidget(search_button)
        
        layout.addLayout(button_layout)
        
        # Connect signals
        self.regex_check.stateChanged.connect(self._on_regex_check_changed)
    
    def _load_query(self, query: SearchQuery):
        """
        Load query values into UI
        
        Args:
            query: Query to load
        """
        self.search_text.setText(query.text)
        
        # Set field
        index = self.field_combo.findData(query.field)
        if index >= 0:
            self.field_combo.setCurrentIndex(index)
        
        # Set options
        self.regex_check.setChecked(query.use_regex)
        self.case_check.setChecked(query.case_sensitive)
    
    def _on_regex_check_changed(self, state):
        """
        Handle regex checkbox state change
        
        Args:
            state: Checkbox state
        """
        if state == Qt.CheckState.Checked:
            self._add_regex_help(self.layout())
        else:
            for i in range(self.layout().count()):
                item = self.layout().itemAt(i)
                if item.widget() and isinstance(item.widget(), QGroupBox) and item.widget().title() == "Regular Expression Help":
                    item.widget().deleteLater()
                    break
    
    def _add_regex_help(self, layout):
        """
        Add regex help section to layout
        
        Args:
            layout: Layout to add help to
        """
        # Check if help already exists
        for i in range(layout.count()):
            item = layout.itemAt(i)
            if item.widget() and isinstance(item.widget(), QGroupBox) and item.widget().title() == "Advanced Search Help":
                return
        
        help_group = QGroupBox("Advanced Search Help")
        help_layout = QVBoxLayout(help_group)
        
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setHtml(
            "<h3>Net4 Search Query Language</h3>"
            "<p>Use our powerful search syntax to find exactly what you need:</p>"
            
            "<h4>Field Operators</h4>"
            "<ul>"
            "<li><b>field=value</b> - Exact match (field equals value)</li>"
            "<li><b>field!=value</b> - Negative exact match (field does not equal value)</li>"
            "<li><b>field:value</b> - Contains match (field contains value)</li>"
            "<li><b>field!:value</b> - Negative contains match (field does not contain value)</li>"
            "<li><b>field>value</b> - Greater than (numeric fields only)</li>"
            "<li><b>field<value</b> - Less than (numeric fields only)</li>"
            "<li><b>field>=value</b> - Greater than or equal to (numeric fields only)</li>"
            "<li><b>field<=value</b> - Less than or equal to (numeric fields only)</li>"
            "<li><b>field~pattern</b> - Regex match (field matches regex pattern)</li>"
            "<li><b>field!~pattern</b> - Negative regex match (field does not match regex pattern)</li>"
            "</ul>"
            
            "<h4>Logical Operators</h4>"
            "<ul>"
            "<li><b>expr1 AND expr2</b> - Both expressions must match</li>"
            "<li><b>expr1 OR expr2</b> - Either expression must match</li>"
            "<li><b>NOT expr</b> - Expression must not match</li>"
            "</ul>"
            
            "<h4>Field Aliases</h4>"
            "<ul>"
            "<li><b>ip</b> - Searches both source and destination IP fields</li>"
            "<li><b>port</b> - Searches both source and destination port fields</li>"
            "<li><b>src</b> - Source IP address</li>"
            "<li><b>dst</b> - Destination IP address</li>"
            "<li><b>proto</b> - Protocol (TCP, UDP, etc.)</li>"
            "<li><b>len</b> - Packet length</li>"
            "<li><b>type</b> - Entity type or event type</li>"
            "<li><b>level</b> - Threat level</li>"
            "<li><b>time</b> - Timestamp fields (first_seen, last_seen, etc.)</li>"
            "</ul>"
            
            "<h4>Example Queries</h4>"
            "<ul>"
            "<li><b>src=192.168.1.1</b> - Packets from this IP</li>"
            "<li><b>ip:192.168</b> - IPs containing this subnet pattern</li>"
            "<li><b>port>1024 AND proto=TCP</b> - TCP traffic using high ports</li>"
            "<li><b>NOT level=safe</b> - All non-safe threat levels</li>"
            "<li><b>type=domain AND level=malicious</b> - Malicious domains</li>"
            "<li><b>proto=HTTP AND dst_port=80</b> - HTTP traffic to port 80</li>"
            "<li><b>http.user_agent~\"(curl|wget)\"</b> - HTTP requests from tools</li>"
            "</ul>"
            
            "<h3>Regular Expression Syntax</h3>"
            "<ul>"
            "<li><b>.</b> - Matches any character except newline</li>"
            "<li><b>\\w</b> - Matches word characters (a-z, A-Z, 0-9, _)</li>"
            "<li><b>\\d</b> - Matches digits (0-9)</li>"
            "<li><b>\\s</b> - Matches whitespace characters</li>"
            "<li><b>[abc]</b> - Matches any character in the set</li>"
            "<li><b>[^abc]</b> - Matches any character not in the set</li>"
            "<li><b>^</b> - Matches start of string</li>"
            "<li><b>$</b> - Matches end of string</li>"
            "<li><b>*</b> - Matches 0 or more repetitions</li>"
            "<li><b>+</b> - Matches 1 or more repetitions</li>"
            "<li><b>?</b> - Matches 0 or 1 repetitions</li>"
            "</ul>"
        )
        help_layout.addWidget(help_text)
        
        layout.addWidget(help_group)
    
    def _test_regex(self):
        """Test the current regex expression"""
        if not self.regex_check.isChecked():
            QMessageBox.information(self, "Test Expression", "Regular expression option is not enabled.")
            return
        
        expression = self.search_text.text()
        if not expression:
            QMessageBox.warning(self, "Test Expression", "Please enter a regular expression.")
            return
        
        try:
            flags = 0 if self.case_check.isChecked() else re.IGNORECASE
            re.compile(expression, flags)
            QMessageBox.information(self, "Test Expression", "Regular expression is valid.")
        except Exception as e:
            QMessageBox.critical(self, "Invalid Expression", f"Regular expression is invalid: {str(e)}")
    
    def get_query(self) -> SearchQuery:
        """
        Get the configured search query
        
        Returns:
            Configured search query
        """
        return SearchQuery(
            text=self.search_text.text(),
            field=self.field_combo.currentData(),
            use_regex=self.regex_check.isChecked(),
            case_sensitive=self.case_check.isChecked()
        )


class GlobalSearchWidget(QWidget):
    """
    Widget for performing global searches across all data in the application.
    """
    
    # Signals
    search_complete = pyqtSignal(list)  # List of search results
    item_selected = pyqtSignal(dict)    # Selected item details
    
    def __init__(self, parent=None):
        """
        Initialize global search widget
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.logger = Logger().get_logger()
        self.session: Optional[Session] = None
        self.current_query = SearchQuery()
        self.results: List[Dict[str, Any]] = []
        self._all_items: List[Dict[str, Any]] = []  # cached searchable objects
        self._index_built = False
        self.available_fields = set()
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize widget UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header with help information - dark theme compatible
        header_frame = QFrame()
        header_frame.setFrameShape(QFrame.Shape.StyledPanel)
        header_frame.setStyleSheet("""
            background-color: #3a3a3a;
            border-radius: 6px;
            border: 1px solid #555555;
            padding: 6px;
            margin: 4px;
        """)
        header_layout = QVBoxLayout(header_frame)
        
        header_title = QLabel("<b>Net4 Global Search</b>")
        header_title.setStyleSheet("font-size: 16px; color: #f0f0f0; font-weight: bold;")
        header_layout.addWidget(header_title)
        
        header_subtitle = QLabel("Use our advanced query language for powerful searches:")
        header_subtitle.setStyleSheet("color: #f0f0f0;")
        header_layout.addWidget(header_subtitle)
        
        query_examples = QLabel(
            "<code style='background-color: #555555; color: #f0f0f0; padding: 2px 4px; border-radius: 3px;'>ip:192.168</code>"
            " - IPs containing this subnet | "
            "<code style='background-color: #555555; color: #f0f0f0; padding: 2px 4px; border-radius: 3px;'>proto=TCP AND port>1024</code>"
            " - TCP high ports | "
            "<code style='background-color: #555555; color: #f0f0f0; padding: 2px 4px; border-radius: 3px;'>level=malicious</code>"
            " - Malicious entities | "
            "<code style='background-color: #555555; color: #f0f0f0; padding: 2px 4px; border-radius: 3px;'>NOT src=10.0.0.1</code>"
            " - Exclude source"
        )
        query_examples.setWordWrap(True)
        query_examples.setStyleSheet("color: #e0e0e0; margin-top: 8px; line-height: 150%;")
        header_layout.addWidget(query_examples)
        
        # Help button - styled for dark theme
        help_button = QPushButton("Query Language Help")
        help_button.setStyleSheet("""
            background-color: #2196f3;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 6px 12px;
            font-size: 12px;
            font-weight: bold;
        """)
        help_button.clicked.connect(self._show_query_language_help)
        header_layout.addWidget(help_button, alignment=Qt.AlignmentFlag.AlignRight)
        
        layout.addWidget(header_frame)
        
        # Enhanced search bar with better styling
        search_frame = QFrame()
        search_frame.setStyleSheet("""
            QFrame {
                background-color: #303030;
                border-radius: 8px;
                border: 1px solid #4a4a4a;
                padding: 10px;
                margin: 8px 4px;
            }
        """)
        search_layout = QHBoxLayout(search_frame)
        search_layout.setContentsMargins(8, 8, 8, 8)
        
        # Enhanced search input with better styling
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search query (e.g., ip:192.168 AND proto=HTTP, or simple text)...")
        self.search_input.returnPressed.connect(self._perform_search)
        self.search_input.setMinimumHeight(36)  # Taller input for better visibility
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: #424242;
                color: #f0f0f0;
                border: 1px solid #5a5a5a;
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid #2196f3;
            }
        """)
        search_layout.addWidget(self.search_input)
        
        # Enhanced search button with better styling
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self._perform_search)
        self.search_button.setMinimumHeight(36)
        self.search_button.setStyleSheet("""
            QPushButton {
                background-color: #2196f3;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 4px 16px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #1976d2;
            }
            QPushButton:pressed {
                background-color: #0d47a1;
            }
        """)
        search_layout.addWidget(self.search_button)
        
        # Enhanced advanced button with better styling
        self.advanced_button = QPushButton("Advanced")
        self.advanced_button.clicked.connect(self._show_advanced_search)
        self.advanced_button.setMinimumHeight(36)
        self.advanced_button.setStyleSheet("""
            QPushButton {
                background-color: #555555;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 4px 16px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #666666;
            }
            QPushButton:pressed {
                background-color: #777777;
            }
        """)
        search_layout.addWidget(self.advanced_button)
        
        layout.addWidget(search_frame)
        
        # Current search info with enhanced styling
        self.search_info = QLabel()
        self.search_info.setVisible(False)
        self.search_info.setStyleSheet("""
            background-color: #424242;
            color: #f0f0f0;
            border-radius: 4px;
            padding: 8px;
            margin: 4px;
            font-weight: bold;
        """)
        layout.addWidget(self.search_info)
        
        # Results container with title
        results_container = QFrame()
        results_container.setStyleSheet("""
            QFrame {
                background-color: #303030;
                border-radius: 8px;
                border: 1px solid #4a4a4a;
                margin: 4px;
            }
        """)
        results_layout = QVBoxLayout(results_container)
        
        # Results title
        results_title = QLabel("Search Results")
        results_title.setStyleSheet("""
            font-size: 14px; 
            font-weight: bold; 
            color: #f0f0f0;
            padding: 4px;
            margin-bottom: 8px;
        """)
        results_layout.addWidget(results_title)
        
        # Enhanced results table with better styling
        self._result_headers = ["Type", "Value", "Details", "Relevance", "Matched Field"]
        self.results_table = QTableView()
        self.results_table.setStyleSheet("""
            QTableView {
                background-color: #2d2d2d;
                alternate-background-color: #353535;
                color: #f0f0f0;
                gridline-color: #4a4a4a;
                border: none;
                border-radius: 4px;
                padding: 4px;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                color: #f0f0f0;
                padding: 6px;
                border: 1px solid #555555;
                font-weight: bold;
            }
            QTableView::item {
                padding: 4px;
                border-bottom: 1px solid #3a3a3a;
            }
            QTableView::item:selected {
                background-color: #2196f3;
                color: white;
            }
        """)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.results_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._results_model = GenericTableModel(self._result_headers, [])
        self.results_table.setModel(self._results_model)
        # Header configuration similar to previous
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(self.results_table)
        
        # Connect double click event
        self.results_table.doubleClicked.connect(self._item_double_clicked)
        
        # Add results container to main layout
        layout.addWidget(results_container)
    
    def _show_query_language_help(self):
        """Show help dialog for query language"""
        help_dialog = QDialog(self)
        help_dialog.setWindowTitle("Net4 Search Query Language")
        help_dialog.resize(700, 500)
        
        layout = QVBoxLayout(help_dialog)
        
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setHtml(
            "<h2>Net4 Search Query Language</h2>"
            "<p>Use our powerful search syntax to find exactly what you need:</p>"
            
            "<h3>Field Operators</h3>"
            "<ul>"
            "<li><b>field=value</b> - Exact match (field equals value)</li>"
            "<li><b>field!=value</b> - Negative exact match (field does not equal value)</li>"
            "<li><b>field:value</b> - Contains match (field contains value)</li>"
            "<li><b>field!:value</b> - Negative contains match (field does not contain value)</li>"
            "<li><b>field>value</b> - Greater than (numeric fields only)</li>"
            "<li><b>field<value</b> - Less than (numeric fields only)</li>"
            "<li><b>field>=value</b> - Greater than or equal to (numeric fields only)</li>"
            "<li><b>field<=value</b> - Less than or equal to (numeric fields only)</li>"
            "<li><b>field~pattern</b> - Regex match (field matches regex pattern)</li>"
            "<li><b>field!~pattern</b> - Negative regex match (field does not match regex pattern)</li>"
            "</ul>"
            
            "<h3>Logical Operators</h3>"
            "<ul>"
            "<li><b>expr1 AND expr2</b> - Both expressions must match</li>"
            "<li><b>expr1 OR expr2</b> - Either expression must match</li>"
            "<li><b>NOT expr</b> - Expression must not match</li>"
            "</ul>"
            
            "<h3>Common Fields</h3>"
            "<table border='1' cellpadding='4' cellspacing='0' style='border-collapse: collapse;'>"
            "<tr><th>Field</th><th>Description</th><th>Example</th></tr>"
            "<tr><td>src_ip</td><td>Source IP address</td><td>src_ip=192.168.1.1</td></tr>"
            "<tr><td>dst_ip</td><td>Destination IP address</td><td>dst_ip:10.0.0</td></tr>"
            "<tr><td>src_port</td><td>Source port number</td><td>src_port>1024</td></tr>"
            "<tr><td>dst_port</td><td>Destination port number</td><td>dst_port=80</td></tr>"
            "<tr><td>protocol</td><td>Protocol (TCP, UDP, etc.)</td><td>protocol=HTTP</td></tr>"
            "<tr><td>length</td><td>Packet length in bytes</td><td>length>1000</td></tr>"
            "<tr><td>timestamp</td><td>Event timestamp</td><td>timestamp:2023-04</td></tr>"
            "<tr><td>entity_type</td><td>Type of entity</td><td>entity_type=domain</td></tr>"
            "<tr><td>threat_level</td><td>Entity threat level</td><td>threat_level=malicious</td></tr>"
            "</table>"
            
            "<h3>Field Aliases (Shortcuts)</h3>"
            "<ul>"
            "<li><b>ip</b> - Searches both source and destination IP fields</li>"
            "<li><b>port</b> - Searches both source and destination port fields</li>"
            "<li><b>src</b> - Source IP address</li>"
            "<li><b>dst</b> - Destination IP address</li>"
            "<li><b>proto</b> - Protocol (TCP, UDP, etc.)</li>"
            "<li><b>len</b> - Packet length</li>"
            "<li><b>type</b> - Entity type or event type</li>"
            "<li><b>level</b> - Threat level</li>"
            "<li><b>time</b> - Timestamp fields (first_seen, last_seen, etc.)</li>"
            "</ul>"
            
            "<h3>Example Queries</h3>"
            "<ul>"
            "<li><b>src=192.168.1.1</b> - Packets from this IP</li>"
            "<li><b>ip:192.168</b> - IPs containing this subnet pattern</li>"
            "<li><b>port>1024 AND proto=TCP</b> - TCP traffic using high ports</li>"
            "<li><b>NOT level=safe</b> - All non-safe threat levels</li>"
            "<li><b>type=domain AND level=malicious</b> - Malicious domains</li>"
            "<li><b>proto=HTTP AND dst_port=80</b> - HTTP traffic to port 80</li>"
            "<li><b>http.user_agent~\"(curl|wget)\"</b> - HTTP requests from tools</li>"
            "</ul>"
        )
        layout.addWidget(help_text)
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(help_dialog.accept)
        layout.addWidget(close_button, alignment=Qt.AlignmentFlag.AlignRight)
        
        help_dialog.exec()
    
    def set_session(self, session: Session):
        """
        Set the analysis session for searching
        
        Args:
            session: Analysis session
        """
        self.session = session
        self.available_fields = self._collect_available_fields()
        
        # Build quick in-memory index once per session for faster repeated searches
        self._build_index()
    
    def _build_index(self):
        """Collect all searchable items from current session and cache them"""
        self._all_items.clear()
        if not self.session:
            return

        # Packets -> Events
        for packet in getattr(self.session, 'packets', []):
            self._all_items.append({
                "type": "packet",
                "time": packet.get("timestamp", datetime.now()),
                "src_ip": packet.get("src_ip", ""),
                "dst_ip": packet.get("dst_ip", ""),
                "protocol": packet.get("protocol", ""),
                "value": f"{packet.get('src_ip', '')} → {packet.get('dst_ip', '')}",
                "details": f"{packet.get('protocol', '')} {packet.get('length', 0)} bytes",
                "original": packet
            })

        # Entities
        for entity in getattr(self.session, 'network_entities', {}).values():
            self._all_items.append({
                "type": "entity",
                "time": entity.first_seen,
                "value": entity.value,
                "entity_type": entity.type,
                "threat_level": entity.threat_level,
                "tags": ", ".join(entity.tags),
                "details": f"{entity.type} ({entity.threat_level})",
                "original": entity
            })

        # Connections
        for conn in getattr(self.session, 'connections', []):
            self._all_items.append({
                "type": "connection",
                "time": conn.get("timestamp", datetime.now()),
                "src_ip": conn.get("src_ip", ""),
                "dst_ip": conn.get("dst_ip", ""),
                "src_port": conn.get("src_port", ""),
                "dst_port": conn.get("dst_port", ""),
                "protocol": conn.get("protocol", ""),
                "value": f"{conn.get('src_ip', '')}:{conn.get('src_port', '')} → {conn.get('dst_ip', '')}:{conn.get('dst_port', '')}",
                "details": f"{conn.get('protocol', '')} connection",
                "original": conn
            })

        # Anomalies
        for anomaly in getattr(self.session, 'anomalies', []):
            self._all_items.append({
                "type": "anomaly",
                "time": anomaly.get("timestamp", datetime.now()),
                "value": anomaly.get("description", ""),
                "anomaly_type": anomaly.get("type", ""),
                "severity": anomaly.get("severity", ""),
                "details": f"{anomaly.get('type', '')} ({anomaly.get('severity', '')})",
                "original": anomaly
            })

        self._index_built = True
    
    def _perform_search(self):
        """Perform search with current query"""
        # Get search text
        search_text = self.search_input.text().strip()
        
        # Update current query
        self.current_query.text = search_text
        
        # Perform search
        self._execute_search(self.current_query)
    
    def _show_advanced_search(self):
        """Show advanced search dialog"""
        dialog = AdvancedSearchDialog(self.current_query, list(self.available_fields), self)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Get query from dialog
            self.current_query = dialog.get_query()
            
            # Update search input
            self.search_input.setText(self.current_query.text)
            
            # Perform search
            self._execute_search(self.current_query)
    
    def _execute_search(self, query: SearchQuery):
        """
        Execute search with given query
        
        Args:
            query: Search query
        """
        if not self.session:
            QMessageBox.warning(self, "No Session", "No active session. Please open a PCAP file first.")
            return
        
        try:
            # Show searching indicator
            self.search_info.setText("Searching...")
            self.search_info.setVisible(True)
            
            # Use cached items, rebuild if needed
            if not self._index_built:
                self._build_index()

            items = self._all_items
            
            # Filter items based on query
            self.results = []
            matched_fields = {}
            
            for item in items:
                # Check if item matches query
                if query.matches(item):
                    # Find matching field for highlighting
                    matching_field = self._find_matching_field(item, query)
                    matched_fields[id(item)] = matching_field
                    
                    # Calculate relevance score
                    score = self._calculate_relevance(item, query)
                    
                    # Add to results with score
                    result = item.copy()
                    result["score"] = score
                    result["matched_field"] = matching_field
                    self.results.append(result)
            
            # Sort by relevance
            self.results.sort(key=lambda x: x["score"], reverse=True)
            
            # Update UI
            self._update_results_table()
            
            # Update search info
            if not query.text:
                self.search_info.setText(f"Showing all {len(self.results)} items")
            else:
                if self.results:
                    self.search_info.setText(f"Found {len(self.results)} matches for '{query.text}'")
                else:
                    self.search_info.setText(f"No matches found for '{query.text}'")
            
            # Emit search complete signal
            self.search_complete.emit(self.results)
        
        except Exception as e:
            self.logger.error(f"Error performing search: {str(e)}")
            QMessageBox.critical(self, "Search Error", f"Error performing search: {str(e)}")
            self.search_info.setText(f"Search error: {str(e)}")
    
    def _find_matching_field(self, item: Dict[str, Any], query: SearchQuery) -> str:
        """
        Find which field in the item matched the query
        
        Args:
            item: Item to check
            query: Search query
            
        Returns:
            Name of matching field or empty string if no match
        """
        if not query.text:
            return ""
        
        # Check specific field or all fields
        if query.field != "all":
            return query.field if query.matches(item) else ""
        
        for field, value in item.items():
            # Skip complex fields
            if isinstance(value, (dict, list)) or field == "original":
                continue
            
            # Convert to string if needed
            if not isinstance(value, str):
                value = str(value)
            
            # Check for match
            if query.use_regex and query.compiled_regex:
                if query.compiled_regex.search(value):
                    return field
            else:
                if query.case_sensitive:
                    if query.text in value:
                        return field
                else:
                    if query.text.lower() in value.lower():
                        return field
        
        return ""
    
    def _calculate_relevance(self, item: Dict[str, Any], query: SearchQuery) -> float:
        """
        Calculate relevance score for an item
        
        Args:
            item: Item to score
            query: Search query
            
        Returns:
            Relevance score (0.0 - 1.0)
        """
        if not query.text:
            return 0.5  # Default score for no query
        
        base_score = 0.4
        type_boost = {
            "entity": 0.3,
            "anomaly": 0.2,
            "connection": 0.1,
            "packet": 0.0
        }
        
        # Add type-based boost
        item_type = item.get("type", "")
        boost = type_boost.get(item_type, 0.0)
        
        # Add threat level boost for entities
        if item_type == "entity" and item.get("threat_level") in ["suspicious", "malicious"]:
            boost += 0.1
        
        # Add severity boost for anomalies
        if item_type == "anomaly" and item.get("severity") in ["medium", "high"]:
            boost += 0.1
        
        # Calculate match quality score
        match_quality = 0.0
        
        value = item.get("value", "")
        if isinstance(value, str):
            # Boost for exact matches
            if query.case_sensitive:
                if value == query.text:
                    match_quality = 0.3
                elif query.text in value:
                    match_quality = 0.2
            else:
                if value.lower() == query.text.lower():
                    match_quality = 0.3
                elif query.text.lower() in value.lower():
                    match_quality = 0.2
        
        return min(1.0, base_score + boost + match_quality)
    
    def _update_results_table(self):
        """Update results table with current results"""
        rows = []
        for result in self.results:
            rows.append({
                "Type": result.get("type", "").capitalize(),
                "Value": str(result.get("value", "")),
                "Details": result.get("details", ""),
                "Relevance": f"{result.get('score', 0):.2f}",
                "Matched Field": result.get("matched_field", "")
            })

        self._results_model.update(rows)
        # Resize for better UX
        self.results_table.resizeColumnsToContents()
    
    def _item_double_clicked(self, index):
        """
        Handle double click on result item
        
        Args:
            index: Item that was clicked
        """
        if 0 <= index.row() < len(self.results):
            result = self.results[index.row()]
            self.item_selected.emit(result)
    
    def _collect_available_fields(self) -> set:
        """
        Collect all available field names for searching
        
        Returns:
            Set of field names
        """
        fields = set()
        
        if not self.session:
            return fields
        
        # Add packet fields
        if self.session.packets:
            for packet in self.session.packets[:10]:  # Sample first 10 packets
                for key in packet.keys():
                    fields.add(key)
        
        # Add entity fields
        for entity in self.session.network_entities.values():
            entity_dict = entity.__dict__
            for key in entity_dict.keys():
                if not key.startswith("_"):
                    fields.add(key)
        
        # Add connection fields
        if self.session.connections:
            for conn in self.session.connections[:10]:  # Sample first 10 connections
                for key in conn.keys():
                    fields.add(key)
        
        # Add anomaly fields
        if self.session.anomalies:
            for anomaly in self.session.anomalies:
                for key in anomaly.keys():
                    fields.add(key)
        
        # Remove complex fields
        for field in list(fields):
            if field in ["original", "packets", "connections", "network_entities", "anomalies"]:
                fields.remove(field)
        
        return fields