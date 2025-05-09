from typing import List, Any, Optional, Callable

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QMenu, QLineEdit, QHBoxLayout, QLabel, QPushButton, QSizePolicy
)
from PyQt6.QtCore import Qt, QSortFilterProxyModel, QRegularExpression
from PyQt6.QtGui import QAction, QColor, QBrush, QFont


class DataTable(QWidget):
    """
    Enhanced data table widget with sorting, filtering, and custom styling.
    """
    
    def __init__(
        self, 
        headers: List[str], 
        data: Optional[List[List[Any]]] = None,
        parent: Optional[QWidget] = None
    ):
        """
        Initialize data table
        
        Args:
            headers: Column headers
            data: Table data (rows of values)
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.headers = headers
        self.data = data or []
        self.searchable = True
        self.filter_text = ""
        
        # Map of text patterns to highlight with colors - using consistent colors with CSS theme
        self.highlight_patterns = {
            "malicious": QColor(185, 28, 28),   # Matches .threat-malicious
            "suspicious": QColor(217, 119, 6),  # Matches .threat-suspicious
            "high": QColor(185, 28, 28),        # Same as malicious
            "medium": QColor(217, 119, 6),      # Same as suspicious
            "low": QColor(75, 85, 99),          # Gray, less alarming
            "safe": QColor(21, 128, 61)         # Matches .threat-safe
        }
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components"""
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Search bar (initially hidden)
        self.search_layout = QHBoxLayout()
        self.search_label = QLabel("🔍")
        self.search_label.setStyleSheet("color: #ffffff; font-size: 14px; margin-right:4px;")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Type to filter...")
        self.search_input.setMinimumHeight(28)
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: #323242;
                color: #ffffff;
                border: 1px solid #414558;
                border-radius: 4px;
                padding: 4px 8px;
            }
            QLineEdit:focus {
                border-color: #2d74da;
            }
        """)
        self.search_input.textChanged.connect(self._filter_changed)
        
        self.search_clear = QPushButton("✖")
        self.search_clear.setToolTip("Clear filter")
        self.search_clear.setFixedWidth(32)
        self.search_clear.setStyleSheet("""
            QPushButton {
                background-color: #414558;
                color: #ffffff;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #53536a; }
            QPushButton:pressed { background-color: #2d74da; }
        """)
        self.search_clear.clicked.connect(self._clear_filter)
        
        self.search_layout.addWidget(self.search_label)
        self.search_layout.addWidget(self.search_input)
        self.search_layout.addWidget(self.search_clear)
        self.search_layout.setContentsMargins(5, 0, 5, 6)
        self.search_layout.setSpacing(6)
        
        # Hide search bar initially if not searchable
        if not self.searchable:
            self.search_label.setVisible(False)
            self.search_input.setVisible(False)
            self.search_clear.setVisible(False)
        
        layout.addLayout(self.search_layout)
        
        # Table widget
        self.table = QTableWidget()
        # Ensure table expands within parent and stays tall enough to avoid single-row squish
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.table.setMinimumHeight(160)
        self.table.setColumnCount(len(self.headers))
        self.table.setHorizontalHeaderLabels(self.headers)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        
        # Make rows slightly taller for readability
        self.table.verticalHeader().setDefaultSectionSize(24)
        
        # Set context menu policy
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        
        # Configure header behavior
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        
        layout.addWidget(self.table)
        
        # Populate with initial data
        self.update_data(self.data)
    
    def update_data(self, data: List[List[Any]]):
        """
        Update table with new data
        
        Args:
            data: New table data (rows of values)
        """
        # Save current sort column and order
        current_column = self.table.horizontalHeader().sortIndicatorSection()
        current_order = self.table.horizontalHeader().sortIndicatorOrder()
        
        # Store new data
        self.data = data
        
        # Disable sorting temporarily to improve performance
        self.table.setSortingEnabled(False)
        
        # Set row count
        self.table.setRowCount(len(data))
        
        # Fill table with data
        for row, row_data in enumerate(data):
            for col, value in enumerate(row_data):
                if col >= len(self.headers):
                    continue
                    
                # Create item with data
                item = QTableWidgetItem(str(value))
                
                # Apply highlighting based on text content
                self._apply_highlighting(item, value)
                
                # Add item to table
                self.table.setItem(row, col, item)
        
        # Restore sorting
        self.table.setSortingEnabled(True)
        
        # Restore sort order
        if current_column >= 0 and current_column < len(self.headers):
            self.table.sortItems(current_column, current_order)
        
        # Resize columns to content
        for i in range(len(self.headers)):
            self.table.resizeColumnToContents(i)
    
    def set_searchable(self, searchable: bool):
        """
        Set whether the table is searchable
        
        Args:
            searchable: True to enable search, False to disable
        """
        self.searchable = searchable
        self.search_label.setVisible(searchable)
        self.search_input.setVisible(searchable)
        self.search_clear.setVisible(searchable)
    
    def set_highlight_patterns(self, patterns: dict):
        """
        Set text patterns to highlight with colors
        
        Args:
            patterns: Dictionary mapping text patterns to QColor objects
        """
        self.highlight_patterns = patterns
        self.update_data(self.data)  # Re-apply highlighting
    
    def add_highlight_pattern(self, pattern: str, color: QColor):
        """
        Add a text pattern to highlight
        
        Args:
            pattern: Text pattern to match (case insensitive)
            color: Color to highlight with
        """
        self.highlight_patterns[pattern.lower()] = color
        self.update_data(self.data)  # Re-apply highlighting
    
    def get_selected_data(self) -> List[Any]:
        """
        Get data from the selected row
        
        Returns:
            List of values from the selected row or empty list if none selected
        """
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return []
            
        row = selected_rows[0].row()
        if row >= len(self.data):
            return []
            
        return self.data[row]
    
    def get_column_data(self, column: int) -> List[Any]:
        """
        Get all data from a specific column
        
        Args:
            column: Column index
            
        Returns:
            List of values from the column
        """
        if column < 0 or column >= len(self.headers):
            return []
            
        return [row[column] for row in self.data if column < len(row)]
    
    def _apply_highlighting(self, item: QTableWidgetItem, value: Any):
        """
        Apply highlighting to a table item based on its value
        
        Args:
            item: QTableWidgetItem to highlight
            value: Value of the item
        """
        # Convert to string for text matching
        text = str(value).lower()
        
        # Check if item text matches any highlight patterns
        for pattern, color in self.highlight_patterns.items():
            if pattern in text:
                # Apply highlighting
                item.setBackground(QBrush(color))
                
                # Set text color based on background brightness for contrast
                # Dark text for light backgrounds, light text for dark backgrounds
                brightness = (color.red() * 299 + color.green() * 587 + color.blue() * 114) / 1000
                if brightness > 170:  # If background is light
                    item.setForeground(QBrush(QColor(0, 0, 0)))  # Black text
                else:
                    item.setForeground(QBrush(QColor(255, 255, 255)))  # White text
                
                # Make text bold for emphasis
                font = item.font()
                font.setBold(True)
                item.setFont(font)
                
                # Only apply the first matching pattern
                break
    
    def _filter_changed(self):
        """Handle filter text change"""
        self.filter_text = self.search_input.text().lower()
        
        # Show all rows
        for row in range(self.table.rowCount()):
            self.table.setRowHidden(row, False)
        
        if not self.filter_text:
            return
            
        # Hide rows that don't match filter
        for row in range(self.table.rowCount()):
            match = False
            
            # Check each column for a match
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item and self.filter_text in item.text().lower():
                    match = True
                    break
            
            # Hide row if no match
            self.table.setRowHidden(row, not match)
    
    def _clear_filter(self):
        """Clear the search filter"""
        self.search_input.clear()
        self.filter_text = ""
        
        # Show all rows
        for row in range(self.table.rowCount()):
            self.table.setRowHidden(row, False)
    
    def _show_context_menu(self, position):
        """
        Show context menu for the table
        
        Args:
            position: Position where the context menu was requested
        """
        menu = QMenu()
        
        # Add actions
        copy_action = QAction("Copy selected", self)
        copy_action.triggered.connect(self._copy_selected)
        menu.addAction(copy_action)
        
        copy_all_action = QAction("Copy all", self)
        copy_all_action.triggered.connect(self._copy_all)
        menu.addAction(copy_all_action)
        
        menu.addSeparator()
        
        export_action = QAction("Export to CSV", self)
        export_action.triggered.connect(self._export_to_csv)
        menu.addAction(export_action)
        
        menu.addSeparator()
        
        # Add search toggle action if searchable
        if self.searchable:
            search_visible = self.search_input.isVisible()
            search_action = QAction("Hide Search" if search_visible else "Show Search", self)
            search_action.triggered.connect(self._toggle_search)
            menu.addAction(search_action)
        
        # Show the menu
        menu.exec(self.table.viewport().mapToGlobal(position))
    
    def _copy_selected(self):
        """Copy selected rows to clipboard"""
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        rows = sorted([index.row() for index in selected_rows])
        text = self._rows_to_text(rows)
        
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
    
    def _copy_all(self):
        """Copy all visible rows to clipboard"""
        rows = [row for row in range(self.table.rowCount()) 
               if not self.table.isRowHidden(row)]
        text = self._rows_to_text(rows)
        
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
    
    def _rows_to_text(self, rows):
        """
        Convert table rows to tab-separated text
        
        Args:
            rows: List of row indices
            
        Returns:
            Tab-separated text representation
        """
        # Start with headers
        text = "\t".join(self.headers) + "\n"
        
        # Add data from each row
        for row in rows:
            row_data = []
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                row_data.append(item.text() if item else "")
            
            text += "\t".join(row_data) + "\n"
        
        return text
    
    def _export_to_csv(self):
        """Export table data to CSV file"""
        from PyQt6.QtWidgets import QFileDialog
        import csv
        
        # Get file name
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export to CSV", "", "CSV Files (*.csv);;All Files (*)"
        )
        
        if not file_path:
            return
            
        # Add .csv extension if missing
        if not file_path.lower().endswith('.csv'):
            file_path += '.csv'
            
        try:
            with open(file_path, 'w', newline='') as file:
                writer = csv.writer(file)
                
                # Write headers
                writer.writerow(self.headers)
                
                # Write visible data
                for row in range(self.table.rowCount()):
                    if not self.table.isRowHidden(row):
                        row_data = []
                        for col in range(self.table.columnCount()):
                            item = self.table.item(row, col)
                            row_data.append(item.text() if item else "")
                        writer.writerow(row_data)
                        
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Export Error", f"Error exporting to CSV: {str(e)}")
    
    def _toggle_search(self):
        """Toggle search bar visibility"""
        visible = self.search_input.isVisible()
        self.search_label.setVisible(not visible)
        self.search_input.setVisible(not visible)
        self.search_clear.setVisible(not visible)
        
        # Clear filter if hiding search
        if visible:
            self._clear_filter()