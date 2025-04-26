import os
from typing import Dict, List, Any, Optional, Set

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QTabWidget, QWidget, QFormLayout, QCheckBox, QFileDialog,
    QGroupBox, QButtonGroup, QRadioButton, QProgressBar, QMessageBox,
    QDialogButtonBox, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QThread

from ...models.session import Session
from ...core.reporting.report_gen import ReportGenerator
from ...core.reporting.exporters import DataExporter


class ExportThread(QThread):
    """Thread for asynchronous data export operations"""
    
    # Signal for progress updates
    progress_updated = pyqtSignal(str, float)
    
    # Signal for export completion
    export_completed = pyqtSignal(bool, str)
    
    def __init__(self, session: Session, export_type: str, output_path: str, params: Dict[str, Any]):
        """
        Initialize export thread
        
        Args:
            session: Analysis session
            export_type: Type of export ('pdf', 'json', 'csv')
            output_path: Output file or directory path
            params: Export parameters
        """
        super().__init__()
        
        self.session = session
        self.export_type = export_type
        self.output_path = output_path
        self.params = params
    
    def run(self):
        """Run the export operation"""
        try:
            if self.export_type == 'pdf':
                # Create report generator
                report_gen = ReportGenerator(None)  # No config needed for this
                
                # Get selected sections
                sections = self.params.get('sections', [])
                
                # Generate PDF report
                success = report_gen.generate_pdf_report(
                    self.session,
                    self.output_path,
                    sections=sections,
                    progress_callback=lambda msg, progress: self.progress_updated.emit(msg, progress)
                )
                
                # Signal completion
                self.export_completed.emit(success, self.output_path)
                
            elif self.export_type == 'json':
                # Create data exporter
                exporter = DataExporter()
                
                # Get selected data types
                data_types = self.params.get('data_types', [])
                pretty_print = self.params.get('pretty_print', True)
                
                # Export to JSON
                success = exporter.export_to_json(
                    self.session,
                    self.output_path,
                    data_types=data_types,
                    pretty_print=pretty_print,
                    progress_callback=lambda msg, progress: self.progress_updated.emit(msg, progress)
                )
                
                # Signal completion
                self.export_completed.emit(success, self.output_path)
                
            elif self.export_type == 'csv':
                # Create data exporter
                exporter = DataExporter()
                
                # Get selected data types
                data_types = self.params.get('data_types', [])
                
                # Export to CSV (to directory)
                result = exporter.export_to_csv(
                    self.session,
                    self.output_path,
                    data_types=data_types,
                    progress_callback=lambda msg, progress: self.progress_updated.emit(msg, progress)
                )
                
                # Signal completion (success if any files were exported)
                self.export_completed.emit(bool(result), self.output_path)
                
            else:
                # Unknown export type
                self.export_completed.emit(False, "Unknown export type")
                
        except Exception as e:
            # Signal error
            self.progress_updated.emit(f"Error: {str(e)}", 1.0)
            self.export_completed.emit(False, str(e))


class ExportDialog(QDialog):
    """
    Dialog for exporting session data in various formats.
    """
    
    def __init__(self, session: Session, parent=None):
        """
        Initialize export dialog
        
        Args:
            session: Analysis session
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.session = session
        self.export_thread = None
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize dialog UI"""
        # Set window properties
        self.setWindowTitle("Export Data")
        self.setMinimumSize(500, 400)
        
        # Apply dark theme stylesheet to export dialog
        self.setStyleSheet("""
            QDialog, QWidget, QTabWidget::pane, QGroupBox {
                background-color: #2d2d2d;
                color: #f0f0f0;
            }
            QLabel, QCheckBox, QRadioButton, QGroupBox::title {
                color: #f0f0f0;
            }
            QLineEdit, QComboBox, QPushButton {
                background-color: #3a3a3a;
                color: #f0f0f0;
                border: 1px solid #555555;
                padding: 4px;
            }
            QTabBar::tab {
                background-color: #3a3a3a;
                color: #f0f0f0;
                border: 1px solid #555555;
                padding: 8px;
            }
            QTabBar::tab:selected {
                background-color: #424242;
                border-bottom: 2px solid #3498db;
            }
            QProgressBar {
                border: 1px solid #555555;
                background-color: #3a3a3a;
                color: #f0f0f0;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #3498db;
            }
        """)
        
        # Main layout
        layout = QVBoxLayout(self)
        
        # Create tab widget for export formats
        self.tab_widget = QTabWidget()
        
        # Add tabs for different export formats
        self.pdf_tab = self._create_pdf_tab()
        self.json_tab = self._create_json_tab()
        self.csv_tab = self._create_csv_tab()
        
        self.tab_widget.addTab(self.pdf_tab, "PDF Report")
        self.tab_widget.addTab(self.json_tab, "JSON")
        self.tab_widget.addTab(self.csv_tab, "CSV")
        
        layout.addWidget(self.tab_widget)
        
        # Progress area (initially hidden)
        self.progress_group = QGroupBox("Export Progress")
        self.progress_group.setVisible(False)
        progress_layout = QVBoxLayout(self.progress_group)
        
        self.progress_label = QLabel("Preparing export...")
        progress_layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)
        
        layout.addWidget(self.progress_group)
        
        # Button box
        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).setText("Export")
        self.button_box.accepted.connect(self._export_data)
        self.button_box.rejected.connect(self.reject)
        
        layout.addWidget(self.button_box)
    
    def _create_pdf_tab(self) -> QWidget:
        """
        Create PDF export tab
        
        Returns:
            Tab widget
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Report sections
        sections_group = QGroupBox("Report Sections")
        sections_layout = QVBoxLayout(sections_group)
        
        # Create section checkboxes
        self.section_checks = {}
        
        for section_id, section_name in [
            ("summary", "Executive Summary"),
            ("traffic_overview", "Traffic Overview"),
            ("entities", "Network Entities"),
            ("anomalies", "Detected Anomalies"),
            ("threats", "Threat Intelligence"),
            ("timeline", "Event Timeline")
        ]:
            checkbox = QCheckBox(section_name)
            checkbox.setChecked(True)
            sections_layout.addWidget(checkbox)
            self.section_checks[section_id] = checkbox
        
        layout.addWidget(sections_group)
        
        # Output file
        output_group = QGroupBox("Output File")
        output_layout = QHBoxLayout(output_group)
        
        self.pdf_path_edit = QLineEdit()
        output_layout.addWidget(self.pdf_path_edit)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_pdf_output)
        output_layout.addWidget(browse_btn)
        
        layout.addWidget(output_group)
        
        # Set default file path
        default_path = os.path.expanduser(f"~/Desktop/{self.session.name}_report.pdf")
        self.pdf_path_edit.setText(default_path)
        
        return tab
    
    def _create_json_tab(self) -> QWidget:
        """
        Create JSON export tab
        
        Returns:
            Tab widget
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Data types to include
        data_group = QGroupBox("Data to Include")
        data_layout = QVBoxLayout(data_group)
        
        # Create data type checkboxes
        self.json_data_checks = {}
        
        for data_id, data_name in [
            ("metadata", "Session Metadata"),
            ("entities", "Network Entities"),
            ("connections", "Connections"),
            ("packets", "Packets"),
            ("timeline", "Timeline Events"),
            ("anomalies", "Detected Anomalies"),
            ("threat_intel", "Threat Intelligence"),
            ("ai_insights", "AI Insights")
        ]:
            checkbox = QCheckBox(data_name)
            checkbox.setChecked(True)
            data_layout.addWidget(checkbox)
            self.json_data_checks[data_id] = checkbox
        
        layout.addWidget(data_group)
        
        # Format options
        format_group = QGroupBox("Format Options")
        format_layout = QVBoxLayout(format_group)
        
        self.pretty_print_check = QCheckBox("Pretty Print (formatted JSON)")
        self.pretty_print_check.setChecked(True)
        format_layout.addWidget(self.pretty_print_check)
        
        layout.addWidget(format_group)
        
        # Output file
        output_group = QGroupBox("Output File")
        output_layout = QHBoxLayout(output_group)
        
        self.json_path_edit = QLineEdit()
        output_layout.addWidget(self.json_path_edit)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_json_output)
        output_layout.addWidget(browse_btn)
        
        layout.addWidget(output_group)
        
        # Set default file path
        default_path = os.path.expanduser(f"~/Desktop/{self.session.name}_data.json")
        self.json_path_edit.setText(default_path)
        
        return tab
    
    def _create_csv_tab(self) -> QWidget:
        """
        Create CSV export tab
        
        Returns:
            Tab widget
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Data types to include
        data_group = QGroupBox("Data to Export")
        data_layout = QVBoxLayout(data_group)
        
        # Create data type checkboxes
        self.csv_data_checks = {}
        
        for data_id, data_name in [
            ("connections", "Connections"),
            ("entities", "Network Entities"),
            ("anomalies", "Detected Anomalies"),
            ("timeline", "Timeline Events"),
            ("packets", "Packets"),
            ("threat_intel", "Threat Intelligence")
        ]:
            checkbox = QCheckBox(data_name)
            checkbox.setChecked(True)
            data_layout.addWidget(checkbox)
            self.csv_data_checks[data_id] = checkbox
        
        layout.addWidget(data_group)
        
        # Output directory
        output_group = QGroupBox("Output Directory")
        output_layout = QHBoxLayout(output_group)
        
        self.csv_path_edit = QLineEdit()
        output_layout.addWidget(self.csv_path_edit)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_csv_output)
        output_layout.addWidget(browse_btn)
        
        layout.addWidget(output_group)
        
        # Set default file path
        default_path = os.path.expanduser(f"~/Desktop/{self.session.name}_csv")
        self.csv_path_edit.setText(default_path)
        
        # Add note about multiple files
        note_label = QLabel(
            "Note: Each selected data type will be exported as a separate CSV file."
        )
        note_label.setWordWrap(True)
        note_label.setStyleSheet("color: #666666;")
        layout.addWidget(note_label)
        
        return tab
    
    def _browse_pdf_output(self):
        """Browse for PDF output file"""
        current_path = self.pdf_path_edit.text()
        
        # Get directory from current path
        if os.path.isdir(current_path):
            directory = current_path
        else:
            directory = os.path.dirname(current_path) if current_path else os.path.expanduser("~")
        
        # Show save dialog
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save PDF Report", directory, "PDF Files (*.pdf);;All Files (*)"
        )
        
        if file_path:
            # Add .pdf extension if missing
            if not file_path.lower().endswith('.pdf'):
                file_path += '.pdf'
            
            self.pdf_path_edit.setText(file_path)
    
    def _browse_json_output(self):
        """Browse for JSON output file"""
        current_path = self.json_path_edit.text()
        
        # Get directory from current path
        if os.path.isdir(current_path):
            directory = current_path
        else:
            directory = os.path.dirname(current_path) if current_path else os.path.expanduser("~")
        
        # Show save dialog
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON Data", directory, "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            # Add .json extension if missing
            if not file_path.lower().endswith('.json'):
                file_path += '.json'
            
            self.json_path_edit.setText(file_path)
    
    def _browse_csv_output(self):
        """Browse for CSV output directory"""
        current_path = self.csv_path_edit.text()
        
        # Use current path as starting directory if it exists
        if os.path.isdir(current_path):
            directory = current_path
        else:
            directory = os.path.expanduser("~")
        
        # Show directory selection dialog
        selected_dir = QFileDialog.getExistingDirectory(
            self, "Select Directory for CSV Files", directory
        )
        
        if selected_dir:
            self.csv_path_edit.setText(selected_dir)
    
    def _export_data(self):
        """Start export based on selected tab"""
        current_tab = self.tab_widget.currentWidget()
        
        if current_tab == self.pdf_tab:
            self._export_pdf()
        elif current_tab == self.json_tab:
            self._export_json()
        elif current_tab == self.csv_tab:
            self._export_csv()
    
    def _export_pdf(self):
        """Export as PDF report"""
        # Validate output path
        output_path = self.pdf_path_edit.text()
        if not output_path:
            QMessageBox.warning(self, "Missing Output Path", "Please specify an output file path.")
            return
        
        # Create output directory if needed
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except Exception as e:
                QMessageBox.critical(
                    self, "Error Creating Directory", 
                    f"Could not create directory: {output_dir}\n\n{str(e)}"
                )
                return
        
        # Get selected sections
        sections = [
            section_id for section_id, checkbox in self.section_checks.items()
            if checkbox.isChecked()
        ]
        
        if not sections:
            QMessageBox.warning(
                self, "No Sections Selected", 
                "Please select at least one section to include in the report."
            )
            return
        
        # Prepare for export
        self._prepare_for_export()
        
        # Create and start export thread
        self.export_thread = ExportThread(
            self.session, 
            'pdf', 
            output_path, 
            {'sections': sections}
        )
        
        self.export_thread.progress_updated.connect(self._update_progress)
        self.export_thread.export_completed.connect(self._export_finished)
        self.export_thread.start()
    
    def _export_json(self):
        """Export as JSON data"""
        # Validate output path
        output_path = self.json_path_edit.text()
        if not output_path:
            QMessageBox.warning(self, "Missing Output Path", "Please specify an output file path.")
            return
        
        # Create output directory if needed
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except Exception as e:
                QMessageBox.critical(
                    self, "Error Creating Directory", 
                    f"Could not create directory: {output_dir}\n\n{str(e)}"
                )
                return
        
        # Get selected data types
        data_types = [
            data_id for data_id, checkbox in self.json_data_checks.items()
            if checkbox.isChecked()
        ]
        
        if not data_types:
            QMessageBox.warning(
                self, "No Data Selected", 
                "Please select at least one data type to export."
            )
            return
        
        # Get pretty print setting
        pretty_print = self.pretty_print_check.isChecked()
        
        # Prepare for export
        self._prepare_for_export()
        
        # Create and start export thread
        self.export_thread = ExportThread(
            self.session, 
            'json', 
            output_path, 
            {'data_types': data_types, 'pretty_print': pretty_print}
        )
        
        self.export_thread.progress_updated.connect(self._update_progress)
        self.export_thread.export_completed.connect(self._export_finished)
        self.export_thread.start()
    
    def _export_csv(self):
        """Export as CSV files"""
        # Validate output path
        output_path = self.csv_path_edit.text()
        if not output_path:
            QMessageBox.warning(self, "Missing Output Path", "Please specify an output directory.")
            return
        
        # Create output directory if needed
        if not os.path.exists(output_path):
            try:
                os.makedirs(output_path)
            except Exception as e:
                QMessageBox.critical(
                    self, "Error Creating Directory", 
                    f"Could not create directory: {output_path}\n\n{str(e)}"
                )
                return
        
        # Get selected data types
        data_types = [
            data_id for data_id, checkbox in self.csv_data_checks.items()
            if checkbox.isChecked()
        ]
        
        if not data_types:
            QMessageBox.warning(
                self, "No Data Selected", 
                "Please select at least one data type to export."
            )
            return
        
        # Prepare for export
        self._prepare_for_export()
        
        # Create and start export thread
        self.export_thread = ExportThread(
            self.session, 
            'csv', 
            output_path, 
            {'data_types': data_types}
        )
        
        self.export_thread.progress_updated.connect(self._update_progress)
        self.export_thread.export_completed.connect(self._export_finished)
        self.export_thread.start()
    
    def _prepare_for_export(self):
        """Prepare UI for export operation"""
        # Show progress group
        self.progress_group.setVisible(True)
        
        # Disable export button
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        
        # Change cancel button to "Stop"
        self.button_box.button(QDialogButtonBox.StandardButton.Cancel).setText("Stop")
        self.button_box.rejected.disconnect()
        self.button_box.rejected.connect(self._stop_export)
        
        # Reset progress
        self.progress_bar.setValue(0)
        self.progress_label.setText("Preparing for export...")
    
    def _update_progress(self, message: str, progress: float):
        """
        Update progress display
        
        Args:
            message: Progress message
            progress: Progress value (0.0 to 1.0)
        """
        self.progress_label.setText(message)
        self.progress_bar.setValue(int(progress * 100))
    
    def _export_finished(self, success: bool, result: str):
        """
        Handle export completion
        
        Args:
            success: Whether export was successful
            result: Output path or error message
        """
        # Re-enable the export button
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)
        
        # Change "Stop" back to "Cancel" and reconnect
        self.button_box.button(QDialogButtonBox.StandardButton.Cancel).setText("Close")
        self.button_box.rejected.disconnect()
        self.button_box.rejected.connect(self.reject)
        
        if success:
            # Show success message
            self.progress_label.setText("Export completed successfully.")
            self.progress_bar.setValue(100)
            
            QMessageBox.information(
                self, "Export Complete", 
                f"Data exported successfully to:\n{result}"
            )
            
            # Ask if user wants to open the output
            reply = QMessageBox.question(
                self, "Open Output",
                "Do you want to open the exported file(s)?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self._open_output(result)
            
            # Close dialog
            self.accept()
            
        else:
            # Show error message
            self.progress_label.setText(f"Export failed: {result}")
            
            QMessageBox.critical(
                self, "Export Failed", 
                f"Failed to export data:\n{result}"
            )
    
    def _stop_export(self):
        """Stop the current export operation"""
        if self.export_thread and self.export_thread.isRunning():
            # Show confirmation dialog
            reply = QMessageBox.question(
                self, "Stop Export",
                "Do you want to stop the current export operation?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                # Stop the thread
                self.export_thread.terminate()
                self.export_thread.wait()
                
                # Update UI
                self.progress_label.setText("Export operation stopped.")
                
                # Re-enable export button
                self.button_box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)
                
                # Change "Stop" back to "Cancel" and reconnect
                self.button_box.button(QDialogButtonBox.StandardButton.Cancel).setText("Close")
                self.button_box.rejected.disconnect()
                self.button_box.rejected.connect(self.reject)
        else:
            # Just close the dialog
            self.reject()
    
    def _open_output(self, path: str):
        """
        Open the exported file or directory
        
        Args:
            path: File or directory path
        """
        import platform
        import subprocess
        
        try:
            if platform.system() == 'Windows':
                os.startfile(path)
            elif platform.system() == 'Darwin':  # macOS
                subprocess.call(['open', path])
            else:  # Linux
                subprocess.call(['xdg-open', path])
        except Exception as e:
            QMessageBox.warning(
                self, "Cannot Open Output",
                f"Could not open the output:\n{str(e)}"
            )