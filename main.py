#!/usr/bin/env python3
import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QCoreApplication
from PyQt6.QtGui import QIcon

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from src.ui.main_window import MainWindow
from src.utils.config import Config

def main():
    # Initialize configuration
    config = Config()
    
    # Create application (conditionally enable HiDPI scaling if constant is available)
    if hasattr(Qt.ApplicationAttribute, "AA_EnableHighDpiScaling"):
        QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    app = QApplication(sys.argv)
    app.setApplicationName("Net4")
    app.setApplicationDisplayName("Net4 - Network Forensic Analysis")
    
    # Set application style
    app.setStyle("Fusion")
    
    # Restore application icon (PNG inside assets/icons)
    icon_path = os.path.join("assets", "icons", "app_icon.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    
    # Create and show main window
    window = MainWindow(config)
    window.show()
    
    # Start event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()