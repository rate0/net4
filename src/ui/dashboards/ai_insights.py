from datetime import datetime
from typing import List, Dict, Any, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QLabel, 
    QTextEdit, QPushButton, QLineEdit, QGroupBox, QScrollArea,
    QFrame, QSizePolicy, QTextBrowser
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize, QTimer
from PyQt6.QtGui import QFont, QColor, QPalette, QTextCursor, QIcon

from ...models.session import Session


class ChatMessageWidget(QFrame):
    """Widget to display a single chat message"""
    
    def __init__(self, message: Dict[str, Any], is_user: bool = False, parent=None):
        """
        Initialize chat message widget
        
        Args:
            message: Message data
            is_user: True if this is a user message, False for AI
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setFrameShadow(QFrame.Shadow.Raised)
        self.setAutoFillBackground(True)
        
        # Set background color based on message type - using more subtle colors
        palette = self.palette()
        if is_user:
            palette.setColor(QPalette.ColorRole.Window, QColor("#f0f0f0"))  # Light gray for user
        else:
            palette.setColor(QPalette.ColorRole.Window, QColor("#f8f8f8"))  # Very light gray for AI
        self.setPalette(palette)
        
        # Create layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        
        # Add header (timestamp + sender)
        header_layout = QHBoxLayout()
        
        # Sender name
        sender_label = QLabel("You:" if is_user else "AI Assistant:")
        sender_label.setStyleSheet("font-weight: bold;")
        header_layout.addWidget(sender_label)
        
        # Timestamp
        timestamp = datetime.fromisoformat(message.get("timestamp", datetime.now().isoformat()))
        timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        timestamp_label = QLabel(timestamp_str)
        timestamp_label.setStyleSheet("color: gray;")
        timestamp_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        header_layout.addWidget(timestamp_label)
        
        layout.addLayout(header_layout)
        
        # Add content
        content_text = QTextBrowser()
        content_text.setOpenExternalLinks(True)
        content_text.setReadOnly(True)
        
        # Style the text area
        content_text.setStyleSheet("""
            QTextBrowser {
                border: none;
                background-color: transparent;
            }
        """)
        
        # Get message content
        if is_user:
            content = message.get("question", "")
        else:
            content = message.get("answer", "")
        
        # Set the document contents
        content_text.setMarkdown(content)
        
        # Adjust height to content
        content_text.document().adjustSize()
        content_height = int(content_text.document().size().height() + 20)
        content_text.setMinimumHeight(min(50, content_height))
        content_text.setMaximumHeight(min(300, content_height))
        
        layout.addWidget(content_text)
        
        # Set maximum width based on parent
        if parent:
            self.setMaximumWidth(int(parent.width() * 0.95))


class ChatHistoryWidget(QScrollArea):
    """Widget to display chat history"""
    
    def __init__(self, parent=None):
        """
        Initialize chat history widget
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Create container widget
        self.container = QWidget()
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.container_layout.setSpacing(10)
        self.container_layout.setContentsMargins(10, 10, 10, 10)
        
        # Set scroll area properties
        self.setWidget(self.container)
        self.setWidgetResizable(True)
        self.setMinimumWidth(400)
        
        # Store messages
        self.messages = []
    
    def add_message(self, message: Dict[str, Any], is_user: bool = False):
        """
        Add a message to the chat history
        
        Args:
            message: Message data
            is_user: True if this is a user message, False for AI
        """
        # Create message widget
        message_widget = ChatMessageWidget(message, is_user, self)
        
        # Add to layout
        self.container_layout.addWidget(message_widget)
        
        # Store message
        self.messages.append({
            "message": message,
            "is_user": is_user
        })
        
        # Scroll to bottom
        QTimer.singleShot(100, self.scroll_to_bottom)
    
    def scroll_to_bottom(self):
        """Scroll to bottom of chat history"""
        vsb = self.verticalScrollBar()
        vsb.setValue(vsb.maximum())
    
    def clear(self):
        """Clear chat history"""
        # Remove all message widgets
        while self.container_layout.count() > 0:
            item = self.container_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Clear message list
        self.messages = []


class SummaryWidget(QGroupBox):
    """Widget to display session summary"""
    
    def __init__(self, parent=None):
        """
        Initialize summary widget
        
        Args:
            parent: Parent widget
        """
        super().__init__("Session Summary", parent)
        
        # Create layout
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Add summary text
        self.summary_text = QTextBrowser()
        self.summary_text.setReadOnly(True)
        self.summary_text.setMinimumHeight(100)
        layout.addWidget(self.summary_text)
        
        # Add key observations
        self.observations_group = QGroupBox("Key Observations")
        observations_layout = QVBoxLayout(self.observations_group)
        self.observations_text = QTextBrowser()
        self.observations_text.setReadOnly(True)
        observations_layout.addWidget(self.observations_text)
        layout.addWidget(self.observations_group)
        
        # Add security concerns
        self.concerns_group = QGroupBox("Security Concerns")
        concerns_layout = QVBoxLayout(self.concerns_group)
        self.concerns_text = QTextBrowser()
        self.concerns_text.setReadOnly(True)
        concerns_layout.addWidget(self.concerns_text)
        layout.addWidget(self.concerns_group)
        
        # Add recommended actions
        self.actions_group = QGroupBox("Recommended Actions")
        actions_layout = QVBoxLayout(self.actions_group)
        self.actions_text = QTextBrowser()
        self.actions_text.setReadOnly(True)
        actions_layout.addWidget(self.actions_text)
        layout.addWidget(self.actions_group)
    
    def update_summary(self, summary_data: Dict[str, Any]):
        """
        Update summary data
        
        Args:
            summary_data: Summary data dictionary
        """
        # Update summary text
        summary_text = summary_data.get("summary", "No summary available")
        self.summary_text.setPlainText(summary_text)
        
        # Update key observations
        observations = summary_data.get("key_observations", [])
        if observations:
            observations_html = "<ul>"
            for item in observations:
                observations_html += f"<li>{item}</li>"
            observations_html += "</ul>"
            self.observations_text.setHtml(observations_html)
            self.observations_group.setVisible(True)
        else:
            self.observations_group.setVisible(False)
        
        # Update security concerns
        concerns = summary_data.get("security_concerns", [])
        if concerns:
            concerns_html = "<ul>"
            for item in concerns:
                concerns_html += f"<li>{item}</li>"
            concerns_html += "</ul>"
            self.concerns_text.setHtml(concerns_html)
            self.concerns_group.setVisible(True)
        else:
            self.concerns_group.setVisible(False)
        
        # Update recommended actions
        actions = summary_data.get("recommended_actions", [])
        if actions:
            actions_html = "<ul>"
            for item in actions:
                actions_html += f"<li>{item}</li>"
            actions_html += "</ul>"
            self.actions_text.setHtml(actions_html)
            self.actions_group.setVisible(True)
        else:
            self.actions_group.setVisible(False)


class AIInsightsDashboard(QWidget):
    """
    Dashboard for AI insights and interactive chat.
    Provides summary of network traffic and allows asking questions.
    """
    
    # Signal to ask a question
    ask_question_signal = pyqtSignal(str)
    
    def __init__(self, session: Session, main_window, parent=None):
        """
        Initialize AI insights dashboard
        
        Args:
            session: Analysis session
            main_window: Main application window
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.session = session
        self.main_window = main_window
        
        # Set up UI
        self._init_ui()
    
    def _init_ui(self):
        """Initialize user interface"""
        main_layout = QVBoxLayout(self)
        
        # Create splitter for summary and chat
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Summary
        summary_container = QWidget()
        summary_layout = QVBoxLayout(summary_container)
        
        # Summary widget
        self.summary_widget = SummaryWidget()
        summary_layout.addWidget(self.summary_widget)
        
        # Run analysis button
        self.analyze_button = QPushButton("Run Network Analysis")
        self.analyze_button.clicked.connect(self._run_analysis)
        summary_layout.addWidget(self.analyze_button)
        
        # Add stretch to push widgets to top
        summary_layout.addStretch()
        
        # Add to splitter
        splitter.addWidget(summary_container)
        
        # Right side - Chat
        chat_container = QWidget()
        chat_layout = QVBoxLayout(chat_container)
        
        # Chat header
        chat_header = QLabel("AI Assistant Chat")
        font = QFont()
        font.setBold(True)
        chat_header.setFont(font)
        chat_layout.addWidget(chat_header)
        
        # Chat instructions
        chat_instructions = QLabel(
            "Ask questions about your network data, potential threats, or anomalies."
        )
        chat_layout.addWidget(chat_instructions)
        
        # Chat history
        self.chat_history = ChatHistoryWidget()
        chat_layout.addWidget(self.chat_history)
        
        # Question input area
        input_layout = QHBoxLayout()
        
        self.question_input = QLineEdit()
        self.question_input.setPlaceholderText("Ask a question about your network data...")
        self.question_input.returnPressed.connect(self._ask_question)
        input_layout.addWidget(self.question_input)
        
        self.ask_button = QPushButton("Ask")
        self.ask_button.clicked.connect(self._ask_question)
        input_layout.addWidget(self.ask_button)
        
        chat_layout.addLayout(input_layout)
        
        # Suggested questions
        suggested_questions_group = QGroupBox("Suggested Questions")
        suggested_layout = QVBoxLayout(suggested_questions_group)
        
        suggested_questions = [
            "What are the most suspicious entities in this session?",
            "Summarize the network traffic patterns",
            "Are there any potential data exfiltration attempts?",
            "What unusual communication patterns are present?",
            "Which IP addresses should I investigate further?"
        ]
        
        for question in suggested_questions:
            question_button = QPushButton(question)
            question_button.clicked.connect(lambda checked=False, q=question: self.set_question(q))
            suggested_layout.addWidget(question_button)
        
        chat_layout.addWidget(suggested_questions_group)
        
        # Add to splitter
        splitter.addWidget(chat_container)
        
        # Set initial sizes (30% summary, 70% chat)
        splitter.setSizes([300, 700])
        
        main_layout.addWidget(splitter)
        
        # Connect signals
        self.ask_question_signal.connect(self.main_window.ask_ai_question)
    
    def update_dashboard(self):
        """Update dashboard with current session data"""
        if self.session:
            # Get summary data
            summary_data = self.main_window.ai_engine.get_network_summary(self.session)
            
            # Update summary widget
            self.summary_widget.update_summary(summary_data)
            
            # Load chat history
            self._load_chat_history()
    
    def _load_chat_history(self):
        """Load chat history from session"""
        # Clear existing history
        self.chat_history.clear()
        
        # Get chat history from AI engine
        history = self.main_window.ai_engine.get_chat_history(self.session)
        
        # Add messages to chat history
        for message in reversed(history):  # Newest last
            # Add question (user message)
            user_message = {
                "question": message.get("question", ""),
                "timestamp": message.get("timestamp", datetime.now().isoformat())
            }
            self.chat_history.add_message(user_message, is_user=True)
            
            # Add answer (AI message)
            ai_message = {
                "answer": message.get("answer", ""),
                "timestamp": message.get("timestamp", datetime.now().isoformat())
            }
            self.chat_history.add_message(ai_message)
    
    def _ask_question(self):
        """Ask a question to the AI assistant"""
        # Get question text
        question = self.question_input.text().strip()
        
        if not question:
            return
        
        # Add question to chat history
        question_message = {
            "question": question,
            "timestamp": datetime.now().isoformat()
        }
        self.chat_history.add_message(question_message, is_user=True)
        
        # Clear input
        self.question_input.clear()
        
        # Add placeholder answer
        answer_message = {
            "answer": "_Processing your question..._",
            "timestamp": datetime.now().isoformat()
        }
        self.chat_history.add_message(answer_message)
        
        # Emit signal to ask question
        self.ask_question_signal.emit(question)
    
    def set_question(self, question: str):
        """
        Set the question input text
        
        Args:
            question: Question text
        """
        self.question_input.setText(question)
        self.question_input.setFocus()
    
    def focus_chat_input(self):
        """Focus on chat input"""
        self.question_input.setFocus()
    
    def add_answer(self, result: Dict[str, Any]):
        """
        Add answer to chat history
        
        Args:
            result: Answer result data
        """
        # Remove last message (placeholder)
        if self.chat_history.messages:
            last_message = self.chat_history.messages[-1]
            if not last_message["is_user"] and "Processing your question" in last_message["message"].get("answer", ""):
                # Remove the widget
                item = self.chat_history.container_layout.takeAt(self.chat_history.container_layout.count() - 1)
                if item.widget():
                    item.widget().deleteLater()
                
                # Remove from list
                self.chat_history.messages.pop()
        
        # Add real answer
        self.chat_history.add_message(result)
    
    def _run_analysis(self):
        """Run network analysis"""
        # Call main window's AI analysis method
        self.main_window._run_ai_analysis()