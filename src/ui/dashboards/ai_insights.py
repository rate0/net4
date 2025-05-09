from datetime import datetime
from typing import List, Dict, Any, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QLabel, 
    QTextEdit, QPushButton, QLineEdit, QGroupBox, QScrollArea,
    QFrame, QSizePolicy, QTextBrowser, QGridLayout
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize, QTimer
from PyQt6.QtGui import QFont, QColor, QPalette, QTextCursor, QIcon

from ...models.session import Session


class ChatMessageWidget(QFrame):
    """Widget to display a single chat message in a modern chat interface style"""
    
    def __init__(self, message: Dict[str, Any], is_user: bool = False, parent=None):
        """
        Initialize chat message widget
        
        Args:
            message: Message data
            is_user: True if this is a user message, False for AI
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Configure frame appearance
        self.setFrameShape(QFrame.Shape.NoFrame)  # Remove frame border
        self.setAutoFillBackground(True)
        
        # Modern styling for message bubbles
        if is_user:
            # User messages aligned right with accent color
            self.setStyleSheet("""
                QFrame {
                    background-color: #2d74da;
                    border-radius: 18px;
                    border-top-right-radius: 4px;
                    margin-left: 50px;
                }
            """)
        else:
            # AI messages aligned left with darker background
            self.setStyleSheet("""
                QFrame {
                    background-color: #323242;
                    border-radius: 18px;
                    border-top-left-radius: 4px;
                    margin-right: 50px;
                }
            """)
        
        # Create layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 12, 15, 12)
        layout.setSpacing(6)
        
        # Create a row for the avatar and sender info
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 5)
        
        # Avatar using emoji instead of external icons
        icon_label = QLabel("👤" if is_user else "🤖")
        icon_label.setStyleSheet("color: white; font-size: 16px;")
        
        header_layout.addWidget(icon_label)
        
        # Sender name with modern styling
        sender_label = QLabel("You" if is_user else "AI Assistant")
        sender_label.setStyleSheet(f"color: {'white' if is_user else '#e0e0e0'}; font-weight: bold;")
        header_layout.addWidget(sender_label)
        header_layout.addStretch()
        
        # Timestamp with subtle styling
        timestamp = datetime.fromisoformat(message.get("timestamp", datetime.now().isoformat()))
        timestamp_str = timestamp.strftime("%H:%M")  # Simpler time format like modern chat apps
        timestamp_label = QLabel(timestamp_str)
        timestamp_label.setStyleSheet(f"color: {'rgba(255,255,255,0.7)' if is_user else 'rgba(224,224,224,0.7)'}; font-size: 10px;")
        header_layout.addWidget(timestamp_label)
        
        layout.addLayout(header_layout)
        
        # Add message content with modern styling
        content_text = QTextBrowser()
        content_text.setOpenExternalLinks(True)
        content_text.setReadOnly(True)
        content_text.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        # Style the text area to match the bubble
        content_text.setStyleSheet(f"""
            QTextBrowser {{
                border: none;
                background-color: transparent;
                color: {'white' if is_user else '#ffffff'};
                font-size: 13px;
                line-height: 1.4;
            }}
        """)
        
        # Get message content
        if is_user:
            content = message.get("question", "")
        else:
            content = message.get("answer", "")
        
        # Set the document contents
        content_text.setMarkdown(content)
        
        # Adjust height to content dynamically
        content_text.document().adjustSize()
        content_height = int(content_text.document().size().height() + 30)
        content_text.setMinimumHeight(min(60, content_height))
        
        # Allow the content to expand more for AI responses
        if is_user:
            content_text.setMaximumHeight(min(300, content_height))
        else:
            content_text.setMaximumHeight(min(500, content_height))
        
        layout.addWidget(content_text)
        
        # Set width constraints based on parent (chat bubble style)
        if parent:
            max_width = int(parent.width() * 0.85)
            self.setMinimumWidth(200)
            self.setMaximumWidth(max_width)


class ChatHistoryWidget(QScrollArea):
    """Widget to display chat history in a modern chat interface style"""
    
    def __init__(self, parent=None):
        """
        Initialize chat history widget
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Create container widget with modern styling
        self.container = QWidget()
        self.container.setObjectName("chatContainer")
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.container_layout.setSpacing(16)  # More space between messages
        self.container_layout.setContentsMargins(15, 20, 15, 20)
        
        # Set scroll area properties with modern styling
        self.setWidget(self.container)
        self.setWidgetResizable(True)
        self.setMinimumWidth(400)
        self.setFrameShape(QFrame.Shape.NoFrame)  # Remove frame border
        
        # Clean modern scrollbar styling
        self.setStyleSheet("""
            QScrollArea {
                background-color: #1e1e2e;
                border: none;
            }
            QScrollBar:vertical {
                background-color: #282838;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #414558;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #5a6988;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background-color: transparent;
            }
        """)
        
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
        
        # Question input area with modern styling
        input_frame = QFrame()
        input_frame.setObjectName("chatInputFrame")
        input_frame.setStyleSheet("""
            #chatInputFrame {
                background-color: #323242;
                border-radius: 20px;
                border: 1px solid #414558;
            }
        """)
        
        input_layout = QHBoxLayout(input_frame)
        input_layout.setContentsMargins(15, 5, 5, 5)
        input_layout.setSpacing(10)
        
        # Modern styled input field
        self.question_input = QLineEdit()
        self.question_input.setPlaceholderText("Ask a question about your network data...")
        self.question_input.returnPressed.connect(self._ask_question)
        self.question_input.setStyleSheet("""
            QLineEdit {
                background-color: transparent;
                color: white;
                border: none;
                padding: 10px 0px;
                font-size: 13px;
                selection-background-color: #2d74da;
            }
        """)
        input_layout.addWidget(self.question_input)
        
        # Modern styled send button
        self.ask_button = QPushButton("➡")
        self.ask_button.setToolTip("Send message")
        
        self.ask_button.clicked.connect(self._ask_question)
        self.ask_button.setStyleSheet("""
            QPushButton {
                background-color: #2d74da;
                color: white;
                border-radius: 18px;
                min-width: 36px;
                min-height: 36px;
                padding: 6px;
            }
            QPushButton:hover {
                background-color: #3a82f7;
            }
            QPushButton:pressed {
                background-color: #2361b8;
            }
        """)
        
        input_layout.addWidget(self.ask_button)
        chat_layout.addWidget(input_frame)
        
        # Suggested questions with modern chip-style buttons
        suggested_frame = QFrame()
        suggested_frame.setObjectName("suggestedQuestionsFrame")
        suggested_frame.setStyleSheet("""
            #suggestedQuestionsFrame {
                background-color: #282838;
                border-radius: 8px;
                border: 1px solid #414558;
                margin-top: 10px;
                padding: 5px;
            }
        """)
        suggested_layout = QVBoxLayout(suggested_frame)
        suggested_layout.setContentsMargins(10, 12, 10, 12)
        suggested_layout.setSpacing(12)
        
        # Title for suggested questions
        suggested_title = QLabel("Suggested Questions")
        suggested_title.setStyleSheet("color: #94a3b8; font-weight: bold; font-size: 12px;")
        suggested_layout.addWidget(suggested_title)
        
        # Grid layout for question chips
        questions_grid = QGridLayout()
        questions_grid.setHorizontalSpacing(10)
        questions_grid.setVerticalSpacing(8)
        
        suggested_questions = [
            "What are the most suspicious entities?",
            "Summarize traffic patterns",
            "Any data exfiltration attempts?",
            "Unusual communication patterns?",
            "Which IPs to investigate?",
            "What ports are suspicious?"
        ]
        
        # Create chip-style buttons in a grid
        for i, question in enumerate(suggested_questions):
            row = i // 2
            col = i % 2
            
            question_button = QPushButton(question)
            question_button.setCursor(Qt.CursorShape.PointingHandCursor)
            question_button.clicked.connect(lambda checked=False, q=question: self.set_question(q))
            question_button.setStyleSheet("""
                QPushButton {
                    background-color: #323242;
                    color: #e0e0e0;
                    border-radius: 15px;
                    border: 1px solid #414558;
                    padding: 8px 12px;
                    text-align: center;
                    font-size: 12px;
                }
                QPushButton:hover {
                    background-color: #414558;
                    border-color: #5a6988;
                }
                QPushButton:pressed {
                    background-color: #2d74da;
                }
            """)
            questions_grid.addWidget(question_button, row, col)
        
        suggested_layout.addLayout(questions_grid)
        chat_layout.addWidget(suggested_frame)
        
        # Add to splitter
        splitter.addWidget(chat_container)
        
        # Set initial sizes (30% summary, 70% chat)
        splitter.setSizes([400, 600])
        
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