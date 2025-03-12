import os
import logging
import logging.handlers
from datetime import datetime
from typing import Optional

class Logger:
    """Centralized logging for Net4"""
    
    LOG_LEVELS = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL
    }
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, log_dir: Optional[str] = None, log_level: str = "info"):
        if self._initialized:
            return
            
        self._initialized = True
        self.log_dir = log_dir or os.path.join(os.path.expanduser("~"), ".net4", "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Setup root logger
        self.logger = logging.getLogger("net4")
        self.logger.setLevel(self.LOG_LEVELS.get(log_level.lower(), logging.INFO))
        
        # Clear existing handlers
        self.logger.handlers = []
        
        # Setup console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s'
        ))
        self.logger.addHandler(console_handler)
        
        # Setup file handler
        log_file = os.path.join(
            self.log_dir, 
            f"net4_{datetime.now().strftime('%Y%m%d')}.log"
        )
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, 
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d - %(message)s'
        ))
        self.logger.addHandler(file_handler)
    
    def get_logger(self):
        """Get the logger instance"""
        return self.logger
    
    def set_level(self, level: str):
        """Set the logging level"""
        level = level.lower()
        if level in self.LOG_LEVELS:
            self.logger.setLevel(self.LOG_LEVELS[level])
    
    # Convenience methods
    def debug(self, message: str):
        self.logger.debug(message)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def critical(self, message: str):
        self.logger.critical(message)