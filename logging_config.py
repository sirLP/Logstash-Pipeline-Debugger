"""
Structured logging configuration for the Logstash Pipeline Debugger
Enables consistent, meaningful logging across the application.
"""
import logging
import logging.handlers
import sys
from datetime import datetime
from typing import Optional


class ContextFilter(logging.Filter):
    """Add contextual information to log records (request_id, event_id, etc.)"""
    
    def __init__(self, context: Optional[dict] = None):
        super().__init__()
        self.context = context or {}
    
    def filter(self, record):
        """Inject context into the log record"""
        record.request_id = self.context.get('request_id', '-')
        record.event_id = self.context.get('event_id', '-')
        return True


class ColoredFormatter(logging.Formatter):
    """Add color to console logs for better readability"""
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        if sys.stdout.isatty():  # Only color if outputting to terminal
            color = self.COLORS.get(record.levelname, self.RESET)
            record.levelname = f'{color}[{record.levelname}]{self.RESET}'
        return super().format(record)


def configure_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    context: Optional[dict] = None
) -> logging.Logger:
    """
    Configure structured logging for the application.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file path for file logging
        context: Optional contextual data (request_id, event_id, etc.)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger('pfelk')
    logger.setLevel(level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler with color
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    # Format: [LEVEL] [context] timestamp module.function:line - message
    console_format = (
        '%(levelname)-8s '
        '[%(request_id)s|%(event_id)s] '
        '%(asctime)s '
        '%(name)s.%(funcName)s:%(lineno)d - '
        '%(message)s'
    )
    console_formatter = ColoredFormatter(console_format, datefmt='%H:%M:%S')
    console_handler.setFormatter(console_formatter)
    
    # Add context filter
    context_filter = ContextFilter(context or {})
    console_handler.addFilter(context_filter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)  # Always log DEBUG to file
        
        file_format = (
            '%(asctime)s | '
            '%(levelname)-8s | '
            '%(request_id)s | '
            '%(event_id)s | '
            '%(name)s.%(funcName)s:%(lineno)d | '
            '%(message)s'
        )
        file_formatter = logging.Formatter(file_format, datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(file_formatter)
        file_handler.addFilter(context_filter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance"""
    return logging.getLogger(f'pfelk.{name}')


# Example usage in modules:
# from logging_config import get_logger
# logger = get_logger(__name__)
# logger.info("Processing filter", extra={'filter_type': 'grok'})
