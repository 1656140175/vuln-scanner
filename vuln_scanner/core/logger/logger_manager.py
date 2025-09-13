"""Logger manager for centralized logging configuration."""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Dict, Any, Optional

from .structured_formatter import StructuredFormatter


class LoggerManager:
    """Manages logging configuration and setup for VulnMiner system."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize logger manager with configuration.
        
        Args:
            config: Configuration dictionary containing logging settings
        """
        self.config = config
        self.logging_config = config.get('logging', {})
        self.loggers: Dict[str, logging.Logger] = {}
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Set up logging configuration based on config."""
        # Ensure logs directory exists
        logs_dir = Path(self.config.get('system', {}).get('logs_dir', 'logs'))
        logs_dir.mkdir(exist_ok=True)
        
        # Configure root logger
        root_logger = logging.getLogger('vuln_miner')
        root_logger.setLevel(self._get_log_level())
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Add console handler
        self._add_console_handler(root_logger)
        
        # Add file handler with rotation
        self._add_file_handler(root_logger, logs_dir)
        
        # Add security audit handler
        self._add_security_audit_handler(logs_dir)
        
        # Store root logger
        self.loggers['root'] = root_logger
    
    def _get_log_level(self) -> int:
        """Get logging level from configuration.
        
        Returns:
            Logging level constant
        """
        level_name = self.logging_config.get('level', 'INFO').upper()
        return getattr(logging, level_name, logging.INFO)
    
    def _add_console_handler(self, logger: logging.Logger) -> None:
        """Add console handler to logger.
        
        Args:
            logger: Logger to add handler to
        """
        console_handler = logging.StreamHandler()
        
        # Use structured formatter for console in production
        if self.config.get('system', {}).get('environment') == 'production':
            console_handler.setFormatter(StructuredFormatter())
        else:
            # Use human-readable format for development
            format_str = self.logging_config.get(
                'format',
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(logging.Formatter(format_str))
        
        console_handler.setLevel(self._get_log_level())
        logger.addHandler(console_handler)
    
    def _add_file_handler(self, logger: logging.Logger, logs_dir: Path) -> None:
        """Add rotating file handler to logger.
        
        Args:
            logger: Logger to add handler to
            logs_dir: Directory for log files
        """
        log_file = logs_dir / 'vuln_miner.log'
        
        if self.logging_config.get('file_rotation', True):
            # Use rotating file handler
            max_bytes = self._parse_size(self.logging_config.get('max_file_size', '10MB'))
            backup_count = self.logging_config.get('backup_count', 5)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
        else:
            # Use regular file handler
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
        
        # Always use structured format for file logs
        file_handler.setFormatter(StructuredFormatter())
        file_handler.setLevel(self._get_log_level())
        
        logger.addHandler(file_handler)
    
    def _add_security_audit_handler(self, logs_dir: Path) -> None:
        """Add dedicated security audit log handler.
        
        Args:
            logs_dir: Directory for log files
        """
        # Create dedicated security logger
        security_logger = logging.getLogger('vuln_miner.security')
        security_logger.setLevel(logging.INFO)
        security_logger.propagate = False  # Don't propagate to root logger
        
        # Security audit log file
        audit_file = logs_dir / 'security_audit.log'
        
        # Use time-based rotation for security logs
        audit_handler = logging.handlers.TimedRotatingFileHandler(
            audit_file,
            when='midnight',
            interval=1,
            backupCount=30,  # Keep 30 days of audit logs
            encoding='utf-8'
        )
        
        # Use structured format for audit logs
        audit_handler.setFormatter(StructuredFormatter())
        security_logger.addHandler(audit_handler)
        
        self.loggers['security'] = security_logger
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string to bytes.
        
        Args:
            size_str: Size string (e.g., '10MB')
            
        Returns:
            Size in bytes
        """
        size_str = size_str.upper()
        multipliers = {
            'B': 1,
            'KB': 1024,
            'MB': 1024 * 1024,
            'GB': 1024 * 1024 * 1024,
        }
        
        for unit, multiplier in multipliers.items():
            if size_str.endswith(unit):
                number_str = size_str[:-len(unit)]
                try:
                    return int(float(number_str) * multiplier)
                except ValueError:
                    break
        
        # Default to 10MB if parsing fails
        return 10 * 1024 * 1024
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get logger by name.
        
        Args:
            name: Logger name
            
        Returns:
            Logger instance
        """
        if name in self.loggers:
            return self.loggers[name]
        
        # Create child logger of root
        logger = logging.getLogger(f'vuln_miner.{name}')
        self.loggers[name] = logger
        return logger
    
    def set_level(self, level: str) -> None:
        """Set logging level for all loggers.
        
        Args:
            level: Logging level name
        """
        log_level = getattr(logging, level.upper(), logging.INFO)
        
        for logger in self.loggers.values():
            logger.setLevel(log_level)
            for handler in logger.handlers:
                handler.setLevel(log_level)
    
    def shutdown(self) -> None:
        """Shutdown logging and close all handlers."""
        for logger in self.loggers.values():
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)
        
        logging.shutdown()