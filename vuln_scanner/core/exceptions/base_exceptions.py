"""Base exception classes for VulnMiner system."""

from typing import Optional, Dict, Any


class VulnMinerException(Exception):
    """Base exception class for all VulnMiner exceptions.
    
    This is the root exception that all other VulnMiner exceptions inherit from.
    It provides common functionality for error handling and logging.
    """
    
    def __init__(self, message: str, error_code: Optional[str] = None, 
                 details: Optional[Dict[str, Any]] = None, 
                 suggestion: Optional[str] = None):
        """Initialize base exception.
        
        Args:
            message: Human-readable error message
            error_code: Machine-readable error code for programmatic handling
            details: Additional details about the error
            suggestion: Suggested action to resolve the error
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.suggestion = suggestion
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging/serialization.
        
        Returns:
            Dictionary representation of the exception
        """
        return {
            'exception_type': self.__class__.__name__,
            'message': self.message,
            'error_code': self.error_code,
            'details': self.details,
            'suggestion': self.suggestion,
        }
    
    def __str__(self) -> str:
        """Return string representation of exception."""
        if self.suggestion:
            return f"{self.message}. Suggestion: {self.suggestion}"
        return self.message


class VulnMinerError(VulnMinerException):
    """General error class for recoverable errors.
    
    Use this for errors that can be handled gracefully and don't require
    immediate termination of the application.
    """
    pass


class VulnMinerCriticalError(VulnMinerException):
    """Critical error class for non-recoverable errors.
    
    Use this for errors that require immediate attention and may cause
    the application to terminate or fail catastrophically.
    """
    pass