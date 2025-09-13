"""Configuration-related exception classes."""

from typing import List, Optional, Dict, Any
from .base_exceptions import VulnMinerException, VulnMinerError


class ConfigurationError(VulnMinerError):
    """Exception raised for configuration-related errors."""
    
    def __init__(self, message: str, config_section: Optional[str] = None,
                 config_key: Optional[str] = None, **kwargs):
        """Initialize configuration error.
        
        Args:
            message: Error message
            config_section: Configuration section where error occurred
            config_key: Configuration key that caused the error
            **kwargs: Additional arguments for base class
        """
        details = kwargs.get('details', {})
        if config_section:
            details['config_section'] = config_section
        if config_key:
            details['config_key'] = config_key
        
        kwargs['details'] = details
        kwargs['error_code'] = kwargs.get('error_code', 'CONFIG_ERROR')
        
        super().__init__(message, **kwargs)
        
        self.config_section = config_section
        self.config_key = config_key


class ConfigValidationError(ConfigurationError):
    """Exception raised when configuration validation fails."""
    
    def __init__(self, validation_errors: List[str], **kwargs):
        """Initialize configuration validation error.
        
        Args:
            validation_errors: List of validation error messages
            **kwargs: Additional arguments for base class
        """
        message = f"Configuration validation failed with {len(validation_errors)} errors"
        
        details = kwargs.get('details', {})
        details['validation_errors'] = validation_errors
        
        kwargs['details'] = details
        kwargs['error_code'] = 'CONFIG_VALIDATION_ERROR'
        kwargs['suggestion'] = 'Check configuration files and fix validation errors'
        
        super().__init__(message, **kwargs)
        
        self.validation_errors = validation_errors


class ConfigFileNotFoundError(ConfigurationError):
    """Exception raised when configuration file is not found."""
    
    def __init__(self, file_path: str, **kwargs):
        """Initialize config file not found error.
        
        Args:
            file_path: Path to the missing configuration file
            **kwargs: Additional arguments for base class
        """
        message = f"Configuration file not found: {file_path}"
        
        details = kwargs.get('details', {})
        details['file_path'] = file_path
        
        kwargs['details'] = details
        kwargs['error_code'] = 'CONFIG_FILE_NOT_FOUND'
        kwargs['suggestion'] = f'Create configuration file at {file_path} or specify valid path'
        
        super().__init__(message, **kwargs)
        
        self.file_path = file_path


class ConfigFileFormatError(ConfigurationError):
    """Exception raised when configuration file format is invalid."""
    
    def __init__(self, file_path: str, format_error: str, **kwargs):
        """Initialize config file format error.
        
        Args:
            file_path: Path to the invalid configuration file
            format_error: Specific format error message
            **kwargs: Additional arguments for base class
        """
        message = f"Invalid configuration file format in {file_path}: {format_error}"
        
        details = kwargs.get('details', {})
        details.update({
            'file_path': file_path,
            'format_error': format_error
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'CONFIG_FORMAT_ERROR'
        kwargs['suggestion'] = 'Check YAML syntax and structure in configuration file'
        
        super().__init__(message, **kwargs)
        
        self.file_path = file_path
        self.format_error = format_error


class MissingRequiredConfigError(ConfigurationError):
    """Exception raised when required configuration is missing."""
    
    def __init__(self, required_keys: List[str], **kwargs):
        """Initialize missing required config error.
        
        Args:
            required_keys: List of missing required configuration keys
            **kwargs: Additional arguments for base class
        """
        if len(required_keys) == 1:
            message = f"Missing required configuration: {required_keys[0]}"
        else:
            message = f"Missing required configurations: {', '.join(required_keys)}"
        
        details = kwargs.get('details', {})
        details['required_keys'] = required_keys
        
        kwargs['details'] = details
        kwargs['error_code'] = 'MISSING_REQUIRED_CONFIG'
        kwargs['suggestion'] = 'Add the required configuration keys to your config file'
        
        super().__init__(message, **kwargs)
        
        self.required_keys = required_keys