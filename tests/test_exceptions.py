"""Tests for exception classes."""

import pytest

from vuln_scanner.core.exceptions import (
    VulnMinerException, VulnMinerError, VulnMinerCriticalError,
    ConfigurationError, ConfigValidationError, ConfigFileNotFoundError,
    SecurityError, UnauthorizedTargetError, RateLimitExceededError,
    ScanError, ScanTimeoutError, ToolNotFoundError, ToolExecutionError,
    SystemError, ResourceNotFoundError, DatabaseError
)


class TestBaseExceptions:
    """Test cases for base exception classes."""
    
    def test_vulnminer_exception_basic(self):
        """Test basic VulnMinerException functionality."""
        exc = VulnMinerException("Test message")
        
        assert str(exc) == "Test message"
        assert exc.message == "Test message"
        assert exc.error_code is None
        assert exc.details == {}
        assert exc.suggestion is None
    
    def test_vulnminer_exception_with_all_params(self):
        """Test VulnMinerException with all parameters."""
        details = {'key': 'value', 'number': 42}
        exc = VulnMinerException(
            "Test message",
            error_code="TEST_ERROR",
            details=details,
            suggestion="Try this fix"
        )
        
        assert exc.message == "Test message"
        assert exc.error_code == "TEST_ERROR"
        assert exc.details == details
        assert exc.suggestion == "Try this fix"
        assert str(exc) == "Test message. Suggestion: Try this fix"
    
    def test_to_dict(self):
        """Test exception to_dict conversion."""
        exc = VulnMinerException(
            "Test message",
            error_code="TEST_ERROR",
            details={'key': 'value'},
            suggestion="Fix suggestion"
        )
        
        result = exc.to_dict()
        
        expected = {
            'exception_type': 'VulnMinerException',
            'message': 'Test message',
            'error_code': 'TEST_ERROR',
            'details': {'key': 'value'},
            'suggestion': 'Fix suggestion'
        }
        
        assert result == expected
    
    def test_inheritance(self):
        """Test exception inheritance."""
        error = VulnMinerError("Error message")
        critical = VulnMinerCriticalError("Critical error")
        
        assert isinstance(error, VulnMinerException)
        assert isinstance(critical, VulnMinerException)
        
        assert isinstance(error, Exception)
        assert isinstance(critical, Exception)


class TestConfigurationExceptions:
    """Test cases for configuration-related exceptions."""
    
    def test_configuration_error(self):
        """Test ConfigurationError."""
        exc = ConfigurationError(
            "Config error",
            config_section="system",
            config_key="debug"
        )
        
        assert exc.message == "Config error"
        assert exc.config_section == "system"
        assert exc.config_key == "debug"
        assert exc.error_code == "CONFIG_ERROR"
        assert exc.details['config_section'] == "system"
        assert exc.details['config_key'] == "debug"
    
    def test_config_validation_error(self):
        """Test ConfigValidationError."""
        errors = ["Error 1", "Error 2", "Error 3"]
        exc = ConfigValidationError(errors)
        
        assert "Configuration validation failed with 3 errors" in exc.message
        assert exc.validation_errors == errors
        assert exc.error_code == "CONFIG_VALIDATION_ERROR"
        assert exc.details['validation_errors'] == errors
    
    def test_config_file_not_found_error(self):
        """Test ConfigFileNotFoundError."""
        file_path = "/path/to/config.yml"
        exc = ConfigFileNotFoundError(file_path)
        
        assert f"Configuration file not found: {file_path}" in exc.message
        assert exc.file_path == file_path
        assert exc.error_code == "CONFIG_FILE_NOT_FOUND"
        assert "Create configuration file" in exc.suggestion


class TestSecurityExceptions:
    """Test cases for security-related exceptions."""
    
    def test_security_error(self):
        """Test base SecurityError."""
        exc = SecurityError("Security error")
        
        assert exc.message == "Security error"
        assert exc.error_code == "SECURITY_ERROR"
        assert isinstance(exc, VulnMinerError)
    
    def test_unauthorized_target_error(self):
        """Test UnauthorizedTargetError."""
        target = "unauthorized.com"
        exc = UnauthorizedTargetError(target)
        
        assert target in exc.message
        assert exc.target == target
        assert exc.error_code == "UNAUTHORIZED_TARGET"
        assert exc.details['target'] == target
        assert "Add target to authorized whitelist" in exc.suggestion
    
    def test_rate_limit_exceeded_error(self):
        """Test RateLimitExceededError."""
        exc = RateLimitExceededError(
            limit_type="global",
            current_count=11,
            max_allowed=10,
            reset_time=1234567890.0,
            target="example.com"
        )
        
        assert "Global rate limit exceeded: 11/10" in exc.message
        assert exc.limit_type == "global"
        assert exc.current_count == 11
        assert exc.max_allowed == 10
        assert exc.reset_time == 1234567890.0
        assert exc.target == "example.com"
        assert exc.error_code == "RATE_LIMIT_EXCEEDED"


class TestScanExceptions:
    """Test cases for scan-related exceptions."""
    
    def test_scan_error(self):
        """Test base ScanError."""
        exc = ScanError(
            "Scan failed",
            target="example.com",
            scan_type="nmap"
        )
        
        assert exc.message == "Scan failed"
        assert exc.target == "example.com"
        assert exc.scan_type == "nmap"
        assert exc.error_code == "SCAN_ERROR"
    
    def test_scan_timeout_error(self):
        """Test ScanTimeoutError."""
        exc = ScanTimeoutError(300)
        
        assert "timed out after 300 seconds" in exc.message
        assert exc.timeout_seconds == 300
        assert exc.error_code == "SCAN_TIMEOUT"
        assert "Increase timeout value" in exc.suggestion
    
    def test_tool_not_found_error(self):
        """Test ToolNotFoundError."""
        exc = ToolNotFoundError(
            "nmap",
            expected_path="/usr/bin/nmap"
        )
        
        assert "Security tool 'nmap' not found" in exc.message
        assert "at expected path: /usr/bin/nmap" in exc.message
        assert exc.tool_name == "nmap"
        assert exc.expected_path == "/usr/bin/nmap"
        assert exc.error_code == "TOOL_NOT_FOUND"
        assert "Install nmap" in exc.suggestion
    
    def test_tool_execution_error(self):
        """Test ToolExecutionError."""
        exc = ToolExecutionError(
            tool_name="nmap",
            exit_code=1,
            command="nmap -sS example.com",
            stdout="Some output",
            stderr="Error output"
        )
        
        assert "Tool 'nmap' execution failed with exit code 1" in exc.message
        assert exc.tool_name == "nmap"
        assert exc.exit_code == 1
        assert exc.command == "nmap -sS example.com"
        assert exc.stdout == "Some output"
        assert exc.stderr == "Error output"
        assert exc.error_code == "TOOL_EXECUTION_ERROR"


class TestSystemExceptions:
    """Test cases for system-related exceptions."""
    
    def test_system_error(self):
        """Test base SystemError."""
        exc = SystemError("System error")
        
        assert exc.message == "System error"
        assert exc.error_code == "SYSTEM_ERROR"
        assert isinstance(exc, VulnMinerError)
    
    def test_resource_not_found_error(self):
        """Test ResourceNotFoundError."""
        exc = ResourceNotFoundError("file", "/path/to/file.txt")
        
        assert "File not found: /path/to/file.txt" in exc.message
        assert exc.resource_type == "file"
        assert exc.resource_identifier == "/path/to/file.txt"
        assert exc.error_code == "RESOURCE_NOT_FOUND"
        assert "Check if file exists" in exc.suggestion
    
    def test_database_error(self):
        """Test DatabaseError."""
        exc = DatabaseError(
            operation="SELECT",
            database_error="Connection failed"
        )
        
        assert "Database operation failed: SELECT" in exc.message
        assert "Connection failed" in exc.message
        assert exc.operation == "SELECT"
        assert exc.database_error == "Connection failed"
        assert exc.error_code == "DATABASE_ERROR"
        assert "Check database connection" in exc.suggestion
    
    def test_exception_chaining(self):
        """Test exception chaining and context preservation."""
        try:
            try:
                raise ValueError("Original error")
            except ValueError as e:
                raise DatabaseError("Database operation failed") from e
        except DatabaseError as db_error:
            assert db_error.__cause__ is not None
            assert isinstance(db_error.__cause__, ValueError)
            assert str(db_error.__cause__) == "Original error"


class TestExceptionHierarchy:
    """Test exception hierarchy and relationships."""
    
    def test_exception_hierarchy(self):
        """Test that all exceptions follow proper hierarchy."""
        # All exceptions should inherit from VulnMinerException
        exceptions_to_test = [
            ConfigurationError,
            SecurityError,
            ScanError,
            SystemError
        ]
        
        for exc_class in exceptions_to_test:
            exc = exc_class("test message")
            assert isinstance(exc, VulnMinerException)
            assert isinstance(exc, Exception)
    
    def test_error_vs_critical_distinction(self):
        """Test distinction between errors and critical errors."""
        error = VulnMinerError("Recoverable error")
        critical = VulnMinerCriticalError("Critical error")
        
        assert isinstance(error, VulnMinerException)
        assert isinstance(critical, VulnMinerException)
        
        # They should be different classes
        assert type(error) != type(critical)
    
    def test_specific_exception_inheritance(self):
        """Test specific exception class inheritance."""
        # Configuration exceptions
        config_exc = ConfigurationError("config error")
        assert isinstance(config_exc, VulnMinerError)
        
        # Security exceptions
        security_exc = SecurityError("security error")
        assert isinstance(security_exc, VulnMinerError)
        
        # Scan exceptions
        scan_exc = ScanError("scan error")
        assert isinstance(scan_exc, VulnMinerError)
        
        # System exceptions
        system_exc = SystemError("system error")
        assert isinstance(system_exc, VulnMinerError)
    
    def test_exception_error_codes(self):
        """Test that exceptions have appropriate error codes."""
        test_cases = [
            (ConfigurationError("test"), "CONFIG_ERROR"),
            (UnauthorizedTargetError("target"), "UNAUTHORIZED_TARGET"),
            (RateLimitExceededError("global", 5, 4), "RATE_LIMIT_EXCEEDED"),
            (ScanTimeoutError(300), "SCAN_TIMEOUT"),
            (ToolNotFoundError("nmap"), "TOOL_NOT_FOUND"),
            (ResourceNotFoundError("file", "path"), "RESOURCE_NOT_FOUND"),
            (DatabaseError("SELECT"), "DATABASE_ERROR")
        ]
        
        for exc, expected_code in test_cases:
            assert exc.error_code == expected_code
    
    def test_exception_suggestions(self):
        """Test that exceptions provide helpful suggestions."""
        exceptions_with_suggestions = [
            ConfigValidationError(["error1"]),
            UnauthorizedTargetError("target"),
            RateLimitExceededError("global", 5, 4),
            ScanTimeoutError(300),
            ToolNotFoundError("nmap"),
            ResourceNotFoundError("file", "path"),
            DatabaseError("SELECT")
        ]
        
        for exc in exceptions_with_suggestions:
            assert exc.suggestion is not None
            assert len(exc.suggestion) > 0