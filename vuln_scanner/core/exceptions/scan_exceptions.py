"""Scan-related exception classes."""

from typing import Optional, Dict, Any, List
from .base_exceptions import VulnMinerException, VulnMinerError


class ScanError(VulnMinerError):
    """Base class for scan-related errors."""
    
    def __init__(self, message: str, target: Optional[str] = None,
                 scan_type: Optional[str] = None, **kwargs):
        """Initialize scan error.
        
        Args:
            message: Error message
            target: Target that was being scanned
            scan_type: Type of scan that failed
            **kwargs: Additional arguments for base class
        """
        details = kwargs.get('details', {})
        if target:
            details['target'] = target
        if scan_type:
            details['scan_type'] = scan_type
        
        kwargs['details'] = details
        kwargs['error_code'] = kwargs.get('error_code', 'SCAN_ERROR')
        
        super().__init__(message, **kwargs)
        
        self.target = target
        self.scan_type = scan_type


class ScanTimeoutError(ScanError):
    """Exception raised when scan operation times out."""
    
    def __init__(self, timeout_seconds: int, **kwargs):
        """Initialize scan timeout error.
        
        Args:
            timeout_seconds: Timeout value in seconds
            **kwargs: Additional arguments for base class
        """
        message = f"Scan operation timed out after {timeout_seconds} seconds"
        
        details = kwargs.get('details', {})
        details['timeout_seconds'] = timeout_seconds
        
        kwargs['details'] = details
        kwargs['error_code'] = 'SCAN_TIMEOUT'
        kwargs['suggestion'] = 'Increase timeout value or optimize scan parameters'
        
        super().__init__(message, **kwargs)
        
        self.timeout_seconds = timeout_seconds


class ToolNotFoundError(ScanError):
    """Exception raised when required security tool is not found."""
    
    def __init__(self, tool_name: str, expected_path: Optional[str] = None,
                 **kwargs):
        """Initialize tool not found error.
        
        Args:
            tool_name: Name of the missing tool
            expected_path: Expected path where tool should be located
            **kwargs: Additional arguments for base class
        """
        message = f"Security tool '{tool_name}' not found"
        if expected_path:
            message += f" at expected path: {expected_path}"
        
        details = kwargs.get('details', {})
        details['tool_name'] = tool_name
        if expected_path:
            details['expected_path'] = expected_path
        
        kwargs['details'] = details
        kwargs['error_code'] = 'TOOL_NOT_FOUND'
        kwargs['suggestion'] = f'Install {tool_name} or update tool path in configuration'
        
        super().__init__(message, **kwargs)
        
        self.tool_name = tool_name
        self.expected_path = expected_path


class ToolExecutionError(ScanError):
    """Exception raised when security tool execution fails."""
    
    def __init__(self, tool_name: str, exit_code: int, command: Optional[str] = None,
                 stdout: Optional[str] = None, stderr: Optional[str] = None,
                 **kwargs):
        """Initialize tool execution error.
        
        Args:
            tool_name: Name of the tool that failed
            exit_code: Exit code returned by the tool
            command: Command that was executed
            stdout: Standard output from the tool
            stderr: Standard error from the tool
            **kwargs: Additional arguments for base class
        """
        message = f"Tool '{tool_name}' execution failed with exit code {exit_code}"
        
        details = kwargs.get('details', {})
        details.update({
            'tool_name': tool_name,
            'exit_code': exit_code,
            'command': command,
            'stdout': stdout,
            'stderr': stderr,
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'TOOL_EXECUTION_ERROR'
        kwargs['suggestion'] = f'Check {tool_name} installation and command parameters'
        
        super().__init__(message, **kwargs)
        
        self.tool_name = tool_name
        self.exit_code = exit_code
        self.command = command
        self.stdout = stdout
        self.stderr = stderr


class InvalidTargetError(ScanError):
    """Exception raised when target format is invalid."""
    
    def __init__(self, target: str, reason: str, **kwargs):
        """Initialize invalid target error.
        
        Args:
            target: Invalid target
            reason: Reason why target is invalid
            **kwargs: Additional arguments for base class
        """
        message = f"Invalid target '{target}': {reason}"
        
        details = kwargs.get('details', {})
        details.update({
            'target': target,
            'reason': reason
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'INVALID_TARGET'
        kwargs['suggestion'] = 'Check target format (should be valid IP, domain, or URL)'
        
        super().__init__(message, **kwargs)
        
        self.reason = reason


class ScanConfigurationError(ScanError):
    """Exception raised when scan configuration is invalid."""
    
    def __init__(self, config_errors: List[str], **kwargs):
        """Initialize scan configuration error.
        
        Args:
            config_errors: List of configuration error messages
            **kwargs: Additional arguments for base class
        """
        message = f"Invalid scan configuration: {'; '.join(config_errors)}"
        
        details = kwargs.get('details', {})
        details['config_errors'] = config_errors
        
        kwargs['details'] = details
        kwargs['error_code'] = 'SCAN_CONFIG_ERROR'
        kwargs['suggestion'] = 'Fix scan configuration parameters'
        
        super().__init__(message, **kwargs)
        
        self.config_errors = config_errors


class ScanInterruptedError(ScanError):
    """Exception raised when scan is interrupted."""
    
    def __init__(self, reason: str, **kwargs):
        """Initialize scan interrupted error.
        
        Args:
            reason: Reason why scan was interrupted
            **kwargs: Additional arguments for base class
        """
        message = f"Scan was interrupted: {reason}"
        
        details = kwargs.get('details', {})
        details['reason'] = reason
        
        kwargs['details'] = details
        kwargs['error_code'] = 'SCAN_INTERRUPTED'
        kwargs['suggestion'] = 'Check system resources and scan parameters'
        
        super().__init__(message, **kwargs)
        
        self.reason = reason


class ScanResultParseError(ScanError):
    """Exception raised when scan result parsing fails."""
    
    def __init__(self, tool_name: str, parse_error: str, 
                 raw_output: Optional[str] = None, **kwargs):
        """Initialize scan result parse error.
        
        Args:
            tool_name: Name of tool whose output failed to parse
            parse_error: Specific parsing error
            raw_output: Raw output that failed to parse
            **kwargs: Additional arguments for base class
        """
        message = f"Failed to parse {tool_name} output: {parse_error}"
        
        details = kwargs.get('details', {})
        details.update({
            'tool_name': tool_name,
            'parse_error': parse_error,
            'raw_output': raw_output
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'SCAN_RESULT_PARSE_ERROR'
        kwargs['suggestion'] = f'Check {tool_name} output format and parsing logic'
        
        super().__init__(message, **kwargs)
        
        self.parse_error = parse_error
        self.raw_output = raw_output


class ScanEngineException(ScanError):
    """Base exception for scan engine specific errors."""
    
    def __init__(self, message: str, **kwargs):
        """Initialize scan engine exception.
        
        Args:
            message: Error message
            **kwargs: Additional arguments for base class
        """
        kwargs['error_code'] = kwargs.get('error_code', 'SCAN_ENGINE_ERROR')
        super().__init__(message, **kwargs)


class UnauthorizedTargetException(ScanEngineException):
    """Exception raised when target is not authorized for scanning."""
    
    def __init__(self, target: str, validation_info: Optional[Dict[str, Any]] = None, **kwargs):
        """Initialize unauthorized target exception.
        
        Args:
            target: Unauthorized target
            validation_info: Security validation information
            **kwargs: Additional arguments for base class
        """
        message = f"Target '{target}' is not authorized for scanning"
        
        details = kwargs.get('details', {})
        details['target'] = target
        if validation_info:
            details['validation_info'] = validation_info
        
        kwargs['details'] = details
        kwargs['error_code'] = 'UNAUTHORIZED_TARGET'
        kwargs['suggestion'] = 'Add target to authorized whitelist or check security policies'
        
        super().__init__(message, **kwargs)
        
        self.validation_info = validation_info


class PipelineConfigurationError(ScanEngineException):
    """Exception raised when scan pipeline configuration is invalid."""
    
    def __init__(self, pipeline_name: str, error_details: str, **kwargs):
        """Initialize pipeline configuration error.
        
        Args:
            pipeline_name: Name of the invalid pipeline
            error_details: Details about the configuration error
            **kwargs: Additional arguments for base class
        """
        message = f"Pipeline '{pipeline_name}' configuration error: {error_details}"
        
        details = kwargs.get('details', {})
        details.update({
            'pipeline_name': pipeline_name,
            'error_details': error_details
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'PIPELINE_CONFIG_ERROR'
        kwargs['suggestion'] = f'Fix configuration for pipeline {pipeline_name}'
        
        super().__init__(message, **kwargs)
        
        self.pipeline_name = pipeline_name
        self.error_details = error_details


class ScanJobError(ScanEngineException):
    """Exception raised for scan job related errors."""
    
    def __init__(self, job_id: str, error_details: str, **kwargs):
        """Initialize scan job error.
        
        Args:
            job_id: ID of the scan job
            error_details: Details about the job error
            **kwargs: Additional arguments for base class
        """
        message = f"Scan job '{job_id}' error: {error_details}"
        
        details = kwargs.get('details', {})
        details.update({
            'job_id': job_id,
            'error_details': error_details
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'SCAN_JOB_ERROR'
        
        super().__init__(message, **kwargs)
        
        self.job_id = job_id
        self.error_details = error_details


class ResultAggregationError(ScanEngineException):
    """Exception raised when result aggregation fails."""
    
    def __init__(self, aggregation_stage: str, error_details: str, **kwargs):
        """Initialize result aggregation error.
        
        Args:
            aggregation_stage: Stage where aggregation failed
            error_details: Details about the aggregation error
            **kwargs: Additional arguments for base class
        """
        message = f"Result aggregation failed at stage '{aggregation_stage}': {error_details}"
        
        details = kwargs.get('details', {})
        details.update({
            'aggregation_stage': aggregation_stage,
            'error_details': error_details
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'RESULT_AGGREGATION_ERROR'
        
        super().__init__(message, **kwargs)
        
        self.aggregation_stage = aggregation_stage
        self.error_details = error_details