"""System-related exception classes."""

from typing import Optional, Dict, Any
from .base_exceptions import VulnMinerException, VulnMinerError, VulnMinerCriticalError


class SystemError(VulnMinerError):
    """Base class for system-related errors."""
    
    def __init__(self, message: str, **kwargs):
        """Initialize system error.
        
        Args:
            message: Error message
            **kwargs: Additional arguments for base class
        """
        kwargs['error_code'] = kwargs.get('error_code', 'SYSTEM_ERROR')
        super().__init__(message, **kwargs)


class ResourceNotFoundError(SystemError):
    """Exception raised when required resource is not found."""
    
    def __init__(self, resource_type: str, resource_identifier: str, **kwargs):
        """Initialize resource not found error.
        
        Args:
            resource_type: Type of resource (file, directory, service, etc.)
            resource_identifier: Identifier for the resource (path, name, etc.)
            **kwargs: Additional arguments for base class
        """
        message = f"{resource_type.title()} not found: {resource_identifier}"
        
        details = kwargs.get('details', {})
        details.update({
            'resource_type': resource_type,
            'resource_identifier': resource_identifier
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'RESOURCE_NOT_FOUND'
        kwargs['suggestion'] = f'Check if {resource_type} exists and is accessible'
        
        super().__init__(message, **kwargs)
        
        self.resource_type = resource_type
        self.resource_identifier = resource_identifier


class ResourceExhaustionError(SystemError):
    """Exception raised when system resources are exhausted."""
    
    def __init__(self, resource_type: str, current_usage: Optional[float] = None,
                 limit: Optional[float] = None, **kwargs):
        """Initialize resource exhaustion error.
        
        Args:
            resource_type: Type of resource (memory, disk, CPU, etc.)
            current_usage: Current resource usage
            limit: Resource limit
            **kwargs: Additional arguments for base class
        """
        message = f"{resource_type.title()} resources exhausted"
        if current_usage is not None and limit is not None:
            message += f": {current_usage}/{limit}"
        
        details = kwargs.get('details', {})
        details.update({
            'resource_type': resource_type,
            'current_usage': current_usage,
            'limit': limit
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'RESOURCE_EXHAUSTION'
        kwargs['suggestion'] = f'Free up {resource_type} resources or increase limits'
        
        super().__init__(message, **kwargs)
        
        self.resource_type = resource_type
        self.current_usage = current_usage
        self.limit = limit


class DatabaseError(SystemError):
    """Exception raised for database-related errors."""
    
    def __init__(self, operation: str, database_error: Optional[str] = None,
                 **kwargs):
        """Initialize database error.
        
        Args:
            operation: Database operation that failed
            database_error: Specific database error message
            **kwargs: Additional arguments for base class
        """
        message = f"Database operation failed: {operation}"
        if database_error:
            message += f" - {database_error}"
        
        details = kwargs.get('details', {})
        details.update({
            'operation': operation,
            'database_error': database_error
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'DATABASE_ERROR'
        kwargs['suggestion'] = 'Check database connection and operation parameters'
        
        super().__init__(message, **kwargs)
        
        self.operation = operation
        self.database_error = database_error


class FileSystemError(SystemError):
    """Exception raised for file system related errors."""
    
    def __init__(self, operation: str, file_path: str, 
                 system_error: Optional[str] = None, **kwargs):
        """Initialize file system error.
        
        Args:
            operation: File system operation that failed
            file_path: Path involved in the operation
            system_error: System error message
            **kwargs: Additional arguments for base class
        """
        message = f"File system operation '{operation}' failed for path: {file_path}"
        if system_error:
            message += f" - {system_error}"
        
        details = kwargs.get('details', {})
        details.update({
            'operation': operation,
            'file_path': file_path,
            'system_error': system_error
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'FILESYSTEM_ERROR'
        kwargs['suggestion'] = 'Check file permissions and disk space'
        
        super().__init__(message, **kwargs)
        
        self.operation = operation
        self.file_path = file_path
        self.system_error = system_error


class NetworkError(SystemError):
    """Exception raised for network-related errors."""
    
    def __init__(self, operation: str, endpoint: Optional[str] = None,
                 network_error: Optional[str] = None, **kwargs):
        """Initialize network error.
        
        Args:
            operation: Network operation that failed
            endpoint: Network endpoint involved
            network_error: Specific network error message
            **kwargs: Additional arguments for base class
        """
        message = f"Network operation '{operation}' failed"
        if endpoint:
            message += f" for endpoint: {endpoint}"
        if network_error:
            message += f" - {network_error}"
        
        details = kwargs.get('details', {})
        details.update({
            'operation': operation,
            'endpoint': endpoint,
            'network_error': network_error
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'NETWORK_ERROR'
        kwargs['suggestion'] = 'Check network connectivity and endpoint availability'
        
        super().__init__(message, **kwargs)
        
        self.operation = operation
        self.endpoint = endpoint
        self.network_error = network_error


class ProcessError(SystemError):
    """Exception raised for process execution errors."""
    
    def __init__(self, command: str, exit_code: Optional[int] = None,
                 process_error: Optional[str] = None, **kwargs):
        """Initialize process error.
        
        Args:
            command: Command that failed to execute
            exit_code: Process exit code
            process_error: Process error message
            **kwargs: Additional arguments for base class
        """
        message = f"Process execution failed: {command}"
        if exit_code is not None:
            message += f" (exit code: {exit_code})"
        if process_error:
            message += f" - {process_error}"
        
        details = kwargs.get('details', {})
        details.update({
            'command': command,
            'exit_code': exit_code,
            'process_error': process_error
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'PROCESS_ERROR'
        kwargs['suggestion'] = 'Check command syntax and system environment'
        
        super().__init__(message, **kwargs)
        
        self.command = command
        self.exit_code = exit_code
        self.process_error = process_error


class DependencyError(VulnMinerCriticalError):
    """Exception raised when critical dependency is missing or incompatible."""
    
    def __init__(self, dependency: str, required_version: Optional[str] = None,
                 current_version: Optional[str] = None, **kwargs):
        """Initialize dependency error.
        
        Args:
            dependency: Name of the missing or incompatible dependency
            required_version: Required version of the dependency
            current_version: Current installed version
            **kwargs: Additional arguments for base class
        """
        message = f"Dependency error: {dependency}"
        if required_version:
            message += f" (required: {required_version}"
            if current_version:
                message += f", current: {current_version}"
            message += ")"
        
        details = kwargs.get('details', {})
        details.update({
            'dependency': dependency,
            'required_version': required_version,
            'current_version': current_version
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'DEPENDENCY_ERROR'
        kwargs['suggestion'] = f'Install or update {dependency} to required version'
        
        super().__init__(message, **kwargs)
        
        self.dependency = dependency
        self.required_version = required_version
        self.current_version = current_version