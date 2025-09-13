"""Security-related exception classes."""

from typing import Optional, Dict, Any
from .base_exceptions import VulnMinerException, VulnMinerError


class SecurityError(VulnMinerError):
    """Base class for security-related errors."""
    
    def __init__(self, message: str, **kwargs):
        """Initialize security error.
        
        Args:
            message: Error message
            **kwargs: Additional arguments for base class
        """
        kwargs['error_code'] = kwargs.get('error_code', 'SECURITY_ERROR')
        super().__init__(message, **kwargs)


class AuthorizationError(SecurityError):
    """Exception raised for authorization failures."""
    
    def __init__(self, message: str, resource: Optional[str] = None,
                 user: Optional[str] = None, **kwargs):
        """Initialize authorization error.
        
        Args:
            message: Error message
            resource: Resource that access was denied to
            user: User who was denied access
            **kwargs: Additional arguments for base class
        """
        details = kwargs.get('details', {})
        if resource:
            details['resource'] = resource
        if user:
            details['user'] = user
        
        kwargs['details'] = details
        kwargs['error_code'] = 'AUTHORIZATION_ERROR'
        kwargs['suggestion'] = 'Check authorization policies and user permissions'
        
        super().__init__(message, **kwargs)
        
        self.resource = resource
        self.user = user


class UnauthorizedTargetError(SecurityError):
    """Exception raised when trying to scan unauthorized target."""
    
    def __init__(self, target: str, **kwargs):
        """Initialize unauthorized target error.
        
        Args:
            target: Target that was not authorized
            **kwargs: Additional arguments for base class
        """
        message = f"Target '{target}' is not authorized for scanning"
        
        details = kwargs.get('details', {})
        details['target'] = target
        
        kwargs['details'] = details
        kwargs['error_code'] = 'UNAUTHORIZED_TARGET'
        kwargs['suggestion'] = 'Add target to authorized whitelist or check authorization policies'
        
        super().__init__(message, **kwargs)
        
        self.target = target


class RateLimitExceededError(SecurityError):
    """Exception raised when rate limit is exceeded."""
    
    def __init__(self, limit_type: str, current_count: int, max_allowed: int,
                 reset_time: Optional[float] = None, target: Optional[str] = None,
                 **kwargs):
        """Initialize rate limit exceeded error.
        
        Args:
            limit_type: Type of rate limit (global, target, user)
            current_count: Current request count
            max_allowed: Maximum allowed requests
            reset_time: When rate limit will reset (timestamp)
            target: Target that triggered rate limit
            **kwargs: Additional arguments for base class
        """
        message = f"{limit_type.title()} rate limit exceeded: {current_count}/{max_allowed} requests"
        
        details = kwargs.get('details', {})
        details.update({
            'limit_type': limit_type,
            'current_count': current_count,
            'max_allowed': max_allowed,
            'reset_time': reset_time,
        })
        if target:
            details['target'] = target
        
        kwargs['details'] = details
        kwargs['error_code'] = 'RATE_LIMIT_EXCEEDED'
        
        if reset_time:
            kwargs['suggestion'] = f'Wait until rate limit resets at {reset_time} or reduce request frequency'
        else:
            kwargs['suggestion'] = 'Reduce request frequency or wait for rate limit window to reset'
        
        super().__init__(message, **kwargs)
        
        self.limit_type = limit_type
        self.current_count = current_count
        self.max_allowed = max_allowed
        self.reset_time = reset_time
        self.target = target


class InvalidCredentialsError(SecurityError):
    """Exception raised for invalid authentication credentials."""
    
    def __init__(self, credential_type: str, **kwargs):
        """Initialize invalid credentials error.
        
        Args:
            credential_type: Type of credential that was invalid
            **kwargs: Additional arguments for base class
        """
        message = f"Invalid {credential_type} credentials provided"
        
        details = kwargs.get('details', {})
        details['credential_type'] = credential_type
        
        kwargs['details'] = details
        kwargs['error_code'] = 'INVALID_CREDENTIALS'
        kwargs['suggestion'] = f'Check and update {credential_type} credentials'
        
        super().__init__(message, **kwargs)
        
        self.credential_type = credential_type


class SecurityPolicyViolationError(SecurityError):
    """Exception raised when security policy is violated."""
    
    def __init__(self, policy: str, violation_reason: str, **kwargs):
        """Initialize security policy violation error.
        
        Args:
            policy: Name of the security policy that was violated
            violation_reason: Reason why policy was violated
            **kwargs: Additional arguments for base class
        """
        message = f"Security policy '{policy}' violation: {violation_reason}"
        
        details = kwargs.get('details', {})
        details.update({
            'policy': policy,
            'violation_reason': violation_reason
        })
        
        kwargs['details'] = details
        kwargs['error_code'] = 'SECURITY_POLICY_VIOLATION'
        kwargs['suggestion'] = f'Review security policy requirements for {policy}'
        
        super().__init__(message, **kwargs)
        
        self.policy = policy
        self.violation_reason = violation_reason


class CryptographyError(SecurityError):
    """Exception raised for cryptographic operation failures."""
    
    def __init__(self, operation: str, **kwargs):
        """Initialize cryptography error.
        
        Args:
            operation: Cryptographic operation that failed
            **kwargs: Additional arguments for base class
        """
        message = f"Cryptographic operation failed: {operation}"
        
        details = kwargs.get('details', {})
        details['operation'] = operation
        
        kwargs['details'] = details
        kwargs['error_code'] = 'CRYPTOGRAPHY_ERROR'
        kwargs['suggestion'] = 'Check cryptographic keys and algorithms'
        
        super().__init__(message, **kwargs)
        
        self.operation = operation