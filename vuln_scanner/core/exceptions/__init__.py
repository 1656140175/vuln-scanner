"""Exception classes for VulnMiner system."""

from .base_exceptions import VulnMinerException, VulnMinerError
from .config_exceptions import ConfigurationError, ConfigValidationError
from .security_exceptions import (
    SecurityError, UnauthorizedTargetError, RateLimitExceededError,
    AuthorizationError
)
from .scan_exceptions import (
    ScanError, ScanTimeoutError, ToolNotFoundError, ToolExecutionError,
    InvalidTargetError
)
from .system_exceptions import (
    SystemError, ResourceNotFoundError, ResourceExhaustionError,
    DatabaseError
)

__all__ = [
    'VulnMinerException', 'VulnMinerError',
    'ConfigurationError', 'ConfigValidationError',
    'SecurityError', 'UnauthorizedTargetError', 'RateLimitExceededError',
    'AuthorizationError',
    'ScanError', 'ScanTimeoutError', 'ToolNotFoundError', 'ToolExecutionError',
    'InvalidTargetError',
    'SystemError', 'ResourceNotFoundError', 'ResourceExhaustionError',
    'DatabaseError'
]