"""Platform integration main module."""

from .manager import PlatformManager
from .models import (
    PlatformSubmissionData,
    PlatformReportStatus,
    PlatformReward,
    PlatformCredentials,
    PlatformConfig,
    SubmissionResult,
    StatusCheckResult,
    RewardInfo,
    PlatformError,
    PlatformType
)
from .connectors import (
    PlatformConnector,
    HackerOneConnector,
    BugcrowdConnector,
    IntigritiConnector,
    OpenBugBountyConnector
)

__all__ = [
    # Core manager
    'PlatformManager',
    
    # Data models
    'PlatformSubmissionData',
    'PlatformReportStatus', 
    'PlatformReward',
    'PlatformCredentials',
    'PlatformConfig',
    'SubmissionResult',
    'StatusCheckResult',
    'RewardInfo',
    'PlatformError',
    'PlatformType',
    
    # Connectors
    'PlatformConnector',
    'HackerOneConnector',
    'BugcrowdConnector',
    'IntigritiConnector',
    'OpenBugBountyConnector'
]