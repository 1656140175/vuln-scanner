"""Progress management system for vulnerability scanning."""

from .models import (
    TaskStatus,
    ProgressState,
    PhaseProgress,
    ProgressError,
    CheckpointInfo,
    QueueStatus,
    PhaseTimingData,
    HealthStatus,
    ResourceMetrics
)
from .manager import ProgressManager
from .events import ProgressEvent, ProgressEventBus, ProgressEventEmitter
from .queue import TaskQueue, ScanConfig, TaskPriority
from .estimator import ProgressEstimator, ComplexityMetrics
from .monitor import ProgressMonitor
from .checkpoint import CheckpointManager
from .websocket import ProgressWebSocketManager
from .api import ProgressAPI
from .cli import ProgressCLI

__all__ = [
    # Models
    'TaskStatus',
    'ProgressState', 
    'PhaseProgress',
    'ProgressError',
    'CheckpointInfo',
    'QueueStatus',
    'PhaseTimingData',
    'HealthStatus',
    'ResourceMetrics',
    
    # Core components
    'ProgressManager',
    'ProgressEvent',
    'ProgressEventBus',
    'ProgressEventEmitter',
    'TaskQueue',
    'ScanConfig',
    'TaskPriority',
    'ProgressEstimator',
    'ComplexityMetrics',
    'ProgressMonitor',
    'CheckpointManager',
    'ProgressWebSocketManager',
    'ProgressAPI',
    'ProgressCLI'
]

__version__ = '1.0.0'
__description__ = 'Comprehensive progress management system for vulnerability scanning'