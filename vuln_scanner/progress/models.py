"""Core data models for the progress management system."""

import uuid
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field, asdict
from enum import Enum

from ..core.scanning.data_structures import ScanPhase


class TaskStatus(Enum):
    """Task execution status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ProgressError:
    """Progress-related error information."""
    error_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    phase: Optional[ScanPhase] = None
    error_type: str = "unknown"
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    recoverable: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        if self.phase:
            data['phase'] = self.phase.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProgressError':
        """Create from dictionary."""
        data = data.copy()
        if 'timestamp' in data:
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        if 'phase' in data and data['phase']:
            data['phase'] = ScanPhase(data['phase'])
        return cls(**data)


@dataclass
class PhaseProgress:
    """Progress information for a specific scan phase."""
    phase: ScanPhase
    status: TaskStatus = TaskStatus.PENDING
    progress_percentage: float = 0.0
    current_step: str = ""
    total_steps: int = 0
    completed_steps: int = 0
    start_time: Optional[datetime] = None
    estimated_duration: Optional[timedelta] = None
    actual_duration: Optional[timedelta] = None
    errors: List[ProgressError] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def update_progress(self, completed: int, current_step: str = "", 
                       metadata: Optional[Dict[str, Any]] = None) -> None:
        """Update phase progress."""
        self.completed_steps = min(completed, self.total_steps)
        if current_step:
            self.current_step = current_step
        
        if self.total_steps > 0:
            self.progress_percentage = (self.completed_steps / self.total_steps) * 100
        
        if metadata:
            self.metadata.update(metadata)
        
        # Update status based on progress
        if self.completed_steps >= self.total_steps:
            self.status = TaskStatus.COMPLETED
        elif self.completed_steps > 0:
            self.status = TaskStatus.RUNNING
    
    def add_error(self, error: ProgressError) -> None:
        """Add an error to this phase."""
        self.errors.append(error)
        if not error.recoverable:
            self.status = TaskStatus.FAILED
    
    def calculate_estimated_completion(self) -> Optional[datetime]:
        """Calculate estimated completion time."""
        if not self.start_time or self.completed_steps == 0 or self.total_steps == 0:
            return None
            
        elapsed = datetime.now() - self.start_time
        if self.completed_steps == self.total_steps:
            return self.start_time + elapsed
            
        avg_time_per_step = elapsed / self.completed_steps
        remaining_steps = self.total_steps - self.completed_steps
        estimated_remaining = avg_time_per_step * remaining_steps
        
        return datetime.now() + estimated_remaining
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'phase': self.phase.value,
            'status': self.status.value,
            'progress_percentage': self.progress_percentage,
            'current_step': self.current_step,
            'total_steps': self.total_steps,
            'completed_steps': self.completed_steps,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'estimated_duration': self.estimated_duration.total_seconds() if self.estimated_duration else None,
            'actual_duration': self.actual_duration.total_seconds() if self.actual_duration else None,
            'errors': [error.to_dict() for error in self.errors],
            'metadata': self.metadata,
            'estimated_completion': self.calculate_estimated_completion().isoformat() 
                                  if self.calculate_estimated_completion() else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PhaseProgress':
        """Create from dictionary."""
        phase_progress = cls(
            phase=ScanPhase(data['phase']),
            status=TaskStatus(data['status']),
            progress_percentage=data.get('progress_percentage', 0.0),
            current_step=data.get('current_step', ''),
            total_steps=data.get('total_steps', 0),
            completed_steps=data.get('completed_steps', 0),
            metadata=data.get('metadata', {})
        )
        
        if data.get('start_time'):
            phase_progress.start_time = datetime.fromisoformat(data['start_time'])
        
        if data.get('estimated_duration'):
            phase_progress.estimated_duration = timedelta(seconds=data['estimated_duration'])
            
        if data.get('actual_duration'):
            phase_progress.actual_duration = timedelta(seconds=data['actual_duration'])
        
        if data.get('errors'):
            phase_progress.errors = [ProgressError.from_dict(error) for error in data['errors']]
        
        return phase_progress


@dataclass
class ProgressState:
    """Complete progress state for a scanning task."""
    task_id: str
    scan_id: str
    scan_profile: str
    target_info: Dict[str, Any]
    current_phase: Optional[ScanPhase] = None
    phase_progress: Dict[ScanPhase, PhaseProgress] = field(default_factory=dict)
    overall_progress: float = 0.0
    status: TaskStatus = TaskStatus.PENDING
    start_time: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    actual_completion: Optional[datetime] = None
    last_checkpoint: Optional[datetime] = None
    last_update: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize phase progress for all scan phases."""
        if not self.phase_progress:
            for phase in ScanPhase:
                self.phase_progress[phase] = PhaseProgress(phase=phase)
    
    def update_phase_progress(self, phase: ScanPhase, completed: int, 
                            total: int, current_step: str = "",
                            metadata: Optional[Dict[str, Any]] = None) -> None:
        """Update progress for a specific phase."""
        if phase not in self.phase_progress:
            self.phase_progress[phase] = PhaseProgress(phase=phase)
        
        phase_prog = self.phase_progress[phase]
        
        # Set total steps if not already set
        if total > 0 and phase_prog.total_steps != total:
            phase_prog.total_steps = total
        
        # Update phase progress
        phase_prog.update_progress(completed, current_step, metadata)
        
        # Start timing if this is the first update for this phase
        if phase_prog.start_time is None and completed > 0:
            phase_prog.start_time = datetime.now()
        
        # Complete timing if phase is completed
        if phase_prog.status == TaskStatus.COMPLETED and phase_prog.actual_duration is None:
            if phase_prog.start_time:
                phase_prog.actual_duration = datetime.now() - phase_prog.start_time
        
        # Update current phase
        if phase_prog.status == TaskStatus.RUNNING:
            self.current_phase = phase
        
        # Recalculate overall progress
        self._calculate_overall_progress()
        self.last_update = datetime.now()
    
    def set_phase_status(self, phase: ScanPhase, status: TaskStatus,
                        error: Optional[ProgressError] = None) -> None:
        """Set status for a specific phase."""
        if phase not in self.phase_progress:
            self.phase_progress[phase] = PhaseProgress(phase=phase)
        
        phase_prog = self.phase_progress[phase]
        phase_prog.status = status
        
        if error:
            phase_prog.add_error(error)
        
        # Update task status based on phase statuses
        self._update_task_status()
        self.last_update = datetime.now()
    
    def add_phase_error(self, phase: ScanPhase, error: ProgressError) -> None:
        """Add an error to a specific phase."""
        if phase not in self.phase_progress:
            self.phase_progress[phase] = PhaseProgress(phase=phase)
        
        self.phase_progress[phase].add_error(error)
        self._update_task_status()
        self.last_update = datetime.now()
    
    def _calculate_overall_progress(self) -> None:
        """Calculate overall progress across all phases."""
        if not self.phase_progress:
            self.overall_progress = 0.0
            return
        
        # Weight phases equally for now (can be made configurable)
        total_phases = len(self.phase_progress)
        total_progress = sum(phase.progress_percentage for phase in self.phase_progress.values())
        
        self.overall_progress = total_progress / total_phases if total_phases > 0 else 0.0
        
        # Update estimated completion
        self._calculate_estimated_completion()
    
    def _calculate_estimated_completion(self) -> None:
        """Calculate estimated completion time."""
        if not self.start_time or self.overall_progress <= 0:
            self.estimated_completion = None
            return
        
        elapsed = datetime.now() - self.start_time
        if self.overall_progress >= 100.0:
            self.estimated_completion = self.start_time + elapsed
            return
        
        # Estimate based on current progress rate
        progress_rate = self.overall_progress / 100.0
        estimated_total_time = elapsed / progress_rate if progress_rate > 0 else None
        
        if estimated_total_time:
            self.estimated_completion = self.start_time + estimated_total_time
    
    def _update_task_status(self) -> None:
        """Update task status based on phase statuses."""
        if not self.phase_progress:
            return
        
        statuses = [phase.status for phase in self.phase_progress.values()]
        
        # Check for failed phases
        if TaskStatus.FAILED in statuses:
            self.status = TaskStatus.FAILED
            return
        
        # Check for cancelled phases
        if TaskStatus.CANCELLED in statuses:
            self.status = TaskStatus.CANCELLED
            return
        
        # Check for paused phases
        if TaskStatus.PAUSED in statuses:
            self.status = TaskStatus.PAUSED
            return
        
        # Check if all phases are completed
        if all(status == TaskStatus.COMPLETED for status in statuses):
            self.status = TaskStatus.COMPLETED
            self.actual_completion = datetime.now()
            return
        
        # Check if any phases are running
        if TaskStatus.RUNNING in statuses:
            self.status = TaskStatus.RUNNING
            if self.start_time is None:
                self.start_time = datetime.now()
            return
        
        # Default to pending if no other status applies
        if all(status == TaskStatus.PENDING for status in statuses):
            self.status = TaskStatus.PENDING
    
    def get_phase_progress(self, phase: ScanPhase) -> Optional[PhaseProgress]:
        """Get progress for a specific phase."""
        return self.phase_progress.get(phase)
    
    def get_active_phases(self) -> List[ScanPhase]:
        """Get currently active (running) phases."""
        return [phase for phase, progress in self.phase_progress.items()
                if progress.status == TaskStatus.RUNNING]
    
    def get_completed_phases(self) -> List[ScanPhase]:
        """Get completed phases."""
        return [phase for phase, progress in self.phase_progress.items()
                if progress.status == TaskStatus.COMPLETED]
    
    def get_failed_phases(self) -> List[ScanPhase]:
        """Get failed phases."""
        return [phase for phase, progress in self.phase_progress.items()
                if progress.status == TaskStatus.FAILED]
    
    def get_all_errors(self) -> List[ProgressError]:
        """Get all errors across all phases."""
        all_errors = []
        for phase_prog in self.phase_progress.values():
            all_errors.extend(phase_prog.errors)
        return sorted(all_errors, key=lambda x: x.timestamp)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'task_id': self.task_id,
            'scan_id': self.scan_id,
            'scan_profile': self.scan_profile,
            'target_info': self.target_info,
            'current_phase': self.current_phase.value if self.current_phase else None,
            'phase_progress': {phase.value: progress.to_dict() 
                             for phase, progress in self.phase_progress.items()},
            'overall_progress': self.overall_progress,
            'status': self.status.value,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'estimated_completion': self.estimated_completion.isoformat() 
                                  if self.estimated_completion else None,
            'actual_completion': self.actual_completion.isoformat() 
                               if self.actual_completion else None,
            'last_checkpoint': self.last_checkpoint.isoformat() 
                             if self.last_checkpoint else None,
            'last_update': self.last_update.isoformat(),
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProgressState':
        """Create from dictionary."""
        progress_state = cls(
            task_id=data['task_id'],
            scan_id=data['scan_id'],
            scan_profile=data['scan_profile'],
            target_info=data['target_info'],
            overall_progress=data.get('overall_progress', 0.0),
            status=TaskStatus(data.get('status', TaskStatus.PENDING.value)),
            metadata=data.get('metadata', {})
        )
        
        # Restore current phase
        if data.get('current_phase'):
            progress_state.current_phase = ScanPhase(data['current_phase'])
        
        # Restore timestamps
        if data.get('start_time'):
            progress_state.start_time = datetime.fromisoformat(data['start_time'])
        
        if data.get('estimated_completion'):
            progress_state.estimated_completion = datetime.fromisoformat(data['estimated_completion'])
        
        if data.get('actual_completion'):
            progress_state.actual_completion = datetime.fromisoformat(data['actual_completion'])
        
        if data.get('last_checkpoint'):
            progress_state.last_checkpoint = datetime.fromisoformat(data['last_checkpoint'])
        
        if data.get('last_update'):
            progress_state.last_update = datetime.fromisoformat(data['last_update'])
        
        # Restore phase progress
        if data.get('phase_progress'):
            progress_state.phase_progress = {}
            for phase_name, phase_data in data['phase_progress'].items():
                phase = ScanPhase(phase_name)
                progress_state.phase_progress[phase] = PhaseProgress.from_dict(phase_data)
        
        return progress_state


@dataclass
class CheckpointInfo:
    """Checkpoint information."""
    checkpoint_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str = ""
    phase: ScanPhase = ScanPhase.DISCOVERY
    timestamp: datetime = field(default_factory=datetime.now)
    progress_state: Optional[Dict[str, Any]] = None
    phase_data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'checkpoint_id': self.checkpoint_id,
            'task_id': self.task_id,
            'phase': self.phase.value,
            'timestamp': self.timestamp.isoformat(),
            'progress_state': self.progress_state,
            'phase_data': self.phase_data,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CheckpointInfo':
        """Create from dictionary."""
        return cls(
            checkpoint_id=data['checkpoint_id'],
            task_id=data['task_id'],
            phase=ScanPhase(data['phase']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            progress_state=data.get('progress_state'),
            phase_data=data.get('phase_data', {}),
            metadata=data.get('metadata', {})
        )


@dataclass
class QueueStatus:
    """Task queue status information."""
    running_count: int = 0
    pending_count: int = 0
    completed_count: int = 0
    failed_count: int = 0
    total_slots: int = 0
    available_slots: int = 0
    queue_health: str = "healthy"  # healthy, degraded, critical
    
    @property
    def utilization_percentage(self) -> float:
        """Calculate queue utilization percentage."""
        if self.total_slots == 0:
            return 0.0
        return (self.running_count / self.total_slots) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'running_count': self.running_count,
            'pending_count': self.pending_count,
            'completed_count': self.completed_count,
            'failed_count': self.failed_count,
            'total_slots': self.total_slots,
            'available_slots': self.available_slots,
            'queue_health': self.queue_health,
            'utilization_percentage': self.utilization_percentage
        }


@dataclass 
class PhaseTimingData:
    """Historical timing data for scan phases."""
    phase: ScanPhase
    target_count: int
    complexity_score: float
    actual_duration: timedelta
    success_rate: float
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'phase': self.phase.value,
            'target_count': self.target_count,
            'complexity_score': self.complexity_score,
            'actual_duration': self.actual_duration.total_seconds(),
            'success_rate': self.success_rate,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PhaseTimingData':
        """Create from dictionary."""
        return cls(
            phase=ScanPhase(data['phase']),
            target_count=data['target_count'],
            complexity_score=data['complexity_score'],
            actual_duration=timedelta(seconds=data['actual_duration']),
            success_rate=data['success_rate'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            metadata=data.get('metadata', {})
        )


@dataclass
class ResourceMetrics:
    """System resource usage metrics."""
    cpu_usage: float = 0.0  # Percentage
    memory_usage: float = 0.0  # Percentage  
    disk_usage: float = 0.0  # Percentage
    network_io: Dict[str, float] = field(default_factory=dict)  # bytes/sec
    active_connections: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'disk_usage': self.disk_usage,
            'network_io': self.network_io,
            'active_connections': self.active_connections,
            'timestamp': self.timestamp.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ResourceMetrics':
        """Create from dictionary."""
        return cls(
            cpu_usage=data.get('cpu_usage', 0.0),
            memory_usage=data.get('memory_usage', 0.0),
            disk_usage=data.get('disk_usage', 0.0),
            network_io=data.get('network_io', {}),
            active_connections=data.get('active_connections', 0),
            timestamp=datetime.fromisoformat(data['timestamp']) if data.get('timestamp') else datetime.now()
        )


@dataclass
class HealthStatus:
    """Task health status information."""
    task_id: str
    is_healthy: bool = True
    last_update: datetime = field(default_factory=datetime.now)
    warnings: List[str] = field(default_factory=list)
    resource_usage: Optional[ResourceMetrics] = None
    performance_score: float = 1.0  # 0.0 to 1.0
    
    def add_warning(self, warning: str) -> None:
        """Add a health warning."""
        self.warnings.append(warning)
        if len(self.warnings) > 10:  # Keep only recent warnings
            self.warnings = self.warnings[-10:]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'task_id': self.task_id,
            'is_healthy': self.is_healthy,
            'last_update': self.last_update.isoformat(),
            'warnings': self.warnings,
            'resource_usage': self.resource_usage.to_dict() if self.resource_usage else None,
            'performance_score': self.performance_score
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HealthStatus':
        """Create from dictionary."""
        health_status = cls(
            task_id=data['task_id'],
            is_healthy=data.get('is_healthy', True),
            warnings=data.get('warnings', []),
            performance_score=data.get('performance_score', 1.0)
        )
        
        if data.get('last_update'):
            health_status.last_update = datetime.fromisoformat(data['last_update'])
        
        if data.get('resource_usage'):
            health_status.resource_usage = ResourceMetrics.from_dict(data['resource_usage'])
        
        return health_status