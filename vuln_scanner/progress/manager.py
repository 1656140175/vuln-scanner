"""Main progress manager for task lifecycle management."""

import asyncio
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from contextlib import asynccontextmanager

from .models import (
    ProgressState, TaskStatus, PhaseProgress, ProgressError, 
    CheckpointInfo, HealthStatus
)
from .events import ProgressEventBus, ProgressEventEmitter
from .storage.base import ProgressStorage
from .storage.sqlite import SqliteProgressStorage
from ..core.scanning.data_structures import ScanPhase
from ..core.exceptions import BaseException


logger = logging.getLogger(__name__)


class ProgressManagerException(BaseException):
    """Progress manager specific exceptions."""
    pass


class ProgressManager:
    """Main progress manager for task lifecycle management."""
    
    def __init__(self, storage: Optional[ProgressStorage] = None, 
                 config: Optional[Dict[str, Any]] = None):
        """Initialize progress manager.
        
        Args:
            storage: Progress storage backend (defaults to SQLite)
            config: Configuration options
        """
        self.config = config or {}
        self.storage = storage or SqliteProgressStorage(
            db_path=self.config.get('storage_path', 'data/progress.db')
        )
        
        self.event_bus = ProgressEventBus(
            max_event_history=self.config.get('max_event_history', 1000)
        )
        self.event_emitter = ProgressEventEmitter(self.event_bus)
        
        # Active tasks cache for performance
        self.active_tasks: Dict[str, ProgressState] = {}
        
        # Configuration
        self.checkpoint_interval = timedelta(seconds=self.config.get('checkpoint_interval', 30))
        self.auto_cleanup_interval = timedelta(hours=self.config.get('auto_cleanup_hours', 24))
        self.max_concurrent_tasks = self.config.get('max_concurrent_tasks', 10)
        
        # Background tasks
        self._background_tasks: List[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()
        self._initialized = False
        
        # Task locks for thread safety
        self._task_locks: Dict[str, asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()
    
    async def initialize(self) -> None:
        """Initialize progress manager."""
        if self._initialized:
            return
        
        logger.info("Initializing progress manager")
        
        # Initialize storage
        await self.storage.initialize()
        
        # Load active tasks from storage
        await self._load_active_tasks()
        
        # Start background tasks
        self._start_background_tasks()
        
        self._initialized = True
        logger.info("Progress manager initialized successfully")
    
    async def shutdown(self) -> None:
        """Shutdown progress manager and cleanup resources."""
        if not self._initialized:
            return
        
        logger.info("Shutting down progress manager")
        
        # Signal shutdown
        self._shutdown_event.set()
        
        # Cancel background tasks
        for task in self._background_tasks:
            task.cancel()
        
        # Wait for background tasks to complete
        await asyncio.gather(*self._background_tasks, return_exceptions=True)
        
        # Cleanup storage
        await self.storage.cleanup()
        
        self._initialized = False
        logger.info("Progress manager shutdown complete")
    
    async def create_task(self, scan_id: str, scan_profile: str, 
                         target_info: Dict[str, Any],
                         metadata: Optional[Dict[str, Any]] = None) -> str:
        """Create new scanning task and initialize progress state.
        
        Args:
            scan_id: Scan identifier
            scan_profile: Scan profile name
            target_info: Target information
            metadata: Additional task metadata
            
        Returns:
            Task ID
            
        Raises:
            ProgressManagerException: If task creation fails
        """
        await self._ensure_initialized()
        
        try:
            task_id = str(uuid.uuid4())
            
            # Create progress state
            progress_state = ProgressState(
                task_id=task_id,
                scan_id=scan_id,
                scan_profile=scan_profile,
                target_info=target_info,
                metadata=metadata or {}
            )
            
            # Save to storage
            await self.storage.save_progress(progress_state)
            
            # Add to active tasks cache
            self.active_tasks[task_id] = progress_state
            
            # Create task lock
            async with self._locks_lock:
                self._task_locks[task_id] = asyncio.Lock()
            
            # Emit event
            await self.event_emitter.task_created(task_id, progress_state)
            
            logger.info(f"Created task {task_id} for scan {scan_id}")
            return task_id
            
        except Exception as e:
            raise ProgressManagerException(f"Failed to create task: {e}") from e
    
    async def start_task(self, task_id: str) -> None:
        """Start a task.
        
        Args:
            task_id: Task identifier
            
        Raises:
            ProgressManagerException: If task start fails
        """
        await self._ensure_initialized()
        
        async with await self._get_task_lock(task_id):
            try:
                progress_state = await self._get_progress_state(task_id)
                
                if progress_state.status != TaskStatus.PENDING:
                    raise ProgressManagerException(
                        f"Task {task_id} cannot be started - current status: {progress_state.status.value}"
                    )
                
                # Update status
                progress_state.status = TaskStatus.RUNNING
                progress_state.start_time = datetime.now()
                
                # Save to storage
                await self.storage.save_progress(progress_state)
                
                # Emit event
                await self.event_emitter.task_started(task_id, progress_state)
                
                logger.info(f"Started task {task_id}")
                
            except Exception as e:
                raise ProgressManagerException(f"Failed to start task {task_id}: {e}") from e
    
    async def update_progress(self, task_id: str, phase: ScanPhase, 
                            progress: float, current_step: str = "",
                            total_steps: Optional[int] = None,
                            metadata: Optional[Dict[str, Any]] = None) -> None:
        """Update task progress.
        
        Args:
            task_id: Task identifier
            phase: Current scan phase
            progress: Progress percentage (0-100)
            current_step: Description of current step
            total_steps: Total number of steps (optional)
            metadata: Additional metadata
            
        Raises:
            ProgressManagerException: If update fails
        """
        await self._ensure_initialized()
        
        async with await self._get_task_lock(task_id):
            try:
                progress_state = await self._get_progress_state(task_id)
                
                if progress_state.status not in [TaskStatus.RUNNING, TaskStatus.PAUSED]:
                    logger.warning(f"Cannot update progress for task {task_id} - status: {progress_state.status.value}")
                    return
                
                # Calculate completed steps from progress percentage
                if total_steps is not None:
                    completed_steps = int((progress / 100.0) * total_steps)
                else:
                    # Use existing total_steps if available
                    phase_prog = progress_state.phase_progress.get(phase)
                    if phase_prog and phase_prog.total_steps > 0:
                        completed_steps = int((progress / 100.0) * phase_prog.total_steps)
                    else:
                        completed_steps = int(progress)
                        total_steps = 100
                
                # Update phase progress
                progress_state.update_phase_progress(
                    phase=phase,
                    completed=completed_steps,
                    total=total_steps or progress_state.phase_progress.get(phase, PhaseProgress(phase)).total_steps,
                    current_step=current_step,
                    metadata=metadata
                )
                
                # Save to storage
                await self.storage.save_progress(progress_state)
                
                # Emit progress event
                await self.event_emitter.task_progress(task_id, progress_state)
                
                logger.debug(f"Updated progress for task {task_id}: {phase.value} - {progress:.1f}%")
                
            except Exception as e:
                logger.error(f"Failed to update progress for task {task_id}: {e}")
                # Don't raise exception to avoid breaking scan flow
    
    async def complete_phase(self, task_id: str, phase: ScanPhase) -> None:
        """Mark a phase as completed.
        
        Args:
            task_id: Task identifier
            phase: Completed scan phase
            
        Raises:
            ProgressManagerException: If completion fails
        """
        await self._ensure_initialized()
        
        async with await self._get_task_lock(task_id):
            try:
                progress_state = await self._get_progress_state(task_id)
                
                # Set phase status to completed
                progress_state.set_phase_status(phase, TaskStatus.COMPLETED)
                
                # Save to storage
                await self.storage.save_progress(progress_state)
                
                logger.info(f"Completed phase {phase.value} for task {task_id}")
                
                # Check if all phases are completed
                if progress_state.status == TaskStatus.COMPLETED:
                    await self.event_emitter.task_completed(task_id, progress_state)
                    logger.info(f"Task {task_id} completed successfully")
                
            except Exception as e:
                raise ProgressManagerException(f"Failed to complete phase {phase.value} for task {task_id}: {e}") from e
    
    async def fail_task(self, task_id: str, error_message: str, 
                       phase: Optional[ScanPhase] = None) -> None:
        """Mark a task as failed.
        
        Args:
            task_id: Task identifier
            error_message: Error description
            phase: Failed phase (optional)
            
        Raises:
            ProgressManagerException: If fail operation fails
        """
        await self._ensure_initialized()
        
        async with await self._get_task_lock(task_id):
            try:
                progress_state = await self._get_progress_state(task_id)
                
                # Create error
                error = ProgressError(
                    phase=phase,
                    error_type="task_failure",
                    message=error_message,
                    recoverable=False
                )
                
                # Add error to appropriate phase or overall task
                if phase:
                    progress_state.add_phase_error(phase, error)
                else:
                    progress_state.status = TaskStatus.FAILED
                
                # Save to storage
                await self.storage.save_progress(progress_state)
                
                # Emit event
                await self.event_emitter.task_failed(task_id, progress_state, error_message)
                
                logger.error(f"Task {task_id} failed: {error_message}")
                
            except Exception as e:
                raise ProgressManagerException(f"Failed to mark task {task_id} as failed: {e}") from e
    
    async def pause_task(self, task_id: str) -> None:
        """Pause a running task.
        
        Args:
            task_id: Task identifier
            
        Raises:
            ProgressManagerException: If pause fails
        """
        await self._ensure_initialized()
        
        async with await self._get_task_lock(task_id):
            try:
                progress_state = await self._get_progress_state(task_id)
                
                if progress_state.status != TaskStatus.RUNNING:
                    raise ProgressManagerException(
                        f"Task {task_id} cannot be paused - current status: {progress_state.status.value}"
                    )
                
                progress_state.status = TaskStatus.PAUSED
                
                # Save to storage
                await self.storage.save_progress(progress_state)
                
                logger.info(f"Paused task {task_id}")
                
            except Exception as e:
                raise ProgressManagerException(f"Failed to pause task {task_id}: {e}") from e
    
    async def resume_task(self, task_id: str) -> None:
        """Resume a paused task.
        
        Args:
            task_id: Task identifier
            
        Raises:
            ProgressManagerException: If resume fails
        """
        await self._ensure_initialized()
        
        async with await self._get_task_lock(task_id):
            try:
                progress_state = await self._get_progress_state(task_id)
                
                if progress_state.status != TaskStatus.PAUSED:
                    raise ProgressManagerException(
                        f"Task {task_id} cannot be resumed - current status: {progress_state.status.value}"
                    )
                
                progress_state.status = TaskStatus.RUNNING
                
                # Save to storage
                await self.storage.save_progress(progress_state)
                
                logger.info(f"Resumed task {task_id}")
                
            except Exception as e:
                raise ProgressManagerException(f"Failed to resume task {task_id}: {e}") from e
    
    async def cancel_task(self, task_id: str) -> None:
        """Cancel a task.
        
        Args:
            task_id: Task identifier
            
        Raises:
            ProgressManagerException: If cancel fails
        """
        await self._ensure_initialized()
        
        async with await self._get_task_lock(task_id):
            try:
                progress_state = await self._get_progress_state(task_id)
                
                progress_state.status = TaskStatus.CANCELLED
                
                # Save to storage
                await self.storage.save_progress(progress_state)
                
                # Remove from active tasks
                self.active_tasks.pop(task_id, None)
                
                # Clean up task lock
                async with self._locks_lock:
                    self._task_locks.pop(task_id, None)
                
                logger.info(f"Cancelled task {task_id}")
                
            except Exception as e:
                raise ProgressManagerException(f"Failed to cancel task {task_id}: {e}") from e
    
    async def checkpoint(self, task_id: str, phase_data: Optional[Dict[str, Any]] = None) -> str:
        """Create a checkpoint for task state.
        
        Args:
            task_id: Task identifier
            phase_data: Phase-specific data to save
            
        Returns:
            Checkpoint ID
            
        Raises:
            ProgressManagerException: If checkpoint creation fails
        """
        await self._ensure_initialized()
        
        async with await self._get_task_lock(task_id):
            try:
                progress_state = await self._get_progress_state(task_id)
                
                # Create checkpoint
                checkpoint = CheckpointInfo(
                    task_id=task_id,
                    phase=progress_state.current_phase or ScanPhase.DISCOVERY,
                    progress_state=progress_state.to_dict(),
                    phase_data=phase_data or {},
                    metadata={
                        'overall_progress': progress_state.overall_progress,
                        'status': progress_state.status.value
                    }
                )
                
                # Save checkpoint
                await self.storage.save_checkpoint(checkpoint)
                
                # Update last checkpoint time
                progress_state.last_checkpoint = datetime.now()
                await self.storage.save_progress(progress_state)
                
                # Emit event
                await self.event_emitter.checkpoint_created(
                    task_id, 
                    checkpoint.checkpoint_id,
                    checkpoint.phase.value
                )
                
                logger.debug(f"Created checkpoint {checkpoint.checkpoint_id} for task {task_id}")
                return checkpoint.checkpoint_id
                
            except Exception as e:
                raise ProgressManagerException(f"Failed to create checkpoint for task {task_id}: {e}") from e
    
    async def get_progress(self, task_id: str) -> Optional[ProgressState]:
        """Get current progress state for a task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            ProgressState if found, None otherwise
        """
        await self._ensure_initialized()
        
        try:
            return await self._get_progress_state(task_id)
        except Exception as e:
            logger.error(f"Failed to get progress for task {task_id}: {e}")
            return None
    
    async def list_tasks(self, status: Optional[TaskStatus] = None) -> List[str]:
        """List tasks by status.
        
        Args:
            status: Filter by status (optional)
            
        Returns:
            List of task IDs
        """
        await self._ensure_initialized()
        
        try:
            if status:
                return await self.storage.list_tasks_by_status(status.value)
            else:
                return await self.storage.list_active_tasks()
        except Exception as e:
            logger.error(f"Failed to list tasks: {e}")
            return []
    
    async def get_task_health(self, task_id: str) -> Optional[HealthStatus]:
        """Get health status for a task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            HealthStatus if task exists, None otherwise
        """
        await self._ensure_initialized()
        
        try:
            progress_state = await self._get_progress_state(task_id)
            if not progress_state:
                return None
            
            # Determine health based on progress and timing
            is_healthy = True
            warnings = []
            performance_score = 1.0
            
            # Check for stalled progress
            time_since_update = datetime.now() - progress_state.last_update
            if time_since_update > timedelta(minutes=5) and progress_state.status == TaskStatus.RUNNING:
                is_healthy = False
                warnings.append("No progress update in over 5 minutes")
                performance_score *= 0.5
            
            # Check for excessive errors
            all_errors = progress_state.get_all_errors()
            if len(all_errors) > 10:
                warnings.append(f"High error count: {len(all_errors)} errors")
                performance_score *= 0.7
            
            return HealthStatus(
                task_id=task_id,
                is_healthy=is_healthy,
                warnings=warnings,
                performance_score=performance_score
            )
            
        except Exception as e:
            logger.error(f"Failed to get task health for {task_id}: {e}")
            return None
    
    async def cleanup_old_tasks(self, older_than: Optional[datetime] = None) -> int:
        """Clean up old completed tasks.
        
        Args:
            older_than: Delete tasks older than this (defaults to 7 days ago)
            
        Returns:
            Number of tasks cleaned up
        """
        await self._ensure_initialized()
        
        if older_than is None:
            older_than = datetime.now() - timedelta(days=7)
        
        try:
            return await self.storage.cleanup_completed_tasks(older_than)
        except Exception as e:
            logger.error(f"Failed to cleanup old tasks: {e}")
            return 0
    
    # Private methods
    
    async def _ensure_initialized(self) -> None:
        """Ensure manager is initialized."""
        if not self._initialized:
            await self.initialize()
    
    async def _load_active_tasks(self) -> None:
        """Load active tasks from storage into memory."""
        try:
            active_task_ids = await self.storage.list_active_tasks()
            
            for task_id in active_task_ids:
                progress_state = await self.storage.load_progress(task_id)
                if progress_state:
                    self.active_tasks[task_id] = progress_state
                    async with self._locks_lock:
                        self._task_locks[task_id] = asyncio.Lock()
            
            logger.info(f"Loaded {len(self.active_tasks)} active tasks")
            
        except Exception as e:
            logger.error(f"Failed to load active tasks: {e}")
    
    async def _get_progress_state(self, task_id: str) -> ProgressState:
        """Get progress state from cache or storage.
        
        Args:
            task_id: Task identifier
            
        Returns:
            ProgressState
            
        Raises:
            ProgressManagerException: If task not found
        """
        # Check cache first
        if task_id in self.active_tasks:
            return self.active_tasks[task_id]
        
        # Load from storage
        progress_state = await self.storage.load_progress(task_id)
        if not progress_state:
            raise ProgressManagerException(f"Task {task_id} not found")
        
        # Add to cache
        self.active_tasks[task_id] = progress_state
        
        return progress_state
    
    async def _get_task_lock(self, task_id: str) -> asyncio.Lock:
        """Get or create lock for task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            asyncio.Lock for the task
        """
        async with self._locks_lock:
            if task_id not in self._task_locks:
                self._task_locks[task_id] = asyncio.Lock()
            return self._task_locks[task_id]
    
    def _start_background_tasks(self) -> None:
        """Start background maintenance tasks."""
        self._background_tasks = [
            asyncio.create_task(self._checkpoint_worker()),
            asyncio.create_task(self._cleanup_worker()),
        ]
    
    async def _checkpoint_worker(self) -> None:
        """Background worker for automatic checkpointing."""
        while not self._shutdown_event.is_set():
            try:
                # Wait for checkpoint interval or shutdown
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.checkpoint_interval.total_seconds()
                )
                break  # Shutdown event was set
                
            except asyncio.TimeoutError:
                # Time to create checkpoints
                await self._create_automatic_checkpoints()
    
    async def _cleanup_worker(self) -> None:
        """Background worker for automatic cleanup."""
        while not self._shutdown_event.is_set():
            try:
                # Wait for cleanup interval or shutdown
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.auto_cleanup_interval.total_seconds()
                )
                break  # Shutdown event was set
                
            except asyncio.TimeoutError:
                # Time to cleanup
                await self.cleanup_old_tasks()
    
    async def _create_automatic_checkpoints(self) -> None:
        """Create automatic checkpoints for running tasks."""
        try:
            for task_id, progress_state in list(self.active_tasks.items()):
                if progress_state.status == TaskStatus.RUNNING:
                    # Check if checkpoint is needed
                    if (progress_state.last_checkpoint is None or 
                        datetime.now() - progress_state.last_checkpoint > self.checkpoint_interval):
                        
                        try:
                            await self.checkpoint(task_id)
                        except Exception as e:
                            logger.error(f"Failed to create automatic checkpoint for task {task_id}: {e}")
        
        except Exception as e:
            logger.error(f"Error in checkpoint worker: {e}")
    
    @asynccontextmanager
    async def task_context(self, scan_id: str, scan_profile: str, 
                          target_info: Dict[str, Any],
                          metadata: Optional[Dict[str, Any]] = None):
        """Context manager for task lifecycle.
        
        Args:
            scan_id: Scan identifier
            scan_profile: Scan profile name
            target_info: Target information
            metadata: Additional metadata
            
        Yields:
            Task ID and progress manager instance
        """
        task_id = await self.create_task(scan_id, scan_profile, target_info, metadata)
        
        try:
            await self.start_task(task_id)
            yield task_id, self
        except Exception as e:
            await self.fail_task(task_id, str(e))
            raise
        else:
            # Only complete if not already in terminal state
            progress_state = await self.get_progress(task_id)
            if progress_state and progress_state.status == TaskStatus.RUNNING:
                # Mark all phases as completed
                for phase in ScanPhase:
                    await self.complete_phase(task_id, phase)