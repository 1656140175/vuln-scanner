"""Task queue system for concurrent scan management."""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum

from .models import ProgressState, TaskStatus, QueueStatus
from .manager import ProgressManager
from ..core.scanning.data_structures import ScanPhase
from ..core.exceptions import BaseException


logger = logging.getLogger(__name__)


class QueueException(BaseException):
    """Task queue specific exceptions."""
    pass


class TaskPriority(Enum):
    """Task priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ScanConfig:
    """Scan configuration for queued tasks."""
    scan_id: str
    scan_profile: str
    target_info: Dict[str, Any]
    priority: TaskPriority = TaskPriority.NORMAL
    timeout: Optional[timedelta] = None
    retry_count: int = 0
    max_retries: int = 3
    metadata: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)  # Task IDs this task depends on
    
    def __post_init__(self):
        """Initialize scan config after creation."""
        if not hasattr(self, 'config_id'):
            self.config_id = str(uuid.uuid4())
        if self.timeout is None:
            self.timeout = timedelta(hours=2)  # Default 2 hour timeout


@dataclass
class QueuedTask:
    """Represents a task in the queue."""
    task_id: str
    scan_config: ScanConfig
    status: TaskStatus = TaskStatus.PENDING
    queued_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    worker_id: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    
    @property
    def priority(self) -> TaskPriority:
        """Get task priority."""
        return self.scan_config.priority
    
    @property
    def queue_time(self) -> timedelta:
        """Get time spent in queue."""
        start_time = self.started_at or datetime.now()
        return start_time - self.queued_at
    
    @property
    def execution_time(self) -> Optional[timedelta]:
        """Get task execution time."""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'task_id': self.task_id,
            'scan_config': {
                'scan_id': self.scan_config.scan_id,
                'scan_profile': self.scan_config.scan_profile,
                'priority': self.scan_config.priority.value,
                'timeout': self.scan_config.timeout.total_seconds() if self.scan_config.timeout else None,
                'retry_count': self.scan_config.retry_count,
                'max_retries': self.scan_config.max_retries,
            },
            'status': self.status.value,
            'queued_at': self.queued_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'worker_id': self.worker_id,
            'error_message': self.error_message,
            'retry_count': self.retry_count,
            'queue_time': self.queue_time.total_seconds(),
            'execution_time': self.execution_time.total_seconds() if self.execution_time else None
        }


class TaskQueue:
    """Task queue for managing concurrent scan execution."""
    
    def __init__(self, max_concurrent: int = 5, progress_manager: Optional[ProgressManager] = None):
        """Initialize task queue.
        
        Args:
            max_concurrent: Maximum number of concurrent tasks
            progress_manager: ProgressManager instance for task tracking
        """
        self.max_concurrent = max_concurrent
        self.progress_manager = progress_manager
        
        # Queue data structures
        self.pending_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.running_tasks: Dict[str, QueuedTask] = {}
        self.completed_tasks: Dict[str, QueuedTask] = {}
        self.failed_tasks: Dict[str, QueuedTask] = {}
        
        # Task execution management
        self.workers: Dict[str, asyncio.Task] = {}
        self.task_futures: Dict[str, asyncio.Task] = {}
        
        # Queue statistics
        self.stats = {
            'total_submitted': 0,
            'total_completed': 0,
            'total_failed': 0,
            'total_retried': 0,
        }
        
        # Control flags
        self._shutdown_event = asyncio.Event()
        self._paused = False
        self._initialized = False
        
        # Callbacks
        self.task_callbacks: Dict[str, List[Callable]] = {
            'on_task_start': [],
            'on_task_complete': [],
            'on_task_fail': [],
            'on_queue_full': [],
            'on_queue_empty': []
        }
    
    async def initialize(self) -> None:
        """Initialize the task queue."""
        if self._initialized:
            return
        
        logger.info(f"Initializing task queue with {self.max_concurrent} concurrent slots")
        
        # Start worker tasks
        for i in range(self.max_concurrent):
            worker_id = f"worker-{i+1}"
            self.workers[worker_id] = asyncio.create_task(
                self._worker_loop(worker_id),
                name=f"TaskQueue-{worker_id}"
            )
        
        self._initialized = True
        logger.info("Task queue initialized successfully")
    
    async def shutdown(self) -> None:
        """Shutdown the task queue gracefully."""
        if not self._initialized:
            return
        
        logger.info("Shutting down task queue")
        
        # Signal shutdown
        self._shutdown_event.set()
        
        # Cancel all running tasks
        for task_id, task_future in list(self.task_futures.items()):
            if not task_future.done():
                task_future.cancel()
                await self._handle_task_completion(task_id, cancelled=True)
        
        # Cancel worker tasks
        for worker_id, worker_task in self.workers.items():
            worker_task.cancel()
        
        # Wait for workers to complete
        await asyncio.gather(*self.workers.values(), return_exceptions=True)
        
        self._initialized = False
        logger.info("Task queue shutdown complete")
    
    async def submit_task(self, scan_config: ScanConfig) -> str:
        """Submit a new task to the queue.
        
        Args:
            scan_config: Scan configuration
            
        Returns:
            Task ID
            
        Raises:
            QueueException: If task submission fails
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Create task ID
            task_id = str(uuid.uuid4())
            
            # Create queued task
            queued_task = QueuedTask(
                task_id=task_id,
                scan_config=scan_config
            )
            
            # Check dependencies
            if scan_config.dependencies:
                unmet_deps = await self._check_dependencies(scan_config.dependencies)
                if unmet_deps:
                    raise QueueException(f"Unmet dependencies: {unmet_deps}")
            
            # Add to pending queue with priority
            priority_value = -scan_config.priority.value  # Negative for high priority first
            await self.pending_queue.put((priority_value, datetime.now(), queued_task))
            
            # Update statistics
            self.stats['total_submitted'] += 1
            
            logger.info(f"Submitted task {task_id} with priority {scan_config.priority.value}")
            
            # Notify callbacks
            await self._notify_callbacks('on_queue_full' if self.is_full() else 'on_task_submit', queued_task)
            
            return task_id
            
        except Exception as e:
            raise QueueException(f"Failed to submit task: {e}") from e
    
    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a queued or running task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            True if cancelled, False if not found
        """
        # Check running tasks
        if task_id in self.running_tasks:
            queued_task = self.running_tasks[task_id]
            
            # Cancel the task future
            if task_id in self.task_futures:
                self.task_futures[task_id].cancel()
            
            # Update task status
            queued_task.status = TaskStatus.CANCELLED
            queued_task.completed_at = datetime.now()
            
            # Move to completed tasks
            del self.running_tasks[task_id]
            self.completed_tasks[task_id] = queued_task
            
            logger.info(f"Cancelled running task {task_id}")
            return True
        
        # For pending tasks, we'd need to search the priority queue
        # This is complex with asyncio.PriorityQueue, so we'll mark it for cancellation
        # when it's picked up by a worker
        
        logger.warning(f"Task {task_id} not found in running tasks (may be pending)")
        return False
    
    async def pause_queue(self) -> None:
        """Pause the task queue (stop processing new tasks)."""
        self._paused = True
        logger.info("Task queue paused")
    
    async def resume_queue(self) -> None:
        """Resume the task queue."""
        self._paused = False
        logger.info("Task queue resumed")
    
    async def get_queue_status(self) -> QueueStatus:
        """Get current queue status.
        
        Returns:
            QueueStatus object
        """
        pending_count = self.pending_queue.qsize()
        running_count = len(self.running_tasks)
        completed_count = len(self.completed_tasks)
        failed_count = len(self.failed_tasks)
        
        available_slots = self.max_concurrent - running_count
        
        # Determine queue health
        queue_health = "healthy"
        if pending_count > self.max_concurrent * 2:
            queue_health = "degraded"
        if pending_count > self.max_concurrent * 5:
            queue_health = "critical"
        
        return QueueStatus(
            running_count=running_count,
            pending_count=pending_count,
            completed_count=completed_count,
            failed_count=failed_count,
            total_slots=self.max_concurrent,
            available_slots=available_slots,
            queue_health=queue_health
        )
    
    async def get_task_info(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            Task information dictionary or None if not found
        """
        # Check all task collections
        for task_collection in [self.running_tasks, self.completed_tasks, self.failed_tasks]:
            if task_id in task_collection:
                return task_collection[task_id].to_dict()
        
        return None
    
    async def list_tasks(self, status: Optional[TaskStatus] = None) -> List[Dict[str, Any]]:
        """List tasks by status.
        
        Args:
            status: Filter by task status (optional)
            
        Returns:
            List of task information dictionaries
        """
        all_tasks = []
        
        # Collect tasks from all collections
        for task_collection in [self.running_tasks, self.completed_tasks, self.failed_tasks]:
            for queued_task in task_collection.values():
                if status is None or queued_task.status == status:
                    all_tasks.append(queued_task.to_dict())
        
        # Sort by queued time
        all_tasks.sort(key=lambda x: x['queued_at'], reverse=True)
        
        return all_tasks
    
    def is_full(self) -> bool:
        """Check if queue is at capacity."""
        return len(self.running_tasks) >= self.max_concurrent
    
    def is_empty(self) -> bool:
        """Check if queue is empty."""
        return self.pending_queue.empty() and not self.running_tasks
    
    async def add_callback(self, event: str, callback: Callable) -> None:
        """Add event callback.
        
        Args:
            event: Event name (on_task_start, on_task_complete, etc.)
            callback: Callback function
        """
        if event in self.task_callbacks:
            self.task_callbacks[event].append(callback)
    
    async def remove_callback(self, event: str, callback: Callable) -> None:
        """Remove event callback.
        
        Args:
            event: Event name
            callback: Callback function
        """
        if event in self.task_callbacks and callback in self.task_callbacks[event]:
            self.task_callbacks[event].remove(callback)
    
    # Private methods
    
    async def _worker_loop(self, worker_id: str) -> None:
        """Main worker loop for processing tasks.
        
        Args:
            worker_id: Worker identifier
        """
        logger.debug(f"Worker {worker_id} started")
        
        while not self._shutdown_event.is_set():
            try:
                if self._paused:
                    await asyncio.sleep(1)
                    continue
                
                # Wait for a task with timeout
                try:
                    priority, queued_time, queued_task = await asyncio.wait_for(
                        self.pending_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Check if task was cancelled while in queue
                if queued_task.status == TaskStatus.CANCELLED:
                    continue
                
                # Execute the task
                await self._execute_task(worker_id, queued_task)
                
            except Exception as e:
                logger.error(f"Error in worker {worker_id}: {e}")
                await asyncio.sleep(1)
        
        logger.debug(f"Worker {worker_id} stopped")
    
    async def _execute_task(self, worker_id: str, queued_task: QueuedTask) -> None:
        """Execute a task.
        
        Args:
            worker_id: Worker identifier
            queued_task: Task to execute
        """
        task_id = queued_task.task_id
        
        try:
            # Update task status
            queued_task.status = TaskStatus.RUNNING
            queued_task.started_at = datetime.now()
            queued_task.worker_id = worker_id
            
            # Move to running tasks
            self.running_tasks[task_id] = queued_task
            
            logger.info(f"Worker {worker_id} starting task {task_id}")
            
            # Notify callbacks
            await self._notify_callbacks('on_task_start', queued_task)
            
            # Create progress manager task if available
            if self.progress_manager:
                progress_task_id = await self.progress_manager.create_task(
                    scan_id=queued_task.scan_config.scan_id,
                    scan_profile=queued_task.scan_config.scan_profile,
                    target_info=queued_task.scan_config.target_info,
                    metadata=queued_task.scan_config.metadata
                )
                queued_task.scan_config.metadata['progress_task_id'] = progress_task_id
            
            # Execute the actual scan task
            task_future = asyncio.create_task(
                self._run_scan_task(queued_task),
                name=f"ScanTask-{task_id}"
            )
            
            self.task_futures[task_id] = task_future
            
            # Wait for task completion with timeout
            timeout = queued_task.scan_config.timeout
            if timeout:
                await asyncio.wait_for(task_future, timeout=timeout.total_seconds())
            else:
                await task_future
            
            # Task completed successfully
            await self._handle_task_completion(task_id, success=True)
            
        except asyncio.CancelledError:
            await self._handle_task_completion(task_id, cancelled=True)
        except asyncio.TimeoutError:
            await self._handle_task_completion(task_id, timeout=True)
        except Exception as e:
            await self._handle_task_completion(task_id, error=str(e))
    
    async def _run_scan_task(self, queued_task: QueuedTask) -> None:
        """Run the actual scan task.
        
        Args:
            queued_task: Task to execute
        """
        # This is a placeholder - the actual scan execution would be implemented
        # by integrating with the scan engine
        
        task_id = queued_task.task_id
        scan_config = queued_task.scan_config
        
        # Simulate scan phases for now
        phases = list(ScanPhase)
        
        if self.progress_manager:
            progress_task_id = scan_config.metadata.get('progress_task_id')
            if progress_task_id:
                await self.progress_manager.start_task(progress_task_id)
                
                # Simulate progress through phases
                for i, phase in enumerate(phases):
                    # Simulate work
                    await asyncio.sleep(1)
                    
                    # Update progress
                    progress_percentage = ((i + 1) / len(phases)) * 100
                    await self.progress_manager.update_progress(
                        progress_task_id,
                        phase,
                        progress_percentage,
                        f"Processing {phase.value}",
                        total_steps=len(phases)
                    )
                    
                    # Complete phase
                    await self.progress_manager.complete_phase(progress_task_id, phase)
        
        logger.info(f"Scan task {task_id} completed successfully")
    
    async def _handle_task_completion(self, task_id: str, success: bool = False,
                                    error: Optional[str] = None, timeout: bool = False,
                                    cancelled: bool = False) -> None:
        """Handle task completion.
        
        Args:
            task_id: Task identifier
            success: Whether task completed successfully
            error: Error message (if failed)
            timeout: Whether task timed out
            cancelled: Whether task was cancelled
        """
        if task_id not in self.running_tasks:
            logger.warning(f"Task {task_id} not found in running tasks")
            return
        
        queued_task = self.running_tasks[task_id]
        queued_task.completed_at = datetime.now()
        
        # Clean up task future
        self.task_futures.pop(task_id, None)
        
        # Update task status and move to appropriate collection
        if success:
            queued_task.status = TaskStatus.COMPLETED
            self.completed_tasks[task_id] = queued_task
            self.stats['total_completed'] += 1
            await self._notify_callbacks('on_task_complete', queued_task)
            
        elif cancelled:
            queued_task.status = TaskStatus.CANCELLED
            queued_task.error_message = "Task was cancelled"
            self.completed_tasks[task_id] = queued_task
            
        elif timeout:
            queued_task.status = TaskStatus.FAILED
            queued_task.error_message = "Task timed out"
            
            # Check for retry
            if await self._should_retry_task(queued_task):
                await self._retry_task(queued_task)
                return
            else:
                self.failed_tasks[task_id] = queued_task
                self.stats['total_failed'] += 1
                await self._notify_callbacks('on_task_fail', queued_task)
                
        else:  # Error occurred
            queued_task.status = TaskStatus.FAILED
            queued_task.error_message = error
            
            # Check for retry
            if await self._should_retry_task(queued_task):
                await self._retry_task(queued_task)
                return
            else:
                self.failed_tasks[task_id] = queued_task
                self.stats['total_failed'] += 1
                await self._notify_callbacks('on_task_fail', queued_task)
        
        # Remove from running tasks
        del self.running_tasks[task_id]
        
        # Notify if queue becomes empty
        if self.is_empty():
            await self._notify_callbacks('on_queue_empty', None)
    
    async def _should_retry_task(self, queued_task: QueuedTask) -> bool:
        """Determine if a task should be retried.
        
        Args:
            queued_task: Failed task
            
        Returns:
            True if task should be retried
        """
        return (queued_task.retry_count < queued_task.scan_config.max_retries and
                queued_task.scan_config.max_retries > 0)
    
    async def _retry_task(self, queued_task: QueuedTask) -> None:
        """Retry a failed task.
        
        Args:
            queued_task: Task to retry
        """
        queued_task.retry_count += 1
        queued_task.scan_config.retry_count += 1
        queued_task.status = TaskStatus.PENDING
        queued_task.started_at = None
        queued_task.completed_at = None
        queued_task.worker_id = None
        
        # Add back to queue with updated priority (lower priority for retries)
        priority_value = -(queued_task.scan_config.priority.value - queued_task.retry_count)
        await self.pending_queue.put((priority_value, datetime.now(), queued_task))
        
        self.stats['total_retried'] += 1
        
        logger.info(f"Retrying task {queued_task.task_id} (attempt {queued_task.retry_count + 1})")
    
    async def _check_dependencies(self, dependencies: List[str]) -> List[str]:
        """Check if task dependencies are met.
        
        Args:
            dependencies: List of task IDs this task depends on
            
        Returns:
            List of unmet dependencies
        """
        unmet_deps = []
        
        for dep_task_id in dependencies:
            # Check if dependency is completed
            if dep_task_id not in self.completed_tasks:
                # Check if it's still running or failed
                if (dep_task_id in self.running_tasks or 
                    dep_task_id in self.failed_tasks):
                    unmet_deps.append(dep_task_id)
                else:
                    # Dependency not found at all
                    unmet_deps.append(f"{dep_task_id} (not found)")
        
        return unmet_deps
    
    async def _notify_callbacks(self, event: str, task: Optional[QueuedTask]) -> None:
        """Notify event callbacks.
        
        Args:
            event: Event name
            task: QueuedTask object (optional)
        """
        callbacks = self.task_callbacks.get(event, [])
        for callback in callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(task)
                else:
                    callback(task)
            except Exception as e:
                logger.error(f"Error in callback for event {event}: {e}")
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get queue statistics.
        
        Returns:
            Dictionary containing queue statistics
        """
        queue_status = await self.get_queue_status()
        
        # Calculate average execution time
        completed_tasks_with_time = [
            task for task in self.completed_tasks.values()
            if task.execution_time is not None
        ]
        
        avg_execution_time = None
        if completed_tasks_with_time:
            total_time = sum(task.execution_time.total_seconds() for task in completed_tasks_with_time)
            avg_execution_time = total_time / len(completed_tasks_with_time)
        
        return {
            'queue_status': queue_status.to_dict(),
            'statistics': self.stats.copy(),
            'average_execution_time': avg_execution_time,
            'workers_active': len([w for w in self.workers.values() if not w.done()]),
            'is_paused': self._paused,
            'total_tasks': (queue_status.running_count + queue_status.pending_count + 
                          queue_status.completed_count + queue_status.failed_count)
        }