"""Event system for real-time progress updates."""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field, asdict
from enum import Enum

from .models import ProgressState, TaskStatus


logger = logging.getLogger(__name__)


class ProgressEventType(Enum):
    """Progress event types."""
    TASK_CREATED = "task_created"
    TASK_STARTED = "task_started"
    TASK_PROGRESS = "task_progress"
    TASK_PHASE_STARTED = "task_phase_started"
    TASK_PHASE_COMPLETED = "task_phase_completed"
    TASK_PHASE_FAILED = "task_phase_failed"
    TASK_PAUSED = "task_paused"
    TASK_RESUMED = "task_resumed"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_CANCELLED = "task_cancelled"
    CHECKPOINT_CREATED = "checkpoint_created"
    ERROR_OCCURRED = "error_occurred"
    HEALTH_CHECK = "health_check"


@dataclass
class ProgressEvent:
    """Progress event data structure."""
    event_id: str = field(default_factory=lambda: str(asyncio.current_task().get_name() + "-" + str(int(datetime.now().timestamp() * 1000))))
    event_type: ProgressEventType = ProgressEventType.TASK_PROGRESS
    task_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    data: Dict[str, Any] = field(default_factory=dict)
    source: str = "progress_manager"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'task_id': self.task_id,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
            'source': self.source
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProgressEvent':
        """Create from dictionary."""
        return cls(
            event_id=data.get('event_id', ''),
            event_type=ProgressEventType(data['event_type']),
            task_id=data.get('task_id', ''),
            timestamp=datetime.fromisoformat(data['timestamp']),
            data=data.get('data', {}),
            source=data.get('source', 'progress_manager')
        )


class ProgressEventBus:
    """Event bus for progress updates."""
    
    def __init__(self, max_event_history: int = 1000):
        """Initialize event bus.
        
        Args:
            max_event_history: Maximum number of events to keep in history
        """
        self.subscribers: Dict[str, List[Callable]] = {}
        self.websocket_connections: Dict[str, Set[Any]] = {}  # task_id -> set of websockets
        self.event_history: List[ProgressEvent] = []
        self.max_event_history = max_event_history
        self._lock = asyncio.Lock()
    
    async def emit(self, event: ProgressEvent) -> None:
        """Emit progress event to all subscribers.
        
        Args:
            event: ProgressEvent to emit
        """
        async with self._lock:
            # Add to event history
            self.event_history.append(event)
            if len(self.event_history) > self.max_event_history:
                self.event_history.pop(0)
        
        logger.debug(f"Emitting event {event.event_type.value} for task {event.task_id}")
        
        # Notify subscribers
        await self._notify_subscribers(event)
        
        # Broadcast to WebSocket connections
        await self._broadcast_to_websockets(event)
    
    async def subscribe(self, event_type: str, callback: Callable[[ProgressEvent], Any]) -> None:
        """Subscribe to progress events.
        
        Args:
            event_type: Event type to subscribe to ('*' for all events)
            callback: Callback function to call when event occurs
        """
        async with self._lock:
            if event_type not in self.subscribers:
                self.subscribers[event_type] = []
            self.subscribers[event_type].append(callback)
        
        logger.debug(f"Subscriber added for event type: {event_type}")
    
    async def unsubscribe(self, event_type: str, callback: Callable[[ProgressEvent], Any]) -> None:
        """Unsubscribe from progress events.
        
        Args:
            event_type: Event type to unsubscribe from
            callback: Callback function to remove
        """
        async with self._lock:
            if event_type in self.subscribers:
                if callback in self.subscribers[event_type]:
                    self.subscribers[event_type].remove(callback)
                if not self.subscribers[event_type]:
                    del self.subscribers[event_type]
        
        logger.debug(f"Subscriber removed for event type: {event_type}")
    
    async def add_websocket_connection(self, task_id: str, websocket: Any) -> None:
        """Add WebSocket connection for task updates.
        
        Args:
            task_id: Task ID to monitor ('*' for all tasks)
            websocket: WebSocket connection object
        """
        async with self._lock:
            if task_id not in self.websocket_connections:
                self.websocket_connections[task_id] = set()
            self.websocket_connections[task_id].add(websocket)
        
        logger.debug(f"WebSocket connection added for task: {task_id}")
    
    async def remove_websocket_connection(self, task_id: str, websocket: Any) -> None:
        """Remove WebSocket connection.
        
        Args:
            task_id: Task ID being monitored
            websocket: WebSocket connection object
        """
        async with self._lock:
            if task_id in self.websocket_connections:
                self.websocket_connections[task_id].discard(websocket)
                if not self.websocket_connections[task_id]:
                    del self.websocket_connections[task_id]
        
        logger.debug(f"WebSocket connection removed for task: {task_id}")
    
    async def get_event_history(self, task_id: Optional[str] = None,
                               event_type: Optional[str] = None,
                               limit: int = 100) -> List[ProgressEvent]:
        """Get event history.
        
        Args:
            task_id: Filter by task ID (optional)
            event_type: Filter by event type (optional)
            limit: Maximum number of events to return
            
        Returns:
            List of ProgressEvent objects
        """
        async with self._lock:
            events = self.event_history.copy()
        
        # Apply filters
        if task_id:
            events = [e for e in events if e.task_id == task_id]
        
        if event_type:
            events = [e for e in events if e.event_type.value == event_type]
        
        # Return most recent events
        return events[-limit:] if limit > 0 else events
    
    async def _notify_subscribers(self, event: ProgressEvent) -> None:
        """Notify all subscribers of an event."""
        # Get subscribers for specific event type and wildcard subscribers
        event_subscribers = self.subscribers.get(event.event_type.value, [])
        wildcard_subscribers = self.subscribers.get('*', [])
        
        all_subscribers = event_subscribers + wildcard_subscribers
        
        # Call all subscribers
        for callback in all_subscribers:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event)
                else:
                    callback(event)
            except Exception as e:
                logger.error(f"Error in event subscriber: {e}")
    
    async def _broadcast_to_websockets(self, event: ProgressEvent) -> None:
        """Broadcast event to WebSocket connections."""
        # Get connections for specific task and wildcard connections
        task_connections = self.websocket_connections.get(event.task_id, set())
        wildcard_connections = self.websocket_connections.get('*', set())
        
        all_connections = task_connections | wildcard_connections
        
        if not all_connections:
            return
        
        event_data = event.to_json()
        
        # Send to all connections
        dead_connections = set()
        for websocket in all_connections:
            try:
                await websocket.send_text(event_data)
            except Exception as e:
                logger.error(f"Error sending WebSocket message: {e}")
                dead_connections.add(websocket)
        
        # Clean up dead connections
        if dead_connections:
            await self._cleanup_dead_connections(dead_connections)
    
    async def _cleanup_dead_connections(self, dead_connections: Set[Any]) -> None:
        """Clean up dead WebSocket connections."""
        async with self._lock:
            for task_id in list(self.websocket_connections.keys()):
                self.websocket_connections[task_id] -= dead_connections
                if not self.websocket_connections[task_id]:
                    del self.websocket_connections[task_id]
    
    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics."""
        async with self._lock:
            total_connections = sum(len(connections) for connections in self.websocket_connections.values())
            
            return {
                'total_connections': total_connections,
                'tasks_with_connections': len(self.websocket_connections),
                'event_history_size': len(self.event_history),
                'subscriber_count': sum(len(subs) for subs in self.subscribers.values()),
                'connection_details': {
                    task_id: len(connections) 
                    for task_id, connections in self.websocket_connections.items()
                }
            }
    
    async def clear_history(self, older_than: Optional[datetime] = None) -> int:
        """Clear event history.
        
        Args:
            older_than: Clear events older than this timestamp (optional)
            
        Returns:
            Number of events cleared
        """
        async with self._lock:
            if older_than is None:
                cleared_count = len(self.event_history)
                self.event_history.clear()
            else:
                original_count = len(self.event_history)
                self.event_history = [e for e in self.event_history if e.timestamp > older_than]
                cleared_count = original_count - len(self.event_history)
        
        if cleared_count > 0:
            logger.info(f"Cleared {cleared_count} events from history")
        
        return cleared_count


class ProgressEventEmitter:
    """Helper class for emitting progress events."""
    
    def __init__(self, event_bus: ProgressEventBus):
        """Initialize event emitter.
        
        Args:
            event_bus: ProgressEventBus instance
        """
        self.event_bus = event_bus
    
    async def task_created(self, task_id: str, progress_state: ProgressState) -> None:
        """Emit task created event."""
        event = ProgressEvent(
            event_type=ProgressEventType.TASK_CREATED,
            task_id=task_id,
            data={
                'scan_id': progress_state.scan_id,
                'scan_profile': progress_state.scan_profile,
                'target_info': progress_state.target_info
            }
        )
        await self.event_bus.emit(event)
    
    async def task_started(self, task_id: str, progress_state: ProgressState) -> None:
        """Emit task started event."""
        event = ProgressEvent(
            event_type=ProgressEventType.TASK_STARTED,
            task_id=task_id,
            data={
                'current_phase': progress_state.current_phase.value if progress_state.current_phase else None,
                'overall_progress': progress_state.overall_progress
            }
        )
        await self.event_bus.emit(event)
    
    async def task_progress(self, task_id: str, progress_state: ProgressState) -> None:
        """Emit task progress update event."""
        event = ProgressEvent(
            event_type=ProgressEventType.TASK_PROGRESS,
            task_id=task_id,
            data={
                'current_phase': progress_state.current_phase.value if progress_state.current_phase else None,
                'overall_progress': progress_state.overall_progress,
                'status': progress_state.status.value,
                'estimated_completion': progress_state.estimated_completion.isoformat() 
                                      if progress_state.estimated_completion else None,
                'phase_progress': {
                    phase.value: {
                        'progress': prog.progress_percentage,
                        'status': prog.status.value,
                        'current_step': prog.current_step
                    }
                    for phase, prog in progress_state.phase_progress.items()
                }
            }
        )
        await self.event_bus.emit(event)
    
    async def task_completed(self, task_id: str, progress_state: ProgressState) -> None:
        """Emit task completed event."""
        event = ProgressEvent(
            event_type=ProgressEventType.TASK_COMPLETED,
            task_id=task_id,
            data={
                'overall_progress': progress_state.overall_progress,
                'actual_completion': progress_state.actual_completion.isoformat() 
                                   if progress_state.actual_completion else None,
                'duration': (progress_state.actual_completion - progress_state.start_time).total_seconds()
                           if progress_state.actual_completion and progress_state.start_time else None
            }
        )
        await self.event_bus.emit(event)
    
    async def task_failed(self, task_id: str, progress_state: ProgressState, error: str) -> None:
        """Emit task failed event."""
        event = ProgressEvent(
            event_type=ProgressEventType.TASK_FAILED,
            task_id=task_id,
            data={
                'error': error,
                'overall_progress': progress_state.overall_progress,
                'failed_phases': [phase.value for phase in progress_state.get_failed_phases()],
                'errors': [error.to_dict() for error in progress_state.get_all_errors()]
            }
        )
        await self.event_bus.emit(event)
    
    async def checkpoint_created(self, task_id: str, checkpoint_id: str, phase: str) -> None:
        """Emit checkpoint created event."""
        event = ProgressEvent(
            event_type=ProgressEventType.CHECKPOINT_CREATED,
            task_id=task_id,
            data={
                'checkpoint_id': checkpoint_id,
                'phase': phase
            }
        )
        await self.event_bus.emit(event)
    
    async def error_occurred(self, task_id: str, error_type: str, message: str, 
                           recoverable: bool = True, phase: Optional[str] = None) -> None:
        """Emit error occurred event."""
        event = ProgressEvent(
            event_type=ProgressEventType.ERROR_OCCURRED,
            task_id=task_id,
            data={
                'error_type': error_type,
                'message': message,
                'recoverable': recoverable,
                'phase': phase
            }
        )
        await self.event_bus.emit(event)