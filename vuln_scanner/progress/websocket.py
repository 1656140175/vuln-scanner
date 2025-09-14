"""WebSocket handler for real-time progress updates."""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from fastapi import WebSocket, WebSocketDisconnect
from contextlib import asynccontextmanager

from .events import ProgressEventBus, ProgressEvent
from .models import ProgressState, TaskStatus
from ..core.exceptions import BaseException


logger = logging.getLogger(__name__)


class class WebSocketException(BaseException):(VulnMinerException):
    """WebSocket specific exceptions."""
    pass


class ProgressWebSocketManager:
    """Manager for WebSocket connections and real-time progress updates."""
    
    def __init__(self, event_bus: ProgressEventBus):
        """Initialize WebSocket manager.
        
        Args:
            event_bus: ProgressEventBus for event handling
        """
        self.event_bus = event_bus
        
        # Active WebSocket connections organized by subscription type
        self.connections: Dict[str, Set[WebSocket]] = {
            'all': set(),  # Connections subscribed to all events
            'tasks': {},   # Connections subscribed to specific tasks
            'health': set(),  # Connections subscribed to health updates
        }
        
        # Connection metadata
        self.connection_metadata: Dict[WebSocket, Dict[str, Any]] = {}
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'messages_sent': 0,
            'connection_errors': 0,
            'disconnections': 0
        }
    
    async def connect(self, websocket: WebSocket, subscription_type: str = 'all',
                     task_id: Optional[str] = None) -> None:
        """Accept WebSocket connection and set up subscriptions.
        
        Args:
            websocket: WebSocket connection
            subscription_type: Type of subscription ('all', 'task', 'health')
            task_id: Task ID for task-specific subscriptions
        """
        try:
            await websocket.accept()
            
            # Track connection
            self.stats['total_connections'] += 1
            self.stats['active_connections'] += 1
            
            # Store connection metadata
            self.connection_metadata[websocket] = {
                'connected_at': datetime.now(),
                'subscription_type': subscription_type,
                'task_id': task_id,
                'messages_sent': 0,
                'last_ping': datetime.now()
            }
            
            # Add to appropriate subscription group
            if subscription_type == 'all':
                self.connections['all'].add(websocket)
                await self.event_bus.add_websocket_connection('*', websocket)
                
            elif subscription_type == 'task' and task_id:
                if 'tasks' not in self.connections:
                    self.connections['tasks'] = {}
                if task_id not in self.connections['tasks']:
                    self.connections['tasks'][task_id] = set()
                
                self.connections['tasks'][task_id].add(websocket)
                await self.event_bus.add_websocket_connection(task_id, websocket)
                
            elif subscription_type == 'health':
                self.connections['health'].add(websocket)
            
            # Send initial connection confirmation
            await self._send_message(websocket, {
                'type': 'connection_established',
                'subscription_type': subscription_type,
                'task_id': task_id,
                'timestamp': datetime.now().isoformat()
            })
            
            logger.info(f"WebSocket connection established: {subscription_type}" + 
                       (f" (task: {task_id})" if task_id else ""))
            
        except Exception as e:
            logger.error(f"Failed to establish WebSocket connection: {e}")
            self.stats['connection_errors'] += 1
            raise WebSocketException(f"Connection failed: {e}") from e
    
    async def disconnect(self, websocket: WebSocket) -> None:
        """Handle WebSocket disconnection cleanup.
        
        Args:
            websocket: WebSocket connection to disconnect
        """
        try:
            # Get connection metadata
            metadata = self.connection_metadata.get(websocket, {})
            subscription_type = metadata.get('subscription_type', 'unknown')
            task_id = metadata.get('task_id')
            
            # Remove from subscription groups
            if subscription_type == 'all':
                self.connections['all'].discard(websocket)
                await self.event_bus.remove_websocket_connection('*', websocket)
                
            elif subscription_type == 'task' and task_id:
                if task_id in self.connections.get('tasks', {}):
                    self.connections['tasks'][task_id].discard(websocket)
                    if not self.connections['tasks'][task_id]:
                        del self.connections['tasks'][task_id]
                await self.event_bus.remove_websocket_connection(task_id, websocket)
                
            elif subscription_type == 'health':
                self.connections['health'].discard(websocket)
            
            # Clean up metadata
            self.connection_metadata.pop(websocket, None)
            
            # Update statistics
            self.stats['active_connections'] = max(0, self.stats['active_connections'] - 1)
            self.stats['disconnections'] += 1
            
            logger.debug(f"WebSocket disconnection cleaned up: {subscription_type}")
            
        except Exception as e:
            logger.error(f"Error during WebSocket disconnection: {e}")
    
    async def send_progress_update(self, task_id: str, progress_state: ProgressState) -> None:
        """Send progress update to subscribed connections.
        
        Args:
            task_id: Task identifier
            progress_state: Current progress state
        """
        try:
            message = {
                'type': 'progress_update',
                'task_id': task_id,
                'data': {
                    'current_phase': progress_state.current_phase.value if progress_state.current_phase else None,
                    'overall_progress': progress_state.overall_progress,
                    'status': progress_state.status.value,
                    'estimated_completion': progress_state.estimated_completion.isoformat() 
                                          if progress_state.estimated_completion else None,
                    'last_update': progress_state.last_update.isoformat(),
                    'phase_progress': {
                        phase.value: {
                            'progress': prog.progress_percentage,
                            'status': prog.status.value,
                            'current_step': prog.current_step
                        }
                        for phase, prog in progress_state.phase_progress.items()
                        if prog.status != TaskStatus.PENDING
                    }
                },
                'timestamp': datetime.now().isoformat()
            }
            
            # Send to all subscribers
            await self._send_to_all_subscribers(websocket)
            
            # Send to task-specific subscribers
            if task_id in self.connections.get('tasks', {}):
                await self._send_to_task_subscribers(task_id, message)
            
        except Exception as e:
            logger.error(f"Failed to send progress update: {e}")
    
    async def send_health_update(self, health_data: Dict[str, Any]) -> None:
        """Send system health update to health subscribers.
        
        Args:
            health_data: System health information
        """
        try:
            message = {
                'type': 'health_update',
                'data': health_data,
                'timestamp': datetime.now().isoformat()
            }
            
            # Send to all subscribers
            await self._send_to_all_subscribers(message)
            
            # Send to health subscribers
            await self._send_to_health_subscribers(message)
            
        except Exception as e:
            logger.error(f"Failed to send health update: {e}")
    
    async def send_alert(self, alert: Dict[str, Any]) -> None:
        """Send alert to all relevant subscribers.
        
        Args:
            alert: Alert information
        """
        try:
            message = {
                'type': 'alert',
                'data': alert,
                'timestamp': datetime.now().isoformat()
            }
            
            # Send to all subscribers
            await self._send_to_all_subscribers(message)
            
            # Send to health subscribers
            await self._send_to_health_subscribers(message)
            
            # Send to specific task subscribers if task_id is present
            task_id = alert.get('task_id')
            if task_id and task_id in self.connections.get('tasks', {}):
                await self._send_to_task_subscribers(task_id, message)
            
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
    
    async def ping_connections(self) -> None:
        """Send ping to all connections to keep them alive."""
        try:
            ping_message = {
                'type': 'ping',
                'timestamp': datetime.now().isoformat()
            }
            
            dead_connections = set()
            
            # Ping all connections
            all_connections = set()
            all_connections.update(self.connections.get('all', set()))
            all_connections.update(self.connections.get('health', set()))
            
            for task_connections in self.connections.get('tasks', {}).values():
                all_connections.update(task_connections)
            
            for websocket in all_connections:
                try:
                    await self._send_message(websocket, ping_message)
                    # Update last ping time
                    if websocket in self.connection_metadata:
                        self.connection_metadata[websocket]['last_ping'] = datetime.now()
                except:
                    dead_connections.add(websocket)
            
            # Clean up dead connections
            for websocket in dead_connections:
                await self.disconnect(websocket)
            
        except Exception as e:
            logger.error(f"Error during connection ping: {e}")
    
    async def handle_client_message(self, websocket: WebSocket, message: str) -> None:
        """Handle incoming message from WebSocket client.
        
        Args:
            websocket: WebSocket connection
            message: Raw message from client
        """
        try:
            data = json.loads(message)
            message_type = data.get('type', 'unknown')
            
            if message_type == 'pong':
                # Update last ping time
                if websocket in self.connection_metadata:
                    self.connection_metadata[websocket]['last_ping'] = datetime.now()
                    
            elif message_type == 'subscribe':
                # Handle subscription change
                await self._handle_subscription_change(websocket, data)
                
            elif message_type == 'get_status':
                # Send current status
                await self._send_current_status(websocket, data.get('task_id'))
                
            else:
                logger.warning(f"Unknown message type from WebSocket client: {message_type}")
                
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON received from WebSocket client: {message}")
        except Exception as e:
            logger.error(f"Error handling client message: {e}")
    
    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get WebSocket connection statistics.
        
        Returns:
            Dictionary containing connection statistics
        """
        task_connections = sum(len(connections) for connections in self.connections.get('tasks', {}).values())
        
        return {
            'total_connections_ever': self.stats['total_connections'],
            'active_connections': self.stats['active_connections'],
            'messages_sent': self.stats['messages_sent'],
            'connection_errors': self.stats['connection_errors'],
            'disconnections': self.stats['disconnections'],
            'subscription_breakdown': {
                'all': len(self.connections.get('all', set())),
                'health': len(self.connections.get('health', set())),
                'task_specific': task_connections,
                'total_task_subscriptions': len(self.connections.get('tasks', {}))
            }
        }
    
    # Private methods
    
    async def _send_message(self, websocket: WebSocket, message: Dict[str, Any]) -> None:
        """Send message to specific WebSocket connection.
        
        Args:
            websocket: WebSocket connection
            message: Message to send
        """
        try:
            await websocket.send_text(json.dumps(message))
            
            # Update statistics
            self.stats['messages_sent'] += 1
            if websocket in self.connection_metadata:
                self.connection_metadata[websocket]['messages_sent'] += 1
                
        except Exception as e:
            logger.error(f"Failed to send WebSocket message: {e}")
            # Connection may be dead, mark for cleanup
            await self.disconnect(websocket)
    
    async def _send_to_all_subscribers(self, message: Dict[str, Any]) -> None:
        """Send message to all global subscribers.
        
        Args:
            message: Message to send
        """
        dead_connections = set()
        
        for websocket in self.connections.get('all', set()).copy():
            try:
                await self._send_message(websocket, message)
            except:
                dead_connections.add(websocket)
        
        # Clean up dead connections
        for websocket in dead_connections:
            await self.disconnect(websocket)
    
    async def _send_to_task_subscribers(self, task_id: str, message: Dict[str, Any]) -> None:
        """Send message to task-specific subscribers.
        
        Args:
            task_id: Task identifier
            message: Message to send
        """
        if task_id not in self.connections.get('tasks', {}):
            return
        
        dead_connections = set()
        
        for websocket in self.connections['tasks'][task_id].copy():
            try:
                await self._send_message(websocket, message)
            except:
                dead_connections.add(websocket)
        
        # Clean up dead connections
        for websocket in dead_connections:
            await self.disconnect(websocket)
    
    async def _send_to_health_subscribers(self, message: Dict[str, Any]) -> None:
        """Send message to health subscribers.
        
        Args:
            message: Message to send
        """
        dead_connections = set()
        
        for websocket in self.connections.get('health', set()).copy():
            try:
                await self._send_message(websocket, message)
            except:
                dead_connections.add(websocket)
        
        # Clean up dead connections
        for websocket in dead_connections:
            await self.disconnect(websocket)
    
    async def _handle_subscription_change(self, websocket: WebSocket, data: Dict[str, Any]) -> None:
        """Handle subscription change request from client.
        
        Args:
            websocket: WebSocket connection
            data: Subscription change data
        """
        try:
            # First disconnect from current subscriptions
            await self.disconnect(websocket)
            
            # Then connect with new subscription
            subscription_type = data.get('subscription_type', 'all')
            task_id = data.get('task_id')
            
            await self.connect(websocket, subscription_type, task_id)
            
        except Exception as e:
            logger.error(f"Failed to handle subscription change: {e}")
    
    async def _send_current_status(self, websocket: WebSocket, task_id: Optional[str] = None) -> None:
        """Send current status to client.
        
        Args:
            websocket: WebSocket connection
            task_id: Optional task ID for specific status
        """
        try:
            # This would integrate with progress manager to get current status
            # For now, send a placeholder response
            
            message = {
                'type': 'current_status',
                'task_id': task_id,
                'data': {
                    'status': 'Status retrieval not yet implemented',
                    'timestamp': datetime.now().isoformat()
                }
            }
            
            await self._send_message(websocket, message)
            
        except Exception as e:
            logger.error(f"Failed to send current status: {e}")


@asynccontextmanager
async def websocket_connection(websocket_manager: ProgressWebSocketManager,
                              websocket: WebSocket,
                              subscription_type: str = 'all',
                              task_id: Optional[str] = None):
    """Context manager for handling WebSocket connections.
    
    Args:
        websocket_manager: ProgressWebSocketManager instance
        websocket: WebSocket connection
        subscription_type: Type of subscription
        task_id: Task ID for task-specific subscriptions
    """
    try:
        await websocket_manager.connect(websocket, subscription_type, task_id)
        yield websocket_manager
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
    finally:
        await websocket_manager.disconnect(websocket)