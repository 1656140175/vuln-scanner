"""Core progress manager integration for the scanning system."""

import asyncio
import logging
from typing import Dict, Any, Optional

from .manager import ProgressManager
from .queue import TaskQueue
from .monitor import ProgressMonitor
from .estimator import ProgressEstimator
from .events import ProgressEventBus
from .websocket import ProgressWebSocketManager
from .storage.sqlite import SqliteProgressStorage
from ..core.exceptions import BaseException


logger = logging.getLogger(__name__)


class ProgressSystemException(BaseException):
    """Progress system integration exceptions."""
    pass


class ProgressManagerFactory:
    """Factory for creating and managing progress system components."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize progress manager factory.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self._instances: Dict[str, Any] = {}
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize all progress system components."""
        if self._initialized:
            return
        
        logger.info("Initializing progress management system")
        
        try:
            # Initialize storage backend
            storage_config = self.config.get('storage', {})
            storage_type = storage_config.get('type', 'sqlite')
            
            if storage_type == 'sqlite':
                storage_path = storage_config.get('path', 'data/progress.db')
                storage = SqliteProgressStorage(db_path=storage_path)
            else:
                raise ProgressSystemException(f"Unsupported storage type: {storage_type}")
            
            await storage.initialize()
            self._instances['storage'] = storage
            
            # Initialize event bus
            event_bus_config = self.config.get('event_bus', {})
            event_bus = ProgressEventBus(
                max_event_history=event_bus_config.get('max_event_history', 1000)
            )
            self._instances['event_bus'] = event_bus
            
            # Initialize progress manager
            manager_config = self.config.get('progress_manager', {})
            progress_manager = ProgressManager(
                storage=storage,
                config=manager_config
            )
            await progress_manager.initialize()
            self._instances['progress_manager'] = progress_manager
            
            # Initialize task queue
            queue_config = self.config.get('task_queue', {})
            if queue_config.get('enabled', True):
                task_queue = TaskQueue(
                    max_concurrent=queue_config.get('max_concurrent', 5),
                    progress_manager=progress_manager
                )
                await task_queue.initialize()
                self._instances['task_queue'] = task_queue
            
            # Initialize progress monitor
            monitor_config = self.config.get('progress_monitor', {})
            if monitor_config.get('enabled', True):
                progress_monitor = ProgressMonitor(
                    progress_manager=progress_manager,
                    task_queue=self._instances.get('task_queue'),
                    storage=storage
                )
                await progress_monitor.initialize()
                self._instances['progress_monitor'] = progress_monitor
            
            # Initialize progress estimator
            estimator_config = self.config.get('progress_estimator', {})
            if estimator_config.get('enabled', True):
                progress_estimator = ProgressEstimator(storage=storage)
                await progress_estimator.initialize()
                self._instances['progress_estimator'] = progress_estimator
            
            # Initialize WebSocket manager
            websocket_config = self.config.get('websocket', {})
            if websocket_config.get('enabled', True):
                websocket_manager = ProgressWebSocketManager(event_bus)
                self._instances['websocket_manager'] = websocket_manager
            
            self._initialized = True
            logger.info("Progress management system initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize progress management system: {e}")
            await self.shutdown()
            raise ProgressSystemException(f"Initialization failed: {e}") from e
    
    async def shutdown(self) -> None:
        """Shutdown all progress system components."""
        if not self._initialized:
            return
        
        logger.info("Shutting down progress management system")
        
        # Shutdown components in reverse order
        for component_name in ['websocket_manager', 'progress_estimator', 
                              'progress_monitor', 'task_queue', 'progress_manager']:
            component = self._instances.get(component_name)
            if component and hasattr(component, 'shutdown'):
                try:
                    await component.shutdown()
                    logger.debug(f"Shutdown {component_name}")
                except Exception as e:
                    logger.error(f"Error shutting down {component_name}: {e}")
        
        # Shutdown storage last
        storage = self._instances.get('storage')
        if storage and hasattr(storage, 'cleanup'):
            try:
                await storage.cleanup()
                logger.debug("Shutdown storage")
            except Exception as e:
                logger.error(f"Error shutting down storage: {e}")
        
        self._instances.clear()
        self._initialized = False
        logger.info("Progress management system shutdown complete")
    
    def get_progress_manager(self) -> Optional[ProgressManager]:
        """Get progress manager instance."""
        return self._instances.get('progress_manager')
    
    def get_task_queue(self) -> Optional[TaskQueue]:
        """Get task queue instance."""
        return self._instances.get('task_queue')
    
    def get_progress_monitor(self) -> Optional[ProgressMonitor]:
        """Get progress monitor instance."""
        return self._instances.get('progress_monitor')
    
    def get_progress_estimator(self) -> Optional[ProgressEstimator]:
        """Get progress estimator instance."""
        return self._instances.get('progress_estimator')
    
    def get_websocket_manager(self) -> Optional[ProgressWebSocketManager]:
        """Get WebSocket manager instance."""
        return self._instances.get('websocket_manager')
    
    def get_event_bus(self) -> Optional[ProgressEventBus]:
        """Get event bus instance."""
        return self._instances.get('event_bus')
    
    def get_storage(self) -> Optional[Any]:
        """Get storage instance."""
        return self._instances.get('storage')
    
    def is_initialized(self) -> bool:
        """Check if system is initialized."""
        return self._initialized


# Global progress manager instance
_progress_factory: Optional[ProgressManagerFactory] = None


async def initialize_progress_system(config: Optional[Dict[str, Any]] = None) -> ProgressManagerFactory:
    """Initialize global progress management system.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        ProgressManagerFactory instance
    """
    global _progress_factory
    
    if _progress_factory is None:
        _progress_factory = ProgressManagerFactory(config)
        await _progress_factory.initialize()
    
    return _progress_factory


async def shutdown_progress_system() -> None:
    """Shutdown global progress management system."""
    global _progress_factory
    
    if _progress_factory:
        await _progress_factory.shutdown()
        _progress_factory = None


def get_progress_manager() -> Optional[ProgressManager]:
    """Get global progress manager instance."""
    global _progress_factory
    return _progress_factory.get_progress_manager() if _progress_factory else None


def get_task_queue() -> Optional[TaskQueue]:
    """Get global task queue instance."""
    global _progress_factory
    return _progress_factory.get_task_queue() if _progress_factory else None


def get_progress_monitor() -> Optional[ProgressMonitor]:
    """Get global progress monitor instance."""
    global _progress_factory
    return _progress_factory.get_progress_monitor() if _progress_factory else None


def get_progress_estimator() -> Optional[ProgressEstimator]:
    """Get global progress estimator instance."""
    global _progress_factory
    return _progress_factory.get_progress_estimator() if _progress_factory else None


def get_websocket_manager() -> Optional[ProgressWebSocketManager]:
    """Get global WebSocket manager instance."""
    global _progress_factory
    return _progress_factory.get_websocket_manager() if _progress_factory else None