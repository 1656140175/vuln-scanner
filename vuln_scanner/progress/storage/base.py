"""Base interface for progress data storage."""

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional

from ..models import ProgressState, CheckpointInfo


class ProgressStorage(ABC):
    """Abstract base class for progress data persistence."""
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize storage backend."""
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup storage resources."""
        pass
    
    @abstractmethod
    async def save_progress(self, progress: ProgressState) -> None:
        """Save progress state to storage.
        
        Args:
            progress: ProgressState to save
            
        Raises:
            StorageException: If save operation fails
        """
        pass
    
    @abstractmethod
    async def load_progress(self, task_id: str) -> Optional[ProgressState]:
        """Load progress state from storage.
        
        Args:
            task_id: Task identifier
            
        Returns:
            ProgressState if found, None otherwise
            
        Raises:
            StorageException: If load operation fails
        """
        pass
    
    @abstractmethod
    async def delete_progress(self, task_id: str) -> bool:
        """Delete progress state from storage.
        
        Args:
            task_id: Task identifier
            
        Returns:
            True if deleted, False if not found
            
        Raises:
            StorageException: If delete operation fails
        """
        pass
    
    @abstractmethod
    async def list_active_tasks(self) -> List[str]:
        """Get list of active task IDs.
        
        Returns:
            List of active task IDs
            
        Raises:
            StorageException: If list operation fails
        """
        pass
    
    @abstractmethod
    async def list_tasks_by_status(self, status: str) -> List[str]:
        """Get list of task IDs by status.
        
        Args:
            status: Task status to filter by
            
        Returns:
            List of task IDs with specified status
            
        Raises:
            StorageException: If list operation fails
        """
        pass
    
    @abstractmethod
    async def cleanup_completed_tasks(self, older_than: datetime) -> int:
        """Clean up completed tasks older than specified time.
        
        Args:
            older_than: Delete tasks completed before this time
            
        Returns:
            Number of tasks deleted
            
        Raises:
            StorageException: If cleanup operation fails
        """
        pass
    
    @abstractmethod
    async def save_checkpoint(self, checkpoint: CheckpointInfo) -> None:
        """Save checkpoint information.
        
        Args:
            checkpoint: CheckpointInfo to save
            
        Raises:
            StorageException: If save operation fails
        """
        pass
    
    @abstractmethod
    async def load_checkpoint(self, checkpoint_id: str) -> Optional[CheckpointInfo]:
        """Load checkpoint information.
        
        Args:
            checkpoint_id: Checkpoint identifier
            
        Returns:
            CheckpointInfo if found, None otherwise
            
        Raises:
            StorageException: If load operation fails
        """
        pass
    
    @abstractmethod
    async def list_checkpoints(self, task_id: str) -> List[CheckpointInfo]:
        """List all checkpoints for a task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            List of CheckpointInfo objects sorted by timestamp
            
        Raises:
            StorageException: If list operation fails
        """
        pass
    
    @abstractmethod
    async def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """Delete checkpoint from storage.
        
        Args:
            checkpoint_id: Checkpoint identifier
            
        Returns:
            True if deleted, False if not found
            
        Raises:
            StorageException: If delete operation fails
        """
        pass
    
    @abstractmethod
    async def get_latest_checkpoint(self, task_id: str) -> Optional[CheckpointInfo]:
        """Get the most recent checkpoint for a task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            Most recent CheckpointInfo if found, None otherwise
            
        Raises:
            StorageException: If operation fails
        """
        pass
    
    @abstractmethod
    async def update_task_metadata(self, task_id: str, metadata: Dict[str, Any]) -> None:
        """Update task metadata.
        
        Args:
            task_id: Task identifier
            metadata: Metadata to update
            
        Raises:
            StorageException: If update operation fails
        """
        pass
    
    @abstractmethod
    async def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics.
        
        Returns:
            Dictionary containing storage statistics
            
        Raises:
            StorageException: If stats operation fails
        """
        pass
    
    async def health_check(self) -> bool:
        """Check storage health.
        
        Returns:
            True if storage is healthy, False otherwise
        """
        try:
            stats = await self.get_storage_stats()
            return stats.get('healthy', False)
        except Exception:
            return False