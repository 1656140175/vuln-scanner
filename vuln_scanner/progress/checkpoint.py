"""Checkpoint and resume system for scan state persistence."""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Type
from abc import ABC, abstractmethod

from .models import CheckpointInfo, ProgressState
from .storage.base import ProgressStorage
from ..core.scanning.data_structures import ScanPhase
from ..core.exceptions import BaseException


logger = logging.getLogger(__name__)


class class CheckpointException(BaseException):(VulnMinerException):
    """Checkpoint system specific exceptions."""
    pass


class CheckpointStrategy(ABC):
    """Abstract base class for phase-specific checkpoint strategies."""
    
    @abstractmethod
    async def create_checkpoint(self, phase_data: Dict[str, Any], 
                              progress_state: ProgressState) -> Dict[str, Any]:
        """Create phase-specific checkpoint data.
        
        Args:
            phase_data: Current phase execution data
            progress_state: Current progress state
            
        Returns:
            Dictionary containing checkpoint data
        """
        pass
    
    @abstractmethod
    async def restore_checkpoint(self, checkpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Restore phase-specific data from checkpoint.
        
        Args:
            checkpoint_data: Checkpoint data to restore
            
        Returns:
            Dictionary containing restored phase data
        """
        pass
    
    @abstractmethod
    def validate_checkpoint(self, checkpoint_data: Dict[str, Any]) -> bool:
        """Validate checkpoint data integrity.
        
        Args:
            checkpoint_data: Checkpoint data to validate
            
        Returns:
            True if valid, False otherwise
        """
        pass
    
    def get_checkpoint_metadata(self, phase_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get metadata for checkpoint.
        
        Args:
            phase_data: Current phase data
            
        Returns:
            Dictionary containing checkpoint metadata
        """
        return {
            'created_at': datetime.now().isoformat(),
            'data_size': len(str(phase_data)),
            'keys': list(phase_data.keys()) if isinstance(phase_data, dict) else []
        }


class DefaultCheckpointStrategy(CheckpointStrategy):
    """Default checkpoint strategy for phases without specific strategies."""
    
    async def create_checkpoint(self, phase_data: Dict[str, Any],
                              progress_state: ProgressState) -> Dict[str, Any]:
        """Create default checkpoint data."""
        return {
            'phase_data': phase_data,
            'progress_snapshot': {
                'current_phase': progress_state.current_phase.value if progress_state.current_phase else None,
                'overall_progress': progress_state.overall_progress,
                'status': progress_state.status.value
            },
            'metadata': self.get_checkpoint_metadata(phase_data)
        }
    
    async def restore_checkpoint(self, checkpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Restore default checkpoint data."""
        return checkpoint_data.get('phase_data', {})
    
    def validate_checkpoint(self, checkpoint_data: Dict[str, Any]) -> bool:
        """Validate default checkpoint structure."""
        required_keys = ['phase_data', 'metadata']
        return all(key in checkpoint_data for key in required_keys)


class CheckpointManager:
    """Manager for checkpoint creation and restoration."""
    
    def __init__(self, storage: ProgressStorage):
        """Initialize checkpoint manager.
        
        Args:
            storage: Progress storage backend
        """
        self.storage = storage
        self.strategies: Dict[ScanPhase, CheckpointStrategy] = {}
        self.default_strategy = DefaultCheckpointStrategy()
        
        # Register default strategies
        self._register_default_strategies()
    
    def register_strategy(self, phase: ScanPhase, strategy: CheckpointStrategy) -> None:
        """Register checkpoint strategy for a phase.
        
        Args:
            phase: Scan phase
            strategy: Checkpoint strategy
        """
        self.strategies[phase] = strategy
        logger.debug(f"Registered checkpoint strategy for phase {phase.value}")
    
    def _register_default_strategies(self) -> None:
        """Register default checkpoint strategies for all phases."""
        # Import strategies to avoid circular imports
        from .strategies.discovery import DiscoveryCheckpointStrategy
        from .strategies.reconnaissance import ReconCheckpointStrategy
        from .strategies.enumeration import EnumerationCheckpointStrategy
        from .strategies.vulnerability_scan import VulnerabilityCheckpointStrategy
        from .strategies.exploitation import ExploitationCheckpointStrategy
        
        self.strategies.update({
            ScanPhase.DISCOVERY: DiscoveryCheckpointStrategy(),
            ScanPhase.RECONNAISSANCE: ReconCheckpointStrategy(),
            ScanPhase.ENUMERATION: EnumerationCheckpointStrategy(),
            ScanPhase.VULNERABILITY_SCAN: VulnerabilityCheckpointStrategy(),
            ScanPhase.EXPLOITATION: ExploitationCheckpointStrategy(),
            ScanPhase.POST_ANALYSIS: self.default_strategy  # Use default for post-analysis
        })
    
    async def create_checkpoint(self, task_id: str, phase: ScanPhase,
                               phase_data: Dict[str, Any],
                               progress_state: ProgressState) -> str:
        """Create checkpoint for task and phase.
        
        Args:
            task_id: Task identifier
            phase: Current scan phase
            phase_data: Phase-specific data
            progress_state: Current progress state
            
        Returns:
            Checkpoint ID
            
        Raises:
            CheckpointException: If checkpoint creation fails
        """
        try:
            # Get appropriate strategy
            strategy = self.strategies.get(phase, self.default_strategy)
            
            # Create checkpoint data
            checkpoint_data = await strategy.create_checkpoint(phase_data, progress_state)
            
            # Validate checkpoint data
            if not strategy.validate_checkpoint(checkpoint_data):
                raise CheckpointException(f"Invalid checkpoint data for phase {phase.value}")
            
            # Create checkpoint info
            checkpoint = CheckpointInfo(
                task_id=task_id,
                phase=phase,
                progress_state=progress_state.to_dict(),
                phase_data=checkpoint_data,
                metadata={
                    'strategy': strategy.__class__.__name__,
                    'validation_passed': True
                }
            )
            
            # Save checkpoint
            await self.storage.save_checkpoint(checkpoint)
            
            logger.info(f"Created checkpoint {checkpoint.checkpoint_id} for task {task_id}, phase {phase.value}")
            return checkpoint.checkpoint_id
            
        except Exception as e:
            raise CheckpointException(f"Failed to create checkpoint: {e}") from e
    
    async def restore_from_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """Restore data from checkpoint.
        
        Args:
            checkpoint_id: Checkpoint identifier
            
        Returns:
            Dictionary containing restored data
            
        Raises:
            CheckpointException: If restoration fails
        """
        try:
            # Load checkpoint
            checkpoint = await self.storage.load_checkpoint(checkpoint_id)
            if not checkpoint:
                raise CheckpointException(f"Checkpoint {checkpoint_id} not found")
            
            # Get appropriate strategy
            strategy = self.strategies.get(checkpoint.phase, self.default_strategy)
            
            # Validate checkpoint data
            if not strategy.validate_checkpoint(checkpoint.phase_data):
                raise CheckpointException(f"Checkpoint {checkpoint_id} data is invalid")
            
            # Restore phase data
            restored_phase_data = await strategy.restore_checkpoint(checkpoint.phase_data)
            
            # Restore progress state
            progress_state = None
            if checkpoint.progress_state:
                progress_state = ProgressState.from_dict(checkpoint.progress_state)
            
            return {
                'checkpoint_id': checkpoint_id,
                'task_id': checkpoint.task_id,
                'phase': checkpoint.phase,
                'timestamp': checkpoint.timestamp,
                'phase_data': restored_phase_data,
                'progress_state': progress_state,
                'metadata': checkpoint.metadata
            }
            
        except Exception as e:
            raise CheckpointException(f"Failed to restore from checkpoint {checkpoint_id}: {e}") from e
    
    async def restore_latest_checkpoint(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Restore from the latest checkpoint for a task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            Dictionary containing restored data, or None if no checkpoints exist
            
        Raises:
            CheckpointException: If restoration fails
        """
        try:
            # Get latest checkpoint
            checkpoint = await self.storage.get_latest_checkpoint(task_id)
            if not checkpoint:
                return None
            
            # Restore from checkpoint
            return await self.restore_from_checkpoint(checkpoint.checkpoint_id)
            
        except Exception as e:
            raise CheckpointException(f"Failed to restore latest checkpoint for task {task_id}: {e}") from e
    
    async def list_checkpoints(self, task_id: str) -> List[CheckpointInfo]:
        """List all checkpoints for a task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            List of CheckpointInfo objects
            
        Raises:
            CheckpointException: If listing fails
        """
        try:
            return await self.storage.list_checkpoints(task_id)
        except Exception as e:
            raise CheckpointException(f"Failed to list checkpoints for task {task_id}: {e}") from e
    
    async def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """Delete a checkpoint.
        
        Args:
            checkpoint_id: Checkpoint identifier
            
        Returns:
            True if deleted, False if not found
            
        Raises:
            CheckpointException: If deletion fails
        """
        try:
            return await self.storage.delete_checkpoint(checkpoint_id)
        except Exception as e:
            raise CheckpointException(f"Failed to delete checkpoint {checkpoint_id}: {e}") from e
    
    async def cleanup_old_checkpoints(self, task_id: str, keep_count: int = 5) -> int:
        """Clean up old checkpoints, keeping only the most recent ones.
        
        Args:
            task_id: Task identifier
            keep_count: Number of checkpoints to keep
            
        Returns:
            Number of checkpoints deleted
            
        Raises:
            CheckpointException: If cleanup fails
        """
        try:
            checkpoints = await self.list_checkpoints(task_id)
            
            if len(checkpoints) <= keep_count:
                return 0
            
            # Sort by timestamp (newest first) and delete old ones
            checkpoints.sort(key=lambda x: x.timestamp, reverse=True)
            old_checkpoints = checkpoints[keep_count:]
            
            deleted_count = 0
            for checkpoint in old_checkpoints:
                if await self.delete_checkpoint(checkpoint.checkpoint_id):
                    deleted_count += 1
            
            logger.info(f"Cleaned up {deleted_count} old checkpoints for task {task_id}")
            return deleted_count
            
        except Exception as e:
            raise CheckpointException(f"Failed to cleanup old checkpoints for task {task_id}: {e}") from e
    
    async def validate_checkpoint_integrity(self, checkpoint_id: str) -> bool:
        """Validate checkpoint data integrity.
        
        Args:
            checkpoint_id: Checkpoint identifier
            
        Returns:
            True if checkpoint is valid, False otherwise
        """
        try:
            checkpoint = await self.storage.load_checkpoint(checkpoint_id)
            if not checkpoint:
                return False
            
            # Get appropriate strategy
            strategy = self.strategies.get(checkpoint.phase, self.default_strategy)
            
            # Validate checkpoint data
            return strategy.validate_checkpoint(checkpoint.phase_data)
            
        except Exception as e:
            logger.error(f"Error validating checkpoint {checkpoint_id}: {e}")
            return False
    
    async def get_checkpoint_stats(self, task_id: Optional[str] = None) -> Dict[str, Any]:
        """Get checkpoint statistics.
        
        Args:
            task_id: Task identifier (optional, for all tasks if not specified)
            
        Returns:
            Dictionary containing checkpoint statistics
        """
        try:
            if task_id:
                checkpoints = await self.list_checkpoints(task_id)
                
                return {
                    'task_id': task_id,
                    'total_checkpoints': len(checkpoints),
                    'phases': {
                        phase.value: len([cp for cp in checkpoints if cp.phase == phase])
                        for phase in ScanPhase
                    },
                    'latest_checkpoint': checkpoints[0].timestamp.isoformat() if checkpoints else None
                }
            else:
                # Get storage stats for all checkpoints
                storage_stats = await self.storage.get_storage_stats()
                return {
                    'total_checkpoints': storage_stats.get('total_checkpoints', 0),
                    'storage_health': storage_stats.get('healthy', False)
                }
                
        except Exception as e:
            logger.error(f"Failed to get checkpoint stats: {e}")
            return {'error': str(e)}


class CheckpointRestorer:
    """Helper class for checkpoint restoration operations."""
    
    def __init__(self, checkpoint_manager: CheckpointManager):
        """Initialize checkpoint restorer.
        
        Args:
            checkpoint_manager: CheckpointManager instance
        """
        self.checkpoint_manager = checkpoint_manager
    
    async def restore_task_from_checkpoint(self, task_id: str, 
                                         checkpoint_id: Optional[str] = None) -> Dict[str, Any]:
        """Restore complete task state from checkpoint.
        
        Args:
            task_id: Task identifier
            checkpoint_id: Specific checkpoint ID (uses latest if not specified)
            
        Returns:
            Dictionary containing restored task state
            
        Raises:
            CheckpointException: If restoration fails
        """
        try:
            # Get checkpoint data
            if checkpoint_id:
                restored_data = await self.checkpoint_manager.restore_from_checkpoint(checkpoint_id)
            else:
                restored_data = await self.checkpoint_manager.restore_latest_checkpoint(task_id)
            
            if not restored_data:
                raise CheckpointException(f"No checkpoint found for task {task_id}")
            
            # Validate restored data
            if not self._validate_restored_data(restored_data):
                raise CheckpointException("Restored checkpoint data is invalid")
            
            logger.info(f"Successfully restored task {task_id} from checkpoint")
            return restored_data
            
        except Exception as e:
            raise CheckpointException(f"Failed to restore task {task_id}: {e}") from e
    
    def _validate_restored_data(self, data: Dict[str, Any]) -> bool:
        """Validate restored checkpoint data.
        
        Args:
            data: Restored data dictionary
            
        Returns:
            True if valid, False otherwise
        """
        required_keys = ['task_id', 'phase', 'phase_data']
        return all(key in data for key in required_keys)