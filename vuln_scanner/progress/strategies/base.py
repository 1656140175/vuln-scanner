"""Base checkpoint strategy interface."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional

from ..models import ProgressState


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
            'keys': list(phase_data.keys()) if isinstance(phase_data, dict) else [],
            'strategy': self.__class__.__name__
        }
    
    def _extract_essential_data(self, phase_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract essential data that must be preserved.
        
        Args:
            phase_data: Full phase data
            
        Returns:
            Dictionary containing essential data
        """
        # Base implementation - subclasses should override
        return phase_data.copy()
    
    def _validate_essential_keys(self, checkpoint_data: Dict[str, Any], 
                                required_keys: List[str]) -> bool:
        """Validate that essential keys are present.
        
        Args:
            checkpoint_data: Checkpoint data to validate
            required_keys: List of required keys
            
        Returns:
            True if all required keys are present
        """
        return all(key in checkpoint_data for key in required_keys)