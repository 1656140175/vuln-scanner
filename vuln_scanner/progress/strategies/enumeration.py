"""Enumeration phase checkpoint strategy."""

import logging
from typing import Dict, List, Any
from .base import CheckpointStrategy
from ..models import ProgressState


logger = logging.getLogger(__name__)


class EnumerationCheckpointStrategy(CheckpointStrategy):
    """Checkpoint strategy for the enumeration phase."""
    
    async def create_checkpoint(self, phase_data: Dict[str, Any],
                              progress_state: ProgressState) -> Dict[str, Any]:
        """Create checkpoint for enumeration phase.
        
        The enumeration phase typically contains:
        - Service enumeration results
        - Directory/file enumeration
        - User enumeration
        - Database enumeration
        - Application-specific enumeration
        """
        essential_data = self._extract_essential_data(phase_data)
        
        return {
            'phase_data': essential_data,
            'service_enumeration': essential_data.get('service_enumeration', {}),
            'directory_enumeration': essential_data.get('directory_enumeration', {}),
            'user_enumeration': essential_data.get('user_enumeration', {}),
            'database_enumeration': essential_data.get('database_enumeration', {}),
            'application_enumeration': essential_data.get('application_enumeration', {}),
            'enumeration_tools': essential_data.get('enumeration_tools', []),
            'found_endpoints': essential_data.get('found_endpoints', []),
            'found_users': essential_data.get('found_users', []),
            'found_databases': essential_data.get('found_databases', []),
            'completion_status': {
                'service_enum_complete': essential_data.get('service_enum_complete', False),
                'directory_enum_complete': essential_data.get('directory_enum_complete', False),
                'user_enum_complete': essential_data.get('user_enum_complete', False),
                'database_enum_complete': essential_data.get('database_enum_complete', False),
                'application_enum_complete': essential_data.get('application_enum_complete', False),
            },
            'metadata': self.get_checkpoint_metadata(phase_data),
            'progress_snapshot': {
                'endpoints_found': len(essential_data.get('found_endpoints', [])),
                'users_found': len(essential_data.get('found_users', [])),
                'databases_found': len(essential_data.get('found_databases', [])),
                'services_enumerated': len(essential_data.get('service_enumeration', {})),
                'phase_progress': progress_state.get_phase_progress(progress_state.current_phase).progress_percentage if progress_state.current_phase else 0
            }
        }
    
    async def restore_checkpoint(self, checkpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Restore enumeration phase data from checkpoint."""
        restored_data = {
            'service_enumeration': checkpoint_data.get('service_enumeration', {}),
            'directory_enumeration': checkpoint_data.get('directory_enumeration', {}),
            'user_enumeration': checkpoint_data.get('user_enumeration', {}),
            'database_enumeration': checkpoint_data.get('database_enumeration', {}),
            'application_enumeration': checkpoint_data.get('application_enumeration', {}),
            'enumeration_tools': checkpoint_data.get('enumeration_tools', []),
            'found_endpoints': checkpoint_data.get('found_endpoints', []),
            'found_users': checkpoint_data.get('found_users', []),
            'found_databases': checkpoint_data.get('found_databases', []),
            'service_enum_complete': checkpoint_data.get('completion_status', {}).get('service_enum_complete', False),
            'directory_enum_complete': checkpoint_data.get('completion_status', {}).get('directory_enum_complete', False),
            'user_enum_complete': checkpoint_data.get('completion_status', {}).get('user_enum_complete', False),
            'database_enum_complete': checkpoint_data.get('completion_status', {}).get('database_enum_complete', False),
            'application_enum_complete': checkpoint_data.get('completion_status', {}).get('application_enum_complete', False),
            'resume_point': 'checkpoint_restored',
            'restored_at': checkpoint_data.get('metadata', {}).get('created_at'),
        }
        
        # Merge any additional phase data
        if 'phase_data' in checkpoint_data:
            restored_data.update(checkpoint_data['phase_data'])
        
        logger.info(f"Restored enumeration phase: {len(restored_data.get('found_endpoints', []))} endpoints, "
                   f"{len(restored_data.get('found_users', []))} users, "
                   f"{len(restored_data.get('found_databases', []))} databases")
        
        return restored_data
    
    def validate_checkpoint(self, checkpoint_data: Dict[str, Any]) -> bool:
        """Validate enumeration phase checkpoint data."""
        required_keys = ['service_enumeration', 'found_endpoints', 'completion_status', 'metadata']
        
        if not self._validate_essential_keys(checkpoint_data, required_keys):
            return False
        
        # Validate data types
        if not isinstance(checkpoint_data.get('service_enumeration'), dict):
            return False
        
        if not isinstance(checkpoint_data.get('found_endpoints'), list):
            return False
        
        if not isinstance(checkpoint_data.get('found_users'), list):
            return False
        
        if not isinstance(checkpoint_data.get('completion_status'), dict):
            return False
        
        # Validate completion status structure
        completion_status = checkpoint_data.get('completion_status', {})
        required_completion_keys = [
            'service_enum_complete', 'directory_enum_complete', 'user_enum_complete',
            'database_enum_complete', 'application_enum_complete'
        ]
        
        for key in required_completion_keys:
            if key not in completion_status or not isinstance(completion_status[key], bool):
                return False
        
        return True
    
    def _extract_essential_data(self, phase_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract essential enumeration phase data."""
        essential_keys = [
            'service_enumeration', 'directory_enumeration', 'user_enumeration',
            'database_enumeration', 'application_enumeration', 'enumeration_tools',
            'found_endpoints', 'found_users', 'found_databases', 'service_enum_complete',
            'directory_enum_complete', 'user_enum_complete', 'database_enum_complete',
            'application_enum_complete', 'enumeration_metadata', 'enumeration_errors'
        ]
        
        essential_data = {}
        for key in essential_keys:
            if key in phase_data:
                essential_data[key] = phase_data[key]
        
        return essential_data