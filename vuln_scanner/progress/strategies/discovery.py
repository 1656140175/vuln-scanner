"""Discovery phase checkpoint strategy."""

import logging
from typing import Dict, List, Any
from .base import CheckpointStrategy
from ..models import ProgressState


logger = logging.getLogger(__name__)


class DiscoveryCheckpointStrategy(CheckpointStrategy):
    """Checkpoint strategy for the discovery phase."""
    
    async def create_checkpoint(self, phase_data: Dict[str, Any],
                              progress_state: ProgressState) -> Dict[str, Any]:
        """Create checkpoint for discovery phase.
        
        The discovery phase typically contains:
        - Target enumeration results
        - DNS resolution data
        - Network topology information
        - Service discovery results
        """
        essential_data = self._extract_essential_data(phase_data)
        
        return {
            'phase_data': essential_data,
            'discovered_targets': essential_data.get('discovered_targets', []),
            'dns_records': essential_data.get('dns_records', {}),
            'network_info': essential_data.get('network_info', {}),
            'service_discovery': essential_data.get('service_discovery', {}),
            'discovery_methods': essential_data.get('discovery_methods', []),
            'completion_status': {
                'dns_resolution': essential_data.get('dns_resolution_complete', False),
                'port_discovery': essential_data.get('port_discovery_complete', False),
                'service_detection': essential_data.get('service_detection_complete', False),
            },
            'metadata': self.get_checkpoint_metadata(phase_data),
            'progress_snapshot': {
                'targets_discovered': len(essential_data.get('discovered_targets', [])),
                'services_found': len(essential_data.get('service_discovery', {})),
                'phase_progress': progress_state.get_phase_progress(progress_state.current_phase).progress_percentage if progress_state.current_phase else 0
            }
        }
    
    async def restore_checkpoint(self, checkpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Restore discovery phase data from checkpoint."""
        restored_data = {
            'discovered_targets': checkpoint_data.get('discovered_targets', []),
            'dns_records': checkpoint_data.get('dns_records', {}),
            'network_info': checkpoint_data.get('network_info', {}),
            'service_discovery': checkpoint_data.get('service_discovery', {}),
            'discovery_methods': checkpoint_data.get('discovery_methods', []),
            'dns_resolution_complete': checkpoint_data.get('completion_status', {}).get('dns_resolution', False),
            'port_discovery_complete': checkpoint_data.get('completion_status', {}).get('port_discovery', False),
            'service_detection_complete': checkpoint_data.get('completion_status', {}).get('service_detection', False),
            'resume_point': 'checkpoint_restored',
            'restored_at': checkpoint_data.get('metadata', {}).get('created_at'),
        }
        
        # Merge any additional phase data
        if 'phase_data' in checkpoint_data:
            restored_data.update(checkpoint_data['phase_data'])
        
        logger.info(f"Restored discovery phase: {len(restored_data.get('discovered_targets', []))} targets, "
                   f"{len(restored_data.get('service_discovery', {}))} services")
        
        return restored_data
    
    def validate_checkpoint(self, checkpoint_data: Dict[str, Any]) -> bool:
        """Validate discovery phase checkpoint data."""
        required_keys = ['discovered_targets', 'dns_records', 'completion_status', 'metadata']
        
        if not self._validate_essential_keys(checkpoint_data, required_keys):
            return False
        
        # Validate data types
        if not isinstance(checkpoint_data.get('discovered_targets'), list):
            return False
        
        if not isinstance(checkpoint_data.get('dns_records'), dict):
            return False
        
        if not isinstance(checkpoint_data.get('completion_status'), dict):
            return False
        
        # Validate completion status structure
        completion_status = checkpoint_data.get('completion_status', {})
        required_completion_keys = ['dns_resolution', 'port_discovery', 'service_detection']
        
        for key in required_completion_keys:
            if key not in completion_status or not isinstance(completion_status[key], bool):
                return False
        
        return True
    
    def _extract_essential_data(self, phase_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract essential discovery phase data."""
        essential_keys = [
            'discovered_targets', 'dns_records', 'network_info', 'service_discovery',
            'discovery_methods', 'dns_resolution_complete', 'port_discovery_complete',
            'service_detection_complete', 'target_metadata', 'discovery_errors'
        ]
        
        essential_data = {}
        for key in essential_keys:
            if key in phase_data:
                essential_data[key] = phase_data[key]
        
        return essential_data