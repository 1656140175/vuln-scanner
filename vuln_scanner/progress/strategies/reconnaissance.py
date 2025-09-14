"""Reconnaissance phase checkpoint strategy."""

import logging
from typing import Dict, List, Any
from .base import CheckpointStrategy
from ..models import ProgressState


logger = logging.getLogger(__name__)


class ReconCheckpointStrategy(CheckpointStrategy):
    """Checkpoint strategy for the reconnaissance phase."""
    
    async def create_checkpoint(self, phase_data: Dict[str, Any],
                              progress_state: ProgressState) -> Dict[str, Any]:
        """Create checkpoint for reconnaissance phase.
        
        The reconnaissance phase typically contains:
        - OSINT gathering results
        - Subdomain enumeration data
        - Technology stack identification
        - Certificate information
        - Social media/public information
        """
        essential_data = self._extract_essential_data(phase_data)
        
        return {
            'phase_data': essential_data,
            'osint_results': essential_data.get('osint_results', {}),
            'subdomains': essential_data.get('subdomains', []),
            'technology_stack': essential_data.get('technology_stack', {}),
            'certificates': essential_data.get('certificates', {}),
            'public_information': essential_data.get('public_information', {}),
            'social_media_data': essential_data.get('social_media_data', {}),
            'reconnaissance_tools': essential_data.get('reconnaissance_tools', []),
            'completion_status': {
                'osint_complete': essential_data.get('osint_complete', False),
                'subdomain_enum_complete': essential_data.get('subdomain_enum_complete', False),
                'tech_stack_complete': essential_data.get('tech_stack_complete', False),
                'certificate_enum_complete': essential_data.get('certificate_enum_complete', False),
            },
            'metadata': self.get_checkpoint_metadata(phase_data),
            'progress_snapshot': {
                'subdomains_found': len(essential_data.get('subdomains', [])),
                'osint_sources_processed': len(essential_data.get('osint_results', {})),
                'technologies_identified': len(essential_data.get('technology_stack', {})),
                'phase_progress': progress_state.get_phase_progress(progress_state.current_phase).progress_percentage if progress_state.current_phase else 0
            }
        }
    
    async def restore_checkpoint(self, checkpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Restore reconnaissance phase data from checkpoint."""
        restored_data = {
            'osint_results': checkpoint_data.get('osint_results', {}),
            'subdomains': checkpoint_data.get('subdomains', []),
            'technology_stack': checkpoint_data.get('technology_stack', {}),
            'certificates': checkpoint_data.get('certificates', {}),
            'public_information': checkpoint_data.get('public_information', {}),
            'social_media_data': checkpoint_data.get('social_media_data', {}),
            'reconnaissance_tools': checkpoint_data.get('reconnaissance_tools', []),
            'osint_complete': checkpoint_data.get('completion_status', {}).get('osint_complete', False),
            'subdomain_enum_complete': checkpoint_data.get('completion_status', {}).get('subdomain_enum_complete', False),
            'tech_stack_complete': checkpoint_data.get('completion_status', {}).get('tech_stack_complete', False),
            'certificate_enum_complete': checkpoint_data.get('completion_status', {}).get('certificate_enum_complete', False),
            'resume_point': 'checkpoint_restored',
            'restored_at': checkpoint_data.get('metadata', {}).get('created_at'),
        }
        
        # Merge any additional phase data
        if 'phase_data' in checkpoint_data:
            restored_data.update(checkpoint_data['phase_data'])
        
        logger.info(f"Restored reconnaissance phase: {len(restored_data.get('subdomains', []))} subdomains, "
                   f"{len(restored_data.get('technology_stack', {}))} technologies identified")
        
        return restored_data
    
    def validate_checkpoint(self, checkpoint_data: Dict[str, Any]) -> bool:
        """Validate reconnaissance phase checkpoint data."""
        required_keys = ['osint_results', 'subdomains', 'technology_stack', 'completion_status', 'metadata']
        
        if not self._validate_essential_keys(checkpoint_data, required_keys):
            return False
        
        # Validate data types
        if not isinstance(checkpoint_data.get('osint_results'), dict):
            return False
        
        if not isinstance(checkpoint_data.get('subdomains'), list):
            return False
        
        if not isinstance(checkpoint_data.get('technology_stack'), dict):
            return False
        
        if not isinstance(checkpoint_data.get('completion_status'), dict):
            return False
        
        # Validate completion status structure
        completion_status = checkpoint_data.get('completion_status', {})
        required_completion_keys = ['osint_complete', 'subdomain_enum_complete', 'tech_stack_complete', 'certificate_enum_complete']
        
        for key in required_completion_keys:
            if key not in completion_status or not isinstance(completion_status[key], bool):
                return False
        
        return True
    
    def _extract_essential_data(self, phase_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract essential reconnaissance phase data."""
        essential_keys = [
            'osint_results', 'subdomains', 'technology_stack', 'certificates',
            'public_information', 'social_media_data', 'reconnaissance_tools',
            'osint_complete', 'subdomain_enum_complete', 'tech_stack_complete',
            'certificate_enum_complete', 'recon_metadata', 'recon_errors'
        ]
        
        essential_data = {}
        for key in essential_keys:
            if key in phase_data:
                essential_data[key] = phase_data[key]
        
        return essential_data