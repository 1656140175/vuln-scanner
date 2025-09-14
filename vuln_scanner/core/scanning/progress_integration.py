"""Progress tracking integration for the scan engine."""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from contextlib import asynccontextmanager

from .data_structures import ScanPhase, ScanStatus, ScanTarget, ScanResult
from ..progress_manager import get_progress_manager, get_progress_estimator
from ...progress.models import TaskStatus, ProgressError
from ...progress.estimator import ComplexityMetrics


logger = logging.getLogger(__name__)


class ProgressTrackingMixin:
    """Mixin to add progress tracking capabilities to scan engines."""
    
    def __init__(self, *args, **kwargs):
        """Initialize progress tracking mixin."""
        super().__init__(*args, **kwargs)
        self.progress_manager = get_progress_manager()
        self.progress_estimator = get_progress_estimator()
        self._progress_task_ids: Dict[str, str] = {}  # scan_id -> progress_task_id
    
    async def create_progress_task(self, scan_id: str, scan_profile: str,
                                 target_info: Dict[str, Any],
                                 metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Create a progress tracking task for a scan.
        
        Args:
            scan_id: Scan identifier
            scan_profile: Scan profile name
            target_info: Target information
            metadata: Additional metadata
            
        Returns:
            Progress task ID if created successfully
        """
        if not self.progress_manager:
            logger.warning("Progress manager not available, skipping progress tracking")
            return None
        
        try:
            progress_task_id = await self.progress_manager.create_task(
                scan_id=scan_id,
                scan_profile=scan_profile,
                target_info=target_info,
                metadata=metadata or {}
            )
            
            self._progress_task_ids[scan_id] = progress_task_id
            
            # Start the progress task
            await self.progress_manager.start_task(progress_task_id)
            
            logger.debug(f"Created progress task {progress_task_id} for scan {scan_id}")
            return progress_task_id
            
        except Exception as e:
            logger.error(f"Failed to create progress task for scan {scan_id}: {e}")
            return None
    
    async def update_scan_progress(self, scan_id: str, phase: ScanPhase,
                                 progress: float, current_step: str = "",
                                 total_steps: Optional[int] = None,
                                 metadata: Optional[Dict[str, Any]] = None) -> None:
        """Update progress for a scan.
        
        Args:
            scan_id: Scan identifier
            phase: Current scan phase
            progress: Progress percentage (0-100)
            current_step: Description of current step
            total_steps: Total number of steps (optional)
            metadata: Additional metadata
        """
        if not self.progress_manager:
            return
        
        progress_task_id = self._progress_task_ids.get(scan_id)
        if not progress_task_id:
            logger.warning(f"No progress task found for scan {scan_id}")
            return
        
        try:
            await self.progress_manager.update_progress(
                task_id=progress_task_id,
                phase=phase,
                progress=progress,
                current_step=current_step,
                total_steps=total_steps,
                metadata=metadata
            )
            
            logger.debug(f"Updated progress for scan {scan_id}: {phase.value} - {progress:.1f}%")
            
        except Exception as e:
            logger.error(f"Failed to update progress for scan {scan_id}: {e}")
    
    async def complete_scan_phase(self, scan_id: str, phase: ScanPhase) -> None:
        """Mark a scan phase as completed.
        
        Args:
            scan_id: Scan identifier
            phase: Completed scan phase
        """
        if not self.progress_manager:
            return
        
        progress_task_id = self._progress_task_ids.get(scan_id)
        if not progress_task_id:
            return
        
        try:
            await self.progress_manager.complete_phase(progress_task_id, phase)
            logger.info(f"Completed phase {phase.value} for scan {scan_id}")
            
        except Exception as e:
            logger.error(f"Failed to complete phase {phase.value} for scan {scan_id}: {e}")
    
    async def fail_scan_with_error(self, scan_id: str, error_message: str,
                                 phase: Optional[ScanPhase] = None) -> None:
        """Mark a scan as failed with an error.
        
        Args:
            scan_id: Scan identifier
            error_message: Error description
            phase: Failed phase (optional)
        """
        if not self.progress_manager:
            return
        
        progress_task_id = self._progress_task_ids.get(scan_id)
        if not progress_task_id:
            return
        
        try:
            await self.progress_manager.fail_task(progress_task_id, error_message, phase)
            logger.error(f"Scan {scan_id} failed: {error_message}")
            
        except Exception as e:
            logger.error(f"Failed to mark scan {scan_id} as failed: {e}")
    
    async def create_scan_checkpoint(self, scan_id: str, 
                                   phase_data: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Create a checkpoint for scan state.
        
        Args:
            scan_id: Scan identifier
            phase_data: Phase-specific data to save
            
        Returns:
            Checkpoint ID if created successfully
        """
        if not self.progress_manager:
            return None
        
        progress_task_id = self._progress_task_ids.get(scan_id)
        if not progress_task_id:
            return None
        
        try:
            checkpoint_id = await self.progress_manager.checkpoint(progress_task_id, phase_data)
            logger.debug(f"Created checkpoint {checkpoint_id} for scan {scan_id}")
            return checkpoint_id
            
        except Exception as e:
            logger.error(f"Failed to create checkpoint for scan {scan_id}: {e}")
            return None
    
    async def estimate_scan_duration(self, target: ScanTarget, scan_profile: str = "normal") -> Optional[Dict[str, Any]]:
        """Estimate scan duration based on target complexity.
        
        Args:
            target: Scan target
            scan_profile: Scan profile name
            
        Returns:
            Duration estimate dictionary
        """
        if not self.progress_estimator:
            return None
        
        try:
            # Calculate complexity metrics based on target
            complexity_metrics = await self._calculate_target_complexity(target)
            
            # Get duration estimate
            estimate = await self.progress_estimator.estimate_total_duration(
                complexity_metrics=complexity_metrics,
                scan_profile=scan_profile
            )
            
            logger.debug(f"Estimated scan duration for {target.target}: {estimate['total_estimated_duration']:.1f}s")
            return estimate
            
        except Exception as e:
            logger.error(f"Failed to estimate scan duration: {e}")
            return None
    
    async def _calculate_target_complexity(self, target: ScanTarget) -> ComplexityMetrics:
        """Calculate complexity metrics for a target.
        
        Args:
            target: Scan target
            
        Returns:
            ComplexityMetrics object
        """
        # Base complexity calculation - can be enhanced with actual analysis
        complexity_metrics = ComplexityMetrics(
            target_count=1,
            port_count=target.constraints.get('port_count', 1000),  # Default port range
            service_count=target.constraints.get('expected_services', 10),
            subdomain_count=target.constraints.get('expected_subdomains', 5),
            technology_count=target.constraints.get('expected_technologies', 3),
            vulnerability_count=target.constraints.get('expected_vulnerabilities', 5)
        )
        
        # Adjust based on target type
        if target.target_type == 'network':
            # Network scans are more complex
            complexity_metrics.port_count *= 2
            complexity_metrics.service_count *= 1.5
        elif target.target_type == 'url':
            # Web application scans focus on different aspects
            complexity_metrics.technology_count *= 2
            complexity_metrics.vulnerability_count *= 1.5
        
        return complexity_metrics
    
    @asynccontextmanager
    async def progress_tracked_scan(self, scan_id: str, scan_profile: str,
                                   target_info: Dict[str, Any],
                                   metadata: Optional[Dict[str, Any]] = None):
        """Context manager for progress-tracked scanning.
        
        Args:
            scan_id: Scan identifier
            scan_profile: Scan profile name
            target_info: Target information
            metadata: Additional metadata
            
        Yields:
            Progress task ID
        """
        progress_task_id = await self.create_progress_task(
            scan_id=scan_id,
            scan_profile=scan_profile,
            target_info=target_info,
            metadata=metadata
        )
        
        try:
            yield progress_task_id
        except Exception as e:
            if progress_task_id:
                await self.fail_scan_with_error(scan_id, str(e))
            raise
        finally:
            # Clean up progress task reference
            self._progress_task_ids.pop(scan_id, None)
    
    def add_progress_hooks(self, scan_job):
        """Add progress tracking hooks to a scan job.
        
        Args:
            scan_job: ScanJob instance to add hooks to
        """
        original_add_result = scan_job.add_result
        
        def tracked_add_result(result):
            """Wrapper for add_result with progress tracking."""
            # Call original method
            original_add_result(result)
            
            # Update progress based on phase
            asyncio.create_task(self._update_progress_from_result(scan_job.job_id, result))
        
        scan_job.add_result = tracked_add_result
    
    async def _update_progress_from_result(self, scan_id: str, result: 'ScanResult') -> None:
        """Update progress based on scan result.
        
        Args:
            scan_id: Scan identifier
            result: Scan result
        """
        try:
            # Calculate progress based on phase and result
            phase_progress = self._calculate_phase_progress(result.phase, result)
            
            await self.update_scan_progress(
                scan_id=scan_id,
                phase=result.phase,
                progress=phase_progress['progress'],
                current_step=phase_progress['current_step'],
                metadata={'last_result': result.to_dict()}
            )
            
        except Exception as e:
            logger.error(f"Failed to update progress from result: {e}")
    
    def _calculate_phase_progress(self, phase: ScanPhase, result: 'ScanResult') -> Dict[str, Any]:
        """Calculate progress for a phase based on results.
        
        Args:
            phase: Scan phase
            result: Scan result
            
        Returns:
            Progress information dictionary
        """
        # Simple progress calculation - can be made more sophisticated
        progress_info = {
            'progress': 50.0,  # Default middle progress
            'current_step': f"Processing {result.tool} results"
        }
        
        # Phase-specific progress calculation
        if phase == ScanPhase.DISCOVERY:
            progress_info['current_step'] = f"Discovering targets with {result.tool}"
        elif phase == ScanPhase.RECONNAISSANCE:
            progress_info['current_step'] = f"Gathering intelligence with {result.tool}"
        elif phase == ScanPhase.ENUMERATION:
            progress_info['current_step'] = f"Enumerating services with {result.tool}"
        elif phase == ScanPhase.VULNERABILITY_SCAN:
            progress_info['current_step'] = f"Scanning vulnerabilities with {result.tool}"
        elif phase == ScanPhase.EXPLOITATION:
            progress_info['current_step'] = f"Testing exploits with {result.tool}"
        elif phase == ScanPhase.POST_ANALYSIS:
            progress_info['current_step'] = f"Analyzing results with {result.tool}"
        
        return progress_info


class ProgressTrackedScanEngine(ProgressTrackingMixin):
    """Scan engine with built-in progress tracking."""
    
    async def scan_target_with_progress(self, target: ScanTarget, scan_profile: str = "normal",
                                       metadata: Optional[Dict[str, Any]] = None) -> str:
        """Scan a target with progress tracking.
        
        Args:
            target: Target to scan
            scan_profile: Scan profile to use
            metadata: Additional metadata
            
        Returns:
            Scan job ID
        """
        scan_id = str(uuid.uuid4())
        
        # Create target info for progress tracking
        target_info = {
            "target": target.target,
            "target_type": target.target_type,
            "constraints": target.constraints,
            "context": target.context
        }
        
        # Estimate duration
        duration_estimate = await self.estimate_scan_duration(target, scan_profile)
        if duration_estimate:
            if not metadata:
                metadata = {}
            metadata['estimated_duration'] = duration_estimate
        
        # Use progress tracking context
        async with self.progress_tracked_scan(scan_id, scan_profile, target_info, metadata) as progress_task_id:
            # This would integrate with the existing scan logic
            logger.info(f"Starting progress-tracked scan {scan_id} for target {target.target}")
            
            # Simulate scan phases for demonstration
            phases = list(ScanPhase)
            for i, phase in enumerate(phases):
                await self.update_scan_progress(
                    scan_id=scan_id,
                    phase=phase,
                    progress=0.0,
                    current_step=f"Starting {phase.value} phase"
                )
                
                # Simulate phase work
                await asyncio.sleep(1)  # Replace with actual scan logic
                
                # Update progress during phase
                await self.update_scan_progress(
                    scan_id=scan_id,
                    phase=phase,
                    progress=50.0,
                    current_step=f"Processing {phase.value}"
                )
                
                await asyncio.sleep(1)  # Replace with actual scan logic
                
                # Complete phase
                await self.complete_scan_phase(scan_id, phase)
                
                # Create checkpoint periodically
                if i % 2 == 0:
                    await self.create_scan_checkpoint(scan_id, {"phase_data": f"Completed {phase.value}"})
        
        logger.info(f"Completed progress-tracked scan {scan_id}")
        return scan_id