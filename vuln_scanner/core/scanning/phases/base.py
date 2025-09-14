"""Base phase class with common functionality."""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, List, Optional

from ..data_structures import (
    ScanPhase, PhaseStatus, PhaseResult, ScanResult, ScanTarget
)
from ...exceptions import ScanEngineException
from ...logger import get_logger


class PhaseExecutionError(ScanEngineException):
    """Phase execution specific error."""
    pass


class BasePhase(ABC):
    """Base class for all scanning phases."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize base phase.
        
        Args:
            config: Phase configuration
        """
        self.config = config
        self.logger = get_logger(self.__class__.__name__)
        self._phase_name = self.get_phase_name()
        
        # Phase-specific configuration
        self.max_retries = config.get('max_retries', 3)
        self.timeout = config.get('timeout', 300)  # 5 minutes default
        self.concurrent_limit = config.get('concurrent_limit', 10)
        
    @property
    @abstractmethod 
    def phase(self) -> ScanPhase:
        """Phase identifier."""
        pass
    
    @abstractmethod
    async def execute_phase_logic(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Execute phase-specific logic.
        
        Args:
            inputs: Input data for the phase
            
        Returns:
            Phase execution results
        """
        pass
    
    @abstractmethod
    def validate_inputs(self, inputs: Dict[str, Any]) -> None:
        """Validate phase inputs.
        
        Args:
            inputs: Input data to validate
            
        Raises:
            PhaseExecutionError: If inputs are invalid
        """
        pass
    
    @abstractmethod
    def prepare_next_phase_inputs(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare inputs for the next phase.
        
        Args:
            results: Current phase results
            
        Returns:
            Input data for next phase
        """
        pass
    
    def get_phase_name(self) -> str:
        """Get human-readable phase name."""
        return self.__class__.__name__.replace('Phase', '').lower()
    
    async def execute(self, inputs: Dict[str, Any]) -> PhaseResult:
        """Execute the phase with error handling and monitoring.
        
        Args:
            inputs: Input data for the phase
            
        Returns:
            PhaseResult with execution details
        """
        start_time = datetime.now()
        phase_result = PhaseResult(
            phase=self.phase,
            status=PhaseStatus.RUNNING,
            start_time=start_time
        )
        
        self.logger.info(f"Starting {self._phase_name} phase")
        
        try:
            # Validate inputs
            self.validate_inputs(inputs)
            
            # Execute phase with timeout
            results = await asyncio.wait_for(
                self.execute_phase_logic(inputs),
                timeout=self.timeout
            )
            
            # Prepare outputs
            phase_result.data = results
            phase_result.next_phase_inputs = self.prepare_next_phase_inputs(results)
            phase_result.status = PhaseStatus.COMPLETED
            phase_result.end_time = datetime.now()
            
            # Calculate metrics
            duration = (phase_result.end_time - start_time).total_seconds()
            phase_result.metrics = {
                'duration_seconds': duration,
                'items_processed': results.get('items_processed', 0),
                'success_rate': results.get('success_rate', 1.0)
            }
            
            self.logger.info(f"Completed {self._phase_name} phase in {duration:.2f}s")
            
        except asyncio.TimeoutError:
            error_msg = f"Phase {self._phase_name} timed out after {self.timeout}s"
            self.logger.error(error_msg)
            phase_result.add_error(error_msg)
            phase_result.status = PhaseStatus.FAILED
            phase_result.end_time = datetime.now()
            
        except Exception as e:
            error_msg = f"Phase {self._phase_name} failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            phase_result.add_error(error_msg)
            phase_result.status = PhaseStatus.FAILED
            phase_result.end_time = datetime.now()
        
        return phase_result
    
    async def execute_with_retry(self, inputs: Dict[str, Any]) -> PhaseResult:
        """Execute phase with retry logic.
        
        Args:
            inputs: Input data for the phase
            
        Returns:
            PhaseResult with execution details
        """
        last_result = None
        
        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                self.logger.warning(f"Retrying {self._phase_name} phase (attempt {attempt + 1}/{self.max_retries + 1})")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            
            result = await self.execute(inputs)
            last_result = result
            
            if result.is_successful():
                return result
            
            if attempt == self.max_retries:
                self.logger.error(f"Phase {self._phase_name} failed after {self.max_retries + 1} attempts")
        
        return last_result
    
    def create_scan_result(self, target: ScanTarget, tool: str, data: Dict[str, Any], **kwargs) -> ScanResult:
        """Create a standardized scan result.
        
        Args:
            target: Scan target
            tool: Tool name that generated the result
            data: Result data
            **kwargs: Additional result parameters
            
        Returns:
            ScanResult instance
        """
        return ScanResult(
            scan_id=kwargs.get('scan_id', 'unknown'),
            target=target,
            phase=self.phase,
            tool=tool,
            timestamp=datetime.now(),
            data=data,
            severity=kwargs.get('severity'),
            confidence=kwargs.get('confidence', 1.0),
            false_positive_likelihood=kwargs.get('false_positive_likelihood', 0.0)
        )
    
    def validate_target(self, target_str: str) -> None:
        """Basic target validation.
        
        Args:
            target_str: Target string to validate
            
        Raises:
            PhaseExecutionError: If target is invalid
        """
        if not target_str or not isinstance(target_str, str):
            raise PhaseExecutionError("Target must be a non-empty string")
        
        if target_str.strip() != target_str:
            raise PhaseExecutionError("Target contains leading/trailing whitespace")
    
    async def run_parallel_tasks(self, tasks: List, max_concurrent: Optional[int] = None) -> List:
        """Run tasks in parallel with concurrency control.
        
        Args:
            tasks: List of coroutines to execute
            max_concurrent: Maximum concurrent tasks (defaults to self.concurrent_limit)
            
        Returns:
            List of task results
        """
        if not tasks:
            return []
        
        max_concurrent = max_concurrent or self.concurrent_limit
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def bounded_task(task):
            async with semaphore:
                return await task
        
        bounded_tasks = [bounded_task(task) for task in tasks]
        return await asyncio.gather(*bounded_tasks, return_exceptions=True)
    
    def filter_successful_results(self, results: List) -> List:
        """Filter out exceptions from parallel task results.
        
        Args:
            results: List of task results (may contain exceptions)
            
        Returns:
            List of successful results only
        """
        successful_results = []
        for result in results:
            if isinstance(result, Exception):
                self.logger.warning(f"Task failed: {result}")
            else:
                successful_results.append(result)
        
        return successful_results