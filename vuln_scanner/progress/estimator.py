"""Progress estimation and prediction algorithms."""

import asyncio
import logging
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque

from .models import PhaseTimingData, ProgressState
from .storage.base import ProgressStorage
from ..core.scanning.data_structures import ScanPhase
from ..core.exceptions import BaseException


logger = logging.getLogger(__name__)


class EstimationException(BaseException):
    """Progress estimation specific exceptions."""
    pass


@dataclass
class ComplexityMetrics:
    """Metrics for calculating target complexity."""
    target_count: int = 1
    port_count: int = 0
    service_count: int = 0
    subdomain_count: int = 0
    technology_count: int = 0
    vulnerability_count: int = 0
    
    def calculate_complexity_score(self) -> float:
        """Calculate overall complexity score (0.0 to 10.0).
        
        Returns:
            Complexity score
        """
        # Base score from target count
        score = min(self.target_count * 0.5, 2.0)
        
        # Port and service complexity
        score += min(self.port_count * 0.01, 1.0)
        score += min(self.service_count * 0.1, 1.5)
        
        # Discovery complexity
        score += min(self.subdomain_count * 0.05, 1.0)
        score += min(self.technology_count * 0.1, 1.0)
        
        # Vulnerability complexity
        score += min(self.vulnerability_count * 0.2, 3.5)
        
        return min(score, 10.0)


@dataclass
class PhaseEstimate:
    """Estimated duration and confidence for a phase."""
    phase: ScanPhase
    estimated_duration: timedelta
    confidence: float  # 0.0 to 1.0
    factors: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'phase': self.phase.value,
            'estimated_duration': self.estimated_duration.total_seconds(),
            'confidence': self.confidence,
            'factors': self.factors
        }


class ProgressEstimator:
    """Progress estimation and prediction system."""
    
    def __init__(self, storage: Optional[ProgressStorage] = None):
        """Initialize progress estimator.
        
        Args:
            storage: Storage backend for historical data
        """
        self.storage = storage
        
        # Historical timing data organized by phase
        self.historical_data: Dict[ScanPhase, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Phase weight multipliers (can be tuned based on experience)
        self.phase_weights = {
            ScanPhase.DISCOVERY: 1.0,
            ScanPhase.RECONNAISSANCE: 1.2,
            ScanPhase.ENUMERATION: 1.5,
            ScanPhase.VULNERABILITY_SCAN: 2.0,
            ScanPhase.EXPLOITATION: 1.8,
            ScanPhase.POST_ANALYSIS: 0.8
        }
        
        # Base duration estimates (fallback when no historical data)
        self.base_estimates = {
            ScanPhase.DISCOVERY: timedelta(minutes=10),
            ScanPhase.RECONNAISSANCE: timedelta(minutes=15),
            ScanPhase.ENUMERATION: timedelta(minutes=25),
            ScanPhase.VULNERABILITY_SCAN: timedelta(minutes=45),
            ScanPhase.EXPLOITATION: timedelta(minutes=30),
            ScanPhase.POST_ANALYSIS: timedelta(minutes=10)
        }
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize estimator and load historical data."""
        if self._initialized:
            return
        
        logger.info("Initializing progress estimator")
        
        # Load historical data from storage if available
        if self.storage:
            await self._load_historical_data()
        
        self._initialized = True
        logger.info("Progress estimator initialized")
    
    async def estimate_phase_duration(self, phase: ScanPhase, 
                                    complexity_metrics: ComplexityMetrics,
                                    scan_profile: str = "default") -> PhaseEstimate:
        """Estimate duration for a specific phase.
        
        Args:
            phase: Scan phase to estimate
            complexity_metrics: Target complexity metrics
            scan_profile: Scan profile name
            
        Returns:
            PhaseEstimate object
        """
        await self._ensure_initialized()
        
        try:
            complexity_score = complexity_metrics.calculate_complexity_score()
            
            # Get historical data for this phase
            historical_times = self._get_historical_times(phase, complexity_score)
            
            if historical_times:
                # Use statistical analysis of historical data
                estimated_duration, confidence = self._calculate_statistical_estimate(
                    historical_times, complexity_score
                )
            else:
                # Use base estimate with complexity adjustment
                estimated_duration, confidence = self._calculate_base_estimate(
                    phase, complexity_score
                )
            
            # Apply scan profile adjustments
            estimated_duration = self._apply_profile_adjustments(
                estimated_duration, scan_profile, phase
            )
            
            factors = {
                'complexity_score': complexity_score,
                'historical_samples': len(historical_times),
                'scan_profile': scan_profile,
                'phase_weight': self.phase_weights.get(phase, 1.0)
            }
            
            return PhaseEstimate(
                phase=phase,
                estimated_duration=estimated_duration,
                confidence=confidence,
                factors=factors
            )
            
        except Exception as e:
            raise EstimationException(f"Failed to estimate phase duration: {e}") from e
    
    async def estimate_total_duration(self, complexity_metrics: ComplexityMetrics,
                                    scan_profile: str = "default",
                                    phases: Optional[List[ScanPhase]] = None) -> Dict[str, Any]:
        """Estimate total duration for all phases.
        
        Args:
            complexity_metrics: Target complexity metrics
            scan_profile: Scan profile name
            phases: Specific phases to estimate (defaults to all)
            
        Returns:
            Dictionary containing total estimate and per-phase estimates
        """
        await self._ensure_initialized()
        
        if phases is None:
            phases = list(ScanPhase)
        
        try:
            phase_estimates = {}
            total_duration = timedelta()
            total_confidence = 0.0
            
            for phase in phases:
                estimate = await self.estimate_phase_duration(
                    phase, complexity_metrics, scan_profile
                )
                
                phase_estimates[phase.value] = estimate.to_dict()
                total_duration += estimate.estimated_duration
                total_confidence += estimate.confidence
            
            # Average confidence across phases
            avg_confidence = total_confidence / len(phases) if phases else 0.0
            
            # Add buffer time based on confidence (lower confidence = more buffer)
            buffer_multiplier = 1.0 + (0.5 * (1.0 - avg_confidence))
            buffered_duration = total_duration * buffer_multiplier
            
            return {
                'total_estimated_duration': total_duration.total_seconds(),
                'buffered_duration': buffered_duration.total_seconds(),
                'average_confidence': avg_confidence,
                'buffer_multiplier': buffer_multiplier,
                'phase_estimates': phase_estimates,
                'estimated_completion': (datetime.now() + buffered_duration).isoformat()
            }
            
        except Exception as e:
            raise EstimationException(f"Failed to estimate total duration: {e}") from e
    
    async def update_historical_data(self, timing_data: PhaseTimingData) -> None:
        """Update historical timing data.
        
        Args:
            timing_data: Phase timing data to add
        """
        await self._ensure_initialized()
        
        try:
            # Add to in-memory storage
            self.historical_data[timing_data.phase].append(timing_data)
            
            # Persist to storage if available
            if self.storage:
                await self._persist_timing_data(timing_data)
            
            logger.debug(f"Updated historical data for phase {timing_data.phase.value}")
            
        except Exception as e:
            logger.error(f"Failed to update historical data: {e}")
    
    async def predict_completion_time(self, progress_state: ProgressState) -> Optional[datetime]:
        """Predict completion time based on current progress.
        
        Args:
            progress_state: Current progress state
            
        Returns:
            Predicted completion time
        """
        await self._ensure_initialized()
        
        try:
            if not progress_state.start_time:
                return None
            
            current_time = datetime.now()
            elapsed_time = current_time - progress_state.start_time
            
            # Calculate progress velocity
            progress_velocity = progress_state.overall_progress / elapsed_time.total_seconds()
            
            if progress_velocity <= 0:
                return None
            
            # Estimate remaining time
            remaining_progress = 100.0 - progress_state.overall_progress
            estimated_remaining_seconds = remaining_progress / progress_velocity
            
            # Apply phase-specific adjustments
            adjustment_factor = self._calculate_phase_adjustment(progress_state)
            adjusted_remaining_seconds = estimated_remaining_seconds * adjustment_factor
            
            predicted_completion = current_time + timedelta(seconds=adjusted_remaining_seconds)
            
            logger.debug(f"Predicted completion for task {progress_state.task_id}: {predicted_completion}")
            
            return predicted_completion
            
        except Exception as e:
            logger.error(f"Failed to predict completion time: {e}")
            return None
    
    async def analyze_estimation_accuracy(self) -> Dict[str, Any]:
        """Analyze the accuracy of previous estimations.
        
        Returns:
            Dictionary containing accuracy metrics
        """
        await self._ensure_initialized()
        
        try:
            accuracy_data = {}
            
            for phase, timing_data in self.historical_data.items():
                if len(timing_data) < 2:
                    continue
                
                # Calculate estimation vs actual accuracy
                errors = []
                for data in timing_data:
                    if hasattr(data, 'estimated_duration') and hasattr(data, 'actual_duration'):
                        estimated = data.estimated_duration.total_seconds()
                        actual = data.actual_duration.total_seconds()
                        error_percentage = abs(estimated - actual) / actual * 100
                        errors.append(error_percentage)
                
                if errors:
                    accuracy_data[phase.value] = {
                        'mean_error_percentage': statistics.mean(errors),
                        'median_error_percentage': statistics.median(errors),
                        'std_dev': statistics.stdev(errors) if len(errors) > 1 else 0,
                        'sample_count': len(errors),
                        'accuracy_grade': self._grade_accuracy(statistics.mean(errors))
                    }
            
            return accuracy_data
            
        except Exception as e:
            logger.error(f"Failed to analyze estimation accuracy: {e}")
            return {}
    
    # Private methods
    
    async def _ensure_initialized(self) -> None:
        """Ensure estimator is initialized."""
        if not self._initialized:
            await self.initialize()
    
    async def _load_historical_data(self) -> None:
        """Load historical timing data from storage."""
        try:
            # This would load from storage - simplified for now
            logger.info("Historical data loading not yet implemented for storage backend")
        except Exception as e:
            logger.error(f"Failed to load historical data: {e}")
    
    async def _persist_timing_data(self, timing_data: PhaseTimingData) -> None:
        """Persist timing data to storage."""
        try:
            # This would persist to storage - simplified for now
            logger.debug("Timing data persistence not yet implemented for storage backend")
        except Exception as e:
            logger.error(f"Failed to persist timing data: {e}")
    
    def _get_historical_times(self, phase: ScanPhase, complexity_score: float) -> List[PhaseTimingData]:
        """Get historical timing data for similar complexity.
        
        Args:
            phase: Scan phase
            complexity_score: Target complexity score
            
        Returns:
            List of similar timing data
        """
        phase_data = self.historical_data.get(phase, deque())
        
        # Filter by similar complexity (within 20% range)
        complexity_tolerance = 0.2 * complexity_score
        
        similar_data = []
        for data in phase_data:
            if abs(data.complexity_score - complexity_score) <= complexity_tolerance:
                similar_data.append(data)
        
        return similar_data
    
    def _calculate_statistical_estimate(self, historical_times: List[PhaseTimingData],
                                       complexity_score: float) -> Tuple[timedelta, float]:
        """Calculate estimate using statistical analysis.
        
        Args:
            historical_times: Historical timing data
            complexity_score: Target complexity score
            
        Returns:
            Tuple of (estimated_duration, confidence)
        """
        if not historical_times:
            return timedelta(), 0.0
        
        durations = [data.actual_duration.total_seconds() for data in historical_times]
        
        # Use median as base estimate (more robust than mean)
        median_duration = statistics.median(durations)
        
        # Adjust based on complexity difference
        if len(historical_times) > 1:
            # Find correlation between complexity and duration
            complexities = [data.complexity_score for data in historical_times]
            
            # Simple linear adjustment
            avg_complexity = statistics.mean(complexities)
            complexity_ratio = complexity_score / avg_complexity if avg_complexity > 0 else 1.0
            
            adjusted_duration = median_duration * complexity_ratio
        else:
            adjusted_duration = median_duration
        
        # Calculate confidence based on data consistency
        if len(durations) > 1:
            std_dev = statistics.stdev(durations)
            cv = std_dev / statistics.mean(durations)  # Coefficient of variation
            confidence = max(0.1, 1.0 - cv)  # Lower CV = higher confidence
        else:
            confidence = 0.5  # Medium confidence with single data point
        
        return timedelta(seconds=adjusted_duration), confidence
    
    def _calculate_base_estimate(self, phase: ScanPhase, 
                               complexity_score: float) -> Tuple[timedelta, float]:
        """Calculate base estimate when no historical data available.
        
        Args:
            phase: Scan phase
            complexity_score: Target complexity score
            
        Returns:
            Tuple of (estimated_duration, confidence)
        """
        base_duration = self.base_estimates.get(phase, timedelta(minutes=20))
        
        # Apply complexity multiplier
        complexity_multiplier = 1.0 + (complexity_score / 10.0)  # Linear scaling
        adjusted_duration = base_duration * complexity_multiplier
        
        # Apply phase weight
        phase_weight = self.phase_weights.get(phase, 1.0)
        final_duration = adjusted_duration * phase_weight
        
        # Lower confidence for base estimates
        confidence = 0.3
        
        return final_duration, confidence
    
    def _apply_profile_adjustments(self, duration: timedelta, scan_profile: str,
                                 phase: ScanPhase) -> timedelta:
        """Apply scan profile adjustments to duration estimate.
        
        Args:
            duration: Base duration estimate
            scan_profile: Scan profile name
            phase: Scan phase
            
        Returns:
            Adjusted duration
        """
        # Profile-specific multipliers
        profile_multipliers = {
            'quick': 0.5,
            'normal': 1.0,
            'thorough': 1.8,
            'comprehensive': 2.5,
            'stealth': 1.3  # Slower due to rate limiting
        }
        
        multiplier = profile_multipliers.get(scan_profile, 1.0)
        
        # Some phases are more affected by profile changes
        phase_sensitivity = {
            ScanPhase.DISCOVERY: 0.8,
            ScanPhase.RECONNAISSANCE: 1.0,
            ScanPhase.ENUMERATION: 1.2,
            ScanPhase.VULNERABILITY_SCAN: 1.5,
            ScanPhase.EXPLOITATION: 1.0,
            ScanPhase.POST_ANALYSIS: 0.5
        }
        
        sensitivity = phase_sensitivity.get(phase, 1.0)
        effective_multiplier = 1.0 + ((multiplier - 1.0) * sensitivity)
        
        return duration * effective_multiplier
    
    def _calculate_phase_adjustment(self, progress_state: ProgressState) -> float:
        """Calculate adjustment factor based on current phase progress.
        
        Args:
            progress_state: Current progress state
            
        Returns:
            Adjustment factor
        """
        if not progress_state.current_phase:
            return 1.0
        
        # Get progress for current and upcoming phases
        current_phase = progress_state.current_phase
        phase_progress = progress_state.get_phase_progress(current_phase)
        
        if not phase_progress:
            return 1.0
        
        # If current phase is progressing slower than expected, adjust future estimates
        phase_list = list(ScanPhase)
        try:
            current_index = phase_list.index(current_phase)
            expected_phase_progress = ((current_index + 1) / len(phase_list)) * 100
            
            if phase_progress.progress_percentage < expected_phase_progress * 0.8:
                # Running behind schedule
                return 1.3
            elif phase_progress.progress_percentage > expected_phase_progress * 1.2:
                # Running ahead of schedule
                return 0.8
            else:
                return 1.0
                
        except ValueError:
            return 1.0
    
    def _grade_accuracy(self, mean_error_percentage: float) -> str:
        """Grade estimation accuracy.
        
        Args:
            mean_error_percentage: Mean error percentage
            
        Returns:
            Accuracy grade string
        """
        if mean_error_percentage <= 10:
            return "Excellent"
        elif mean_error_percentage <= 20:
            return "Good"
        elif mean_error_percentage <= 35:
            return "Fair"
        else:
            return "Poor"
    
    async def get_estimation_stats(self) -> Dict[str, Any]:
        """Get estimation system statistics.
        
        Returns:
            Dictionary containing statistics
        """
        await self._ensure_initialized()
        
        stats = {
            'total_historical_samples': sum(len(data) for data in self.historical_data.values()),
            'phases_with_data': len([phase for phase, data in self.historical_data.items() if data]),
            'estimation_accuracy': await self.analyze_estimation_accuracy(),
            'base_estimates': {
                phase.value: duration.total_seconds() 
                for phase, duration in self.base_estimates.items()
            },
            'phase_weights': {
                phase.value: weight 
                for phase, weight in self.phase_weights.items()
            }
        }
        
        return stats