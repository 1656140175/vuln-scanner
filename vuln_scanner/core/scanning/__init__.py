"""Core scanning engine modules for VulnMiner."""

from .scan_engine import ScanEngine
from .data_structures import (
    ScanPhase, ScanStatus, ScanSeverity, 
    ScanTarget, ScanResult, ScanJob,
    PhaseStatus, PhaseResult
)
from .pipeline import ScanPipeline, PhaseExecutor
from .result_aggregator import ResultAggregator

__all__ = [
    'ScanEngine',
    'ScanPhase', 'ScanStatus', 'ScanSeverity',
    'ScanTarget', 'ScanResult', 'ScanJob',
    'PhaseStatus', 'PhaseResult',
    'ScanPipeline', 'PhaseExecutor',
    'ResultAggregator'
]