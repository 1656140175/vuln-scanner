"""Core data structures for the scanning engine."""

import uuid
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class ScanPhase(Enum):
    """Scanning phases enumeration."""
    DISCOVERY = "discovery"           # Discovery phase
    RECONNAISSANCE = "reconnaissance" # Reconnaissance phase  
    ENUMERATION = "enumeration"       # Enumeration phase
    VULNERABILITY_SCAN = "vulnerability_scan"  # Vulnerability scanning
    EXPLOITATION = "exploitation"     # Exploitation verification (PoC only)
    POST_ANALYSIS = "post_analysis"   # Post-analysis phase


class ScanStatus(Enum):
    """Scan job status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class ScanSeverity(Enum):
    """Vulnerability severity enumeration."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanTarget:
    """Scan target definition."""
    target: str
    target_type: str  # ip, domain, url, network
    context: Dict[str, Any] = field(default_factory=dict)
    constraints: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize target ID after object creation."""
        self.target_id = str(uuid.uuid4())


@dataclass
class ScanResult:
    """Scan result representation."""
    scan_id: str
    target: ScanTarget
    phase: ScanPhase
    tool: str
    timestamp: datetime
    data: Dict[str, Any]
    severity: ScanSeverity = ScanSeverity.INFO
    confidence: float = 1.0
    false_positive_likelihood: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary format.
        
        Returns:
            Dictionary representation of the scan result
        """
        return {
            'scan_id': self.scan_id,
            'target': self.target.target,
            'target_id': self.target.target_id,
            'phase': self.phase.value,
            'tool': self.tool,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'false_positive_likelihood': self.false_positive_likelihood
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any], target: ScanTarget) -> 'ScanResult':
        """Create ScanResult from dictionary.
        
        Args:
            data: Dictionary containing scan result data
            target: ScanTarget object
            
        Returns:
            ScanResult instance
        """
        return cls(
            scan_id=data['scan_id'],
            target=target,
            phase=ScanPhase(data['phase']),
            tool=data['tool'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            data=data['data'],
            severity=ScanSeverity(data.get('severity', 'info')),
            confidence=data.get('confidence', 1.0),
            false_positive_likelihood=data.get('false_positive_likelihood', 0.0)
        )


@dataclass
class ScanJob:
    """Scan job definition."""
    job_id: str
    target: ScanTarget
    scan_profile: str
    status: ScanStatus = ScanStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: List[ScanResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    progress: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan job to dictionary format.
        
        Returns:
            Dictionary representation of the scan job
        """
        return {
            'job_id': self.job_id,
            'target': {
                'target': self.target.target,
                'target_type': self.target.target_type,
                'target_id': self.target.target_id,
                'context': self.target.context,
                'constraints': self.target.constraints
            },
            'scan_profile': self.scan_profile,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'results_count': len(self.results),
            'metadata': self.metadata,
            'error_message': self.error_message,
            'progress': self.progress
        }
    
    def add_result(self, result: ScanResult) -> None:
        """Add scan result to job.
        
        Args:
            result: ScanResult to add
        """
        self.results.append(result)
        
        # Update progress tracking
        phase = result.phase.value
        if 'phases' not in self.progress:
            self.progress['phases'] = {}
        
        if phase not in self.progress['phases']:
            self.progress['phases'][phase] = {'results': 0, 'last_update': None}
        
        self.progress['phases'][phase]['results'] += 1
        self.progress['phases'][phase]['last_update'] = datetime.now().isoformat()
    
    def get_results_by_phase(self, phase: ScanPhase) -> List[ScanResult]:
        """Get results for specific scan phase.
        
        Args:
            phase: Scan phase to filter by
            
        Returns:
            List of results for the specified phase
        """
        return [result for result in self.results if result.phase == phase]
    
    def get_results_by_severity(self, severity: ScanSeverity) -> List[ScanResult]:
        """Get results by severity level.
        
        Args:
            severity: Severity level to filter by
            
        Returns:
            List of results with the specified severity
        """
        return [result for result in self.results if result.severity == severity]
    
    def get_high_severity_results(self) -> List[ScanResult]:
        """Get high and critical severity results.
        
        Returns:
            List of high and critical severity results
        """
        return [result for result in self.results 
                if result.severity in [ScanSeverity.HIGH, ScanSeverity.CRITICAL]]