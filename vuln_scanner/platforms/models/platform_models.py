"""Platform integration data models for bug bounty platforms."""

import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum


class PlatformType(Enum):
    """Supported platform types."""
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd" 
    INTIGRITI = "intigriti"
    OPENBUGBOUNTY = "openbugbounty"
    CUSTOM = "custom"


class SubmissionStatus(Enum):
    """Submission status states."""
    PENDING = "pending"
    SUBMITTED = "submitted"
    TRIAGED = "triaged"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"
    INFORMATIVE = "informative"
    SPAM = "spam"
    REJECTED = "rejected"
    RETESTING = "retesting"
    CLOSED = "closed"


class RewardStatus(Enum):
    """Reward status states."""
    NONE = "none"
    PENDING = "pending"
    AWARDED = "awarded"
    PAID = "paid"
    BOUNTY_ELIGIBLE = "bounty_eligible"
    BOUNTY_INELIGIBLE = "bounty_ineligible"
    REPUTATION_ONLY = "reputation_only"


class SeverityMapping(Enum):
    """Platform-specific severity mappings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium" 
    LOW = "low"
    INFORMATIONAL = "informational"
    NONE = "none"


@dataclass
class PlatformCredentials:
    """Platform authentication credentials."""
    platform: PlatformType
    username: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    api_token: Optional[str] = None
    api_key: Optional[str] = None
    secret_key: Optional[str] = None
    session_token: Optional[str] = None
    additional_headers: Dict[str, str] = field(default_factory=dict)
    additional_params: Dict[str, Any] = field(default_factory=dict)
    
    def is_valid(self) -> bool:
        """Check if credentials have required fields for the platform."""
        if self.platform == PlatformType.HACKERONE:
            return bool(self.username and self.api_token)
        elif self.platform == PlatformType.BUGCROWD:
            return bool(self.email and self.password)
        elif self.platform == PlatformType.INTIGRITI:
            return bool(self.api_key and self.secret_key)
        elif self.platform == PlatformType.OPENBUGBOUNTY:
            return bool(self.username and self.password)
        return bool(self.api_key or self.api_token)


@dataclass
class PlatformConfig:
    """Platform configuration settings."""
    platform: PlatformType
    enabled: bool = True
    base_url: Optional[str] = None
    rate_limit_per_hour: int = 60
    rate_limit_per_minute: int = 10
    retry_config: Dict[str, int] = field(default_factory=lambda: {
        "max_retries": 3,
        "backoff_factor": 2,
        "timeout_seconds": 30
    })
    custom_headers: Dict[str, str] = field(default_factory=dict)
    submission_settings: Dict[str, Any] = field(default_factory=dict)
    severity_mapping: Dict[str, str] = field(default_factory=dict)


@dataclass
class PlatformSubmissionData:
    """Data structure for platform vulnerability submissions."""
    title: str
    description: str
    severity: str
    target: str
    proof_of_concept: str
    impact: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_references: List[str] = field(default_factory=list)
    cve_references: List[str] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    steps_to_reproduce: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    platform_specific_fields: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    weakness_type: Optional[str] = None
    attack_vector: Optional[str] = None
    remediation_advice: Optional[str] = None
    business_impact: Optional[str] = None
    technical_impact: Optional[str] = None
    
    # Metadata
    submission_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.now)
    source_report_id: Optional[str] = None
    source_scan_id: Optional[str] = None


@dataclass
class SubmissionResult:
    """Result of a platform submission."""
    platform: PlatformType
    submission_id: str
    platform_report_id: Optional[str] = None
    status: SubmissionStatus = SubmissionStatus.PENDING
    success: bool = False
    error_message: Optional[str] = None
    response_data: Dict[str, Any] = field(default_factory=dict)
    submitted_at: datetime = field(default_factory=datetime.now)
    submission_url: Optional[str] = None
    tracking_id: Optional[str] = None


@dataclass
class PlatformReportStatus:
    """Status tracking for platform reports."""
    platform: PlatformType
    platform_report_id: str
    submission_id: str
    current_status: SubmissionStatus
    status_history: List[Dict[str, Any]] = field(default_factory=list)
    last_checked: datetime = field(default_factory=datetime.now)
    next_check_at: Optional[datetime] = None
    triager_username: Optional[str] = None
    triage_date: Optional[datetime] = None
    resolution_date: Optional[datetime] = None
    resolution_notes: Optional[str] = None
    duplicate_of: Optional[str] = None
    feedback: Optional[str] = None
    severity_assigned: Optional[str] = None
    priority_score: Optional[float] = None
    public_disclosure_date: Optional[datetime] = None
    
    def add_status_update(self, new_status: SubmissionStatus, notes: Optional[str] = None):
        """Add a new status update to history."""
        update = {
            "status": new_status,
            "timestamp": datetime.now(),
            "previous_status": self.current_status,
            "notes": notes
        }
        self.status_history.append(update)
        self.current_status = new_status
        self.last_checked = datetime.now()


@dataclass
class RewardInfo:
    """Reward information for a report."""
    platform: PlatformType
    platform_report_id: str
    reward_status: RewardStatus
    bounty_amount: Optional[float] = None
    currency: str = "USD"
    bonus_amount: Optional[float] = None
    reputation_points: Optional[int] = None
    awarded_date: Optional[datetime] = None
    paid_date: Optional[datetime] = None
    payment_method: Optional[str] = None
    payment_reference: Optional[str] = None
    award_details: Dict[str, Any] = field(default_factory=dict)
    tax_information: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PlatformReward:
    """Comprehensive reward tracking."""
    reward_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    platform: PlatformType = PlatformType.CUSTOM
    platform_report_id: str = ""
    submission_id: str = ""
    reward_info: RewardInfo = field(default_factory=lambda: RewardInfo(
        platform=PlatformType.CUSTOM,
        platform_report_id="",
        reward_status=RewardStatus.NONE
    ))
    vulnerability_type: Optional[str] = None
    severity_rewarded: Optional[str] = None
    program_name: Optional[str] = None
    researcher_rank_before: Optional[str] = None
    researcher_rank_after: Optional[str] = None
    total_lifetime_earnings: Optional[float] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class StatusCheckResult:
    """Result of checking platform status."""
    platform: PlatformType
    success: bool
    status_data: Optional[PlatformReportStatus] = None
    reward_data: Optional[RewardInfo] = None
    error_message: Optional[str] = None
    checked_at: datetime = field(default_factory=datetime.now)
    api_response: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PlatformStats:
    """Platform statistics and metrics."""
    platform: PlatformType
    total_submissions: int = 0
    accepted_submissions: int = 0
    rejected_submissions: int = 0
    duplicate_submissions: int = 0
    total_rewards: float = 0.0
    average_reward: float = 0.0
    highest_reward: float = 0.0
    reputation_points: int = 0
    current_rank: Optional[str] = None
    success_rate: float = 0.0
    average_response_time_hours: Optional[float] = None
    last_submission_date: Optional[datetime] = None
    last_reward_date: Optional[datetime] = None
    statistics_updated_at: datetime = field(default_factory=datetime.now)


class PlatformError(Exception):
    """Base exception for platform integration errors."""
    
    def __init__(self, message: str, platform: Optional[PlatformType] = None, 
                 error_code: Optional[str] = None, response_data: Optional[Dict] = None):
        super().__init__(message)
        self.platform = platform
        self.error_code = error_code
        self.response_data = response_data or {}
        self.timestamp = datetime.now()


class AuthenticationError(PlatformError):
    """Authentication-related platform errors."""
    pass


class SubmissionError(PlatformError):
    """Submission-related platform errors."""
    pass


class RateLimitError(PlatformError):
    """Rate limiting platform errors."""
    pass


class ConfigurationError(PlatformError):
    """Configuration-related platform errors."""
    pass