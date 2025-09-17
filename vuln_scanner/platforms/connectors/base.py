"""Base platform connector interface."""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..models.platform_models import (
    PlatformType,
    PlatformCredentials,
    PlatformConfig,
    PlatformSubmissionData,
    SubmissionResult,
    PlatformReportStatus,
    StatusCheckResult,
    RewardInfo,
    PlatformError,
    AuthenticationError,
    SubmissionError,
    RateLimitError,
    SubmissionStatus,
    RewardStatus
)


class PlatformConnector(ABC):
    """Abstract base class for platform connectors."""
    
    def __init__(self, credentials: PlatformCredentials, config: PlatformConfig):
        self.credentials = credentials
        self.config = config
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.session = requests.Session()
        self._last_request_time = 0.0
        self._request_count = 0
        self._rate_limit_reset_time = 0.0
        
        # Set up session with retry strategy
        retry_strategy = Retry(
            total=config.retry_config.get("max_retries", 3),
            backoff_factor=config.retry_config.get("backoff_factor", 2),
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set custom headers
        if self.config.custom_headers:
            self.session.headers.update(self.config.custom_headers)
    
    @property
    @abstractmethod
    def platform_type(self) -> PlatformType:
        """Return the platform type this connector handles."""
        pass
    
    @property
    @abstractmethod 
    def base_url(self) -> str:
        """Return the base API URL for the platform."""
        pass
    
    def _enforce_rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        current_time = time.time()
        
        # Reset rate limit counter if enough time has passed
        if current_time > self._rate_limit_reset_time:
            self._request_count = 0
            self._rate_limit_reset_time = current_time + 3600  # Reset every hour
        
        # Check per-minute rate limit
        time_since_last_request = current_time - self._last_request_time
        min_interval = 60.0 / self.config.rate_limit_per_minute
        
        if time_since_last_request < min_interval:
            sleep_time = min_interval - time_since_last_request
            self.logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        # Check per-hour rate limit
        if self._request_count >= self.config.rate_limit_per_hour:
            time_to_reset = self._rate_limit_reset_time - current_time
            if time_to_reset > 0:
                raise RateLimitError(
                    f"Hourly rate limit exceeded. Reset in {time_to_reset:.0f} seconds",
                    platform=self.platform_type
                )
        
        self._last_request_time = time.time()
        self._request_count += 1
    
    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make an HTTP request with rate limiting and error handling."""
        self._enforce_rate_limit()
        
        timeout = self.config.retry_config.get("timeout_seconds", 30)
        kwargs.setdefault("timeout", timeout)
        
        try:
            response = self.session.request(method, url, **kwargs)
            
            # Handle rate limit responses
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait_time = int(retry_after)
                        self.logger.warning(f"Rate limited, waiting {wait_time} seconds")
                        time.sleep(wait_time)
                        return self._make_request(method, url, **kwargs)
                    except ValueError:
                        pass
                raise RateLimitError("Rate limit exceeded", platform=self.platform_type)
            
            return response
            
        except requests.exceptions.RequestException as e:
            raise PlatformError(f"Request failed: {str(e)}", platform=self.platform_type)
    
    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with the platform."""
        pass
    
    @abstractmethod
    async def test_connection(self) -> Tuple[bool, Optional[str]]:
        """Test the connection and authentication."""
        pass
    
    @abstractmethod
    async def submit_vulnerability(self, submission_data: PlatformSubmissionData) -> SubmissionResult:
        """Submit a vulnerability report to the platform."""
        pass
    
    @abstractmethod
    async def check_submission_status(self, platform_report_id: str) -> StatusCheckResult:
        """Check the status of a submitted report."""
        pass
    
    @abstractmethod
    async def get_reward_info(self, platform_report_id: str) -> Optional[RewardInfo]:
        """Get reward information for a report."""
        pass
    
    @abstractmethod
    def format_submission_data(self, submission_data: PlatformSubmissionData) -> Dict[str, Any]:
        """Format submission data for the specific platform."""
        pass
    
    @abstractmethod
    def parse_response_data(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse platform-specific response data."""
        pass
    
    def _map_severity(self, severity: str) -> str:
        """Map internal severity to platform-specific severity."""
        severity_map = self.config.severity_mapping
        return severity_map.get(severity.lower(), severity)
    
    def _parse_submission_status(self, status_string: str) -> SubmissionStatus:
        """Parse platform status to internal status enum."""
        status_mapping = {
            # Common status mappings
            "new": SubmissionStatus.SUBMITTED,
            "pending": SubmissionStatus.PENDING,
            "triaged": SubmissionStatus.TRIAGED,
            "accepted": SubmissionStatus.ACCEPTED,
            "resolved": SubmissionStatus.RESOLVED,
            "closed": SubmissionStatus.CLOSED,
            "duplicate": SubmissionStatus.DUPLICATE,
            "not_applicable": SubmissionStatus.NOT_APPLICABLE,
            "informative": SubmissionStatus.INFORMATIVE,
            "spam": SubmissionStatus.SPAM,
            "rejected": SubmissionStatus.REJECTED,
            "retesting": SubmissionStatus.RETESTING
        }
        
        return status_mapping.get(status_string.lower(), SubmissionStatus.PENDING)
    
    def _parse_reward_status(self, reward_string: str) -> RewardStatus:
        """Parse platform reward status to internal enum."""
        reward_mapping = {
            "none": RewardStatus.NONE,
            "pending": RewardStatus.PENDING,
            "awarded": RewardStatus.AWARDED,
            "paid": RewardStatus.PAID,
            "eligible": RewardStatus.BOUNTY_ELIGIBLE,
            "ineligible": RewardStatus.BOUNTY_INELIGIBLE,
            "reputation": RewardStatus.REPUTATION_ONLY
        }
        
        return reward_mapping.get(reward_string.lower(), RewardStatus.NONE)
    
    async def get_platform_info(self) -> Dict[str, Any]:
        """Get general platform information and statistics."""
        return {
            "platform": self.platform_type.value,
            "base_url": self.base_url,
            "rate_limits": {
                "per_hour": self.config.rate_limit_per_hour,
                "per_minute": self.config.rate_limit_per_minute
            },
            "authenticated": await self.authenticate()
        }
    
    def _validate_submission_data(self, submission_data: PlatformSubmissionData) -> List[str]:
        """Validate submission data for the platform."""
        errors = []
        
        if not submission_data.title:
            errors.append("Title is required")
        
        if not submission_data.description:
            errors.append("Description is required")
        
        if not submission_data.severity:
            errors.append("Severity is required")
        
        if not submission_data.target:
            errors.append("Target is required")
        
        if not submission_data.proof_of_concept:
            errors.append("Proof of concept is required")
        
        return errors
    
    async def bulk_status_check(self, report_ids: List[str]) -> List[StatusCheckResult]:
        """Check status for multiple reports."""
        results = []
        
        for report_id in report_ids:
            try:
                result = await self.check_submission_status(report_id)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Failed to check status for {report_id}: {e}")
                results.append(StatusCheckResult(
                    platform=self.platform_type,
                    success=False,
                    error_message=str(e)
                ))
                
            # Add small delay between requests
            await asyncio.sleep(0.5)
        
        return results
    
    def close(self):
        """Close the session and clean up resources."""
        if self.session:
            self.session.close()