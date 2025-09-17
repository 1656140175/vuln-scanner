"""HackerOne platform connector implementation."""

import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

from .base import PlatformConnector
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
    SubmissionStatus,
    RewardStatus
)


class HackerOneConnector(PlatformConnector):
    """HackerOne platform connector implementation."""
    
    @property
    def platform_type(self) -> PlatformType:
        return PlatformType.HACKERONE
    
    @property
    def base_url(self) -> str:
        return self.config.base_url or "https://api.hackerone.com/v1"
    
    def __init__(self, credentials: PlatformCredentials, config: PlatformConfig):
        super().__init__(credentials, config)
        
        # Validate HackerOne specific credentials
        if not credentials.username or not credentials.api_token:
            raise AuthenticationError(
                "HackerOne requires username and api_token",
                platform=self.platform_type
            )
        
        # Set up authentication
        self.session.auth = (credentials.username, credentials.api_token)
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
    
    async def authenticate(self) -> bool:
        """Authenticate with HackerOne API."""
        try:
            url = f"{self.base_url}/me"
            response = self._make_request("GET", url)
            
            if response.status_code == 200:
                user_data = response.json()
                self.logger.info(f"Authenticated as {user_data.get('data', {}).get('attributes', {}).get('username', 'unknown')}")
                return True
            elif response.status_code == 401:
                raise AuthenticationError("Invalid credentials", platform=self.platform_type)
            else:
                raise AuthenticationError(f"Authentication failed: {response.status_code}", platform=self.platform_type)
                
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            return False
    
    async def test_connection(self) -> Tuple[bool, Optional[str]]:
        """Test connection to HackerOne API."""
        try:
            authenticated = await self.authenticate()
            if authenticated:
                return True, "Connection successful"
            else:
                return False, "Authentication failed"
        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
    
    def format_submission_data(self, submission_data: PlatformSubmissionData) -> Dict[str, Any]:
        """Format submission data for HackerOne API."""
        # Map severity to HackerOne's rating system
        severity_mapping = {
            "critical": "critical",
            "high": "high", 
            "medium": "medium",
            "low": "low",
            "informational": "none"
        }
        
        # Build the vulnerability information
        vuln_info = submission_data.description
        if submission_data.steps_to_reproduce:
            vuln_info += "\\n\\n## Steps to Reproduce\\n" + "\\n".join(f"{i+1}. {step}" for i, step in enumerate(submission_data.steps_to_reproduce))
        
        if submission_data.proof_of_concept:
            vuln_info += "\\n\\n## Proof of Concept\\n" + submission_data.proof_of_concept
        
        if submission_data.impact:
            vuln_info += "\\n\\n## Impact\\n" + submission_data.impact
        
        if submission_data.remediation_advice:
            vuln_info += "\\n\\n## Remediation\\n" + submission_data.remediation_advice
        
        # Build structured scope
        structured_scope = {
            "asset_identifier": submission_data.target,
            "asset_type": "url"  # Default to URL, could be enhanced
        }
        
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": submission_data.title,
                    "vulnerability_information": vuln_info,
                    "severity_rating": severity_mapping.get(submission_data.severity.lower(), "medium"),
                    "structured_scope": structured_scope
                }
            }
        }
        
        # Add optional fields
        if submission_data.weakness_type:
            payload["data"]["attributes"]["weakness"] = {
                "id": submission_data.weakness_type
            }
        
        # Add platform-specific fields
        if submission_data.platform_specific_fields:
            payload["data"]["attributes"].update(submission_data.platform_specific_fields)
        
        return payload
    
    async def submit_vulnerability(self, submission_data: PlatformSubmissionData) -> SubmissionResult:
        """Submit vulnerability report to HackerOne."""
        # Validate submission data
        validation_errors = self._validate_submission_data(submission_data)
        if validation_errors:
            return SubmissionResult(
                platform=self.platform_type,
                submission_id=submission_data.submission_id,
                success=False,
                error_message=f"Validation errors: {', '.join(validation_errors)}"
            )
        
        # Check if authenticated
        if not await self.authenticate():
            return SubmissionResult(
                platform=self.platform_type,
                submission_id=submission_data.submission_id,
                success=False,
                error_message="Authentication failed"
            )
        
        try:
            # Format the submission
            payload = self.format_submission_data(submission_data)
            
            # Submit to HackerOne
            url = f"{self.base_url}/reports"
            response = self._make_request("POST", url, json=payload)
            
            if response.status_code == 201:
                response_data = response.json()
                report_data = response_data.get("data", {})
                report_id = report_data.get("id")
                report_attributes = report_data.get("attributes", {})
                
                return SubmissionResult(
                    platform=self.platform_type,
                    submission_id=submission_data.submission_id,
                    platform_report_id=report_id,
                    success=True,
                    status=SubmissionStatus.SUBMITTED,
                    response_data=response_data,
                    submission_url=f"https://hackerone.com/reports/{report_id}",
                    tracking_id=report_id
                )
            else:
                error_msg = f"Submission failed with status {response.status_code}: {response.text}"
                return SubmissionResult(
                    platform=self.platform_type,
                    submission_id=submission_data.submission_id,
                    success=False,
                    error_message=error_msg,
                    response_data=response.json() if response.text else {}
                )
                
        except Exception as e:
            self.logger.error(f"Failed to submit to HackerOne: {e}")
            return SubmissionResult(
                platform=self.platform_type,
                submission_id=submission_data.submission_id,
                success=False,
                error_message=f"Submission error: {str(e)}"
            )
    
    async def check_submission_status(self, platform_report_id: str) -> StatusCheckResult:
        """Check status of a HackerOne report."""
        try:
            url = f"{self.base_url}/reports/{platform_report_id}"
            response = self._make_request("GET", url)
            
            if response.status_code == 200:
                data = response.json()
                report_data = data.get("data", {})
                attributes = report_data.get("attributes", {})
                
                # Parse status
                state = attributes.get("state", "new")
                status = self._parse_hackerone_status(state)
                
                # Build status object
                report_status = PlatformReportStatus(
                    platform=self.platform_type,
                    platform_report_id=platform_report_id,
                    submission_id="",  # Would need to be tracked separately
                    current_status=status,
                    triager_username=attributes.get("triager_name"),
                    severity_assigned=attributes.get("severity_rating"),
                    feedback=attributes.get("vulnerability_information")
                )
                
                # Parse dates
                if attributes.get("created_at"):
                    try:
                        report_status.triage_date = datetime.fromisoformat(
                            attributes["created_at"].replace("Z", "+00:00")
                        )
                    except:
                        pass
                
                if attributes.get("disclosed_at"):
                    try:
                        report_status.resolution_date = datetime.fromisoformat(
                            attributes["disclosed_at"].replace("Z", "+00:00")
                        )
                    except:
                        pass
                
                return StatusCheckResult(
                    platform=self.platform_type,
                    success=True,
                    status_data=report_status,
                    api_response=data
                )
            else:
                return StatusCheckResult(
                    platform=self.platform_type,
                    success=False,
                    error_message=f"Status check failed: {response.status_code} - {response.text}"
                )
                
        except Exception as e:
            self.logger.error(f"Failed to check status for {platform_report_id}: {e}")
            return StatusCheckResult(
                platform=self.platform_type,
                success=False,
                error_message=str(e)
            )
    
    async def get_reward_info(self, platform_report_id: str) -> Optional[RewardInfo]:
        """Get reward information for a HackerOne report."""
        try:
            url = f"{self.base_url}/reports/{platform_report_id}"
            response = self._make_request("GET", url)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                # Check for bounty information
                bounty_awarded = attributes.get("bounty_awarded_at")
                bounty_amount = attributes.get("total_awarded_amount")
                
                if bounty_awarded or bounty_amount:
                    reward_status = RewardStatus.AWARDED if bounty_awarded else RewardStatus.PENDING
                    
                    reward_info = RewardInfo(
                        platform=self.platform_type,
                        platform_report_id=platform_report_id,
                        reward_status=reward_status,
                        bounty_amount=bounty_amount,
                        currency="USD"  # HackerOne typically uses USD
                    )
                    
                    if bounty_awarded:
                        try:
                            reward_info.awarded_date = datetime.fromisoformat(
                                bounty_awarded.replace("Z", "+00:00")
                            )
                        except:
                            pass
                    
                    return reward_info
                else:
                    return RewardInfo(
                        platform=self.platform_type,
                        platform_report_id=platform_report_id,
                        reward_status=RewardStatus.NONE
                    )
            else:
                self.logger.error(f"Failed to get reward info: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get reward info for {platform_report_id}: {e}")
            return None
    
    def parse_response_data(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse HackerOne specific response data."""
        if "data" in response_data:
            data = response_data["data"]
            attributes = data.get("attributes", {})
            
            return {
                "report_id": data.get("id"),
                "title": attributes.get("title"),
                "state": attributes.get("state"),
                "severity": attributes.get("severity_rating"),
                "bounty_amount": attributes.get("total_awarded_amount"),
                "created_at": attributes.get("created_at"),
                "triager": attributes.get("triager_name"),
                "url": f"https://hackerone.com/reports/{data.get('id')}"
            }
        return response_data
    
    def _parse_hackerone_status(self, state: str) -> SubmissionStatus:
        """Parse HackerOne specific status strings."""
        status_mapping = {
            "new": SubmissionStatus.SUBMITTED,
            "pending-program-review": SubmissionStatus.SUBMITTED,
            "triaged": SubmissionStatus.TRIAGED,
            "needs-more-info": SubmissionStatus.TRIAGED,
            "resolved": SubmissionStatus.RESOLVED,
            "informative": SubmissionStatus.INFORMATIVE,
            "not-applicable": SubmissionStatus.NOT_APPLICABLE,
            "duplicate": SubmissionStatus.DUPLICATE,
            "spam": SubmissionStatus.SPAM,
            "retesting": SubmissionStatus.RETESTING,
            "closed": SubmissionStatus.CLOSED
        }
        
        return status_mapping.get(state.lower(), SubmissionStatus.PENDING)
    
    def _validate_submission_data(self, submission_data: PlatformSubmissionData) -> List[str]:
        """Validate HackerOne specific submission requirements."""
        errors = super()._validate_submission_data(submission_data)
        
        # HackerOne specific validations
        if len(submission_data.title) > 100:
            errors.append("Title must be 100 characters or less")
        
        if len(submission_data.description) < 50:
            errors.append("Description must be at least 50 characters")
        
        valid_severities = ["critical", "high", "medium", "low", "informational"]
        if submission_data.severity.lower() not in valid_severities:
            errors.append(f"Severity must be one of: {', '.join(valid_severities)}")
        
        return errors