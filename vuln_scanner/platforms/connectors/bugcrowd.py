"""Bugcrowd platform connector implementation."""

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


class BugcrowdConnector(PlatformConnector):
    """Bugcrowd platform connector implementation."""
    
    @property
    def platform_type(self) -> PlatformType:
        return PlatformType.BUGCROWD
    
    @property
    def base_url(self) -> str:
        return self.config.base_url or "https://api.bugcrowd.com"
    
    def __init__(self, credentials: PlatformCredentials, config: PlatformConfig):
        super().__init__(credentials, config)
        
        # Validate Bugcrowd specific credentials
        if not credentials.email or not credentials.password:
            raise AuthenticationError(
                "Bugcrowd requires email and password",
                platform=self.platform_type
            )
        
        self.access_token = None
        self.token_expires_at = None
        
        # Set up headers
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "VulnMiner/1.0"
        })
    
    async def authenticate(self) -> bool:
        """Authenticate with Bugcrowd API."""
        try:
            # Login to get access token
            login_url = f"{self.base_url}/user_sessions"
            login_data = {
                "email": self.credentials.email,
                "password": self.credentials.password
            }
            
            response = self._make_request("POST", login_url, json=login_data)
            
            if response.status_code == 200:
                auth_data = response.json()
                self.access_token = auth_data.get("token") or auth_data.get("access_token")
                
                if self.access_token:
                    # Update session headers with token
                    self.session.headers.update({
                        "Authorization": f"Bearer {self.access_token}"
                    })
                    
                    self.logger.info("Successfully authenticated with Bugcrowd")
                    return True
                else:
                    raise AuthenticationError("No access token in response", platform=self.platform_type)
            elif response.status_code == 401:
                raise AuthenticationError("Invalid credentials", platform=self.platform_type)
            else:
                raise AuthenticationError(f"Authentication failed: {response.status_code}", platform=self.platform_type)
                
        except Exception as e:
            self.logger.error(f"Bugcrowd authentication failed: {e}")
            return False
    
    async def test_connection(self) -> Tuple[bool, Optional[str]]:
        """Test connection to Bugcrowd API."""
        try:
            authenticated = await self.authenticate()
            if authenticated:
                # Test with a simple API call
                url = f"{self.base_url}/me"
                response = self._make_request("GET", url)
                if response.status_code == 200:
                    return True, "Connection successful"
                else:
                    return False, f"API test failed: {response.status_code}"
            else:
                return False, "Authentication failed"
        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
    
    def format_submission_data(self, submission_data: PlatformSubmissionData) -> Dict[str, Any]:
        """Format submission data for Bugcrowd API."""
        # Map severity to Bugcrowd's priority system
        priority_mapping = {
            "critical": "P1",
            "high": "P2", 
            "medium": "P3",
            "low": "P4",
            "informational": "P5"
        }
        
        # Build the description with all details
        full_description = submission_data.description
        
        if submission_data.steps_to_reproduce:
            full_description += "\\n\\n**Steps to Reproduce:**\\n" + "\\n".join(f"{i+1}. {step}" for i, step in enumerate(submission_data.steps_to_reproduce))
        
        if submission_data.proof_of_concept:
            full_description += "\\n\\n**Proof of Concept:**\\n" + submission_data.proof_of_concept
        
        if submission_data.impact:
            full_description += "\\n\\n**Impact:**\\n" + submission_data.impact
        
        if submission_data.remediation_advice:
            full_description += "\\n\\n**Remediation:**\\n" + submission_data.remediation_advice
        
        # Add technical details
        if submission_data.cvss_score:
            full_description += f"\\n\\n**CVSS Score:** {submission_data.cvss_score}"
        
        if submission_data.cwe_references:
            full_description += f"\\n\\n**CWE References:** {', '.join(submission_data.cwe_references)}"
        
        if submission_data.cve_references:
            full_description += f"\\n\\n**CVE References:** {', '.join(submission_data.cve_references)}"
        
        payload = {
            "title": submission_data.title,
            "description": full_description,
            "priority": priority_mapping.get(submission_data.severity.lower(), "P3"),
            "target": submission_data.target,
            "vulnerability_types": [submission_data.weakness_type] if submission_data.weakness_type else [],
            "custom_fields": {}
        }
        
        # Add optional fields
        if submission_data.attack_vector:
            payload["custom_fields"]["attack_vector"] = submission_data.attack_vector
        
        if submission_data.business_impact:
            payload["custom_fields"]["business_impact"] = submission_data.business_impact
        
        if submission_data.technical_impact:
            payload["custom_fields"]["technical_impact"] = submission_data.technical_impact
        
        # Add platform-specific fields
        if submission_data.platform_specific_fields:
            payload.update(submission_data.platform_specific_fields)
        
        return payload
    
    async def submit_vulnerability(self, submission_data: PlatformSubmissionData) -> SubmissionResult:
        """Submit vulnerability report to Bugcrowd."""
        # Validate submission data
        validation_errors = self._validate_submission_data(submission_data)
        if validation_errors:
            return SubmissionResult(
                platform=self.platform_type,
                submission_id=submission_data.submission_id,
                success=False,
                error_message=f"Validation errors: {', '.join(validation_errors)}"
            )
        
        # Ensure authentication
        if not self.access_token or not await self.authenticate():
            return SubmissionResult(
                platform=self.platform_type,
                submission_id=submission_data.submission_id,
                success=False,
                error_message="Authentication failed"
            )
        
        try:
            # Format the submission
            payload = self.format_submission_data(submission_data)
            
            # Submit to Bugcrowd
            url = f"{self.base_url}/submissions"
            response = self._make_request("POST", url, json=payload)
            
            if response.status_code in [200, 201]:
                response_data = response.json()
                submission_id = response_data.get("id") or response_data.get("submission_id")
                
                return SubmissionResult(
                    platform=self.platform_type,
                    submission_id=submission_data.submission_id,
                    platform_report_id=str(submission_id),
                    success=True,
                    status=SubmissionStatus.SUBMITTED,
                    response_data=response_data,
                    submission_url=f"https://bugcrowd.com/submissions/{submission_id}",
                    tracking_id=str(submission_id)
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
            self.logger.error(f"Failed to submit to Bugcrowd: {e}")
            return SubmissionResult(
                platform=self.platform_type,
                submission_id=submission_data.submission_id,
                success=False,
                error_message=f"Submission error: {str(e)}"
            )
    
    async def check_submission_status(self, platform_report_id: str) -> StatusCheckResult:
        """Check status of a Bugcrowd submission."""
        try:
            if not self.access_token:
                await self.authenticate()
            
            url = f"{self.base_url}/submissions/{platform_report_id}"
            response = self._make_request("GET", url)
            
            if response.status_code == 200:
                data = response.json()
                
                # Parse status
                state = data.get("state", "submitted")
                status = self._parse_bugcrowd_status(state)
                
                # Build status object
                report_status = PlatformReportStatus(
                    platform=self.platform_type,
                    platform_report_id=platform_report_id,
                    submission_id="",  # Would need to be tracked separately
                    current_status=status,
                    triager_username=data.get("reviewer", {}).get("username"),
                    severity_assigned=data.get("priority"),
                    feedback=data.get("internal_notes") or data.get("researcher_notes")
                )
                
                # Parse dates
                if data.get("created_at"):
                    try:
                        report_status.triage_date = datetime.fromisoformat(
                            data["created_at"].replace("Z", "+00:00")
                        )
                    except:
                        pass
                
                if data.get("resolved_at"):
                    try:
                        report_status.resolution_date = datetime.fromisoformat(
                            data["resolved_at"].replace("Z", "+00:00")
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
        """Get reward information for a Bugcrowd submission."""
        try:
            if not self.access_token:
                await self.authenticate()
            
            url = f"{self.base_url}/submissions/{platform_report_id}"
            response = self._make_request("GET", url)
            
            if response.status_code == 200:
                data = response.json()
                
                # Check for reward information
                bounty_amount = data.get("bounty_amount") or data.get("reward_amount")
                reward_status_str = data.get("reward_status", "none")
                
                reward_status = self._parse_reward_status(reward_status_str)
                
                reward_info = RewardInfo(
                    platform=self.platform_type,
                    platform_report_id=platform_report_id,
                    reward_status=reward_status,
                    bounty_amount=bounty_amount,
                    currency="USD"  # Bugcrowd typically uses USD
                )
                
                # Parse reward date
                if data.get("rewarded_at"):
                    try:
                        reward_info.awarded_date = datetime.fromisoformat(
                            data["rewarded_at"].replace("Z", "+00:00")
                        )
                    except:
                        pass
                
                return reward_info
            else:
                self.logger.error(f"Failed to get reward info: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get reward info for {platform_report_id}: {e}")
            return None
    
    def parse_response_data(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Bugcrowd specific response data."""
        return {
            "submission_id": response_data.get("id"),
            "title": response_data.get("title"),
            "state": response_data.get("state"),
            "priority": response_data.get("priority"),
            "bounty_amount": response_data.get("bounty_amount"),
            "created_at": response_data.get("created_at"),
            "reviewer": response_data.get("reviewer", {}).get("username"),
            "url": f"https://bugcrowd.com/submissions/{response_data.get('id')}"
        }
    
    def _parse_bugcrowd_status(self, state: str) -> SubmissionStatus:
        """Parse Bugcrowd specific status strings."""
        status_mapping = {
            "submitted": SubmissionStatus.SUBMITTED,
            "new": SubmissionStatus.SUBMITTED,
            "triaged": SubmissionStatus.TRIAGED,
            "in_review": SubmissionStatus.TRIAGED,
            "accepted": SubmissionStatus.ACCEPTED,
            "resolved": SubmissionStatus.RESOLVED,
            "closed": SubmissionStatus.CLOSED,
            "duplicate": SubmissionStatus.DUPLICATE,
            "not_applicable": SubmissionStatus.NOT_APPLICABLE,
            "informative": SubmissionStatus.INFORMATIVE,
            "spam": SubmissionStatus.SPAM,
            "rejected": SubmissionStatus.REJECTED,
            "unresolved": SubmissionStatus.TRIAGED,
            "wont_fix": SubmissionStatus.CLOSED
        }
        
        return status_mapping.get(state.lower(), SubmissionStatus.PENDING)
    
    def _validate_submission_data(self, submission_data: PlatformSubmissionData) -> List[str]:
        """Validate Bugcrowd specific submission requirements."""
        errors = super()._validate_submission_data(submission_data)
        
        # Bugcrowd specific validations
        if len(submission_data.title) > 150:
            errors.append("Title must be 150 characters or less")
        
        if len(submission_data.description) < 30:
            errors.append("Description must be at least 30 characters")
        
        valid_priorities = ["critical", "high", "medium", "low", "informational"]
        if submission_data.severity.lower() not in valid_priorities:
            errors.append(f"Severity must be one of: {', '.join(valid_priorities)}")
        
        return errors