"""Intigriti platform connector implementation."""

import json
import logging
import hashlib
import hmac
import time
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


class IntigritiConnector(PlatformConnector):
    """Intigriti platform connector implementation."""
    
    @property
    def platform_type(self) -> PlatformType:
        return PlatformType.INTIGRITI
    
    @property
    def base_url(self) -> str:
        return self.config.base_url or "https://api.intigriti.com/core/researcher"
    
    def __init__(self, credentials: PlatformCredentials, config: PlatformConfig):
        super().__init__(credentials, config)
        
        # Validate Intigriti specific credentials
        if not credentials.api_key or not credentials.secret_key:
            raise AuthenticationError(
                "Intigriti requires api_key and secret_key",
                platform=self.platform_type
            )
        
        # Set up headers
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "VulnMiner/1.0"
        })
    
    def _generate_auth_signature(self, method: str, endpoint: str, timestamp: str, body: str = "") -> str:
        """Generate HMAC signature for Intigriti API authentication."""
        # Create the string to sign
        string_to_sign = f"{method}\\n{endpoint}\\n{timestamp}\\n{body}"
        
        # Generate HMAC-SHA256 signature
        signature = hmac.new(
            self.credentials.secret_key.encode('utf-8'),
            string_to_sign.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def _add_auth_headers(self, method: str, endpoint: str, body: str = "") -> Dict[str, str]:
        """Add authentication headers for Intigriti API."""
        timestamp = str(int(time.time()))
        signature = self._generate_auth_signature(method, endpoint, timestamp, body)
        
        return {
            "Authorization": f"Bearer {self.credentials.api_key}",
            "X-Intigriti-Timestamp": timestamp,
            "X-Intigriti-Signature": signature
        }
    
    async def authenticate(self) -> bool:
        """Authenticate with Intigriti API."""
        try:
            # Test authentication with a simple API call
            endpoint = "/profile"
            headers = self._add_auth_headers("GET", endpoint)
            url = f"{self.base_url}{endpoint}"
            
            response = self._make_request("GET", url, headers=headers)
            
            if response.status_code == 200:
                profile_data = response.json()
                username = profile_data.get("data", {}).get("attributes", {}).get("userName", "unknown")
                self.logger.info(f"Authenticated with Intigriti as {username}")
                return True
            elif response.status_code == 401:
                raise AuthenticationError("Invalid credentials", platform=self.platform_type)
            else:
                raise AuthenticationError(f"Authentication failed: {response.status_code}", platform=self.platform_type)
                
        except Exception as e:
            self.logger.error(f"Intigriti authentication failed: {e}")
            return False
    
    async def test_connection(self) -> Tuple[bool, Optional[str]]:
        """Test connection to Intigriti API."""
        try:
            authenticated = await self.authenticate()
            if authenticated:
                return True, "Connection successful"
            else:
                return False, "Authentication failed"
        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
    
    def format_submission_data(self, submission_data: PlatformSubmissionData) -> Dict[str, Any]:
        """Format submission data for Intigriti API."""
        # Map severity to Intigriti's severity system
        severity_mapping = {
            "critical": "Critical",
            "high": "High", 
            "medium": "Medium",
            "low": "Low",
            "informational": "Info"
        }
        
        # Build the vulnerability description
        vuln_description = submission_data.description
        
        if submission_data.steps_to_reproduce:
            vuln_description += "\\n\\n## Steps to Reproduce\\n" + "\\n".join(f"{i+1}. {step}" for i, step in enumerate(submission_data.steps_to_reproduce))
        
        if submission_data.proof_of_concept:
            vuln_description += "\\n\\n## Proof of Concept\\n" + submission_data.proof_of_concept
        
        if submission_data.impact:
            vuln_description += "\\n\\n## Impact\\n" + submission_data.impact
        
        if submission_data.remediation_advice:
            vuln_description += "\\n\\n## Remediation\\n" + submission_data.remediation_advice
        
        # Add technical details
        if submission_data.cvss_score:
            vuln_description += f"\\n\\n## CVSS Score\\n{submission_data.cvss_score}"
        
        if submission_data.cwe_references:
            vuln_description += f"\\n\\n## CWE References\\n{', '.join(submission_data.cwe_references)}"
        
        payload = {
            "data": {
                "type": "submission",
                "attributes": {
                    "title": submission_data.title,
                    "description": vuln_description,
                    "severity": severity_mapping.get(submission_data.severity.lower(), "Medium"),
                    "endpoint": submission_data.target,
                    "attachments": []
                }
            }
        }
        
        # Add optional fields
        if submission_data.weakness_type:
            payload["data"]["attributes"]["vulnerability_type"] = submission_data.weakness_type
        
        if submission_data.attack_vector:
            payload["data"]["attributes"]["attack_vector"] = submission_data.attack_vector
        
        # Add platform-specific fields
        if submission_data.platform_specific_fields:
            payload["data"]["attributes"].update(submission_data.platform_specific_fields)
        
        return payload
    
    async def submit_vulnerability(self, submission_data: PlatformSubmissionData) -> SubmissionResult:
        """Submit vulnerability report to Intigriti."""
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
            body = json.dumps(payload)
            
            # Generate auth headers
            endpoint = "/submissions"
            headers = self._add_auth_headers("POST", endpoint, body)
            
            # Submit to Intigriti
            url = f"{self.base_url}{endpoint}"
            response = self._make_request("POST", url, json=payload, headers=headers)
            
            if response.status_code == 201:
                response_data = response.json()
                submission_data_resp = response_data.get("data", {})
                submission_id = submission_data_resp.get("id")
                attributes = submission_data_resp.get("attributes", {})
                
                return SubmissionResult(
                    platform=self.platform_type,
                    submission_id=submission_data.submission_id,
                    platform_report_id=submission_id,
                    success=True,
                    status=SubmissionStatus.SUBMITTED,
                    response_data=response_data,
                    submission_url=f"https://app.intigriti.com/researcher/submissions/{submission_id}",
                    tracking_id=submission_id
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
            self.logger.error(f"Failed to submit to Intigriti: {e}")
            return SubmissionResult(
                platform=self.platform_type,
                submission_id=submission_data.submission_id,
                success=False,
                error_message=f"Submission error: {str(e)}"
            )
    
    async def check_submission_status(self, platform_report_id: str) -> StatusCheckResult:
        """Check status of an Intigriti submission."""
        try:
            endpoint = f"/submissions/{platform_report_id}"
            headers = self._add_auth_headers("GET", endpoint)
            url = f"{self.base_url}{endpoint}"
            
            response = self._make_request("GET", url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                submission_data = data.get("data", {})
                attributes = submission_data.get("attributes", {})
                
                # Parse status
                state = attributes.get("state", "submitted")
                status = self._parse_intigriti_status(state)
                
                # Build status object
                report_status = PlatformReportStatus(
                    platform=self.platform_type,
                    platform_report_id=platform_report_id,
                    submission_id="",  # Would need to be tracked separately
                    current_status=status,
                    severity_assigned=attributes.get("severity"),
                    feedback=attributes.get("feedback") or attributes.get("comments")
                )
                
                # Parse dates
                if attributes.get("created_at"):
                    try:
                        report_status.triage_date = datetime.fromisoformat(
                            attributes["created_at"].replace("Z", "+00:00")
                        )
                    except:
                        pass
                
                if attributes.get("resolved_at"):
                    try:
                        report_status.resolution_date = datetime.fromisoformat(
                            attributes["resolved_at"].replace("Z", "+00:00")
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
        """Get reward information for an Intigriti submission."""
        try:
            endpoint = f"/submissions/{platform_report_id}"
            headers = self._add_auth_headers("GET", endpoint)
            url = f"{self.base_url}{endpoint}"
            
            response = self._make_request("GET", url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                # Check for reward information
                bounty_amount = attributes.get("bounty_amount") or attributes.get("payout")
                reward_status_str = attributes.get("payout_status", "none")
                
                reward_status = self._parse_reward_status(reward_status_str)
                
                reward_info = RewardInfo(
                    platform=self.platform_type,
                    platform_report_id=platform_report_id,
                    reward_status=reward_status,
                    bounty_amount=bounty_amount,
                    currency="EUR"  # Intigriti typically uses EUR
                )
                
                # Parse reward date
                if attributes.get("payout_date"):
                    try:
                        reward_info.awarded_date = datetime.fromisoformat(
                            attributes["payout_date"].replace("Z", "+00:00")
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
        """Parse Intigriti specific response data."""
        if "data" in response_data:
            data = response_data["data"]
            attributes = data.get("attributes", {})
            
            return {
                "submission_id": data.get("id"),
                "title": attributes.get("title"),
                "state": attributes.get("state"),
                "severity": attributes.get("severity"),
                "bounty_amount": attributes.get("bounty_amount"),
                "created_at": attributes.get("created_at"),
                "endpoint": attributes.get("endpoint"),
                "url": f"https://app.intigriti.com/researcher/submissions/{data.get('id')}"
            }
        return response_data
    
    def _parse_intigriti_status(self, state: str) -> SubmissionStatus:
        """Parse Intigriti specific status strings."""
        status_mapping = {
            "submitted": SubmissionStatus.SUBMITTED,
            "new": SubmissionStatus.SUBMITTED,
            "under_review": SubmissionStatus.TRIAGED,
            "triaged": SubmissionStatus.TRIAGED,
            "accepted": SubmissionStatus.ACCEPTED,
            "resolved": SubmissionStatus.RESOLVED,
            "closed": SubmissionStatus.CLOSED,
            "duplicate": SubmissionStatus.DUPLICATE,
            "not_applicable": SubmissionStatus.NOT_APPLICABLE,
            "informative": SubmissionStatus.INFORMATIVE,
            "out_of_scope": SubmissionStatus.NOT_APPLICABLE,
            "spam": SubmissionStatus.SPAM,
            "rejected": SubmissionStatus.REJECTED
        }
        
        return status_mapping.get(state.lower(), SubmissionStatus.PENDING)
    
    def _validate_submission_data(self, submission_data: PlatformSubmissionData) -> List[str]:
        """Validate Intigriti specific submission requirements."""
        errors = super()._validate_submission_data(submission_data)
        
        # Intigriti specific validations
        if len(submission_data.title) > 120:
            errors.append("Title must be 120 characters or less")
        
        if len(submission_data.description) < 40:
            errors.append("Description must be at least 40 characters")
        
        valid_severities = ["critical", "high", "medium", "low", "informational"]
        if submission_data.severity.lower() not in valid_severities:
            errors.append(f"Severity must be one of: {', '.join(valid_severities)}")
        
        # Validate target is a proper URL/endpoint
        if not submission_data.target.startswith(("http://", "https://", "ftp://", "mailto:")):
            errors.append("Target must be a valid URL or endpoint")
        
        return errors