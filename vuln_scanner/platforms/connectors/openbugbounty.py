"""OpenBugBounty platform connector implementation."""

import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urljoin

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


class OpenBugBountyConnector(PlatformConnector):
    """OpenBugBounty platform connector implementation."""
    
    @property
    def platform_type(self) -> PlatformType:
        return PlatformType.OPENBUGBOUNTY
    
    @property
    def base_url(self) -> str:
        return self.config.base_url or "https://www.openbugbounty.org"
    
    def __init__(self, credentials: PlatformCredentials, config: PlatformConfig):
        super().__init__(credentials, config)
        
        # Validate OpenBugBounty specific credentials
        if not credentials.username or not credentials.password:
            raise AuthenticationError(
                "OpenBugBounty requires username and password",
                platform=self.platform_type
            )
        
        self.session_cookies = None
        self.csrf_token = None
        
        # Set up headers
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 VulnMiner/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })
    
    async def authenticate(self) -> bool:
        """Authenticate with OpenBugBounty (web-based login)."""
        try:
            # First, get the login page to extract CSRF token
            login_page_url = urljoin(self.base_url, "/users/sign_in")
            response = self._make_request("GET", login_page_url)
            
            if response.status_code != 200:
                raise AuthenticationError("Failed to access login page", platform=self.platform_type)
            
            # Extract CSRF token (simplified - in practice would need proper HTML parsing)
            html_content = response.text
            csrf_start = html_content.find('name="csrf-token" content="')
            if csrf_start != -1:
                csrf_start += len('name="csrf-token" content="')
                csrf_end = html_content.find('"', csrf_start)
                if csrf_end != -1:
                    self.csrf_token = html_content[csrf_start:csrf_end]
            
            # Prepare login data
            login_data = {
                "user[email]": self.credentials.username,
                "user[password]": self.credentials.password,
                "user[remember_me]": "0",
                "commit": "Log in"
            }
            
            if self.csrf_token:
                login_data["authenticity_token"] = self.csrf_token
            
            # Update headers for form submission
            self.session.headers.update({
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": login_page_url
            })
            
            # Submit login form
            login_url = urljoin(self.base_url, "/users/sign_in")
            response = self._make_request("POST", login_url, data=login_data)
            
            # Check if login was successful (redirects on success)
            if response.status_code in [200, 302]:
                # Check if we got redirected to dashboard or similar
                if "dashboard" in response.url or "sign_in" not in response.url or response.status_code == 302:
                    self.logger.info("Successfully authenticated with OpenBugBounty")
                    self.session_cookies = self.session.cookies
                    return True
            
            raise AuthenticationError("Login failed - invalid credentials", platform=self.platform_type)
            
        except Exception as e:
            self.logger.error(f"OpenBugBounty authentication failed: {e}")
            return False
    
    async def test_connection(self) -> Tuple[bool, Optional[str]]:
        """Test connection to OpenBugBounty."""
        try:
            authenticated = await self.authenticate()
            if authenticated:
                # Test with a simple protected page request
                dashboard_url = urljoin(self.base_url, "/researchers/dashboard")
                response = self._make_request("GET", dashboard_url)
                if response.status_code == 200 and "dashboard" in response.url:
                    return True, "Connection successful"
                else:
                    return False, "Authentication verification failed"
            else:
                return False, "Authentication failed"
        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
    
    def format_submission_data(self, submission_data: PlatformSubmissionData) -> Dict[str, Any]:
        """Format submission data for OpenBugBounty submission form."""
        # OpenBugBounty uses web forms, so we format for form submission
        
        # Build detailed description
        full_description = submission_data.description
        
        if submission_data.steps_to_reproduce:
            full_description += "\\n\\nSteps to Reproduce:\\n" + "\\n".join(f"{i+1}. {step}" for i, step in enumerate(submission_data.steps_to_reproduce))
        
        if submission_data.proof_of_concept:
            full_description += "\\n\\nProof of Concept:\\n" + submission_data.proof_of_concept
        
        if submission_data.impact:
            full_description += "\\n\\nImpact:\\n" + submission_data.impact
        
        if submission_data.remediation_advice:
            full_description += "\\n\\nRemediation:\\n" + submission_data.remediation_advice
        
        # Add technical details
        if submission_data.cvss_score:
            full_description += f"\\n\\nCVSS Score: {submission_data.cvss_score}"
        
        if submission_data.cwe_references:
            full_description += f"\\n\\nCWE References: {', '.join(submission_data.cwe_references)}"
        
        # Map severity to OpenBugBounty categories
        severity_mapping = {
            "critical": "High",
            "high": "High", 
            "medium": "Medium",
            "low": "Low",
            "informational": "Info"
        }
        
        # Format for web form submission
        form_data = {
            "vulnerability[title]": submission_data.title,
            "vulnerability[description]": full_description,
            "vulnerability[url]": submission_data.target,
            "vulnerability[severity]": severity_mapping.get(submission_data.severity.lower(), "Medium"),
            "vulnerability[category]": submission_data.weakness_type or "Other",
            "commit": "Submit Report"
        }
        
        if self.csrf_token:
            form_data["authenticity_token"] = self.csrf_token
        
        # Add platform-specific fields
        if submission_data.platform_specific_fields:
            form_data.update(submission_data.platform_specific_fields)
        
        return form_data
    
    async def submit_vulnerability(self, submission_data: PlatformSubmissionData) -> SubmissionResult:
        """Submit vulnerability report to OpenBugBounty."""
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
        if not self.session_cookies or not await self.authenticate():
            return SubmissionResult(
                platform=self.platform_type,
                submission_id=submission_data.submission_id,
                success=False,
                error_message="Authentication failed"
            )
        
        try:
            # Get submission form page to extract CSRF token
            submit_url = urljoin(self.base_url, "/researchers/vulnerabilities/new")
            response = self._make_request("GET", submit_url)
            
            if response.status_code != 200:
                raise SubmissionError("Failed to access submission form", platform=self.platform_type)
            
            # Update CSRF token from form page
            html_content = response.text
            csrf_start = html_content.find('name="csrf-token" content="')
            if csrf_start != -1:
                csrf_start += len('name="csrf-token" content="')
                csrf_end = html_content.find('"', csrf_start)
                if csrf_end != -1:
                    self.csrf_token = html_content[csrf_start:csrf_end]
            
            # Format the submission
            form_data = self.format_submission_data(submission_data)
            
            # Submit the vulnerability report
            self.session.headers.update({
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": submit_url
            })
            
            submit_post_url = urljoin(self.base_url, "/researchers/vulnerabilities")
            response = self._make_request("POST", submit_post_url, data=form_data)
            
            if response.status_code in [200, 201, 302]:
                # Try to extract vulnerability ID from response
                vulnerability_id = None
                
                # Check if redirected to vulnerability page
                if response.status_code == 302:
                    location = response.headers.get("Location", "")
                    if "/vulnerabilities/" in location:
                        vulnerability_id = location.split("/vulnerabilities/")[-1].split("/")[0]
                
                # If no ID found, generate a tracking ID
                if not vulnerability_id:
                    vulnerability_id = f"obb_{int(datetime.now().timestamp())}"
                
                return SubmissionResult(
                    platform=self.platform_type,
                    submission_id=submission_data.submission_id,
                    platform_report_id=vulnerability_id,
                    success=True,
                    status=SubmissionStatus.SUBMITTED,
                    response_data={"status_code": response.status_code, "url": response.url},
                    submission_url=f"{self.base_url}/vulnerabilities/{vulnerability_id}",
                    tracking_id=vulnerability_id
                )
            else:
                error_msg = f"Submission failed with status {response.status_code}"
                return SubmissionResult(
                    platform=self.platform_type,
                    submission_id=submission_data.submission_id,
                    success=False,
                    error_message=error_msg,
                    response_data={"status_code": response.status_code, "response": response.text[:500]}
                )
                
        except Exception as e:
            self.logger.error(f"Failed to submit to OpenBugBounty: {e}")
            return SubmissionResult(
                platform=self.platform_type,
                submission_id=submission_data.submission_id,
                success=False,
                error_message=f"Submission error: {str(e)}"
            )
    
    async def check_submission_status(self, platform_report_id: str) -> StatusCheckResult:
        """Check status of an OpenBugBounty vulnerability."""
        try:
            if not self.session_cookies:
                await self.authenticate()
            
            # OpenBugBounty doesn't have a REST API, so we scrape the vulnerability page
            vuln_url = urljoin(self.base_url, f"/vulnerabilities/{platform_report_id}")
            response = self._make_request("GET", vuln_url)
            
            if response.status_code == 200:
                html_content = response.text
                
                # Extract status from HTML (simplified parsing)
                status = SubmissionStatus.SUBMITTED  # Default
                
                if "Status: Verified" in html_content or "status-verified" in html_content:
                    status = SubmissionStatus.ACCEPTED
                elif "Status: Fixed" in html_content or "status-fixed" in html_content:
                    status = SubmissionStatus.RESOLVED
                elif "Status: Duplicate" in html_content or "status-duplicate" in html_content:
                    status = SubmissionStatus.DUPLICATE
                elif "Status: Rejected" in html_content or "status-rejected" in html_content:
                    status = SubmissionStatus.REJECTED
                elif "Status: Pending" in html_content or "status-pending" in html_content:
                    status = SubmissionStatus.TRIAGED
                
                # Build status object
                report_status = PlatformReportStatus(
                    platform=self.platform_type,
                    platform_report_id=platform_report_id,
                    submission_id="",  # Would need to be tracked separately
                    current_status=status
                )
                
                return StatusCheckResult(
                    platform=self.platform_type,
                    success=True,
                    status_data=report_status,
                    api_response={"status_code": response.status_code, "content_length": len(html_content)}
                )
            else:
                return StatusCheckResult(
                    platform=self.platform_type,
                    success=False,
                    error_message=f"Status check failed: {response.status_code} - Vulnerability not found or access denied"
                )
                
        except Exception as e:
            self.logger.error(f"Failed to check status for {platform_report_id}: {e}")
            return StatusCheckResult(
                platform=self.platform_type,
                success=False,
                error_message=str(e)
            )
    
    async def get_reward_info(self, platform_report_id: str) -> Optional[RewardInfo]:
        """Get reward information for an OpenBugBounty vulnerability."""
        # OpenBugBounty is primarily for coordinated disclosure, not bounties
        # But some organizations may offer rewards
        try:
            status_result = await self.check_submission_status(platform_report_id)
            
            if status_result.success and status_result.status_data:
                # OpenBugBounty typically doesn't have monetary rewards
                # but provides reputation and disclosure coordination
                return RewardInfo(
                    platform=self.platform_type,
                    platform_report_id=platform_report_id,
                    reward_status=RewardStatus.REPUTATION_ONLY,
                    reputation_points=1 if status_result.status_data.current_status == SubmissionStatus.ACCEPTED else 0
                )
            
            return RewardInfo(
                platform=self.platform_type,
                platform_report_id=platform_report_id,
                reward_status=RewardStatus.NONE
            )
            
        except Exception as e:
            self.logger.error(f"Failed to get reward info for {platform_report_id}: {e}")
            return None
    
    def parse_response_data(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse OpenBugBounty specific response data."""
        return {
            "vulnerability_id": response_data.get("vulnerability_id"),
            "status_code": response_data.get("status_code"),
            "url": response_data.get("url"),
            "platform_url": f"{self.base_url}/vulnerabilities/{response_data.get('vulnerability_id', '')}"
        }
    
    def _validate_submission_data(self, submission_data: PlatformSubmissionData) -> List[str]:
        """Validate OpenBugBounty specific submission requirements."""
        errors = super()._validate_submission_data(submission_data)
        
        # OpenBugBounty specific validations
        if len(submission_data.title) > 200:
            errors.append("Title must be 200 characters or less")
        
        if len(submission_data.description) < 50:
            errors.append("Description must be at least 50 characters")
        
        # Validate target is a proper URL
        if not submission_data.target.startswith(("http://", "https://")):
            errors.append("Target must be a valid HTTP/HTTPS URL")
        
        valid_severities = ["critical", "high", "medium", "low", "informational"]
        if submission_data.severity.lower() not in valid_severities:
            errors.append(f"Severity must be one of: {', '.join(valid_severities)}")
        
        return errors