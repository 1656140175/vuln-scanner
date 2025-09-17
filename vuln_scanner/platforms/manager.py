"""Platform integration manager for coordinating multiple bug bounty platforms."""

import asyncio
import logging
import os
from typing import Dict, List, Any, Optional, Type, Tuple
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from ..core.exceptions import ConfigurationError
from .models.platform_models import (
    PlatformType,
    PlatformCredentials,
    PlatformConfig,
    PlatformSubmissionData,
    SubmissionResult,
    PlatformReportStatus,
    StatusCheckResult,
    RewardInfo,
    PlatformReward,
    PlatformStats,
    PlatformError,
    AuthenticationError,
    SubmissionStatus,
    RewardStatus
)
from .connectors import (
    PlatformConnector,
    HackerOneConnector,
    BugcrowdConnector,
    IntigritiConnector,
    OpenBugBountyConnector
)


class PlatformManager:
    """Unified manager for bug bounty platform integrations."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config_path = config_path or self._get_default_config_path()
        self.platforms_config: Dict[str, Any] = {}
        self.connectors: Dict[PlatformType, PlatformConnector] = {}
        self.platform_stats: Dict[PlatformType, PlatformStats] = {}
        
        # Load configuration
        self._load_configuration()
        
        # Initialize connectors for enabled platforms
        self._initialize_connectors()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path."""
        return os.path.join("config", "platforms.yml")
    
    def _load_configuration(self) -> None:
        """Load platform configuration from YAML file."""
        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                self.logger.warning(f"Platform config file not found: {self.config_path}")
                self.platforms_config = self._get_default_config()
                return
            
            with open(config_file, 'r', encoding='utf-8') as f:
                self.platforms_config = yaml.safe_load(f) or {}
            
            self.logger.info(f"Loaded platform configuration from {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load platform configuration: {e}")
            self.platforms_config = self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default platform configuration."""
        return {
            "hackerone": {
                "enabled": False,
                "credentials": {
                    "username": "${HACKERONE_USERNAME}",
                    "api_token": "${HACKERONE_API_TOKEN}"
                },
                "config": {
                    "base_url": "https://api.hackerone.com/v1",
                    "rate_limit_per_hour": 60,
                    "rate_limit_per_minute": 10,
                    "retry_config": {
                        "max_retries": 3,
                        "backoff_factor": 2,
                        "timeout_seconds": 30
                    }
                }
            },
            "bugcrowd": {
                "enabled": False,
                "credentials": {
                    "email": "${BUGCROWD_EMAIL}",
                    "password": "${BUGCROWD_PASSWORD}"
                },
                "config": {
                    "base_url": "https://api.bugcrowd.com",
                    "rate_limit_per_hour": 100,
                    "rate_limit_per_minute": 15
                }
            },
            "intigriti": {
                "enabled": False,
                "credentials": {
                    "api_key": "${INTIGRITI_API_KEY}",
                    "secret_key": "${INTIGRITI_SECRET_KEY}"
                },
                "config": {
                    "base_url": "https://api.intigriti.com/core/researcher",
                    "rate_limit_per_hour": 120,
                    "rate_limit_per_minute": 20
                }
            },
            "openbugbounty": {
                "enabled": False,
                "credentials": {
                    "username": "${OBB_USERNAME}",
                    "password": "${OBB_PASSWORD}"
                },
                "config": {
                    "base_url": "https://www.openbugbounty.org",
                    "rate_limit_per_hour": 50,
                    "rate_limit_per_minute": 5
                }
            }
        }
    
    def _expand_env_variables(self, value: str) -> str:
        """Expand environment variables in configuration values."""
        if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
            env_var = value[2:-1]  # Remove ${ and }
            return os.getenv(env_var, value)  # Return original if env var not found
        return value
    
    def _initialize_connectors(self) -> None:
        """Initialize platform connectors for enabled platforms."""
        connector_classes = {
            PlatformType.HACKERONE: HackerOneConnector,
            PlatformType.BUGCROWD: BugcrowdConnector,
            PlatformType.INTIGRITI: IntigritiConnector,
            PlatformType.OPENBUGBOUNTY: OpenBugBountyConnector
        }
        
        for platform_name, platform_config in self.platforms_config.items():
            if not platform_config.get("enabled", False):
                continue
            
            try:
                platform_type = PlatformType(platform_name.lower())
                connector_class = connector_classes.get(platform_type)
                
                if not connector_class:
                    self.logger.warning(f"No connector available for platform: {platform_name}")
                    continue
                
                # Parse credentials
                creds_config = platform_config.get("credentials", {})
                credentials = PlatformCredentials(
                    platform=platform_type,
                    username=self._expand_env_variables(creds_config.get("username", "")),
                    email=self._expand_env_variables(creds_config.get("email", "")),
                    password=self._expand_env_variables(creds_config.get("password", "")),
                    api_token=self._expand_env_variables(creds_config.get("api_token", "")),
                    api_key=self._expand_env_variables(creds_config.get("api_key", "")),
                    secret_key=self._expand_env_variables(creds_config.get("secret_key", ""))
                )
                
                # Parse configuration
                config_data = platform_config.get("config", {})
                config = PlatformConfig(
                    platform=platform_type,
                    enabled=True,
                    base_url=config_data.get("base_url"),
                    rate_limit_per_hour=config_data.get("rate_limit_per_hour", 60),
                    rate_limit_per_minute=config_data.get("rate_limit_per_minute", 10),
                    retry_config=config_data.get("retry_config", {}),
                    custom_headers=config_data.get("custom_headers", {}),
                    submission_settings=config_data.get("submission_settings", {}),
                    severity_mapping=config_data.get("severity_mapping", {})
                )
                
                # Initialize connector
                connector = connector_class(credentials, config)
                self.connectors[platform_type] = connector
                
                # Initialize stats
                self.platform_stats[platform_type] = PlatformStats(platform=platform_type)
                
                self.logger.info(f"Initialized connector for {platform_name}")
                
            except Exception as e:
                self.logger.error(f"Failed to initialize {platform_name} connector: {e}")
    
    async def test_all_connections(self) -> Dict[PlatformType, Tuple[bool, Optional[str]]]:
        """Test connections to all enabled platforms."""
        results = {}
        
        for platform_type, connector in self.connectors.items():
            try:
                success, message = await connector.test_connection()
                results[platform_type] = (success, message)
                self.logger.info(f"{platform_type.value} connection test: {'PASS' if success else 'FAIL'}")
                if message:
                    self.logger.info(f"  {message}")
            except Exception as e:
                results[platform_type] = (False, str(e))
                self.logger.error(f"{platform_type.value} connection test failed: {e}")
        
        return results
    
    def convert_vulnerability_report_to_submission_data(
        self, 
        finding_data: Dict[str, Any],
        platform_type: PlatformType
    ) -> PlatformSubmissionData:
        """Convert a vulnerability finding to platform submission data."""
        
        # Map severity
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium", 
            "low": "low",
            "info": "informational"
        }
        
        # Create submission data from dictionary
        submission_data = PlatformSubmissionData(
            title=finding_data.get("title", ""),
            description=finding_data.get("description", ""),
            severity=severity_map.get(finding_data.get("severity", "medium").lower(), "medium"),
            target=finding_data.get("target", ""),
            proof_of_concept=finding_data.get("proof_of_concept", ""),
            impact=finding_data.get("impact", ""),
            cvss_score=finding_data.get("cvss_score"),
            cvss_vector=finding_data.get("cvss_vector"),
            cwe_references=finding_data.get("cwe_references", []),
            cve_references=finding_data.get("cve_references", []),
            affected_assets=finding_data.get("affected_urls", []),
            steps_to_reproduce=finding_data.get("steps_to_reproduce", []),
            weakness_type=finding_data.get("weakness_type"),
            remediation_advice=finding_data.get("remediation_advice"),
            business_impact=finding_data.get("business_impact"),
            technical_impact=finding_data.get("technical_impact"),
            source_report_id=finding_data.get("source_report_id"),
            source_scan_id=finding_data.get("source_scan_id")
        )
        
        return submission_data
    
    async def submit_finding_to_platform(
        self, 
        platform_type: PlatformType,
        finding_data: Dict[str, Any]
    ) -> SubmissionResult:
        """Submit a single finding to a specific platform."""
        if platform_type not in self.connectors:
            return SubmissionResult(
                platform=platform_type,
                submission_id="",
                success=False,
                error_message=f"Platform {platform_type.value} not configured or enabled"
            )
        
        connector = self.connectors[platform_type]
        
        try:
            # Convert finding to submission data
            submission_data = self.convert_vulnerability_report_to_submission_data(
                finding_data, platform_type
            )
            
            # Submit to platform
            result = await connector.submit_vulnerability(submission_data)
            
            # Update stats
            self._update_submission_stats(platform_type, result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to submit finding to {platform_type.value}: {e}")
            return SubmissionResult(
                platform=platform_type,
                submission_id=finding_data.get("finding_id", ""),
                success=False,
                error_message=str(e)
            )
    
    async def submit_findings_to_all_platforms(
        self, 
        findings_data: List[Dict[str, Any]],
        findings_filter: Optional[callable] = None
    ) -> Dict[PlatformType, List[SubmissionResult]]:
        """Submit vulnerability findings to all enabled platforms."""
        results = {}
        
        # Filter findings if filter provided
        findings = findings_data
        if findings_filter:
            findings = [f for f in findings if findings_filter(f)]
        
        # Submit to each platform
        for platform_type, connector in self.connectors.items():
            platform_results = []
            
            for finding in findings:
                try:
                    result = await self.submit_finding_to_platform(platform_type, finding)
                    platform_results.append(result)
                    
                    # Add delay between submissions
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    self.logger.error(f"Error submitting finding {finding.get('finding_id', 'unknown')} to {platform_type.value}: {e}")
                    platform_results.append(SubmissionResult(
                        platform=platform_type,
                        submission_id=finding.get("finding_id", ""),
                        success=False,
                        error_message=str(e)
                    ))
            
            results[platform_type] = platform_results
            
            # Delay between platforms
            await asyncio.sleep(2)
        
        return results
    
    async def check_submission_status_bulk(
        self, 
        platform_type: PlatformType,
        report_ids: List[str]
    ) -> List[StatusCheckResult]:
        """Check status for multiple submissions on a platform."""
        if platform_type not in self.connectors:
            return []
        
        connector = self.connectors[platform_type]
        return await connector.bulk_status_check(report_ids)
    
    async def get_platform_rewards(
        self, 
        platform_type: PlatformType,
        report_ids: List[str]
    ) -> List[Optional[RewardInfo]]:
        """Get reward information for multiple reports."""
        if platform_type not in self.connectors:
            return []
        
        connector = self.connectors[platform_type]
        rewards = []
        
        for report_id in report_ids:
            try:
                reward = await connector.get_reward_info(report_id)
                rewards.append(reward)
                await asyncio.sleep(0.5)  # Rate limiting
            except Exception as e:
                self.logger.error(f"Failed to get reward info for {report_id}: {e}")
                rewards.append(None)
        
        return rewards
    
    def get_platform_statistics(self, platform_type: PlatformType) -> Optional[PlatformStats]:
        """Get statistics for a specific platform."""
        return self.platform_stats.get(platform_type)
    
    def get_all_platform_statistics(self) -> Dict[PlatformType, PlatformStats]:
        """Get statistics for all platforms."""
        return self.platform_stats.copy()
    
    def _update_submission_stats(self, platform_type: PlatformType, result: SubmissionResult):
        """Update platform statistics based on submission result."""
        stats = self.platform_stats.get(platform_type)
        if not stats:
            return
        
        stats.total_submissions += 1
        stats.last_submission_date = datetime.now()
        
        if result.success:
            if result.status == SubmissionStatus.ACCEPTED:
                stats.accepted_submissions += 1
            # Calculate success rate
            total_decided = stats.accepted_submissions + stats.rejected_submissions + stats.duplicate_submissions
            if total_decided > 0:
                stats.success_rate = stats.accepted_submissions / total_decided
        
        stats.statistics_updated_at = datetime.now()
    
    async def cleanup(self):
        """Clean up resources and close connections."""
        for connector in self.connectors.values():
            try:
                connector.close()
            except Exception as e:
                self.logger.error(f"Error closing connector: {e}")
        
        self.connectors.clear()
    
    def get_enabled_platforms(self) -> List[PlatformType]:
        """Get list of enabled platforms."""
        return list(self.connectors.keys())
    
    def is_platform_enabled(self, platform_type: PlatformType) -> bool:
        """Check if a platform is enabled."""
        return platform_type in self.connectors
    
    async def authenticate_all_platforms(self) -> Dict[PlatformType, bool]:
        """Authenticate with all enabled platforms."""
        results = {}
        
        for platform_type, connector in self.connectors.items():
            try:
                success = await connector.authenticate()
                results[platform_type] = success
                self.logger.info(f"{platform_type.value} authentication: {'SUCCESS' if success else 'FAILED'}")
            except Exception as e:
                results[platform_type] = False
                self.logger.error(f"{platform_type.value} authentication failed: {e}")
        
        return results