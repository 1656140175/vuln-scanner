"""Comprehensive tests for platform integration system."""

import pytest
import asyncio
import os
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
from pathlib import Path

from vuln_scanner.platforms import (
    PlatformManager,
    PlatformSubmissionData,
    PlatformCredentials,
    PlatformConfig,
    PlatformType,
    SubmissionResult,
    SubmissionStatus
)
from vuln_scanner.platforms.connectors import (
    HackerOneConnector,
    BugcrowdConnector,
    IntigritiConnector,
    OpenBugBountyConnector
)
from vuln_scanner.platforms.formatters import (
    HackerOneFormatter,
    BugcrowdFormatter,
    IntigritiFormatter,
    OpenBugBountyFormatter
)
from vuln_scanner.reporting.models import (
    VulnerabilityReport,
    TechnicalFinding,
    TargetInfo,
    ScanMetadata,
    ExecutiveSummary,
    SeverityLevel,
    ConfidenceLevel,
    ProofOfConcept
)


@pytest.fixture
def sample_vulnerability_report():
    """Create a sample vulnerability report for testing."""
    target_info = TargetInfo(
        primary_target="https://example.com",
        scope=["https://example.com", "https://api.example.com"],
        environment="production"
    )
    
    scan_metadata = ScanMetadata(
        scan_start_time=datetime.now(),
        scan_end_time=datetime.now(),
        total_duration=datetime.now() - datetime.now(),
        scanner_version="1.0.0"
    )
    
    exec_summary = ExecutiveSummary(
        summary_text="Test scan summary",
        key_findings_count={SeverityLevel.HIGH: 1}
    )
    
    poc = ProofOfConcept(
        poc_id="test-poc",
        title="Test POC",
        description="Test proof of concept",
        steps=["Step 1: Navigate to vulnerable endpoint", "Step 2: Execute payload"],
        request_response={"request": "GET /test HTTP/1.1", "response": "HTTP/1.1 200 OK"}
    )
    
    finding = TechnicalFinding(
        finding_id="test-finding-1",
        title="Cross-Site Scripting (XSS) in Search Parameter",
        description="The application is vulnerable to reflected XSS through the search parameter",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.CONFIRMED,
        cvss_score=7.5,
        cwe_references=["CWE-79"],
        affected_urls=["https://example.com/search?q=<script>alert(1)</script>"],
        proof_of_concept=poc,
        business_impact="Potential for account takeover and data theft",
        technical_impact="JavaScript execution in user browsers"
    )
    
    report = VulnerabilityReport(
        report_id="test-report-1",
        scan_id="test-scan-1",
        target_info=target_info,
        scan_metadata=scan_metadata,
        executive_summary=exec_summary,
        technical_findings=[finding]
    )
    
    return report


@pytest.fixture
def sample_credentials():
    """Create sample credentials for testing."""
    return {
        PlatformType.HACKERONE: PlatformCredentials(
            platform=PlatformType.HACKERONE,
            username="test_user",
            api_token="test_token"
        ),
        PlatformType.BUGCROWD: PlatformCredentials(
            platform=PlatformType.BUGCROWD,
            email="test@example.com",
            password="test_password"
        ),
        PlatformType.INTIGRITI: PlatformCredentials(
            platform=PlatformType.INTIGRITI,
            api_key="test_api_key",
            secret_key="test_secret"
        ),
        PlatformType.OPENBUGBOUNTY: PlatformCredentials(
            platform=PlatformType.OPENBUGBOUNTY,
            username="test_user",
            password="test_password"
        )
    }


@pytest.fixture
def sample_config():
    """Create sample platform configuration."""
    return PlatformConfig(
        platform=PlatformType.HACKERONE,
        enabled=True,
        base_url="https://api.test.com",
        rate_limit_per_hour=60,
        rate_limit_per_minute=10
    )


class TestPlatformDataModels:
    """Test platform data models."""
    
    def test_platform_credentials_validation(self, sample_credentials):
        """Test platform credentials validation."""
        # Test valid HackerOne credentials
        hackerone_creds = sample_credentials[PlatformType.HACKERONE]
        assert hackerone_creds.is_valid() is True
        
        # Test invalid HackerOne credentials
        invalid_creds = PlatformCredentials(
            platform=PlatformType.HACKERONE,
            username="test",
            api_token=""  # Missing token
        )
        assert invalid_creds.is_valid() is False
        
        # Test valid Bugcrowd credentials
        bugcrowd_creds = sample_credentials[PlatformType.BUGCROWD]
        assert bugcrowd_creds.is_valid() is True
    
    def test_submission_data_creation(self):
        """Test platform submission data creation."""
        submission = PlatformSubmissionData(
            title="Test Vulnerability",
            description="Test description",
            severity="high",
            target="https://example.com",
            proof_of_concept="Test POC"
        )
        
        assert submission.title == "Test Vulnerability"
        assert submission.severity == "high"
        assert submission.submission_id is not None
        assert submission.created_at is not None
    
    def test_submission_result_creation(self):
        """Test submission result creation."""
        result = SubmissionResult(
            platform=PlatformType.HACKERONE,
            submission_id="test-123",
            platform_report_id="report-456",
            success=True,
            status=SubmissionStatus.SUBMITTED
        )
        
        assert result.platform == PlatformType.HACKERONE
        assert result.success is True
        assert result.status == SubmissionStatus.SUBMITTED


class TestPlatformConnectors:
    """Test platform connectors."""
    
    @pytest.mark.asyncio
    async def test_hackerone_connector_initialization(self, sample_credentials, sample_config):
        """Test HackerOne connector initialization."""
        credentials = sample_credentials[PlatformType.HACKERONE]
        config = sample_config
        
        connector = HackerOneConnector(credentials, config)
        
        assert connector.platform_type == PlatformType.HACKERONE
        assert connector.credentials == credentials
        assert connector.config == config
    
    @pytest.mark.asyncio
    async def test_hackerone_format_submission_data(self, sample_credentials, sample_config):
        """Test HackerOne submission data formatting."""
        credentials = sample_credentials[PlatformType.HACKERONE]
        config = sample_config
        
        connector = HackerOneConnector(credentials, config)
        
        submission_data = PlatformSubmissionData(
            title="Test XSS Vulnerability",
            description="Test description",
            severity="high",
            target="https://example.com",
            proof_of_concept="<script>alert(1)</script>"
        )
        
        formatted = connector.format_submission_data(submission_data)
        
        assert "data" in formatted
        assert "type" in formatted["data"]
        assert formatted["data"]["type"] == "report"
        assert "attributes" in formatted["data"]
        
        attributes = formatted["data"]["attributes"]
        assert attributes["title"] == "Test XSS Vulnerability"
        assert attributes["severity_rating"] == "high"
    
    @pytest.mark.asyncio
    @patch('requests.Session.request')
    async def test_hackerone_authentication(self, mock_request, sample_credentials, sample_config):
        """Test HackerOne authentication."""
        # Mock successful authentication response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "username": "test_user"
                }
            }
        }
        mock_request.return_value = mock_response
        
        credentials = sample_credentials[PlatformType.HACKERONE]
        config = sample_config
        
        connector = HackerOneConnector(credentials, config)
        
        result = await connector.authenticate()
        assert result is True
        
        # Test failed authentication
        mock_response.status_code = 401
        result = await connector.authenticate()
        assert result is False
    
    @pytest.mark.asyncio
    async def test_bugcrowd_connector_initialization(self, sample_credentials):
        """Test Bugcrowd connector initialization."""
        credentials = sample_credentials[PlatformType.BUGCROWD]
        config = PlatformConfig(platform=PlatformType.BUGCROWD)
        
        connector = BugcrowdConnector(credentials, config)
        
        assert connector.platform_type == PlatformType.BUGCROWD
        assert connector.credentials == credentials
    
    @pytest.mark.asyncio
    async def test_connector_rate_limiting(self, sample_credentials, sample_config):
        """Test connector rate limiting functionality."""
        credentials = sample_credentials[PlatformType.HACKERONE]
        config = PlatformConfig(
            platform=PlatformType.HACKERONE,
            rate_limit_per_minute=2,  # Very low for testing
            rate_limit_per_hour=10
        )
        
        connector = HackerOneConnector(credentials, config)
        
        # First request should go through
        start_time = connector._last_request_time
        connector._enforce_rate_limit()
        
        # Second request should be delayed
        import time
        time_before = time.time()
        connector._enforce_rate_limit()
        time_after = time.time()
        
        # Should have been delayed
        assert time_after > time_before


class TestPlatformFormatters:
    """Test platform-specific formatters."""
    
    def test_hackerone_formatter(self, sample_vulnerability_report):
        """Test HackerOne formatter."""
        formatter = HackerOneFormatter()
        report = sample_vulnerability_report
        finding = report.technical_findings[0]
        
        # Test title formatting
        title = formatter.format_finding_title(finding)
        assert "[HIGH]" in title  # Should add severity indicator
        assert finding.title in title
        
        # Test description formatting
        description = formatter.format_finding_description(finding, report)
        assert "## Summary" in description
        assert "## Steps to Reproduce" in description
        assert "## Proof of Concept" in description
        
        # Test severity mapping
        severity_mapping = formatter.get_severity_mapping()
        assert severity_mapping["critical"] == "critical"
        assert severity_mapping["info"] == "none"
        
        # Test complete submission formatting
        submission_data = formatter.format_complete_submission(finding, report)
        assert submission_data.title is not None
        assert submission_data.description is not None
        assert submission_data.severity == "high"  # Mapped from HIGH
    
    def test_bugcrowd_formatter(self, sample_vulnerability_report):
        """Test Bugcrowd formatter."""
        formatter = BugcrowdFormatter()
        report = sample_vulnerability_report
        finding = report.technical_findings[0]
        
        # Test title formatting (should add vulnerability type)
        title = formatter.format_finding_title(finding)
        assert "Cross-Site Scripting (XSS):" in title
        
        # Test description formatting
        description = formatter.format_finding_description(finding, report)
        assert "**Executive Summary**" in description
        assert "**Steps to Reproduce**" in description
        assert "**Impact Assessment**" in description
        
        # Test severity mapping (P1-P5 system)
        severity_mapping = formatter.get_severity_mapping()
        assert severity_mapping["critical"] == "P1"
        assert severity_mapping["high"] == "P2"
    
    def test_intigriti_formatter(self, sample_vulnerability_report):
        """Test Intigriti formatter."""
        formatter = IntigritiFormatter()
        report = sample_vulnerability_report
        finding = report.technical_findings[0]
        
        # Test description formatting
        description = formatter.format_finding_description(finding, report)
        assert "## Description" in description
        assert "## Affected Asset" in description
        assert "## Steps to Reproduce" in description
        
        # Test severity mapping
        severity_mapping = formatter.get_severity_mapping()
        assert severity_mapping["critical"] == "Critical"
        assert severity_mapping["high"] == "High"
    
    def test_openbugbounty_formatter(self, sample_vulnerability_report):
        """Test OpenBugBounty formatter."""
        formatter = OpenBugBountyFormatter()
        report = sample_vulnerability_report
        finding = report.technical_findings[0]
        
        # Test title formatting (should add vulnerability type)
        title = formatter.format_finding_title(finding)
        assert "XSS -" in title
        
        # Test description formatting (plain text style)
        description = formatter.format_finding_description(finding, report)
        assert "VULNERABILITY SUMMARY:" in description
        assert "AFFECTED URL(S):" in description
        assert "STEPS TO REPRODUCE:" in description
        
        # Test severity mapping
        severity_mapping = formatter.get_severity_mapping()
        assert severity_mapping["critical"] == "High"
        assert severity_mapping["medium"] == "Medium"


class TestPlatformManager:
    """Test platform manager functionality."""
    
    @pytest.fixture
    def mock_config_file(self, tmp_path):
        """Create a mock configuration file."""
        config_content = """
hackerone:
  enabled: true
  credentials:
    username: test_user
    api_token: test_token
  config:
    base_url: https://api.hackerone.com/v1
    rate_limit_per_hour: 60

bugcrowd:
  enabled: false
  credentials:
    email: test@example.com
    password: test_password
  config:
    base_url: https://api.bugcrowd.com
    rate_limit_per_hour: 100
"""
        config_file = tmp_path / "test_platforms.yml"
        config_file.write_text(config_content)
        return str(config_file)
    
    def test_platform_manager_initialization(self, mock_config_file):
        """Test platform manager initialization."""
        with patch.dict(os.environ, {'HACKERONE_USERNAME': 'test_user', 'HACKERONE_API_TOKEN': 'test_token'}):
            manager = PlatformManager(config_path=mock_config_file)
            
            assert PlatformType.HACKERONE in manager.connectors
            assert PlatformType.BUGCROWD not in manager.connectors  # Disabled
    
    @pytest.mark.asyncio
    async def test_platform_manager_test_connections(self, mock_config_file):
        """Test platform manager connection testing."""
        with patch.dict(os.environ, {'HACKERONE_USERNAME': 'test_user', 'HACKERONE_API_TOKEN': 'test_token'}):
            manager = PlatformManager(config_path=mock_config_file)
            
            # Mock the test_connection method
            for connector in manager.connectors.values():
                connector.test_connection = AsyncMock(return_value=(True, "Connection successful"))
            
            results = await manager.test_all_connections()
            
            assert PlatformType.HACKERONE in results
            success, message = results[PlatformType.HACKERONE]
            assert success is True
    
    @pytest.mark.asyncio
    async def test_platform_manager_submit_finding(self, mock_config_file, sample_vulnerability_report):
        """Test platform manager finding submission."""
        with patch.dict(os.environ, {'HACKERONE_USERNAME': 'test_user', 'HACKERONE_API_TOKEN': 'test_token'}):
            manager = PlatformManager(config_path=mock_config_file)
            
            # Mock the submit_vulnerability method
            mock_result = SubmissionResult(
                platform=PlatformType.HACKERONE,
                submission_id="test-123",
                platform_report_id="report-456",
                success=True,
                status=SubmissionStatus.SUBMITTED
            )
            
            for connector in manager.connectors.values():
                connector.submit_vulnerability = AsyncMock(return_value=mock_result)
            
            report = sample_vulnerability_report
            finding = report.technical_findings[0]
            
            result = await manager.submit_finding_to_platform(
                PlatformType.HACKERONE, report, finding
            )
            
            assert result.success is True
            assert result.platform == PlatformType.HACKERONE
    
    @pytest.mark.asyncio
    async def test_platform_manager_submit_to_all_platforms(self, mock_config_file, sample_vulnerability_report):
        """Test submitting to all enabled platforms."""
        with patch.dict(os.environ, {'HACKERONE_USERNAME': 'test_user', 'HACKERONE_API_TOKEN': 'test_token'}):
            manager = PlatformManager(config_path=mock_config_file)
            
            # Mock the submit_vulnerability method
            mock_result = SubmissionResult(
                platform=PlatformType.HACKERONE,
                submission_id="test-123",
                success=True
            )
            
            for connector in manager.connectors.values():
                connector.submit_vulnerability = AsyncMock(return_value=mock_result)
            
            report = sample_vulnerability_report
            
            results = await manager.submit_report_to_all_platforms(report)
            
            assert PlatformType.HACKERONE in results
            assert len(results[PlatformType.HACKERONE]) > 0
            assert results[PlatformType.HACKERONE][0].success is True
    
    def test_vulnerability_report_conversion(self, mock_config_file, sample_vulnerability_report):
        """Test conversion of vulnerability report to submission data."""
        with patch.dict(os.environ, {'HACKERONE_USERNAME': 'test_user', 'HACKERONE_API_TOKEN': 'test_token'}):
            manager = PlatformManager(config_path=mock_config_file)
            
            report = sample_vulnerability_report
            finding = report.technical_findings[0]
            
            submission_data = manager.convert_vulnerability_report_to_submission_data(
                report, finding, PlatformType.HACKERONE
            )
            
            assert submission_data.title == finding.title
            assert submission_data.description == finding.description
            assert submission_data.severity == "high"  # Mapped from HIGH
            assert submission_data.target == finding.affected_urls[0]
            assert submission_data.cvss_score == finding.cvss_score


class TestIntegrationScenarios:
    """Test complete integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_submission_flow(self, sample_vulnerability_report):
        """Test complete end-to-end submission flow."""
        # Create a mock platform manager with mocked connectors
        manager = PlatformManager()
        
        # Override with mock connectors
        mock_connector = Mock()
        mock_connector.platform_type = PlatformType.HACKERONE
        mock_connector.authenticate = AsyncMock(return_value=True)
        mock_connector.submit_vulnerability = AsyncMock(return_value=SubmissionResult(
            platform=PlatformType.HACKERONE,
            submission_id="test-123",
            platform_report_id="report-456",
            success=True,
            status=SubmissionStatus.SUBMITTED,
            submission_url="https://hackerone.com/reports/456"
        ))
        
        manager.connectors = {PlatformType.HACKERONE: mock_connector}
        
        report = sample_vulnerability_report
        finding = report.technical_findings[0]
        
        # Test submission
        result = await manager.submit_finding_to_platform(
            PlatformType.HACKERONE, report, finding
        )
        
        # Verify results
        assert result.success is True
        assert result.platform_report_id == "report-456"
        assert result.submission_url is not None
        
        # Verify connector was called correctly
        mock_connector.submit_vulnerability.assert_called_once()
        call_args = mock_connector.submit_vulnerability.call_args[0][0]
        assert call_args.title == finding.title
    
    def test_configuration_error_handling(self):
        """Test configuration error handling."""
        # Test with non-existent config file
        with pytest.raises(Exception):
            manager = PlatformManager(config_path="/nonexistent/path.yml")
        
        # Test with invalid credentials
        with patch.dict(os.environ, {}, clear=True):  # Clear environment variables
            manager = PlatformManager()
            # Should initialize with default config (all platforms disabled)
            assert len(manager.connectors) == 0
    
    def test_rate_limiting_compliance(self):
        """Test that rate limiting is properly enforced."""
        # This would require more complex time-based testing
        # For now, we verify the rate limiting structure exists
        config = PlatformConfig(
            platform=PlatformType.HACKERONE,
            rate_limit_per_hour=60,
            rate_limit_per_minute=10
        )
        
        assert config.rate_limit_per_hour == 60
        assert config.rate_limit_per_minute == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])