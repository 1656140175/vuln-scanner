"""Base platform report formatter interface."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime

from ...reporting.models import VulnerabilityReport, TechnicalFinding, ProofOfConcept
from ..models.platform_models import PlatformType, PlatformSubmissionData


class PlatformReportFormatter(ABC):
    """Abstract base class for platform-specific report formatters."""
    
    def __init__(self, platform_type: PlatformType):
        self.platform_type = platform_type
    
    @abstractmethod
    def format_finding_title(self, finding: TechnicalFinding) -> str:
        """Format finding title for the platform."""
        pass
    
    @abstractmethod
    def format_finding_description(self, finding: TechnicalFinding, report: VulnerabilityReport) -> str:
        """Format finding description for the platform."""
        pass
    
    @abstractmethod
    def format_proof_of_concept(self, poc: Optional[ProofOfConcept]) -> str:
        """Format proof of concept for the platform."""
        pass
    
    @abstractmethod
    def format_steps_to_reproduce(self, steps: List[str]) -> str:
        """Format steps to reproduce for the platform."""
        pass
    
    @abstractmethod
    def format_impact_description(self, finding: TechnicalFinding) -> str:
        """Format impact description for the platform."""
        pass
    
    @abstractmethod
    def format_remediation_advice(self, finding: TechnicalFinding) -> str:
        """Format remediation advice for the platform."""
        pass
    
    @abstractmethod
    def get_severity_mapping(self) -> Dict[str, str]:
        """Get platform-specific severity mapping."""
        pass
    
    @abstractmethod
    def get_maximum_title_length(self) -> int:
        """Get maximum allowed title length for the platform."""
        pass
    
    @abstractmethod
    def get_maximum_description_length(self) -> int:
        """Get maximum allowed description length for the platform."""
        pass
    
    def format_complete_submission(
        self, 
        finding: TechnicalFinding, 
        report: VulnerabilityReport
    ) -> PlatformSubmissionData:
        """Format complete submission data for the platform."""
        
        # Extract proof of concept
        poc_text = self.format_proof_of_concept(finding.proof_of_concept)
        
        # Extract steps to reproduce
        steps = []
        if finding.proof_of_concept and finding.proof_of_concept.steps:
            steps = finding.proof_of_concept.steps
        
        # Format title (truncate if needed)
        title = self.format_finding_title(finding)
        max_title_len = self.get_maximum_title_length()
        if len(title) > max_title_len:
            title = title[:max_title_len-3] + "..."
        
        # Format description
        description = self.format_finding_description(finding, report)
        max_desc_len = self.get_maximum_description_length()
        if len(description) > max_desc_len:
            # Try to truncate gracefully
            description = self._truncate_description(description, max_desc_len)
        
        # Map severity
        severity_mapping = self.get_severity_mapping()
        mapped_severity = severity_mapping.get(finding.severity.value, finding.severity.value)
        
        # Determine target
        target = ""
        if finding.affected_urls:
            target = finding.affected_urls[0]
        else:
            target = report.target_info.primary_target
        
        # Create submission data
        return PlatformSubmissionData(
            title=title,
            description=description,
            severity=mapped_severity,
            target=target,
            proof_of_concept=poc_text,
            impact=self.format_impact_description(finding),
            cvss_score=finding.cvss_score,
            cvss_vector=finding.cvss_vector,
            cwe_references=finding.cwe_references,
            cve_references=finding.cve_references,
            affected_assets=finding.affected_urls or [target],
            steps_to_reproduce=steps,
            weakness_type=finding.cwe_references[0] if finding.cwe_references else None,
            remediation_advice=self.format_remediation_advice(finding),
            business_impact=finding.business_impact,
            technical_impact=finding.technical_impact
        )
    
    def _truncate_description(self, description: str, max_length: int) -> str:
        """Truncate description while preserving structure."""
        if len(description) <= max_length:
            return description
        
        # Try to truncate at paragraph boundaries
        paragraphs = description.split('\\n\\n')
        truncated = ""
        
        for paragraph in paragraphs:
            if len(truncated + paragraph + "\\n\\n") <= max_length - 50:  # Leave some buffer
                truncated += paragraph + "\\n\\n"
            else:
                break
        
        # If we couldn't fit any paragraphs, just truncate
        if not truncated:
            truncated = description[:max_length-50]
        
        truncated += "\\n\\n[Description truncated due to platform limits]"
        return truncated
    
    def _format_technical_details(self, finding: TechnicalFinding) -> str:
        """Format technical details section."""
        details = []
        
        if finding.cvss_score:
            details.append(f"**CVSS Score:** {finding.cvss_score}")
        
        if finding.cvss_vector:
            details.append(f"**CVSS Vector:** {finding.cvss_vector}")
        
        if finding.cwe_references:
            details.append(f"**CWE:** {', '.join(finding.cwe_references)}")
        
        if finding.cve_references:
            details.append(f"**CVE:** {', '.join(finding.cve_references)}")
        
        if finding.exploit_complexity:
            details.append(f"**Exploit Complexity:** {finding.exploit_complexity}")
        
        return "\\n".join(details) if details else ""
    
    def _format_metadata(self, report: VulnerabilityReport) -> str:
        """Format report metadata section."""
        metadata = []
        
        metadata.append(f"**Scan ID:** {report.scan_id}")
        metadata.append(f"**Report Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        metadata.append(f"**Scanner Version:** {report.scan_metadata.scanner_version}")
        
        if report.target_info.environment:
            metadata.append(f"**Environment:** {report.target_info.environment}")
        
        return "\\n".join(metadata)
    
    def get_platform_specific_tags(self, finding: TechnicalFinding) -> List[str]:
        """Get platform-specific tags for a finding."""
        tags = []
        
        # Add severity tag
        tags.append(f"severity-{finding.severity.value}")
        
        # Add confidence tag
        tags.append(f"confidence-{finding.confidence.value}")
        
        # Add CWE tags
        for cwe in finding.cwe_references:
            tags.append(f"cwe-{cwe}")
        
        # Add discovery phase tag
        tags.append(f"phase-{finding.discovery_phase}")
        
        return tags