"""HackerOne-specific report formatter."""

from typing import Dict, List, Optional

from ...reporting.models import VulnerabilityReport, TechnicalFinding, ProofOfConcept
from ..models.platform_models import PlatformType
from .base_formatter import PlatformReportFormatter


class HackerOneFormatter(PlatformReportFormatter):
    """HackerOne-specific report formatter."""
    
    def __init__(self):
        super().__init__(PlatformType.HACKERONE)
    
    def format_finding_title(self, finding: TechnicalFinding) -> str:
        """Format finding title for HackerOne."""
        # HackerOne prefers concise, action-oriented titles
        title = finding.title
        
        # Add severity indicator for high/critical findings
        if finding.severity.value in ['critical', 'high']:
            title = f"[{finding.severity.value.upper()}] {title}"
        
        return title
    
    def format_finding_description(self, finding: TechnicalFinding, report: VulnerabilityReport) -> str:
        """Format finding description for HackerOne."""
        sections = []
        
        # Summary section
        sections.append("## Summary")
        sections.append(finding.description)
        
        # Technical details
        technical_details = self._format_technical_details(finding)
        if technical_details:
            sections.append("## Technical Details")
            sections.append(technical_details)
        
        # Impact section
        impact = self.format_impact_description(finding)
        if impact:
            sections.append("## Impact")
            sections.append(impact)
        
        # Steps to reproduce
        if finding.proof_of_concept and finding.proof_of_concept.steps:
            sections.append("## Steps to Reproduce")
            steps_text = self.format_steps_to_reproduce(finding.proof_of_concept.steps)
            sections.append(steps_text)
        
        # Proof of concept
        poc = self.format_proof_of_concept(finding.proof_of_concept)
        if poc:
            sections.append("## Proof of Concept")
            sections.append(poc)
        
        # Remediation
        remediation = self.format_remediation_advice(finding)
        if remediation:
            sections.append("## Remediation")
            sections.append(remediation)
        
        # References
        if finding.references:
            sections.append("## References")
            for ref in finding.references:
                sections.append(f"- [{ref.title}]({ref.url})")
        
        # Add report metadata
        metadata = self._format_metadata(report)
        if metadata:
            sections.append("## Report Metadata")
            sections.append(metadata)
        
        return "\\n\\n".join(sections)
    
    def format_proof_of_concept(self, poc: Optional[ProofOfConcept]) -> str:
        """Format proof of concept for HackerOne."""
        if not poc:
            return ""
        
        sections = []
        
        # Main POC description
        if poc.description:
            sections.append(poc.description)
        
        # Request/Response data
        if poc.request_response:
            sections.append("### HTTP Request/Response")
            sections.append("```http")
            
            if isinstance(poc.request_response, dict):
                if 'request' in poc.request_response:
                    sections.append("# Request:")
                    sections.append(str(poc.request_response['request']))
                if 'response' in poc.request_response:
                    sections.append("\\n# Response:")
                    sections.append(str(poc.request_response['response']))
            else:
                sections.append(str(poc.request_response))
            
            sections.append("```")
        
        # Code samples
        if poc.code_samples:
            sections.append("### Code Examples")
            for language, code in poc.code_samples.items():
                sections.append(f"**{language.title()}:**")
                sections.append(f"```{language}")
                sections.append(code)
                sections.append("```")
        
        # Screenshots
        if poc.screenshots:
            sections.append("### Screenshots")
            for i, screenshot in enumerate(poc.screenshots):
                sections.append(f"![Screenshot {i+1}]({screenshot})")
        
        # Video
        if poc.video_path:
            sections.append("### Video Demonstration")
            sections.append(f"[Video proof of concept]({poc.video_path})")
        
        return "\\n\\n".join(sections)
    
    def format_steps_to_reproduce(self, steps: List[str]) -> str:
        """Format steps to reproduce for HackerOne."""
        if not steps:
            return ""
        
        formatted_steps = []
        for i, step in enumerate(steps, 1):
            formatted_steps.append(f"{i}. {step}")
        
        return "\\n".join(formatted_steps)
    
    def format_impact_description(self, finding: TechnicalFinding) -> str:
        """Format impact description for HackerOne."""
        impact_parts = []
        
        # Business impact
        if finding.business_impact:
            impact_parts.append(f"**Business Impact:** {finding.business_impact}")
        
        # Technical impact
        if finding.technical_impact:
            impact_parts.append(f"**Technical Impact:** {finding.technical_impact}")
        
        # Generic impact based on severity
        if not impact_parts:
            severity_impacts = {
                'critical': "This vulnerability could lead to complete system compromise, data breach, or significant business disruption.",
                'high': "This vulnerability could result in unauthorized access to sensitive data or system functions.",
                'medium': "This vulnerability could allow attackers to gain elevated privileges or access restricted information.",
                'low': "This vulnerability could be used in combination with other attacks to compromise security.",
                'info': "This finding provides information that could be useful for attackers in planning future attacks."
            }
            impact_parts.append(severity_impacts.get(finding.severity.value, "Impact assessment pending."))
        
        return "\\n\\n".join(impact_parts)
    
    def format_remediation_advice(self, finding: TechnicalFinding) -> str:
        """Format remediation advice for HackerOne."""
        if finding.remediation:
            sections = []
            
            sections.append(finding.remediation.description)
            
            if finding.remediation.remediation_steps:
                sections.append("### Remediation Steps:")
                for i, step in enumerate(finding.remediation.remediation_steps, 1):
                    sections.append(f"{i}. {step}")
            
            if finding.remediation.verification_steps:
                sections.append("### Verification Steps:")
                for i, step in enumerate(finding.remediation.verification_steps, 1):
                    sections.append(f"{i}. {step}")
            
            if finding.remediation.timeline_estimate:
                sections.append(f"**Estimated Timeline:** {finding.remediation.timeline_estimate}")
            
            return "\\n\\n".join(sections)
        
        return ""
    
    def get_severity_mapping(self) -> Dict[str, str]:
        """Get HackerOne severity mapping."""
        return {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'none'
        }
    
    def get_maximum_title_length(self) -> int:
        """Get maximum title length for HackerOne (100 chars)."""
        return 100
    
    def get_maximum_description_length(self) -> int:
        """Get maximum description length for HackerOne."""
        # HackerOne doesn't have a strict limit, but we use a reasonable max
        return 50000
    
    def get_platform_specific_tags(self, finding: TechnicalFinding) -> List[str]:
        """Get HackerOne-specific tags."""
        tags = super().get_platform_specific_tags(finding)
        
        # Add HackerOne specific tags
        if finding.verification_status.value == 'verified':
            tags.append('verified')
        
        # Add weakness type tags
        weakness_tags = {
            'xss': ['cross-site-scripting', 'web'],
            'sql': ['sql-injection', 'database'],
            'csrf': ['cross-site-request-forgery', 'web'],
            'rce': ['remote-code-execution', 'server'],
            'lfi': ['local-file-inclusion', 'web'],
            'rfi': ['remote-file-inclusion', 'web'],
            'ssrf': ['server-side-request-forgery', 'web'],
            'xxe': ['xml-external-entities', 'web']
        }
        
        for weakness in finding.cwe_references:
            weakness_lower = weakness.lower()
            for key, weakness_tags_list in weakness_tags.items():
                if key in weakness_lower:
                    tags.extend(weakness_tags_list)
                    break
        
        return tags