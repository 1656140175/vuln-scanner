"""Intigriti-specific report formatter."""

from typing import Dict, List, Optional

from ...reporting.models import VulnerabilityReport, TechnicalFinding, ProofOfConcept
from ..models.platform_models import PlatformType
from .base_formatter import PlatformReportFormatter


class IntigritiFormatter(PlatformReportFormatter):
    """Intigriti-specific report formatter."""
    
    def __init__(self):
        super().__init__(PlatformType.INTIGRITI)
    
    def format_finding_title(self, finding: TechnicalFinding) -> str:
        """Format finding title for Intigriti."""
        # Intigriti prefers clear, technical titles
        return finding.title.strip()
    
    def format_finding_description(self, finding: TechnicalFinding, report: VulnerabilityReport) -> str:
        """Format finding description for Intigriti."""
        sections = []
        
        # Description
        sections.append("## Description")
        sections.append(finding.description)
        
        # Affected endpoint/asset
        if finding.affected_urls:
            sections.append("## Affected Asset")
            sections.append("- " + "\\n- ".join(finding.affected_urls))
        
        # Technical information
        technical_details = self._format_technical_details(finding)
        if technical_details:
            sections.append("## Technical Information")
            sections.append(technical_details)
        
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
        
        # Impact
        impact = self.format_impact_description(finding)
        if impact:
            sections.append("## Impact")
            sections.append(impact)
        
        # Recommendations
        remediation = self.format_remediation_advice(finding)
        if remediation:
            sections.append("## Recommendations")
            sections.append(remediation)
        
        # Additional information
        if finding.references:
            sections.append("## References")
            for ref in finding.references:
                sections.append(f"- [{ref.title}]({ref.url})")
        
        return "\\n\\n".join(sections)
    
    def format_proof_of_concept(self, poc: Optional[ProofOfConcept]) -> str:
        """Format proof of concept for Intigriti."""
        if not poc:
            return ""
        
        sections = []
        
        if poc.description:
            sections.append(poc.description)
        
        # Request/Response
        if poc.request_response:
            sections.append("### HTTP Request/Response")
            sections.append("```http")
            
            if isinstance(poc.request_response, dict):
                if 'request' in poc.request_response:
                    sections.append("# Request")
                    sections.append(str(poc.request_response['request']))
                if 'response' in poc.request_response:
                    sections.append("\\n# Response")
                    sections.append(str(poc.request_response['response']))
            else:
                sections.append(str(poc.request_response))
            
            sections.append("```")
        
        # Code examples
        if poc.code_samples:
            sections.append("### Code Examples")
            for language, code in poc.code_samples.items():
                sections.append(f"**{language.title()}:**")
                sections.append(f"```{language}")
                sections.append(code)
                sections.append("```")
        
        # Screenshots
        if poc.screenshots:
            sections.append("### Visual Evidence")
            for i, screenshot in enumerate(poc.screenshots, 1):
                sections.append(f"Screenshot {i}: ![Evidence]({screenshot})")
        
        return "\\n\\n".join(sections)
    
    def format_steps_to_reproduce(self, steps: List[str]) -> str:
        """Format steps to reproduce for Intigriti."""
        if not steps:
            return ""
        
        formatted_steps = []
        for i, step in enumerate(steps, 1):
            formatted_steps.append(f"{i}. {step}")
        
        return "\\n".join(formatted_steps)
    
    def format_impact_description(self, finding: TechnicalFinding) -> str:
        """Format impact description for Intigriti."""
        impact_sections = []
        
        # Business impact
        if finding.business_impact:
            impact_sections.append(f"**Business Impact:** {finding.business_impact}")
        
        # Technical impact
        if finding.technical_impact:
            impact_sections.append(f"**Technical Impact:** {finding.technical_impact}")
        
        # Severity-based impact
        if not impact_sections:
            severity_impacts = {
                'critical': "Critical vulnerability that could lead to complete system compromise or significant data breach.",
                'high': "High-impact vulnerability that could result in unauthorized access to sensitive information or system functions.",
                'medium': "Medium-impact vulnerability that could be exploited to gain elevated access or compromise data integrity.", 
                'low': "Low-impact vulnerability that could assist attackers in reconnaissance or be combined with other vulnerabilities.",
                'info': "Informational finding that provides insight into potential security weaknesses."
            }
            impact_sections.append(severity_impacts.get(finding.severity.value, "Impact assessment required."))
        
        # Add exploitability assessment
        if finding.exploit_complexity:
            complexity_map = {
                'low': 'Easy to exploit - minimal technical skills required',
                'medium': 'Moderate exploitation complexity - some technical knowledge needed',
                'high': 'Difficult to exploit - advanced technical skills required'
            }
            exploit_desc = complexity_map.get(finding.exploit_complexity, finding.exploit_complexity)
            impact_sections.append(f"**Exploitability:** {exploit_desc}")
        
        return "\\n\\n".join(impact_sections)
    
    def format_remediation_advice(self, finding: TechnicalFinding) -> str:
        """Format remediation advice for Intigriti."""
        if not finding.remediation:
            return ""
        
        sections = []
        
        # Main recommendation
        sections.append(finding.remediation.description)
        
        # Specific steps
        if finding.remediation.remediation_steps:
            sections.append("### Implementation Steps")
            for i, step in enumerate(finding.remediation.remediation_steps, 1):
                sections.append(f"{i}. {step}")
        
        # Priority and timeline
        details = []
        if finding.remediation.priority:
            details.append(f"**Priority:** {finding.remediation.priority}")
        if finding.remediation.effort_estimate:
            details.append(f"**Effort:** {finding.remediation.effort_estimate}")
        if finding.remediation.timeline_estimate:
            details.append(f"**Timeline:** {finding.remediation.timeline_estimate}")
        
        if details:
            sections.append("### Implementation Details")
            sections.append(" | ".join(details))
        
        # Verification
        if finding.remediation.verification_steps:
            sections.append("### Verification")
            for i, step in enumerate(finding.remediation.verification_steps, 1):
                sections.append(f"{i}. {step}")
        
        return "\\n\\n".join(sections)
    
    def get_severity_mapping(self) -> Dict[str, str]:
        """Get Intigriti severity mapping."""
        return {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Info'
        }
    
    def get_maximum_title_length(self) -> int:
        """Get maximum title length for Intigriti (120 chars)."""
        return 120
    
    def get_maximum_description_length(self) -> int:
        """Get maximum description length for Intigriti."""
        return 30000