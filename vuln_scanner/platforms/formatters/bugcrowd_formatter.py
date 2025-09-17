"""Bugcrowd-specific report formatter."""

from typing import Dict, List, Optional

from ...reporting.models import VulnerabilityReport, TechnicalFinding, ProofOfConcept
from ..models.platform_models import PlatformType
from .base_formatter import PlatformReportFormatter


class BugcrowdFormatter(PlatformReportFormatter):
    """Bugcrowd-specific report formatter."""
    
    def __init__(self):
        super().__init__(PlatformType.BUGCROWD)
    
    def format_finding_title(self, finding: TechnicalFinding) -> str:
        """Format finding title for Bugcrowd."""
        # Bugcrowd prefers descriptive titles with vulnerability type
        title = finding.title
        
        # Add vulnerability type if available
        if finding.cwe_references:
            cwe = finding.cwe_references[0]
            if 'xss' in cwe.lower():
                title = f"Cross-Site Scripting (XSS): {title}"
            elif 'sql' in cwe.lower():
                title = f"SQL Injection: {title}"
            elif 'csrf' in cwe.lower():
                title = f"Cross-Site Request Forgery (CSRF): {title}"
            elif 'rce' in cwe.lower():
                title = f"Remote Code Execution: {title}"
        
        return title
    
    def format_finding_description(self, finding: TechnicalFinding, report: VulnerabilityReport) -> str:
        """Format finding description for Bugcrowd."""
        sections = []
        
        # Executive summary
        sections.append("**Executive Summary**")
        sections.append(finding.description)
        
        # Vulnerability details
        sections.append("**Vulnerability Details**")
        vulnerability_details = []
        
        if finding.affected_urls:
            vulnerability_details.append(f"Affected URL(s): {', '.join(finding.affected_urls)}")
        
        technical_details = self._format_technical_details(finding)
        if technical_details:
            vulnerability_details.append(technical_details)
        
        sections.append("\\n".join(vulnerability_details))
        
        # Steps to reproduce
        if finding.proof_of_concept and finding.proof_of_concept.steps:
            sections.append("**Steps to Reproduce**")
            steps_text = self.format_steps_to_reproduce(finding.proof_of_concept.steps)
            sections.append(steps_text)
        
        # Proof of concept
        poc = self.format_proof_of_concept(finding.proof_of_concept)
        if poc:
            sections.append("**Proof of Concept**")
            sections.append(poc)
        
        # Impact assessment
        impact = self.format_impact_description(finding)
        if impact:
            sections.append("**Impact Assessment**")
            sections.append(impact)
        
        # Risk rating
        if finding.cvss_score:
            sections.append("**Risk Rating**")
            sections.append(f"CVSS Score: {finding.cvss_score}/10 ({finding.severity.value.title()})")
        
        # Remediation
        remediation = self.format_remediation_advice(finding)
        if remediation:
            sections.append("**Remediation Recommendations**")
            sections.append(remediation)
        
        # References
        if finding.references:
            sections.append("**References**")
            for ref in finding.references:
                sections.append(f"• {ref.title}: {ref.url}")
        
        return "\\n\\n".join(sections)
    
    def format_proof_of_concept(self, poc: Optional[ProofOfConcept]) -> str:
        """Format proof of concept for Bugcrowd."""
        if not poc:
            return ""
        
        sections = []
        
        if poc.description:
            sections.append(poc.description)
        
        # HTTP details
        if poc.request_response:
            sections.append("**HTTP Request/Response:**")
            sections.append("```")
            
            if isinstance(poc.request_response, dict):
                if 'request' in poc.request_response:
                    sections.append("Request:")
                    sections.append(str(poc.request_response['request']))
                if 'response' in poc.request_response:
                    sections.append("\\nResponse:")
                    sections.append(str(poc.request_response['response']))
            else:
                sections.append(str(poc.request_response))
            
            sections.append("```")
        
        # Code samples
        if poc.code_samples:
            sections.append("**Code Examples:**")
            for language, code in poc.code_samples.items():
                sections.append(f"{language.title()} code:")
                sections.append(f"```{language}")
                sections.append(code)
                sections.append("```")
        
        # Exploitability rating
        if poc.exploitability_rating > 0:
            sections.append(f"**Exploitability Rating:** {poc.exploitability_rating}/10")
        
        return "\\n\\n".join(sections)
    
    def format_steps_to_reproduce(self, steps: List[str]) -> str:
        """Format steps to reproduce for Bugcrowd."""
        if not steps:
            return ""
        
        formatted_steps = []
        for i, step in enumerate(steps, 1):
            formatted_steps.append(f"Step {i}: {step}")
        
        return "\\n".join(formatted_steps)
    
    def format_impact_description(self, finding: TechnicalFinding) -> str:
        """Format impact description for Bugcrowd."""
        impact_parts = []
        
        # Business impact
        if finding.business_impact:
            impact_parts.append(f"Business Impact: {finding.business_impact}")
        
        # Technical impact  
        if finding.technical_impact:
            impact_parts.append(f"Technical Impact: {finding.technical_impact}")
        
        # Risk assessment based on severity
        risk_descriptions = {
            'critical': "This vulnerability poses an immediate and severe risk to the organization. Attackers could potentially gain complete control over affected systems.",
            'high': "This vulnerability represents a significant security risk that could lead to unauthorized access to sensitive data or systems.",
            'medium': "This vulnerability could be exploited by attackers to gain elevated privileges or access to restricted resources.",
            'low': "This vulnerability has limited impact but should be addressed as part of overall security hardening.",
            'info': "This finding provides information that could assist attackers in reconnaissance activities."
        }
        
        if not impact_parts:
            impact_parts.append(risk_descriptions.get(finding.severity.value, "Impact analysis pending."))
        
        return "\\n".join(impact_parts)
    
    def format_remediation_advice(self, finding: TechnicalFinding) -> str:
        """Format remediation advice for Bugcrowd."""
        if not finding.remediation:
            return ""
        
        sections = []
        
        # Main remediation description
        sections.append(finding.remediation.description)
        
        # Specific remediation steps
        if finding.remediation.remediation_steps:
            sections.append("**Remediation Steps:**")
            for i, step in enumerate(finding.remediation.remediation_steps, 1):
                sections.append(f"{i}. {step}")
        
        # Timeline and priority
        if finding.remediation.timeline_estimate or finding.remediation.priority:
            timeline_priority = []
            if finding.remediation.priority:
                timeline_priority.append(f"Priority: {finding.remediation.priority}")
            if finding.remediation.timeline_estimate:
                timeline_priority.append(f"Estimated Timeline: {finding.remediation.timeline_estimate}")
            sections.append("**Implementation Details:**")
            sections.append(" | ".join(timeline_priority))
        
        # Verification steps
        if finding.remediation.verification_steps:
            sections.append("**Verification Steps:**")
            for i, step in enumerate(finding.remediation.verification_steps, 1):
                sections.append(f"{i}. {step}")
        
        return "\\n\\n".join(sections)
    
    def get_severity_mapping(self) -> Dict[str, str]:
        """Get Bugcrowd severity mapping (uses P1-P5 priority system)."""
        return {
            'critical': 'P1',
            'high': 'P2',
            'medium': 'P3',
            'low': 'P4',
            'info': 'P5'
        }
    
    def get_maximum_title_length(self) -> int:
        """Get maximum title length for Bugcrowd (150 chars)."""
        return 150
    
    def get_maximum_description_length(self) -> int:
        """Get maximum description length for Bugcrowd."""
        return 25000  # Reasonable limit for Bugcrowd submissions