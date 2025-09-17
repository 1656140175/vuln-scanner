"""OpenBugBounty-specific report formatter."""

from typing import Dict, List, Optional

from ...reporting.models import VulnerabilityReport, TechnicalFinding, ProofOfConcept
from ..models.platform_models import PlatformType
from .base_formatter import PlatformReportFormatter


class OpenBugBountyFormatter(PlatformReportFormatter):
    """OpenBugBounty-specific report formatter."""
    
    def __init__(self):
        super().__init__(PlatformType.OPENBUGBOUNTY)
    
    def format_finding_title(self, finding: TechnicalFinding) -> str:
        """Format finding title for OpenBugBounty."""
        # OpenBugBounty prefers descriptive titles with the vulnerability type
        title = finding.title
        
        # Add vulnerability type prefix if not already present
        vuln_types = {
            'xss': 'XSS',
            'sql': 'SQL Injection',
            'csrf': 'CSRF',
            'rce': 'RCE',
            'lfi': 'LFI',
            'rfi': 'RFI',
            'ssrf': 'SSRF',
            'xxe': 'XXE'
        }
        
        if finding.cwe_references:
            cwe = finding.cwe_references[0].lower()
            for vuln_key, vuln_name in vuln_types.items():
                if vuln_key in cwe and not vuln_name.lower() in title.lower():
                    title = f"{vuln_name} - {title}"
                    break
        
        return title
    
    def format_finding_description(self, finding: TechnicalFinding, report: VulnerabilityReport) -> str:
        """Format finding description for OpenBugBounty."""
        sections = []
        
        # Vulnerability summary
        sections.append("VULNERABILITY SUMMARY:")
        sections.append(finding.description)
        sections.append("")
        
        # Affected URL/Asset
        if finding.affected_urls:
            sections.append("AFFECTED URL(S):")
            for url in finding.affected_urls:
                sections.append(f"- {url}")
            sections.append("")
        
        # Technical details
        technical_details = self._format_technical_details(finding)
        if technical_details:
            sections.append("TECHNICAL DETAILS:")
            # Convert markdown formatting to plain text for OpenBugBounty
            technical_plain = technical_details.replace("**", "").replace("*", "")
            sections.append(technical_plain)
            sections.append("")
        
        # Steps to reproduce
        if finding.proof_of_concept and finding.proof_of_concept.steps:
            sections.append("STEPS TO REPRODUCE:")
            steps_text = self.format_steps_to_reproduce(finding.proof_of_concept.steps)
            sections.append(steps_text)
            sections.append("")
        
        # Proof of concept
        poc = self.format_proof_of_concept(finding.proof_of_concept)
        if poc:
            sections.append("PROOF OF CONCEPT:")
            sections.append(poc)
            sections.append("")
        
        # Impact assessment
        impact = self.format_impact_description(finding)
        if impact:
            sections.append("IMPACT:")
            sections.append(impact)
            sections.append("")
        
        # Remediation
        remediation = self.format_remediation_advice(finding)
        if remediation:
            sections.append("REMEDIATION:")
            sections.append(remediation)
            sections.append("")
        
        # Additional references
        if finding.references:
            sections.append("REFERENCES:")
            for ref in finding.references:
                sections.append(f"- {ref.title}: {ref.url}")
        
        return "\\n".join(sections)
    
    def format_proof_of_concept(self, poc: Optional[ProofOfConcept]) -> str:
        """Format proof of concept for OpenBugBounty."""
        if not poc:
            return ""
        
        sections = []
        
        if poc.description:
            sections.append(poc.description)
        
        # HTTP request/response (plain text format)
        if poc.request_response:
            sections.append("\\nHTTP REQUEST/RESPONSE:")
            sections.append("=" * 40)
            
            if isinstance(poc.request_response, dict):
                if 'request' in poc.request_response:
                    sections.append("REQUEST:")
                    sections.append(str(poc.request_response['request']))
                if 'response' in poc.request_response:
                    sections.append("\\nRESPONSE:")
                    sections.append(str(poc.request_response['response']))
            else:
                sections.append(str(poc.request_response))
            
            sections.append("=" * 40)
        
        # Code samples (plain text)
        if poc.code_samples:
            sections.append("\\nCODE EXAMPLES:")
            for language, code in poc.code_samples.items():
                sections.append(f"\\n{language.upper()} CODE:")
                sections.append("-" * 20)
                sections.append(code)
                sections.append("-" * 20)
        
        return "\\n".join(sections)
    
    def format_steps_to_reproduce(self, steps: List[str]) -> str:
        """Format steps to reproduce for OpenBugBounty."""
        if not steps:
            return ""
        
        formatted_steps = []
        for i, step in enumerate(steps, 1):
            formatted_steps.append(f"{i}. {step}")
        
        return "\\n".join(formatted_steps)
    
    def format_impact_description(self, finding: TechnicalFinding) -> str:
        """Format impact description for OpenBugBounty."""
        impact_parts = []
        
        # Use business and technical impact if available
        if finding.business_impact:
            impact_parts.append(f"Business Impact: {finding.business_impact}")
        
        if finding.technical_impact:
            impact_parts.append(f"Technical Impact: {finding.technical_impact}")
        
        # Generic impact descriptions for OpenBugBounty
        if not impact_parts:
            generic_impacts = {
                'critical': "This critical vulnerability could allow attackers to completely compromise the affected system, leading to full data breach or system takeover.",
                'high': "This high-severity vulnerability could enable attackers to gain unauthorized access to sensitive data or perform privileged operations.",
                'medium': "This vulnerability could be exploited by attackers to gain elevated access or compromise the integrity of the system.",
                'low': "This low-severity vulnerability could provide attackers with information useful for further attacks or minor unauthorized access.",
                'info': "This informational finding reveals details about the system that could assist attackers in planning future attacks."
            }
            impact_parts.append(generic_impacts.get(finding.severity.value, "Impact assessment pending."))
        
        # Add severity classification
        impact_parts.append(f"\\nSeverity Classification: {finding.severity.value.upper()}")
        
        if finding.cvss_score:
            impact_parts.append(f"CVSS Score: {finding.cvss_score}/10")
        
        return "\\n".join(impact_parts)
    
    def format_remediation_advice(self, finding: TechnicalFinding) -> str:
        """Format remediation advice for OpenBugBounty."""
        if not finding.remediation:
            # Provide generic remediation advice based on vulnerability type
            generic_advice = {
                'xss': "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers to prevent XSS attacks.",
                'sql': "Use parameterized queries or prepared statements. Implement proper input validation and avoid dynamic SQL construction.",
                'csrf': "Implement anti-CSRF tokens for all state-changing operations. Verify the referrer header and use SameSite cookies.",
                'rce': "Validate and sanitize all user inputs. Avoid executing user-supplied data as system commands. Use whitelisting for allowed operations.",
                'ssrf': "Implement proper URL validation and use whitelists for allowed destinations. Disable unnecessary URL schemas and implement network segmentation."
            }
            
            if finding.cwe_references:
                cwe = finding.cwe_references[0].lower()
                for vuln_type, advice in generic_advice.items():
                    if vuln_type in cwe:
                        return advice
            
            return "Implement proper security controls to prevent exploitation of this vulnerability. Review and update security policies as needed."
        
        sections = []
        
        # Main remediation description
        sections.append(finding.remediation.description)
        
        # Remediation steps (plain text format)
        if finding.remediation.remediation_steps:
            sections.append("\\nREMEDIATION STEPS:")
            for i, step in enumerate(finding.remediation.remediation_steps, 1):
                sections.append(f"{i}. {step}")
        
        # Priority information
        if finding.remediation.priority:
            sections.append(f"\\nPRIORITY: {finding.remediation.priority.upper()}")
        
        if finding.remediation.timeline_estimate:
            sections.append(f"ESTIMATED TIMELINE: {finding.remediation.timeline_estimate}")
        
        return "\\n".join(sections)
    
    def get_severity_mapping(self) -> Dict[str, str]:
        """Get OpenBugBounty severity mapping."""
        return {
            'critical': 'High',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Info'
        }
    
    def get_maximum_title_length(self) -> int:
        """Get maximum title length for OpenBugBounty (200 chars)."""
        return 200
    
    def get_maximum_description_length(self) -> int:
        """Get maximum description length for OpenBugBounty."""
        return 15000  # Conservative limit for web form submissions