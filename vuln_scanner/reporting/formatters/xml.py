"""XML and Markdown formatters."""

import logging
import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import Union

from .base import BaseFormatter, FormatterError
from ..models import VulnerabilityReport, TechnicalFinding
from ..config import ReportConfig, ReportFormat
from ..templates import TemplateManager


class XMLFormatter(BaseFormatter):
    """XML report formatter."""
    
    @property
    def supported_format(self) -> ReportFormat:
        return ReportFormat.XML
    
    @property
    def output_extension(self) -> str:
        return "xml"
    
    @property
    def content_type(self) -> str:
        return "application/xml"
    
    async def format_report(self, report: VulnerabilityReport,
                          config: ReportConfig,
                          template_manager: TemplateManager) -> str:
        """Format report as XML.
        
        Args:
            report: Vulnerability report data
            config: Report configuration  
            template_manager: Template manager instance
            
        Returns:
            XML report content
        """
        self.logger.info(f"Formatting XML report for {report.target_info.primary_target}")
        
        try:
            # Create root element
            root = ET.Element('vulnerabilityReport')
            root.set('reportId', report.report_id)
            root.set('scanId', report.scan_id)
            root.set('version', report.version)
            root.set('generatedAt', report.generated_at.isoformat())
            
            # Add target information
            self._add_target_info(root, report.target_info)
            
            # Add scan metadata
            self._add_scan_metadata(root, report.scan_metadata)
            
            # Add executive summary
            self._add_executive_summary(root, report.executive_summary)
            
            # Add technical findings
            self._add_technical_findings(root, report.technical_findings)
            
            # Add risk assessment if present
            if report.risk_assessment:
                self._add_risk_assessment(root, report.risk_assessment)
            
            # Convert to pretty XML string
            rough_string = ET.tostring(root, encoding='unicode')
            reparsed = minidom.parseString(rough_string)
            xml_content = reparsed.toprettyxml(indent='  ')
            
            self.logger.info(f"Successfully generated XML report")
            return xml_content
            
        except Exception as e:
            self.logger.error(f"XML formatting failed: {e}")
            raise FormatterError(f"Failed to format XML report: {e}")
    
    def _add_target_info(self, parent: ET.Element, target_info) -> None:
        """Add target information to XML."""
        target_elem = ET.SubElement(parent, 'targetInfo')
        
        ET.SubElement(target_elem, 'primaryTarget').text = target_info.primary_target
        ET.SubElement(target_elem, 'targetType').text = target_info.target_type.value
        ET.SubElement(target_elem, 'environment').text = target_info.environment
        ET.SubElement(target_elem, 'businessContext').text = target_info.business_context
        ET.SubElement(target_elem, 'criticalityLevel').text = target_info.criticality_level.value
        
        if target_info.scope:
            scope_elem = ET.SubElement(target_elem, 'scope')
            for scope_item in target_info.scope:
                ET.SubElement(scope_elem, 'item').text = scope_item
        
        if target_info.exclusions:
            exclusions_elem = ET.SubElement(target_elem, 'exclusions')
            for exclusion in target_info.exclusions:
                ET.SubElement(exclusions_elem, 'item').text = exclusion
    
    def _add_scan_metadata(self, parent: ET.Element, scan_metadata) -> None:
        """Add scan metadata to XML."""
        metadata_elem = ET.SubElement(parent, 'scanMetadata')
        
        ET.SubElement(metadata_elem, 'startTime').text = scan_metadata.scan_start_time.isoformat()
        ET.SubElement(metadata_elem, 'endTime').text = scan_metadata.scan_end_time.isoformat()
        ET.SubElement(metadata_elem, 'duration').text = str(scan_metadata.total_duration.total_seconds())
        ET.SubElement(metadata_elem, 'scannerVersion').text = scan_metadata.scanner_version
        ET.SubElement(metadata_elem, 'scanProfile').text = scan_metadata.scan_profile
        
        if scan_metadata.operator:
            ET.SubElement(metadata_elem, 'operator').text = scan_metadata.operator
    
    def _add_executive_summary(self, parent: ET.Element, executive_summary) -> None:
        """Add executive summary to XML."""
        summary_elem = ET.SubElement(parent, 'executiveSummary')
        
        ET.SubElement(summary_elem, 'summaryText').text = executive_summary.summary_text
        ET.SubElement(summary_elem, 'businessRiskLevel').text = executive_summary.business_risk_level.value
        
        # Key findings count
        if executive_summary.key_findings_count:
            findings_count_elem = ET.SubElement(summary_elem, 'keyFindingsCount')
            for severity, count in executive_summary.key_findings_count.items():
                count_elem = ET.SubElement(findings_count_elem, 'count')
                count_elem.set('severity', severity.value)
                count_elem.text = str(count)
        
        # Recommended actions
        if executive_summary.recommended_actions:
            actions_elem = ET.SubElement(summary_elem, 'recommendedActions')
            for action in executive_summary.recommended_actions:
                ET.SubElement(actions_elem, 'action').text = action
    
    def _add_technical_findings(self, parent: ET.Element, findings: list[TechnicalFinding]) -> None:
        """Add technical findings to XML."""
        findings_elem = ET.SubElement(parent, 'technicalFindings')
        findings_elem.set('count', str(len(findings)))
        
        for finding in findings:
            finding_elem = ET.SubElement(findings_elem, 'finding')
            finding_elem.set('id', finding.finding_id)
            
            ET.SubElement(finding_elem, 'title').text = finding.title
            ET.SubElement(finding_elem, 'description').text = finding.description
            ET.SubElement(finding_elem, 'severity').text = finding.severity.value
            ET.SubElement(finding_elem, 'confidence').text = finding.confidence.value
            ET.SubElement(finding_elem, 'discoveryPhase').text = finding.discovery_phase
            ET.SubElement(finding_elem, 'verificationStatus').text = finding.verification_status.value
            ET.SubElement(finding_elem, 'firstDiscovered').text = finding.first_discovered.isoformat()
            ET.SubElement(finding_elem, 'lastUpdated').text = finding.last_updated.isoformat()
            
            if finding.cvss_score:
                ET.SubElement(finding_elem, 'cvssScore').text = str(finding.cvss_score)
            
            if finding.affected_urls:
                urls_elem = ET.SubElement(finding_elem, 'affectedUrls')
                for url in finding.affected_urls:
                    ET.SubElement(urls_elem, 'url').text = url
            
            if finding.cve_references:
                cves_elem = ET.SubElement(finding_elem, 'cveReferences')
                for cve in finding.cve_references:
                    ET.SubElement(cves_elem, 'cve').text = cve
            
            if finding.cwe_references:
                cwes_elem = ET.SubElement(finding_elem, 'cweReferences')
                for cwe in finding.cwe_references:
                    ET.SubElement(cwes_elem, 'cwe').text = cwe
    
    def _add_risk_assessment(self, parent: ET.Element, risk_assessment) -> None:
        """Add risk assessment to XML."""
        risk_elem = ET.SubElement(parent, 'riskAssessment')
        
        # Overall risk score
        risk_score_elem = ET.SubElement(risk_elem, 'overallRiskScore')
        ET.SubElement(risk_score_elem, 'score').text = str(risk_assessment.overall_risk_score.overall_score)
        ET.SubElement(risk_score_elem, 'riskLevel').text = risk_assessment.overall_risk_score.risk_level.value
        ET.SubElement(risk_score_elem, 'confidence').text = str(risk_assessment.overall_risk_score.confidence)
        
        # Business impact
        business_impact_elem = ET.SubElement(risk_elem, 'businessImpact')
        ET.SubElement(business_impact_elem, 'financialImpact').text = risk_assessment.business_impact.financial_impact
        ET.SubElement(business_impact_elem, 'operationalImpact').text = risk_assessment.business_impact.operational_impact
        ET.SubElement(business_impact_elem, 'reputationalImpact').text = risk_assessment.business_impact.reputational_impact


class MarkdownFormatter(BaseFormatter):
    """Markdown report formatter for documentation systems."""
    
    @property
    def supported_format(self) -> ReportFormat:
        return ReportFormat.MARKDOWN
    
    @property
    def output_extension(self) -> str:
        return "md"
    
    @property
    def content_type(self) -> str:
        return "text/markdown"
    
    async def format_report(self, report: VulnerabilityReport,
                          config: ReportConfig,
                          template_manager: TemplateManager) -> str:
        """Format report as Markdown.
        
        Args:
            report: Vulnerability report data
            config: Report configuration
            template_manager: Template manager instance
            
        Returns:
            Markdown report content
        """
        self.logger.info(f"Formatting Markdown report for {report.target_info.primary_target}")
        
        try:
            md_lines = []
            
            # Report header
            md_lines.extend(self._generate_header(report))
            
            # Executive summary
            md_lines.extend(self._generate_executive_summary(report.executive_summary))
            
            # Statistics
            md_lines.extend(self._generate_statistics(report))
            
            # Technical findings
            md_lines.extend(self._generate_technical_findings(report.technical_findings))
            
            # Risk assessment
            if report.risk_assessment:
                md_lines.extend(self._generate_risk_assessment(report.risk_assessment))
            
            # Remediation plan
            if report.remediation_plan:
                md_lines.extend(self._generate_remediation_plan(report.remediation_plan))
            
            # Appendices
            md_lines.extend(self._generate_appendices(report))
            
            markdown_content = '\n'.join(md_lines)
            
            self.logger.info(f"Successfully generated Markdown report")
            return markdown_content
            
        except Exception as e:
            self.logger.error(f"Markdown formatting failed: {e}")
            raise FormatterError(f"Failed to format Markdown report: {e}")
    
    def _generate_header(self, report: VulnerabilityReport) -> list[str]:
        """Generate report header."""
        return [
            f"# Vulnerability Assessment Report",
            f"",
            f"**Target:** {report.target_info.primary_target}",
            f"**Report ID:** {report.report_id}",
            f"**Scan ID:** {report.scan_id}",
            f"**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Scanner Version:** {report.scan_metadata.scanner_version}",
            f"",
            f"---",
            f""
        ]
    
    def _generate_executive_summary(self, executive_summary) -> list[str]:
        """Generate executive summary section."""
        lines = [
            "## Executive Summary",
            "",
            executive_summary.summary_text,
            "",
            f"**Overall Business Risk:** {executive_summary.business_risk_level.value.title()}",
            ""
        ]
        
        if executive_summary.key_findings_count:
            lines.extend([
                "### Key Findings Summary",
                ""
            ])
            
            for severity, count in executive_summary.key_findings_count.items():
                if count > 0:
                    emoji = self._get_severity_emoji(severity.value)
                    lines.append(f"- {emoji} **{severity.value.title()}:** {count} finding{'s' if count != 1 else ''}")
            
            lines.append("")
        
        if executive_summary.recommended_actions:
            lines.extend([
                "### Immediate Actions Required",
                ""
            ])
            
            for i, action in enumerate(executive_summary.recommended_actions, 1):
                lines.append(f"{i}. {action}")
            
            lines.append("")
        
        return lines
    
    def _generate_statistics(self, report: VulnerabilityReport) -> list[str]:
        """Generate statistics section."""
        stats = report.get_summary_statistics()
        
        lines = [
            "## Scan Statistics",
            "",
            f"- **Total Findings:** {stats['total_findings']}",
            f"- **Verified Findings:** {stats['verified_findings']} ({stats['verification_rate']:.1f}%)",
            f"- **Findings with PoC:** {stats['findings_with_poc']} ({stats['poc_coverage']:.1f}%)",
            "",
            "### Findings by Severity",
            ""
        ]
        
        for severity, count in stats['severity_breakdown'].items():
            if count > 0:
                emoji = self._get_severity_emoji(severity)
                lines.append(f"- {emoji} **{severity.title()}:** {count}")
        
        lines.append("")
        
        return lines
    
    def _generate_technical_findings(self, findings: list[TechnicalFinding]) -> list[str]:
        """Generate technical findings section."""
        if not findings:
            return ["## Technical Findings", "", "No findings detected.", ""]
        
        lines = [
            "## Technical Findings",
            f"",
            f"Total findings: {len(findings)}",
            f""
        ]
        
        # Group findings by severity
        by_severity = {}
        for finding in findings:
            severity = finding.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        # Generate sections for each severity
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        for severity in severity_order:
            if severity in by_severity:
                lines.extend(self._generate_severity_section(severity, by_severity[severity]))
        
        return lines
    
    def _generate_severity_section(self, severity: str, findings: list[TechnicalFinding]) -> list[str]:
        """Generate section for specific severity level."""
        emoji = self._get_severity_emoji(severity)
        lines = [
            f"### {emoji} {severity.title()} Severity ({len(findings)} finding{'s' if len(findings) != 1 else ''})",
            ""
        ]
        
        for i, finding in enumerate(findings, 1):
            lines.extend([
                f"#### {i}. {finding.title}",
                "",
                f"**Finding ID:** {finding.finding_id}",
                f"**Confidence:** {finding.confidence.value.title()}",
                f"**Discovery Phase:** {finding.discovery_phase}",
                ""
            ])
            
            if finding.cvss_score:
                lines.append(f"**CVSS Score:** {finding.cvss_score}/10.0")
            
            if finding.cve_references:
                lines.append(f"**CVE References:** {', '.join(finding.cve_references)}")
            
            if finding.cwe_references:
                lines.append(f"**CWE References:** {', '.join(finding.cwe_references)}")
            
            lines.extend([
                "",
                "**Description:**",
                "",
                finding.description,
                ""
            ])
            
            if finding.affected_urls:
                lines.extend([
                    "**Affected URLs:**",
                    ""
                ])
                for url in finding.affected_urls:
                    lines.append(f"- `{url}`")
                lines.append("")
            
            if finding.remediation:
                lines.extend([
                    "**Remediation:**",
                    "",
                    f"**Priority:** {finding.remediation.priority.title()}",
                    f"**Effort:** {finding.remediation.effort_estimate.title()}",
                    "",
                    finding.remediation.description,
                    ""
                ])
                
                if finding.remediation.remediation_steps:
                    lines.extend([
                        "**Remediation Steps:**",
                        ""
                    ])
                    for j, step in enumerate(finding.remediation.remediation_steps, 1):
                        lines.append(f"{j}. {step}")
                    lines.append("")
            
            lines.append("---")
            lines.append("")
        
        return lines
    
    def _generate_risk_assessment(self, risk_assessment) -> list[str]:
        """Generate risk assessment section."""
        lines = [
            "## Risk Assessment",
            "",
            f"**Overall Risk Score:** {risk_assessment.overall_risk_score.overall_score:.1f}/10.0",
            f"**Risk Level:** {risk_assessment.overall_risk_score.risk_level.value.title()}",
            f"**Risk Trend:** {risk_assessment.overall_risk_score.risk_trend.title()}",
            "",
            "### Business Impact Analysis",
            "",
            f"- **Financial Impact:** {risk_assessment.business_impact.financial_impact.title()}",
            f"- **Operational Impact:** {risk_assessment.business_impact.operational_impact.title()}",
            f"- **Reputational Impact:** {risk_assessment.business_impact.reputational_impact.title()}",
            f"- **Regulatory Impact:** {risk_assessment.business_impact.regulatory_impact.title()}",
            f"- **Customer Impact:** {risk_assessment.business_impact.customer_impact.title()}",
            ""
        ]
        
        if risk_assessment.business_impact.impact_description:
            lines.extend([
                "**Impact Description:**",
                "",
                risk_assessment.business_impact.impact_description,
                ""
            ])
        
        return lines
    
    def _generate_remediation_plan(self, remediation_plan) -> list[str]:
        """Generate remediation plan section."""
        lines = [
            "## Remediation Plan",
            "",
            remediation_plan.executive_summary,
            ""
        ]
        
        if remediation_plan.immediate_actions:
            lines.extend([
                "### 🚨 Immediate Actions (0-7 days)",
                ""
            ])
            for action in remediation_plan.immediate_actions:
                lines.extend([
                    f"#### {action.title}",
                    "",
                    f"**Priority:** {action.priority.title()}",
                    f"**Effort:** {action.implementation_effort.title()}",
                    "",
                    action.description,
                    ""
                ])
        
        if remediation_plan.short_term_actions:
            lines.extend([
                "### ⏱️ Short-term Actions (1-4 weeks)",
                ""
            ])
            for action in remediation_plan.short_term_actions:
                lines.extend([
                    f"#### {action.title}",
                    "",
                    f"**Priority:** {action.priority.title()}",
                    f"**Effort:** {action.implementation_effort.title()}",
                    "",
                    action.description,
                    ""
                ])
        
        if remediation_plan.long_term_actions:
            lines.extend([
                "### 📅 Long-term Actions (1-6 months)",
                ""
            ])
            for action in remediation_plan.long_term_actions:
                lines.extend([
                    f"#### {action.title}",
                    "",
                    f"**Priority:** {action.priority.title()}",
                    f"**Effort:** {action.implementation_effort.title()}",
                    "",
                    action.description,
                    ""
                ])
        
        return lines
    
    def _generate_appendices(self, report: VulnerabilityReport) -> list[str]:
        """Generate appendices section."""
        lines = [
            "## Appendices",
            "",
            "### Scan Information",
            "",
            f"- **Scan Start:** {report.scan_metadata.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **Scan End:** {report.scan_metadata.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **Duration:** {report.scan_metadata.total_duration}",
            f"- **Scan Profile:** {report.scan_metadata.scan_profile}",
            ""
        ]
        
        if report.scan_metadata.limitations:
            lines.extend([
                "### Scan Limitations",
                ""
            ])
            for limitation in report.scan_metadata.limitations:
                lines.append(f"- {limitation}")
            lines.append("")
        
        if report.appendices.get('tools_used'):
            lines.extend([
                "### Tools Used",
                ""
            ])
            for tool, info in report.appendices['tools_used'].items():
                lines.append(f"- **{tool}:** {info['usage_count']} executions, {info['findings_generated']} findings")
            lines.append("")
        
        return lines
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level."""
        emoji_map = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'info': '⚪'
        }
        return emoji_map.get(severity.lower(), '⚪')