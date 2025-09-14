"""CSV report formatter for tabular data export."""

import csv
import logging
from io import StringIO
from typing import Union

from .base import BaseFormatter, FormatterError
from ..models import VulnerabilityReport, TechnicalFinding
from ..config import ReportConfig, ReportFormat
from ..templates import TemplateManager


class CSVFormatter(BaseFormatter):
    """CSV report formatter for spreadsheet analysis."""
    
    @property
    def supported_format(self) -> ReportFormat:
        return ReportFormat.CSV
    
    @property
    def output_extension(self) -> str:
        return "csv"
    
    @property
    def content_type(self) -> str:
        return "text/csv"
    
    async def format_report(self, report: VulnerabilityReport,
                          config: ReportConfig,
                          template_manager: TemplateManager) -> str:
        """Format report as CSV.
        
        Args:
            report: Vulnerability report data
            config: Report configuration
            template_manager: Template manager instance
            
        Returns:
            CSV report content
        """
        self.logger.info(f"Formatting CSV report for {report.target_info.primary_target}")
        
        try:
            # Create CSV content
            output = StringIO()
            writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
            
            # Write headers
            headers = self._get_csv_headers()
            writer.writerow(headers)
            
            # Write findings data
            for finding in report.technical_findings:
                row_data = self._finding_to_csv_row(finding, report)
                writer.writerow(row_data)
            
            csv_content = output.getvalue()
            output.close()
            
            self.logger.info(f"Successfully generated CSV report with {len(report.technical_findings)} findings")
            return csv_content
            
        except Exception as e:
            self.logger.error(f"CSV formatting failed: {e}")
            raise FormatterError(f"Failed to format CSV report: {e}")
    
    def _get_csv_headers(self) -> list[str]:
        """Get CSV column headers.
        
        Returns:
            List of column headers
        """
        return [
            'Finding ID',
            'Title',
            'Severity',
            'Confidence',
            'CVSS Score',
            'CVE References',
            'CWE References',
            'Status',
            'Discovery Phase',
            'First Discovered',
            'Last Updated',
            'Affected URLs',
            'Business Impact',
            'Technical Impact',
            'Exploit Complexity',
            'False Positive Likelihood',
            'Description',
            'Remediation Title',
            'Remediation Priority',
            'Tool',
            'Target'
        ]
    
    def _finding_to_csv_row(self, finding: TechnicalFinding, report: VulnerabilityReport) -> list:
        """Convert finding to CSV row.
        
        Args:
            finding: Technical finding
            report: Vulnerability report
            
        Returns:
            List of field values for CSV row
        """
        return [
            finding.finding_id,
            finding.title,
            finding.severity.value,
            finding.confidence.value,
            finding.cvss_score or '',
            '; '.join(finding.cve_references) if finding.cve_references else '',
            '; '.join(finding.cwe_references) if finding.cwe_references else '',
            finding.verification_status.value,
            finding.discovery_phase,
            finding.first_discovered.isoformat(),
            finding.last_updated.isoformat(),
            '; '.join(finding.affected_urls) if finding.affected_urls else '',
            finding.business_impact or '',
            finding.technical_impact or '',
            finding.exploit_complexity,
            finding.false_positive_likelihood,
            finding.description.replace('\n', ' '),  # Remove newlines for CSV
            finding.remediation.title if finding.remediation else '',
            finding.remediation.priority if finding.remediation else '',
            finding.metadata.get('tool', ''),
            report.target_info.primary_target
        ]