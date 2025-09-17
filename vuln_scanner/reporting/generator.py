"""Main report generation engine."""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from pathlib import Path

from .models import (
    VulnerabilityReport, TechnicalFinding, ScanMetadata, TargetInfo,
    ExecutiveSummary, RiskAssessment, RemediationPlan, ComplianceMapping,
    GeneratedReport, SeverityLevel, RiskLevel, BusinessImpactAnalysis,
    RiskScore, Recommendation
)
from .config import ReportConfig, ReportFormat
from .formatters import FormatterRegistry
from .templates import TemplateManager
from .risk import RiskCalculator
from .compliance import ComplianceMapper
from .intelligence import IntelligentSummarizer

from ..scanning.data_structures import ScanJob, ScanResult, ScanPhase
from ..exceptions import ScanEngineException


class ReportGenerationError(ScanEngineException):
    """Report generation error."""
    pass


class ReportGenerator:
    """Main report generation engine with multi-format support."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize report generator.
        
        Args:
            config: System configuration
        """
        self.config = config
        self.logger = logging.getLogger('report_generator')
        
        # Initialize components
        reporting_config = config.get('reporting', {})
        
        # Template system
        template_path = reporting_config.get('template_path', 'vuln_scanner/reporting/templates')
        self.template_manager = TemplateManager(template_path)
        
        # Formatters
        self.formatter_registry = FormatterRegistry()
        
        # Analysis engines
        self.risk_calculator = RiskCalculator(config)
        self.compliance_mapper = ComplianceMapper(config)
        self.intelligent_summarizer = IntelligentSummarizer(config)
        self.recommendation_engine = RecommendationEngine(config)
        
        self.logger.info("Report generator initialized successfully")
    
    async def generate_report_from_scan_job(self, scan_job: ScanJob, 
                                          report_config: ReportConfig) -> List[GeneratedReport]:
        """Generate comprehensive report from scan job.
        
        Args:
            scan_job: Completed scan job with results
            report_config: Report generation configuration
            
        Returns:
            List of generated reports in different formats
        """
        start_time = datetime.now()
        self.logger.info(f"Starting report generation for job {scan_job.job_id}")
        
        try:
            # Validate inputs
            if not scan_job.results:
                raise ReportGenerationError(f"No scan results found for job {scan_job.job_id}")
            
            config_errors = report_config.validate()
            if config_errors:
                raise ReportGenerationError(f"Invalid report configuration: {', '.join(config_errors)}")
            
            # Convert scan job to report structure
            vulnerability_report = await self._convert_scan_job_to_report(scan_job, report_config)
            
            # Generate reports in all requested formats
            generated_reports = await self._generate_multi_format_reports(
                vulnerability_report, report_config
            )
            
            generation_time = datetime.now() - start_time
            self.logger.info(f"Report generation completed in {generation_time.total_seconds():.2f}s")
            
            return generated_reports
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {str(e)}")
            raise ReportGenerationError(f"Failed to generate report: {str(e)}") from e
    
    async def generate_report(self, scan_results: List[ScanResult], 
                            target_info: TargetInfo,
                            scan_metadata: ScanMetadata,
                            report_config: ReportConfig) -> List[GeneratedReport]:
        """Generate report from individual components.
        
        Args:
            scan_results: List of scan results
            target_info: Target information
            scan_metadata: Scan metadata
            report_config: Report configuration
            
        Returns:
            List of generated reports
        """
        self.logger.info(f"Generating report for {len(scan_results)} findings")
        
        # Build vulnerability report
        vulnerability_report = await self._build_vulnerability_report(
            scan_results, target_info, scan_metadata, report_config
        )
        
        # Generate multi-format reports
        return await self._generate_multi_format_reports(vulnerability_report, report_config)
    
    async def _convert_scan_job_to_report(self, scan_job: ScanJob, 
                                        report_config: ReportConfig) -> VulnerabilityReport:
        """Convert scan job to vulnerability report structure.
        
        Args:
            scan_job: Scan job with results
            report_config: Report configuration
            
        Returns:
            VulnerabilityReport object
        """
        self.logger.debug(f"Converting scan job {scan_job.job_id} to report structure")
        
        # Extract target information
        target_info = TargetInfo(
            primary_target=scan_job.target.target,
            target_type=scan_job.target.target_type,
            business_context=scan_job.target.context.get('business_context', ''),
            scope=[scan_job.target.target],  # Basic scope
            exclusions=scan_job.target.constraints.get('exclusions', []),
            environment=scan_job.metadata.get('environment', 'unknown'),
            technology_stack=scan_job.metadata.get('technology_stack', [])
        )
        
        # Create scan metadata
        scan_metadata = ScanMetadata(
            scan_start_time=scan_job.started_at or scan_job.created_at,
            scan_end_time=scan_job.completed_at or datetime.now(),
            total_duration=(scan_job.completed_at or datetime.now()) - (scan_job.started_at or scan_job.created_at),
            scanner_version=self.config.get('version', '1.0.0'),
            scan_configuration={'profile': scan_job.scan_profile},
            scan_profile=scan_job.scan_profile,
            operator=scan_job.metadata.get('operator'),
            limitations=scan_job.metadata.get('limitations', []),
            assumptions=scan_job.metadata.get('assumptions', [])
        )
        
        # Build full report
        return await self._build_vulnerability_report(
            scan_job.results, target_info, scan_metadata, report_config
        )
    
    async def _build_vulnerability_report(self, scan_results: List[ScanResult],
                                        target_info: TargetInfo,
                                        scan_metadata: ScanMetadata,
                                        report_config: ReportConfig) -> VulnerabilityReport:
        """Build comprehensive vulnerability report.
        
        Args:
            scan_results: List of scan results
            target_info: Target information
            scan_metadata: Scan metadata
            report_config: Report configuration
            
        Returns:
            Complete VulnerabilityReport
        """
        self.logger.debug(f"Building vulnerability report from {len(scan_results)} results")
        
        # Convert scan results to technical findings
        technical_findings = await self._convert_to_technical_findings(scan_results, report_config)
        
        # Filter findings based on configuration
        filtered_findings = self._filter_findings(technical_findings, report_config)
        
        # Generate components in parallel for performance
        tasks = []
        
        # Risk assessment
        if report_config.is_section_included(ReportSection.RISK_ASSESSMENT):
            tasks.append(self._generate_risk_assessment(filtered_findings, target_info))
        
        # Compliance mapping
        if report_config.is_section_included(ReportSection.COMPLIANCE_MAPPING) and report_config.compliance_frameworks:
            tasks.append(self._generate_compliance_mapping(filtered_findings, report_config.compliance_frameworks))
        
        # Remediation plan
        if report_config.is_section_included(ReportSection.REMEDIATION_PLAN):
            tasks.append(self._generate_remediation_plan(filtered_findings, target_info))
        
        # Executive summary
        if report_config.is_section_included(ReportSection.EXECUTIVE_SUMMARY):
            tasks.append(self._generate_executive_summary(filtered_findings, target_info))
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        risk_assessment = None
        compliance_mapping = None
        remediation_plan = None
        executive_summary = None
        
        result_index = 0
        if report_config.is_section_included(ReportSection.RISK_ASSESSMENT):
            risk_assessment = results[result_index] if not isinstance(results[result_index], Exception) else None
            result_index += 1
        
        if report_config.is_section_included(ReportSection.COMPLIANCE_MAPPING) and report_config.compliance_frameworks:
            compliance_mapping = results[result_index] if not isinstance(results[result_index], Exception) else None
            result_index += 1
        
        if report_config.is_section_included(ReportSection.REMEDIATION_PLAN):
            remediation_plan = results[result_index] if not isinstance(results[result_index], Exception) else None
            result_index += 1
        
        if report_config.is_section_included(ReportSection.EXECUTIVE_SUMMARY):
            executive_summary = results[result_index] if not isinstance(results[result_index], Exception) else None
        
        # Create default executive summary if not generated
        if not executive_summary:
            executive_summary = self._create_default_executive_summary(filtered_findings)
        
        # Build final report
        report = VulnerabilityReport(
            report_id="",  # Will be auto-generated
            scan_id=scan_metadata.scan_configuration.get('scan_id', 'unknown'),
            target_info=target_info,
            scan_metadata=scan_metadata,
            executive_summary=executive_summary,
            technical_findings=filtered_findings,
            risk_assessment=risk_assessment,
            remediation_plan=remediation_plan,
            compliance_mapping=compliance_mapping,
            appendices=self._build_appendices(scan_results, report_config),
            report_metadata={
                'generator_version': self.config.get('version', '1.0.0'),
                'generation_config': {
                    'template': report_config.template_name,
                    'formats': [f.value for f in report_config.output_formats],
                    'sections': [s.value for s in report_config.include_sections]
                },
                'statistics': {
                    'total_findings': len(filtered_findings),
                    'severity_breakdown': {
                        severity.value: len([f for f in filtered_findings if f.severity == severity])
                        for severity in SeverityLevel
                    }
                }
            }
        )
        
        self.logger.info(f"Built vulnerability report with {len(filtered_findings)} findings")
        return report
    
    async def _convert_to_technical_findings(self, scan_results: List[ScanResult], 
                                          report_config: ReportConfig) -> List[TechnicalFinding]:
        """Convert scan results to technical findings.
        
        Args:
            scan_results: List of scan results
            report_config: Report configuration
            
        Returns:
            List of TechnicalFinding objects
        """
        findings = []
        
        for result in scan_results:
            try:
                # Extract finding information from result data
                finding_data = result.data
                
                # Create technical finding
                finding = TechnicalFinding(
                    finding_id="",  # Will be auto-generated
                    title=finding_data.get('title', f"Finding from {result.tool}"),
                    description=finding_data.get('description', 'No description available'),
                    severity=result.severity,
                    confidence=ConfidenceLevel.TENTATIVE,  # Map from result.confidence
                    cvss_score=finding_data.get('cvss_score'),
                    cvss_vector=finding_data.get('cvss_vector'),
                    cve_references=finding_data.get('cve_references', []),
                    cwe_references=finding_data.get('cwe_references', []),
                    discovery_phase=result.phase.value,
                    first_discovered=result.timestamp,
                    last_updated=result.timestamp,
                    false_positive_likelihood=result.false_positive_likelihood,
                    business_impact=finding_data.get('business_impact'),
                    technical_impact=finding_data.get('technical_impact'),
                    exploit_complexity=finding_data.get('exploit_complexity', 'medium'),
                    affected_urls=finding_data.get('affected_urls', []),
                    metadata={
                        'tool': result.tool,
                        'scan_id': result.scan_id,
                        'target_id': result.target.target_id,
                        'original_data': finding_data
                    }
                )
                
                # Set confidence based on result confidence
                if result.confidence >= 0.9:
                    finding.confidence = ConfidenceLevel.CONFIRMED
                elif result.confidence >= 0.7:
                    finding.confidence = ConfidenceLevel.FIRM
                elif result.confidence >= 0.5:
                    finding.confidence = ConfidenceLevel.TENTATIVE
                else:
                    finding.confidence = ConfidenceLevel.POSSIBLE
                
                findings.append(finding)
                
            except Exception as e:
                self.logger.warning(f"Failed to convert scan result to finding: {e}")
                continue
        
        # Group similar findings if enabled
        if report_config.group_similar_findings:
            findings = self._group_similar_findings(findings, report_config.similarity_threshold)
        
        return findings
    
    def _filter_findings(self, findings: List[TechnicalFinding], 
                        report_config: ReportConfig) -> List[TechnicalFinding]:
        """Filter findings based on report configuration.
        
        Args:
            findings: List of technical findings
            report_config: Report configuration
            
        Returns:
            Filtered list of findings
        """
        filtered = []
        
        for finding in findings:
            # Filter by severity
            if not report_config.include_low_severity and finding.severity == SeverityLevel.LOW:
                continue
            
            if not report_config.include_info_severity and finding.severity == SeverityLevel.INFO:
                continue
            
            # Filter by verification status
            if not report_config.include_false_positives and finding.verification_status == VerificationStatus.FALSE_POSITIVE:
                continue
            
            if not report_config.include_unverified_findings and finding.verification_status == VerificationStatus.UNVERIFIED:
                continue
            
            filtered.append(finding)
        
        # Limit findings per section if configured
        if report_config.max_findings_per_section > 0:
            filtered = filtered[:report_config.max_findings_per_section]
        
        return filtered
    
    def _group_similar_findings(self, findings: List[TechnicalFinding], 
                              threshold: float) -> List[TechnicalFinding]:
        """Group similar findings together.
        
        Args:
            findings: List of findings to group
            threshold: Similarity threshold (0.0 to 1.0)
            
        Returns:
            List with similar findings grouped
        """
        # Simple implementation - can be enhanced with more sophisticated algorithms
        grouped = []
        used_indices = set()
        
        for i, finding in enumerate(findings):
            if i in used_indices:
                continue
            
            # Find similar findings
            similar = [finding]
            for j, other_finding in enumerate(findings[i+1:], i+1):
                if j in used_indices:
                    continue
                
                # Simple similarity check based on title and description
                similarity = self._calculate_finding_similarity(finding, other_finding)
                if similarity >= threshold:
                    similar.append(other_finding)
                    used_indices.add(j)
            
            # If we have similar findings, merge them
            if len(similar) > 1:
                merged_finding = self._merge_similar_findings(similar)
                grouped.append(merged_finding)
            else:
                grouped.append(finding)
            
            used_indices.add(i)
        
        return grouped
    
    def _calculate_finding_similarity(self, finding1: TechnicalFinding, 
                                   finding2: TechnicalFinding) -> float:
        """Calculate similarity score between two findings.
        
        Args:
            finding1: First finding
            finding2: Second finding
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        # Simple implementation using string similarity
        title_similarity = self._string_similarity(finding1.title, finding2.title)
        desc_similarity = self._string_similarity(finding1.description, finding2.description)
        
        # Weight title more heavily than description
        return (title_similarity * 0.7) + (desc_similarity * 0.3)
    
    def _string_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using simple algorithm.
        
        Args:
            str1: First string
            str2: Second string
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        if not str1 or not str2:
            return 0.0
        
        # Simple word-based similarity
        words1 = set(str1.lower().split())
        words2 = set(str2.lower().split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union)
    
    def _merge_similar_findings(self, findings: List[TechnicalFinding]) -> TechnicalFinding:
        """Merge similar findings into a single finding.
        
        Args:
            findings: List of similar findings
            
        Returns:
            Merged finding
        """
        # Use the highest severity finding as the base
        base_finding = max(findings, key=lambda f: list(SeverityLevel).index(f.severity))
        
        # Merge data from all findings
        merged_urls = []
        merged_cves = []
        merged_cwes = []
        
        for finding in findings:
            merged_urls.extend(finding.affected_urls)
            merged_cves.extend(finding.cve_references)
            merged_cwes.extend(finding.cwe_references)
        
        # Update merged finding
        base_finding.affected_urls = list(set(merged_urls))
        base_finding.cve_references = list(set(merged_cves))
        base_finding.cwe_references = list(set(merged_cwes))
        base_finding.description += f"\n\nNote: This finding represents {len(findings)} similar vulnerabilities grouped together."
        
        return base_finding
    
    async def _generate_risk_assessment(self, findings: List[TechnicalFinding], 
                                      target_info: TargetInfo) -> RiskAssessment:
        """Generate comprehensive risk assessment.
        
        Args:
            findings: List of technical findings
            target_info: Target information
            
        Returns:
            RiskAssessment object
        """
        self.logger.debug("Generating risk assessment")
        return await self.risk_calculator.calculate_comprehensive_risk(findings, target_info)
    
    async def _generate_compliance_mapping(self, findings: List[TechnicalFinding], 
                                         frameworks: List[str]) -> ComplianceMapping:
        """Generate compliance framework mapping.
        
        Args:
            findings: List of technical findings
            frameworks: List of framework names
            
        Returns:
            ComplianceMapping object
        """
        self.logger.debug(f"Generating compliance mapping for {len(frameworks)} frameworks")
        return await self.compliance_mapper.map_findings_to_compliance(findings, frameworks)
    
    async def _generate_remediation_plan(self, findings: List[TechnicalFinding], 
                                       target_info: TargetInfo) -> RemediationPlan:
        """Generate comprehensive remediation plan.
        
        Args:
            findings: List of technical findings
            target_info: Target information
            
        Returns:
            RemediationPlan object
        """
        self.logger.debug("Generating remediation plan")
        return await self.recommendation_engine.generate_remediation_plan(findings, target_info)
    
    async def _generate_executive_summary(self, findings: List[TechnicalFinding], 
                                        target_info: TargetInfo) -> ExecutiveSummary:
        """Generate executive summary.
        
        Args:
            findings: List of technical findings
            target_info: Target information
            
        Returns:
            ExecutiveSummary object
        """
        self.logger.debug("Generating executive summary")
        return await self.intelligent_summarizer.generate_executive_summary(findings, target_info)
    
    def _create_default_executive_summary(self, findings: List[TechnicalFinding]) -> ExecutiveSummary:
        """Create default executive summary when intelligent generation fails.
        
        Args:
            findings: List of technical findings
            
        Returns:
            Basic ExecutiveSummary
        """
        # Calculate basic statistics
        severity_counts = {severity: 0 for severity in SeverityLevel}
        for finding in findings:
            severity_counts[finding.severity] += 1
        
        # Determine risk level
        if severity_counts[SeverityLevel.CRITICAL] > 0:
            risk_level = RiskLevel.CRITICAL
        elif severity_counts[SeverityLevel.HIGH] > 0:
            risk_level = RiskLevel.HIGH
        elif severity_counts[SeverityLevel.MEDIUM] > 0:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        # Generate summary text
        total_findings = len(findings)
        critical_high = severity_counts[SeverityLevel.CRITICAL] + severity_counts[SeverityLevel.HIGH]
        
        summary_text = f"""
        Security assessment identified {total_findings} total findings, with {critical_high} requiring immediate attention.
        The overall security posture presents {risk_level.value} risk to the organization.
        Immediate remediation is recommended for critical and high-severity vulnerabilities.
        """
        
        return ExecutiveSummary(
            summary_text=summary_text.strip(),
            key_findings_count=severity_counts,
            business_risk_level=risk_level,
            recommended_actions=[
                "Prioritize remediation of critical and high-severity vulnerabilities",
                "Implement security monitoring and alerting",
                "Conduct regular security assessments",
                "Provide security training for development team"
            ]
        )
    
    def _build_appendices(self, scan_results: List[ScanResult], 
                        report_config: ReportConfig) -> Dict[str, Any]:
        """Build report appendices.
        
        Args:
            scan_results: Original scan results
            report_config: Report configuration
            
        Returns:
            Dictionary of appendix data
        """
        appendices = {}
        
        # Scan methodology
        if report_config.is_section_included(ReportSection.METHODOLOGY):
            appendices['methodology'] = self._build_methodology_appendix(scan_results)
        
        # Tool information
        appendices['tools_used'] = self._build_tools_appendix(scan_results)
        
        # Raw data (if requested)
        if report_config.include_raw_data:
            appendices['raw_scan_data'] = [result.to_dict() for result in scan_results]
        
        return appendices
    
    def _build_methodology_appendix(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """Build scanning methodology appendix.
        
        Args:
            scan_results: Scan results
            
        Returns:
            Methodology information
        """
        # Analyze scan phases and tools used
        phases_used = set()
        tools_used = set()
        
        for result in scan_results:
            phases_used.add(result.phase)
            tools_used.add(result.tool)
        
        return {
            'scan_phases': [phase.value for phase in phases_used],
            'tools_utilized': list(tools_used),
            'scan_approach': 'Five-phase comprehensive security assessment',
            'coverage_areas': [
                'Network reconnaissance',
                'Service discovery',
                'Vulnerability scanning',
                'Manual verification',
                'Risk assessment'
            ]
        }
    
    def _build_tools_appendix(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """Build tools information appendix.
        
        Args:
            scan_results: Scan results
            
        Returns:
            Tools information
        """
        tools_info = {}
        
        for result in scan_results:
            tool = result.tool
            if tool not in tools_info:
                tools_info[tool] = {
                    'usage_count': 0,
                    'phases_used': set(),
                    'findings_generated': 0
                }
            
            tools_info[tool]['usage_count'] += 1
            tools_info[tool]['phases_used'].add(result.phase.value)
            if result.data:
                tools_info[tool]['findings_generated'] += 1
        
        # Convert sets to lists for JSON serialization
        for tool_info in tools_info.values():
            tool_info['phases_used'] = list(tool_info['phases_used'])
        
        return tools_info
    
    async def _generate_multi_format_reports(self, vulnerability_report: VulnerabilityReport,
                                           report_config: ReportConfig) -> List[GeneratedReport]:
        """Generate reports in multiple formats concurrently.
        
        Args:
            vulnerability_report: Complete vulnerability report
            report_config: Report configuration
            
        Returns:
            List of generated reports in different formats
        """
        self.logger.info(f"Generating reports in {len(report_config.output_formats)} formats")
        
        generation_tasks = []
        
        # Create generation tasks for each format
        for format_type in report_config.output_formats:
            task = self._generate_single_format_report(
                vulnerability_report, format_type, report_config
            )
            generation_tasks.append(task)
        
        # Execute generation tasks with concurrency limit
        if report_config.parallel_generation:
            semaphore = asyncio.Semaphore(report_config.max_concurrent_formats)
            
            async def limited_generation(task):
                async with semaphore:
                    return await task
            
            limited_tasks = [limited_generation(task) for task in generation_tasks]
            generated_reports = await asyncio.gather(*limited_tasks, return_exceptions=True)
        else:
            # Sequential generation
            generated_reports = []
            for task in generation_tasks:
                try:
                    report = await task
                    generated_reports.append(report)
                except Exception as e:
                    self.logger.error(f"Format generation failed: {e}")
                    generated_reports.append(e)
        
        # Filter out failed generations
        successful_reports = []
        for i, result in enumerate(generated_reports):
            if isinstance(result, Exception):
                format_type = report_config.output_formats[i]
                self.logger.error(f"Failed to generate {format_type.value} report: {result}")
            else:
                successful_reports.append(result)
        
        self.logger.info(f"Successfully generated {len(successful_reports)} reports")
        return successful_reports
    
    async def _generate_single_format_report(self, vulnerability_report: VulnerabilityReport,
                                           format_type: ReportFormat,
                                           report_config: ReportConfig) -> GeneratedReport:
        """Generate report in a single format.
        
        Args:
            vulnerability_report: Vulnerability report data
            format_type: Target format
            report_config: Report configuration
            
        Returns:
            Generated report
        """
        start_time = datetime.now()
        self.logger.debug(f"Generating {format_type.value} report")
        
        try:
            # Get appropriate formatter
            formatter = self.formatter_registry.get_formatter(format_type)
            if not formatter:
                raise ReportGenerationError(f"No formatter available for format: {format_type.value}")
            
            # Generate report content
            content = await formatter.format_report(
                vulnerability_report, 
                report_config,
                self.template_manager
            )
            
            generation_time = datetime.now() - start_time
            
            # Create generated report object
            generated_report = GeneratedReport(
                report_id=vulnerability_report.report_id,
                format_type=format_type.value,
                content=content,
                file_size=len(content) if isinstance(content, bytes) else len(content.encode('utf-8')),
                template_used=report_config.template_name,
                generation_time=generation_time,
                metadata={
                    'formatter': formatter.__class__.__name__,
                    'config_hash': hash(str(report_config.__dict__)),
                    'findings_count': len(vulnerability_report.technical_findings)
                }
            )
            
            # Save to file if export is configured
            if report_config.export_config:
                output_path = report_config.get_output_path(vulnerability_report.report_id, format_type)
                generated_report.save_to_file(output_path)
                self.logger.info(f"Saved {format_type.value} report to {output_path}")
            
            return generated_report
            
        except Exception as e:
            self.logger.error(f"Failed to generate {format_type.value} report: {e}")
            raise
    
    async def validate_report_data(self, vulnerability_report: VulnerabilityReport) -> List[str]:
        """Validate report data for completeness and accuracy.
        
        Args:
            vulnerability_report: Report to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Basic structure validation
        if not vulnerability_report.target_info:
            errors.append("Missing target information")
        
        if not vulnerability_report.scan_metadata:
            errors.append("Missing scan metadata")
        
        if not vulnerability_report.executive_summary:
            errors.append("Missing executive summary")
        
        # Findings validation
        if not vulnerability_report.technical_findings:
            errors.append("No technical findings present")
        else:
            for i, finding in enumerate(vulnerability_report.technical_findings):
                if not finding.title:
                    errors.append(f"Finding {i+1}: Missing title")
                if not finding.description:
                    errors.append(f"Finding {i+1}: Missing description")
                if finding.cvss_score and not (0.0 <= finding.cvss_score <= 10.0):
                    errors.append(f"Finding {i+1}: Invalid CVSS score")
        
        # Risk assessment validation
        if vulnerability_report.risk_assessment:
            if not (0.0 <= vulnerability_report.risk_assessment.overall_risk_score.overall_score <= 10.0):
                errors.append("Invalid overall risk score")
        
        return errors


# Import required section enum
from .config import ReportSection
from .models import VerificationStatus