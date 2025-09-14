"""JSON report formatter."""

import json
import logging
from datetime import datetime
from typing import Union, Dict, Any

from .base import BaseFormatter, FormatterError
from ..models import VulnerabilityReport, SeverityLevel, RiskLevel
from ..config import ReportConfig, ReportFormat
from ..templates import TemplateManager


class JSONFormatter(BaseFormatter):
    """JSON report formatter for API consumption."""
    
    @property
    def supported_format(self) -> ReportFormat:
        return ReportFormat.JSON
    
    @property
    def output_extension(self) -> str:
        return "json"
    
    @property
    def content_type(self) -> str:
        return "application/json"
    
    async def format_report(self, report: VulnerabilityReport,
                          config: ReportConfig,
                          template_manager: TemplateManager) -> str:
        """Format report as JSON.
        
        Args:
            report: Vulnerability report data
            config: Report configuration
            template_manager: Template manager instance
            
        Returns:
            JSON report content
        """
        self.logger.info(f"Formatting JSON report for {report.target_info.primary_target}")
        
        try:
            # Get JSON-specific configuration
            json_config = config.format_config.json
            
            # Convert report to JSON-serializable format
            report_data = self._convert_report_to_json_data(report, config)
            
            # Add JSON-specific metadata
            if json_config.include_metadata:
                report_data['_metadata'] = {
                    'format': 'json',
                    'version': '1.0',
                    'generated_at': datetime.now().isoformat(),
                    'generator': 'VulnMiner',
                    'schema_version': '1.0'
                }
            
            # Add JSON schema if requested
            if json_config.include_schema:
                report_data['$schema'] = self._get_json_schema()
            
            # Serialize to JSON
            json_content = json.dumps(
                report_data,
                indent=json_config.indent if json_config.pretty_print else None,
                sort_keys=json_config.sort_keys,
                ensure_ascii=False,
                default=self._json_serializer
            )
            
            # Validate output if requested
            if json_config.validate_output:
                self._validate_json_output(json_content)
            
            self.logger.info(f"Successfully generated JSON report ({len(json_content)} chars)")
            return json_content
            
        except Exception as e:
            self.logger.error(f"JSON formatting failed: {e}")
            raise FormatterError(f"Failed to format JSON report: {e}")
    
    def _convert_report_to_json_data(self, report: VulnerabilityReport, 
                                   config: ReportConfig) -> Dict[str, Any]:
        """Convert vulnerability report to JSON-serializable data.
        
        Args:
            report: Vulnerability report
            config: Report configuration
            
        Returns:
            JSON-serializable dictionary
        """
        # Start with base report data
        json_data = {
            'report_id': report.report_id,
            'scan_id': report.scan_id,
            'version': report.version,
            'generated_at': report.generated_at.isoformat()
        }
        
        # Target information
        json_data['target'] = {
            'primary_target': report.target_info.primary_target,
            'scope': report.target_info.scope,
            'exclusions': report.target_info.exclusions,
            'target_type': report.target_info.target_type.value,
            'business_context': report.target_info.business_context,
            'criticality_level': report.target_info.criticality_level.value,
            'owner': report.target_info.owner,
            'contact_info': report.target_info.contact_info,
            'environment': report.target_info.environment,
            'technology_stack': report.target_info.technology_stack,
            'authentication_required': report.target_info.authentication_required
        }
        
        # Scan metadata
        json_data['scan_metadata'] = {
            'start_time': report.scan_metadata.scan_start_time.isoformat(),
            'end_time': report.scan_metadata.scan_end_time.isoformat(),
            'duration_seconds': int(report.scan_metadata.total_duration.total_seconds()),
            'scanner_version': report.scan_metadata.scanner_version,
            'scan_profile': report.scan_metadata.scan_profile,
            'operator': report.scan_metadata.operator,
            'scan_purpose': report.scan_metadata.scan_purpose,
            'tool_versions': report.scan_metadata.tool_versions,
            'limitations': report.scan_metadata.limitations,
            'assumptions': report.scan_metadata.assumptions
        }
        
        # Coverage metrics if available
        if hasattr(report.scan_metadata, 'coverage_metrics'):
            json_data['scan_metadata']['coverage_metrics'] = {
                'total_endpoints': report.scan_metadata.coverage_metrics.total_endpoints,
                'scanned_endpoints': report.scan_metadata.coverage_metrics.scanned_endpoints,
                'total_parameters': report.scan_metadata.coverage_metrics.total_parameters,
                'tested_parameters': report.scan_metadata.coverage_metrics.tested_parameters,
                'attack_surface_coverage': report.scan_metadata.coverage_metrics.attack_surface_coverage,
                'tool_coverage': report.scan_metadata.coverage_metrics.tool_coverage
            }
        
        # Executive summary
        json_data['executive_summary'] = {
            'summary_text': report.executive_summary.summary_text,
            'business_risk_level': report.executive_summary.business_risk_level.value,
            'key_findings_count': {
                k.value: v for k, v in report.executive_summary.key_findings_count.items()
            },
            'top_critical_findings': report.executive_summary.top_critical_findings,
            'recommended_actions': report.executive_summary.recommended_actions,
            'investment_required': report.executive_summary.investment_required,
            'timeline_to_secure': report.executive_summary.timeline_to_secure,
            'regulatory_implications': report.executive_summary.regulatory_implications,
            'board_recommendations': report.executive_summary.board_recommendations
        }
        
        # Technical findings
        json_data['technical_findings'] = []
        for finding in report.technical_findings:
            finding_data = {
                'finding_id': finding.finding_id,
                'title': finding.title,
                'description': finding.description,
                'severity': finding.severity.value,
                'confidence': finding.confidence.value,
                'cvss_score': finding.cvss_score,
                'cvss_vector': finding.cvss_vector,
                'cve_references': finding.cve_references,
                'cwe_references': finding.cwe_references,
                'verification_status': finding.verification_status.value,
                'discovery_phase': finding.discovery_phase,
                'first_discovered': finding.first_discovered.isoformat(),
                'last_updated': finding.last_updated.isoformat(),
                'false_positive_likelihood': finding.false_positive_likelihood,
                'business_impact': finding.business_impact,
                'technical_impact': finding.technical_impact,
                'exploit_complexity': finding.exploit_complexity,
                'affected_urls': finding.affected_urls,
                'metadata': finding.metadata
            }
            
            # Add affected components
            if finding.affected_components:
                finding_data['affected_components'] = [
                    {
                        'name': comp.name,
                        'version': comp.version,
                        'location': comp.location,
                        'criticality': comp.criticality.value,
                        'metadata': comp.metadata
                    }
                    for comp in finding.affected_components
                ]
            
            # Add proof of concept if available
            if finding.proof_of_concept:
                poc = finding.proof_of_concept
                finding_data['proof_of_concept'] = {
                    'poc_id': poc.poc_id,
                    'title': poc.title,
                    'description': poc.description,
                    'steps': poc.steps,
                    'request_response': poc.request_response,
                    'screenshots': poc.screenshots,
                    'video_path': poc.video_path,
                    'code_samples': poc.code_samples,
                    'exploitability_rating': poc.exploitability_rating
                }
            
            # Add remediation if available
            if finding.remediation:
                remediation = finding.remediation
                finding_data['remediation'] = {
                    'title': remediation.title,
                    'description': remediation.description,
                    'priority': remediation.priority,
                    'effort_estimate': remediation.effort_estimate,
                    'remediation_steps': remediation.remediation_steps,
                    'verification_steps': remediation.verification_steps,
                    'cost_estimate': remediation.cost_estimate,
                    'timeline_estimate': remediation.timeline_estimate,
                    'responsible_team': remediation.responsible_team
                }
            
            # Add references
            if finding.references:
                finding_data['references'] = [
                    {
                        'title': ref.title,
                        'url': ref.url,
                        'type': ref.reference_type,
                        'published_date': ref.published_date.isoformat() if ref.published_date else None
                    }
                    for ref in finding.references
                ]
            
            json_data['technical_findings'].append(finding_data)
        
        # Risk assessment
        if report.risk_assessment:
            risk_assessment = {
                'overall_risk_score': {
                    'score': report.risk_assessment.overall_risk_score.overall_score,
                    'critical_path_score': report.risk_assessment.overall_risk_score.critical_path_score,
                    'risk_level': report.risk_assessment.overall_risk_score.risk_level.value,
                    'risk_trend': report.risk_assessment.overall_risk_score.risk_trend,
                    'risk_velocity': report.risk_assessment.overall_risk_score.risk_velocity,
                    'confidence': report.risk_assessment.overall_risk_score.confidence
                },
                'business_impact': {
                    'financial_impact': report.risk_assessment.business_impact.financial_impact,
                    'operational_impact': report.risk_assessment.business_impact.operational_impact,
                    'reputational_impact': report.risk_assessment.business_impact.reputational_impact,
                    'regulatory_impact': report.risk_assessment.business_impact.regulatory_impact,
                    'customer_impact': report.risk_assessment.business_impact.customer_impact,
                    'impact_description': report.risk_assessment.business_impact.impact_description,
                    'affected_business_processes': report.risk_assessment.business_impact.affected_business_processes,
                    'recovery_time_objective': report.risk_assessment.business_impact.recovery_time_objective,
                    'recovery_point_objective': report.risk_assessment.business_impact.recovery_point_objective
                },
                'risk_matrix': report.risk_assessment.risk_matrix,
                'risk_appetite_alignment': report.risk_assessment.risk_appetite_alignment,
                'risk_treatment_strategy': report.risk_assessment.risk_treatment_strategy,
                'risk_owner': report.risk_assessment.risk_owner,
                'next_assessment_date': report.risk_assessment.next_assessment_date.isoformat() if report.risk_assessment.next_assessment_date else None
            }
            
            # Add contributing factors
            if report.risk_assessment.overall_risk_score.contributing_factors:
                risk_assessment['overall_risk_score']['contributing_factors'] = [
                    {
                        'factor_name': factor.factor_name,
                        'impact_level': factor.impact_level,
                        'likelihood': factor.likelihood,
                        'description': factor.description,
                        'mitigation_priority': factor.mitigation_priority
                    }
                    for factor in report.risk_assessment.overall_risk_score.contributing_factors
                ]
            
            json_data['risk_assessment'] = risk_assessment
        
        # Remediation plan
        if report.remediation_plan:
            remediation_plan = {
                'plan_id': report.remediation_plan.plan_id,
                'executive_summary': report.remediation_plan.executive_summary,
                'total_estimated_cost': report.remediation_plan.total_estimated_cost,
                'total_estimated_timeline': report.remediation_plan.total_estimated_timeline,
                'success_metrics': report.remediation_plan.success_metrics,
                'risk_mitigation_effectiveness': report.remediation_plan.risk_mitigation_effectiveness
            }
            
            # Add recommendations by category
            for category in ['immediate_actions', 'short_term_actions', 'long_term_actions', 'strategic_recommendations']:
                recommendations = getattr(report.remediation_plan, category, [])
                remediation_plan[category] = [
                    {
                        'recommendation_id': rec.recommendation_id,
                        'title': rec.title,
                        'description': rec.description,
                        'priority': rec.priority,
                        'category': rec.category,
                        'implementation_effort': rec.implementation_effort,
                        'cost_estimate': rec.cost_estimate,
                        'timeline': rec.timeline,
                        'success_criteria': rec.success_criteria,
                        'dependencies': rec.dependencies,
                        'risks_if_not_implemented': rec.risks_if_not_implemented,
                        'responsible_party': rec.responsible_party
                    }
                    for rec in recommendations
                ]
            
            json_data['remediation_plan'] = remediation_plan
        
        # Compliance mapping
        if report.compliance_mapping:
            compliance_mapping = {
                'frameworks': {},
                'compliance_status': {k.value: v for k, v in report.compliance_mapping.compliance_status.items()},
                'gap_analysis': {k.value: v for k, v in report.compliance_mapping.gap_analysis.items()},
                'recommendations': {k.value: v for k, v in report.compliance_mapping.recommendations.items()},
                'certification_readiness': {k.value: v for k, v in report.compliance_mapping.certification_readiness.items()}
            }
            
            # Convert framework mappings
            for framework, mapping_data in report.compliance_mapping.frameworks.items():
                compliance_mapping['frameworks'][framework.value] = mapping_data
            
            json_data['compliance_mapping'] = compliance_mapping
        
        # Appendices and metadata
        json_data['appendices'] = report.appendices
        json_data['report_metadata'] = report.report_metadata
        
        # Summary statistics
        json_data['statistics'] = report.get_summary_statistics()
        
        return json_data
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for non-serializable objects.
        
        Args:
            obj: Object to serialize
            
        Returns:
            Serializable representation
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, 'value'):  # Enum objects
            return obj.value
        elif hasattr(obj, '__dict__'):  # Custom objects
            return obj.__dict__
        else:
            return str(obj)
    
    def _get_json_schema(self) -> str:
        """Get JSON schema URL for validation.
        
        Returns:
            Schema URL
        """
        return "https://raw.githubusercontent.com/vulnminer/schemas/main/report-v1.0.json"
    
    def _validate_json_output(self, json_content: str) -> None:
        """Validate JSON output format.
        
        Args:
            json_content: JSON content to validate
            
        Raises:
            FormatterError: If JSON is invalid
        """
        try:
            # Basic JSON validation
            parsed = json.loads(json_content)
            
            # Check required fields
            required_fields = ['report_id', 'scan_id', 'target', 'technical_findings', 'executive_summary']
            for field in required_fields:
                if field not in parsed:
                    raise FormatterError(f"Required field missing: {field}")
            
        except json.JSONDecodeError as e:
            raise FormatterError(f"Invalid JSON generated: {e}")
        except Exception as e:
            raise FormatterError(f"JSON validation failed: {e}")