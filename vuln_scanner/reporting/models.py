"""Core data models for vulnerability reporting."""

import uuid
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(Enum):
    """Confidence levels for findings."""
    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"
    POSSIBLE = "possible"


class TargetType(Enum):
    """Types of scan targets."""
    WEB_APPLICATION = "web_app"
    NETWORK = "network"
    API = "api"
    MOBILE = "mobile"
    CLOUD = "cloud"
    INFRASTRUCTURE = "infrastructure"


class CriticalityLevel(Enum):
    """Business criticality levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VerificationStatus(Enum):
    """Verification status for findings."""
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


class RiskLevel(Enum):
    """Overall risk levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    OWASP_TOP10 = "owasp_top10"
    CWE = "cwe"
    NIST = "nist"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    SOX = "sox"
    HIPAA = "hipaa"


@dataclass
class Component:
    """Affected component information."""
    name: str
    version: Optional[str] = None
    location: Optional[str] = None
    criticality: CriticalityLevel = CriticalityLevel.MEDIUM
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProofOfConcept:
    """Proof of concept for vulnerability."""
    poc_id: str
    title: str
    description: str
    steps: List[str]
    request_response: Optional[Dict[str, Any]] = None
    screenshots: List[str] = field(default_factory=list)
    video_path: Optional[str] = None
    code_samples: Dict[str, str] = field(default_factory=dict)
    exploitability_rating: float = 0.0
    
    def __post_init__(self):
        if not self.poc_id:
            self.poc_id = str(uuid.uuid4())


@dataclass
class Reference:
    """External reference information."""
    title: str
    url: str
    reference_type: str = "external"  # cve, advisory, documentation, etc.
    published_date: Optional[datetime] = None
    
    
@dataclass
class Remediation:
    """Remediation information for a finding."""
    title: str
    description: str
    priority: str = "high"  # critical, high, medium, low
    effort_estimate: str = "medium"  # low, medium, high
    remediation_steps: List[str] = field(default_factory=list)
    verification_steps: List[str] = field(default_factory=list)
    cost_estimate: Optional[str] = None
    timeline_estimate: Optional[str] = None
    responsible_team: Optional[str] = None


@dataclass
class TechnicalFinding:
    """Technical vulnerability finding."""
    finding_id: str
    title: str
    description: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cve_references: List[str] = field(default_factory=list)
    cwe_references: List[str] = field(default_factory=list)
    affected_components: List[Component] = field(default_factory=list)
    proof_of_concept: Optional[ProofOfConcept] = None
    remediation: Optional[Remediation] = None
    references: List[Reference] = field(default_factory=list)
    discovery_phase: str = "scanning"  # From ScanPhase
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    first_discovered: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    false_positive_likelihood: float = 0.0
    business_impact: Optional[str] = None
    technical_impact: Optional[str] = None
    exploit_complexity: str = "medium"  # low, medium, high
    affected_urls: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.finding_id:
            self.finding_id = str(uuid.uuid4())


@dataclass
class CoverageMetrics:
    """Coverage metrics for the scan."""
    total_endpoints: int = 0
    scanned_endpoints: int = 0
    total_parameters: int = 0
    tested_parameters: int = 0
    code_coverage_percent: Optional[float] = None
    attack_surface_coverage: float = 0.0
    tool_coverage: Dict[str, float] = field(default_factory=dict)


@dataclass
class TargetInfo:
    """Target information for the scan."""
    primary_target: str
    scope: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    target_type: TargetType = TargetType.WEB_APPLICATION
    business_context: str = ""
    criticality_level: CriticalityLevel = CriticalityLevel.MEDIUM
    owner: Optional[str] = None
    contact_info: Optional[str] = None
    environment: str = "production"  # production, staging, development
    technology_stack: List[str] = field(default_factory=list)
    authentication_required: bool = False
    rate_limiting_info: Optional[str] = None


@dataclass
class ScanMetadata:
    """Metadata about the scan execution."""
    scan_start_time: datetime
    scan_end_time: datetime
    total_duration: timedelta
    scanner_version: str
    scan_configuration: Dict[str, Any] = field(default_factory=dict)
    coverage_metrics: CoverageMetrics = field(default_factory=CoverageMetrics)
    tool_versions: Dict[str, str] = field(default_factory=dict)
    scan_profile: str = "comprehensive"
    operator: Optional[str] = None
    scan_purpose: str = "vulnerability_assessment"
    limitations: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)


@dataclass
class RiskFactor:
    """Individual risk factor."""
    factor_name: str
    impact_level: float  # 0.0 to 1.0
    likelihood: float   # 0.0 to 1.0
    description: str
    mitigation_priority: str = "medium"


@dataclass
class RiskScore:
    """Overall risk scoring information."""
    overall_score: float  # 0.0 to 10.0
    critical_path_score: float
    risk_level: RiskLevel
    contributing_factors: List[RiskFactor] = field(default_factory=list)
    risk_trend: str = "stable"  # increasing, decreasing, stable
    risk_velocity: float = 0.0
    confidence: float = 1.0


@dataclass
class BusinessImpactAnalysis:
    """Business impact analysis."""
    financial_impact: str = "medium"  # low, medium, high, critical
    operational_impact: str = "medium"
    reputational_impact: str = "medium"
    regulatory_impact: str = "low"
    customer_impact: str = "medium"
    impact_description: str = ""
    affected_business_processes: List[str] = field(default_factory=list)
    recovery_time_objective: Optional[str] = None
    recovery_point_objective: Optional[str] = None


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment."""
    overall_risk_score: RiskScore
    business_impact: BusinessImpactAnalysis
    risk_matrix: Dict[str, Dict[str, int]] = field(default_factory=dict)
    risk_appetite_alignment: str = "unknown"  # within, exceeds, unknown
    residual_risk_after_mitigation: Optional[RiskScore] = None
    risk_treatment_strategy: str = "mitigate"  # accept, avoid, mitigate, transfer
    risk_owner: Optional[str] = None
    next_assessment_date: Optional[datetime] = None


@dataclass
class Recommendation:
    """Security recommendation."""
    recommendation_id: str
    title: str
    description: str
    priority: str = "high"  # critical, high, medium, low
    category: str = "security"  # security, process, technical, strategic
    implementation_effort: str = "medium"  # low, medium, high
    cost_estimate: Optional[str] = None
    timeline: Optional[str] = None
    success_criteria: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    risks_if_not_implemented: List[str] = field(default_factory=list)
    responsible_party: Optional[str] = None
    
    def __post_init__(self):
        if not self.recommendation_id:
            self.recommendation_id = str(uuid.uuid4())


@dataclass
class RemediationPlan:
    """Comprehensive remediation plan."""
    plan_id: str
    executive_summary: str
    immediate_actions: List[Recommendation] = field(default_factory=list)
    short_term_actions: List[Recommendation] = field(default_factory=list)
    long_term_actions: List[Recommendation] = field(default_factory=list)
    strategic_recommendations: List[Recommendation] = field(default_factory=list)
    total_estimated_cost: Optional[str] = None
    total_estimated_timeline: Optional[str] = None
    success_metrics: List[str] = field(default_factory=list)
    risk_mitigation_effectiveness: Optional[float] = None
    
    def __post_init__(self):
        if not self.plan_id:
            self.plan_id = str(uuid.uuid4())


@dataclass
class ComplianceMapping:
    """Compliance framework mapping."""
    frameworks: Dict[ComplianceFramework, Dict[str, Any]] = field(default_factory=dict)
    compliance_status: Dict[ComplianceFramework, str] = field(default_factory=dict)  # compliant, non_compliant, partial
    gap_analysis: Dict[ComplianceFramework, List[str]] = field(default_factory=dict)
    recommendations: Dict[ComplianceFramework, List[str]] = field(default_factory=dict)
    certification_readiness: Dict[ComplianceFramework, float] = field(default_factory=dict)


@dataclass
class ExecutiveSummary:
    """Executive summary for management."""
    summary_text: str
    key_findings_count: Dict[SeverityLevel, int] = field(default_factory=dict)
    top_critical_findings: List[str] = field(default_factory=list)
    business_risk_level: RiskLevel = RiskLevel.MEDIUM
    recommended_actions: List[str] = field(default_factory=list)
    investment_required: Optional[str] = None
    timeline_to_secure: Optional[str] = None
    regulatory_implications: List[str] = field(default_factory=list)
    competitive_implications: Optional[str] = None
    board_recommendations: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityReport:
    """Main vulnerability report data structure."""
    report_id: str
    scan_id: str
    target_info: TargetInfo
    scan_metadata: ScanMetadata
    executive_summary: ExecutiveSummary
    technical_findings: List[TechnicalFinding] = field(default_factory=list)
    risk_assessment: Optional[RiskAssessment] = None
    remediation_plan: Optional[RemediationPlan] = None
    compliance_mapping: Optional[ComplianceMapping] = None
    appendices: Dict[str, Any] = field(default_factory=dict)
    report_metadata: Dict[str, Any] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=datetime.now)
    version: str = "1.0"
    
    def __post_init__(self):
        if not self.report_id:
            self.report_id = str(uuid.uuid4())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary format."""
        return {
            'report_id': self.report_id,
            'scan_id': self.scan_id,
            'target_info': {
                'primary_target': self.target_info.primary_target,
                'scope': self.target_info.scope,
                'exclusions': self.target_info.exclusions,
                'target_type': self.target_info.target_type.value,
                'business_context': self.target_info.business_context,
                'criticality_level': self.target_info.criticality_level.value,
                'owner': self.target_info.owner,
                'contact_info': self.target_info.contact_info,
                'environment': self.target_info.environment,
                'technology_stack': self.target_info.technology_stack,
                'authentication_required': self.target_info.authentication_required,
                'rate_limiting_info': self.target_info.rate_limiting_info
            },
            'scan_metadata': {
                'scan_start_time': self.scan_metadata.scan_start_time.isoformat(),
                'scan_end_time': self.scan_metadata.scan_end_time.isoformat(),
                'total_duration': str(self.scan_metadata.total_duration),
                'scanner_version': self.scan_metadata.scanner_version,
                'scan_configuration': self.scan_metadata.scan_configuration,
                'tool_versions': self.scan_metadata.tool_versions,
                'scan_profile': self.scan_metadata.scan_profile,
                'operator': self.scan_metadata.operator,
                'scan_purpose': self.scan_metadata.scan_purpose,
                'limitations': self.scan_metadata.limitations,
                'assumptions': self.scan_metadata.assumptions
            },
            'executive_summary': {
                'summary_text': self.executive_summary.summary_text,
                'key_findings_count': {k.value: v for k, v in self.executive_summary.key_findings_count.items()},
                'top_critical_findings': self.executive_summary.top_critical_findings,
                'business_risk_level': self.executive_summary.business_risk_level.value,
                'recommended_actions': self.executive_summary.recommended_actions,
                'investment_required': self.executive_summary.investment_required,
                'timeline_to_secure': self.executive_summary.timeline_to_secure,
                'regulatory_implications': self.executive_summary.regulatory_implications,
                'competitive_implications': self.executive_summary.competitive_implications,
                'board_recommendations': self.executive_summary.board_recommendations
            },
            'technical_findings': [
                {
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
                    'first_discovered': finding.first_discovered.isoformat(),
                    'last_updated': finding.last_updated.isoformat(),
                    'false_positive_likelihood': finding.false_positive_likelihood,
                    'business_impact': finding.business_impact,
                    'technical_impact': finding.technical_impact,
                    'exploit_complexity': finding.exploit_complexity,
                    'affected_urls': finding.affected_urls,
                    'metadata': finding.metadata
                } for finding in self.technical_findings
            ],
            'report_metadata': self.report_metadata,
            'generated_at': self.generated_at.isoformat(),
            'version': self.version
        }
    
    def get_findings_by_severity(self, severity: SeverityLevel) -> List[TechnicalFinding]:
        """Get findings filtered by severity."""
        return [f for f in self.technical_findings if f.severity == severity]
    
    def get_critical_findings(self) -> List[TechnicalFinding]:
        """Get critical severity findings."""
        return self.get_findings_by_severity(SeverityLevel.CRITICAL)
    
    def get_high_findings(self) -> List[TechnicalFinding]:
        """Get high severity findings."""
        return self.get_findings_by_severity(SeverityLevel.HIGH)
    
    def get_verified_findings(self) -> List[TechnicalFinding]:
        """Get verified findings only."""
        return [f for f in self.technical_findings if f.verification_status == VerificationStatus.VERIFIED]
    
    def get_findings_with_poc(self) -> List[TechnicalFinding]:
        """Get findings that have proof of concept."""
        return [f for f in self.technical_findings if f.proof_of_concept is not None]
    
    def get_summary_statistics(self) -> Dict[str, Any]:
        """Get summary statistics for the report."""
        total_findings = len(self.technical_findings)
        severity_counts = {
            severity.value: len(self.get_findings_by_severity(severity))
            for severity in SeverityLevel
        }
        
        verified_count = len(self.get_verified_findings())
        poc_count = len(self.get_findings_with_poc())
        
        return {
            'total_findings': total_findings,
            'severity_breakdown': severity_counts,
            'verified_findings': verified_count,
            'findings_with_poc': poc_count,
            'verification_rate': verified_count / total_findings if total_findings > 0 else 0,
            'poc_coverage': poc_count / total_findings if total_findings > 0 else 0
        }


# Report generation specific data structures

@dataclass
class GeneratedReport:
    """Generated report with metadata."""
    report_id: str
    format_type: str
    content: Union[bytes, str]
    file_size: int
    generated_at: datetime = field(default_factory=datetime.now)
    template_used: Optional[str] = None
    generation_time: Optional[timedelta] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def save_to_file(self, file_path: Union[str, Path]) -> None:
        """Save generated report to file."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        if isinstance(self.content, bytes):
            with open(path, 'wb') as f:
                f.write(self.content)
        else:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.content)


@dataclass
class ReportTemplate:
    """Report template definition."""
    template_id: str
    name: str
    description: str
    template_type: str  # executive, technical, compliance
    supported_formats: List[str] = field(default_factory=list)
    template_files: Dict[str, str] = field(default_factory=dict)  # format -> template_path
    variables: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    version: str = "1.0"