"""Risk calculation engine for comprehensive risk assessment."""

import logging
import math
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict

from ..models import (
    TechnicalFinding, TargetInfo, RiskAssessment, RiskScore, RiskFactor, 
    BusinessImpactAnalysis, SeverityLevel, ConfidenceLevel, RiskLevel,
    CriticalityLevel, VerificationStatus
)


class RiskCalculationError(Exception):
    """Risk calculation error."""
    pass


class RiskCalculator:
    """Advanced risk calculation engine with multiple methodologies."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize risk calculator.
        
        Args:
            config: System configuration
        """
        self.config = config
        self.logger = logging.getLogger('risk_calculator')
        
        # Risk calculation parameters
        risk_config = config.get('risk_assessment', {})
        
        # Severity weights for CVSS-like scoring
        self.severity_weights = {
            SeverityLevel.CRITICAL: 10.0,
            SeverityLevel.HIGH: 8.0,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.0,
            SeverityLevel.INFO: 0.5
        }
        
        # Confidence modifiers
        self.confidence_modifiers = {
            ConfidenceLevel.CONFIRMED: 1.0,
            ConfidenceLevel.FIRM: 0.9,
            ConfidenceLevel.TENTATIVE: 0.7,
            ConfidenceLevel.POSSIBLE: 0.5
        }
        
        # Business criticality multipliers
        self.criticality_multipliers = {
            CriticalityLevel.CRITICAL: 2.0,
            CriticalityLevel.HIGH: 1.5,
            CriticalityLevel.MEDIUM: 1.0,
            CriticalityLevel.LOW: 0.7
        }
        
        # Verification status adjustments
        self.verification_adjustments = {
            VerificationStatus.VERIFIED: 1.0,
            VerificationStatus.UNVERIFIED: 0.8,
            VerificationStatus.FALSE_POSITIVE: 0.0,
            VerificationStatus.DUPLICATE: 0.5
        }
        
        # Risk calculation settings
        self.max_risk_score = risk_config.get('max_risk_score', 10.0)
        self.time_decay_factor = risk_config.get('time_decay_factor', 0.1)
        self.exploit_complexity_weights = {
            'low': 1.2,
            'medium': 1.0,
            'high': 0.8
        }
        
        self.logger.info("Risk calculator initialized with comprehensive methodology")
    
    async def calculate_comprehensive_risk(self, findings: List[TechnicalFinding], 
                                         target_info: TargetInfo) -> RiskAssessment:
        """Calculate comprehensive risk assessment.
        
        Args:
            findings: List of technical findings
            target_info: Target information
            
        Returns:
            Complete RiskAssessment object
        """
        self.logger.info(f"Calculating comprehensive risk for {len(findings)} findings")
        
        try:
            # Calculate overall risk score
            overall_risk_score = await self._calculate_overall_risk_score(findings, target_info)
            
            # Calculate business impact analysis
            business_impact = await self._calculate_business_impact(findings, target_info)
            
            # Generate risk matrix
            risk_matrix = await self._generate_risk_matrix(findings)
            
            # Determine risk treatment strategy
            risk_treatment_strategy = self._determine_risk_treatment_strategy(overall_risk_score)
            
            # Calculate risk appetite alignment
            risk_appetite_alignment = self._assess_risk_appetite_alignment(overall_risk_score, target_info)
            
            # Create risk assessment
            risk_assessment = RiskAssessment(
                overall_risk_score=overall_risk_score,
                business_impact=business_impact,
                risk_matrix=risk_matrix,
                risk_appetite_alignment=risk_appetite_alignment,
                risk_treatment_strategy=risk_treatment_strategy,
                next_assessment_date=self._calculate_next_assessment_date(overall_risk_score)
            )
            
            self.logger.info(f"Risk assessment completed - Overall risk: {overall_risk_score.risk_level.value}")
            return risk_assessment
            
        except Exception as e:
            self.logger.error(f"Risk calculation failed: {e}")
            raise RiskCalculationError(f"Failed to calculate comprehensive risk: {e}")
    
    async def _calculate_overall_risk_score(self, findings: List[TechnicalFinding], 
                                          target_info: TargetInfo) -> RiskScore:
        """Calculate overall risk score using multiple factors.
        
        Args:
            findings: List of findings
            target_info: Target information
            
        Returns:
            RiskScore object
        """
        if not findings:
            return RiskScore(
                overall_score=0.0,
                critical_path_score=0.0,
                risk_level=RiskLevel.NEGLIGIBLE,
                contributing_factors=[]
            )
        
        # Calculate base risk scores
        raw_scores = []
        critical_path_scores = []
        contributing_factors = []
        
        for finding in findings:
            # Base severity score
            base_score = self.severity_weights.get(finding.severity, 0.0)
            
            # Apply confidence modifier
            confidence_modifier = self.confidence_modifiers.get(finding.confidence, 0.5)
            
            # Apply verification status
            verification_modifier = self.verification_adjustments.get(finding.verification_status, 0.8)
            
            # Apply exploit complexity
            exploit_modifier = self.exploit_complexity_weights.get(finding.exploit_complexity, 1.0)
            
            # Apply time decay (newer findings are more concerning)
            time_factor = self._calculate_time_decay_factor(finding.first_discovered)
            
            # Apply CVSS score if available
            cvss_factor = 1.0
            if finding.cvss_score:
                cvss_factor = finding.cvss_score / 10.0
            
            # Apply false positive likelihood
            fp_modifier = 1.0 - finding.false_positive_likelihood
            
            # Calculate finding risk score
            finding_risk = (base_score * confidence_modifier * verification_modifier * 
                          exploit_modifier * time_factor * cvss_factor * fp_modifier)
            
            # Apply business criticality multiplier
            criticality_multiplier = self.criticality_multipliers.get(target_info.criticality_level, 1.0)
            finding_risk *= criticality_multiplier
            
            raw_scores.append(finding_risk)
            
            # Check if this affects critical business processes
            if self._affects_critical_path(finding, target_info):
                critical_path_scores.append(finding_risk)
            
            # Add to contributing factors if significant
            if finding_risk > 3.0:  # Threshold for significant risk contribution
                contributing_factors.append(
                    RiskFactor(
                        factor_name=f"{finding.severity.value.title()} - {finding.title}",
                        impact_level=min(finding_risk / 10.0, 1.0),
                        likelihood=confidence_modifier,
                        description=f"Vulnerability contributes {finding_risk:.1f} risk points",
                        mitigation_priority=self._determine_mitigation_priority(finding_risk, finding.severity)
                    )
                )
        
        # Calculate aggregate scores
        if not raw_scores:
            overall_score = 0.0
        else:
            # Use weighted average with diminishing returns for multiple findings
            overall_score = self._calculate_aggregate_risk_score(raw_scores)
        
        critical_path_score = sum(critical_path_scores)
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)
        
        # Calculate risk trend and velocity
        risk_trend, risk_velocity = self._calculate_risk_trends(findings)
        
        # Calculate confidence in risk assessment
        assessment_confidence = self._calculate_assessment_confidence(findings)
        
        return RiskScore(
            overall_score=min(overall_score, self.max_risk_score),
            critical_path_score=critical_path_score,
            risk_level=risk_level,
            contributing_factors=contributing_factors[:10],  # Limit to top 10
            risk_trend=risk_trend,
            risk_velocity=risk_velocity,
            confidence=assessment_confidence
        )
    
    def _calculate_aggregate_risk_score(self, scores: List[float]) -> float:
        """Calculate aggregate risk score with diminishing returns.
        
        Args:
            scores: List of individual risk scores
            
        Returns:
            Aggregated risk score
        """
        if not scores:
            return 0.0
        
        # Sort scores in descending order
        sorted_scores = sorted(scores, reverse=True)
        
        # Apply diminishing returns formula
        # Formula: score = primary + (secondary * 0.8) + (tertiary * 0.6) + ... 
        aggregate = 0.0
        for i, score in enumerate(sorted_scores):
            weight = max(0.2, 1.0 - (i * 0.2))  # Diminishing weight, minimum 0.2
            aggregate += score * weight
        
        return aggregate
    
    def _calculate_time_decay_factor(self, discovery_time: datetime) -> float:
        """Calculate time decay factor for risk scoring.
        
        Args:
            discovery_time: When the finding was discovered
            
        Returns:
            Time decay factor (0.5 to 1.0)
        """
        days_since_discovery = (datetime.now() - discovery_time).days
        
        # Recent findings (< 7 days) get full weight
        if days_since_discovery <= 7:
            return 1.0
        
        # Apply exponential decay for older findings
        decay_factor = math.exp(-self.time_decay_factor * (days_since_discovery - 7) / 30)
        return max(0.5, decay_factor)  # Minimum factor of 0.5
    
    def _affects_critical_path(self, finding: TechnicalFinding, target_info: TargetInfo) -> bool:
        """Determine if finding affects critical business path.
        
        Args:
            finding: Technical finding
            target_info: Target information
            
        Returns:
            True if affects critical path
        """
        # Check if target is critical
        if target_info.criticality_level in [CriticalityLevel.CRITICAL, CriticalityLevel.HIGH]:
            return True
        
        # Check if finding affects critical business processes
        if finding.business_impact and 'critical' in finding.business_impact.lower():
            return True
        
        # Check if finding is in production environment
        if target_info.environment.lower() == 'production':
            return True
        
        # Check for high-impact vulnerabilities
        critical_keywords = ['authentication', 'authorization', 'payment', 'database', 'admin']
        finding_text = (finding.title + ' ' + finding.description).lower()
        
        return any(keyword in finding_text for keyword in critical_keywords)
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from numerical score.
        
        Args:
            risk_score: Numerical risk score
            
        Returns:
            RiskLevel enum value
        """
        if risk_score >= 8.0:
            return RiskLevel.CRITICAL
        elif risk_score >= 6.0:
            return RiskLevel.HIGH
        elif risk_score >= 3.0:
            return RiskLevel.MEDIUM
        elif risk_score >= 1.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.NEGLIGIBLE
    
    def _determine_mitigation_priority(self, risk_score: float, severity: SeverityLevel) -> str:
        """Determine mitigation priority.
        
        Args:
            risk_score: Risk score for the finding
            severity: Finding severity
            
        Returns:
            Priority string
        """
        if risk_score >= 8.0 or severity == SeverityLevel.CRITICAL:
            return "critical"
        elif risk_score >= 5.0 or severity == SeverityLevel.HIGH:
            return "high"
        elif risk_score >= 2.0:
            return "medium"
        else:
            return "low"
    
    def _calculate_risk_trends(self, findings: List[TechnicalFinding]) -> Tuple[str, float]:
        """Calculate risk trend and velocity.
        
        Args:
            findings: List of findings
            
        Returns:
            Tuple of (trend, velocity)
        """
        if not findings:
            return "stable", 0.0
        
        # Group findings by discovery time buckets
        now = datetime.now()
        recent_findings = []  # Last 7 days
        older_findings = []   # 8-30 days
        
        for finding in findings:
            days_ago = (now - finding.first_discovered).days
            if days_ago <= 7:
                recent_findings.append(finding)
            elif days_ago <= 30:
                older_findings.append(finding)
        
        # Calculate trend based on recent vs older findings
        recent_score = sum(self.severity_weights.get(f.severity, 0) for f in recent_findings)
        older_score = sum(self.severity_weights.get(f.severity, 0) for f in older_findings)
        
        if len(recent_findings) > len(older_findings) * 1.5:
            trend = "increasing"
            velocity = (recent_score - older_score) / max(older_score, 1.0)
        elif len(recent_findings) < len(older_findings) * 0.5:
            trend = "decreasing"
            velocity = -(older_score - recent_score) / max(recent_score, 1.0)
        else:
            trend = "stable"
            velocity = 0.0
        
        return trend, velocity
    
    def _calculate_assessment_confidence(self, findings: List[TechnicalFinding]) -> float:
        """Calculate confidence in risk assessment.
        
        Args:
            findings: List of findings
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        if not findings:
            return 0.0
        
        # Base confidence on finding verification and confidence levels
        verified_count = sum(1 for f in findings if f.verification_status == VerificationStatus.VERIFIED)
        high_confidence_count = sum(1 for f in findings if f.confidence in [ConfidenceLevel.CONFIRMED, ConfidenceLevel.FIRM])
        
        verification_ratio = verified_count / len(findings)
        confidence_ratio = high_confidence_count / len(findings)
        
        # Average the ratios
        overall_confidence = (verification_ratio + confidence_ratio) / 2
        
        return min(1.0, max(0.1, overall_confidence))
    
    async def _calculate_business_impact(self, findings: List[TechnicalFinding], 
                                       target_info: TargetInfo) -> BusinessImpactAnalysis:
        """Calculate business impact analysis.
        
        Args:
            findings: List of findings
            target_info: Target information
            
        Returns:
            BusinessImpactAnalysis object
        """
        if not findings:
            return BusinessImpactAnalysis()
        
        # Analyze impact categories
        financial_impact = self._assess_financial_impact(findings, target_info)
        operational_impact = self._assess_operational_impact(findings, target_info)
        reputational_impact = self._assess_reputational_impact(findings, target_info)
        regulatory_impact = self._assess_regulatory_impact(findings, target_info)
        customer_impact = self._assess_customer_impact(findings, target_info)
        
        # Generate impact description
        impact_description = self._generate_impact_description(findings, target_info)
        
        # Identify affected business processes
        affected_processes = self._identify_affected_processes(findings, target_info)
        
        return BusinessImpactAnalysis(
            financial_impact=financial_impact,
            operational_impact=operational_impact,
            reputational_impact=reputational_impact,
            regulatory_impact=regulatory_impact,
            customer_impact=customer_impact,
            impact_description=impact_description,
            affected_business_processes=affected_processes,
            recovery_time_objective=self._estimate_rto(findings),
            recovery_point_objective=self._estimate_rpo(findings)
        )
    
    def _assess_financial_impact(self, findings: List[TechnicalFinding], target_info: TargetInfo) -> str:
        """Assess financial impact level."""
        critical_high_count = sum(1 for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH])
        
        if critical_high_count >= 5 and target_info.criticality_level == CriticalityLevel.CRITICAL:
            return "critical"
        elif critical_high_count >= 3 or target_info.criticality_level == CriticalityLevel.HIGH:
            return "high"
        elif critical_high_count >= 1 or any(f.severity == SeverityLevel.MEDIUM for f in findings):
            return "medium"
        else:
            return "low"
    
    def _assess_operational_impact(self, findings: List[TechnicalFinding], target_info: TargetInfo) -> str:
        """Assess operational impact level."""
        # Check for findings that could disrupt operations
        disruptive_keywords = ['denial of service', 'dos', 'availability', 'downtime']
        
        disruptive_findings = 0
        for finding in findings:
            finding_text = (finding.title + ' ' + finding.description).lower()
            if any(keyword in finding_text for keyword in disruptive_keywords):
                disruptive_findings += 1
        
        if disruptive_findings >= 3:
            return "high"
        elif disruptive_findings >= 1:
            return "medium"
        elif any(f.severity == SeverityLevel.CRITICAL for f in findings):
            return "medium"
        else:
            return "low"
    
    def _assess_reputational_impact(self, findings: List[TechnicalFinding], target_info: TargetInfo) -> str:
        """Assess reputational impact level."""
        # Data exposure and customer-facing vulnerabilities have high reputational risk
        reputation_keywords = ['data breach', 'exposure', 'leak', 'customer data', 'personal information']
        
        high_reputation_risk = 0
        for finding in findings:
            finding_text = (finding.title + ' ' + finding.description).lower()
            if any(keyword in finding_text for keyword in reputation_keywords):
                high_reputation_risk += 1
        
        if high_reputation_risk >= 2 or target_info.environment == 'production':
            return "high"
        elif high_reputation_risk >= 1:
            return "medium"
        else:
            return "low"
    
    def _assess_regulatory_impact(self, findings: List[TechnicalFinding], target_info: TargetInfo) -> str:
        """Assess regulatory impact level."""
        # Privacy and data protection vulnerabilities have regulatory implications
        regulatory_keywords = ['gdpr', 'privacy', 'data protection', 'compliance', 'regulation']
        
        regulatory_findings = 0
        for finding in findings:
            finding_text = (finding.title + ' ' + finding.description).lower()
            if any(keyword in finding_text for keyword in regulatory_keywords):
                regulatory_findings += 1
        
        # Also consider business context
        if target_info.business_context:
            business_text = target_info.business_context.lower()
            if any(keyword in business_text for keyword in ['healthcare', 'finance', 'banking', 'payment']):
                return "high"
        
        if regulatory_findings >= 2:
            return "high"
        elif regulatory_findings >= 1:
            return "medium"
        else:
            return "low"
    
    def _assess_customer_impact(self, findings: List[TechnicalFinding], target_info: TargetInfo) -> str:
        """Assess customer impact level."""
        # Customer-facing and authentication vulnerabilities impact customers
        customer_keywords = ['authentication', 'login', 'account', 'session', 'customer', 'user data']
        
        customer_findings = 0
        for finding in findings:
            finding_text = (finding.title + ' ' + finding.description).lower()
            if any(keyword in finding_text for keyword in customer_keywords):
                customer_findings += 1
        
        if customer_findings >= 3 or target_info.target_type.value == 'web_app':
            return "high"
        elif customer_findings >= 1:
            return "medium"
        else:
            return "low"
    
    def _generate_impact_description(self, findings: List[TechnicalFinding], target_info: TargetInfo) -> str:
        """Generate comprehensive impact description."""
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        
        description_parts = []
        
        if critical_count > 0:
            description_parts.append(f"{critical_count} critical vulnerabilities pose immediate threat to business operations")
        
        if high_count > 0:
            description_parts.append(f"{high_count} high-severity vulnerabilities require urgent attention")
        
        if target_info.environment == 'production':
            description_parts.append("Production environment exposure increases business risk")
        
        if target_info.criticality_level == CriticalityLevel.CRITICAL:
            description_parts.append("Critical business system classification amplifies potential impact")
        
        if not description_parts:
            description_parts.append("Identified vulnerabilities present manageable business risk")
        
        return ". ".join(description_parts) + "."
    
    def _identify_affected_processes(self, findings: List[TechnicalFinding], target_info: TargetInfo) -> List[str]:
        """Identify affected business processes."""
        processes = set()
        
        # Map vulnerabilities to business processes
        process_keywords = {
            'authentication': ['User Authentication', 'Access Control'],
            'payment': ['Payment Processing', 'Financial Transactions'],
            'database': ['Data Management', 'Information Storage'],
            'api': ['API Services', 'System Integration'],
            'admin': ['System Administration', 'Management Functions'],
            'backup': ['Data Backup', 'Disaster Recovery'],
            'encryption': ['Data Protection', 'Security Controls']
        }
        
        for finding in findings:
            finding_text = (finding.title + ' ' + finding.description).lower()
            for keyword, process_list in process_keywords.items():
                if keyword in finding_text:
                    processes.update(process_list)
        
        # Add target-type specific processes
        if target_info.target_type.value == 'web_app':
            processes.add('Web Application Services')
        elif target_info.target_type.value == 'api':
            processes.add('API Gateway Services')
        
        return sorted(list(processes))
    
    def _estimate_rto(self, findings: List[TechnicalFinding]) -> Optional[str]:
        """Estimate Recovery Time Objective."""
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        
        if critical_count >= 3:
            return "< 4 hours"
        elif critical_count >= 1:
            return "< 24 hours"
        elif any(f.severity == SeverityLevel.HIGH for f in findings):
            return "< 72 hours"
        else:
            return "< 1 week"
    
    def _estimate_rpo(self, findings: List[TechnicalFinding]) -> Optional[str]:
        """Estimate Recovery Point Objective."""
        data_related = sum(1 for f in findings if any(keyword in f.description.lower() 
                          for keyword in ['data', 'database', 'storage', 'backup']))
        
        if data_related >= 2:
            return "< 1 hour"
        elif data_related >= 1:
            return "< 4 hours"
        else:
            return "< 24 hours"
    
    async def _generate_risk_matrix(self, findings: List[TechnicalFinding]) -> Dict[str, Dict[str, int]]:
        """Generate risk matrix for visualization.
        
        Args:
            findings: List of findings
            
        Returns:
            Risk matrix dictionary
        """
        # Initialize matrix
        impact_levels = ['low', 'medium', 'high', 'critical']
        likelihood_levels = ['low', 'medium', 'high', 'critical']
        
        matrix = {}
        for impact in impact_levels:
            matrix[impact] = {}
            for likelihood in likelihood_levels:
                matrix[impact][likelihood] = 0
        
        # Populate matrix based on findings
        for finding in findings:
            impact = self._map_severity_to_impact(finding.severity)
            likelihood = self._map_confidence_to_likelihood(finding.confidence)
            
            matrix[impact][likelihood] += 1
        
        return matrix
    
    def _map_severity_to_impact(self, severity: SeverityLevel) -> str:
        """Map severity to impact level."""
        mapping = {
            SeverityLevel.CRITICAL: 'critical',
            SeverityLevel.HIGH: 'high',
            SeverityLevel.MEDIUM: 'medium',
            SeverityLevel.LOW: 'low',
            SeverityLevel.INFO: 'low'
        }
        return mapping.get(severity, 'low')
    
    def _map_confidence_to_likelihood(self, confidence: ConfidenceLevel) -> str:
        """Map confidence to likelihood level."""
        mapping = {
            ConfidenceLevel.CONFIRMED: 'critical',
            ConfidenceLevel.FIRM: 'high',
            ConfidenceLevel.TENTATIVE: 'medium',
            ConfidenceLevel.POSSIBLE: 'low'
        }
        return mapping.get(confidence, 'low')
    
    def _determine_risk_treatment_strategy(self, risk_score: RiskScore) -> str:
        """Determine appropriate risk treatment strategy.
        
        Args:
            risk_score: Overall risk score
            
        Returns:
            Risk treatment strategy
        """
        if risk_score.risk_level == RiskLevel.CRITICAL:
            return "mitigate"
        elif risk_score.risk_level == RiskLevel.HIGH:
            return "mitigate"
        elif risk_score.risk_level == RiskLevel.MEDIUM:
            return "mitigate"
        elif risk_score.risk_level == RiskLevel.LOW:
            return "accept"
        else:
            return "accept"
    
    def _assess_risk_appetite_alignment(self, risk_score: RiskScore, target_info: TargetInfo) -> str:
        """Assess alignment with organizational risk appetite.
        
        Args:
            risk_score: Risk score
            target_info: Target information
            
        Returns:
            Risk appetite alignment status
        """
        # Risk appetite thresholds based on business criticality
        if target_info.criticality_level == CriticalityLevel.CRITICAL:
            threshold = 3.0
        elif target_info.criticality_level == CriticalityLevel.HIGH:
            threshold = 5.0
        else:
            threshold = 7.0
        
        if risk_score.overall_score <= threshold:
            return "within"
        else:
            return "exceeds"
    
    def _calculate_next_assessment_date(self, risk_score: RiskScore) -> Optional[datetime]:
        """Calculate next recommended assessment date.
        
        Args:
            risk_score: Risk score
            
        Returns:
            Next assessment date
        """
        now = datetime.now()
        
        if risk_score.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            # High risk - reassess monthly
            return now + timedelta(days=30)
        elif risk_score.risk_level == RiskLevel.MEDIUM:
            # Medium risk - reassess quarterly
            return now + timedelta(days=90)
        else:
            # Low risk - reassess annually
            return now + timedelta(days=365)