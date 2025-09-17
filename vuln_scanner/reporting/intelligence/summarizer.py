"""Intelligent summarization engine for executive reporting."""

import logging
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter

from ..models import (
    TechnicalFinding, TargetInfo, ExecutiveSummary, SeverityLevel, 
    RiskLevel, VerificationStatus, BusinessImpactAnalysis
)


class SummarizationError(Exception):
    """Summarization error."""
    pass


class IntelligentSummarizer:
    """Intelligent summarization engine with fallback to template-based summarization."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize intelligent summarizer.
        
        Args:
            config: System configuration
        """
        self.config = config
        self.logger = logging.getLogger('intelligent_summarizer')
        
        # Initialize LLM client if available
        self.llm_client = self._initialize_llm_client(config)
        
        # Template-based summarizer as fallback
        self.template_summarizer = TemplateSummarizer(config)
        
        self.logger.info(f"Intelligent summarizer initialized (LLM: {'enabled' if self.llm_client else 'disabled'})")
    
    def _initialize_llm_client(self, config: Dict[str, Any]) -> Optional[Any]:
        """Initialize LLM client if configured.
        
        Args:
            config: System configuration
            
        Returns:
            LLM client or None if not available
        """
        llm_config = config.get('llm', {})
        
        if not llm_config.get('enabled', False):
            return None
        
        # In a real implementation, you would initialize your preferred LLM client here
        # This could be OpenAI, Anthropic, local models, etc.
        try:
            # Placeholder for LLM client initialization
            self.logger.info("LLM client would be initialized here")
            return None  # Disabled for now
        except Exception as e:
            self.logger.warning(f"Failed to initialize LLM client: {e}")
            return None
    
    async def generate_executive_summary(self, findings: List[TechnicalFinding], 
                                       target_info: TargetInfo) -> ExecutiveSummary:
        """Generate intelligent executive summary.
        
        Args:
            findings: List of technical findings
            target_info: Target information
            
        Returns:
            ExecutiveSummary object
        """
        self.logger.info(f"Generating executive summary for {len(findings)} findings")
        
        try:
            if self.llm_client:
                return await self._generate_ai_summary(findings, target_info)
            else:
                return await self.template_summarizer.generate_summary(findings, target_info)
        except Exception as e:
            self.logger.error(f"Executive summary generation failed: {e}")
            # Fallback to basic template summary
            return await self.template_summarizer.generate_basic_summary(findings, target_info)
    
    async def _generate_ai_summary(self, findings: List[TechnicalFinding], 
                                 target_info: TargetInfo) -> ExecutiveSummary:
        """Generate AI-powered executive summary.
        
        Args:
            findings: List of findings
            target_info: Target information
            
        Returns:
            ExecutiveSummary from LLM
        """
        # Prepare context for LLM
        context = self._prepare_llm_context(findings, target_info)
        
        # Generate summary using LLM
        prompt = self._build_executive_summary_prompt(context)
        
        # This would call your LLM service
        llm_response = await self._call_llm_service(prompt)
        
        # Parse LLM response into ExecutiveSummary object
        return self._parse_llm_summary(llm_response, findings, target_info)
    
    def _prepare_llm_context(self, findings: List[TechnicalFinding], 
                            target_info: TargetInfo) -> Dict[str, Any]:
        """Prepare context for LLM processing."""
        # Analyze findings
        severity_counts = Counter(f.severity for f in findings)
        verified_count = sum(1 for f in findings if f.verification_status == VerificationStatus.VERIFIED)
        
        # Top critical findings
        critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL][:5]
        high_findings = [f for f in findings if f.severity == SeverityLevel.HIGH][:5]
        
        # Business impact keywords
        business_keywords = self._extract_business_impact_keywords(findings)
        
        return {
            'target': {
                'name': target_info.primary_target,
                'type': target_info.target_type.value,
                'environment': target_info.environment,
                'criticality': target_info.criticality_level.value,
                'business_context': target_info.business_context
            },
            'statistics': {
                'total_findings': len(findings),
                'verified_findings': verified_count,
                'severity_breakdown': {s.value: severity_counts.get(s, 0) for s in SeverityLevel},
                'verification_rate': verified_count / len(findings) if findings else 0
            },
            'critical_findings': [
                {
                    'title': f.title,
                    'severity': f.severity.value,
                    'description': f.description[:200] + '...' if len(f.description) > 200 else f.description,
                    'business_impact': f.business_impact or 'Not specified'
                }
                for f in critical_findings
            ],
            'high_findings': [
                {
                    'title': f.title,
                    'severity': f.severity.value,
                    'description': f.description[:200] + '...' if len(f.description) > 200 else f.description
                }
                for f in high_findings
            ],
            'business_impact_keywords': business_keywords
        }
    
    def _extract_business_impact_keywords(self, findings: List[TechnicalFinding]) -> List[str]:
        """Extract business impact keywords from findings."""
        business_keywords = set()
        
        impact_terms = {
            'data_exposure': ['data breach', 'information disclosure', 'data exposure', 'privacy'],
            'financial_loss': ['payment', 'financial', 'transaction', 'billing'],
            'service_disruption': ['denial of service', 'availability', 'downtime', 'outage'],
            'compliance_violation': ['compliance', 'regulatory', 'gdpr', 'pci', 'hipaa'],
            'reputation_damage': ['public', 'customer', 'reputation', 'trust']
        }
        
        for finding in findings:
            finding_text = (finding.title + ' ' + finding.description).lower()
            
            for category, terms in impact_terms.items():
                if any(term in finding_text for term in terms):
                    business_keywords.add(category)
        
        return list(business_keywords)
    
    def _build_executive_summary_prompt(self, context: Dict[str, Any]) -> str:
        """Build prompt for executive summary generation."""
        prompt = f"""
        Generate an executive summary for a cybersecurity assessment report.
        
        TARGET INFORMATION:
        - Target: {context['target']['name']}
        - Type: {context['target']['type']}
        - Environment: {context['target']['environment']}
        - Business Criticality: {context['target']['criticality']}
        - Business Context: {context['target']['business_context']}
        
        SECURITY FINDINGS:
        - Total Findings: {context['statistics']['total_findings']}
        - Verified Findings: {context['statistics']['verified_findings']} ({context['statistics']['verification_rate']:.1%})
        - Critical: {context['statistics']['severity_breakdown']['critical']}
        - High: {context['statistics']['severity_breakdown']['high']}
        - Medium: {context['statistics']['severity_breakdown']['medium']}
        - Low: {context['statistics']['severity_breakdown']['low']}
        
        TOP CRITICAL FINDINGS:
        """
        
        for finding in context['critical_findings']:
            prompt += f"- {finding['title']}: {finding['description']}\n"
        
        prompt += f"""
        
        BUSINESS IMPACT AREAS: {', '.join(context['business_impact_keywords'])}
        
        Please generate a professional executive summary that includes:
        1. Overall security posture assessment (2-3 sentences)
        2. Key business risks and impact (2-3 sentences)
        3. Critical findings that need immediate attention (bullet points)
        4. Recommended immediate actions (bullet points)
        5. Investment and timeline recommendations
        
        Write in business language suitable for executive leadership. Focus on business impact rather than technical details.
        """
        
        return prompt
    
    async def _call_llm_service(self, prompt: str) -> str:
        """Call LLM service with prompt.
        
        Args:
            prompt: Prompt for LLM
            
        Returns:
            LLM response
        """
        # Placeholder for actual LLM service call
        # In real implementation, this would call OpenAI, Anthropic, etc.
        
        # For now, return a template response
        return """
        The security assessment of {target} has identified significant vulnerabilities that pose immediate risk to business operations. 
        Critical vulnerabilities require urgent remediation to prevent potential data breaches and service disruptions.
        
        Key business risks include potential compliance violations, customer data exposure, and operational downtime.
        The current security posture presents elevated risk that exceeds acceptable thresholds for a production environment.
        
        Immediate actions required:
        - Address all critical severity vulnerabilities within 48 hours
        - Implement emergency access controls and monitoring
        - Coordinate with compliance and legal teams on regulatory requirements
        
        Recommended investment: $50,000-$100,000 for immediate remediation
        Timeline: 2-4 weeks for comprehensive security improvements
        """
    
    async def _parse_llm_summary(self, llm_response: str, findings: List[TechnicalFinding], 
                          target_info: TargetInfo) -> ExecutiveSummary:
        """Parse LLM response into ExecutiveSummary object."""
        # For now, use template summarizer to create structured object
        # and enhance with LLM-generated text
        template_summary = await self.template_summarizer.generate_summary(findings, target_info)
        
        # Replace summary text with LLM-generated content
        template_summary.summary_text = llm_response.strip()
        
        return template_summary
    
    async def generate_business_impact_analysis(self, findings: List[TechnicalFinding], 
                                              target_info: TargetInfo) -> BusinessImpactAnalysis:
        """Generate business impact analysis.
        
        Args:
            findings: List of findings
            target_info: Target information
            
        Returns:
            BusinessImpactAnalysis object
        """
        if self.llm_client:
            return await self._generate_ai_impact_analysis(findings, target_info)
        else:
            return await self.template_summarizer.generate_impact_analysis(findings, target_info)
    
    async def _generate_ai_impact_analysis(self, findings: List[TechnicalFinding],
                                         target_info: TargetInfo) -> BusinessImpactAnalysis:
        """Generate AI-powered business impact analysis."""
        # Prepare context for business impact analysis
        context = self._prepare_impact_context(findings, target_info)
        
        # Generate analysis using LLM
        prompt = self._build_impact_analysis_prompt(context)
        llm_response = await self._call_llm_service(prompt)
        
        # Parse response into BusinessImpactAnalysis
        return self._parse_impact_analysis(llm_response, findings)
    
    def _prepare_impact_context(self, findings: List[TechnicalFinding], 
                               target_info: TargetInfo) -> Dict[str, Any]:
        """Prepare context for business impact analysis."""
        # Analyze impact vectors
        impact_vectors = {
            'data_exposure': [],
            'service_disruption': [],
            'financial_risk': [],
            'compliance_risk': [],
            'reputation_risk': []
        }
        
        for finding in findings:
            finding_text = (finding.title + ' ' + finding.description).lower()
            
            if any(term in finding_text for term in ['data', 'information', 'exposure', 'leak']):
                impact_vectors['data_exposure'].append(finding)
            
            if any(term in finding_text for term in ['dos', 'denial', 'availability', 'crash']):
                impact_vectors['service_disruption'].append(finding)
            
            if any(term in finding_text for term in ['payment', 'financial', 'fraud', 'transaction']):
                impact_vectors['financial_risk'].append(finding)
            
            if any(term in finding_text for term in ['compliance', 'regulation', 'gdpr', 'pci']):
                impact_vectors['compliance_risk'].append(finding)
        
        return {
            'target_info': target_info,
            'impact_vectors': impact_vectors,
            'critical_count': sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL),
            'high_count': sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        }
    
    def _build_impact_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """Build prompt for business impact analysis."""
        return f"""
        Analyze the business impact of cybersecurity vulnerabilities for {context['target_info'].primary_target}.
        
        Impact Analysis:
        - Data Exposure Risk: {len(context['impact_vectors']['data_exposure'])} vulnerabilities
        - Service Disruption Risk: {len(context['impact_vectors']['service_disruption'])} vulnerabilities  
        - Financial Risk: {len(context['impact_vectors']['financial_risk'])} vulnerabilities
        - Compliance Risk: {len(context['impact_vectors']['compliance_risk'])} vulnerabilities
        
        Critical vulnerabilities: {context['critical_count']}
        High severity vulnerabilities: {context['high_count']}
        
        Provide impact assessment for:
        1. Financial Impact (low/medium/high/critical)
        2. Operational Impact (low/medium/high/critical)
        3. Reputational Impact (low/medium/high/critical)
        4. Regulatory Impact (low/medium/high/critical)
        5. Customer Impact (low/medium/high/critical)
        6. Recovery Time Objective (RTO)
        7. Recovery Point Objective (RPO)
        """
    
    def _parse_impact_analysis(self, llm_response: str, 
                             findings: List[TechnicalFinding]) -> BusinessImpactAnalysis:
        """Parse LLM impact analysis response."""
        # Fallback to template-based analysis with LLM enhancements
        return BusinessImpactAnalysis(
            financial_impact="medium",
            operational_impact="medium", 
            reputational_impact="medium",
            regulatory_impact="low",
            customer_impact="medium",
            impact_description=llm_response.strip()[:500],  # Truncate for field limit
            recovery_time_objective="< 24 hours",
            recovery_point_objective="< 4 hours"
        )


class TemplateSummarizer:
    """Template-based summarization engine as fallback."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize template summarizer."""
        self.config = config
        self.logger = logging.getLogger('template_summarizer')
    
    async def generate_summary(self, findings: List[TechnicalFinding], 
                             target_info: TargetInfo) -> ExecutiveSummary:
        """Generate template-based executive summary."""
        self.logger.info("Generating template-based executive summary")
        
        # Calculate statistics
        severity_counts = {severity: 0 for severity in SeverityLevel}
        for finding in findings:
            severity_counts[finding.severity] += 1
        
        # Determine overall risk level
        business_risk_level = self._determine_business_risk_level(findings, target_info)
        
        # Generate summary text
        summary_text = self._generate_summary_text(findings, target_info, severity_counts)
        
        # Get top critical findings
        top_critical_findings = self._get_top_critical_findings(findings)
        
        # Generate recommendations
        recommended_actions = self._generate_recommended_actions(findings, target_info)
        
        # Estimate investment and timeline
        investment_required = self._estimate_investment(findings)
        timeline_to_secure = self._estimate_timeline(findings)
        
        # Generate regulatory implications
        regulatory_implications = self._identify_regulatory_implications(findings, target_info)
        
        # Generate board recommendations
        board_recommendations = self._generate_board_recommendations(findings, target_info)
        
        return ExecutiveSummary(
            summary_text=summary_text,
            key_findings_count=severity_counts,
            top_critical_findings=top_critical_findings,
            business_risk_level=business_risk_level,
            recommended_actions=recommended_actions,
            investment_required=investment_required,
            timeline_to_secure=timeline_to_secure,
            regulatory_implications=regulatory_implications,
            board_recommendations=board_recommendations
        )
    
    async def generate_basic_summary(self, findings: List[TechnicalFinding], 
                                   target_info: TargetInfo) -> ExecutiveSummary:
        """Generate basic executive summary with minimal processing."""
        severity_counts = Counter(f.severity for f in findings)
        
        if severity_counts.get(SeverityLevel.CRITICAL, 0) > 0:
            risk_level = RiskLevel.CRITICAL
        elif severity_counts.get(SeverityLevel.HIGH, 0) > 0:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.MEDIUM
        
        summary_text = f"Security assessment identified {len(findings)} total findings requiring attention."
        
        return ExecutiveSummary(
            summary_text=summary_text,
            key_findings_count=dict(severity_counts),
            business_risk_level=risk_level,
            recommended_actions=["Review and remediate identified vulnerabilities"],
            investment_required="To be determined",
            timeline_to_secure="2-4 weeks"
        )
    
    def _determine_business_risk_level(self, findings: List[TechnicalFinding], 
                                     target_info: TargetInfo) -> RiskLevel:
        """Determine business risk level based on findings and target."""
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        
        # Adjust risk based on target criticality and environment
        risk_multiplier = 1.0
        if target_info.criticality_level.value == 'critical':
            risk_multiplier = 1.5
        elif target_info.criticality_level.value == 'high':
            risk_multiplier = 1.2
        
        if target_info.environment == 'production':
            risk_multiplier *= 1.3
        
        adjusted_critical = critical_count * risk_multiplier
        adjusted_high = high_count * risk_multiplier
        
        if adjusted_critical >= 3:
            return RiskLevel.CRITICAL
        elif adjusted_critical >= 1 or adjusted_high >= 5:
            return RiskLevel.HIGH
        elif adjusted_high >= 1 or len(findings) >= 10:
            return RiskLevel.MEDIUM
        elif len(findings) > 0:
            return RiskLevel.LOW
        else:
            return RiskLevel.NEGLIGIBLE
    
    def _generate_summary_text(self, findings: List[TechnicalFinding], 
                             target_info: TargetInfo, 
                             severity_counts: Dict[SeverityLevel, int]) -> str:
        """Generate executive summary text."""
        total_findings = len(findings)
        critical_high = severity_counts[SeverityLevel.CRITICAL] + severity_counts[SeverityLevel.HIGH]
        
        summary_parts = []
        
        # Opening statement
        summary_parts.append(
            f"The security assessment of {target_info.primary_target} identified "
            f"{total_findings} vulnerabilities across the {target_info.target_type.value} environment."
        )
        
        # Risk assessment
        if critical_high > 0:
            summary_parts.append(
                f"Of particular concern are {critical_high} critical and high-severity vulnerabilities "
                f"that pose immediate risk to business operations and data security."
            )
        
        # Business context
        if target_info.environment == 'production':
            summary_parts.append(
                "The production environment exposure significantly increases the potential impact "
                "of successful exploitation."
            )
        
        # Criticality context
        if target_info.criticality_level.value in ['critical', 'high']:
            summary_parts.append(
                f"Given the {target_info.criticality_level.value} business criticality of this system, "
                f"these vulnerabilities represent substantial risk to organizational objectives."
            )
        
        # Remediation urgency
        if severity_counts[SeverityLevel.CRITICAL] > 0:
            summary_parts.append(
                "Immediate action is required to address critical vulnerabilities and prevent "
                "potential security incidents."
            )
        elif severity_counts[SeverityLevel.HIGH] > 0:
            summary_parts.append(
                "Prompt remediation of high-severity vulnerabilities is recommended to maintain "
                "acceptable security posture."
            )
        
        return " ".join(summary_parts)
    
    def _get_top_critical_findings(self, findings: List[TechnicalFinding]) -> List[str]:
        """Get top critical findings for executive attention."""
        # Sort by severity and confidence
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                list(SeverityLevel).index(f.severity),
                -list(ConfidenceLevel).index(f.confidence) if hasattr(f, 'confidence') else 0
            )
        )
        
        # Get top 5 most critical findings
        top_findings = []
        for finding in sorted_findings[:5]:
            if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                top_findings.append(f"{finding.severity.value.title()}: {finding.title}")
        
        return top_findings
    
    def _generate_recommended_actions(self, findings: List[TechnicalFinding], 
                                    target_info: TargetInfo) -> List[str]:
        """Generate recommended immediate actions."""
        actions = []
        
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        
        if critical_count > 0:
            actions.append(f"Immediately remediate {critical_count} critical vulnerabilities within 48 hours")
        
        if high_count > 0:
            actions.append(f"Address {high_count} high-severity vulnerabilities within 1 week")
        
        # Environment-specific actions
        if target_info.environment == 'production':
            actions.append("Implement enhanced monitoring and alerting for production environment")
        
        # Generic security actions
        actions.extend([
            "Establish regular vulnerability scanning and assessment schedule",
            "Review and update incident response procedures",
            "Provide security awareness training for relevant personnel"
        ])
        
        return actions[:6]  # Limit to 6 actions for executive consumption
    
    def _estimate_investment(self, findings: List[TechnicalFinding]) -> str:
        """Estimate investment required for remediation."""
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        total_significant = critical_count + high_count
        
        if total_significant >= 10:
            return "$100,000 - $250,000"
        elif total_significant >= 5:
            return "$50,000 - $100,000"
        elif total_significant >= 1:
            return "$20,000 - $50,000"
        else:
            return "$10,000 - $20,000"
    
    def _estimate_timeline(self, findings: List[TechnicalFinding]) -> str:
        """Estimate timeline to secure system."""
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        
        if critical_count >= 5:
            return "6-12 weeks"
        elif critical_count >= 1 or high_count >= 5:
            return "4-8 weeks"
        elif high_count >= 1:
            return "2-4 weeks"
        else:
            return "1-2 weeks"
    
    def _identify_regulatory_implications(self, findings: List[TechnicalFinding], 
                                       target_info: TargetInfo) -> List[str]:
        """Identify regulatory compliance implications."""
        implications = []
        
        # Check for data-related vulnerabilities
        data_vulnerabilities = [
            f for f in findings 
            if any(keyword in (f.title + ' ' + f.description).lower() 
                  for keyword in ['data', 'privacy', 'personal', 'customer'])
        ]
        
        if data_vulnerabilities:
            implications.append("GDPR compliance risks due to potential data exposure vulnerabilities")
        
        # Check for payment-related vulnerabilities  
        payment_vulnerabilities = [
            f for f in findings
            if any(keyword in (f.title + ' ' + f.description).lower()
                  for keyword in ['payment', 'card', 'financial', 'transaction'])
        ]
        
        if payment_vulnerabilities:
            implications.append("PCI DSS compliance requirements for payment data protection")
        
        # Business context implications
        if target_info.business_context:
            business_lower = target_info.business_context.lower()
            if 'healthcare' in business_lower or 'medical' in business_lower:
                implications.append("HIPAA compliance considerations for healthcare data protection")
            elif 'financial' in business_lower or 'banking' in business_lower:
                implications.append("Financial services regulatory requirements may apply")
        
        return implications
    
    def _generate_board_recommendations(self, findings: List[TechnicalFinding], 
                                      target_info: TargetInfo) -> List[str]:
        """Generate board-level recommendations."""
        recommendations = []
        
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        
        if critical_count >= 3:
            recommendations.append("Consider engaging external cybersecurity consultants for immediate remediation support")
            recommendations.append("Review and potentially increase cybersecurity budget allocation")
        
        if high_count >= 5 or critical_count >= 1:
            recommendations.append("Schedule monthly board briefings on cybersecurity posture until risks are mitigated")
        
        recommendations.extend([
            "Ensure adequate cyber insurance coverage given identified vulnerabilities",
            "Review incident response plan and communication procedures with legal counsel",
            "Consider third-party security assessments on quarterly basis"
        ])
        
        return recommendations[:5]  # Limit for board consumption
    
    async def generate_impact_analysis(self, findings: List[TechnicalFinding],
                                     target_info: TargetInfo) -> BusinessImpactAnalysis:
        """Generate business impact analysis using templates."""
        # Analyze findings for business impact indicators
        impact_keywords = {
            'financial': ['payment', 'transaction', 'billing', 'financial', 'money'],
            'operational': ['service', 'availability', 'performance', 'downtime'],
            'data': ['data', 'information', 'privacy', 'customer', 'personal'],
            'compliance': ['compliance', 'regulatory', 'audit', 'legal'],
            'reputation': ['public', 'customer', 'brand', 'reputation', 'trust']
        }
        
        impact_scores = {category: 0 for category in impact_keywords.keys()}
        
        for finding in findings:
            finding_text = (finding.title + ' ' + finding.description).lower()
            for category, keywords in impact_keywords.items():
                if any(keyword in finding_text for keyword in keywords):
                    # Weight by severity
                    if finding.severity == SeverityLevel.CRITICAL:
                        impact_scores[category] += 3
                    elif finding.severity == SeverityLevel.HIGH:
                        impact_scores[category] += 2
                    else:
                        impact_scores[category] += 1
        
        # Convert scores to impact levels
        def score_to_impact(score: int) -> str:
            if score >= 6:
                return "critical"
            elif score >= 4:
                return "high"
            elif score >= 2:
                return "medium"
            else:
                return "low"
        
        return BusinessImpactAnalysis(
            financial_impact=score_to_impact(impact_scores['financial']),
            operational_impact=score_to_impact(impact_scores['operational']),
            reputational_impact=score_to_impact(impact_scores['reputation']),
            regulatory_impact=score_to_impact(impact_scores['compliance']),
            customer_impact=score_to_impact(impact_scores['data']),
            impact_description=self._generate_impact_description(findings, impact_scores),
            recovery_time_objective=self._estimate_rto(findings),
            recovery_point_objective=self._estimate_rpo(findings)
        )
    
    def _generate_impact_description(self, findings: List[TechnicalFinding], 
                                   impact_scores: Dict[str, int]) -> str:
        """Generate comprehensive impact description."""
        description_parts = []
        
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        
        if critical_count > 0:
            description_parts.append(f"{critical_count} critical vulnerabilities pose immediate threat to business operations")
        
        # Identify primary impact areas
        sorted_impacts = sorted(impact_scores.items(), key=lambda x: x[1], reverse=True)
        primary_impacts = [impact for impact, score in sorted_impacts[:2] if score > 0]
        
        if primary_impacts:
            impact_str = " and ".join(primary_impacts)
            description_parts.append(f"Primary business impact areas include {impact_str}")
        
        if not description_parts:
            description_parts.append("Identified vulnerabilities present manageable business risk")
        
        return ". ".join(description_parts) + "."
    
    def _estimate_rto(self, findings: List[TechnicalFinding]) -> str:
        """Estimate Recovery Time Objective."""
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        
        if critical_count >= 3:
            return "< 4 hours"
        elif critical_count >= 1:
            return "< 24 hours"
        else:
            return "< 72 hours"
    
    def _estimate_rpo(self, findings: List[TechnicalFinding]) -> str:
        """Estimate Recovery Point Objective."""
        data_related = sum(
            1 for f in findings 
            if any(keyword in f.description.lower() 
                  for keyword in ['data', 'database', 'storage', 'backup'])
        )
        
        if data_related >= 2:
            return "< 1 hour"
        elif data_related >= 1:
            return "< 4 hours"
        else:
            return "< 24 hours"


# Import required classes at module level
from ..models import ConfidenceLevel