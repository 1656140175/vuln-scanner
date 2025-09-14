"""Main compliance mapping engine."""

import logging
from typing import Dict, List, Any, Optional
from collections import defaultdict

from ..models import TechnicalFinding, ComplianceMapping, ComplianceFramework
from .frameworks import (
    OWASPTop10Mapper, CWEMapper, NISTMapper, ISO27001Mapper,
    PCIDSSMapper, GDPRMapper, FrameworkMapping
)


class ComplianceMappingError(Exception):
    """Compliance mapping error."""
    pass


class ComplianceMapper:
    """Main compliance framework mapping engine."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize compliance mapper.
        
        Args:
            config: System configuration
        """
        self.config = config
        self.logger = logging.getLogger('compliance_mapper')
        
        # Initialize framework mappers
        self.frameworks = {
            ComplianceFramework.OWASP_TOP10: OWASPTop10Mapper(),
            ComplianceFramework.CWE: CWEMapper(),
            ComplianceFramework.NIST: NISTMapper(),
            ComplianceFramework.ISO27001: ISO27001Mapper(),
            ComplianceFramework.PCI_DSS: PCIDSSMapper(),
            ComplianceFramework.GDPR: GDPRMapper()
        }
        
        self.logger.info(f"Compliance mapper initialized with {len(self.frameworks)} frameworks")
    
    async def map_findings_to_compliance(self, findings: List[TechnicalFinding],
                                       framework_names: List[str]) -> ComplianceMapping:
        """Map findings to compliance frameworks.
        
        Args:
            findings: List of technical findings
            framework_names: List of framework names to map to
            
        Returns:
            ComplianceMapping object
        """
        self.logger.info(f"Mapping {len(findings)} findings to {len(framework_names)} frameworks")
        
        try:
            # Convert framework names to enums
            frameworks = []
            for name in framework_names:
                try:
                    framework = ComplianceFramework(name.lower())
                    frameworks.append(framework)
                except ValueError:
                    self.logger.warning(f"Unknown compliance framework: {name}")
                    continue
            
            if not frameworks:
                self.logger.warning("No valid compliance frameworks specified")
                return ComplianceMapping()
            
            # Initialize compliance mapping
            compliance_mapping = ComplianceMapping()
            
            # Map to each framework
            for framework in frameworks:
                mapper = self.frameworks.get(framework)
                if not mapper:
                    self.logger.warning(f"No mapper available for framework: {framework.value}")
                    continue
                
                try:
                    framework_mapping = await mapper.map_findings(findings)
                    
                    # Store mapping results
                    compliance_mapping.frameworks[framework] = framework_mapping.mappings
                    
                    # Calculate compliance status
                    compliance_status = self._calculate_compliance_status(framework_mapping, findings)
                    compliance_mapping.compliance_status[framework] = compliance_status
                    
                    # Generate gap analysis
                    gap_analysis = await self._generate_gap_analysis(framework, framework_mapping, findings)
                    compliance_mapping.gap_analysis[framework] = gap_analysis
                    
                    # Generate recommendations
                    recommendations = await self._generate_compliance_recommendations(framework, framework_mapping, findings)
                    compliance_mapping.recommendations[framework] = recommendations
                    
                    # Calculate certification readiness
                    readiness_score = self._calculate_certification_readiness(framework_mapping, findings)
                    compliance_mapping.certification_readiness[framework] = readiness_score
                    
                    self.logger.info(f"Successfully mapped to {framework.value} - Status: {compliance_status}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to map to {framework.value}: {e}")
                    continue
            
            return compliance_mapping
            
        except Exception as e:
            self.logger.error(f"Compliance mapping failed: {e}")
            raise ComplianceMappingError(f"Failed to map findings to compliance frameworks: {e}")
    
    def _calculate_compliance_status(self, framework_mapping: FrameworkMapping, 
                                   findings: List[TechnicalFinding]) -> str:
        """Calculate compliance status for a framework.
        
        Args:
            framework_mapping: Framework mapping results
            findings: List of findings
            
        Returns:
            Compliance status string
        """
        if not findings:
            return "compliant"
        
        # Count findings by severity that map to compliance categories
        critical_violations = 0
        high_violations = 0
        total_violations = 0
        
        for finding_id, categories in framework_mapping.mappings.items():
            # Find the corresponding finding
            finding = next((f for f in findings if f.finding_id == finding_id), None)
            if not finding:
                continue
            
            total_violations += 1
            
            if finding.severity.value in ['critical']:
                critical_violations += 1
            elif finding.severity.value in ['high']:
                high_violations += 1
        
        # Determine compliance status
        if critical_violations > 0:
            return "non_compliant"
        elif high_violations >= 3:
            return "non_compliant"
        elif total_violations > 0:
            return "partial"
        else:
            return "compliant"
    
    async def _generate_gap_analysis(self, framework: ComplianceFramework,
                                   framework_mapping: FrameworkMapping,
                                   findings: List[TechnicalFinding]) -> List[str]:
        """Generate gap analysis for compliance framework.
        
        Args:
            framework: Compliance framework
            framework_mapping: Framework mapping results
            findings: List of findings
            
        Returns:
            List of compliance gaps
        """
        gaps = []
        
        # Analyze findings by compliance categories
        category_violations = defaultdict(list)
        
        for finding_id, categories in framework_mapping.mappings.items():
            finding = next((f for f in findings if f.finding_id == finding_id), None)
            if not finding:
                continue
                
            for category in categories:
                category_violations[category].append(finding)
        
        # Generate gap descriptions
        for category, violations in category_violations.items():
            if violations:
                high_severity_count = sum(1 for v in violations if v.severity.value in ['critical', 'high'])
                
                if high_severity_count > 0:
                    gaps.append(f"{category}: {high_severity_count} high-risk violations require immediate attention")
                else:
                    gaps.append(f"{category}: {len(violations)} violations need remediation")
        
        # Framework-specific gap analysis
        mapper = self.frameworks.get(framework)
        if hasattr(mapper, 'identify_gaps'):
            additional_gaps = await mapper.identify_gaps(findings, framework_mapping)
            gaps.extend(additional_gaps)
        
        return gaps
    
    async def _generate_compliance_recommendations(self, framework: ComplianceFramework,
                                                 framework_mapping: FrameworkMapping,
                                                 findings: List[TechnicalFinding]) -> List[str]:
        """Generate compliance-specific recommendations.
        
        Args:
            framework: Compliance framework
            framework_mapping: Framework mapping results
            findings: List of findings
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Get framework-specific recommendations
        mapper = self.frameworks.get(framework)
        if hasattr(mapper, 'generate_recommendations'):
            mapper_recommendations = await mapper.generate_recommendations(findings, framework_mapping)
            recommendations.extend(mapper_recommendations)
        
        # General compliance recommendations based on findings
        critical_findings = [f for f in findings if f.severity.value == 'critical']
        high_findings = [f for f in findings if f.severity.value == 'high']
        
        if critical_findings:
            recommendations.append(f"Immediately address {len(critical_findings)} critical findings to maintain compliance")
        
        if high_findings:
            recommendations.append(f"Prioritize remediation of {len(high_findings)} high-severity findings")
        
        # Framework-specific standard recommendations
        if framework == ComplianceFramework.PCI_DSS:
            if any('payment' in f.description.lower() or 'card' in f.description.lower() for f in findings):
                recommendations.append("Implement additional payment data protection controls")
        
        elif framework == ComplianceFramework.GDPR:
            if any('data' in f.description.lower() or 'privacy' in f.description.lower() for f in findings):
                recommendations.append("Review data processing activities and privacy controls")
        
        elif framework == ComplianceFramework.SOX:
            if any('financial' in f.description.lower() or 'audit' in f.description.lower() for f in findings):
                recommendations.append("Strengthen financial reporting controls and audit trails")
        
        return recommendations
    
    def _calculate_certification_readiness(self, framework_mapping: FrameworkMapping,
                                         findings: List[TechnicalFinding]) -> float:
        """Calculate certification readiness score.
        
        Args:
            framework_mapping: Framework mapping results
            findings: List of findings
            
        Returns:
            Readiness score (0.0 to 100.0)
        """
        if not findings:
            return 100.0
        
        # Calculate penalties for different severity levels
        total_penalty = 0.0
        max_penalty = len(findings) * 10.0  # Maximum 10 points per finding
        
        for finding in findings:
            if finding.severity.value == 'critical':
                total_penalty += 10.0
            elif finding.severity.value == 'high':
                total_penalty += 7.0
            elif finding.severity.value == 'medium':
                total_penalty += 4.0
            elif finding.severity.value == 'low':
                total_penalty += 2.0
            else:  # info
                total_penalty += 0.5
        
        # Calculate readiness as percentage
        readiness_score = max(0.0, (max_penalty - total_penalty) / max_penalty * 100.0)
        
        return round(readiness_score, 1)
    
    def get_framework_info(self, framework_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a compliance framework.
        
        Args:
            framework_name: Name of the framework
            
        Returns:
            Framework information dictionary or None if not found
        """
        try:
            framework = ComplianceFramework(framework_name.lower())
            mapper = self.frameworks.get(framework)
            
            if not mapper:
                return None
            
            return {
                'name': framework.value,
                'full_name': mapper.get_full_name() if hasattr(mapper, 'get_full_name') else framework.value,
                'description': mapper.get_description() if hasattr(mapper, 'get_description') else 'No description available',
                'categories': mapper.get_categories() if hasattr(mapper, 'get_categories') else [],
                'version': mapper.get_version() if hasattr(mapper, 'get_version') else 'Unknown'
            }
        except ValueError:
            return None
    
    def get_supported_frameworks(self) -> List[Dict[str, Any]]:
        """Get list of supported compliance frameworks.
        
        Returns:
            List of framework information dictionaries
        """
        frameworks_info = []
        
        for framework in ComplianceFramework:
            info = self.get_framework_info(framework.value)
            if info:
                frameworks_info.append(info)
        
        return frameworks_info