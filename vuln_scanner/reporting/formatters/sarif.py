"""SARIF report formatter for integration with security tools."""

import json
import logging
from datetime import datetime
from typing import Union, Dict, Any, List
from uuid import uuid4

from .base import BaseFormatter, FormatterError
from ..models import VulnerabilityReport, TechnicalFinding, SeverityLevel
from ..config import ReportConfig, ReportFormat
from ..templates import TemplateManager


class SARIFFormatter(BaseFormatter):
    """SARIF (Static Analysis Results Interchange Format) formatter."""
    
    @property
    def supported_format(self) -> ReportFormat:
        return ReportFormat.SARIF
    
    @property
    def output_extension(self) -> str:
        return "sarif"
    
    @property
    def content_type(self) -> str:
        return "application/sarif+json"
    
    async def format_report(self, report: VulnerabilityReport,
                          config: ReportConfig,
                          template_manager: TemplateManager) -> str:
        """Format report as SARIF.
        
        Args:
            report: Vulnerability report data
            config: Report configuration
            template_manager: Template manager instance
            
        Returns:
            SARIF report content
        """
        self.logger.info(f"Formatting SARIF report for {report.target_info.primary_target}")
        
        try:
            # Get SARIF-specific configuration
            sarif_config = config.format_config.sarif
            
            # Build SARIF document
            sarif_document = self._build_sarif_document(report, config, sarif_config)
            
            # Serialize to JSON
            sarif_content = json.dumps(
                sarif_document,
                indent=2,
                ensure_ascii=False,
                default=self._sarif_serializer
            )
            
            self.logger.info(f"Successfully generated SARIF report ({len(sarif_content)} chars)")
            return sarif_content
            
        except Exception as e:
            self.logger.error(f"SARIF formatting failed: {e}")
            raise FormatterError(f"Failed to format SARIF report: {e}")
    
    def _build_sarif_document(self, report: VulnerabilityReport,
                            config: ReportConfig,
                            sarif_config) -> Dict[str, Any]:
        """Build complete SARIF document.
        
        Args:
            report: Vulnerability report
            config: Report configuration
            sarif_config: SARIF-specific configuration
            
        Returns:
            SARIF document dictionary
        """
        # Build main SARIF structure
        sarif_doc = {
            "$schema": sarif_config.schema_uri,
            "version": sarif_config.sarif_version,
            "runs": [
                self._build_sarif_run(report, config, sarif_config)
            ]
        }
        
        return sarif_doc
    
    def _build_sarif_run(self, report: VulnerabilityReport,
                        config: ReportConfig,
                        sarif_config) -> Dict[str, Any]:
        """Build SARIF run object.
        
        Args:
            report: Vulnerability report
            config: Report configuration
            sarif_config: SARIF configuration
            
        Returns:
            SARIF run dictionary
        """
        run = {
            "tool": self._build_tool_info(sarif_config),
            "invocations": [
                self._build_invocation_info(report)
            ],
            "artifacts": self._build_artifacts(report),
            "results": self._build_results(report.technical_findings, sarif_config),
            "taxonomies": self._build_taxonomies(),
            "properties": {
                "reportId": report.report_id,
                "scanId": report.scan_id,
                "targetInfo": {
                    "primaryTarget": report.target_info.primary_target,
                    "targetType": report.target_info.target_type.value,
                    "environment": report.target_info.environment
                }
            }
        }
        
        # Add column kinds for enhanced display
        run["columnKind"] = "utf16CodeUnits"
        
        return run
    
    def _build_tool_info(self, sarif_config) -> Dict[str, Any]:
        """Build SARIF tool information.
        
        Args:
            sarif_config: SARIF configuration
            
        Returns:
            Tool information dictionary
        """
        return {
            "driver": {
                "name": sarif_config.tool_name,
                "version": sarif_config.tool_version,
                "informationUri": "https://github.com/vulnminer/vulnminer",
                "organization": "VulnMiner Security",
                "product": "VulnMiner Vulnerability Scanner",
                "shortDescription": {
                    "text": "Comprehensive vulnerability scanning and assessment tool"
                },
                "fullDescription": {
                    "text": "VulnMiner is a comprehensive five-phase vulnerability scanning system that performs reconnaissance, discovery, scanning, verification, and reporting of security vulnerabilities."
                },
                "semanticVersion": sarif_config.tool_version,
                "rules": self._build_sarif_rules(),
                "notifications": self._build_notifications(sarif_config)
            }
        }
    
    def _build_sarif_rules(self) -> List[Dict[str, Any]]:
        """Build SARIF rules for different vulnerability types.
        
        Returns:
            List of SARIF rule objects
        """
        rules = []
        
        # Define common vulnerability rules
        vulnerability_rules = [
            {
                "id": "SQL_INJECTION",
                "name": "SQLInjection",
                "shortDescription": {"text": "SQL Injection vulnerability detected"},
                "fullDescription": {"text": "Application is vulnerable to SQL injection attacks which can lead to unauthorized data access, modification, or deletion."},
                "defaultConfiguration": {"level": "error"},
                "help": {"text": "Implement parameterized queries and input validation to prevent SQL injection."},
                "properties": {"tags": ["security", "injection", "database"]}
            },
            {
                "id": "XSS",
                "name": "CrossSiteScripting",
                "shortDescription": {"text": "Cross-Site Scripting vulnerability detected"},
                "fullDescription": {"text": "Application is vulnerable to cross-site scripting attacks which can lead to session hijacking, defacement, or malicious code execution."},
                "defaultConfiguration": {"level": "warning"},
                "help": {"text": "Implement proper input validation and output encoding to prevent XSS."},
                "properties": {"tags": ["security", "xss", "web"]}
            },
            {
                "id": "CSRF",
                "name": "CrossSiteRequestForgery",
                "shortDescription": {"text": "Cross-Site Request Forgery vulnerability detected"},
                "fullDescription": {"text": "Application lacks proper CSRF protection allowing attackers to perform unauthorized actions on behalf of authenticated users."},
                "defaultConfiguration": {"level": "warning"},
                "help": {"text": "Implement CSRF tokens and proper request validation."},
                "properties": {"tags": ["security", "csrf", "web"]}
            },
            {
                "id": "WEAK_CRYPTO",
                "name": "WeakCryptography",
                "shortDescription": {"text": "Weak cryptographic implementation detected"},
                "fullDescription": {"text": "Application uses weak or deprecated cryptographic algorithms that may be vulnerable to attacks."},
                "defaultConfiguration": {"level": "warning"},
                "help": {"text": "Use strong, up-to-date cryptographic algorithms and proper key management."},
                "properties": {"tags": ["security", "cryptography"]}
            },
            {
                "id": "INFO_DISCLOSURE",
                "name": "InformationDisclosure",
                "shortDescription": {"text": "Information disclosure vulnerability detected"},
                "fullDescription": {"text": "Application reveals sensitive information that could aid attackers in further exploitation."},
                "defaultConfiguration": {"level": "note"},
                "help": {"text": "Remove or properly protect sensitive information from public exposure."},
                "properties": {"tags": ["security", "information-disclosure"]}
            }
        ]
        
        return vulnerability_rules
    
    def _build_notifications(self, sarif_config) -> List[Dict[str, Any]]:
        """Build SARIF notifications.
        
        Args:
            sarif_config: SARIF configuration
            
        Returns:
            List of notification objects
        """
        return [
            {
                "id": "scan-info",
                "name": "ScanInformation",
                "shortDescription": {"text": "General scan information"},
                "fullDescription": {"text": "Informational messages about the scanning process"},
                "defaultConfiguration": {"level": sarif_config.notification_level}
            }
        ]
    
    def _build_invocation_info(self, report: VulnerabilityReport) -> Dict[str, Any]:
        """Build SARIF invocation information.
        
        Args:
            report: Vulnerability report
            
        Returns:
            Invocation information dictionary
        """
        return {
            "executionSuccessful": True,
            "startTimeUtc": report.scan_metadata.scan_start_time.isoformat(),
            "endTimeUtc": report.scan_metadata.scan_end_time.isoformat(),
            "machine": "scanner-host",
            "account": report.scan_metadata.operator or "unknown",
            "processId": 0,  # Not applicable for our scanner
            "commandLine": f"vulnminer scan --target {report.target_info.primary_target}",
            "environmentVariables": {},
            "toolConfigurationNotifications": [],
            "toolExecutionNotifications": [],
            "exitCode": 0,
            "exitCodeDescription": "Success"
        }
    
    def _build_artifacts(self, report: VulnerabilityReport) -> List[Dict[str, Any]]:
        """Build SARIF artifacts list.
        
        Args:
            report: Vulnerability report
            
        Returns:
            List of artifact objects
        """
        artifacts = []
        
        # Add primary target as artifact
        artifacts.append({
            "location": {
                "uri": report.target_info.primary_target
            },
            "mimeType": "text/html",
            "description": {
                "text": f"Primary scan target: {report.target_info.primary_target}"
            },
            "properties": {
                "targetType": report.target_info.target_type.value,
                "environment": report.target_info.environment
            }
        })
        
        # Add scope targets as artifacts
        for scope_target in report.target_info.scope:
            if scope_target != report.target_info.primary_target:
                artifacts.append({
                    "location": {
                        "uri": scope_target
                    },
                    "description": {
                        "text": f"Scope target: {scope_target}"
                    }
                })
        
        return artifacts
    
    def _build_results(self, findings: List[TechnicalFinding], 
                      sarif_config) -> List[Dict[str, Any]]:
        """Build SARIF results from technical findings.
        
        Args:
            findings: List of technical findings
            sarif_config: SARIF configuration
            
        Returns:
            List of SARIF result objects
        """
        results = []
        
        for finding in findings:
            result = {
                "ruleId": self._get_rule_id_for_finding(finding),
                "ruleIndex": 0,  # Will be updated based on actual rule
                "message": {
                    "text": finding.title,
                    "markdown": f"**{finding.title}**\n\n{finding.description}"
                },
                "level": self._severity_to_sarif_level(finding.severity),
                "locations": self._build_locations_for_finding(finding),
                "partialFingerprints": {
                    "primaryLocationLineHash": self._generate_fingerprint(finding),
                    "findingHash": finding.finding_id
                },
                "baselineState": "new",
                "properties": {
                    "findingId": finding.finding_id,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "cvssScore": finding.cvss_score,
                    "cvssVector": finding.cvss_vector,
                    "cveReferences": finding.cve_references,
                    "cweReferences": finding.cwe_references,
                    "discoveryPhase": finding.discovery_phase,
                    "verificationStatus": finding.verification_status.value,
                    "falsePositiveLikelihood": finding.false_positive_likelihood,
                    "businessImpact": finding.business_impact,
                    "technicalImpact": finding.technical_impact,
                    "exploitComplexity": finding.exploit_complexity
                }
            }
            
            # Add proof of concept if available
            if finding.proof_of_concept and sarif_config.include_fixes:
                result["attachments"] = self._build_poc_attachments(finding.proof_of_concept)
            
            # Add remediation information
            if finding.remediation and sarif_config.include_fixes:
                result["fixes"] = self._build_remediation_fixes(finding.remediation)
            
            # Add code flows if available
            if finding.metadata.get('code_flows'):
                result["codeFlows"] = self._build_code_flows(finding.metadata['code_flows'])
            
            # Add related locations
            if len(finding.affected_urls) > 1:
                result["relatedLocations"] = self._build_related_locations(finding.affected_urls[1:])
            
            results.append(result)
        
        return results
    
    def _get_rule_id_for_finding(self, finding: TechnicalFinding) -> str:
        """Get appropriate rule ID for a finding.
        
        Args:
            finding: Technical finding
            
        Returns:
            Rule ID string
        """
        # Simple mapping based on finding title/description keywords
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        
        if any(keyword in title_lower or keyword in desc_lower for keyword in ['sql injection', 'sqli']):
            return "SQL_INJECTION"
        elif any(keyword in title_lower or keyword in desc_lower for keyword in ['xss', 'cross-site scripting']):
            return "XSS"
        elif any(keyword in title_lower or keyword in desc_lower for keyword in ['csrf', 'cross-site request forgery']):
            return "CSRF"
        elif any(keyword in title_lower or keyword in desc_lower for keyword in ['crypto', 'encryption', 'cipher']):
            return "WEAK_CRYPTO"
        else:
            return "INFO_DISCLOSURE"
    
    def _severity_to_sarif_level(self, severity: SeverityLevel) -> str:
        """Convert severity to SARIF level.
        
        Args:
            severity: Severity level
            
        Returns:
            SARIF level string
        """
        mapping = {
            SeverityLevel.CRITICAL: "error",
            SeverityLevel.HIGH: "error",
            SeverityLevel.MEDIUM: "warning",
            SeverityLevel.LOW: "note",
            SeverityLevel.INFO: "note"
        }
        return mapping.get(severity, "note")
    
    def _build_locations_for_finding(self, finding: TechnicalFinding) -> List[Dict[str, Any]]:
        """Build SARIF locations for a finding.
        
        Args:
            finding: Technical finding
            
        Returns:
            List of location objects
        """
        locations = []
        
        # Use first affected URL as primary location
        if finding.affected_urls:
            primary_url = finding.affected_urls[0]
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": primary_url
                    },
                    "region": {
                        "startLine": 1,
                        "startColumn": 1,
                        "snippet": {
                            "text": f"Vulnerability found at: {primary_url}"
                        }
                    }
                },
                "message": {
                    "text": f"Vulnerability location: {primary_url}"
                }
            })
        else:
            # Fallback location
            locations.append({
                "message": {
                    "text": "Vulnerability location not specified"
                }
            })
        
        return locations
    
    def _build_related_locations(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Build related locations for additional URLs.
        
        Args:
            urls: List of related URLs
            
        Returns:
            List of related location objects
        """
        related_locations = []
        
        for url in urls:
            related_locations.append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": url
                    }
                },
                "message": {
                    "text": f"Related vulnerability instance: {url}"
                }
            })
        
        return related_locations
    
    def _build_poc_attachments(self, poc) -> List[Dict[str, Any]]:
        """Build attachments for proof of concept.
        
        Args:
            poc: Proof of concept object
            
        Returns:
            List of attachment objects
        """
        attachments = []
        
        # Add PoC description as attachment
        attachments.append({
            "description": {
                "text": "Proof of Concept"
            },
            "artifactLocation": {
                "uri": f"data:text/plain;base64,{self._encode_base64(poc.description)}"
            }
        })
        
        # Add code samples
        for language, code in poc.code_samples.items():
            attachments.append({
                "description": {
                    "text": f"Code sample ({language})"
                },
                "artifactLocation": {
                    "uri": f"data:text/{language};base64,{self._encode_base64(code)}"
                }
            })
        
        return attachments
    
    def _build_remediation_fixes(self, remediation) -> List[Dict[str, Any]]:
        """Build SARIF fixes from remediation information.
        
        Args:
            remediation: Remediation object
            
        Returns:
            List of fix objects
        """
        fixes = []
        
        fix = {
            "description": {
                "text": remediation.title,
                "markdown": f"**{remediation.title}**\n\n{remediation.description}"
            },
            "artifactChanges": []
        }
        
        # Add remediation steps as description
        if remediation.remediation_steps:
            steps_text = "\n".join([f"{i+1}. {step}" for i, step in enumerate(remediation.remediation_steps)])
            fix["description"]["markdown"] += f"\n\n**Remediation Steps:**\n{steps_text}"
        
        fixes.append(fix)
        
        return fixes
    
    def _build_code_flows(self, code_flows_data) -> List[Dict[str, Any]]:
        """Build SARIF code flows.
        
        Args:
            code_flows_data: Code flow data
            
        Returns:
            List of code flow objects
        """
        # Placeholder implementation - would need actual code flow data
        return []
    
    def _build_taxonomies(self) -> List[Dict[str, Any]]:
        """Build SARIF taxonomies for vulnerability classification.
        
        Returns:
            List of taxonomy objects
        """
        taxonomies = []
        
        # CWE taxonomy
        cwe_taxonomy = {
            "name": "CWE",
            "version": "4.8",
            "organization": "MITRE",
            "shortDescription": {"text": "Common Weakness Enumeration"},
            "fullDescription": {"text": "A list of software and hardware weakness types"},
            "downloadUri": "https://cwe.mitre.org/data/xml/cwec_v4.8.xml",
            "informationUri": "https://cwe.mitre.org/",
            "isComprehensive": False
        }
        taxonomies.append(cwe_taxonomy)
        
        # OWASP Top 10 taxonomy
        owasp_taxonomy = {
            "name": "OWASP-Top-10",
            "version": "2021",
            "organization": "OWASP",
            "shortDescription": {"text": "OWASP Top 10 - 2021"},
            "fullDescription": {"text": "The OWASP Top 10 is a standard awareness document for developers and web application security."},
            "informationUri": "https://owasp.org/www-project-top-ten/",
            "isComprehensive": False
        }
        taxonomies.append(owasp_taxonomy)
        
        return taxonomies
    
    def _generate_fingerprint(self, finding: TechnicalFinding) -> str:
        """Generate fingerprint for finding deduplication.
        
        Args:
            finding: Technical finding
            
        Returns:
            Fingerprint string
        """
        import hashlib
        
        # Create fingerprint from title and primary URL
        fingerprint_data = f"{finding.title}:{finding.affected_urls[0] if finding.affected_urls else 'no-url'}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()
    
    def _encode_base64(self, text: str) -> str:
        """Encode text to base64.
        
        Args:
            text: Text to encode
            
        Returns:
            Base64 encoded string
        """
        import base64
        return base64.b64encode(text.encode()).decode()
    
    def _sarif_serializer(self, obj):
        """Custom serializer for SARIF JSON.
        
        Args:
            obj: Object to serialize
            
        Returns:
            Serializable representation
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, 'value'):  # Enum objects
            return obj.value
        else:
            return str(obj)