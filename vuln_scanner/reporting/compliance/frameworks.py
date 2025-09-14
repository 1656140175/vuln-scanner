"""Compliance framework implementation classes."""

import logging
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field

from ..models import TechnicalFinding, ComplianceFramework


@dataclass
class FrameworkMapping:
    """Framework mapping results."""
    framework: ComplianceFramework
    mappings: Dict[str, List[str]] = field(default_factory=dict)  # finding_id -> categories
    coverage: Dict[str, int] = field(default_factory=dict)  # category -> finding_count
    unmapped_findings: List[str] = field(default_factory=list)  # finding_ids with no mapping
    
    def add_mapping(self, finding_id: str, categories: List[str]) -> None:
        """Add mapping for a finding."""
        self.mappings[finding_id] = categories
        
        for category in categories:
            self.coverage[category] = self.coverage.get(category, 0) + 1


class BaseFrameworkMapper(ABC):
    """Base class for compliance framework mappers."""
    
    def __init__(self):
        self.logger = logging.getLogger(f'{self.__class__.__name__.lower()}')
    
    @abstractmethod
    async def map_findings(self, findings: List[TechnicalFinding]) -> FrameworkMapping:
        """Map findings to framework categories."""
        pass
    
    @abstractmethod
    def get_categories(self) -> List[str]:
        """Get list of framework categories."""
        pass
    
    def get_full_name(self) -> str:
        """Get full framework name."""
        return self.__class__.__name__.replace('Mapper', '')
    
    def get_description(self) -> str:
        """Get framework description."""
        return f"Compliance mapping for {self.get_full_name()}"
    
    def get_version(self) -> str:
        """Get framework version."""
        return "Latest"


class OWASPTop10Mapper(BaseFrameworkMapper):
    """OWASP Top 10 compliance mapper."""
    
    def __init__(self):
        super().__init__()
        
        # OWASP Top 10 2021 categories
        self.owasp_categories = {
            "A01_2021": "Broken Access Control",
            "A02_2021": "Cryptographic Failures",
            "A03_2021": "Injection",
            "A04_2021": "Insecure Design",
            "A05_2021": "Security Misconfiguration",
            "A06_2021": "Vulnerable and Outdated Components",
            "A07_2021": "Identification and Authentication Failures",
            "A08_2021": "Software and Data Integrity Failures",
            "A09_2021": "Security Logging and Monitoring Failures",
            "A10_2021": "Server-Side Request Forgery"
        }
        
        # Keyword mappings for automatic categorization
        self.keyword_mappings = {
            "A01_2021": [
                "access control", "authorization", "privilege escalation", "path traversal",
                "directory traversal", "insecure direct object reference", "idor", "broken access"
            ],
            "A02_2021": [
                "encryption", "cryptographic", "weak cipher", "ssl", "tls", "certificate",
                "hash", "md5", "des", "weak crypto", "insecure transmission"
            ],
            "A03_2021": [
                "sql injection", "sqli", "command injection", "ldap injection", "xpath injection",
                "code injection", "script injection", "injection"
            ],
            "A04_2021": [
                "insecure design", "threat modeling", "design flaw", "architecture",
                "secure design pattern"
            ],
            "A05_2021": [
                "misconfiguration", "default configuration", "unnecessary features",
                "error messages", "security headers", "cloud misconfiguration"
            ],
            "A06_2021": [
                "outdated component", "vulnerable library", "dependency", "third party",
                "known vulnerability", "cve", "library vulnerability"
            ],
            "A07_2021": [
                "authentication", "session management", "password", "credential",
                "brute force", "session fixation", "weak password", "login"
            ],
            "A08_2021": [
                "software integrity", "data integrity", "deserialization", "insecure deserialization",
                "code signing", "update mechanism"
            ],
            "A09_2021": [
                "logging", "monitoring", "audit", "log injection", "insufficient logging",
                "security monitoring"
            ],
            "A10_2021": [
                "ssrf", "server-side request forgery", "url validation", "internal resource"
            ]
        }
    
    async def map_findings(self, findings: List[TechnicalFinding]) -> FrameworkMapping:
        """Map findings to OWASP Top 10 categories."""
        mapping = FrameworkMapping(framework=ComplianceFramework.OWASP_TOP10)
        
        for finding in findings:
            categories = await self._categorize_finding(finding)
            if categories:
                mapping.add_mapping(finding.finding_id, categories)
            else:
                mapping.unmapped_findings.append(finding.finding_id)
        
        self.logger.info(f"Mapped {len(mapping.mappings)} findings to OWASP Top 10")
        return mapping
    
    async def _categorize_finding(self, finding: TechnicalFinding) -> List[str]:
        """Categorize a single finding."""
        categories = []
        finding_text = (finding.title + ' ' + finding.description).lower()
        
        # Check each OWASP category
        for category_id, keywords in self.keyword_mappings.items():
            if any(keyword in finding_text for keyword in keywords):
                category_name = self.owasp_categories[category_id]
                categories.append(f"{category_id}: {category_name}")
        
        # Additional CWE-based mapping if available
        if finding.cwe_references:
            cwe_mappings = self._map_cwe_to_owasp(finding.cwe_references)
            categories.extend(cwe_mappings)
        
        return list(set(categories))  # Remove duplicates
    
    def _map_cwe_to_owasp(self, cwe_references: List[str]) -> List[str]:
        """Map CWE references to OWASP categories."""
        cwe_owasp_mapping = {
            # A01 - Broken Access Control
            "CWE-22": "A01_2021: Broken Access Control",  # Path Traversal
            "CWE-79": "A01_2021: Broken Access Control",  # Improper Access Control
            "CWE-200": "A01_2021: Broken Access Control", # Information Exposure
            "CWE-284": "A01_2021: Broken Access Control", # Improper Access Control
            
            # A02 - Cryptographic Failures
            "CWE-295": "A02_2021: Cryptographic Failures", # Certificate Validation
            "CWE-327": "A02_2021: Cryptographic Failures", # Weak Crypto
            "CWE-328": "A02_2021: Cryptographic Failures", # Reversible One-Way Hash
            
            # A03 - Injection
            "CWE-89": "A03_2021: Injection",   # SQL Injection
            "CWE-77": "A03_2021: Injection",   # Command Injection
            "CWE-79": "A03_2021: Injection",   # XSS
            "CWE-94": "A03_2021: Injection",   # Code Injection
            
            # A07 - Authentication Failures
            "CWE-287": "A07_2021: Identification and Authentication Failures",
            "CWE-288": "A07_2021: Identification and Authentication Failures",
            "CWE-384": "A07_2021: Identification and Authentication Failures",
        }
        
        mapped_categories = []
        for cwe in cwe_references:
            # Extract CWE number
            cwe_match = re.search(r'CWE[_-]?(\d+)', cwe.upper())
            if cwe_match:
                cwe_id = f"CWE-{cwe_match.group(1)}"
                if cwe_id in cwe_owasp_mapping:
                    mapped_categories.append(cwe_owasp_mapping[cwe_id])
        
        return mapped_categories
    
    def get_categories(self) -> List[str]:
        """Get OWASP Top 10 categories."""
        return [f"{k}: {v}" for k, v in self.owasp_categories.items()]
    
    def get_full_name(self) -> str:
        return "OWASP Top 10"
    
    def get_version(self) -> str:
        return "2021"


class CWEMapper(BaseFrameworkMapper):
    """Common Weakness Enumeration (CWE) mapper."""
    
    def __init__(self):
        super().__init__()
        
        # Common CWE categories
        self.cwe_categories = {
            "CWE-22": "Path Traversal",
            "CWE-79": "Cross-site Scripting",
            "CWE-89": "SQL Injection",
            "CWE-94": "Code Injection", 
            "CWE-200": "Information Exposure",
            "CWE-287": "Improper Authentication",
            "CWE-295": "Improper Certificate Validation",
            "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
            "CWE-352": "Cross-Site Request Forgery",
            "CWE-434": "Unrestricted Upload of File",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-611": "XML External Entity Reference",
            "CWE-798": "Use of Hard-coded Credentials"
        }
    
    async def map_findings(self, findings: List[TechnicalFinding]) -> FrameworkMapping:
        """Map findings to CWE categories."""
        mapping = FrameworkMapping(framework=ComplianceFramework.CWE)
        
        for finding in findings:
            categories = await self._extract_cwe_categories(finding)
            if categories:
                mapping.add_mapping(finding.finding_id, categories)
            else:
                mapping.unmapped_findings.append(finding.finding_id)
        
        return mapping
    
    async def _extract_cwe_categories(self, finding: TechnicalFinding) -> List[str]:
        """Extract CWE categories from finding."""
        categories = []
        
        # Direct CWE references
        if finding.cwe_references:
            for cwe_ref in finding.cwe_references:
                cwe_match = re.search(r'CWE[_-]?(\d+)', cwe_ref.upper())
                if cwe_match:
                    cwe_id = f"CWE-{cwe_match.group(1)}"
                    cwe_name = self.cwe_categories.get(cwe_id, f"Unknown CWE {cwe_id}")
                    categories.append(f"{cwe_id}: {cwe_name}")
        
        # Infer CWE from finding content
        finding_text = (finding.title + ' ' + finding.description).lower()
        
        cwe_patterns = {
            "CWE-22": ["path traversal", "directory traversal", "../", "..\\"],
            "CWE-79": ["xss", "cross-site scripting", "script injection"],
            "CWE-89": ["sql injection", "sqli"],
            "CWE-94": ["code injection", "remote code execution"],
            "CWE-200": ["information disclosure", "information exposure"],
            "CWE-287": ["authentication bypass", "login bypass"],
            "CWE-327": ["weak encryption", "broken crypto", "md5", "des"],
            "CWE-352": ["csrf", "cross-site request forgery"],
            "CWE-502": ["deserialization", "pickle", "unserialize"]
        }
        
        for cwe_id, patterns in cwe_patterns.items():
            if any(pattern in finding_text for pattern in patterns):
                cwe_name = self.cwe_categories.get(cwe_id, f"CWE {cwe_id}")
                category = f"{cwe_id}: {cwe_name}"
                if category not in categories:
                    categories.append(category)
        
        return categories
    
    def get_categories(self) -> List[str]:
        """Get CWE categories."""
        return [f"{k}: {v}" for k, v in self.cwe_categories.items()]
    
    def get_full_name(self) -> str:
        return "Common Weakness Enumeration"
    
    def get_version(self) -> str:
        return "4.8"


class NISTMapper(BaseFrameworkMapper):
    """NIST Cybersecurity Framework mapper."""
    
    def __init__(self):
        super().__init__()
        
        # NIST CSF categories
        self.nist_categories = {
            "ID.AM": "Asset Management",
            "ID.BE": "Business Environment", 
            "ID.GV": "Governance",
            "ID.RA": "Risk Assessment",
            "ID.RM": "Risk Management Strategy",
            "ID.SC": "Supply Chain Risk Management",
            "PR.AC": "Identity Management and Access Control",
            "PR.AT": "Awareness and Training",
            "PR.DS": "Data Security",
            "PR.IP": "Information Protection Processes and Procedures",
            "PR.MA": "Maintenance",
            "PR.PT": "Protective Technology",
            "DE.AE": "Anomalies and Events",
            "DE.CM": "Security Continuous Monitoring",
            "DE.DP": "Detection Processes",
            "RS.RP": "Response Planning",
            "RS.CO": "Communications",
            "RS.AN": "Analysis",
            "RS.MI": "Mitigation",
            "RS.IM": "Improvements",
            "RC.RP": "Recovery Planning",
            "RC.IM": "Improvements",
            "RC.CO": "Communications"
        }
    
    async def map_findings(self, findings: List[TechnicalFinding]) -> FrameworkMapping:
        """Map findings to NIST CSF categories."""
        mapping = FrameworkMapping(framework=ComplianceFramework.NIST)
        
        for finding in findings:
            categories = await self._categorize_to_nist(finding)
            if categories:
                mapping.add_mapping(finding.finding_id, categories)
            else:
                mapping.unmapped_findings.append(finding.finding_id)
        
        return mapping
    
    async def _categorize_to_nist(self, finding: TechnicalFinding) -> List[str]:
        """Categorize finding to NIST framework."""
        categories = []
        finding_text = (finding.title + ' ' + finding.description).lower()
        
        # Map based on vulnerability type and content
        if any(keyword in finding_text for keyword in ['access control', 'authorization', 'authentication']):
            categories.append("PR.AC: Identity Management and Access Control")
        
        if any(keyword in finding_text for keyword in ['encryption', 'data protection', 'confidentiality']):
            categories.append("PR.DS: Data Security")
        
        if any(keyword in finding_text for keyword in ['configuration', 'hardening', 'security controls']):
            categories.append("PR.PT: Protective Technology")
        
        if any(keyword in finding_text for keyword in ['monitoring', 'logging', 'detection']):
            categories.append("DE.CM: Security Continuous Monitoring")
        
        if any(keyword in finding_text for keyword in ['vulnerability', 'patch', 'update']):
            categories.append("ID.RA: Risk Assessment")
        
        return categories
    
    def get_categories(self) -> List[str]:
        """Get NIST categories."""
        return [f"{k}: {v}" for k, v in self.nist_categories.items()]
    
    def get_full_name(self) -> str:
        return "NIST Cybersecurity Framework"
    
    def get_version(self) -> str:
        return "1.1"


class ISO27001Mapper(BaseFrameworkMapper):
    """ISO 27001 compliance mapper."""
    
    def __init__(self):
        super().__init__()
        
        # ISO 27001:2013 Annex A controls
        self.iso_controls = {
            "A.5": "Information Security Policies",
            "A.6": "Organization of Information Security",
            "A.7": "Human Resource Security", 
            "A.8": "Asset Management",
            "A.9": "Access Control",
            "A.10": "Cryptography",
            "A.11": "Physical and Environmental Security",
            "A.12": "Operations Security",
            "A.13": "Communications Security",
            "A.14": "System Acquisition, Development and Maintenance",
            "A.15": "Supplier Relationships",
            "A.16": "Information Security Incident Management",
            "A.17": "Information Security Aspects of Business Continuity Management",
            "A.18": "Compliance"
        }
    
    async def map_findings(self, findings: List[TechnicalFinding]) -> FrameworkMapping:
        """Map findings to ISO 27001 controls."""
        mapping = FrameworkMapping(framework=ComplianceFramework.ISO27001)
        
        for finding in findings:
            categories = await self._map_to_iso_controls(finding)
            if categories:
                mapping.add_mapping(finding.finding_id, categories)
            else:
                mapping.unmapped_findings.append(finding.finding_id)
        
        return mapping
    
    async def _map_to_iso_controls(self, finding: TechnicalFinding) -> List[str]:
        """Map finding to ISO 27001 controls."""
        categories = []
        finding_text = (finding.title + ' ' + finding.description).lower()
        
        # Control mapping based on content
        control_keywords = {
            "A.9": ["access control", "authorization", "authentication", "privilege"],
            "A.10": ["encryption", "cryptography", "cipher", "key management"],
            "A.12": ["configuration", "patch", "vulnerability", "malware"],
            "A.13": ["network security", "transmission", "communication"],
            "A.14": ["secure development", "code review", "testing"],
            "A.16": ["incident", "security event", "breach"],
            "A.18": ["compliance", "audit", "regulatory"]
        }
        
        for control, keywords in control_keywords.items():
            if any(keyword in finding_text for keyword in keywords):
                control_name = self.iso_controls[control]
                categories.append(f"{control}: {control_name}")
        
        return categories
    
    def get_categories(self) -> List[str]:
        """Get ISO 27001 controls."""
        return [f"{k}: {v}" for k, v in self.iso_controls.items()]
    
    def get_full_name(self) -> str:
        return "ISO/IEC 27001:2013"


class PCIDSSMapper(BaseFrameworkMapper):
    """PCI DSS compliance mapper."""
    
    def __init__(self):
        super().__init__()
        
        # PCI DSS requirements
        self.pci_requirements = {
            "1": "Install and maintain a firewall configuration",
            "2": "Do not use vendor-supplied defaults for system passwords",
            "3": "Protect stored cardholder data",
            "4": "Encrypt transmission of cardholder data across networks",
            "6": "Develop and maintain secure systems and applications",
            "7": "Restrict access to cardholder data by business need-to-know",
            "8": "Identify and authenticate access to system components",
            "9": "Restrict physical access to cardholder data",
            "10": "Track and monitor all access to network resources",
            "11": "Regularly test security systems and processes",
            "12": "Maintain a policy that addresses information security"
        }
    
    async def map_findings(self, findings: List[TechnicalFinding]) -> FrameworkMapping:
        """Map findings to PCI DSS requirements."""
        mapping = FrameworkMapping(framework=ComplianceFramework.PCI_DSS)
        
        for finding in findings:
            categories = await self._map_to_pci_requirements(finding)
            if categories:
                mapping.add_mapping(finding.finding_id, categories)
            else:
                mapping.unmapped_findings.append(finding.finding_id)
        
        return mapping
    
    async def _map_to_pci_requirements(self, finding: TechnicalFinding) -> List[str]:
        """Map finding to PCI DSS requirements."""
        categories = []
        finding_text = (finding.title + ' ' + finding.description).lower()
        
        # PCI requirement mapping
        requirement_keywords = {
            "2": ["default password", "default credential", "vendor default"],
            "3": ["data storage", "encryption", "cardholder data"],
            "4": ["transmission", "ssl", "tls", "encryption in transit"],
            "6": ["vulnerability", "patch", "secure coding", "code injection"],
            "7": ["access control", "authorization", "need-to-know"],
            "8": ["authentication", "password", "credential", "user id"],
            "10": ["logging", "monitoring", "audit trail", "access log"],
            "11": ["vulnerability scan", "penetration test", "security test"]
        }
        
        for requirement, keywords in requirement_keywords.items():
            if any(keyword in finding_text for keyword in keywords):
                req_name = self.pci_requirements[requirement]
                categories.append(f"Requirement {requirement}: {req_name}")
        
        return categories
    
    def get_categories(self) -> List[str]:
        """Get PCI DSS requirements."""
        return [f"Requirement {k}: {v}" for k, v in self.pci_requirements.items()]
    
    def get_full_name(self) -> str:
        return "Payment Card Industry Data Security Standard"
    
    def get_version(self) -> str:
        return "3.2.1"


class GDPRMapper(BaseFrameworkMapper):
    """GDPR compliance mapper."""
    
    def __init__(self):
        super().__init__()
        
        # GDPR articles and principles
        self.gdpr_principles = {
            "Article 5": "Principles of processing personal data",
            "Article 6": "Lawfulness of processing",
            "Article 25": "Data protection by design and by default",
            "Article 32": "Security of processing",
            "Article 33": "Notification of data breach",
            "Article 34": "Communication of data breach to data subject",
            "Article 35": "Data protection impact assessment"
        }
    
    async def map_findings(self, findings: List[TechnicalFinding]) -> FrameworkMapping:
        """Map findings to GDPR articles."""
        mapping = FrameworkMapping(framework=ComplianceFramework.GDPR)
        
        for finding in findings:
            categories = await self._map_to_gdpr_articles(finding)
            if categories:
                mapping.add_mapping(finding.finding_id, categories)
            else:
                mapping.unmapped_findings.append(finding.finding_id)
        
        return mapping
    
    async def _map_to_gdpr_articles(self, finding: TechnicalFinding) -> List[str]:
        """Map finding to GDPR articles."""
        categories = []
        finding_text = (finding.title + ' ' + finding.description).lower()
        
        # GDPR article mapping
        article_keywords = {
            "Article 5": ["data minimization", "purpose limitation", "accuracy"],
            "Article 25": ["privacy by design", "data protection by design", "default settings"],
            "Article 32": ["security", "encryption", "pseudonymisation", "confidentiality", "integrity"],
            "Article 33": ["data breach", "breach notification", "supervisory authority"],
            "Article 34": ["data subject notification", "high risk breach"],
            "Article 35": ["data protection impact", "high risk processing"]
        }
        
        for article, keywords in article_keywords.items():
            if any(keyword in finding_text for keyword in keywords):
                article_name = self.gdpr_principles[article]
                categories.append(f"{article}: {article_name}")
        
        # Check for data-related vulnerabilities
        data_keywords = ["personal data", "data processing", "privacy", "data subject"]
        if any(keyword in finding_text for keyword in data_keywords):
            if "Article 32: Security of processing" not in categories:
                categories.append("Article 32: Security of processing")
        
        return categories
    
    def get_categories(self) -> List[str]:
        """Get GDPR articles.""" 
        return [f"{k}: {v}" for k, v in self.gdpr_principles.items()]
    
    def get_full_name(self) -> str:
        return "General Data Protection Regulation"