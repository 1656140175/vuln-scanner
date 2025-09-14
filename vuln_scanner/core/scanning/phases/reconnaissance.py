"""Reconnaissance phase implementation."""

import re
import asyncio
import subprocess
from typing import Dict, Any, List, Set
from urllib.parse import urlparse

from .base import BasePhase, PhaseExecutionError
from ..data_structures import ScanPhase, ScanTarget, ScanSeverity
from ...tools.manager import ToolManager


class ReconnaissancePhase(BasePhase):
    """Phase 1: Deep reconnaissance - subdomain discovery, tech stack identification."""
    
    @property
    def phase(self) -> ScanPhase:
        return ScanPhase.RECONNAISSANCE
    
    def validate_inputs(self, inputs: Dict[str, Any]) -> None:
        """Validate reconnaissance phase inputs.
        
        Args:
            inputs: Input data to validate
            
        Raises:
            PhaseExecutionError: If inputs are invalid
        """
        if 'target' not in inputs:
            raise PhaseExecutionError("Missing required input: target")
        
        target = inputs['target']
        self.validate_target(target)
        
        # Validate target format (domain or URL)
        if not self._is_valid_domain_or_url(target):
            raise PhaseExecutionError(f"Invalid target format: {target}")
    
    async def execute_phase_logic(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Execute reconnaissance phase logic.
        
        Args:
            inputs: Input data for the phase
            
        Returns:
            Reconnaissance results
        """
        target = inputs['target']
        target_domain = self._extract_domain(target)
        
        self.logger.info(f"Starting reconnaissance for target: {target}")
        
        # Parallel reconnaissance tasks
        tasks = [
            self.enumerate_subdomains(target_domain),
            self.identify_technologies(target),
            self.gather_osint_data(target_domain),
            self.collect_ip_ranges(target_domain)
        ]
        
        results = await self.run_parallel_tasks(tasks)
        successful_results = self.filter_successful_results(results)
        
        if len(successful_results) < 2:  # Require at least 2 successful tasks
            raise PhaseExecutionError("Insufficient successful reconnaissance tasks")
        
        # Combine results
        subdomains = successful_results[0] if len(successful_results) > 0 else set()
        tech_stack = successful_results[1] if len(successful_results) > 1 else {}
        osint_data = successful_results[2] if len(successful_results) > 2 else {}
        ip_ranges = successful_results[3] if len(successful_results) > 3 else set()
        
        # Additional processing
        all_targets = self._combine_targets(target, subdomains)
        
        return {
            'target_domain': target_domain,
            'original_target': target,
            'subdomains': list(subdomains),
            'all_targets': list(all_targets),
            'tech_stack': tech_stack,
            'osint_data': osint_data,
            'ip_ranges': list(ip_ranges),
            'items_processed': len(all_targets),
            'success_rate': len(successful_results) / len(tasks)
        }
    
    def prepare_next_phase_inputs(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare inputs for discovery phase.
        
        Args:
            results: Reconnaissance phase results
            
        Returns:
            Input data for discovery phase
        """
        return {
            'targets': results['all_targets'],
            'primary_domain': results['target_domain'],
            'tech_stack': results['tech_stack'],
            'ip_ranges': results['ip_ranges']
        }
    
    async def enumerate_subdomains(self, domain: str) -> Set[str]:
        """Enumerate subdomains using multiple tools.
        
        Args:
            domain: Domain to enumerate
            
        Returns:
            Set of discovered subdomains
        """
        self.logger.info(f"Enumerating subdomains for: {domain}")
        subdomains = set()
        
        try:
            # Use subfinder if available
            subfinder_results = await self._run_subfinder(domain)
            subdomains.update(subfinder_results)
            
            # Use amass if available  
            amass_results = await self._run_amass(domain)
            subdomains.update(amass_results)
            
            # DNS bruteforce with common names
            brute_results = await self._dns_bruteforce(domain)
            subdomains.update(brute_results)
            
        except Exception as e:
            self.logger.error(f"Subdomain enumeration error: {e}")
        
        self.logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        return subdomains
    
    async def identify_technologies(self, target: str) -> Dict[str, Any]:
        """Identify technologies using httpx and other tools.
        
        Args:
            target: Target URL or domain
            
        Returns:
            Technology stack information
        """
        self.logger.info(f"Identifying technologies for: {target}")
        tech_info = {
            'web_technologies': [],
            'server_headers': {},
            'cms': None,
            'frameworks': [],
            'javascript_libraries': []
        }
        
        try:
            # Use httpx for web technology detection
            httpx_results = await self._run_httpx(target)
            if httpx_results:
                tech_info.update(httpx_results)
            
            # Additional technology fingerprinting
            fingerprint_results = await self._fingerprint_technologies(target)
            tech_info.update(fingerprint_results)
            
        except Exception as e:
            self.logger.error(f"Technology identification error: {e}")
        
        return tech_info
    
    async def gather_osint_data(self, domain: str) -> Dict[str, Any]:
        """Gather OSINT data about the target.
        
        Args:
            domain: Target domain
            
        Returns:
            OSINT information
        """
        self.logger.info(f"Gathering OSINT data for: {domain}")
        osint_data = {
            'whois_info': {},
            'certificate_info': {},
            'social_media': [],
            'email_addresses': [],
            'organization_info': {}
        }
        
        try:
            # WHOIS lookup
            whois_info = await self._whois_lookup(domain)
            osint_data['whois_info'] = whois_info
            
            # SSL Certificate information
            cert_info = await self._get_certificate_info(domain)
            osint_data['certificate_info'] = cert_info
            
            # Search for email addresses and social media
            contact_info = await self._search_contact_info(domain)
            osint_data.update(contact_info)
            
        except Exception as e:
            self.logger.error(f"OSINT gathering error: {e}")
        
        return osint_data
    
    async def collect_ip_ranges(self, domain: str) -> Set[str]:
        """Collect IP ranges associated with the domain.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of IP ranges
        """
        self.logger.info(f"Collecting IP ranges for: {domain}")
        ip_ranges = set()
        
        try:
            # DNS resolution to get IPs
            ips = await self._resolve_domain_ips(domain)
            
            # ASN lookup for IP ranges
            for ip in ips:
                asn_info = await self._asn_lookup(ip)
                if asn_info and 'cidr' in asn_info:
                    ip_ranges.add(asn_info['cidr'])
            
        except Exception as e:
            self.logger.error(f"IP range collection error: {e}")
        
        return ip_ranges
    
    # Helper methods
    def _is_valid_domain_or_url(self, target: str) -> bool:
        """Check if target is a valid domain or URL."""
        # Simple validation - could be enhanced
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        
        # Check if it's a URL
        try:
            parsed = urlparse(target)
            if parsed.scheme and parsed.netloc:
                return True
        except:
            pass
        
        # Check if it's a domain
        return bool(domain_pattern.match(target))
    
    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or return domain as-is."""
        try:
            parsed = urlparse(target)
            if parsed.netloc:
                return parsed.netloc
        except:
            pass
        return target
    
    def _combine_targets(self, original_target: str, subdomains: Set[str]) -> Set[str]:
        """Combine original target with discovered subdomains."""
        all_targets = {original_target}
        all_targets.update(subdomains)
        return all_targets
    
    async def _run_subfinder(self, domain: str) -> Set[str]:
        """Run subfinder tool for subdomain enumeration."""
        try:
            cmd = ['subfinder', '-d', domain, '-silent']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = set()
                for line in stdout.decode().strip().split('\n'):
                    if line.strip():
                        subdomains.add(line.strip())
                return subdomains
        except FileNotFoundError:
            self.logger.warning("subfinder tool not found")
        except Exception as e:
            self.logger.error(f"subfinder execution error: {e}")
        
        return set()
    
    async def _run_amass(self, domain: str) -> Set[str]:
        """Run amass tool for subdomain enumeration."""
        try:
            cmd = ['amass', 'enum', '-d', domain, '-o', '/dev/stdout']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = set()
                for line in stdout.decode().strip().split('\n'):
                    if line.strip():
                        subdomains.add(line.strip())
                return subdomains
        except FileNotFoundError:
            self.logger.warning("amass tool not found")
        except Exception as e:
            self.logger.error(f"amass execution error: {e}")
        
        return set()
    
    async def _dns_bruteforce(self, domain: str) -> Set[str]:
        """Basic DNS bruteforce for common subdomains."""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'app', 'blog', 'shop', 'secure', 'portal', 'vpn'
        ]
        
        subdomains = set()
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                # Simple DNS resolution check
                import socket
                socket.gethostbyname(full_domain)
                subdomains.add(full_domain)
            except socket.gaierror:
                pass  # Domain doesn't resolve
            except Exception:
                pass
        
        return subdomains
    
    async def _run_httpx(self, target: str) -> Dict[str, Any]:
        """Run httpx for web technology identification."""
        tech_info = {}
        try:
            cmd = ['httpx', '-u', target, '-tech-detect', '-json', '-silent']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                import json
                for line in stdout.decode().strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'tech' in data:
                                tech_info['web_technologies'] = data['tech']
                            if 'webserver' in data:
                                tech_info['server_headers'] = {'server': data['webserver']}
                        except json.JSONDecodeError:
                            pass
        except FileNotFoundError:
            self.logger.warning("httpx tool not found")
        except Exception as e:
            self.logger.error(f"httpx execution error: {e}")
        
        return tech_info
    
    async def _fingerprint_technologies(self, target: str) -> Dict[str, Any]:
        """Additional technology fingerprinting."""
        # Placeholder for additional tech fingerprinting
        # Could integrate with tools like Wappalyzer, whatweb, etc.
        return {
            'additional_tech': []
        }
    
    async def _whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup."""
        whois_info = {}
        try:
            cmd = ['whois', domain]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                whois_data = stdout.decode()
                whois_info['raw_data'] = whois_data
                # Parse key information
                whois_info['parsed'] = self._parse_whois_data(whois_data)
        except FileNotFoundError:
            self.logger.warning("whois tool not found")
        except Exception as e:
            self.logger.error(f"whois lookup error: {e}")
        
        return whois_info
    
    def _parse_whois_data(self, whois_data: str) -> Dict[str, Any]:
        """Parse WHOIS data for key information."""
        parsed = {}
        lines = whois_data.split('\n')
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key in ['registrar', 'organization', 'creation date', 'expiry date']:
                    parsed[key.replace(' ', '_')] = value
        
        return parsed
    
    async def _get_certificate_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate information."""
        cert_info = {}
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
        except Exception as e:
            self.logger.error(f"Certificate info error: {e}")
        
        return cert_info
    
    async def _search_contact_info(self, domain: str) -> Dict[str, Any]:
        """Search for contact information and social media."""
        # Placeholder for contact info search
        # Could integrate with tools like theHarvester
        return {
            'email_addresses': [],
            'social_media': []
        }
    
    async def _resolve_domain_ips(self, domain: str) -> Set[str]:
        """Resolve domain to IP addresses."""
        ips = set()
        try:
            import socket
            # Get IPv4 addresses
            result = socket.getaddrinfo(domain, None, socket.AF_INET)
            for item in result:
                ip = item[4][0]
                ips.add(ip)
        except Exception as e:
            self.logger.error(f"DNS resolution error: {e}")
        
        return ips
    
    async def _asn_lookup(self, ip: str) -> Dict[str, Any]:
        """Perform ASN lookup for IP address."""
        # Placeholder for ASN lookup
        # Could integrate with whois or specialized ASN tools
        return {}