"""Discovery phase implementation."""

import asyncio
import json
import ipaddress
from typing import Dict, Any, List, Set, Tuple
from urllib.parse import urlparse

from .base import BasePhase, PhaseExecutionError
from ..data_structures import ScanPhase, ScanTarget, ScanSeverity, ScanResult
from ...tools.manager import ToolManager


class DiscoveryPhase(BasePhase):
    """Phase 2: Comprehensive discovery - port scanning, service identification."""
    
    @property
    def phase(self) -> ScanPhase:
        return ScanPhase.DISCOVERY
    
    def validate_inputs(self, inputs: Dict[str, Any]) -> None:
        """Validate discovery phase inputs.
        
        Args:
            inputs: Input data to validate
            
        Raises:
            PhaseExecutionError: If inputs are invalid
        """
        if 'targets' not in inputs:
            raise PhaseExecutionError("Missing required input: targets")
        
        targets = inputs['targets']
        if not isinstance(targets, list) or not targets:
            raise PhaseExecutionError("targets must be a non-empty list")
        
        # Validate each target
        for target in targets:
            self.validate_target(target)
    
    async def execute_phase_logic(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Execute discovery phase logic.
        
        Args:
            inputs: Input data for the phase
            
        Returns:
            Discovery results
        """
        targets = inputs['targets']
        primary_domain = inputs.get('primary_domain', '')
        ip_ranges = inputs.get('ip_ranges', [])
        
        self.logger.info(f"Starting discovery for {len(targets)} targets")
        
        # Extract IPs and domains
        ips, domains = self._categorize_targets(targets)
        
        # Add IPs from IP ranges if specified
        if ip_ranges:
            additional_ips = self._expand_ip_ranges(ip_ranges)
            ips.update(additional_ips)
        
        # Parallel discovery tasks
        tasks = [
            self.check_hosts_alive(list(ips.union(domains))),
            self.scan_ports(list(ips.union(domains))),
            self.identify_services(list(ips.union(domains))),
            self.web_fingerprinting(domains)
        ]
        
        results = await self.run_parallel_tasks(tasks)
        successful_results = self.filter_successful_results(results)
        
        if len(successful_results) < 2:  # Require at least 2 successful tasks
            raise PhaseExecutionError("Insufficient successful discovery tasks")
        
        # Combine results
        live_hosts = successful_results[0] if len(successful_results) > 0 else set()
        port_scan_results = successful_results[1] if len(successful_results) > 1 else {}
        service_info = successful_results[2] if len(successful_results) > 2 else {}
        web_services = successful_results[3] if len(successful_results) > 3 else {}
        
        # Process and combine data
        processed_results = self._process_discovery_results(
            live_hosts, port_scan_results, service_info, web_services
        )
        
        return {
            'live_hosts': list(live_hosts),
            'open_ports': port_scan_results,
            'services': service_info,
            'web_services': web_services,
            'processed_targets': processed_results,
            'items_processed': len(live_hosts),
            'success_rate': len(successful_results) / len(tasks)
        }
    
    def prepare_next_phase_inputs(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare inputs for scanning phase.
        
        Args:
            results: Discovery phase results
            
        Returns:
            Input data for scanning phase
        """
        return {
            'live_hosts': results['live_hosts'],
            'services': results['services'],
            'web_services': results['web_services'],
            'processed_targets': results['processed_targets'],
            'open_ports': results['open_ports']
        }
    
    async def check_hosts_alive(self, targets: List[str]) -> Set[str]:
        """Check which hosts are alive using ping and basic connectivity.
        
        Args:
            targets: List of target hosts
            
        Returns:
            Set of live hosts
        """
        self.logger.info(f"Checking {len(targets)} hosts for aliveness")
        live_hosts = set()
        
        # Parallel host alive checks
        tasks = [self._check_single_host_alive(target) for target in targets]
        results = await self.run_parallel_tasks(tasks, max_concurrent=20)
        
        for i, result in enumerate(results):
            if result and not isinstance(result, Exception):
                live_hosts.add(targets[i])
        
        self.logger.info(f"Found {len(live_hosts)} live hosts")
        return live_hosts
    
    async def scan_ports(self, targets: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Scan ports on target hosts using nmap.
        
        Args:
            targets: List of target hosts
            
        Returns:
            Dictionary mapping hosts to open port information
        """
        self.logger.info(f"Scanning ports on {len(targets)} targets")
        port_results = {}
        
        try:
            # Use nmap for port scanning
            nmap_results = await self._run_nmap_scan(targets)
            port_results.update(nmap_results)
            
        except Exception as e:
            self.logger.error(f"Port scanning error: {e}")
        
        total_open_ports = sum(len(ports) for ports in port_results.values())
        self.logger.info(f"Found {total_open_ports} open ports across {len(port_results)} hosts")
        
        return port_results
    
    async def identify_services(self, targets: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Identify services running on discovered ports.
        
        Args:
            targets: List of target hosts
            
        Returns:
            Dictionary mapping hosts to service information
        """
        self.logger.info(f"Identifying services on {len(targets)} targets")
        service_info = {}
        
        try:
            # Use nmap service detection
            service_results = await self._run_service_detection(targets)
            service_info.update(service_results)
            
            # Additional service fingerprinting
            additional_services = await self._additional_service_detection(targets)
            service_info.update(additional_services)
            
        except Exception as e:
            self.logger.error(f"Service identification error: {e}")
        
        total_services = sum(len(services) for services in service_info.values())
        self.logger.info(f"Identified {total_services} services")
        
        return service_info
    
    async def web_fingerprinting(self, domains: Set[str]) -> Dict[str, Dict[str, Any]]:
        """Perform web fingerprinting on discovered web services.
        
        Args:
            domains: Set of domain targets
            
        Returns:
            Dictionary mapping domains to web service information
        """
        self.logger.info(f"Performing web fingerprinting on {len(domains)} domains")
        web_services = {}
        
        # Test both HTTP and HTTPS
        web_targets = []
        for domain in domains:
            web_targets.extend([f"http://{domain}", f"https://{domain}"])
        
        try:
            # Use httpx for web discovery
            httpx_results = await self._run_httpx_discovery(web_targets)
            web_services.update(httpx_results)
            
        except Exception as e:
            self.logger.error(f"Web fingerprinting error: {e}")
        
        self.logger.info(f"Found {len(web_services)} web services")
        return web_services
    
    # Helper methods
    def _categorize_targets(self, targets: List[str]) -> Tuple[Set[str], Set[str]]:
        """Categorize targets into IPs and domains.
        
        Args:
            targets: List of targets
            
        Returns:
            Tuple of (ips, domains)
        """
        ips = set()
        domains = set()
        
        for target in targets:
            # Extract domain/IP from URL if needed
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                target = parsed.netloc
            
            # Check if it's an IP address
            try:
                ipaddress.ip_address(target)
                ips.add(target)
            except ValueError:
                domains.add(target)
        
        return ips, domains
    
    def _expand_ip_ranges(self, ip_ranges: List[str]) -> Set[str]:
        """Expand CIDR ranges to individual IPs.
        
        Args:
            ip_ranges: List of CIDR ranges
            
        Returns:
            Set of individual IP addresses
        """
        expanded_ips = set()
        
        for ip_range in ip_ranges:
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                # Limit to reasonable size to avoid massive scans
                if network.num_addresses <= 1024:
                    for ip in network.hosts():
                        expanded_ips.add(str(ip))
                else:
                    self.logger.warning(f"Skipping large IP range: {ip_range}")
            except ValueError as e:
                self.logger.error(f"Invalid IP range {ip_range}: {e}")
        
        return expanded_ips
    
    def _process_discovery_results(self, live_hosts: Set[str], port_results: Dict, 
                                  service_info: Dict, web_services: Dict) -> List[Dict[str, Any]]:
        """Process and combine discovery results.
        
        Args:
            live_hosts: Set of live hosts
            port_results: Port scan results
            service_info: Service identification results
            web_services: Web service information
            
        Returns:
            List of processed target information
        """
        processed_targets = []
        
        for host in live_hosts:
            target_info = {
                'host': host,
                'open_ports': port_results.get(host, []),
                'services': service_info.get(host, []),
                'web_services': []
            }
            
            # Add web service info
            for protocol in ['http', 'https']:
                web_url = f"{protocol}://{host}"
                if web_url in web_services:
                    target_info['web_services'].append(web_services[web_url])
            
            processed_targets.append(target_info)
        
        return processed_targets
    
    async def _check_single_host_alive(self, target: str) -> bool:
        """Check if a single host is alive.
        
        Args:
            target: Target host
            
        Returns:
            True if host is alive
        """
        try:
            # Try ping first
            if await self._ping_host(target):
                return True
            
            # Try TCP connect to common ports
            common_ports = [80, 443, 22, 21, 25, 53, 110, 143]
            for port in common_ports:
                if await self._tcp_connect_test(target, port):
                    return True
            
        except Exception:
            pass
        
        return False
    
    async def _ping_host(self, target: str) -> bool:
        """Ping a host to check if it's alive.
        
        Args:
            target: Target host
            
        Returns:
            True if ping succeeds
        """
        try:
            cmd = ['ping', '-c', '1', '-W', '2', target]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            returncode = await process.wait()
            return returncode == 0
        except Exception:
            return False
    
    async def _tcp_connect_test(self, host: str, port: int) -> bool:
        """Test TCP connection to a host and port.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            True if connection succeeds
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=3
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    async def _run_nmap_scan(self, targets: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Run nmap port scan.
        
        Args:
            targets: List of target hosts
            
        Returns:
            Port scan results
        """
        port_results = {}
        
        try:
            # Create target list string
            target_str = ' '.join(targets)
            
            # Common ports for faster scanning
            common_ports = "80,443,22,21,25,53,110,143,993,995,8080,8443,3389,5432,3306"
            
            cmd = [
                'nmap', '-sS', '-T4', '--open', '-p', common_ports,
                '--max-retries', '1', '--host-timeout', '30s',
                '-oG', '-', target_str
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                port_results = self._parse_nmap_grepable(stdout.decode())
            else:
                self.logger.warning(f"nmap scan failed: {stderr.decode()}")
                
        except FileNotFoundError:
            self.logger.warning("nmap tool not found, using fallback method")
            # Fallback to manual port testing
            port_results = await self._manual_port_scan(targets)
        except Exception as e:
            self.logger.error(f"nmap scan error: {e}")
        
        return port_results
    
    def _parse_nmap_grepable(self, nmap_output: str) -> Dict[str, List[Dict[str, Any]]]:
        """Parse nmap grepable output.
        
        Args:
            nmap_output: Raw nmap output
            
        Returns:
            Parsed port information
        """
        port_results = {}
        
        for line in nmap_output.split('\n'):
            if line.startswith('Host:') and 'Ports:' in line:
                parts = line.split()
                host = parts[1]
                
                # Find ports section
                ports_idx = line.find('Ports:')
                if ports_idx == -1:
                    continue
                    
                ports_section = line[ports_idx + 6:].split('\t')[0]
                port_list = []
                
                for port_info in ports_section.split(','):
                    port_info = port_info.strip()
                    if '/open/' in port_info:
                        port_parts = port_info.split('/')
                        if len(port_parts) >= 3:
                            port_num = port_parts[0]
                            protocol = port_parts[2]
                            service = port_parts[4] if len(port_parts) > 4 else 'unknown'
                            
                            port_list.append({
                                'port': int(port_num),
                                'protocol': protocol,
                                'service': service,
                                'state': 'open'
                            })
                
                if port_list:
                    port_results[host] = port_list
        
        return port_results
    
    async def _manual_port_scan(self, targets: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Manual port scanning when nmap is not available.
        
        Args:
            targets: List of target hosts
            
        Returns:
            Port scan results
        """
        port_results = {}
        common_ports = [80, 443, 22, 21, 25, 53, 110, 143]
        
        for target in targets:
            open_ports = []
            for port in common_ports:
                if await self._tcp_connect_test(target, port):
                    open_ports.append({
                        'port': port,
                        'protocol': 'tcp',
                        'service': self._guess_service(port),
                        'state': 'open'
                    })
            
            if open_ports:
                port_results[target] = open_ports
        
        return port_results
    
    def _guess_service(self, port: int) -> str:
        """Guess service name based on port number.
        
        Args:
            port: Port number
            
        Returns:
            Service name guess
        """
        common_services = {
            80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp',
            25: 'smtp', 53: 'dns', 110: 'pop3', 143: 'imap',
            993: 'imaps', 995: 'pop3s', 8080: 'http-alt',
            8443: 'https-alt', 3389: 'rdp', 5432: 'postgresql',
            3306: 'mysql'
        }
        return common_services.get(port, 'unknown')
    
    async def _run_service_detection(self, targets: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Run nmap service detection.
        
        Args:
            targets: List of target hosts
            
        Returns:
            Service detection results
        """
        service_results = {}
        
        try:
            target_str = ' '.join(targets)
            cmd = [
                'nmap', '-sV', '--version-intensity', '3',
                '--max-retries', '1', '--host-timeout', '30s',
                '-oX', '-', target_str
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                service_results = self._parse_nmap_xml_services(stdout.decode())
                
        except FileNotFoundError:
            self.logger.warning("nmap not available for service detection")
        except Exception as e:
            self.logger.error(f"Service detection error: {e}")
        
        return service_results
    
    def _parse_nmap_xml_services(self, xml_output: str) -> Dict[str, List[Dict[str, Any]]]:
        """Parse nmap XML output for services.
        
        Args:
            xml_output: Raw nmap XML output
            
        Returns:
            Parsed service information
        """
        # Simplified XML parsing - could use xml.etree.ElementTree for full parsing
        service_results = {}
        
        # Basic pattern matching for service info
        import re
        host_pattern = r'<host.*?<address addr="([^"]+)"'
        port_pattern = r'<port.*?portid="(\d+)".*?protocol="([^"]+)".*?<service name="([^"]*)".*?product="([^"]*)".*?version="([^"]*)"'
        
        hosts = re.findall(host_pattern, xml_output)
        
        for host in hosts:
            host_services = []
            host_section = xml_output[xml_output.find(f'addr="{host}"'):]
            
            ports = re.findall(port_pattern, host_section)
            for port_info in ports:
                port_num, protocol, service_name, product, version = port_info
                host_services.append({
                    'port': int(port_num),
                    'protocol': protocol,
                    'service': service_name or 'unknown',
                    'product': product,
                    'version': version
                })
            
            if host_services:
                service_results[host] = host_services
        
        return service_results
    
    async def _additional_service_detection(self, targets: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Additional service detection methods.
        
        Args:
            targets: List of target hosts
            
        Returns:
            Additional service information
        """
        # Placeholder for additional service detection
        # Could add banner grabbing, specific protocol tests, etc.
        return {}
    
    async def _run_httpx_discovery(self, web_targets: List[str]) -> Dict[str, Dict[str, Any]]:
        """Run httpx for web service discovery.
        
        Args:
            web_targets: List of web targets (URLs)
            
        Returns:
            Web service information
        """
        web_services = {}
        
        try:
            # Create target file for httpx
            import tempfile
            import os
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for target in web_targets:
                    f.write(target + '\n')
                target_file = f.name
            
            try:
                cmd = [
                    'httpx', '-l', target_file, '-json', '-silent',
                    '-title', '-tech-detect', '-status-code',
                    '-content-length', '-response-time'
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    for line in stdout.decode().strip().split('\n'):
                        if line.strip():
                            try:
                                data = json.loads(line)
                                url = data.get('url', '')
                                if url:
                                    web_services[url] = {
                                        'status_code': data.get('status-code'),
                                        'title': data.get('title', ''),
                                        'tech': data.get('tech', []),
                                        'content_length': data.get('content-length'),
                                        'response_time': data.get('response-time'),
                                        'webserver': data.get('webserver', '')
                                    }
                            except json.JSONDecodeError:
                                pass
            finally:
                os.unlink(target_file)
                
        except FileNotFoundError:
            self.logger.warning("httpx tool not found")
        except Exception as e:
            self.logger.error(f"httpx discovery error: {e}")
        
        return web_services