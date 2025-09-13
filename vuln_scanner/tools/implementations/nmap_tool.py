"""Nmap tool implementation."""

import asyncio
import re
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
import tempfile
import os
from pathlib import Path
import time

from ..base import SecurityTool, ToolStatus, ToolExecutionResult


class NmapTool(SecurityTool):
    """Nmap (Network Mapper) tool implementation."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Nmap tool.
        
        Args:
            config: Tool configuration
        """
        super().__init__("nmap", config)
        
        # Nmap-specific configuration
        self.scan_profiles = {
            'quick': ['-T4', '-F'],  # Fast scan, limited ports
            'basic': ['-sS', '-sV'],  # SYN scan with version detection
            'comprehensive': ['-sS', '-sV', '-sC', '-O'],  # Full scan
            'stealth': ['-sS', '-T1'],  # Stealth scan
            'udp': ['-sU'],  # UDP scan
            'ping': ['-sn'],  # Ping scan only
            'tcp_connect': ['-sT'],  # TCP connect scan
            'intense': ['-T4', '-A'],  # Intense scan
            'intense_no_ping': ['-T4', '-A', '-Pn']  # Intense scan without ping
        }
        
        # Common Nmap scripts
        self.script_categories = {
            'vuln': '--script vuln',
            'default': '--script default',
            'discovery': '--script discovery',
            'safe': '--script safe',
            'intrusive': '--script intrusive',
            'malware': '--script malware'
        }
    
    async def install(self) -> bool:
        """Install Nmap tool."""
        try:
            if await self.validate_installation():
                self.status = ToolStatus.INSTALLED
                return True
            
            self.logger.info("Installing Nmap")
            self.status = ToolStatus.INSTALLING
            
            # Try package manager installation
            success = await self._install_via_package_manager("nmap")
            
            if success and await self.validate_installation():
                self.status = ToolStatus.INSTALLED
                self.logger.info("Nmap installed successfully")
                return True
            else:
                self.status = ToolStatus.ERROR
                self.logger.error("Nmap installation failed")
                return False
                
        except Exception as e:
            self.status = ToolStatus.ERROR
            self.logger.error(f"Error installing Nmap: {e}")
            return False
    
    async def update(self) -> bool:
        """Update Nmap tool."""
        try:
            self.logger.info("Updating Nmap")
            self.status = ToolStatus.UPDATING
            
            # Update via package manager
            success = await self._install_via_package_manager("nmap")
            
            if success:
                self.status = ToolStatus.INSTALLED
                self.logger.info("Nmap updated successfully")
                return True
            else:
                self.status = ToolStatus.ERROR
                self.logger.error("Nmap update failed")
                return False
                
        except Exception as e:
            self.status = ToolStatus.ERROR
            self.logger.error(f"Error updating Nmap: {e}")
            return False
    
    async def check_version(self) -> Optional[str]:
        """Check Nmap version."""
        try:
            result = await self._run_command([self.binary_path, '--version'])
            
            if result['returncode'] == 0:
                # Parse version from output like "Nmap version 7.93"
                version_match = re.search(r'Nmap version (\d+\.\d+)', result['stdout'])
                if version_match:
                    return version_match.group(1)
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error checking Nmap version: {e}")
            return None
    
    async def validate_installation(self) -> bool:
        """Validate Nmap installation."""
        if not self._is_installed():
            return False
        
        # Check if we can get version (indicates working installation)
        version = await self.check_version()
        return version is not None
    
    async def execute(self, target: str, scan_type: str = "basic", 
                     output_format: str = "json", **kwargs) -> ToolExecutionResult:
        """Execute Nmap scan.
        
        Args:
            target: Target to scan (IP, hostname, range, etc.)
            scan_type: Type of scan (quick, basic, comprehensive, etc.)
            output_format: Output format (json, xml, text)
            **kwargs: Additional arguments
                - ports: Port specification (e.g., "1-1000", "22,80,443")
                - scripts: Script category or specific scripts
                - timing: Timing template (0-5)
                - extra_args: Additional command line arguments
                - exclude: Hosts to exclude
                - interface: Network interface to use
                - source_port: Source port to use
        
        Returns:
            ToolExecutionResult with scan results
        """
        start_time = time.time()
        
        try:
            # Validate target
            if not target or not isinstance(target, str):
                raise ValueError("Target must be a non-empty string")
            
            # Build command
            cmd = [self.binary_path]
            
            # Add scan profile arguments
            profile_args = self.scan_profiles.get(scan_type, self.default_args)
            cmd.extend(profile_args)
            
            # Add port specification
            if 'ports' in kwargs:
                cmd.extend(['-p', str(kwargs['ports'])])
            
            # Add scripts
            if 'scripts' in kwargs:
                script_arg = kwargs['scripts']
                if script_arg in self.script_categories:
                    script_arg = self.script_categories[script_arg]
                cmd.append(script_arg)
            
            # Add timing template
            if 'timing' in kwargs:
                timing = kwargs['timing']
                if isinstance(timing, int) and 0 <= timing <= 5:
                    cmd.append(f'-T{timing}')
            
            # Add exclusions
            if 'exclude' in kwargs:
                cmd.extend(['--exclude', kwargs['exclude']])
            
            # Add interface
            if 'interface' in kwargs:
                cmd.extend(['-e', kwargs['interface']])
            
            # Add source port
            if 'source_port' in kwargs:
                cmd.extend(['--source-port', str(kwargs['source_port'])])
            
            # Set up output format
            temp_file = None
            if output_format in ['json', 'xml']:
                temp_file = tempfile.NamedTemporaryFile(
                    mode='w+',
                    suffix=f'.{output_format}',
                    delete=False
                )
                temp_file.close()
                
                if output_format == 'xml':
                    cmd.extend(['-oX', temp_file.name])
                else:
                    # For JSON, we'll parse XML output
                    cmd.extend(['-oX', temp_file.name])
            
            # Add extra arguments
            if 'extra_args' in kwargs and isinstance(kwargs['extra_args'], list):
                cmd.extend(kwargs['extra_args'])
            
            # Add target (always last)
            cmd.append(target)
            
            # Execute command
            timeout = kwargs.get('timeout', self.timeout)
            result = await self._run_command(cmd, timeout=timeout)
            
            execution_time = time.time() - start_time
            
            # Parse output
            parsed_output = None
            if temp_file and result['returncode'] == 0:
                try:
                    if output_format == 'json':
                        # Convert XML to JSON
                        parsed_output = self._xml_to_json(temp_file.name)
                    elif output_format == 'xml':
                        # Read raw XML
                        with open(temp_file.name, 'r') as f:
                            parsed_output = {'xml': f.read()}
                    
                    # Clean up temp file
                    os.unlink(temp_file.name)
                    
                except Exception as e:
                    self.logger.warning(f"Error parsing output: {e}")
                    if temp_file and os.path.exists(temp_file.name):
                        os.unlink(temp_file.name)
            
            return ToolExecutionResult(
                tool="nmap",
                success=result['returncode'] == 0,
                returncode=result['returncode'],
                stdout=result['stdout'],
                stderr=result['stderr'],
                execution_time=execution_time,
                command=cmd,
                target=target,
                scan_type=scan_type,
                parsed_output=parsed_output
            )
            
        except asyncio.TimeoutError:
            return ToolExecutionResult(
                tool="nmap",
                success=False,
                returncode=-1,
                stdout="",
                stderr="",
                execution_time=time.time() - start_time,
                command=[],
                target=target,
                scan_type=scan_type,
                error=f"Scan timed out after {kwargs.get('timeout', self.timeout)} seconds"
            )
        
        except Exception as e:
            return ToolExecutionResult(
                tool="nmap",
                success=False,
                returncode=-1,
                stdout="",
                stderr=str(e),
                execution_time=time.time() - start_time,
                command=[],
                target=target,
                scan_type=scan_type,
                error=str(e)
            )
    
    def _xml_to_json(self, xml_file_path: str) -> Dict[str, Any]:
        """Convert Nmap XML output to structured JSON.
        
        Args:
            xml_file_path: Path to XML output file
            
        Returns:
            Structured dictionary with scan results
        """
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()
            
            scan_info = {
                'scan_info': {
                    'nmap_version': root.get('version'),
                    'scan_args': root.get('args'),
                    'start_time': root.get('startstr'),
                    'scan_stats': {}
                },
                'hosts': []
            }
            
            # Parse scan statistics
            finished = root.find('runstats/finished')
            if finished is not None:
                scan_info['scan_info']['scan_stats'] = {
                    'total_time': finished.get('elapsed'),
                    'exit_status': finished.get('exit'),
                    'hosts_up': 0,
                    'hosts_down': 0,
                    'hosts_total': 0
                }
            
            # Parse hosts
            for host in root.findall('host'):
                host_info = {
                    'state': host.find('status').get('state'),
                    'addresses': {},
                    'hostnames': [],
                    'ports': [],
                    'os': {},
                    'scripts': []
                }
                
                # Extract addresses
                for address in host.findall('address'):
                    addr_type = address.get('addrtype')
                    addr_value = address.get('addr')
                    host_info['addresses'][addr_type] = addr_value
                
                # Extract hostnames
                for hostname in host.findall('hostnames/hostname'):
                    host_info['hostnames'].append({
                        'name': hostname.get('name'),
                        'type': hostname.get('type')
                    })
                
                # Extract ports
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        state = port.find('state')
                        service = port.find('service')
                        
                        port_info = {
                            'port': int(port.get('portid')),
                            'protocol': port.get('protocol'),
                            'state': state.get('state') if state is not None else 'unknown',
                            'service': {}
                        }
                        
                        if service is not None:
                            port_info['service'] = {
                                'name': service.get('name', ''),
                                'product': service.get('product', ''),
                                'version': service.get('version', ''),
                                'extrainfo': service.get('extrainfo', ''),
                                'method': service.get('method', '')
                            }
                        
                        # Extract scripts for this port
                        port_scripts = []
                        for script in port.findall('script'):
                            script_info = {
                                'id': script.get('id'),
                                'output': script.get('output', '').strip()
                            }
                            
                            # Parse structured script output
                            if script.find('table') is not None:
                                script_info['structured'] = self._parse_script_table(script.find('table'))
                            
                            port_scripts.append(script_info)
                        
                        port_info['scripts'] = port_scripts
                        host_info['ports'].append(port_info)
                
                # Extract OS information
                os_elem = host.find('os')
                if os_elem is not None:
                    os_matches = []
                    for osmatch in os_elem.findall('osmatch'):
                        os_matches.append({
                            'name': osmatch.get('name'),
                            'accuracy': int(osmatch.get('accuracy', 0)),
                            'line': osmatch.get('line', '')
                        })
                    host_info['os']['matches'] = os_matches
                
                # Extract host scripts
                for script in host.findall('hostscript/script'):
                    script_info = {
                        'id': script.get('id'),
                        'output': script.get('output', '').strip()
                    }
                    
                    if script.find('table') is not None:
                        script_info['structured'] = self._parse_script_table(script.find('table'))
                    
                    host_info['scripts'].append(script_info)
                
                scan_info['hosts'].append(host_info)
            
            # Update scan stats
            if scan_info['hosts']:
                hosts_up = sum(1 for h in scan_info['hosts'] if h['state'] == 'up')
                scan_info['scan_info']['scan_stats'].update({
                    'hosts_up': hosts_up,
                    'hosts_down': len(scan_info['hosts']) - hosts_up,
                    'hosts_total': len(scan_info['hosts'])
                })
            
            return scan_info
            
        except Exception as e:
            self.logger.error(f"Error parsing XML output: {e}")
            return {'error': str(e)}
    
    def _parse_script_table(self, table_elem) -> Dict[str, Any]:
        """Parse Nmap script table element into structured data."""
        result = {}
        
        for elem in table_elem.findall('elem'):
            key = elem.get('key', '')
            value = elem.text or ''
            result[key] = value
        
        for table in table_elem.findall('table'):
            key = table.get('key', 'table')
            result[key] = self._parse_script_table(table)
        
        return result
    
    def get_available_scan_types(self) -> Dict[str, List[str]]:
        """Get available scan types and their arguments.
        
        Returns:
            Dictionary mapping scan types to their arguments
        """
        return self.scan_profiles.copy()
    
    def get_available_scripts(self) -> Dict[str, str]:
        """Get available script categories.
        
        Returns:
            Dictionary mapping script names to their descriptions
        """
        return {
            'vuln': 'Vulnerability detection scripts',
            'default': 'Default safe scripts',
            'discovery': 'Host and service discovery scripts',
            'safe': 'Scripts unlikely to crash services',
            'intrusive': 'Scripts that may crash services',
            'malware': 'Malware detection scripts'
        }
    
    async def ping_scan(self, targets: str, **kwargs) -> ToolExecutionResult:
        """Perform ping scan to discover live hosts.
        
        Args:
            targets: Target specification
            **kwargs: Additional arguments
            
        Returns:
            ToolExecutionResult with live hosts
        """
        return await self.execute(targets, scan_type='ping', **kwargs)
    
    async def port_scan(self, target: str, ports: str = "1-1000", 
                       scan_type: str = "basic", **kwargs) -> ToolExecutionResult:
        """Perform port scan.
        
        Args:
            target: Target to scan
            ports: Port specification
            scan_type: Scan type to use
            **kwargs: Additional arguments
            
        Returns:
            ToolExecutionResult with port information
        """
        kwargs['ports'] = ports
        return await self.execute(target, scan_type=scan_type, **kwargs)
    
    async def vuln_scan(self, target: str, **kwargs) -> ToolExecutionResult:
        """Perform vulnerability scan using NSE scripts.
        
        Args:
            target: Target to scan
            **kwargs: Additional arguments
            
        Returns:
            ToolExecutionResult with vulnerability information
        """
        kwargs['scripts'] = 'vuln'
        return await self.execute(target, scan_type='comprehensive', **kwargs)
    
    async def os_detection(self, target: str, **kwargs) -> ToolExecutionResult:
        """Perform OS detection scan.
        
        Args:
            target: Target to scan
            **kwargs: Additional arguments
            
        Returns:
            ToolExecutionResult with OS information
        """
        return await self.execute(target, scan_type='comprehensive', **kwargs)