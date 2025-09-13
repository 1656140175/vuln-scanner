"""Nuclei tool implementation."""

import asyncio
import json
import re
import shutil
import os
from typing import Dict, List, Any, Optional
from pathlib import Path
import time

from ..base import SecurityTool, ToolStatus, ToolExecutionResult


class NucleiTool(SecurityTool):
    """Nuclei vulnerability scanner tool implementation."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Nuclei tool.
        
        Args:
            config: Tool configuration
        """
        super().__init__("nuclei", config)
        
        # Nuclei-specific configuration
        self.templates_dir = Path(config.get('templates_dir', 'data/nuclei-templates'))
        self.config_file = Path(config.get('config_file', 'data/nuclei-config.yaml'))
        
        # Default scan profiles
        self.scan_profiles = {
            'critical': ['-severity', 'critical'],
            'high': ['-severity', 'high,critical'],
            'medium': ['-severity', 'medium,high,critical'],
            'all': ['-severity', 'info,low,medium,high,critical'],
            'cve': ['-tags', 'cve'],
            'rce': ['-tags', 'rce'],
            'sqli': ['-tags', 'sqli'],
            'xss': ['-tags', 'xss'],
            'lfi': ['-tags', 'lfi'],
            'ssrf': ['-tags', 'ssrf'],
            'oob': ['-tags', 'oob'],
            'takeover': ['-tags', 'takeover'],
            'dns': ['-tags', 'dns'],
            'headless': ['-headless']
        }
        
        # Rate limiting and performance settings
        self.default_rate_limit = config.get('rate_limit', 150)  # requests per second
        self.default_concurrency = config.get('concurrency', 25)  # concurrent templates
    
    async def install(self) -> bool:
        """Install Nuclei tool."""
        try:
            if await self.validate_installation():
                self.status = ToolStatus.INSTALLED
                return True
            
            self.logger.info("Installing Nuclei")
            self.status = ToolStatus.INSTALLING
            
            # Install via Go if available
            if shutil.which('go'):
                success = await self._install_via_go()
            else:
                # Try binary download as fallback
                success = await self._install_binary()
            
            if success and await self.validate_installation():
                # Update templates after installation
                await self.update_templates()
                self.status = ToolStatus.INSTALLED
                self.logger.info("Nuclei installed successfully")
                return True
            else:
                self.status = ToolStatus.ERROR
                self.logger.error("Nuclei installation failed")
                return False
                
        except Exception as e:
            self.status = ToolStatus.ERROR
            self.logger.error(f"Error installing Nuclei: {e}")
            return False
    
    async def _install_via_go(self) -> bool:
        """Install Nuclei via Go."""
        try:
            cmd = ['go', 'install', '-v', 'github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest']
            result = await self._run_command(cmd, timeout=300)
            return result['returncode'] == 0
        except Exception as e:
            self.logger.debug(f"Go installation failed: {e}")
            return False
    
    async def _install_binary(self) -> bool:
        """Install Nuclei binary (fallback method)."""
        # This would implement binary download and installation
        # For now, return False to indicate it's not implemented
        self.logger.warning("Binary installation not yet implemented")
        return False
    
    async def update(self) -> bool:
        """Update Nuclei tool."""
        try:
            self.logger.info("Updating Nuclei")
            self.status = ToolStatus.UPDATING
            
            # Update via Go
            if shutil.which('go'):
                cmd = ['go', 'install', '-v', 'github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest']
                result = await self._run_command(cmd, timeout=300)
                success = result['returncode'] == 0
            else:
                success = False
            
            if success:
                # Also update templates
                await self.update_templates()
                self.status = ToolStatus.INSTALLED
                self.logger.info("Nuclei updated successfully")
                return True
            else:
                self.status = ToolStatus.ERROR
                self.logger.error("Nuclei update failed")
                return False
                
        except Exception as e:
            self.status = ToolStatus.ERROR
            self.logger.error(f"Error updating Nuclei: {e}")
            return False
    
    async def check_version(self) -> Optional[str]:
        """Check Nuclei version."""
        try:
            result = await self._run_command([self.binary_path, '-version'])
            
            if result['returncode'] == 0:
                # Parse version from output like "Current Version: v2.8.5"
                for line in result['stdout'].split('\n'):
                    if 'Current Version:' in line:
                        version_match = re.search(r'v(\d+\.\d+\.\d+)', line)
                        if version_match:
                            return version_match.group(1)
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error checking Nuclei version: {e}")
            return None
    
    async def validate_installation(self) -> bool:
        """Validate Nuclei installation."""
        if not self._is_installed():
            return False
        
        # Check if we can get version
        version = await self.check_version()
        return version is not None
    
    async def update_templates(self) -> bool:
        """Update Nuclei templates."""
        try:
            self.logger.info("Updating Nuclei templates")
            
            # Create templates directory
            self.templates_dir.mkdir(parents=True, exist_ok=True)
            
            cmd = [
                self.binary_path, 
                '-update-templates', 
                '-update-template-dir', str(self.templates_dir)
            ]
            
            result = await self._run_command(cmd, timeout=300)
            
            if result['returncode'] == 0:
                self.logger.info("Nuclei templates updated successfully")
                return True
            else:
                self.logger.error(f"Template update failed: {result['stderr']}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error updating templates: {e}")
            return False
    
    async def execute(self, target: str, severity: str = "medium", 
                     output_format: str = "json", **kwargs) -> ToolExecutionResult:
        """Execute Nuclei scan.
        
        Args:
            target: Target URL or list of URLs
            severity: Severity filter (critical, high, medium, low, info, all)
            output_format: Output format (json, text)
            **kwargs: Additional arguments
                - templates: Specific templates to use
                - exclude_templates: Templates to exclude
                - tags: Template tags to include
                - exclude_tags: Template tags to exclude
                - rate_limit: Rate limit (requests per second)
                - concurrency: Number of concurrent templates
                - timeout: Request timeout
                - retries: Number of retries
                - proxy: Proxy URL
                - headers: Custom headers (dict)
                - exclude_matchers: Matchers to exclude
                - include_matchers: Matchers to include
                - follow_redirects: Follow redirects
                - max_redirects: Maximum redirects to follow
                - disable_clustering: Disable template clustering
                - passive: Run passive templates only
                - headless: Run headless browser templates
        
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
            
            # Add target
            if target.startswith('http'):
                cmd.extend(['-u', target])
            else:
                # Assume it's a file with URLs
                cmd.extend(['-l', target])
            
            # Add severity filter
            if severity in self.scan_profiles:
                cmd.extend(self.scan_profiles[severity])
            elif severity != 'all':
                cmd.extend(['-severity', severity])
            
            # Templates configuration
            if self.templates_dir.exists():
                cmd.extend(['-t', str(self.templates_dir)])
            
            # Specific templates
            if 'templates' in kwargs:
                cmd.extend(['-t', kwargs['templates']])
            
            # Exclude templates
            if 'exclude_templates' in kwargs:
                cmd.extend(['-exclude-templates', kwargs['exclude_templates']])
            
            # Tags
            if 'tags' in kwargs:
                cmd.extend(['-tags', kwargs['tags']])
            
            # Exclude tags
            if 'exclude_tags' in kwargs:
                cmd.extend(['-exclude-tags', kwargs['exclude_tags']])
            
            # Rate limiting
            rate_limit = kwargs.get('rate_limit', self.default_rate_limit)
            cmd.extend(['-rate-limit', str(rate_limit)])
            
            # Concurrency
            concurrency = kwargs.get('concurrency', self.default_concurrency)
            cmd.extend(['-c', str(concurrency)])
            
            # Timeout
            if 'timeout' in kwargs:
                cmd.extend(['-timeout', str(kwargs['timeout'])])
            
            # Retries
            if 'retries' in kwargs:
                cmd.extend(['-retries', str(kwargs['retries'])])
            
            # Proxy
            if 'proxy' in kwargs:
                cmd.extend(['-proxy', kwargs['proxy']])
            
            # Custom headers
            if 'headers' in kwargs and isinstance(kwargs['headers'], dict):
                for key, value in kwargs['headers'].items():
                    cmd.extend(['-H', f'{key}: {value}'])
            
            # Matcher options
            if 'exclude_matchers' in kwargs:
                cmd.extend(['-exclude-matchers', kwargs['exclude_matchers']])
            
            if 'include_matchers' in kwargs:
                cmd.extend(['-include-matchers', kwargs['include_matchers']])
            
            # Redirect options
            if kwargs.get('follow_redirects', True):
                cmd.append('-fr')
            
            if 'max_redirects' in kwargs:
                cmd.extend(['-mr', str(kwargs['max_redirects'])])
            
            # Clustering
            if kwargs.get('disable_clustering', False):
                cmd.append('-nc')
            
            # Passive mode
            if kwargs.get('passive', False):
                cmd.append('-passive')
            
            # Headless mode
            if kwargs.get('headless', False):
                cmd.append('-headless')
            
            # Output format
            if output_format == 'json':
                cmd.append('-json')
            
            # Silent mode for cleaner output
            cmd.append('-silent')
            
            # No color output
            cmd.append('-no-color')
            
            # Execute command
            timeout = kwargs.get('scan_timeout', self.timeout)
            result = await self._run_command(cmd, timeout=timeout)
            
            execution_time = time.time() - start_time
            
            # Parse JSON output
            parsed_output = None
            vulnerabilities = []
            
            if result['returncode'] == 0 and output_format == 'json':
                try:
                    # Parse JSON lines
                    for line in result['stdout'].strip().split('\n'):
                        if line.strip():
                            try:
                                vuln_data = json.loads(line)
                                vulnerabilities.append(vuln_data)
                            except json.JSONDecodeError as e:
                                self.logger.debug(f"Error parsing JSON line: {e}")
                                continue
                    
                    parsed_output = {
                        'vulnerabilities': vulnerabilities,
                        'total_found': len(vulnerabilities),
                        'by_severity': self._categorize_by_severity(vulnerabilities),
                        'by_template': self._categorize_by_template(vulnerabilities)
                    }
                    
                except Exception as e:
                    self.logger.warning(f"Error parsing output: {e}")
            
            return ToolExecutionResult(
                tool="nuclei",
                success=result['returncode'] == 0,
                returncode=result['returncode'],
                stdout=result['stdout'],
                stderr=result['stderr'],
                execution_time=execution_time,
                command=cmd,
                target=target,
                scan_type=severity,
                parsed_output=parsed_output
            )
            
        except asyncio.TimeoutError:
            return ToolExecutionResult(
                tool="nuclei",
                success=False,
                returncode=-1,
                stdout="",
                stderr="",
                execution_time=time.time() - start_time,
                command=[],
                target=target,
                scan_type=severity,
                error=f"Scan timed out after {kwargs.get('scan_timeout', self.timeout)} seconds"
            )
        
        except Exception as e:
            return ToolExecutionResult(
                tool="nuclei",
                success=False,
                returncode=-1,
                stdout="",
                stderr=str(e),
                execution_time=time.time() - start_time,
                command=[],
                target=target,
                scan_type=severity,
                error=str(e)
            )
    
    def _categorize_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize vulnerabilities by severity."""
        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('info', {}).get('severity', 'info').lower()
            if severity in severity_count:
                severity_count[severity] += 1
        
        return severity_count
    
    def _categorize_by_template(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize vulnerabilities by template."""
        template_count = {}
        
        for vuln in vulnerabilities:
            template_id = vuln.get('template-id', 'unknown')
            template_count[template_id] = template_count.get(template_id, 0) + 1
        
        return template_count
    
    async def scan_url(self, url: str, severity: str = "medium", **kwargs) -> ToolExecutionResult:
        """Scan a single URL.
        
        Args:
            url: URL to scan
            severity: Severity filter
            **kwargs: Additional arguments
            
        Returns:
            ToolExecutionResult with scan results
        """
        return await self.execute(url, severity=severity, **kwargs)
    
    async def scan_urls_from_file(self, file_path: str, severity: str = "medium", 
                                 **kwargs) -> ToolExecutionResult:
        """Scan URLs from a file.
        
        Args:
            file_path: Path to file containing URLs
            severity: Severity filter
            **kwargs: Additional arguments
            
        Returns:
            ToolExecutionResult with scan results
        """
        return await self.execute(file_path, severity=severity, **kwargs)
    
    async def scan_with_template(self, target: str, template_path: str, 
                                **kwargs) -> ToolExecutionResult:
        """Scan with specific template.
        
        Args:
            target: Target to scan
            template_path: Path to template file
            **kwargs: Additional arguments
            
        Returns:
            ToolExecutionResult with scan results
        """
        kwargs['templates'] = template_path
        return await self.execute(target, **kwargs)
    
    async def scan_cve(self, target: str, **kwargs) -> ToolExecutionResult:
        """Scan for CVE-based vulnerabilities.
        
        Args:
            target: Target to scan
            **kwargs: Additional arguments
            
        Returns:
            ToolExecutionResult with CVE results
        """
        kwargs['tags'] = 'cve'
        return await self.execute(target, severity='all', **kwargs)
    
    async def passive_scan(self, target: str, **kwargs) -> ToolExecutionResult:
        """Perform passive scan (no active requests).
        
        Args:
            target: Target to scan
            **kwargs: Additional arguments
            
        Returns:
            ToolExecutionResult with passive scan results
        """
        kwargs['passive'] = True
        return await self.execute(target, **kwargs)
    
    async def get_templates_info(self) -> Dict[str, Any]:
        """Get information about installed templates.
        
        Returns:
            Dictionary with template information
        """
        try:
            if not self.templates_dir.exists():
                return {'error': 'Templates directory not found'}
            
            cmd = [self.binary_path, '-tl']
            result = await self._run_command(cmd, timeout=60)
            
            if result['returncode'] == 0:
                template_count = len(result['stdout'].strip().split('\n'))
                return {
                    'templates_dir': str(self.templates_dir),
                    'template_count': template_count,
                    'last_updated': self._get_templates_last_updated()
                }
            else:
                return {'error': 'Failed to get template list'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _get_templates_last_updated(self) -> Optional[str]:
        """Get last update time of templates directory."""
        try:
            if self.templates_dir.exists():
                stat_result = self.templates_dir.stat()
                return str(stat_result.st_mtime)
            return None
        except Exception:
            return None
    
    def get_available_scan_types(self) -> Dict[str, List[str]]:
        """Get available scan profiles.
        
        Returns:
            Dictionary mapping scan types to their arguments
        """
        return self.scan_profiles.copy()
    
    async def validate_template(self, template_path: str) -> Dict[str, Any]:
        """Validate a Nuclei template.
        
        Args:
            template_path: Path to template file
            
        Returns:
            Validation results
        """
        try:
            cmd = [self.binary_path, '-validate', '-t', template_path]
            result = await self._run_command(cmd, timeout=30)
            
            return {
                'valid': result['returncode'] == 0,
                'output': result['stdout'],
                'errors': result['stderr']
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }