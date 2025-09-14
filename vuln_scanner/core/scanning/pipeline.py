"""Scan pipeline and phase execution system."""

import asyncio
import logging
import re
from datetime import datetime
from typing import Dict, List, Any, AsyncGenerator, Optional
from contextlib import asynccontextmanager

from .data_structures import ScanPhase, ScanStatus, ScanSeverity, ScanTarget, ScanResult, ScanJob
from ..exceptions import ScanEngineException


class PipelineConfigurationError(ScanEngineException):
    """Pipeline configuration error."""
    pass


class ToolExecutionError(ScanEngineException):
    """Tool execution error."""
    pass


class ScanPipeline:
    """Scan pipeline that orchestrates multi-phase scanning."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """Initialize scan pipeline.
        
        Args:
            name: Pipeline name
            config: System configuration
        """
        self.name = name
        self.config = config
        self.logger = logging.getLogger(f'scan_pipeline.{name}')
        
        # Pipeline components
        self.phases: List[ScanPhase] = []
        self.phase_configs: Dict[ScanPhase, Dict[str, Any]] = {}
        
        # Setup pipeline from configuration
        self.setup_pipeline()
    
    def setup_pipeline(self) -> None:
        """Setup scan pipeline from configuration."""
        pipeline_config = self.config.get('pipelines', {}).get(self.name, {})
        
        if not pipeline_config:
            raise PipelineConfigurationError(f"Pipeline '{self.name}' not found in configuration")
        
        # Load phases in order
        for phase_name, phase_config in pipeline_config.items():
            try:
                phase = ScanPhase(phase_name)
                self.phases.append(phase)
                self.phase_configs[phase] = phase_config
                
                self.logger.debug(f"Added phase {phase_name} with {len(phase_config.get('tools', []))} tools")
                
            except ValueError:
                self.logger.warning(f"Unknown scan phase: {phase_name}")
                continue
        
        if not self.phases:
            raise PipelineConfigurationError(f"No valid phases configured for pipeline '{self.name}'")
        
        self.logger.info(f"Pipeline '{self.name}' setup complete with {len(self.phases)} phases")
    
    async def execute(self, target: ScanTarget, job: ScanJob) -> AsyncGenerator[ScanResult, None]:
        """Execute scan pipeline.
        
        Args:
            target: Target to scan
            job: Scan job context
            
        Yields:
            ScanResult objects as they become available
        """
        self.logger.info(f"Starting pipeline '{self.name}' for target: {target.target}")
        
        try:
            for phase_index, phase in enumerate(self.phases):
                if job.status == ScanStatus.CANCELLED:
                    self.logger.info(f"Pipeline execution cancelled for job {job.job_id}")
                    break
                
                self.logger.info(f"Executing phase {phase.value} ({phase_index + 1}/{len(self.phases)})")
                
                # Update job progress
                job.progress['current_phase'] = phase.value
                job.progress['phase_index'] = phase_index + 1
                job.progress['total_phases'] = len(self.phases)
                
                phase_config = self.phase_configs[phase]
                phase_executor = PhaseExecutor(phase, phase_config, self.logger)
                
                phase_results = 0
                async for result in phase_executor.execute(target, job):
                    yield result
                    phase_results += 1
                
                self.logger.info(f"Phase {phase.value} completed with {phase_results} results")
                
        except Exception as e:
            self.logger.error(f"Pipeline execution failed: {e}")
            raise
        
        self.logger.info(f"Pipeline '{self.name}' execution completed")


class PhaseExecutor:
    """Executes tools for a specific scan phase."""
    
    def __init__(self, phase: ScanPhase, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """Initialize phase executor.
        
        Args:
            phase: Scan phase to execute
            config: Phase configuration
            logger: Logger instance
        """
        self.phase = phase
        self.config = config
        self.logger = logger or logging.getLogger(f'phase_executor.{phase.value}')
        
        # Phase settings
        self.tools = config.get('tools', [])
        self.parallel = config.get('parallel', False)
        self.timeout = config.get('timeout', 300)
        self.continue_on_error = config.get('continue_on_error', True)
        
        if not self.tools:
            self.logger.warning(f"No tools configured for phase {phase.value}")
    
    async def execute(self, target: ScanTarget, job: ScanJob) -> AsyncGenerator[ScanResult, None]:
        """Execute scan phase.
        
        Args:
            target: Target to scan
            job: Scan job context
            
        Yields:
            ScanResult objects from tool executions
        """
        if not self.tools:
            self.logger.info(f"Skipping phase {self.phase.value} - no tools configured")
            return
        
        self.logger.info(f"Executing phase {self.phase.value} with {len(self.tools)} tools, parallel={self.parallel}")
        
        if self.parallel:
            # Parallel execution of tools
            async for result in self._execute_parallel(target, job):
                yield result
        else:
            # Sequential execution of tools
            async for result in self._execute_sequential(target, job):
                yield result
    
    async def _execute_parallel(self, target: ScanTarget, job: ScanJob) -> AsyncGenerator[ScanResult, None]:
        """Execute tools in parallel.
        
        Args:
            target: Target to scan
            job: Scan job context
            
        Yields:
            ScanResult objects from parallel tool executions
        """
        # Create tasks for all tools
        tasks = []
        for tool_config in self.tools:
            task = asyncio.create_task(
                self._execute_tool_with_timeout(target, job, tool_config)
            )
            tasks.append((task, tool_config))
        
        # Wait for tasks to complete and yield results
        for task, tool_config in tasks:
            try:
                results = await task
                for result in results:
                    yield result
            except Exception as e:
                self.logger.error(f"Tool {tool_config.get('name', 'unknown')} failed: {e}")
                if not self.continue_on_error:
                    # Cancel remaining tasks
                    for remaining_task, _ in tasks:
                        if not remaining_task.done():
                            remaining_task.cancel()
                    raise
    
    async def _execute_sequential(self, target: ScanTarget, job: ScanJob) -> AsyncGenerator[ScanResult, None]:
        """Execute tools sequentially.
        
        Args:
            target: Target to scan
            job: Scan job context
            
        Yields:
            ScanResult objects from sequential tool executions
        """
        for tool_config in self.tools:
            if job.status == ScanStatus.CANCELLED:
                break
            
            try:
                results = await self._execute_tool_with_timeout(target, job, tool_config)
                for result in results:
                    yield result
            except Exception as e:
                self.logger.error(f"Tool {tool_config.get('name', 'unknown')} failed: {e}")
                if not self.continue_on_error:
                    raise
    
    async def _execute_tool_with_timeout(self, target: ScanTarget, job: ScanJob, 
                                       tool_config: Dict[str, Any]) -> List[ScanResult]:
        """Execute single tool with timeout protection.
        
        Args:
            target: Target to scan
            job: Scan job context
            tool_config: Tool configuration
            
        Returns:
            List of scan results
        """
        tool_name = tool_config.get('name', 'unknown')
        tool_timeout = tool_config.get('timeout', self.timeout)
        
        try:
            return await asyncio.wait_for(
                self._execute_tool(target, job, tool_config),
                timeout=tool_timeout
            )
        except asyncio.TimeoutError:
            self.logger.warning(f"Tool {tool_name} timed out after {tool_timeout}s")
            raise ToolExecutionError(f"Tool {tool_name} execution timed out")
    
    async def _execute_tool(self, target: ScanTarget, job: ScanJob, 
                          tool_config: Dict[str, Any]) -> List[ScanResult]:
        """Execute single tool.
        
        Args:
            target: Target to scan
            job: Scan job context
            tool_config: Tool configuration
            
        Returns:
            List of scan results
        """
        tool_name = tool_config['name']
        tool_args = tool_config.get('args', {})
        
        self.logger.debug(f"Executing tool {tool_name} with args: {tool_args}")
        
        # Import here to avoid circular imports
        from ..tool_manager import ToolManagerComponent
        
        # Get tool manager from job metadata or create new one
        tool_manager_component = job.metadata.get('tool_manager_component')
        if not tool_manager_component:
            raise ToolExecutionError("Tool manager component not available in job context")
        
        tool_manager = tool_manager_component.get_tool_manager()
        
        # Execute tool
        result = await tool_manager.execute_tool(tool_name, target.target, **tool_args)
        
        if not result.success:
            error_msg = f"Tool {tool_name} execution failed: {result.error or result.stderr}"
            self.logger.error(error_msg)
            
            # Create error result
            error_result = ScanResult(
                scan_id=job.job_id,
                target=target,
                phase=self.phase,
                tool=tool_name,
                timestamp=datetime.now(),
                data={
                    'error': result.error or result.stderr,
                    'returncode': result.returncode,
                    'execution_time': result.execution_time
                },
                severity=ScanSeverity.INFO
            )
            return [error_result]
        
        # Convert tool result to scan results
        scan_results = self._convert_to_scan_results(
            job.job_id, target, result, tool_name
        )
        
        self.logger.debug(f"Tool {tool_name} produced {len(scan_results)} results")
        return scan_results
    
    def _convert_to_scan_results(self, scan_id: str, target: ScanTarget,
                               raw_result: Any, tool_name: str) -> List[ScanResult]:
        """Convert tool raw result to standard scan results.
        
        Args:
            scan_id: Scan job ID
            target: Scan target
            raw_result: Raw tool execution result
            tool_name: Name of the tool
            
        Returns:
            List of standardized scan results
        """
        # Tool-specific result parsing
        if tool_name == 'nmap':
            return self._parse_nmap_results(scan_id, target, raw_result)
        elif tool_name == 'nuclei':
            return self._parse_nuclei_results(scan_id, target, raw_result)
        elif tool_name == 'httpx':
            return self._parse_httpx_results(scan_id, target, raw_result)
        elif tool_name == 'subfinder':
            return self._parse_subfinder_results(scan_id, target, raw_result)
        elif tool_name == 'gobuster':
            return self._parse_gobuster_results(scan_id, target, raw_result)
        else:
            # Generic result handling
            return self._parse_generic_results(scan_id, target, raw_result, tool_name)
    
    def _parse_nmap_results(self, scan_id: str, target: ScanTarget, 
                          raw_result: Any) -> List[ScanResult]:
        """Parse Nmap scan results.
        
        Args:
            scan_id: Scan job ID
            target: Scan target
            raw_result: Raw Nmap result
            
        Returns:
            List of parsed scan results
        """
        results = []
        
        # Extract stdout from tool result
        nmap_output = getattr(raw_result, 'stdout', '')
        if not nmap_output:
            return results
        
        # Parse open ports
        port_pattern = r'(\d+)/(\w+)\s+open\s+(\w+)'
        ports = re.findall(port_pattern, nmap_output)
        
        for port, protocol, service in ports:
            result = ScanResult(
                scan_id=scan_id,
                target=target,
                phase=self.phase,
                tool='nmap',
                timestamp=datetime.now(),
                data={
                    'type': 'open_port',
                    'port': int(port),
                    'protocol': protocol,
                    'service': service,
                    'state': 'open'
                },
                severity=ScanSeverity.INFO,
                confidence=0.95
            )
            results.append(result)
        
        # Parse OS detection if available
        os_pattern = r'Running: ([^\n]+)'
        os_matches = re.findall(os_pattern, nmap_output)
        
        for os_info in os_matches:
            result = ScanResult(
                scan_id=scan_id,
                target=target,
                phase=self.phase,
                tool='nmap',
                timestamp=datetime.now(),
                data={
                    'type': 'os_detection',
                    'os_info': os_info.strip()
                },
                severity=ScanSeverity.INFO,
                confidence=0.8
            )
            results.append(result)
        
        return results
    
    def _parse_nuclei_results(self, scan_id: str, target: ScanTarget,
                            raw_result: Any) -> List[ScanResult]:
        """Parse Nuclei scan results.
        
        Args:
            scan_id: Scan job ID
            target: Scan target
            raw_result: Raw Nuclei result
            
        Returns:
            List of parsed scan results
        """
        results = []
        
        # Nuclei typically outputs JSON or structured text
        nuclei_output = getattr(raw_result, 'stdout', '')
        if not nuclei_output:
            return results
        
        # Try to parse as JSON (if nuclei was run with -json flag)
        try:
            import json
            for line in nuclei_output.strip().split('\n'):
                if line.strip():
                    vuln_data = json.loads(line)
                    
                    # Map nuclei severity to our severity
                    severity_map = {
                        'info': ScanSeverity.INFO,
                        'low': ScanSeverity.LOW,
                        'medium': ScanSeverity.MEDIUM,
                        'high': ScanSeverity.HIGH,
                        'critical': ScanSeverity.CRITICAL
                    }
                    
                    info = vuln_data.get('info', {})
                    severity = severity_map.get(
                        info.get('severity', 'info').lower(),
                        ScanSeverity.INFO
                    )
                    
                    result = ScanResult(
                        scan_id=scan_id,
                        target=target,
                        phase=self.phase,
                        tool='nuclei',
                        timestamp=datetime.now(),
                        data={
                            'type': 'vulnerability',
                            'template_id': vuln_data.get('template-id'),
                            'template_name': info.get('name'),
                            'description': info.get('description'),
                            'matched_at': vuln_data.get('matched-at'),
                            'tags': info.get('tags', []),
                            'raw_data': vuln_data
                        },
                        severity=severity,
                        confidence=0.9
                    )
                    results.append(result)
                    
        except json.JSONDecodeError:
            # Parse as text output
            vulnerability_pattern = r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)'
            matches = re.findall(vulnerability_pattern, nuclei_output)
            
            for severity_str, template_id, matched_url in matches:
                severity_map = {
                    'info': ScanSeverity.INFO,
                    'low': ScanSeverity.LOW,
                    'medium': ScanSeverity.MEDIUM,
                    'high': ScanSeverity.HIGH,
                    'critical': ScanSeverity.CRITICAL
                }
                
                severity = severity_map.get(severity_str.lower(), ScanSeverity.INFO)
                
                result = ScanResult(
                    scan_id=scan_id,
                    target=target,
                    phase=self.phase,
                    tool='nuclei',
                    timestamp=datetime.now(),
                    data={
                        'type': 'vulnerability',
                        'template_id': template_id,
                        'matched_at': matched_url,
                        'severity_string': severity_str
                    },
                    severity=severity,
                    confidence=0.8
                )
                results.append(result)
        
        return results
    
    def _parse_httpx_results(self, scan_id: str, target: ScanTarget,
                           raw_result: Any) -> List[ScanResult]:
        """Parse httpx scan results.
        
        Args:
            scan_id: Scan job ID
            target: Scan target
            raw_result: Raw httpx result
            
        Returns:
            List of parsed scan results
        """
        results = []
        
        httpx_output = getattr(raw_result, 'stdout', '')
        if not httpx_output:
            return results
        
        # Parse httpx output - typically URLs with status codes
        for line in httpx_output.strip().split('\n'):
            if line.strip():
                # Basic URL detection
                url_pattern = r'(https?://[^\s]+)'
                urls = re.findall(url_pattern, line)
                
                for url in urls:
                    result = ScanResult(
                        scan_id=scan_id,
                        target=target,
                        phase=self.phase,
                        tool='httpx',
                        timestamp=datetime.now(),
                        data={
                            'type': 'web_service',
                            'url': url,
                            'status': 'active'
                        },
                        severity=ScanSeverity.INFO,
                        confidence=0.9
                    )
                    results.append(result)
        
        return results
    
    def _parse_subfinder_results(self, scan_id: str, target: ScanTarget,
                               raw_result: Any) -> List[ScanResult]:
        """Parse subfinder scan results.
        
        Args:
            scan_id: Scan job ID
            target: Scan target
            raw_result: Raw subfinder result
            
        Returns:
            List of parsed scan results
        """
        results = []
        
        subfinder_output = getattr(raw_result, 'stdout', '')
        if not subfinder_output:
            return results
        
        # Each line is typically a subdomain
        for line in subfinder_output.strip().split('\n'):
            subdomain = line.strip()
            if subdomain and '.' in subdomain:
                result = ScanResult(
                    scan_id=scan_id,
                    target=target,
                    phase=self.phase,
                    tool='subfinder',
                    timestamp=datetime.now(),
                    data={
                        'type': 'subdomain',
                        'subdomain': subdomain,
                        'parent_domain': target.target
                    },
                    severity=ScanSeverity.INFO,
                    confidence=0.85
                )
                results.append(result)
        
        return results
    
    def _parse_gobuster_results(self, scan_id: str, target: ScanTarget,
                              raw_result: Any) -> List[ScanResult]:
        """Parse gobuster scan results.
        
        Args:
            scan_id: Scan job ID
            target: Scan target
            raw_result: Raw gobuster result
            
        Returns:
            List of parsed scan results
        """
        results = []
        
        gobuster_output = getattr(raw_result, 'stdout', '')
        if not gobuster_output:
            return results
        
        # Parse gobuster directory/file findings
        finding_pattern = r'(.*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]'
        matches = re.findall(finding_pattern, gobuster_output)
        
        for path, status_code, size in matches:
            severity = ScanSeverity.INFO
            if status_code in ['200', '301', '302']:
                severity = ScanSeverity.LOW  # Found paths might be interesting
            
            result = ScanResult(
                scan_id=scan_id,
                target=target,
                phase=self.phase,
                tool='gobuster',
                timestamp=datetime.now(),
                data={
                    'type': 'directory_listing',
                    'path': path.strip(),
                    'status_code': int(status_code),
                    'size': int(size)
                },
                severity=severity,
                confidence=0.9
            )
            results.append(result)
        
        return results
    
    def _parse_generic_results(self, scan_id: str, target: ScanTarget,
                             raw_result: Any, tool_name: str) -> List[ScanResult]:
        """Parse generic tool results.
        
        Args:
            scan_id: Scan job ID
            target: Scan target
            raw_result: Raw tool result
            tool_name: Name of the tool
            
        Returns:
            List of generic scan results
        """
        # Create generic result
        result = ScanResult(
            scan_id=scan_id,
            target=target,
            phase=self.phase,
            tool=tool_name,
            timestamp=datetime.now(),
            data={
                'type': 'generic_output',
                'stdout': getattr(raw_result, 'stdout', ''),
                'stderr': getattr(raw_result, 'stderr', ''),
                'returncode': getattr(raw_result, 'returncode', 0),
                'execution_time': getattr(raw_result, 'execution_time', 0)
            },
            severity=ScanSeverity.INFO,
            confidence=0.5
        )
        
        return [result]