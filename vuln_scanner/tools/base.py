"""Base classes and interfaces for security tools."""

import asyncio
import platform
import subprocess
import os
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import json
import logging


class ToolStatus(Enum):
    """Status of a security tool."""
    NOT_INSTALLED = "not_installed"
    INSTALLING = "installing"
    INSTALLED = "installed"
    UPDATING = "updating"
    OUTDATED = "outdated"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class ToolInfo:
    """Information about a security tool."""
    name: str
    version: Optional[str] = None
    path: Optional[str] = None
    config: Dict[str, Any] = None
    status: ToolStatus = ToolStatus.NOT_INSTALLED
    last_updated: Optional[str] = None
    dependencies: List[str] = None
    
    def __post_init__(self):
        if self.config is None:
            self.config = {}
        if self.dependencies is None:
            self.dependencies = []


@dataclass
class ToolExecutionResult:
    """Result of tool execution."""
    tool: str
    success: bool
    returncode: int
    stdout: str
    stderr: str
    execution_time: float
    command: List[str]
    target: Optional[str] = None
    scan_type: Optional[str] = None
    error: Optional[str] = None
    parsed_output: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'tool': self.tool,
            'success': self.success,
            'returncode': self.returncode,
            'stdout': self.stdout,
            'stderr': self.stderr,
            'execution_time': self.execution_time,
            'command': self.command,
            'target': self.target,
            'scan_type': self.scan_type,
            'error': self.error,
            'parsed_output': self.parsed_output
        }


class SecurityTool(ABC):
    """Abstract base class for all security tools."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """Initialize security tool.
        
        Args:
            name: Tool name
            config: Tool configuration
        """
        self.name = name
        self.config = config
        self.status = ToolStatus.NOT_INSTALLED
        self.logger = logging.getLogger(f"tool.{name}")
        
        # Extract common config values
        self.binary_path = config.get('path', name)
        self.timeout = config.get('timeout', 300)
        self.default_args = config.get('default_args', [])
        
        # Check if tool is already installed
        self._check_initial_status()
    
    def _check_initial_status(self) -> None:
        """Check initial tool status."""
        try:
            if self._is_installed():
                self.status = ToolStatus.INSTALLED
            else:
                self.status = ToolStatus.NOT_INSTALLED
        except Exception as e:
            self.logger.warning(f"Error checking initial status: {e}")
            self.status = ToolStatus.UNKNOWN
    
    def _is_installed(self) -> bool:
        """Check if tool is installed."""
        # First check if explicit path exists and is executable
        if os.path.isabs(self.binary_path):
            return os.path.isfile(self.binary_path) and os.access(self.binary_path, os.X_OK)
        
        # Otherwise check if it's in PATH
        return shutil.which(self.binary_path) is not None
    
    async def _run_command(self, cmd: List[str], timeout: Optional[int] = None,
                          cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Run a system command asynchronously.
        
        Args:
            cmd: Command and arguments to run
            timeout: Command timeout in seconds
            cwd: Working directory
            env: Environment variables
            
        Returns:
            Dictionary with execution results
        """
        if timeout is None:
            timeout = self.timeout
        
        self.logger.debug(f"Running command: {' '.join(cmd)}")
        
        try:
            # Prepare environment
            full_env = os.environ.copy()
            if env:
                full_env.update(env)
            
            # Create subprocess
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=full_env
            )
            
            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            result = {
                'returncode': process.returncode,
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore')
            }
            
            self.logger.debug(f"Command finished with return code {result['returncode']}")
            return result
            
        except asyncio.TimeoutError:
            self.logger.warning(f"Command timed out after {timeout} seconds")
            if 'process' in locals():
                try:
                    process.kill()
                    await process.wait()
                except:
                    pass
            raise
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            raise
    
    @abstractmethod
    async def install(self) -> bool:
        """Install the tool.
        
        Returns:
            True if installation successful
        """
        pass
    
    @abstractmethod
    async def update(self) -> bool:
        """Update the tool.
        
        Returns:
            True if update successful
        """
        pass
    
    @abstractmethod
    async def check_version(self) -> Optional[str]:
        """Check tool version.
        
        Returns:
            Version string or None if cannot determine
        """
        pass
    
    @abstractmethod
    async def validate_installation(self) -> bool:
        """Validate that the tool is properly installed.
        
        Returns:
            True if installation is valid
        """
        pass
    
    @abstractmethod
    async def execute(self, *args, **kwargs) -> ToolExecutionResult:
        """Execute the tool with given arguments.
        
        Returns:
            Tool execution result
        """
        pass
    
    def get_info(self) -> ToolInfo:
        """Get tool information.
        
        Returns:
            ToolInfo object with current tool state
        """
        return ToolInfo(
            name=self.name,
            version=asyncio.run(self.check_version()) if self.status == ToolStatus.INSTALLED else None,
            path=self.binary_path,
            config=self.config,
            status=self.status,
            dependencies=self.get_dependencies()
        )
    
    def get_dependencies(self) -> List[str]:
        """Get tool dependencies.
        
        Returns:
            List of dependency names
        """
        return self.config.get('dependencies', [])
    
    def _get_platform_install_commands(self) -> Dict[str, List[List[str]]]:
        """Get platform-specific install commands.
        
        Returns:
            Dictionary mapping platform to list of command sequences
        """
        system = platform.system().lower()
        
        # Default empty commands - subclasses should override
        return {
            'linux': [],
            'darwin': [],
            'windows': []
        }
    
    async def _install_via_package_manager(self, package_name: Optional[str] = None) -> bool:
        """Install tool via system package manager.
        
        Args:
            package_name: Package name (defaults to tool name)
            
        Returns:
            True if installation successful
        """
        if package_name is None:
            package_name = self.name
        
        system = platform.system().lower()
        
        try:
            if system == "linux":
                # Try different Linux package managers
                package_managers = [
                    (['apt', 'update'], ['apt', 'install', '-y', package_name]),
                    (['yum', 'install', '-y', package_name],),
                    (['pacman', '-S', '--noconfirm', package_name],),
                    (['zypper', 'install', '-y', package_name],)
                ]
                
                for commands in package_managers:
                    try:
                        # Check if package manager exists
                        pm_cmd = commands[0][0]
                        if not shutil.which(pm_cmd):
                            continue
                        
                        # Execute command sequence
                        for cmd in commands:
                            result = await self._run_command(['sudo'] + cmd)
                            if result['returncode'] != 0:
                                break
                        else:
                            return True
                            
                    except Exception as e:
                        self.logger.debug(f"Package manager {pm_cmd} failed: {e}")
                        continue
                        
            elif system == "darwin":  # macOS
                if shutil.which('brew'):
                    result = await self._run_command(['brew', 'install', package_name])
                    return result['returncode'] == 0
                elif shutil.which('port'):
                    result = await self._run_command(['sudo', 'port', 'install', package_name])
                    return result['returncode'] == 0
                    
            elif system == "windows":
                # Try chocolatey first, then scoop
                if shutil.which('choco'):
                    result = await self._run_command(['choco', 'install', package_name, '-y'])
                    return result['returncode'] == 0
                elif shutil.which('scoop'):
                    result = await self._run_command(['scoop', 'install', package_name])
                    return result['returncode'] == 0
                elif shutil.which('winget'):
                    result = await self._run_command(['winget', 'install', package_name])
                    return result['returncode'] == 0
            
            return False
            
        except Exception as e:
            self.logger.error(f"Package manager installation failed: {e}")
            return False
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name='{self.name}', status={self.status.value})"