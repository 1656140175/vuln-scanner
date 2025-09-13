"""Generic tool implementation for tools without specific implementations."""

import asyncio
import json
import re
import time
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..base import SecurityTool, ToolStatus, ToolExecutionResult
from ..registry import ToolDefinition


class GenericTool(SecurityTool):
    """Generic tool implementation for tools without specific implementations."""
    
    def __init__(self, name: str, config: Dict[str, Any], tool_def: ToolDefinition):
        """Initialize generic tool.
        
        Args:
            name: Tool name
            config: Tool configuration
            tool_def: Tool definition from registry
        """
        super().__init__(name, config)
        self.tool_def = tool_def
        
        # Override binary path if specified in tool definition
        if tool_def.binary_name:
            self.binary_path = config.get('path', tool_def.binary_name)
        
        # Set up version checking
        self.version_command = tool_def.version_command or [self.binary_path, '--version']
        self.version_regex = tool_def.version_regex
    
    async def install(self) -> bool:
        """Install the tool using available methods."""
        try:
            if await self.validate_installation():
                self.status = ToolStatus.INSTALLED
                return True
            
            self.logger.info(f"Installing {self.name}")
            self.status = ToolStatus.INSTALLING
            
            # Try different installation methods
            install_methods = self.tool_def.install_methods or ['package_manager']
            
            for method in install_methods:
                success = await self._try_install_method(method)
                if success and await self.validate_installation():
                    self.status = ToolStatus.INSTALLED
                    self.logger.info(f"{self.name} installed successfully via {method}")
                    return True
            
            self.status = ToolStatus.ERROR
            self.logger.error(f"{self.name} installation failed")
            return False
            
        except Exception as e:
            self.status = ToolStatus.ERROR
            self.logger.error(f"Error installing {self.name}: {e}")
            return False
    
    async def _try_install_method(self, method: str) -> bool:
        """Try a specific installation method.
        
        Args:
            method: Installation method name
            
        Returns:
            True if installation succeeded
        """
        try:
            if method == 'package_manager':
                package_name = self.tool_def.package_name or self.name
                return await self._install_via_package_manager(package_name)
            
            elif method == 'go_install':
                if self.tool_def.install_url:
                    return await self._install_via_go()
                
            elif method == 'git':
                if self.tool_def.repository:
                    return await self._install_via_git()
            
            elif method == 'binary':
                if self.tool_def.install_url:
                    return await self._install_via_binary()
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Installation method {method} failed: {e}")
            return False
    
    async def _install_via_go(self) -> bool:
        """Install via Go."""
        try:
            import shutil
            if not shutil.which('go'):
                return False
            
            cmd = ['go', 'install', '-v', self.tool_def.install_url]
            result = await self._run_command(cmd, timeout=300)
            return result['returncode'] == 0
            
        except Exception as e:
            self.logger.debug(f"Go installation failed: {e}")
            return False
    
    async def _install_via_git(self) -> bool:
        """Install via Git clone."""
        try:
            import shutil
            if not shutil.which('git'):
                return False
            
            # Clone to temporary directory
            temp_dir = Path(f'/tmp/{self.name}')
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            
            cmd = ['git', 'clone', self.tool_def.repository, str(temp_dir)]
            result = await self._run_command(cmd, timeout=300)
            
            if result['returncode'] != 0:
                return False
            
            # Try to install from cloned repo
            install_script = temp_dir / 'install.sh'
            if install_script.exists():
                cmd = ['bash', str(install_script)]
                result = await self._run_command(cmd, cwd=str(temp_dir), timeout=300)
                return result['returncode'] == 0
            
            # Try setup.py
            setup_py = temp_dir / 'setup.py'
            if setup_py.exists():
                cmd = ['python3', 'setup.py', 'install']
                result = await self._run_command(cmd, cwd=str(temp_dir), timeout=300)
                return result['returncode'] == 0
            
            # Try Makefile
            makefile = temp_dir / 'Makefile'
            if makefile.exists():
                # Try make install
                cmd = ['make', 'install']
                result = await self._run_command(cmd, cwd=str(temp_dir), timeout=300)
                return result['returncode'] == 0
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Git installation failed: {e}")
            return False
    
    async def _install_via_binary(self) -> bool:
        """Install via binary download."""
        # This would implement binary download and installation
        # For now, return False to indicate it's not implemented
        self.logger.debug("Binary installation not yet implemented")
        return False
    
    async def update(self) -> bool:
        """Update the tool."""
        try:
            self.logger.info(f"Updating {self.name}")
            self.status = ToolStatus.UPDATING
            
            # For most tools, update is the same as install
            success = await self.install()
            
            if success:
                self.status = ToolStatus.INSTALLED
                self.logger.info(f"{self.name} updated successfully")
                return True
            else:
                self.status = ToolStatus.ERROR
                self.logger.error(f"{self.name} update failed")
                return False
                
        except Exception as e:
            self.status = ToolStatus.ERROR
            self.logger.error(f"Error updating {self.name}: {e}")
            return False
    
    async def check_version(self) -> Optional[str]:
        """Check tool version."""
        try:
            result = await self._run_command(self.version_command, timeout=30)
            
            if result['returncode'] == 0:
                output = result['stdout']
                
                # Try to extract version using regex if provided
                if self.version_regex:
                    version_match = re.search(self.version_regex, output)
                    if version_match:
                        return version_match.group(1)
                
                # Fallback: look for common version patterns
                version_patterns = [
                    r'version[:\s]+v?(\d+\.\d+(?:\.\d+)?)',
                    r'v(\d+\.\d+(?:\.\d+)?)',
                    r'(\d+\.\d+(?:\.\d+)?)',
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        return match.group(1)
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error checking {self.name} version: {e}")
            return None
    
    async def validate_installation(self) -> bool:
        """Validate tool installation."""
        if not self._is_installed():
            return False
        
        # Check if we can get version (indicates working installation)
        version = await self.check_version()
        return version is not None
    
    async def execute(self, *args, **kwargs) -> ToolExecutionResult:
        """Execute the tool with given arguments.
        
        Args:
            *args: Command arguments
            **kwargs: Additional options
                - extra_args: Additional command line arguments
                - timeout: Execution timeout
                - input_data: Input data to pass to command
                - env: Environment variables
                - cwd: Working directory
        
        Returns:
            ToolExecutionResult with execution results
        """
        start_time = time.time()
        
        try:
            # Build command
            cmd = [self.binary_path]
            
            # Add default arguments from tool definition
            if self.default_args:
                cmd.extend(self.default_args)
            
            # Add provided arguments
            cmd.extend(str(arg) for arg in args)
            
            # Add extra arguments if provided
            if 'extra_args' in kwargs and isinstance(kwargs['extra_args'], list):
                cmd.extend(kwargs['extra_args'])
            
            # Prepare execution parameters
            timeout = kwargs.get('timeout', self.timeout)
            cwd = kwargs.get('cwd')
            env = kwargs.get('env')
            
            # Execute command
            result = await self._run_command(cmd, timeout=timeout, cwd=cwd, env=env)
            
            execution_time = time.time() - start_time
            
            # Try to parse output as JSON if it looks like JSON
            parsed_output = None
            if result['stdout'].strip().startswith(('{', '[')):
                try:
                    parsed_output = json.loads(result['stdout'])
                except json.JSONDecodeError:
                    # Not valid JSON, leave as None
                    pass
            
            return ToolExecutionResult(
                tool=self.name,
                success=result['returncode'] == 0,
                returncode=result['returncode'],
                stdout=result['stdout'],
                stderr=result['stderr'],
                execution_time=execution_time,
                command=cmd,
                parsed_output=parsed_output
            )
            
        except asyncio.TimeoutError:
            return ToolExecutionResult(
                tool=self.name,
                success=False,
                returncode=-1,
                stdout="",
                stderr="",
                execution_time=time.time() - start_time,
                command=[],
                error=f"Command timed out after {kwargs.get('timeout', self.timeout)} seconds"
            )
        
        except Exception as e:
            return ToolExecutionResult(
                tool=self.name,
                success=False,
                returncode=-1,
                stdout="",
                stderr=str(e),
                execution_time=time.time() - start_time,
                command=[],
                error=str(e)
            )
    
    def get_tool_info(self) -> Dict[str, Any]:
        """Get detailed tool information.
        
        Returns:
            Dictionary with tool information
        """
        return {
            'name': self.name,
            'display_name': self.tool_def.display_name,
            'category': self.tool_def.category.value,
            'description': self.tool_def.description,
            'homepage': self.tool_def.homepage,
            'repository': self.tool_def.repository,
            'binary_path': self.binary_path,
            'status': self.status.value,
            'dependencies': self.tool_def.dependencies,
            'supported_platforms': self.tool_def.supported_platforms,
            'install_methods': self.tool_def.install_methods,
            'tags': self.tool_def.tags,
            'version': asyncio.run(self.check_version()) if self.status == ToolStatus.INSTALLED else None
        }
    
    async def help(self) -> ToolExecutionResult:
        """Get tool help information.
        
        Returns:
            ToolExecutionResult with help output
        """
        help_args = ['--help', '-h', 'help']
        
        for arg in help_args:
            try:
                result = await self.execute(arg, timeout=30)
                if result.success or result.stdout:  # Some tools exit with non-zero for help
                    return result
            except:
                continue
        
        # If no help available, return tool information
        return ToolExecutionResult(
            tool=self.name,
            success=True,
            returncode=0,
            stdout=json.dumps(self.get_tool_info(), indent=2),
            stderr="",
            execution_time=0,
            command=[],
            parsed_output=self.get_tool_info()
        )