"""Dependency management system for security tools."""

import asyncio
import logging
import platform
import shutil
import os
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path
import subprocess


class DependencyError(Exception):
    """Exception raised when dependency requirements cannot be satisfied."""
    pass


class DependencyManager:
    """Manages dependencies for security tools."""
    
    def __init__(self):
        """Initialize dependency manager."""
        self.logger = logging.getLogger('dependency_manager')
        
        # Define dependency graph
        self.dependency_graph = {
            # Go-based tools
            'nuclei': ['go'],
            'subfinder': ['go'], 
            'httpx': ['go'],
            'gobuster': ['go'],
            'amass': ['go'],
            
            # Python-based tools
            'sqlmap': ['python3'],
            'dirsearch': ['python3'],
            
            # System tools (usually pre-installed or easy to install)
            'nmap': [],
            'curl': [],
            'wget': [],
            'git': [],
            
            # Core dependencies
            'go': [],
            'python3': [],
            'nodejs': [],
        }
        
        # Version requirements
        self.version_requirements = {
            'go': '1.19',  # Minimum Go version
            'python3': '3.8',  # Minimum Python version
            'nodejs': '16.0',  # Minimum Node.js version
        }
        
        # Installation URLs and methods
        self.install_methods = {
            'go': self._install_go,
            'python3': self._install_python3,
            'nodejs': self._install_nodejs,
            'git': self._install_git,
        }
    
    async def check_dependencies(self, tool_name: str) -> Tuple[bool, List[str]]:
        """Check if all dependencies for a tool are satisfied.
        
        Args:
            tool_name: Name of the tool to check dependencies for
            
        Returns:
            Tuple of (all_satisfied, list_of_missing_dependencies)
        """
        dependencies = self.dependency_graph.get(tool_name, [])
        missing = []
        
        for dep in dependencies:
            if not await self._check_dependency(dep):
                missing.append(dep)
        
        return len(missing) == 0, missing
    
    async def install_dependencies(self, tool_name: str) -> bool:
        """Install all dependencies for a tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            True if all dependencies installed successfully
        """
        self.logger.info(f"Installing dependencies for {tool_name}")
        
        dependencies = self.dependency_graph.get(tool_name, [])
        
        # Build dependency resolution order
        install_order = self._resolve_dependency_order(dependencies)
        
        # Install dependencies in order
        for dep in install_order:
            self.logger.info(f"Installing dependency: {dep}")
            
            if await self._check_dependency(dep):
                self.logger.info(f"Dependency {dep} already satisfied")
                continue
            
            if not await self._install_dependency(dep):
                self.logger.error(f"Failed to install dependency: {dep}")
                return False
            
            # Verify installation
            if not await self._check_dependency(dep):
                self.logger.error(f"Dependency {dep} installation verification failed")
                return False
        
        self.logger.info(f"All dependencies installed for {tool_name}")
        return True
    
    def _resolve_dependency_order(self, dependencies: List[str]) -> List[str]:
        """Resolve dependencies in installation order.
        
        Args:
            dependencies: List of dependency names
            
        Returns:
            List of dependencies in installation order
        """
        visited = set()
        temp_visited = set()
        result = []
        
        def visit(dep: str):
            if dep in temp_visited:
                raise DependencyError(f"Circular dependency detected: {dep}")
            if dep in visited:
                return
                
            temp_visited.add(dep)
            
            # Visit dependencies of this dependency
            sub_deps = self.dependency_graph.get(dep, [])
            for sub_dep in sub_deps:
                visit(sub_dep)
            
            temp_visited.remove(dep)
            visited.add(dep)
            result.append(dep)
        
        # Visit all dependencies
        for dep in dependencies:
            if dep not in visited:
                visit(dep)
        
        return result
    
    async def _check_dependency(self, dep_name: str) -> bool:
        """Check if a dependency is available.
        
        Args:
            dep_name: Name of the dependency
            
        Returns:
            True if dependency is available
        """
        try:
            # Special case for Python3 check
            if dep_name == 'python3':
                return await self._check_python3()
            
            # Check if command is available
            result = await self._run_command(['which' if os.name != 'nt' else 'where', dep_name])
            if result['returncode'] != 0:
                return False
            
            # For versioned dependencies, check version
            if dep_name in self.version_requirements:
                return await self._check_version(dep_name)
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Error checking dependency {dep_name}: {e}")
            return False
    
    async def _check_version(self, dep_name: str) -> bool:
        """Check if dependency version meets requirements.
        
        Args:
            dep_name: Dependency name
            
        Returns:
            True if version requirements are met
        """
        try:
            required_version = self.version_requirements.get(dep_name)
            if not required_version:
                return True
            
            # Get actual version
            if dep_name == 'go':
                result = await self._run_command(['go', 'version'])
                if result['returncode'] == 0:
                    # Parse "go version go1.19.4 linux/amd64"
                    parts = result['stdout'].split()
                    if len(parts) >= 3:
                        version_str = parts[2][2:]  # Remove 'go' prefix
                        return self._compare_versions(version_str, required_version) >= 0
            
            elif dep_name == 'python3':
                result = await self._run_command(['python3', '--version'])
                if result['returncode'] == 0:
                    # Parse "Python 3.9.7"
                    parts = result['stdout'].split()
                    if len(parts) >= 2:
                        version_str = parts[1]
                        return self._compare_versions(version_str, required_version) >= 0
            
            elif dep_name == 'nodejs':
                result = await self._run_command(['node', '--version'])
                if result['returncode'] == 0:
                    # Parse "v16.14.0"
                    version_str = result['stdout'].strip().lstrip('v')
                    return self._compare_versions(version_str, required_version) >= 0
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking version for {dep_name}: {e}")
            return False
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compare two version strings.
        
        Args:
            version1: First version string
            version2: Second version string
            
        Returns:
            -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        try:
            def parse_version(v):
                return [int(x) for x in v.split('.')]
            
            v1_parts = parse_version(version1)
            v2_parts = parse_version(version2)
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for a, b in zip(v1_parts, v2_parts):
                if a < b:
                    return -1
                elif a > b:
                    return 1
            
            return 0
            
        except Exception:
            return 0  # Assume equal if can't parse
    
    async def _check_python3(self) -> bool:
        """Check if Python 3 is available."""
        # Try different Python 3 commands
        python_commands = ['python3', 'python']
        
        for cmd in python_commands:
            try:
                result = await self._run_command([cmd, '--version'])
                if result['returncode'] == 0 and 'Python 3' in result['stdout']:
                    return True
            except:
                continue
        
        return False
    
    async def _install_dependency(self, dep_name: str) -> bool:
        """Install a specific dependency.
        
        Args:
            dep_name: Name of the dependency to install
            
        Returns:
            True if installation successful
        """
        installer = self.install_methods.get(dep_name)
        if installer:
            return await installer()
        
        # Try generic package manager installation
        return await self._install_via_package_manager(dep_name)
    
    async def _install_go(self) -> bool:
        """Install Go programming language."""
        self.logger.info("Installing Go programming language")
        
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        try:
            if system == "linux":
                # Determine architecture
                if machine in ['x86_64', 'amd64']:
                    arch = 'amd64'
                elif machine in ['aarch64', 'arm64']:
                    arch = 'arm64'
                elif machine.startswith('arm'):
                    arch = 'armv6l'
                else:
                    arch = 'amd64'  # Default
                
                # Download and install Go
                go_version = "1.21.3"
                filename = f"go{go_version}.linux-{arch}.tar.gz"
                url = f"https://golang.org/dl/{filename}"
                
                commands = [
                    ['wget', url, '-O', f'/tmp/{filename}'],
                    ['sudo', 'rm', '-rf', '/usr/local/go'],
                    ['sudo', 'tar', '-C', '/usr/local', '-xzf', f'/tmp/{filename}'],
                    ['rm', f'/tmp/{filename}']
                ]
                
                for cmd in commands:
                    result = await self._run_command(cmd)
                    if result['returncode'] != 0:
                        self.logger.error(f"Go installation command failed: {' '.join(cmd)}")
                        return False
                
                # Add to PATH in profile
                profile_files = ['~/.profile', '~/.bashrc', '~/.zshrc']
                go_path_export = 'export PATH=$PATH:/usr/local/go/bin'
                
                for profile in profile_files:
                    try:
                        profile_path = Path(profile).expanduser()
                        if profile_path.exists():
                            with open(profile_path, 'r') as f:
                                content = f.read()
                            
                            if go_path_export not in content:
                                with open(profile_path, 'a') as f:
                                    f.write(f'\n# Added by VulnMiner\n{go_path_export}\n')
                    except Exception as e:
                        self.logger.debug(f"Could not update {profile}: {e}")
                
                return True
                
            elif system == "darwin":  # macOS
                # Try Homebrew first
                if shutil.which('brew'):
                    result = await self._run_command(['brew', 'install', 'go'])
                    return result['returncode'] == 0
                
                # Manual installation for macOS
                go_version = "1.21.3"
                if machine == 'arm64':
                    filename = f"go{go_version}.darwin-arm64.pkg"
                else:
                    filename = f"go{go_version}.darwin-amd64.pkg"
                
                url = f"https://golang.org/dl/{filename}"
                
                result = await self._run_command(['curl', '-L', url, '-o', f'/tmp/{filename}'])
                if result['returncode'] == 0:
                    result = await self._run_command(['sudo', 'installer', '-pkg', f'/tmp/{filename}', '-target', '/'])
                    return result['returncode'] == 0
                
            elif system == "windows":
                # Try chocolatey, scoop, or winget
                if shutil.which('choco'):
                    result = await self._run_command(['choco', 'install', 'golang', '-y'])
                    return result['returncode'] == 0
                elif shutil.which('scoop'):
                    result = await self._run_command(['scoop', 'install', 'go'])
                    return result['returncode'] == 0
                elif shutil.which('winget'):
                    result = await self._run_command(['winget', 'install', 'GoLang.Go'])
                    return result['returncode'] == 0
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to install Go: {e}")
            return False
    
    async def _install_python3(self) -> bool:
        """Install Python 3."""
        return await self._install_via_package_manager('python3')
    
    async def _install_nodejs(self) -> bool:
        """Install Node.js."""
        return await self._install_via_package_manager('nodejs')
    
    async def _install_git(self) -> bool:
        """Install Git."""
        return await self._install_via_package_manager('git')
    
    async def _install_via_package_manager(self, package_name: str) -> bool:
        """Install package via system package manager."""
        system = platform.system().lower()
        
        try:
            if system == "linux":
                # Try different package managers
                package_managers = [
                    (['apt', 'update'], ['apt', 'install', '-y', package_name]),
                    (['yum', 'install', '-y', package_name],),
                    (['pacman', '-S', '--noconfirm', package_name],),
                    (['zypper', 'install', '-y', package_name],)
                ]
                
                for commands in package_managers:
                    try:
                        pm_cmd = commands[0][0]
                        if not shutil.which(pm_cmd):
                            continue
                        
                        for cmd in commands:
                            result = await self._run_command(['sudo'] + cmd)
                            if result['returncode'] != 0:
                                break
                        else:
                            return True
                    except Exception:
                        continue
                        
            elif system == "darwin":
                if shutil.which('brew'):
                    result = await self._run_command(['brew', 'install', package_name])
                    return result['returncode'] == 0
                    
            elif system == "windows":
                if shutil.which('choco'):
                    result = await self._run_command(['choco', 'install', package_name, '-y'])
                    return result['returncode'] == 0
                elif shutil.which('scoop'):
                    result = await self._run_command(['scoop', 'install', package_name])
                    return result['returncode'] == 0
            
            return False
            
        except Exception as e:
            self.logger.error(f"Package manager installation failed for {package_name}: {e}")
            return False
    
    async def _run_command(self, cmd: List[str], timeout: int = 300) -> Dict[str, any]:
        """Run a system command."""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            return {
                'returncode': process.returncode,
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore')
            }
            
        except asyncio.TimeoutError:
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
    
    def get_dependency_graph(self) -> Dict[str, List[str]]:
        """Get the complete dependency graph."""
        return self.dependency_graph.copy()
    
    def add_tool_dependencies(self, tool_name: str, dependencies: List[str]) -> None:
        """Add dependencies for a tool.
        
        Args:
            tool_name: Name of the tool
            dependencies: List of dependency names
        """
        self.dependency_graph[tool_name] = dependencies
    
    async def get_system_info(self) -> Dict[str, any]:
        """Get system information relevant to dependency management."""
        system_info = {
            'platform': platform.system(),
            'machine': platform.machine(),
            'python_version': platform.python_version(),
            'available_package_managers': []
        }
        
        # Check available package managers
        package_managers = {
            'apt': ['apt', '--version'],
            'yum': ['yum', '--version'],
            'pacman': ['pacman', '--version'],
            'brew': ['brew', '--version'],
            'choco': ['choco', '--version'],
            'scoop': ['scoop', '--version'],
            'winget': ['winget', '--version']
        }
        
        for pm_name, version_cmd in package_managers.items():
            if shutil.which(pm_name):
                try:
                    result = await self._run_command(version_cmd)
                    if result['returncode'] == 0:
                        system_info['available_package_managers'].append(pm_name)
                except:
                    pass
        
        return system_info