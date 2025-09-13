"""Cross-platform dependency management system."""

import asyncio
import subprocess
import sys
import os
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import tempfile

from .detector import PlatformInfo, PlatformType

logger = logging.getLogger(__name__)


class PackageManager(Enum):
    """Supported package managers."""
    PIP = "pip"
    CONDA = "conda"
    APT = "apt"
    CHOCOLATEY = "choco"
    SYSTEM = "system"


@dataclass
class PackageRequirement:
    """Package requirement specification."""
    name: str
    version: Optional[str] = None
    platform_specific: bool = False
    required_platforms: Optional[List[PlatformType]] = None
    package_manager: PackageManager = PackageManager.PIP
    install_command: Optional[str] = None
    check_command: Optional[str] = None
    description: Optional[str] = None


class DependencyManager:
    """Cross-platform dependency management and installation."""
    
    def __init__(self, platform_info: PlatformInfo):
        """Initialize dependency manager.
        
        Args:
            platform_info: Platform information
        """
        self.platform_info = platform_info
        self.installed_packages: Dict[str, bool] = {}
        self.failed_packages: List[str] = []
        
    def get_required_packages(self) -> List[PackageRequirement]:
        """Get list of required packages for the platform.
        
        Returns:
            List of package requirements
        """
        # Core Python packages (all platforms)
        base_packages = [
            PackageRequirement(
                name="requests",
                version=">=2.25.0",
                description="HTTP library for API requests"
            ),
            PackageRequirement(
                name="aiohttp",
                version=">=3.8.0",
                description="Async HTTP client/server"
            ),
            PackageRequirement(
                name="beautifulsoup4",
                version=">=4.9.0",
                description="HTML/XML parser"
            ),
            PackageRequirement(
                name="lxml",
                version=">=4.6.0",
                description="XML/HTML processing"
            ),
            PackageRequirement(
                name="selenium",
                version=">=4.0.0",
                description="Web browser automation"
            ),
            PackageRequirement(
                name="numpy",
                version=">=1.21.0",
                description="Numerical computing"
            ),
            PackageRequirement(
                name="pandas",
                version=">=1.3.0",
                description="Data analysis and manipulation"
            ),
            PackageRequirement(
                name="scikit-learn",
                version=">=1.0.0",
                description="Machine learning library"
            ),
            PackageRequirement(
                name="psutil",
                version=">=5.8.0",
                description="System and process utilities"
            ),
            PackageRequirement(
                name="pyyaml",
                version=">=5.4.0",
                description="YAML parser and emitter"
            ),
            PackageRequirement(
                name="python-dotenv",
                version=">=0.19.0",
                description="Environment variable management"
            ),
            PackageRequirement(
                name="colorama",
                version=">=0.4.4",
                description="Cross-platform colored terminal text"
            ),
            PackageRequirement(
                name="tqdm",
                version=">=4.62.0",
                description="Progress bars"
            )
        ]
        
        # Platform-specific packages
        platform_packages = []
        
        if self.platform_info.platform_type == PlatformType.WINDOWS:
            platform_packages.extend([
                PackageRequirement(
                    name="pywin32",
                    version=">=227",
                    platform_specific=True,
                    required_platforms=[PlatformType.WINDOWS],
                    description="Windows API access"
                ),
                PackageRequirement(
                    name="wmi",
                    version=">=1.5.1",
                    platform_specific=True,
                    required_platforms=[PlatformType.WINDOWS],
                    description="Windows Management Instrumentation"
                )
            ])
        
        elif self.platform_info.platform_type == PlatformType.COLAB:
            platform_packages.extend([
                PackageRequirement(
                    name="google-colab",
                    version=">=1.0.0",
                    platform_specific=True,
                    required_platforms=[PlatformType.COLAB],
                    description="Google Colab integration"
                ),
                PackageRequirement(
                    name="ipywidgets",
                    version=">=7.6.0",
                    platform_specific=True,
                    required_platforms=[PlatformType.COLAB],
                    description="Interactive Jupyter widgets"
                )
            ])
        
        # Optional GPU packages
        if self.platform_info.is_gpu_available:
            gpu_packages = [
                PackageRequirement(
                    name="torch",
                    version=">=1.9.0",
                    description="PyTorch deep learning framework"
                ),
                PackageRequirement(
                    name="torchvision",
                    version=">=0.10.0", 
                    description="PyTorch computer vision"
                )
            ]
            platform_packages.extend(gpu_packages)
        
        return base_packages + platform_packages
    
    async def ensure_dependencies(self, 
                                 force_reinstall: bool = False,
                                 parallel: bool = True) -> Dict[str, Any]:
        """Ensure all required dependencies are installed.
        
        Args:
            force_reinstall: Force reinstallation of packages
            parallel: Install packages in parallel when possible
            
        Returns:
            Dict with installation results
        """
        results = {
            'success': True,
            'installed': [],
            'failed': [],
            'skipped': [],
            'warnings': []
        }
        
        required_packages = self.get_required_packages()
        logger.info(f"Checking {len(required_packages)} dependencies...")
        
        # Filter packages for current platform
        relevant_packages = []
        for pkg in required_packages:
            if pkg.platform_specific:
                if pkg.required_platforms and self.platform_info.platform_type not in pkg.required_platforms:
                    results['skipped'].append(f"{pkg.name} (not needed on {self.platform_info.platform_type.value})")
                    continue
            relevant_packages.append(pkg)
        
        logger.info(f"Installing {len(relevant_packages)} relevant packages...")
        
        if parallel and len(relevant_packages) > 1:
            # Install packages in parallel
            semaphore = asyncio.Semaphore(4)  # Limit concurrent installations
            
            async def install_with_semaphore(pkg):
                async with semaphore:
                    return await self._install_package_async(pkg, force_reinstall)
            
            install_tasks = [install_with_semaphore(pkg) for pkg in relevant_packages]
            install_results = await asyncio.gather(*install_tasks, return_exceptions=True)
            
            for pkg, result in zip(relevant_packages, install_results):
                if isinstance(result, Exception):
                    logger.error(f"Exception installing {pkg.name}: {result}")
                    results['failed'].append(pkg.name)
                    results['success'] = False
                elif result:
                    results['installed'].append(pkg.name)
                else:
                    results['failed'].append(pkg.name)
                    results['success'] = False
        else:
            # Install packages sequentially
            for pkg in relevant_packages:
                success = await self._install_package_async(pkg, force_reinstall)
                if success:
                    results['installed'].append(pkg.name)
                else:
                    results['failed'].append(pkg.name)
                    results['success'] = False
        
        # Log summary
        if results['installed']:
            logger.info(f"Successfully installed: {', '.join(results['installed'])}")
        if results['failed']:
            logger.error(f"Failed to install: {', '.join(results['failed'])}")
        if results['skipped']:
            logger.debug(f"Skipped: {', '.join(results['skipped'])}")
        
        return results
    
    async def _install_package_async(self, 
                                   package: PackageRequirement, 
                                   force_reinstall: bool = False) -> bool:
        """Install a single package asynchronously.
        
        Args:
            package: Package requirement
            force_reinstall: Force reinstallation
            
        Returns:
            bool: True if successful
        """
        # Check if already installed (unless force reinstall)
        if not force_reinstall:
            if await self._is_package_available(package):
                logger.debug(f"{package.name} is already available")
                return True
        
        logger.info(f"Installing {package.name}{f' {package.version}' if package.version else ''}...")
        
        try:
            if package.install_command:
                # Use custom install command
                return await self._run_custom_install(package)
            else:
                # Use package manager
                return await self._install_with_package_manager(package)
                
        except Exception as e:
            logger.error(f"Failed to install {package.name}: {e}")
            return False
    
    async def _is_package_available(self, package: PackageRequirement) -> bool:
        """Check if package is available/installed.
        
        Args:
            package: Package requirement
            
        Returns:
            bool: True if available
        """
        if package.check_command:
            # Use custom check command
            try:
                process = await asyncio.create_subprocess_shell(
                    package.check_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                return process.returncode == 0
            except Exception:
                return False
        
        # Default: try to import the package
        try:
            if package.package_manager == PackageManager.PIP:
                # For pip packages, try importing
                import importlib
                # Convert package name to import name (basic conversion)
                import_name = package.name.lower().replace('-', '_')
                
                # Special cases for common packages
                import_mappings = {
                    'beautifulsoup4': 'bs4',
                    'pillow': 'PIL',
                    'pyyaml': 'yaml',
                    'python-dotenv': 'dotenv',
                    'scikit-learn': 'sklearn'
                }
                
                import_name = import_mappings.get(package.name, import_name)
                importlib.import_module(import_name)
                return True
        except ImportError:
            pass
        
        return False
    
    async def _install_with_package_manager(self, package: PackageRequirement) -> bool:
        """Install package using appropriate package manager.
        
        Args:
            package: Package requirement
            
        Returns:
            bool: True if successful
        """
        if package.package_manager == PackageManager.PIP:
            return await self._install_pip_package(package)
        elif package.package_manager == PackageManager.APT:
            return await self._install_apt_package(package)
        elif package.package_manager == PackageManager.CHOCOLATEY:
            return await self._install_chocolatey_package(package)
        else:
            logger.error(f"Unsupported package manager: {package.package_manager}")
            return False
    
    async def _install_pip_package(self, package: PackageRequirement) -> bool:
        """Install Python package using pip.
        
        Args:
            package: Package requirement
            
        Returns:
            bool: True if successful
        """
        try:
            package_spec = package.name
            if package.version:
                package_spec += package.version
            
            cmd = [sys.executable, '-m', 'pip', 'install', package_spec]
            
            # Add platform-specific options
            if self.platform_info.platform_type == PlatformType.COLAB:
                cmd.append('--quiet')
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.debug(f"Successfully installed {package.name}")
                return True
            else:
                logger.error(f"pip install failed for {package.name}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error running pip for {package.name}: {e}")
            return False
    
    async def _install_apt_package(self, package: PackageRequirement) -> bool:
        """Install system package using apt (Linux/Colab).
        
        Args:
            package: Package requirement
            
        Returns:
            bool: True if successful
        """
        if self.platform_info.platform_type not in [PlatformType.LINUX, PlatformType.COLAB]:
            logger.warning(f"apt not available on {self.platform_info.platform_type}")
            return False
        
        try:
            cmd = ['apt-get', 'install', '-y', package.name]
            
            # Add quiet flag for Colab
            if self.platform_info.platform_type == PlatformType.COLAB:
                cmd.insert(2, '-qq')
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.debug(f"Successfully installed {package.name} via apt")
                return True
            else:
                logger.error(f"apt install failed for {package.name}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error running apt for {package.name}: {e}")
            return False
    
    async def _install_chocolatey_package(self, package: PackageRequirement) -> bool:
        """Install package using Chocolatey (Windows).
        
        Args:
            package: Package requirement
            
        Returns:
            bool: True if successful
        """
        if self.platform_info.platform_type != PlatformType.WINDOWS:
            logger.warning(f"Chocolatey not available on {self.platform_info.platform_type}")
            return False
        
        try:
            cmd = ['choco', 'install', package.name, '-y']
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.debug(f"Successfully installed {package.name} via Chocolatey")
                return True
            else:
                logger.error(f"Chocolatey install failed for {package.name}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error running Chocolatey for {package.name}: {e}")
            return False
    
    async def _run_custom_install(self, package: PackageRequirement) -> bool:
        """Run custom installation command.
        
        Args:
            package: Package requirement with custom install command
            
        Returns:
            bool: True if successful
        """
        if not package.install_command:
            return False
        
        try:
            process = await asyncio.create_subprocess_shell(
                package.install_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.debug(f"Successfully ran custom install for {package.name}")
                return True
            else:
                logger.error(f"Custom install failed for {package.name}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error running custom install for {package.name}: {e}")
            return False
    
    def get_installed_packages(self) -> Dict[str, str]:
        """Get list of currently installed Python packages.
        
        Returns:
            Dict mapping package names to versions
        """
        installed = {}
        
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'list', '--format=json'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                import json
                packages = json.loads(result.stdout)
                for pkg in packages:
                    installed[pkg['name'].lower()] = pkg['version']
            
        except Exception as e:
            logger.error(f"Failed to get installed packages: {e}")
        
        return installed
    
    def create_requirements_file(self, file_path: str) -> bool:
        """Create requirements.txt file with current dependencies.
        
        Args:
            file_path: Path to requirements file
            
        Returns:
            bool: True if successful
        """
        try:
            requirements = self.get_required_packages()
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("# VulnMiner Dependencies\\n")
                f.write("# Generated automatically\\n\\n")
                
                for req in requirements:
                    if not req.platform_specific:
                        line = req.name
                        if req.version:
                            line += req.version
                        if req.description:
                            line += f"  # {req.description}"
                        f.write(line + "\\n")
                
                # Platform-specific sections
                platforms = set()
                for req in requirements:
                    if req.platform_specific and req.required_platforms:
                        platforms.update(req.required_platforms)
                
                for platform in platforms:
                    f.write(f"\\n# {platform.value.title()} specific packages\\n")
                    for req in requirements:
                        if (req.platform_specific and 
                            req.required_platforms and 
                            platform in req.required_platforms):
                            
                            line = req.name
                            if req.version:
                                line += req.version
                            if req.description:
                                line += f"  # {req.description}"
                            f.write(line + "\\n")
            
            logger.info(f"Created requirements file: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create requirements file: {e}")
            return False
    
    async def verify_installation(self) -> Dict[str, Any]:
        """Verify that all required packages are properly installed.
        
        Returns:
            Dict with verification results
        """
        results = {
            'verified': [],
            'missing': [],
            'broken': [],
            'success': True
        }
        
        required_packages = self.get_required_packages()
        
        for package in required_packages:
            # Skip platform-specific packages not relevant to current platform
            if package.platform_specific:
                if (package.required_platforms and 
                    self.platform_info.platform_type not in package.required_platforms):
                    continue
            
            try:
                if await self._is_package_available(package):
                    results['verified'].append(package.name)
                else:
                    results['missing'].append(package.name)
                    results['success'] = False
                    
            except Exception as e:
                logger.error(f"Error verifying {package.name}: {e}")
                results['broken'].append(package.name)
                results['success'] = False
        
        return results