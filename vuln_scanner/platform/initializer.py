"""Platform initialization system for cross-platform compatibility."""

import asyncio
import logging
import sys
import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from .detector import PlatformDetector, PlatformInfo, PlatformType
from .adapter import ConfigAdapter
from .filesystem import FileSystemAdapter
from .dependency_manager import DependencyManager
from .windows import WindowsUtils
from .colab import ColabUtils

logger = logging.getLogger(__name__)


@dataclass
class InitializationResult:
    """Result of platform initialization."""
    success: bool
    platform_info: PlatformInfo
    config: Dict[str, Any]
    actions_taken: List[str]
    warnings: List[str]
    errors: List[str]
    capabilities: Dict[str, Any]
    validation_results: Dict[str, Any]


class PlatformInitializer:
    """Comprehensive platform initialization and environment setup."""
    
    def __init__(self, config_overrides: Optional[Dict[str, Any]] = None):
        """Initialize platform initializer.
        
        Args:
            config_overrides: Optional configuration overrides
        """
        self.config_overrides = config_overrides or {}
        self.platform_info: Optional[PlatformInfo] = None
        self.config_adapter: Optional[ConfigAdapter] = None
        self.filesystem_adapter: Optional[FileSystemAdapter] = None
        self.dependency_manager: Optional[DependencyManager] = None
        
    async def initialize(self, 
                        install_dependencies: bool = True,
                        setup_environment: bool = True,
                        validate_environment: bool = True) -> InitializationResult:
        """Perform complete platform initialization.
        
        Args:
            install_dependencies: Whether to install required dependencies
            setup_environment: Whether to setup platform-specific environment
            validate_environment: Whether to validate the environment
            
        Returns:
            InitializationResult with complete initialization status
        """
        result = InitializationResult(
            success=False,
            platform_info=None,
            config={},
            actions_taken=[],
            warnings=[],
            errors=[],
            capabilities={},
            validation_results={}
        )
        
        try:
            logger.info("Starting platform initialization...")
            
            # Step 1: Detect platform
            result.platform_info = self._detect_platform()
            result.actions_taken.append(f"Detected platform: {result.platform_info.platform_type.value}")
            
            # Step 2: Initialize adapters
            await self._initialize_adapters(result)
            
            # Step 3: Setup platform-specific environment
            if setup_environment:
                await self._setup_platform_environment(result)
            
            # Step 4: Create necessary directories
            self._create_directories(result)
            
            # Step 5: Install dependencies
            if install_dependencies:
                await self._install_dependencies(result)
            
            # Step 6: Validate environment
            if validate_environment:
                await self._validate_environment(result)
            
            # Step 7: Get platform capabilities
            result.capabilities = PlatformDetector.get_platform_capabilities(result.platform_info)
            result.actions_taken.append("Determined platform capabilities")
            
            # Step 8: Finalize configuration
            result.config = self.config_adapter.to_dict()
            
            # Determine overall success
            result.success = len(result.errors) == 0
            
            if result.success:
                logger.info("Platform initialization completed successfully")
                result.actions_taken.append("Platform initialization completed")
            else:
                logger.error(f"Platform initialization failed with {len(result.errors)} errors")
            
        except Exception as e:
            logger.error(f"Critical error during platform initialization: {e}")
            result.errors.append(f"Critical initialization error: {e}")
            result.success = False
        
        return result
    
    def _detect_platform(self) -> PlatformInfo:
        """Detect and analyze current platform.
        
        Returns:
            PlatformInfo with complete platform details
        """
        logger.info("Detecting platform information...")
        platform_info = PlatformDetector.detect()
        
        logger.info(f"Platform detected: {platform_info.platform_type.value}")
        logger.info(f"OS: {platform_info.os_name} {platform_info.os_version}")
        logger.info(f"Python: {platform_info.python_version}")
        logger.info(f"CPU cores: {platform_info.cpu_count}")
        logger.info(f"Available memory: {platform_info.available_memory}MB")
        logger.info(f"GPU available: {platform_info.is_gpu_available}")
        logger.info(f"Admin privileges: {platform_info.is_admin}")
        
        return platform_info
    
    async def _initialize_adapters(self, result: InitializationResult) -> None:
        """Initialize platform adapters.
        
        Args:
            result: Initialization result to update
        """
        try:
            # Initialize configuration adapter
            self.config_adapter = ConfigAdapter(result.platform_info, self.config_overrides)
            result.actions_taken.append("Initialized configuration adapter")
            
            # Initialize filesystem adapter
            self.filesystem_adapter = FileSystemAdapter(result.platform_info)
            result.actions_taken.append("Initialized filesystem adapter")
            
            # Initialize dependency manager
            self.dependency_manager = DependencyManager(result.platform_info)
            result.actions_taken.append("Initialized dependency manager")
            
            self.platform_info = result.platform_info
            
        except Exception as e:
            error_msg = f"Failed to initialize adapters: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
    
    async def _setup_platform_environment(self, result: InitializationResult) -> None:
        """Setup platform-specific environment.
        
        Args:
            result: Initialization result to update
        """
        try:
            if result.platform_info.platform_type == PlatformType.COLAB:
                await self._setup_colab_environment(result)
            elif result.platform_info.platform_type == PlatformType.WINDOWS:
                await self._setup_windows_environment(result)
            elif result.platform_info.platform_type == PlatformType.LINUX:
                await self._setup_linux_environment(result)
            elif result.platform_info.platform_type == PlatformType.DOCKER:
                await self._setup_docker_environment(result)
            
        except Exception as e:
            error_msg = f"Failed to setup platform environment: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
    
    async def _setup_colab_environment(self, result: InitializationResult) -> None:
        """Setup Google Colab environment.
        
        Args:
            result: Initialization result to update
        """
        logger.info("Setting up Google Colab environment...")
        
        try:
            # Setup Colab environment
            colab_result = ColabUtils.setup_colab_environment(
                mount_drive=True,
                install_system_deps=True
            )
            
            result.actions_taken.extend(colab_result['actions_taken'])
            result.warnings.extend(colab_result['warnings'])
            if not colab_result['success']:
                result.errors.extend(colab_result['errors'])
            
            # Display setup message
            ColabUtils.display_message(
                "VulnMiner platform initialization in progress...", 
                "info"
            )
            
        except Exception as e:
            error_msg = f"Colab environment setup failed: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
    
    async def _setup_windows_environment(self, result: InitializationResult) -> None:
        """Setup Windows environment.
        
        Args:
            result: Initialization result to update
        """
        logger.info("Setting up Windows environment...")
        
        try:
            working_dir = self.config_adapter.get('output_dir')
            
            # Setup Windows environment
            windows_result = WindowsUtils.setup_windows_environment(working_dir)
            
            result.actions_taken.extend(windows_result['actions_taken'])
            result.warnings.extend(windows_result['warnings'])
            if not windows_result['success']:
                result.errors.extend(windows_result['errors'])
            
            # Check Windows-specific features
            features = WindowsUtils.check_required_features()
            missing_features = [k for k, v in features.items() if not v and k != 'admin_privileges']
            
            if missing_features:
                result.warnings.append(f"Missing Windows features: {', '.join(missing_features)}")
            
        except Exception as e:
            error_msg = f"Windows environment setup failed: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
    
    async def _setup_linux_environment(self, result: InitializationResult) -> None:
        """Setup Linux environment.
        
        Args:
            result: Initialization result to update
        """
        logger.info("Setting up Linux environment...")
        
        try:
            # Check for required system tools
            required_tools = ['curl', 'wget', 'unzip']
            missing_tools = []
            
            for tool in required_tools:
                try:
                    import subprocess
                    subprocess.run(['which', tool], check=True, capture_output=True)
                except subprocess.CalledProcessError:
                    missing_tools.append(tool)
            
            if missing_tools:
                result.warnings.append(f"Missing system tools: {', '.join(missing_tools)}")
            
            result.actions_taken.append("Linux environment checked")
            
        except Exception as e:
            error_msg = f"Linux environment setup failed: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
    
    async def _setup_docker_environment(self, result: InitializationResult) -> None:
        """Setup Docker container environment.
        
        Args:
            result: Initialization result to update
        """
        logger.info("Setting up Docker environment...")
        
        try:
            # Check if running as root (common in containers)
            is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
            
            if is_root:
                result.warnings.append("Running as root in container")
            
            # Check for Docker-specific environment variables
            if 'DOCKER_CONTAINER' in os.environ:
                result.actions_taken.append("Detected Docker container environment")
            
            result.actions_taken.append("Docker environment configured")
            
        except Exception as e:
            error_msg = f"Docker environment setup failed: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
    
    def _create_directories(self, result: InitializationResult) -> None:
        """Create necessary directories.
        
        Args:
            result: Initialization result to update
        """
        try:
            logger.info("Creating necessary directories...")
            
            config = self.config_adapter.config
            directories = [
                config.get('output_dir'),
                config.get('data_dir'),
                config.get('log_dir'),
                config.get('cache_dir'),
                os.path.join(config.get('output_dir', ''), 'reports'),
                os.path.join(config.get('output_dir', ''), 'screenshots'),
                os.path.join(config.get('output_dir', ''), 'raw_data')
            ]
            
            created_dirs = []
            for directory in directories:
                if directory and self.filesystem_adapter.create_directory(directory):
                    created_dirs.append(directory)
            
            if created_dirs:
                result.actions_taken.append(f"Created {len(created_dirs)} directories")
            
        except Exception as e:
            error_msg = f"Failed to create directories: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
    
    async def _install_dependencies(self, result: InitializationResult) -> None:
        """Install required dependencies.
        
        Args:
            result: Initialization result to update
        """
        try:
            logger.info("Installing dependencies...")
            
            # Install dependencies
            install_result = await self.dependency_manager.ensure_dependencies(
                force_reinstall=False,
                parallel=True
            )
            
            if install_result['success']:
                if install_result['installed']:
                    result.actions_taken.append(
                        f"Installed packages: {', '.join(install_result['installed'])}"
                    )
                if install_result['skipped']:
                    result.actions_taken.append(
                        f"Skipped packages: {', '.join(install_result['skipped'])}"
                    )
            else:
                if install_result['failed']:
                    result.errors.append(
                        f"Failed to install packages: {', '.join(install_result['failed'])}"
                    )
            
            # Update warnings
            result.warnings.extend(install_result.get('warnings', []))
            
        except Exception as e:
            error_msg = f"Dependency installation failed: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
    
    async def _validate_environment(self, result: InitializationResult) -> None:
        """Validate the environment meets requirements.
        
        Args:
            result: Initialization result to update
        """
        try:
            logger.info("Validating environment...")
            
            # Platform validation
            platform_validation = PlatformDetector.validate_environment(result.platform_info)
            result.validation_results['platform'] = platform_validation
            
            if not platform_validation['is_valid']:
                result.errors.extend(platform_validation['errors'])
            
            result.warnings.extend(platform_validation['warnings'])
            
            # Dependency validation
            dependency_validation = await self.dependency_manager.verify_installation()
            result.validation_results['dependencies'] = dependency_validation
            
            if not dependency_validation['success']:
                if dependency_validation['missing']:
                    result.errors.append(
                        f"Missing dependencies: {', '.join(dependency_validation['missing'])}"
                    )
                if dependency_validation['broken']:
                    result.errors.append(
                        f"Broken dependencies: {', '.join(dependency_validation['broken'])}"
                    )
            
            # Resource validation
            resource_validation = self._validate_resources(result.platform_info)
            result.validation_results['resources'] = resource_validation
            
            if not resource_validation['sufficient']:
                result.warnings.extend(resource_validation['warnings'])
            
            result.actions_taken.append("Environment validation completed")
            
        except Exception as e:
            error_msg = f"Environment validation failed: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
    
    def _validate_resources(self, platform_info: PlatformInfo) -> Dict[str, Any]:
        """Validate system resources.
        
        Args:
            platform_info: Platform information
            
        Returns:
            Dict with resource validation results
        """
        validation = {
            'sufficient': True,
            'warnings': [],
            'memory_check': True,
            'disk_check': True,
            'cpu_check': True
        }
        
        # Memory check
        min_memory_mb = 1024  # 1GB minimum
        if platform_info.available_memory < min_memory_mb:
            validation['sufficient'] = False
            validation['memory_check'] = False
            validation['warnings'].append(
                f"Low memory: {platform_info.available_memory}MB (minimum: {min_memory_mb}MB)"
            )
        
        # CPU check
        min_cpu_cores = 1
        if platform_info.cpu_count < min_cpu_cores:
            validation['sufficient'] = False
            validation['cpu_check'] = False
            validation['warnings'].append(
                f"Insufficient CPU cores: {platform_info.cpu_count} (minimum: {min_cpu_cores})"
            )
        
        # Disk space check
        try:
            working_dir = platform_info.working_directory
            available_space = self.filesystem_adapter.get_available_space(working_dir)
            
            if available_space != -1:
                min_space_bytes = 5 * 1024 * 1024 * 1024  # 5GB
                if available_space < min_space_bytes:
                    validation['sufficient'] = False
                    validation['disk_check'] = False
                    validation['warnings'].append(
                        f"Low disk space: {available_space // (1024**3)}GB (minimum: 5GB)"
                    )
        except Exception:
            validation['warnings'].append("Could not check disk space")
        
        return validation
    
    def get_platform_info(self) -> Optional[PlatformInfo]:
        """Get platform information.
        
        Returns:
            PlatformInfo if initialized, None otherwise
        """
        return self.platform_info
    
    def get_config(self) -> Optional[ConfigAdapter]:
        """Get configuration adapter.
        
        Returns:
            ConfigAdapter if initialized, None otherwise
        """
        return self.config_adapter
    
    def get_filesystem(self) -> Optional[FileSystemAdapter]:
        """Get filesystem adapter.
        
        Returns:
            FileSystemAdapter if initialized, None otherwise
        """
        return self.filesystem_adapter
    
    def get_dependency_manager(self) -> Optional[DependencyManager]:
        """Get dependency manager.
        
        Returns:
            DependencyManager if initialized, None otherwise
        """
        return self.dependency_manager
    
    async def quick_setup(self) -> bool:
        """Perform quick platform setup with minimal configuration.
        
        Returns:
            bool: True if successful
        """
        try:
            result = await self.initialize(
                install_dependencies=False,
                setup_environment=True,
                validate_environment=False
            )
            return result.success
        except Exception as e:
            logger.error(f"Quick setup failed: {e}")
            return False
    
    async def full_setup(self) -> InitializationResult:
        """Perform complete platform setup with all features.
        
        Returns:
            InitializationResult with complete setup status
        """
        return await self.initialize(
            install_dependencies=True,
            setup_environment=True,
            validate_environment=True
        )
    
    def create_platform_report(self) -> Dict[str, Any]:
        """Create comprehensive platform report.
        
        Returns:
            Dict with platform analysis and recommendations
        """
        if not self.platform_info:
            return {'error': 'Platform not initialized'}
        
        report = {
            'platform_info': {
                'type': self.platform_info.platform_type.value,
                'os': f"{self.platform_info.os_name} {self.platform_info.os_version}",
                'python_version': self.platform_info.python_version,
                'architecture': self.platform_info.architecture,
                'cpu_cores': self.platform_info.cpu_count,
                'memory_mb': self.platform_info.available_memory,
                'gpu_available': self.platform_info.is_gpu_available,
                'admin_privileges': self.platform_info.is_admin,
                'notebook_environment': self.platform_info.is_notebook
            },
            'capabilities': {},
            'recommendations': [],
            'limitations': []
        }
        
        # Add capabilities
        if self.platform_info:
            report['capabilities'] = PlatformDetector.get_platform_capabilities(self.platform_info)
        
        # Add platform-specific recommendations
        if self.platform_info.platform_type == PlatformType.COLAB:
            report['recommendations'].extend([
                "Mount Google Drive for persistent storage",
                "Use progress widgets for better user experience",
                "Save results to Drive before session expires"
            ])
            report['limitations'].extend([
                "Session timeout (12 hours)",
                "Limited CPU and memory",
                "No persistent local storage"
            ])
        elif self.platform_info.platform_type == PlatformType.WINDOWS:
            if not self.platform_info.is_admin:
                report['recommendations'].append("Consider running as administrator for full functionality")
            report['recommendations'].append("Add Windows Defender exclusions for working directory")
        
        if not self.platform_info.is_gpu_available:
            report['recommendations'].append("Consider enabling GPU acceleration for better performance")
        
        if self.platform_info.available_memory < 4096:
            report['recommendations'].append("Consider increasing available memory for better performance")
        
        return report