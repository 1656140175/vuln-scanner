"""Platform detection system for cross-platform compatibility."""

import platform
import sys
import os
import tempfile
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class PlatformType(Enum):
    """Supported platform types."""
    WINDOWS = "windows"
    COLAB = "colab"
    LINUX = "linux"
    DOCKER = "docker"
    UNKNOWN = "unknown"


@dataclass
class PlatformInfo:
    """Platform information data class."""
    platform_type: PlatformType
    os_name: str
    os_version: str
    python_version: str
    is_gpu_available: bool
    available_memory: int  # MB
    cpu_count: int
    is_notebook: bool
    working_directory: str
    temp_directory: str
    is_admin: bool = False
    architecture: str = ""


class PlatformDetector:
    """Platform detection and system information gathering."""
    
    @staticmethod
    def detect() -> PlatformInfo:
        """Detect current running platform and gather system information.
        
        Returns:
            PlatformInfo: Complete platform information
        """
        platform_type = PlatformDetector._detect_platform_type()
        
        return PlatformInfo(
            platform_type=platform_type,
            os_name=platform.system(),
            os_version=platform.version(),
            python_version=sys.version.split()[0],
            is_gpu_available=PlatformDetector._check_gpu_availability(),
            available_memory=PlatformDetector._get_available_memory(),
            cpu_count=os.cpu_count() or 1,
            is_notebook=PlatformDetector._is_running_in_notebook(),
            working_directory=os.getcwd(),
            temp_directory=PlatformDetector._get_temp_directory(),
            is_admin=PlatformDetector._check_admin_privileges(),
            architecture=platform.machine()
        )
    
    @staticmethod
    def _detect_platform_type() -> PlatformType:
        """Detect platform type with comprehensive checks.
        
        Returns:
            PlatformType: Detected platform type
        """
        # Check for Google Colab first (most specific)
        if PlatformDetector._is_colab():
            return PlatformType.COLAB
        
        # Check for Docker environment
        if PlatformDetector._is_docker():
            return PlatformType.DOCKER
        
        # Check operating system
        system = platform.system().lower()
        if system == 'windows':
            return PlatformType.WINDOWS
        elif system in ['linux', 'darwin']:
            return PlatformType.LINUX
        
        return PlatformType.UNKNOWN
    
    @staticmethod
    def _is_colab() -> bool:
        """Check if running in Google Colab.
        
        Returns:
            bool: True if running in Colab
        """
        try:
            import google.colab  # noqa: F401
            return True
        except ImportError:
            pass
        
        # Additional check for Colab environment variables
        return 'COLAB_GPU' in os.environ or 'COLAB_RELEASE_TAG' in os.environ
    
    @staticmethod
    def _is_docker() -> bool:
        """Check if running in Docker container.
        
        Returns:
            bool: True if running in Docker
        """
        # Check for Docker-specific files
        docker_indicators = [
            '/.dockerenv',
            '/proc/1/cgroup'  # Will contain 'docker' if in container
        ]
        
        for indicator in docker_indicators:
            if os.path.exists(indicator):
                if indicator.endswith('cgroup'):
                    try:
                        with open(indicator, 'r') as f:
                            content = f.read()
                            if 'docker' in content or 'containerd' in content:
                                return True
                    except Exception:
                        pass
                else:
                    return True
        
        # Check environment variables
        return 'DOCKER_CONTAINER' in os.environ
    
    @staticmethod
    def _check_gpu_availability() -> bool:
        """Check GPU availability across different frameworks.
        
        Returns:
            bool: True if GPU is available
        """
        # Try PyTorch first
        try:
            import torch
            if torch.cuda.is_available():
                return True
        except ImportError:
            pass
        
        # Try TensorFlow
        try:
            import tensorflow as tf
            gpus = tf.config.experimental.list_physical_devices('GPU')
            if len(gpus) > 0:
                return True
        except ImportError:
            pass
        
        # Check NVIDIA-ML for NVIDIA GPUs
        try:
            import pynvml
            pynvml.nvmlInit()
            device_count = pynvml.nvmlDeviceGetCount()
            return device_count > 0
        except ImportError:
            pass
        
        return False
    
    @staticmethod
    def _get_available_memory() -> int:
        """Get available system memory in MB.
        
        Returns:
            int: Available memory in MB
        """
        try:
            import psutil
            memory = psutil.virtual_memory()
            return memory.available // (1024 * 1024)
        except ImportError:
            pass
        
        # Fallback for systems without psutil
        try:
            if platform.system() == 'Linux':
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemAvailable:'):
                            # MemAvailable is in KB, convert to MB
                            return int(line.split()[1]) // 1024
        except Exception:
            pass
        
        # Default fallback
        return 2048  # Assume 2GB minimum
    
    @staticmethod
    def _is_running_in_notebook() -> bool:
        """Check if code is running in a Jupyter notebook or similar.
        
        Returns:
            bool: True if running in notebook environment
        """
        try:
            # Check for IPython kernel
            from IPython import get_ipython
            ipython = get_ipython()
            if ipython is not None:
                # Check if it's a kernel (notebook) or terminal IPython
                return hasattr(ipython, 'kernel')
        except ImportError:
            pass
        
        # Check for notebook-specific environment variables
        notebook_indicators = [
            'JUPYTER_RUNTIME_DIR',
            'JUPYTER_CONFIG_DIR',
            'COLAB_GPU'
        ]
        
        return any(indicator in os.environ for indicator in notebook_indicators)
    
    @staticmethod
    def _get_temp_directory() -> str:
        """Get system temporary directory.
        
        Returns:
            str: Path to temporary directory
        """
        return tempfile.gettempdir()
    
    @staticmethod
    def _check_admin_privileges() -> bool:
        """Check if running with administrator/root privileges.
        
        Returns:
            bool: True if running with elevated privileges
        """
        try:
            if platform.system() == 'Windows':
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            else:
                # Unix-like systems
                return os.geteuid() == 0
        except Exception:
            return False
    
    @classmethod
    def get_platform_capabilities(cls, platform_info: PlatformInfo) -> Dict[str, Any]:
        """Get platform-specific capabilities and limitations.
        
        Args:
            platform_info: Platform information
            
        Returns:
            Dict containing platform capabilities
        """
        capabilities = {
            'supports_multiprocessing': True,
            'supports_threading': True,
            'supports_gpu': platform_info.is_gpu_available,
            'supports_selenium': True,
            'supports_system_tools': False,
            'max_memory_mb': platform_info.available_memory,
            'temp_space_available': True,
            'network_access': True,
            'file_system_access': True
        }
        
        # Platform-specific adjustments
        if platform_info.platform_type == PlatformType.COLAB:
            capabilities.update({
                'supports_apt_install': True,
                'supports_drive_mount': True,
                'session_persistent': False,
                'supports_widgets': True,
                'default_timeout': 12 * 3600,  # 12 hours
                'supports_system_tools': True
            })
        elif platform_info.platform_type == PlatformType.WINDOWS:
            capabilities.update({
                'supports_powershell': True,
                'supports_wmi': True,
                'path_length_limit': 260,
                'supports_symlinks': platform_info.is_admin,
                'supports_system_tools': platform_info.is_admin
            })
        elif platform_info.platform_type == PlatformType.LINUX:
            capabilities.update({
                'supports_apt_install': platform_info.is_admin,
                'supports_systemctl': platform_info.is_admin,
                'supports_package_managers': True,
                'supports_system_tools': True
            })
        
        return capabilities
    
    @classmethod
    def validate_environment(cls, platform_info: PlatformInfo) -> Dict[str, Any]:
        """Validate if environment meets minimum requirements.
        
        Args:
            platform_info: Platform information
            
        Returns:
            Dict containing validation results
        """
        validation = {
            'is_valid': True,
            'warnings': [],
            'errors': [],
            'recommendations': []
        }
        
        # Python version check
        python_version = tuple(map(int, platform_info.python_version.split('.')[:2]))
        if python_version < (3, 8):
            validation['errors'].append(
                f"Python {platform_info.python_version} is not supported. Requires Python 3.8+"
            )
            validation['is_valid'] = False
        
        # Memory check
        min_memory_mb = 1024  # 1GB minimum
        if platform_info.available_memory < min_memory_mb:
            validation['warnings'].append(
                f"Low available memory: {platform_info.available_memory}MB (recommended: {min_memory_mb}MB+)"
            )
        
        # Platform-specific validations
        if platform_info.platform_type == PlatformType.WINDOWS:
            if not platform_info.is_admin:
                validation['warnings'].append(
                    "Running without administrator privileges may limit some functionality"
                )
        elif platform_info.platform_type == PlatformType.UNKNOWN:
            validation['warnings'].append(
                "Unknown platform detected. Some features may not work correctly"
            )
        
        # Add recommendations
        if not platform_info.is_gpu_available:
            validation['recommendations'].append(
                "GPU not detected. Consider enabling GPU acceleration for better performance"
            )
        
        return validation