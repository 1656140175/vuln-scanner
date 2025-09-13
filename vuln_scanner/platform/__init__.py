"""Platform-specific modules for cross-platform compatibility."""

from .detector import PlatformDetector, PlatformInfo, PlatformType
from .adapter import ConfigAdapter
from .filesystem import FileSystemAdapter
from .dependency_manager import DependencyManager
from .initializer import PlatformInitializer

__all__ = [
    'PlatformDetector',
    'PlatformInfo', 
    'PlatformType',
    'ConfigAdapter',
    'FileSystemAdapter',
    'DependencyManager',
    'PlatformInitializer'
]