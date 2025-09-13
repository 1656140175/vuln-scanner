"""Platform utilities for cross-platform compatibility."""

import os
import sys
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path

# Import platform modules
from ..platform.detector import PlatformDetector, PlatformInfo, PlatformType
from ..platform.initializer import PlatformInitializer
from ..platform.adapter import ConfigAdapter
from ..platform.filesystem import FileSystemAdapter

logger = logging.getLogger(__name__)

# Global platform instance
_platform_instance: Optional[PlatformInitializer] = None


def initialize_platform(config_overrides: Optional[Dict[str, Any]] = None) -> bool:
    """Initialize platform compatibility layer.
    
    Args:
        config_overrides: Optional configuration overrides
        
    Returns:
        bool: True if initialization successful
    """
    global _platform_instance
    
    try:
        _platform_instance = PlatformInitializer(config_overrides)
        
        # Run quick setup for immediate compatibility
        import asyncio
        result = asyncio.run(_platform_instance.quick_setup())
        
        if result:
            logger.info("Platform compatibility layer initialized successfully")
        else:
            logger.error("Platform initialization failed")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to initialize platform: {e}")
        return False


async def initialize_platform_async(config_overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Initialize platform compatibility layer asynchronously.
    
    Args:
        config_overrides: Optional configuration overrides
        
    Returns:
        Dict with initialization results
    """
    global _platform_instance
    
    try:
        _platform_instance = PlatformInitializer(config_overrides)
        result = await _platform_instance.full_setup()
        
        return {
            'success': result.success,
            'platform': result.platform_info.platform_type.value if result.platform_info else 'unknown',
            'actions_taken': result.actions_taken,
            'warnings': result.warnings,
            'errors': result.errors
        }
        
    except Exception as e:
        logger.error(f"Failed to initialize platform: {e}")
        return {
            'success': False,
            'platform': 'unknown',
            'actions_taken': [],
            'warnings': [],
            'errors': [str(e)]
        }


def get_platform_info() -> Optional[PlatformInfo]:
    """Get current platform information.
    
    Returns:
        PlatformInfo if available, None otherwise
    """
    if _platform_instance:
        return _platform_instance.get_platform_info()
    
    # Fallback to direct detection
    try:
        return PlatformDetector.detect()
    except Exception as e:
        logger.error(f"Failed to detect platform: {e}")
        return None


def get_platform_type() -> PlatformType:
    """Get current platform type.
    
    Returns:
        PlatformType enum value
    """
    info = get_platform_info()
    return info.platform_type if info else PlatformType.UNKNOWN


def is_windows() -> bool:
    """Check if running on Windows.
    
    Returns:
        bool: True if Windows
    """
    return get_platform_type() == PlatformType.WINDOWS


def is_colab() -> bool:
    """Check if running in Google Colab.
    
    Returns:
        bool: True if Colab
    """
    return get_platform_type() == PlatformType.COLAB


def is_linux() -> bool:
    """Check if running on Linux.
    
    Returns:
        bool: True if Linux
    """
    return get_platform_type() == PlatformType.LINUX


def is_docker() -> bool:
    """Check if running in Docker.
    
    Returns:
        bool: True if Docker
    """
    return get_platform_type() == PlatformType.DOCKER


def get_config_adapter() -> Optional[ConfigAdapter]:
    """Get platform configuration adapter.
    
    Returns:
        ConfigAdapter if available, None otherwise
    """
    if _platform_instance:
        return _platform_instance.get_config()
    return None


def get_filesystem_adapter() -> Optional[FileSystemAdapter]:
    """Get platform filesystem adapter.
    
    Returns:
        FileSystemAdapter if available, None otherwise
    """
    if _platform_instance:
        return _platform_instance.get_filesystem()
    return None


def get_config_value(key: str, default: Any = None) -> Any:
    """Get platform-specific configuration value.
    
    Args:
        key: Configuration key
        default: Default value if not found
        
    Returns:
        Configuration value or default
    """
    adapter = get_config_adapter()
    if adapter:
        return adapter.get(key, default)
    return default


def safe_path_join(*parts: str) -> str:
    """Join path components safely for current platform.
    
    Args:
        *parts: Path components
        
    Returns:
        str: Platform-appropriate joined path
    """
    filesystem = get_filesystem_adapter()
    if filesystem:
        return filesystem.safe_path_join(*parts)
    
    # Fallback to standard os.path.join
    return os.path.join(*parts)


def normalize_path(path: str) -> str:
    """Normalize path for current platform.
    
    Args:
        path: Path to normalize
        
    Returns:
        str: Normalized path
    """
    filesystem = get_filesystem_adapter()
    if filesystem:
        return filesystem.normalize_path(path)
    
    # Fallback to os.path.normpath
    return os.path.normpath(path)


def create_directory(path: str, exist_ok: bool = True) -> bool:
    """Create directory safely on current platform.
    
    Args:
        path: Directory path
        exist_ok: Don't raise error if exists
        
    Returns:
        bool: True if successful
    """
    filesystem = get_filesystem_adapter()
    if filesystem:
        return filesystem.create_directory(path, exist_ok=exist_ok)
    
    # Fallback to os.makedirs
    try:
        os.makedirs(path, exist_ok=exist_ok)
        return True
    except Exception as e:
        logger.error(f"Failed to create directory {path}: {e}")
        return False


def get_temp_directory() -> str:
    """Get temporary directory for current platform.
    
    Returns:
        str: Temporary directory path
    """
    filesystem = get_filesystem_adapter()
    if filesystem:
        return filesystem.get_temp_directory()
    
    # Fallback to tempfile
    import tempfile
    return tempfile.gettempdir()


def get_output_directory() -> str:
    """Get output directory for current platform.
    
    Returns:
        str: Output directory path
    """
    return get_config_value('output_dir', os.path.join(os.getcwd(), 'output'))


def get_data_directory() -> str:
    """Get data directory for current platform.
    
    Returns:
        str: Data directory path
    """
    return get_config_value('data_dir', os.path.join(os.getcwd(), 'data'))


def get_log_directory() -> str:
    """Get log directory for current platform.
    
    Returns:
        str: Log directory path
    """
    return get_config_value('log_dir', os.path.join(os.getcwd(), 'logs'))


def setup_logging(log_level: str = "INFO") -> bool:
    """Setup platform-appropriate logging.
    
    Args:
        log_level: Logging level
        
    Returns:
        bool: True if successful
    """
    try:
        # Configure logging format based on platform
        log_format = get_config_value(
            'log_format', 
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Setup basic logging
        logging.basicConfig(
            level=getattr(logging, log_level.upper(), logging.INFO),
            format=log_format,
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        
        # Add file handler if log directory is available
        log_dir = get_log_directory()
        if log_dir and create_directory(log_dir):
            log_file = safe_path_join(log_dir, 'vuln_scanner.log')
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter(log_format))
            logging.getLogger().addHandler(file_handler)
        
        logger.info("Logging configured successfully")
        return True
        
    except Exception as e:
        print(f"Failed to setup logging: {e}")
        return False


def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system information.
    
    Returns:
        Dict with system information
    """
    info = get_platform_info()
    if not info:
        return {}
    
    return {
        'platform_type': info.platform_type.value,
        'os_name': info.os_name,
        'os_version': info.os_version,
        'python_version': info.python_version,
        'cpu_count': info.cpu_count,
        'available_memory_mb': info.available_memory,
        'gpu_available': info.is_gpu_available,
        'admin_privileges': info.is_admin,
        'notebook_environment': info.is_notebook,
        'working_directory': info.working_directory,
        'temp_directory': info.temp_directory,
        'architecture': info.architecture
    }


def get_platform_capabilities() -> Dict[str, Any]:
    """Get platform capabilities.
    
    Returns:
        Dict with platform capabilities
    """
    info = get_platform_info()
    if not info:
        return {}
    
    return PlatformDetector.get_platform_capabilities(info)


def validate_environment() -> Dict[str, Any]:
    """Validate current environment.
    
    Returns:
        Dict with validation results
    """
    info = get_platform_info()
    if not info:
        return {'valid': False, 'error': 'Platform not detected'}
    
    return PlatformDetector.validate_environment(info)


def display_platform_info() -> None:
    """Display platform information in a user-friendly format."""
    info = get_system_info()
    
    if not info:
        print("Platform information not available")
        return
    
    print("\\n" + "="*50)
    print("PLATFORM INFORMATION")
    print("="*50)
    print(f"Platform Type: {info['platform_type']}")
    print(f"Operating System: {info['os_name']} {info['os_version']}")
    print(f"Python Version: {info['python_version']}")
    print(f"Architecture: {info['architecture']}")
    print(f"CPU Cores: {info['cpu_count']}")
    print(f"Available Memory: {info['available_memory_mb']}MB")
    print(f"GPU Available: {'Yes' if info['gpu_available'] else 'No'}")
    print(f"Admin Privileges: {'Yes' if info['admin_privileges'] else 'No'}")
    print(f"Notebook Environment: {'Yes' if info['notebook_environment'] else 'No'}")
    print(f"Working Directory: {info['working_directory']}")
    print("="*50)
    
    # Display capabilities
    capabilities = get_platform_capabilities()
    if capabilities:
        print("\\nPLATFORM CAPABILITIES")
        print("-"*30)
        for key, value in capabilities.items():
            if isinstance(value, bool):
                print(f"{key.replace('_', ' ').title()}: {'Yes' if value else 'No'}")
            else:
                print(f"{key.replace('_', ' ').title()}: {value}")
    
    # Display validation results
    validation = validate_environment()
    if validation:
        print("\\nENVIRONMENT VALIDATION")
        print("-"*30)
        print(f"Valid: {'Yes' if validation.get('is_valid', False) else 'No'}")
        
        if validation.get('warnings'):
            print("\\nWarnings:")
            for warning in validation['warnings']:
                print(f"  - {warning}")
        
        if validation.get('errors'):
            print("\\nErrors:")
            for error in validation['errors']:
                print(f"  - {error}")
        
        if validation.get('recommendations'):
            print("\\nRecommendations:")
            for rec in validation['recommendations']:
                print(f"  - {rec}")
    
    print()


def ensure_platform_ready() -> bool:
    """Ensure platform is ready for use.
    
    Returns:
        bool: True if platform is ready
    """
    global _platform_instance
    
    if _platform_instance is None:
        logger.info("Platform not initialized, performing initialization...")
        return initialize_platform()
    
    # Check if basic requirements are met
    info = get_platform_info()
    if not info:
        logger.error("Platform information not available")
        return False
    
    validation = validate_environment()
    if not validation.get('is_valid', False):
        logger.error("Environment validation failed")
        if validation.get('errors'):
            for error in validation['errors']:
                logger.error(f"Validation error: {error}")
        return False
    
    return True


# Utility functions for common operations
def get_user_data_dir() -> str:
    """Get user data directory following platform conventions.
    
    Returns:
        str: User data directory path
    """
    if is_windows():
        return os.path.expanduser("~/AppData/Local/vuln_scanner")
    elif is_colab():
        return "/content/vuln_scanner_data"
    else:  # Linux/Unix
        return os.path.expanduser("~/.local/share/vuln_scanner")


def get_user_config_dir() -> str:
    """Get user configuration directory following platform conventions.
    
    Returns:
        str: User config directory path
    """
    if is_windows():
        return os.path.expanduser("~/AppData/Local/vuln_scanner/config")
    elif is_colab():
        return "/content/vuln_scanner_config"
    else:  # Linux/Unix
        return os.path.expanduser("~/.config/vuln_scanner")


def get_platform_specific_browser_path() -> Optional[str]:
    """Get platform-specific default browser path.
    
    Returns:
        str: Browser path if found, None otherwise
    """
    if is_windows():
        # Common Chrome paths on Windows
        chrome_paths = [
            r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            r"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
            os.path.expanduser(r"~\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe")
        ]
        for path in chrome_paths:
            if os.path.exists(path):
                return path
    elif is_linux() or is_docker():
        # Common Chrome/Chromium paths on Linux
        chrome_paths = [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable", 
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium"
        ]
        for path in chrome_paths:
            if os.path.exists(path):
                return path
    elif is_colab():
        # Colab typically has chromium-browser
        return "/usr/bin/chromium-browser"
    
    return None