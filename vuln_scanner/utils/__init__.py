"""Utility functions and helpers for VulnMiner system."""

from .file_utils import ensure_directory, safe_write_file, safe_read_file
from .platform_utils import (
    initialize_platform, get_platform_info, get_platform_type,
    is_windows, is_colab, is_linux, is_docker,
    get_config_value, safe_path_join, normalize_path,
    create_directory, get_temp_directory, setup_logging,
    display_platform_info, ensure_platform_ready
)

# Legacy imports (will be updated to use platform_utils)
try:
    from .network_utils import validate_target, resolve_hostname
    from .time_utils import format_duration, get_timestamp  
    from .validation_utils import validate_config_value, sanitize_input
except ImportError:
    # Create placeholder functions if modules don't exist yet
    def validate_target(target): return True
    def resolve_hostname(hostname): return hostname
    def format_duration(seconds): return f"{seconds}s"
    def get_timestamp(): 
        import datetime
        return datetime.datetime.now().isoformat()
    def validate_config_value(key, value): return True
    def sanitize_input(input_str): return str(input_str)

__all__ = [
    # File utilities
    'ensure_directory', 'safe_write_file', 'safe_read_file',
    
    # Platform utilities  
    'initialize_platform', 'get_platform_info', 'get_platform_type',
    'is_windows', 'is_colab', 'is_linux', 'is_docker',
    'get_config_value', 'safe_path_join', 'normalize_path',
    'create_directory', 'get_temp_directory', 'setup_logging',
    'display_platform_info', 'ensure_platform_ready',
    
    # Legacy utilities
    'validate_target', 'resolve_hostname', 
    'format_duration', 'get_timestamp',
    'validate_config_value', 'sanitize_input'
]