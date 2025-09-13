"""Platform-specific configuration adapter system."""

import os
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
import logging

from .detector import PlatformInfo, PlatformType

logger = logging.getLogger(__name__)


class ConfigAdapter:
    """Platform-specific configuration adapter."""
    
    def __init__(self, platform_info: PlatformInfo, base_config: Optional[Dict[str, Any]] = None):
        """Initialize configuration adapter.
        
        Args:
            platform_info: Platform information
            base_config: Base configuration dictionary
        """
        self.platform_info = platform_info
        self.base_config = base_config or {}
        self.config = self._build_platform_config()
    
    def _build_platform_config(self) -> Dict[str, Any]:
        """Build complete platform-specific configuration.
        
        Returns:
            Dict with merged configuration
        """
        # Start with base configuration
        config = self.base_config.copy()
        
        # Apply base defaults
        base_defaults = self._get_base_defaults()
        for key, value in base_defaults.items():
            if key not in config:
                config[key] = value
        
        # Apply platform-specific overrides
        platform_config = self._get_platform_specific_config()
        config = self._deep_merge(config, platform_config)
        
        # Apply environment variable overrides
        env_overrides = self._get_environment_overrides()
        config = self._deep_merge(config, env_overrides)
        
        # Validate and adjust configuration
        config = self._validate_and_adjust_config(config)
        
        return config
    
    def _get_base_defaults(self) -> Dict[str, Any]:
        """Get base default configuration values.
        
        Returns:
            Dict with base defaults
        """
        return {
            # Resource limits
            "max_workers": min(self.platform_info.cpu_count, 4),
            "memory_limit_mb": min(int(self.platform_info.available_memory * 0.8), 8192),
            "max_concurrent_scans": 2,
            "request_timeout": 30,
            "max_retries": 3,
            
            # Directories
            "temp_dir": self.platform_info.temp_directory,
            "log_level": "INFO",
            "log_format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            
            # Features
            "enable_gpu": self.platform_info.is_gpu_available,
            "enable_parallel_processing": True,
            "enable_caching": True,
            "cache_size_mb": 256,
            
            # Network settings
            "user_agent": "VulnMiner/1.0 (Security Research Tool)",
            "max_redirects": 5,
            "verify_ssl": True,
            
            # Security settings
            "enable_sandbox": True,
            "max_scan_time_minutes": 60,
            "rate_limit_requests_per_second": 5,
            
            # Output settings
            "output_format": "json",
            "save_screenshots": True,
            "save_raw_responses": False,
            "compress_outputs": True
        }
    
    def _get_platform_specific_config(self) -> Dict[str, Any]:
        """Get platform-specific configuration overrides.
        
        Returns:
            Dict with platform-specific settings
        """
        if self.platform_info.platform_type == PlatformType.COLAB:
            return self._get_colab_config()
        elif self.platform_info.platform_type == PlatformType.WINDOWS:
            return self._get_windows_config()
        elif self.platform_info.platform_type == PlatformType.LINUX:
            return self._get_linux_config()
        elif self.platform_info.platform_type == PlatformType.DOCKER:
            return self._get_docker_config()
        else:
            return {}
    
    def _get_colab_config(self) -> Dict[str, Any]:
        """Get Google Colab-specific configuration.
        
        Returns:
            Dict with Colab settings
        """
        return {
            # Directories
            "output_dir": "/content/vuln_scanner_output",
            "data_dir": "/content/vuln_scanner_data",
            "log_dir": "/content/vuln_scanner_logs",
            "cache_dir": "/content/vuln_scanner_cache",
            
            # Drive integration
            "drive_output_dir": "/content/drive/MyDrive/vuln_scanner_output",
            "auto_save_to_drive": True,
            "drive_backup_interval": 300,  # 5 minutes
            
            # Resource settings
            "memory_limit_mb": min(self.platform_info.available_memory, 12288),  # Max 12GB
            "max_workers": min(self.platform_info.cpu_count, 2),  # Limited CPU in Colab
            "enable_gpu": self.platform_info.is_gpu_available,
            
            # Colab-specific settings
            "session_timeout": 12 * 3600,  # 12 hours
            "auto_save_interval": 300,  # 5 minutes
            "display_progress_bars": True,
            "use_colab_widgets": True,
            "install_system_deps": True,
            
            # Network settings optimized for Colab
            "request_timeout": 60,  # Longer timeout for Colab
            "max_concurrent_requests": 3,  # Conservative for Colab
            "rate_limit_requests_per_second": 2,  # Lower rate limit
            
            # Output settings
            "compress_outputs": True,  # Save space in Colab
            "max_log_size_mb": 50,
            "log_rotation": True
        }
    
    def _get_windows_config(self) -> Dict[str, Any]:
        """Get Windows-specific configuration.
        
        Returns:
            Dict with Windows settings
        """
        # Determine user directories
        user_home = os.path.expanduser("~")
        documents_dir = os.path.join(user_home, "Documents")
        appdata_dir = os.path.join(user_home, "AppData", "Local")
        
        return {
            # Directories
            "output_dir": os.path.join(documents_dir, "vuln_scanner_output"),
            "data_dir": os.path.join(appdata_dir, "vuln_scanner"),
            "log_dir": os.path.join(appdata_dir, "vuln_scanner", "logs"),
            "cache_dir": os.path.join(appdata_dir, "vuln_scanner", "cache"),
            
            # Windows-specific settings
            "use_powershell": True,
            "enable_windows_defender_bypass": True,
            "use_long_path_prefix": True,
            "path_separator": "\\\\",
            "max_path_length": 260,
            
            # Resource settings
            "memory_limit_mb": min(int(self.platform_info.available_memory * 0.7), 16384),
            "max_workers": self.platform_info.cpu_count,
            
            # Windows-specific tools
            "browser_executable": None,  # Auto-detect
            "chromedriver_path": None,  # Auto-detect
            
            # Security settings
            "require_admin_for_system_scans": True,
            "enable_uac_bypass": False,  # Disabled by default for security
            
            # Console settings
            "console_encoding": "utf-8",
            "enable_colors": True
        }
    
    def _get_linux_config(self) -> Dict[str, Any]:
        """Get Linux-specific configuration.
        
        Returns:
            Dict with Linux settings
        """
        user_home = os.path.expanduser("~")
        
        return {
            # Directories following XDG Base Directory Specification
            "output_dir": os.path.join(user_home, "vuln_scanner_output"),
            "data_dir": os.path.join(user_home, ".local", "share", "vuln_scanner"),
            "config_dir": os.path.join(user_home, ".config", "vuln_scanner"),
            "cache_dir": os.path.join(user_home, ".cache", "vuln_scanner"),
            "log_dir": os.path.join(user_home, ".local", "share", "vuln_scanner", "logs"),
            
            # Linux-specific settings
            "path_separator": "/",
            "use_system_packages": True,
            "package_manager": "auto",  # Auto-detect (apt, yum, etc.)
            
            # Resource settings
            "memory_limit_mb": min(int(self.platform_info.available_memory * 0.8), 32768),
            "max_workers": self.platform_info.cpu_count,
            
            # Tools
            "browser_executable": None,  # Auto-detect
            "prefer_headless": True,
            
            # Permissions
            "enable_sudo": False,  # Disabled by default
            "file_permissions": 0o755,
            "log_permissions": 0o644
        }
    
    def _get_docker_config(self) -> Dict[str, Any]:
        """Get Docker container-specific configuration.
        
        Returns:
            Dict with Docker settings
        """
        return {
            # Directories (container-optimized)
            "output_dir": "/app/output",
            "data_dir": "/app/data",
            "log_dir": "/app/logs",
            "cache_dir": "/app/cache",
            "temp_dir": "/tmp/vuln_scanner",
            
            # Resource settings (conservative for containers)
            "memory_limit_mb": min(int(self.platform_info.available_memory * 0.9), 16384),
            "max_workers": min(self.platform_info.cpu_count, 4),
            
            # Container-specific settings
            "assume_headless": True,
            "disable_gpu": not self.platform_info.is_gpu_available,
            "enable_health_checks": True,
            "container_optimized": True,
            
            # Network settings (container-friendly)
            "bind_address": "0.0.0.0",
            "disable_local_browser": True,
            
            # Logging optimized for containers
            "log_to_stdout": True,
            "structured_logging": True,
            "disable_log_files": False
        }
    
    def _get_environment_overrides(self) -> Dict[str, Any]:
        """Get configuration overrides from environment variables.
        
        Returns:
            Dict with environment-based overrides
        """
        overrides = {}
        env_prefix = "VULN_SCANNER_"
        
        # Map of environment variables to config keys
        env_mappings = {
            f"{env_prefix}OUTPUT_DIR": "output_dir",
            f"{env_prefix}DATA_DIR": "data_dir", 
            f"{env_prefix}LOG_DIR": "log_dir",
            f"{env_prefix}LOG_LEVEL": "log_level",
            f"{env_prefix}MAX_WORKERS": ("max_workers", int),
            f"{env_prefix}MEMORY_LIMIT_MB": ("memory_limit_mb", int),
            f"{env_prefix}REQUEST_TIMEOUT": ("request_timeout", int),
            f"{env_prefix}MAX_RETRIES": ("max_retries", int),
            f"{env_prefix}RATE_LIMIT": ("rate_limit_requests_per_second", float),
            f"{env_prefix}ENABLE_GPU": ("enable_gpu", lambda x: x.lower() in ["true", "1", "yes"]),
            f"{env_prefix}VERIFY_SSL": ("verify_ssl", lambda x: x.lower() in ["true", "1", "yes"]),
            f"{env_prefix}USER_AGENT": "user_agent",
            f"{env_prefix}OUTPUT_FORMAT": "output_format"
        }
        
        for env_var, config_key in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                try:
                    if isinstance(config_key, tuple):
                        key, converter = config_key
                        overrides[key] = converter(env_value)
                    else:
                        overrides[config_key] = env_value
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid environment variable {env_var}={env_value}: {e}")
        
        return overrides
    
    def _validate_and_adjust_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and adjust configuration for platform constraints.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Dict with validated and adjusted configuration
        """
        validated = config.copy()
        
        # Validate resource limits
        max_memory = self.platform_info.available_memory
        if validated.get("memory_limit_mb", 0) > max_memory:
            validated["memory_limit_mb"] = int(max_memory * 0.8)
            logger.warning(f"Reduced memory limit to {validated['memory_limit_mb']}MB")
        
        max_cpu = self.platform_info.cpu_count
        if validated.get("max_workers", 0) > max_cpu:
            validated["max_workers"] = max_cpu
            logger.warning(f"Reduced max workers to {validated['max_workers']}")
        
        # Validate directories and create if needed
        for dir_key in ["output_dir", "data_dir", "log_dir", "cache_dir"]:
            if dir_key in validated:
                directory = validated[dir_key]
                if directory:
                    try:
                        os.makedirs(directory, exist_ok=True)
                        validated[dir_key] = os.path.abspath(directory)
                    except Exception as e:
                        logger.warning(f"Could not create directory {directory}: {e}")
                        # Fallback to temp directory
                        fallback = os.path.join(tempfile.gettempdir(), f"vuln_scanner_{dir_key[:-4]}")
                        os.makedirs(fallback, exist_ok=True)
                        validated[dir_key] = fallback
        
        # Platform-specific validations
        if self.platform_info.platform_type == PlatformType.COLAB:
            # Ensure Colab-specific directories are writable
            for key in ["output_dir", "data_dir", "log_dir"]:
                if key in validated and validated[key].startswith("/content/"):
                    # Good, in Colab writable area
                    continue
                elif key in validated:
                    # Move to /content for Colab
                    dir_name = os.path.basename(validated[key])
                    validated[key] = f"/content/{dir_name}"
                    os.makedirs(validated[key], exist_ok=True)
        
        elif self.platform_info.platform_type == PlatformType.WINDOWS:
            # Check path length limits
            for key in ["output_dir", "data_dir", "log_dir"]:
                if key in validated and len(validated[key]) > 240:  # Leave room for files
                    # Use shorter path
                    import tempfile
                    short_name = key.replace("_dir", "")
                    validated[key] = os.path.join(tempfile.gettempdir(), f"vs_{short_name}")
                    os.makedirs(validated[key], exist_ok=True)
                    logger.warning(f"Shortened {key} due to Windows path length limits")
        
        # Validate GPU settings
        if not self.platform_info.is_gpu_available:
            validated["enable_gpu"] = False
        
        # Validate network settings
        if validated.get("request_timeout", 0) < 1:
            validated["request_timeout"] = 30
        
        if validated.get("max_retries", 0) < 0:
            validated["max_retries"] = 3
        
        return validated
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries.
        
        Args:
            base: Base dictionary
            override: Override dictionary
            
        Returns:
            Dict with merged values
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get_config(self) -> Dict[str, Any]:
        """Get the complete configuration.
        
        Returns:
            Dict with complete configuration
        """
        return self.config.copy()
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key.
        
        Args:
            key: Configuration key (supports dot notation)
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split(".")
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by key.
        
        Args:
            key: Configuration key (supports dot notation)
            value: Value to set
        """
        keys = key.split(".")
        config = self.config
        
        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def update(self, updates: Dict[str, Any]) -> None:
        """Update configuration with new values.
        
        Args:
            updates: Dictionary with configuration updates
        """
        self.config = self._deep_merge(self.config, updates)
        self.config = self._validate_and_adjust_config(self.config)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary.
        
        Returns:
            Dictionary representation of configuration
        """
        return self.get_config()
    
    def save_to_file(self, file_path: str, format_type: str = "yaml") -> bool:
        """Save configuration to file.
        
        Args:
            file_path: File path to save to
            format_type: Format type (yaml, json)
            
        Returns:
            bool: True if successful
        """
        try:
            import yaml
            import json
            
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                if format_type.lower() == "yaml":
                    yaml.dump(self.config, f, default_flow_style=False, indent=2)
                elif format_type.lower() == "json":
                    json.dump(self.config, f, indent=2, ensure_ascii=False)
                else:
                    raise ValueError(f"Unsupported format: {format_type}")
            
            logger.info(f"Configuration saved to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    @classmethod
    def load_from_file(cls, file_path: str, platform_info: PlatformInfo) -> 'ConfigAdapter':
        """Load configuration from file.
        
        Args:
            file_path: File path to load from
            platform_info: Platform information
            
        Returns:
            ConfigAdapter instance
        """
        config = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.endswith(('.yaml', '.yml')):
                    import yaml
                    config = yaml.safe_load(f) or {}
                elif file_path.endswith('.json'):
                    import json
                    config = json.load(f)
                else:
                    logger.warning(f"Unknown config file format: {file_path}")
            
            logger.info(f"Configuration loaded from {file_path}")
            
        except Exception as e:
            logger.error(f"Failed to load configuration from {file_path}: {e}")
        
        return cls(platform_info, config)