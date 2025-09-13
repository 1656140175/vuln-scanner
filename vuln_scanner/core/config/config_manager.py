"""Configuration manager for VulnMiner system."""

import os
import yaml
from typing import Dict, Any, Optional, List
from pathlib import Path


class ConfigManager:
    """Manages configuration loading and validation for VulnMiner system."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager.
        
        Args:
            config_path: Optional path to custom configuration file
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.base_dir = Path(__file__).parent.parent.parent.parent
        self._load_configuration()
    
    def _load_configuration(self) -> None:
        """Load configuration from multiple sources in order of priority."""
        # Start with default configuration
        default_config = self._load_config_file(self.base_dir / "config" / "default.yml")
        if default_config:
            self.config.update(default_config)
        
        # Override with environment-specific configuration
        env = os.getenv('VULN_MINER_ENV', 'development')
        env_config = self._load_config_file(self.base_dir / "config" / f"{env}.yml")
        if env_config:
            self._deep_merge(self.config, env_config)
        
        # Override with user-specified configuration
        if self.config_path:
            user_config = self._load_config_file(Path(self.config_path))
            if user_config:
                self._deep_merge(self.config, user_config)
        
        # Override with environment variables
        self._load_environment_variables()
    
    def _load_config_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load configuration from YAML file.
        
        Args:
            file_path: Path to configuration file
            
        Returns:
            Configuration dictionary or None if file doesn't exist
        """
        if not file_path.exists():
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except (yaml.YAMLError, IOError) as e:
            raise ConfigurationError(f"Failed to load configuration from {file_path}: {e}")
    
    def _deep_merge(self, base: Dict[str, Any], update: Dict[str, Any]) -> None:
        """Deep merge update dictionary into base dictionary.
        
        Args:
            base: Base dictionary to merge into
            update: Dictionary with updates to merge
        """
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _load_environment_variables(self) -> None:
        """Load configuration overrides from environment variables."""
        env_mappings = {
            'VULN_MINER_DEBUG': ('system', 'debug'),
            'VULN_MINER_LOG_LEVEL': ('logging', 'level'),
            'VULN_MINER_MAX_CONCURRENT': ('system', 'max_concurrent_scans'),
            'VULN_MINER_TIMEOUT': ('system', 'timeout'),
            'VULN_MINER_DB_PATH': ('database', 'path'),
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                self._set_nested_value(self.config, config_path, self._convert_env_value(value))
    
    def _set_nested_value(self, config: Dict[str, Any], path: tuple, value: Any) -> None:
        """Set nested configuration value.
        
        Args:
            config: Configuration dictionary
            path: Tuple representing nested path
            value: Value to set
        """
        current = config
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[path[-1]] = value
    
    def _convert_env_value(self, value: str) -> Any:
        """Convert environment variable string to appropriate type.
        
        Args:
            value: String value from environment variable
            
        Returns:
            Converted value (bool, int, float, or str)
        """
        # Convert boolean values
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # Convert numeric values
        try:
            if '.' in value:
                return float(value)
            return int(value)
        except ValueError:
            return value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-separated key.
        
        Args:
            key: Dot-separated configuration key (e.g., 'system.debug')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        current = self.config
        
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        
        return current
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by dot-separated key.
        
        Args:
            key: Dot-separated configuration key
            value: Value to set
        """
        keys = key.split('.')
        current = self.config
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section.
        
        Args:
            section: Section name
            
        Returns:
            Configuration section dictionary
        """
        return self.config.get(section, {})
    
    def reload(self) -> None:
        """Reload configuration from all sources."""
        self.config = {}
        self._load_configuration()
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of errors.
        
        Returns:
            List of validation error messages
        """
        from .config_validator import ConfigValidator
        validator = ConfigValidator(self.config)
        return validator.validate()
    
    def to_dict(self) -> Dict[str, Any]:
        """Get complete configuration as dictionary.
        
        Returns:
            Complete configuration dictionary
        """
        return self.config.copy()


class ConfigurationError(Exception):
    """Configuration-related error."""
    pass