"""Configuration validator for VulnMiner system."""

from typing import Dict, Any, List, Tuple, Optional
import ipaddress
from pathlib import Path


class ConfigValidator:
    """Validates VulnMiner configuration for correctness and security."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize validator with configuration.
        
        Args:
            config: Configuration dictionary to validate
        """
        self.config = config
        self.errors: List[str] = []
    
    def validate(self) -> List[str]:
        """Validate complete configuration.
        
        Returns:
            List of validation error messages
        """
        self.errors = []
        
        self._validate_system_config()
        self._validate_security_config()
        self._validate_logging_config()
        self._validate_database_config()
        self._validate_tools_config()
        
        return self.errors
    
    def _validate_system_config(self) -> None:
        """Validate system configuration section."""
        system = self.config.get('system', {})
        
        # Validate version
        version = system.get('version')
        if not version or not isinstance(version, str):
            self.errors.append("System version must be a non-empty string")
        
        # Validate environment
        environment = system.get('environment')
        valid_envs = ['development', 'testing', 'production']
        if environment not in valid_envs:
            self.errors.append(f"Environment must be one of: {valid_envs}")
        
        # Validate max_concurrent_scans
        max_concurrent = system.get('max_concurrent_scans')
        if not isinstance(max_concurrent, int) or max_concurrent <= 0:
            self.errors.append("max_concurrent_scans must be a positive integer")
        elif max_concurrent > 100:
            self.errors.append("max_concurrent_scans should not exceed 100 for system stability")
        
        # Validate timeout
        timeout = system.get('timeout')
        if not isinstance(timeout, int) or timeout <= 0:
            self.errors.append("timeout must be a positive integer")
    
    def _validate_security_config(self) -> None:
        """Validate security configuration section."""
        security = self.config.get('security', {})
        
        # Validate authorization
        auth = security.get('authorization', {})
        if not isinstance(auth.get('enabled'), bool):
            self.errors.append("security.authorization.enabled must be a boolean")
        
        if not isinstance(auth.get('whitelist_only'), bool):
            self.errors.append("security.authorization.whitelist_only must be a boolean")
        
        # Validate allowed_targets
        allowed_targets = auth.get('allowed_targets', [])
        if not isinstance(allowed_targets, list):
            self.errors.append("security.authorization.allowed_targets must be a list")
        else:
            for target in allowed_targets:
                if not self._validate_target_format(target):
                    self.errors.append(f"Invalid target format: {target}")
        
        # Validate rate limiting
        rate_limit = security.get('rate_limiting', {})
        if not isinstance(rate_limit.get('enabled'), bool):
            self.errors.append("security.rate_limiting.enabled must be a boolean")
        
        requests_per_minute = rate_limit.get('requests_per_minute')
        if not isinstance(requests_per_minute, int) or requests_per_minute <= 0:
            self.errors.append("requests_per_minute must be a positive integer")
        
        # Validate SSL verification
        ssl_verification = security.get('ssl_verification')
        if not isinstance(ssl_verification, bool):
            self.errors.append("security.ssl_verification must be a boolean")
    
    def _validate_target_format(self, target: str) -> bool:
        """Validate target format (IP, CIDR, domain).
        
        Args:
            target: Target string to validate
            
        Returns:
            True if valid format, False otherwise
        """
        try:
            # Check if it's an IP address or CIDR
            if '/' in target:
                ipaddress.ip_network(target, strict=False)
                return True
            else:
                ipaddress.ip_address(target)
                return True
        except ValueError:
            # Check if it's a valid domain format
            if self._validate_domain_format(target):
                return True
            return False
    
    def _validate_domain_format(self, domain: str) -> bool:
        """Validate domain name format.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            True if valid domain format, False otherwise
        """
        if not domain:
            return False
        
        # Allow localhost as special case
        if domain.lower() == 'localhost':
            return True
        
        # Allow wildcard domains
        if domain.startswith('*.'):
            domain = domain[2:]
        
        # Basic domain validation
        if len(domain) > 253:
            return False
        
        labels = domain.split('.')
        if len(labels) < 2:
            return False
        
        for label in labels:
            if not label or len(label) > 63:
                return False
            if not label.replace('-', '').isalnum():
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
        
        return True
    
    def _validate_logging_config(self) -> None:
        """Validate logging configuration section."""
        logging_config = self.config.get('logging', {})
        
        # Validate log level
        level = logging_config.get('level')
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if level not in valid_levels:
            self.errors.append(f"logging.level must be one of: {valid_levels}")
        
        # Validate file rotation
        file_rotation = logging_config.get('file_rotation')
        if not isinstance(file_rotation, bool):
            self.errors.append("logging.file_rotation must be a boolean")
        
        # Validate max file size
        max_size = logging_config.get('max_file_size')
        if not isinstance(max_size, str) or not self._validate_size_format(max_size):
            self.errors.append("logging.max_file_size must be a valid size string (e.g., '10MB')")
        
        # Validate backup count
        backup_count = logging_config.get('backup_count')
        if not isinstance(backup_count, int) or backup_count < 0:
            self.errors.append("logging.backup_count must be a non-negative integer")
    
    def _validate_size_format(self, size: str) -> bool:
        """Validate size format string.
        
        Args:
            size: Size string to validate (e.g., '10MB')
            
        Returns:
            True if valid format, False otherwise
        """
        if not size:
            return False
        
        # Check longer units first to avoid partial matches
        valid_units = ['GB', 'MB', 'KB', 'B']
        for unit in valid_units:
            if size.upper().endswith(unit):
                number_part = size[:-len(unit)]
                try:
                    float(number_part)
                    return True
                except ValueError:
                    return False
        
        return False
    
    def _validate_database_config(self) -> None:
        """Validate database configuration section."""
        db_config = self.config.get('database', {})
        
        # Validate database type
        db_type = db_config.get('type')
        valid_types = ['sqlite', 'postgresql', 'mysql']
        if db_type not in valid_types:
            self.errors.append(f"database.type must be one of: {valid_types}")
        
        # Validate database path for SQLite
        if db_type == 'sqlite':
            db_path = db_config.get('path')
            if not db_path or not isinstance(db_path, str):
                self.errors.append("database.path must be specified for SQLite")
        
        # Validate pool size
        pool_size = db_config.get('pool_size')
        if not isinstance(pool_size, int) or pool_size <= 0:
            self.errors.append("database.pool_size must be a positive integer")
        
        # Validate timeout
        timeout = db_config.get('timeout')
        if not isinstance(timeout, int) or timeout <= 0:
            self.errors.append("database.timeout must be a positive integer")
    
    def _validate_tools_config(self) -> None:
        """Validate tools configuration section."""
        tools = self.config.get('tools', {})
        
        # Validate required tools
        required_tools = ['nmap', 'nuclei']
        for tool in required_tools:
            tool_config = tools.get(tool, {})
            
            # Validate tool path
            tool_path = tool_config.get('path')
            if not tool_path or not isinstance(tool_path, str):
                self.errors.append(f"tools.{tool}.path must be specified")
            
            # Validate default arguments
            if 'default_args' in tool_config:
                args = tool_config['default_args']
                if not isinstance(args, list):
                    self.errors.append(f"tools.{tool}.default_args must be a list")
        
        # Validate custom scripts directory
        custom_scripts = tools.get('custom_scripts_dir')
        if custom_scripts and not isinstance(custom_scripts, str):
            self.errors.append("tools.custom_scripts_dir must be a string")
    
    def is_valid(self) -> bool:
        """Check if configuration is valid.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        return len(self.validate()) == 0