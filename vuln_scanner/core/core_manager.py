"""Core manager class that orchestrates all VulnMiner components."""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
import signal
import threading
import time

from .config import ConfigManager, ConfigValidator
from .logger import LoggerManager, SecurityAuditLogger
from .security import SecurityController
from .component_manager import ComponentManager
from .tool_manager import ToolManagerComponent
from .exceptions import (
    VulnMinerException, ConfigurationError, ConfigValidationError,
    SystemError, DependencyError
)


class VulnMinerCore:
    """Core class that orchestrates all VulnMiner system components.
    
    This is the main entry point for the VulnMiner system. It manages
    configuration, logging, security, and coordinates all other components.
    """
    
    def __init__(self, config_path: Optional[str] = None, skip_tool_validation: bool = False):
        """Initialize VulnMiner core system.
        
        Args:
            config_path: Optional path to custom configuration file
            skip_tool_validation: Skip validation of external tools (for config validation)
        """
        self.config_path = config_path
        self.skip_tool_validation = skip_tool_validation
        self.initialized = False
        self.shutdown_requested = False
        
        # Core components
        self.config_manager: Optional[ConfigManager] = None
        self.logger_manager: Optional[LoggerManager] = None
        self.security_controller: Optional[SecurityController] = None
        self.component_manager: Optional[ComponentManager] = None
        self.audit_logger: Optional[SecurityAuditLogger] = None
        self.tool_manager_component: Optional[ToolManagerComponent] = None
        
        # Component references
        self._logger = None
        
        # Threading
        self._main_thread = threading.current_thread()
        self._shutdown_lock = threading.Lock()
        
        # Initialize the system
        self._initialize()
    
    def _initialize(self) -> None:
        """Initialize all core components."""
        try:
            # 1. Load and validate configuration
            self._initialize_configuration()
            
            # 2. Set up logging system
            self._initialize_logging()
            
            # 3. Initialize component manager
            self._initialize_component_manager()
            
            # 4. Set up security framework
            self._initialize_security()
            
            # 5. Initialize tool management
            self._initialize_tool_manager()
            
            # 6. Register signal handlers
            self._register_signal_handlers()
            
            # 7. Validate environment
            self._validate_environment()
            
            self.initialized = True
            
            self._logger.info("VulnMiner core system initialized successfully", extra={
                'event_type': 'system_startup',
                'version': self.get_version(),
                'environment': self.config_manager.get('system.environment'),
                'config_path': self.config_path
            })
            
        except Exception as e:
            if self._logger:
                self._logger.error(f"Failed to initialize VulnMiner core: {e}", exc_info=True)
            raise SystemError(f"Core initialization failed: {e}")
    
    def _initialize_configuration(self) -> None:
        """Initialize configuration management."""
        try:
            self.config_manager = ConfigManager(self.config_path)
            
            # Validate configuration
            validation_errors = self.config_manager.validate()
            if validation_errors:
                raise ConfigValidationError(validation_errors)
            
        except Exception as e:
            if isinstance(e, (ConfigurationError, ConfigValidationError)):
                raise
            raise ConfigurationError(f"Configuration initialization failed: {e}")
    
    def _initialize_logging(self) -> None:
        """Initialize logging system."""
        try:
            config = self.config_manager.to_dict()
            self.logger_manager = LoggerManager(config)
            self._logger = self.logger_manager.get_logger('core')
            self.audit_logger = SecurityAuditLogger(self.logger_manager)
            
        except Exception as e:
            raise SystemError(f"Logging initialization failed: {e}")
    
    def _initialize_component_manager(self) -> None:
        """Initialize component manager."""
        try:
            config = self.config_manager.to_dict()
            self.component_manager = ComponentManager(config)
            
            # Register core components
            self.component_manager.register_component('config', self.config_manager)
            self.component_manager.register_component('logger', self.logger_manager, ['config'])
            
        except Exception as e:
            raise SystemError(f"Component manager initialization failed: {e}")
    
    def _initialize_security(self) -> None:
        """Initialize security framework."""
        try:
            config = self.config_manager.to_dict()
            self.security_controller = SecurityController(config, self.logger_manager)
            
            # Register security component
            self.component_manager.register_component(
                'security', 
                self.security_controller, 
                ['config', 'logger']
            )
            
        except Exception as e:
            raise SystemError(f"Security framework initialization failed: {e}")
    
    def _initialize_tool_manager(self) -> None:
        """Initialize tool management system."""
        try:
            config = self.config_manager.to_dict()
            self.tool_manager_component = ToolManagerComponent(config, self.logger_manager)
            self.tool_manager_component.initialize()
            
            # Register tool manager component
            self.component_manager.register_component(
                'tool_manager',
                self.tool_manager_component,
                ['config', 'logger', 'security']
            )
            
        except Exception as e:
            raise SystemError(f"Tool manager initialization failed: {e}")
    
    def _register_signal_handlers(self) -> None:
        """Register signal handlers for graceful shutdown."""
        if threading.current_thread() is not self._main_thread:
            return  # Signal handlers can only be registered from main thread
        
        def signal_handler(signum, frame):
            self._logger.info(f"Received signal {signum}, initiating graceful shutdown")
            self.shutdown()
        
        try:
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            
            # Windows-specific signals
            if hasattr(signal, 'SIGBREAK'):
                signal.signal(signal.SIGBREAK, signal_handler)
                
        except Exception as e:
            self._logger.warning(f"Failed to register signal handlers: {e}")
    
    def _validate_environment(self) -> None:
        """Validate the runtime environment."""
        validation_errors = []
        
        # Check Python version
        python_version = sys.version_info
        if python_version < (3, 8):
            validation_errors.append(f"Python 3.8+ required, found {python_version.major}.{python_version.minor}")
        
        # Check required directories exist and are writable
        required_dirs = ['logs', 'data']
        for dir_name in required_dirs:
            dir_path = Path(dir_name)
            if not dir_path.exists():
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                except OSError as e:
                    validation_errors.append(f"Cannot create directory {dir_path}: {e}")
            elif not os.access(dir_path, os.W_OK):
                validation_errors.append(f"Directory {dir_path} is not writable")
        
        # Check required tools (if not skipping tool validation)
        if not self.skip_tool_validation:
            tools_config = self.config_manager.get_section('tools')
            for tool_name, tool_config in tools_config.items():
                if isinstance(tool_config, dict):
                    tool_path = tool_config.get('path')
                    if tool_path and not Path(tool_path).exists():
                        validation_errors.append(f"Required tool '{tool_name}' not found at {tool_path}")
        
        if validation_errors:
            error_msg = "Environment validation failed:\n" + "\n".join(f"- {error}" for error in validation_errors)
            self._logger.error(error_msg)
            raise SystemError(error_msg)
        
        self._logger.info("Environment validation passed")
    
    def get_version(self) -> str:
        """Get VulnMiner version.
        
        Returns:
            Version string
        """
        return self.config_manager.get('system.version', '1.0.0')
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        return self.config_manager.get(key, default)
    
    def set_config(self, key: str, value: Any) -> None:
        """Set configuration value.
        
        Args:
            key: Configuration key
            value: Value to set
        """
        old_value = self.config_manager.get(key)
        self.config_manager.set(key, value)
        
        # Log configuration change
        if self.audit_logger:
            self.audit_logger.log_configuration_change(
                section=key.split('.')[0] if '.' in key else 'system',
                key=key,
                old_value=old_value,
                new_value=value
            )
    
    def validate_scan_target(self, target: str, scan_type: str, 
                           user: Optional[str] = None) -> bool:
        """Validate if a scan target is authorized.
        
        Args:
            target: Target to validate
            scan_type: Type of scan
            user: User requesting the scan
            
        Returns:
            True if target is authorized
            
        Raises:
            SecurityError: If target is not authorized
        """
        if not self.security_controller:
            raise SystemError("Security controller not initialized")
        
        allowed, validation_info = self.security_controller.validate_scan_request(
            target, scan_type, user
        )
        
        if not allowed:
            from .exceptions import UnauthorizedTargetError
            raise UnauthorizedTargetError(
                target,
                details=validation_info,
                suggestion="Add target to authorized whitelist or check security policies"
            )
        
        return True
    
    def get_tool_manager(self):
        """Get the tool manager instance.
        
        Returns:
            ToolManager instance
            
        Raises:
            SystemError: If tool manager not initialized
        """
        if not self.tool_manager_component:
            raise SystemError("Tool manager not initialized")
        
        return self.tool_manager_component.get_tool_manager()
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get system status information.
        
        Returns:
            Dictionary with system status
        """
        status = {
            'initialized': self.initialized,
            'version': self.get_version(),
            'environment': self.config_manager.get('system.environment'),
            'uptime_seconds': time.time() - getattr(self, '_start_time', time.time()),
            'shutdown_requested': self.shutdown_requested,
        }
        
        if self.component_manager:
            status['components'] = self.component_manager.get_component_status()
        
        if self.security_controller:
            status['security'] = self.security_controller.get_security_status()
        
        if self.tool_manager_component:
            status['tool_manager'] = self.tool_manager_component.get_status()
        
        return status
    
    def health_check(self) -> Dict[str, Any]:
        """Perform system health check.
        
        Returns:
            Health check results
        """
        health_status = {
            'healthy': True,
            'checks': {},
            'timestamp': time.time()
        }
        
        # Check core components
        core_components = ['config_manager', 'logger_manager', 'security_controller', 'tool_manager_component']
        for component_name in core_components:
            component = getattr(self, component_name, None)
            if component is None:
                health_status['healthy'] = False
                health_status['checks'][component_name] = {
                    'status': 'failed',
                    'message': 'Component not initialized'
                }
            else:
                health_status['checks'][component_name] = {
                    'status': 'healthy',
                    'message': 'Component operational'
                }
        
        # Check configuration validity
        try:
            validation_errors = self.config_manager.validate()
            if validation_errors:
                health_status['healthy'] = False
                health_status['checks']['configuration'] = {
                    'status': 'failed',
                    'message': f'Configuration validation failed: {validation_errors}'
                }
            else:
                health_status['checks']['configuration'] = {
                    'status': 'healthy',
                    'message': 'Configuration valid'
                }
        except Exception as e:
            health_status['healthy'] = False
            health_status['checks']['configuration'] = {
                'status': 'failed',
                'message': f'Configuration check failed: {e}'
            }
        
        # Check tool manager health
        if self.tool_manager_component:
            try:
                import asyncio
                tool_health = asyncio.run(self.tool_manager_component.health_check())
                health_status['checks']['tool_manager'] = tool_health['checks']
                if not tool_health['healthy']:
                    health_status['healthy'] = False
            except Exception as e:
                health_status['healthy'] = False
                health_status['checks']['tool_manager'] = {
                    'status': 'failed',
                    'message': f'Tool manager health check failed: {e}'
                }
        
        # Check disk space
        try:
            import shutil
            logs_dir = Path('logs')
            data_dir = Path('data')
            
            for directory in [logs_dir, data_dir]:
                if directory.exists():
                    free_space = shutil.disk_usage(directory).free
                    # Warn if less than 100MB free
                    if free_space < 100 * 1024 * 1024:
                        health_status['healthy'] = False
                        health_status['checks'][f'disk_space_{directory.name}'] = {
                            'status': 'warning',
                            'message': f'Low disk space: {free_space / (1024*1024):.1f}MB free'
                        }
                    else:
                        health_status['checks'][f'disk_space_{directory.name}'] = {
                            'status': 'healthy',
                            'message': f'Sufficient disk space: {free_space / (1024*1024):.1f}MB free'
                        }
        except Exception as e:
            health_status['checks']['disk_space'] = {
                'status': 'unknown',
                'message': f'Could not check disk space: {e}'
            }
        
        return health_status
    
    def shutdown(self, timeout: float = 30.0) -> None:
        """Shutdown the VulnMiner system gracefully.
        
        Args:
            timeout: Maximum time to wait for shutdown
        """
        with self._shutdown_lock:
            if self.shutdown_requested:
                return
            
            self.shutdown_requested = True
        
        if self._logger:
            self._logger.info("Initiating system shutdown")
        
        try:
            # Shutdown components in reverse order
            if self.component_manager:
                self.component_manager.shutdown()
            
            # Shutdown logging last
            if self.logger_manager:
                self.logger_manager.shutdown()
            
        except Exception as e:
            if self._logger:
                self._logger.error(f"Error during shutdown: {e}")
            else:
                print(f"Error during shutdown: {e}")
        
        if self._logger:
            self._logger.info("System shutdown completed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()
    
    def __del__(self):
        """Destructor to ensure cleanup."""
        if hasattr(self, 'shutdown_requested') and not self.shutdown_requested:
            self.shutdown()