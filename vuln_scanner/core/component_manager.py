"""Component manager for managing lifecycle of VulnMiner components."""

import atexit
from typing import Dict, Any, List, Optional
from contextlib import contextmanager
import threading

from ..core.logger import LoggerManager
from ..core.exceptions import SystemError, ResourceExhaustionError


class ComponentManager:
    """Manages the lifecycle of VulnMiner system components."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize component manager.
        
        Args:
            config: System configuration
        """
        self.config = config
        self.components: Dict[str, Any] = {}
        self.component_order: List[str] = []
        self.shutdown_handlers: List[callable] = []
        self._lock = threading.RLock()
        self._shutdown_called = False
        
        # Register shutdown handler
        atexit.register(self.shutdown)
    
    def register_component(self, name: str, component: Any, 
                          dependencies: Optional[List[str]] = None) -> None:
        """Register a component with the manager.
        
        Args:
            name: Component name
            component: Component instance
            dependencies: List of component names this component depends on
        """
        with self._lock:
            if name in self.components:
                raise SystemError(f"Component '{name}' is already registered")
            
            # Validate dependencies exist
            dependencies = dependencies or []
            for dep in dependencies:
                if dep not in self.components:
                    raise SystemError(f"Dependency '{dep}' not found for component '{name}'")
            
            self.components[name] = {
                'instance': component,
                'dependencies': dependencies,
                'initialized': False,
                'shutdown': False
            }
            
            # Add to component order for shutdown
            self.component_order.append(name)
    
    def get_component(self, name: str) -> Any:
        """Get component instance by name.
        
        Args:
            name: Component name
            
        Returns:
            Component instance
            
        Raises:
            SystemError: If component not found
        """
        with self._lock:
            if name not in self.components:
                raise SystemError(f"Component '{name}' not found")
            
            component_info = self.components[name]
            
            # Initialize component if not already initialized
            if not component_info['initialized']:
                self._initialize_component(name)
            
            return component_info['instance']
    
    def _initialize_component(self, name: str) -> None:
        """Initialize a component and its dependencies.
        
        Args:
            name: Component name to initialize
        """
        if name not in self.components:
            raise SystemError(f"Component '{name}' not found")
        
        component_info = self.components[name]
        
        if component_info['initialized']:
            return
        
        # Initialize dependencies first
        for dep_name in component_info['dependencies']:
            if not self.components[dep_name]['initialized']:
                self._initialize_component(dep_name)
        
        # Initialize the component
        component = component_info['instance']
        
        # Call initialize method if it exists
        if hasattr(component, 'initialize'):
            try:
                component.initialize()
            except Exception as e:
                raise SystemError(f"Failed to initialize component '{name}': {e}")
        
        component_info['initialized'] = True
    
    def initialize_all(self) -> None:
        """Initialize all registered components."""
        with self._lock:
            for name in self.components:
                if not self.components[name]['initialized']:
                    self._initialize_component(name)
    
    def shutdown_component(self, name: str) -> None:
        """Shutdown a specific component.
        
        Args:
            name: Component name to shutdown
        """
        with self._lock:
            if name not in self.components:
                return
            
            component_info = self.components[name]
            
            if component_info['shutdown']:
                return
            
            component = component_info['instance']
            
            # Call shutdown method if it exists
            if hasattr(component, 'shutdown'):
                try:
                    component.shutdown()
                except Exception:
                    # Log error but continue shutdown
                    pass
            
            component_info['shutdown'] = True
    
    def shutdown(self) -> None:
        """Shutdown all components in reverse order."""
        with self._lock:
            if self._shutdown_called:
                return
            
            self._shutdown_called = True
            
            # Shutdown components in reverse order
            for name in reversed(self.component_order):
                self.shutdown_component(name)
            
            # Run registered shutdown handlers
            for handler in self.shutdown_handlers:
                try:
                    handler()
                except Exception:
                    # Ignore errors during shutdown
                    pass
    
    def add_shutdown_handler(self, handler: callable) -> None:
        """Add a shutdown handler function.
        
        Args:
            handler: Function to call during shutdown
        """
        with self._lock:
            self.shutdown_handlers.append(handler)
    
    def get_component_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all components.
        
        Returns:
            Dictionary with component status information
        """
        with self._lock:
            status = {}
            for name, component_info in self.components.items():
                status[name] = {
                    'initialized': component_info['initialized'],
                    'shutdown': component_info['shutdown'],
                    'dependencies': component_info['dependencies'],
                    'type': type(component_info['instance']).__name__
                }
            return status
    
    @contextmanager
    def managed_component(self, name: str, component: Any, 
                         dependencies: Optional[List[str]] = None):
        """Context manager for temporary components.
        
        Args:
            name: Component name
            component: Component instance
            dependencies: Component dependencies
        """
        self.register_component(name, component, dependencies)
        try:
            yield self.get_component(name)
        finally:
            self.shutdown_component(name)
            with self._lock:
                if name in self.components:
                    del self.components[name]
                if name in self.component_order:
                    self.component_order.remove(name)