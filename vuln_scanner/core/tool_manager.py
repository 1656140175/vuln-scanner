"""Tool manager integration with VulnMiner core system."""

import asyncio
import logging
from typing import Dict, Any, Optional

from ..tools.manager import ToolManager
from ..tools.registry import ToolRegistry
from ..tools.implementations import NmapTool, NucleiTool
from .exceptions import VulnMinerException


class ToolManagerComponent:
    """Tool manager component for integration with VulnMiner core."""
    
    def __init__(self, config: Dict[str, Any], logger_manager=None):
        """Initialize tool manager component.
        
        Args:
            config: System configuration
            logger_manager: Logger manager instance
        """
        self.config = config
        self.logger_manager = logger_manager
        self.logger = logging.getLogger('tool_manager_component')
        
        # Core components
        self.tool_manager: Optional[ToolManager] = None
        self.registry: Optional[ToolRegistry] = None
        
        # State
        self.initialized = False
    
    def initialize(self) -> None:
        """Initialize the tool manager component."""
        try:
            self.logger.info("Initializing tool manager component")
            
            # Create registry
            registry_file = self.config.get('tools', {}).get('registry_file')
            self.registry = ToolRegistry(registry_file)
            
            # Register tool implementations
            self._register_tool_implementations()
            
            # Create tool manager
            db_path = self.config.get('tools', {}).get('db_path', 'data/tools.db')
            self.tool_manager = ToolManager(self.config, db_path)
            
            self.initialized = True
            self.logger.info("Tool manager component initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize tool manager component: {e}")
            raise VulnMinerException(f"Tool manager initialization failed: {e}")
    
    def _register_tool_implementations(self) -> None:
        """Register specific tool implementations."""
        # Register Nmap
        self.registry.register_tool_class('nmap', NmapTool)
        
        # Register Nuclei
        self.registry.register_tool_class('nuclei', NucleiTool)
        
        self.logger.debug("Tool implementations registered")
    
    def get_tool_manager(self) -> ToolManager:
        """Get tool manager instance.
        
        Returns:
            ToolManager instance
            
        Raises:
            VulnMinerException: If component not initialized
        """
        if not self.initialized or not self.tool_manager:
            raise VulnMinerException("Tool manager component not initialized")
        
        return self.tool_manager
    
    def get_registry(self) -> ToolRegistry:
        """Get tool registry instance.
        
        Returns:
            ToolRegistry instance
            
        Raises:
            VulnMinerException: If component not initialized
        """
        if not self.initialized or not self.registry:
            raise VulnMinerException("Tool manager component not initialized")
        
        return self.registry
    
    async def install_configured_tools(self) -> Dict[str, bool]:
        """Install all configured tools.
        
        Returns:
            Dictionary mapping tool names to installation success
        """
        if not self.initialized:
            raise VulnMinerException("Tool manager component not initialized")
        
        return await self.tool_manager.install_all_tools()
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on tool manager.
        
        Returns:
            Health check results
        """
        health_status = {
            'healthy': True,
            'checks': {},
            'component': 'tool_manager'
        }
        
        if not self.initialized:
            health_status['healthy'] = False
            health_status['checks']['initialization'] = {
                'status': 'failed',
                'message': 'Component not initialized'
            }
            return health_status
        
        # Check tool manager
        if self.tool_manager:
            health_status['checks']['tool_manager'] = {
                'status': 'healthy',
                'message': 'Tool manager operational'
            }
        else:
            health_status['healthy'] = False
            health_status['checks']['tool_manager'] = {
                'status': 'failed',
                'message': 'Tool manager not available'
            }
        
        # Check registry
        if self.registry:
            tool_count = len(self.registry.list_tools())
            health_status['checks']['registry'] = {
                'status': 'healthy',
                'message': f'Registry loaded with {tool_count} tools'
            }
        else:
            health_status['healthy'] = False
            health_status['checks']['registry'] = {
                'status': 'failed',
                'message': 'Tool registry not available'
            }
        
        # Check tool status
        if self.tool_manager:
            try:
                tool_status_list = self.tool_manager.list_tools()
                installed_tools = sum(1 for t in tool_status_list if t.status.value == 'installed')
                total_tools = len(tool_status_list)
                
                health_status['checks']['tools'] = {
                    'status': 'healthy' if installed_tools > 0 else 'warning',
                    'message': f'{installed_tools}/{total_tools} tools installed',
                    'installed_tools': installed_tools,
                    'total_tools': total_tools
                }
                
                if installed_tools == 0:
                    health_status['healthy'] = False
                    
            except Exception as e:
                health_status['healthy'] = False
                health_status['checks']['tools'] = {
                    'status': 'failed',
                    'message': f'Error checking tool status: {e}'
                }
        
        return health_status
    
    def shutdown(self) -> None:
        """Shutdown tool manager component."""
        self.logger.info("Shutting down tool manager component")
        
        if self.tool_manager:
            # Tool manager has async shutdown, but we can't await here
            # The core system should handle async shutdown properly
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self.tool_manager.shutdown())
                else:
                    asyncio.run(self.tool_manager.shutdown())
            except Exception as e:
                self.logger.error(f"Error shutting down tool manager: {e}")
        
        self.initialized = False
        self.logger.info("Tool manager component shutdown complete")
    
    def get_status(self) -> Dict[str, Any]:
        """Get component status.
        
        Returns:
            Status information
        """
        status = {
            'initialized': self.initialized,
            'tool_manager_available': self.tool_manager is not None,
            'registry_available': self.registry is not None
        }
        
        if self.registry:
            status['registry_stats'] = self.registry.get_stats()
        
        if self.tool_manager:
            try:
                tools = self.tool_manager.list_tools()
                status['tools'] = {
                    'total': len(tools),
                    'installed': sum(1 for t in tools if t.status.value == 'installed'),
                    'not_installed': sum(1 for t in tools if t.status.value == 'not_installed'),
                    'error': sum(1 for t in tools if t.status.value == 'error')
                }
            except Exception as e:
                status['tools_error'] = str(e)
        
        return status