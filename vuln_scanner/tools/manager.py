"""Main tool manager for security tools lifecycle management."""

import asyncio
import logging
import sqlite3
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Type
from contextlib import asynccontextmanager
import threading

from .base import SecurityTool, ToolStatus, ToolInfo, ToolExecutionResult
from .registry import ToolRegistry, ToolDefinition
from .dependencies import DependencyManager
from ..core.exceptions import VulnMinerException


class ToolManagerError(VulnMinerException):
    """Tool manager specific errors."""
    pass


class ToolNotFoundError(ToolManagerError):
    """Tool not found in registry."""
    pass


class ToolInstallationError(ToolManagerError):
    """Tool installation failed."""
    pass


class ToolManager:
    """Main tool manager for security tools lifecycle management."""
    
    def __init__(self, config: Dict[str, Any], db_path: Optional[str] = None):
        """Initialize tool manager.
        
        Args:
            config: System configuration
            db_path: Path to SQLite database file
        """
        self.config = config
        self.logger = logging.getLogger('tool_manager')
        
        # Database setup
        self.db_path = db_path or config.get('tools', {}).get('db_path', 'data/tools.db')
        self._db_lock = threading.RLock()
        
        # Core components
        self.registry = ToolRegistry(config.get('tools', {}).get('registry_file'))
        self.dependency_manager = DependencyManager()
        
        # Tool instances
        self.tools: Dict[str, SecurityTool] = {}
        self._tool_locks: Dict[str, asyncio.Lock] = {}
        
        # Background tasks
        self._background_tasks: List[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()
        
        # Initialize
        self._init_database()
        self._load_tool_configurations()
        
        # Start background tasks
        if not config.get('testing', False):  # Skip background tasks in testing
            self._start_background_tasks()
    
    def _init_database(self) -> None:
        """Initialize SQLite database."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with self._db_lock:
            conn = sqlite3.connect(self.db_path)
            try:
                # Create tools table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS tools (
                        name TEXT PRIMARY KEY,
                        version TEXT,
                        path TEXT,
                        status TEXT NOT NULL,
                        last_updated TEXT,
                        last_check TEXT,
                        config TEXT,
                        installation_log TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create tool usage stats table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS tool_usage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tool_name TEXT NOT NULL,
                        execution_time REAL NOT NULL,
                        success INTEGER NOT NULL,
                        target TEXT,
                        scan_type TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (tool_name) REFERENCES tools (name)
                    )
                ''')
                
                # Create indexes
                conn.execute('CREATE INDEX IF NOT EXISTS idx_tool_usage_tool ON tool_usage(tool_name)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_tool_usage_created ON tool_usage(created_at)')
                
                conn.commit()
                
            finally:
                conn.close()
    
    def _load_tool_configurations(self) -> None:
        """Load tool configurations from config."""
        tools_config = self.config.get('tools', {})
        
        # Register tool implementations based on config
        for tool_name, tool_config in tools_config.items():
            if tool_name in ['db_path', 'registry_file']:  # Skip system config keys
                continue
            
            if isinstance(tool_config, dict):
                # Get tool definition from registry
                tool_def = self.registry.get_tool_definition(tool_name)
                if tool_def:
                    # Merge default config with user config
                    merged_config = {**tool_def.default_config, **tool_config}
                    
                    # Store merged config for later instantiation
                    self.config.setdefault('tools', {})[tool_name] = merged_config
    
    def _start_background_tasks(self) -> None:
        """Start background tasks."""
        # Update check task
        update_task = asyncio.create_task(self._update_check_loop())
        self._background_tasks.append(update_task)
        
        # Cleanup task
        cleanup_task = asyncio.create_task(self._cleanup_loop())
        self._background_tasks.append(cleanup_task)
        
        self.logger.info("Background tasks started")
    
    async def _update_check_loop(self) -> None:
        """Background loop for checking tool updates."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(3600)  # Check every hour
                
                if self._shutdown_event.is_set():
                    break
                
                await self.check_updates()
                
            except Exception as e:
                self.logger.error(f"Error in update check loop: {e}")
                await asyncio.sleep(60)  # Wait before retry
    
    async def _cleanup_loop(self) -> None:
        """Background loop for cleanup tasks."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(86400)  # Daily cleanup
                
                if self._shutdown_event.is_set():
                    break
                
                await self._cleanup_old_usage_stats()
                
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(3600)  # Wait before retry
    
    async def _cleanup_old_usage_stats(self) -> None:
        """Clean up old usage statistics."""
        retention_days = self.config.get('tools', {}).get('usage_retention_days', 30)
        cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()
        
        with self._db_lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute(
                    'DELETE FROM tool_usage WHERE created_at < ?',
                    (cutoff_date,)
                )
                deleted_count = cursor.rowcount
                conn.commit()
                
                if deleted_count > 0:
                    self.logger.info(f"Cleaned up {deleted_count} old usage records")
                    
            finally:
                conn.close()
    
    async def get_tool(self, name: str, auto_install: bool = False) -> SecurityTool:
        """Get tool instance, optionally installing if needed.
        
        Args:
            name: Tool name
            auto_install: Whether to automatically install if not available
            
        Returns:
            Tool instance
            
        Raises:
            ToolNotFoundError: If tool not found in registry
            ToolInstallationError: If installation fails
        """
        # Get or create lock for this tool
        if name not in self._tool_locks:
            self._tool_locks[name] = asyncio.Lock()
        
        async with self._tool_locks[name]:
            # Return cached instance if available and installed
            if name in self.tools:
                tool = self.tools[name]
                if tool.status == ToolStatus.INSTALLED:
                    return tool
            
            # Get tool definition from registry
            tool_def = self.registry.get_tool_definition(name)
            if not tool_def:
                raise ToolNotFoundError(f"Tool '{name}' not found in registry")
            
            # Get tool configuration
            tool_config = self.config.get('tools', {}).get(name, tool_def.default_config)
            
            # Create tool instance
            tool_class = self.registry.get_tool_class(name)
            if tool_class:
                tool = tool_class(tool_config)
            else:
                # Use generic tool wrapper (will be implemented)
                from .implementations.generic import GenericTool
                tool = GenericTool(name, tool_config, tool_def)
            
            # Check if tool is already installed
            if await tool.validate_installation():
                tool.status = ToolStatus.INSTALLED
                version = await tool.check_version()
                self._save_tool_status(tool, version)
            elif auto_install:
                # Install tool and dependencies
                success = await self.install_tool(name)
                if not success:
                    raise ToolInstallationError(f"Failed to install tool '{name}'")
            
            # Cache the tool instance
            self.tools[name] = tool
            return tool
    
    async def install_tool(self, name: str) -> bool:
        """Install a specific tool.
        
        Args:
            name: Tool name to install
            
        Returns:
            True if installation successful
        """
        self.logger.info(f"Installing tool: {name}")
        
        tool_def = self.registry.get_tool_definition(name)
        if not tool_def:
            raise ToolNotFoundError(f"Tool '{name}' not found in registry")
        
        try:
            # Install dependencies first
            if tool_def.dependencies:
                self.logger.info(f"Installing dependencies for {name}: {tool_def.dependencies}")
                deps_installed = await self.dependency_manager.install_dependencies(name)
                if not deps_installed:
                    self.logger.error(f"Failed to install dependencies for {name}")
                    return False
            
            # Get tool instance
            tool = await self.get_tool(name, auto_install=False)
            
            # Install the tool
            tool.status = ToolStatus.INSTALLING
            self._save_tool_status(tool, installation_log="Starting installation")
            
            success = await tool.install()
            
            if success:
                tool.status = ToolStatus.INSTALLED
                version = await tool.check_version()
                self._save_tool_status(tool, version, "Installation completed successfully")
                self.logger.info(f"Tool {name} installed successfully")
            else:
                tool.status = ToolStatus.ERROR
                self._save_tool_status(tool, installation_log="Installation failed")
                self.logger.error(f"Tool {name} installation failed")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error installing tool {name}: {e}")
            if name in self.tools:
                self.tools[name].status = ToolStatus.ERROR
                self._save_tool_status(self.tools[name], installation_log=f"Installation error: {str(e)}")
            return False
    
    async def install_all_tools(self) -> Dict[str, bool]:
        """Install all configured tools.
        
        Returns:
            Dictionary mapping tool names to installation success
        """
        results = {}
        tools_config = self.config.get('tools', {})
        
        # Get list of tools to install
        tool_names = [name for name in tools_config.keys() 
                     if name not in ['db_path', 'registry_file'] and 
                     isinstance(tools_config[name], dict)]
        
        self.logger.info(f"Installing {len(tool_names)} tools: {tool_names}")
        
        # Install tools with dependency resolution
        dependency_graph = self.registry.get_dependency_graph()
        install_order = self._resolve_install_order(tool_names, dependency_graph)
        
        for tool_name in install_order:
            try:
                results[tool_name] = await self.install_tool(tool_name)
            except Exception as e:
                self.logger.error(f"Failed to install {tool_name}: {e}")
                results[tool_name] = False
        
        successful = sum(1 for success in results.values() if success)
        self.logger.info(f"Installation complete: {successful}/{len(results)} tools installed")
        
        return results
    
    def _resolve_install_order(self, tool_names: List[str], 
                              dependency_graph: Dict[str, List[str]]) -> List[str]:
        """Resolve tool installation order based on dependencies.
        
        Args:
            tool_names: List of tools to install
            dependency_graph: Tool dependency mapping
            
        Returns:
            List of tools in installation order
        """
        visited = set()
        temp_visited = set()
        result = []
        
        def visit(tool: str):
            if tool in temp_visited:
                # Circular dependency - log warning and continue
                self.logger.warning(f"Circular dependency detected involving {tool}")
                return
            if tool in visited:
                return
            
            temp_visited.add(tool)
            
            # Visit dependencies first
            deps = dependency_graph.get(tool, [])
            for dep in deps:
                if dep in tool_names:  # Only consider tools we're actually installing
                    visit(dep)
            
            temp_visited.remove(tool)
            visited.add(tool)
            result.append(tool)
        
        for tool_name in tool_names:
            if tool_name not in visited:
                visit(tool_name)
        
        return result
    
    async def update_tool(self, name: str) -> bool:
        """Update a specific tool.
        
        Args:
            name: Tool name to update
            
        Returns:
            True if update successful
        """
        self.logger.info(f"Updating tool: {name}")
        
        try:
            tool = await self.get_tool(name)
            
            if tool.status != ToolStatus.INSTALLED:
                self.logger.warning(f"Tool {name} is not installed, cannot update")
                return False
            
            tool.status = ToolStatus.UPDATING
            self._save_tool_status(tool)
            
            success = await tool.update()
            
            if success:
                tool.status = ToolStatus.INSTALLED
                version = await tool.check_version()
                self._save_tool_status(tool, version, "Update completed successfully")
                self.logger.info(f"Tool {name} updated successfully")
            else:
                tool.status = ToolStatus.ERROR
                self._save_tool_status(tool, installation_log="Update failed")
                self.logger.error(f"Tool {name} update failed")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error updating tool {name}: {e}")
            return False
    
    async def check_updates(self) -> Dict[str, bool]:
        """Check for updates for all installed tools.
        
        Returns:
            Dictionary mapping tool names to update availability
        """
        updates_available = {}
        
        for tool_name in self.tools:
            try:
                tool = self.tools[tool_name]
                
                if tool.status != ToolStatus.INSTALLED:
                    continue
                
                # Check if we should check for updates (rate limiting)
                last_check = self._get_last_update_check(tool_name)
                if last_check and (datetime.now() - last_check).total_seconds() < 86400:  # 24 hours
                    continue
                
                # This is a simplified check - real implementation would 
                # check remote versions
                current_version = await tool.check_version()
                updates_available[tool_name] = False  # Placeholder
                
                self._save_last_update_check(tool_name)
                
            except Exception as e:
                self.logger.debug(f"Error checking updates for {tool_name}: {e}")
                updates_available[tool_name] = False
        
        return updates_available
    
    async def execute_tool(self, name: str, *args, **kwargs) -> ToolExecutionResult:
        """Execute a tool with given arguments.
        
        Args:
            name: Tool name
            *args: Positional arguments for tool
            **kwargs: Keyword arguments for tool
            
        Returns:
            Tool execution result
        """
        start_time = time.time()
        
        try:
            tool = await self.get_tool(name, auto_install=True)
            
            if tool.status != ToolStatus.INSTALLED:
                raise ToolManagerError(f"Tool '{name}' is not installed")
            
            # Execute tool
            result = await tool.execute(*args, **kwargs)
            
            # Record usage statistics
            execution_time = time.time() - start_time
            await self._record_usage(name, execution_time, result.success,
                                   result.target, result.scan_type)
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            await self._record_usage(name, execution_time, False)
            
            # Create error result
            return ToolExecutionResult(
                tool=name,
                success=False,
                returncode=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                command=[],
                error=str(e)
            )
    
    async def _record_usage(self, tool_name: str, execution_time: float,
                          success: bool, target: Optional[str] = None,
                          scan_type: Optional[str] = None) -> None:
        """Record tool usage statistics."""
        try:
            with self._db_lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    conn.execute('''
                        INSERT INTO tool_usage 
                        (tool_name, execution_time, success, target, scan_type)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (tool_name, execution_time, int(success), target, scan_type))
                    conn.commit()
                finally:
                    conn.close()
        except Exception as e:
            self.logger.debug(f"Error recording usage stats: {e}")
    
    def _save_tool_status(self, tool: SecurityTool, version: Optional[str] = None,
                         installation_log: Optional[str] = None) -> None:
        """Save tool status to database."""
        try:
            with self._db_lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    now = datetime.now().isoformat()
                    
                    conn.execute('''
                        INSERT OR REPLACE INTO tools 
                        (name, version, path, status, last_updated, config, installation_log, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        tool.name,
                        version,
                        tool.binary_path,
                        tool.status.value,
                        now if tool.status in [ToolStatus.INSTALLED, ToolStatus.UPDATED] else None,
                        json.dumps(tool.config),
                        installation_log,
                        now
                    ))
                    conn.commit()
                finally:
                    conn.close()
        except Exception as e:
            self.logger.debug(f"Error saving tool status: {e}")
    
    def _get_last_update_check(self, tool_name: str) -> Optional[datetime]:
        """Get last update check time for tool."""
        try:
            with self._db_lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.execute(
                        'SELECT last_check FROM tools WHERE name = ?',
                        (tool_name,)
                    )
                    result = cursor.fetchone()
                    if result and result[0]:
                        return datetime.fromisoformat(result[0])
                    return None
                finally:
                    conn.close()
        except Exception:
            return None
    
    def _save_last_update_check(self, tool_name: str) -> None:
        """Save last update check time for tool."""
        try:
            with self._db_lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    conn.execute('''
                        UPDATE tools SET last_check = ? WHERE name = ?
                    ''', (datetime.now().isoformat(), tool_name))
                    conn.commit()
                finally:
                    conn.close()
        except Exception as e:
            self.logger.debug(f"Error saving update check time: {e}")
    
    def get_tool_status(self, name: str) -> Optional[ToolInfo]:
        """Get current status of a tool.
        
        Args:
            name: Tool name
            
        Returns:
            Tool information or None if not found
        """
        if name in self.tools:
            return self.tools[name].get_info()
        
        # Check database
        try:
            with self._db_lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.execute(
                        'SELECT version, path, status, last_updated, config FROM tools WHERE name = ?',
                        (name,)
                    )
                    result = cursor.fetchone()
                    if result:
                        config = json.loads(result[4]) if result[4] else {}
                        return ToolInfo(
                            name=name,
                            version=result[0],
                            path=result[1],
                            status=ToolStatus(result[2]),
                            last_updated=result[3],
                            config=config
                        )
                finally:
                    conn.close()
        except Exception as e:
            self.logger.debug(f"Error getting tool status: {e}")
        
        return None
    
    def list_tools(self) -> List[ToolInfo]:
        """List all tools and their status.
        
        Returns:
            List of tool information
        """
        tools_info = []
        
        # Get all tools from registry
        for tool_def in self.registry.list_tools():
            status = self.get_tool_status(tool_def.name)
            if status:
                tools_info.append(status)
            else:
                # Tool in registry but not installed
                tools_info.append(ToolInfo(
                    name=tool_def.name,
                    status=ToolStatus.NOT_INSTALLED,
                    config=tool_def.default_config,
                    dependencies=tool_def.dependencies
                ))
        
        return tools_info
    
    def get_usage_stats(self, tool_name: Optional[str] = None,
                       days: int = 30) -> Dict[str, Any]:
        """Get tool usage statistics.
        
        Args:
            tool_name: Specific tool name (optional)
            days: Number of days to look back
            
        Returns:
            Usage statistics
        """
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        try:
            with self._db_lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    if tool_name:
                        # Stats for specific tool
                        cursor = conn.execute('''
                            SELECT 
                                COUNT(*) as total_executions,
                                SUM(success) as successful_executions,
                                AVG(execution_time) as avg_execution_time,
                                MAX(execution_time) as max_execution_time,
                                MIN(execution_time) as min_execution_time
                            FROM tool_usage 
                            WHERE tool_name = ? AND created_at >= ?
                        ''', (tool_name, cutoff_date))
                        
                        result = cursor.fetchone()
                        if result:
                            return {
                                'tool_name': tool_name,
                                'period_days': days,
                                'total_executions': result[0],
                                'successful_executions': result[1] or 0,
                                'failed_executions': result[0] - (result[1] or 0),
                                'success_rate': (result[1] or 0) / result[0] if result[0] > 0 else 0,
                                'avg_execution_time': result[2] or 0,
                                'max_execution_time': result[3] or 0,
                                'min_execution_time': result[4] or 0
                            }
                    else:
                        # Overall stats
                        cursor = conn.execute('''
                            SELECT 
                                tool_name,
                                COUNT(*) as executions,
                                SUM(success) as successes,
                                AVG(execution_time) as avg_time
                            FROM tool_usage 
                            WHERE created_at >= ?
                            GROUP BY tool_name
                            ORDER BY executions DESC
                        ''', (cutoff_date,))
                        
                        tool_stats = {}
                        total_executions = 0
                        total_successes = 0
                        
                        for row in cursor:
                            tool_name, executions, successes, avg_time = row
                            tool_stats[tool_name] = {
                                'executions': executions,
                                'successes': successes or 0,
                                'success_rate': (successes or 0) / executions,
                                'avg_execution_time': avg_time or 0
                            }
                            total_executions += executions
                            total_successes += (successes or 0)
                        
                        return {
                            'period_days': days,
                            'total_executions': total_executions,
                            'total_successes': total_successes,
                            'overall_success_rate': total_successes / total_executions if total_executions > 0 else 0,
                            'tool_stats': tool_stats
                        }
                        
                finally:
                    conn.close()
        except Exception as e:
            self.logger.error(f"Error getting usage stats: {e}")
            return {}
    
    @asynccontextmanager
    async def managed_tool(self, name: str):
        """Context manager for tool usage.
        
        Args:
            name: Tool name
            
        Yields:
            Tool instance
        """
        tool = await self.get_tool(name, auto_install=True)
        try:
            yield tool
        finally:
            # Cleanup if needed
            pass
    
    async def shutdown(self) -> None:
        """Shutdown tool manager."""
        self.logger.info("Shutting down tool manager")
        
        # Signal shutdown to background tasks
        self._shutdown_event.set()
        
        # Wait for background tasks to complete
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        
        # Clear tool instances
        self.tools.clear()
        
        self.logger.info("Tool manager shutdown complete")
    
    def __del__(self):
        """Destructor."""
        if hasattr(self, '_shutdown_event') and not self._shutdown_event.is_set():
            asyncio.create_task(self.shutdown())