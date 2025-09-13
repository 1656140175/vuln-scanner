"""Test suite for tool lifecycle management system."""

import pytest
import asyncio
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
import sqlite3

from vuln_scanner.tools.base import SecurityTool, ToolStatus, ToolInfo
from vuln_scanner.tools.registry import ToolRegistry, ToolDefinition, ToolCategory
from vuln_scanner.tools.dependencies import DependencyManager
from vuln_scanner.tools.manager import ToolManager
from vuln_scanner.tools.implementations.generic import GenericTool
from vuln_scanner.tools.implementations.nmap_tool import NmapTool


class MockSecurityTool(SecurityTool):
    """Mock security tool for testing."""
    
    def __init__(self, name: str, config: dict):
        super().__init__(name, config)
        self._version = "1.0.0"
        self._install_success = True
        self._execute_success = True
    
    async def install(self) -> bool:
        self.status = ToolStatus.INSTALLING
        await asyncio.sleep(0.1)  # Simulate installation time
        if self._install_success:
            self.status = ToolStatus.INSTALLED
        else:
            self.status = ToolStatus.ERROR
        return self._install_success
    
    async def update(self) -> bool:
        return await self.install()
    
    async def check_version(self) -> str:
        return self._version if self.status == ToolStatus.INSTALLED else None
    
    async def validate_installation(self) -> bool:
        return self.status == ToolStatus.INSTALLED
    
    async def execute(self, *args, **kwargs):
        from vuln_scanner.tools.base import ToolExecutionResult
        import time
        
        return ToolExecutionResult(
            tool=self.name,
            success=self._execute_success,
            returncode=0 if self._execute_success else 1,
            stdout="mock output",
            stderr="",
            execution_time=0.1,
            command=["mock", "command"],
            target=kwargs.get('target'),
            scan_type=kwargs.get('scan_type')
        )


@pytest.fixture
def temp_db():
    """Temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def test_config():
    """Test configuration."""
    return {
        'tools': {
            'db_path': ':memory:',  # Use in-memory SQLite for tests
            'usage_retention_days': 30,
            'testing': True,  # Skip background tasks
            'mock_tool': {
                'path': 'mock_tool',
                'timeout': 30,
                'default_args': ['-v']
            }
        },
        'system': {
            'environment': 'testing'
        }
    }


@pytest.fixture
def tool_registry():
    """Tool registry for testing."""
    return ToolRegistry()


@pytest.fixture
def dependency_manager():
    """Dependency manager for testing."""
    return DependencyManager()


@pytest.fixture
async def tool_manager(test_config, temp_db):
    """Tool manager for testing."""
    config = test_config.copy()
    config['tools']['db_path'] = temp_db
    manager = ToolManager(config, temp_db)
    yield manager
    await manager.shutdown()


class TestToolRegistry:
    """Tests for tool registry."""
    
    def test_builtin_tools_loaded(self, tool_registry):
        """Test that builtin tools are loaded."""
        tools = tool_registry.list_tools()
        tool_names = [t.name for t in tools]
        
        assert 'nmap' in tool_names
        assert 'nuclei' in tool_names
        assert 'subfinder' in tool_names
        assert len(tools) > 0
    
    def test_register_custom_tool(self, tool_registry):
        """Test registering a custom tool."""
        tool_def = ToolDefinition(
            name="test_tool",
            display_name="Test Tool",
            category=ToolCategory.UTILITY,
            description="A test tool"
        )
        
        tool_registry.register_tool(tool_def)
        
        registered_tool = tool_registry.get_tool_definition("test_tool")
        assert registered_tool is not None
        assert registered_tool.name == "test_tool"
        assert registered_tool.category == ToolCategory.UTILITY
    
    def test_search_tools(self, tool_registry):
        """Test tool search functionality."""
        results = tool_registry.search_tools("network")
        
        # Should find tools with "network" in description or tags
        assert len(results) > 0
        
        # Search for specific tool
        results = tool_registry.search_tools("nmap")
        assert len(results) >= 1
        assert any(t.name == "nmap" for t in results)
    
    def test_filter_by_category(self, tool_registry):
        """Test filtering tools by category."""
        network_scanners = tool_registry.list_tools(category=ToolCategory.NETWORK_SCANNER)
        assert len(network_scanners) > 0
        assert all(t.category == ToolCategory.NETWORK_SCANNER for t in network_scanners)
    
    def test_get_dependency_graph(self, tool_registry):
        """Test dependency graph generation."""
        deps = tool_registry.get_dependency_graph()
        
        # Nuclei should depend on Go
        assert 'nuclei' in deps
        assert 'go' in deps['nuclei']
        
        # Nmap should have no dependencies
        assert 'nmap' in deps
        assert len(deps['nmap']) == 0


class TestDependencyManager:
    """Tests for dependency manager."""
    
    @pytest.mark.asyncio
    async def test_check_dependencies(self, dependency_manager):
        """Test dependency checking."""
        # Test with a tool that has dependencies
        satisfied, missing = await dependency_manager.check_dependencies('nuclei')
        
        # We expect 'go' dependency for nuclei
        assert isinstance(satisfied, bool)
        assert isinstance(missing, list)
        if not satisfied:
            assert 'go' in missing
    
    def test_dependency_resolution_order(self, dependency_manager):
        """Test dependency resolution ordering."""
        tools = ['nuclei', 'subfinder']  # Both depend on Go
        deps = dependency_manager.get_dependency_graph()
        
        order = dependency_manager._resolve_dependency_order(tools, deps)
        
        # Should include the tools and potentially dependencies
        assert isinstance(order, list)
        assert len(order) >= len(tools)
    
    def test_version_comparison(self, dependency_manager):
        """Test version comparison logic."""
        assert dependency_manager._compare_versions("1.2.0", "1.1.0") == 1
        assert dependency_manager._compare_versions("1.1.0", "1.2.0") == -1
        assert dependency_manager._compare_versions("1.1.0", "1.1.0") == 0
        assert dependency_manager._compare_versions("2.0.0", "1.9.9") == 1


class TestToolManager:
    """Tests for tool manager."""
    
    @pytest.mark.asyncio
    async def test_tool_manager_initialization(self, tool_manager):
        """Test tool manager initialization."""
        assert tool_manager.registry is not None
        assert tool_manager.dependency_manager is not None
        assert Path(tool_manager.db_path).exists() or tool_manager.db_path == ':memory:'
    
    @pytest.mark.asyncio
    async def test_register_mock_tool(self, tool_manager):
        """Test registering and getting a mock tool."""
        # Register mock tool class
        tool_manager.registry.register_tool_class('mock_tool', MockSecurityTool)
        
        # Get tool instance
        tool = await tool_manager.get_tool('mock_tool', auto_install=False)
        assert isinstance(tool, MockSecurityTool)
        assert tool.name == 'mock_tool'
    
    @pytest.mark.asyncio
    async def test_tool_installation(self, tool_manager):
        """Test tool installation process."""
        # Register mock tool
        tool_manager.registry.register_tool_class('mock_tool', MockSecurityTool)
        
        # Install tool
        success = await tool_manager.install_tool('mock_tool')
        assert success
        
        # Check status
        status = tool_manager.get_tool_status('mock_tool')
        assert status is not None
        assert status.status == ToolStatus.INSTALLED
    
    @pytest.mark.asyncio
    async def test_tool_execution(self, tool_manager):
        """Test tool execution."""
        # Register and install mock tool
        tool_manager.registry.register_tool_class('mock_tool', MockSecurityTool)
        await tool_manager.install_tool('mock_tool')
        
        # Execute tool
        result = await tool_manager.execute_tool('mock_tool', 'test_arg', target='test_target')
        
        assert result.success
        assert result.tool == 'mock_tool'
        assert result.target == 'test_target'
        assert result.execution_time > 0
    
    @pytest.mark.asyncio
    async def test_usage_statistics(self, tool_manager):
        """Test usage statistics collection."""
        # Register and install mock tool
        tool_manager.registry.register_tool_class('mock_tool', MockSecurityTool)
        await tool_manager.install_tool('mock_tool')
        
        # Execute tool multiple times
        for i in range(3):
            await tool_manager.execute_tool('mock_tool', f'arg_{i}')
        
        # Get usage stats
        stats = tool_manager.get_usage_stats('mock_tool')
        
        assert stats['tool_name'] == 'mock_tool'
        assert stats['total_executions'] == 3
        assert stats['successful_executions'] == 3
        assert stats['success_rate'] == 1.0
    
    @pytest.mark.asyncio
    async def test_tool_not_found_error(self, tool_manager):
        """Test error when tool not found."""
        from vuln_scanner.tools.manager import ToolNotFoundError
        
        with pytest.raises(ToolNotFoundError):
            await tool_manager.get_tool('nonexistent_tool')


class TestNmapTool:
    """Tests for Nmap tool implementation."""
    
    def test_nmap_initialization(self):
        """Test Nmap tool initialization."""
        config = {
            'path': 'nmap',
            'timeout': 300,
            'default_args': ['-sS', '-sV']
        }
        
        nmap = NmapTool(config)
        assert nmap.name == 'nmap'
        assert nmap.binary_path == 'nmap'
        assert nmap.timeout == 300
        assert '-sS' in nmap.default_args
    
    def test_scan_profiles(self):
        """Test Nmap scan profiles."""
        config = {'path': 'nmap'}
        nmap = NmapTool(config)
        
        profiles = nmap.get_available_scan_types()
        
        assert 'basic' in profiles
        assert 'comprehensive' in profiles
        assert 'stealth' in profiles
        assert isinstance(profiles['basic'], list)
    
    @pytest.mark.asyncio
    async def test_nmap_version_check(self):
        """Test Nmap version checking."""
        config = {'path': 'nmap'}
        nmap = NmapTool(config)
        
        # Mock version check
        with patch.object(nmap, '_run_command') as mock_run:
            mock_run.return_value = {
                'returncode': 0,
                'stdout': 'Nmap version 7.93 ( https://nmap.org )',
                'stderr': ''
            }
            
            version = await nmap.check_version()
            assert version == '7.93'
    
    @pytest.mark.asyncio
    async def test_nmap_execution_mock(self):
        """Test Nmap execution with mocked command."""
        config = {'path': 'nmap'}
        nmap = NmapTool(config)
        
        # Mock command execution
        with patch.object(nmap, '_run_command') as mock_run:
            mock_run.return_value = {
                'returncode': 0,
                'stdout': 'Starting Nmap scan...\nNmap scan completed',
                'stderr': ''
            }
            
            result = await nmap.execute('127.0.0.1', scan_type='basic')
            
            assert result.success
            assert result.tool == 'nmap'
            assert result.target == '127.0.0.1'
            assert result.scan_type == 'basic'


class TestGenericTool:
    """Tests for generic tool implementation."""
    
    def test_generic_tool_initialization(self):
        """Test generic tool initialization."""
        tool_def = ToolDefinition(
            name="test_tool",
            display_name="Test Tool",
            category=ToolCategory.UTILITY,
            description="A test tool",
            binary_name="test_tool",
            version_command=["test_tool", "--version"],
            version_regex=r"version (\d+\.\d+)"
        )
        
        config = {'path': 'test_tool'}
        
        tool = GenericTool('test_tool', config, tool_def)
        
        assert tool.name == 'test_tool'
        assert tool.binary_path == 'test_tool'
        assert tool.version_command == ["test_tool", "--version"]
        assert tool.version_regex == r"version (\d+\.\d+)"
    
    @pytest.mark.asyncio
    async def test_generic_version_parsing(self):
        """Test generic version parsing."""
        tool_def = ToolDefinition(
            name="test_tool",
            display_name="Test Tool", 
            category=ToolCategory.UTILITY,
            description="A test tool",
            version_regex=r"version (\d+\.\d+\.\d+)"
        )
        
        config = {'path': 'test_tool'}
        tool = GenericTool('test_tool', config, tool_def)
        
        # Mock version check
        with patch.object(tool, '_run_command') as mock_run:
            mock_run.return_value = {
                'returncode': 0,
                'stdout': 'test_tool version 1.2.3\n',
                'stderr': ''
            }
            
            version = await tool.check_version()
            assert version == '1.2.3'
    
    @pytest.mark.asyncio
    async def test_generic_execution(self):
        """Test generic tool execution."""
        tool_def = ToolDefinition(
            name="test_tool",
            display_name="Test Tool",
            category=ToolCategory.UTILITY,
            description="A test tool"
        )
        
        config = {'path': 'test_tool', 'default_args': ['--verbose']}
        tool = GenericTool('test_tool', config, tool_def)
        
        # Mock command execution
        with patch.object(tool, '_run_command') as mock_run:
            mock_run.return_value = {
                'returncode': 0,
                'stdout': '{"result": "success"}',
                'stderr': ''
            }
            
            result = await tool.execute('arg1', 'arg2')
            
            assert result.success
            assert result.tool == 'test_tool'
            assert result.parsed_output == {"result": "success"}
            mock_run.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])