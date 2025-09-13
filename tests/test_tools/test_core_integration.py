"""Test suite for tool manager integration with VulnMiner core."""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock

from vuln_scanner.core.core_manager import VulnMinerCore
from vuln_scanner.core.tool_manager import ToolManagerComponent
from vuln_scanner.tools.registry import ToolRegistry


@pytest.fixture
def test_config_file():
    """Create a temporary test configuration file."""
    config_content = """
system:
  version: "1.0.0-test"
  environment: "testing"
  debug: true

security:
  authorization:
    enabled: false  # Disable for testing
  rate_limiting:
    enabled: false

logging:
  level: "DEBUG"

database:
  type: "sqlite"
  path: ":memory:"

tools:
  db_path: ":memory:"
  auto_install: false
  nmap:
    path: "nmap"
    timeout: 30
  nuclei:
    path: "nuclei"
    timeout: 60

scanning:
  default_profile: "quick"

reporting:
  formats:
    - "json"
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write(config_content)
        config_path = f.name
    
    yield config_path
    Path(config_path).unlink(missing_ok=True)


class TestToolManagerIntegration:
    """Tests for tool manager integration with core system."""
    
    def test_tool_manager_component_initialization(self):
        """Test tool manager component initialization."""
        config = {
            'tools': {
                'db_path': ':memory:',
                'nmap': {'path': 'nmap'}
            }
        }
        
        component = ToolManagerComponent(config)
        component.initialize()
        
        assert component.initialized
        assert component.tool_manager is not None
        assert component.registry is not None
    
    def test_get_tool_manager(self):
        """Test getting tool manager instance."""
        config = {
            'tools': {
                'db_path': ':memory:',
                'nmap': {'path': 'nmap'}
            }
        }
        
        component = ToolManagerComponent(config)
        component.initialize()
        
        tool_manager = component.get_tool_manager()
        assert tool_manager is not None
        assert hasattr(tool_manager, 'registry')
        assert hasattr(tool_manager, 'dependency_manager')
    
    def test_get_registry(self):
        """Test getting tool registry instance."""
        config = {
            'tools': {
                'db_path': ':memory:',
                'nmap': {'path': 'nmap'}
            }
        }
        
        component = ToolManagerComponent(config)
        component.initialize()
        
        registry = component.get_registry()
        assert isinstance(registry, ToolRegistry)
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test health check functionality."""
        config = {
            'tools': {
                'db_path': ':memory:',
                'nmap': {'path': 'nmap'}
            }
        }
        
        component = ToolManagerComponent(config)
        component.initialize()
        
        health = await component.health_check()
        
        assert isinstance(health, dict)
        assert 'healthy' in health
        assert 'checks' in health
        assert 'component' in health
        assert health['component'] == 'tool_manager'
    
    def test_get_status(self):
        """Test status information."""
        config = {
            'tools': {
                'db_path': ':memory:',
                'nmap': {'path': 'nmap'}
            }
        }
        
        component = ToolManagerComponent(config)
        component.initialize()
        
        status = component.get_status()
        
        assert isinstance(status, dict)
        assert 'initialized' in status
        assert 'tool_manager_available' in status
        assert 'registry_available' in status
        assert status['initialized'] is True
        assert status['tool_manager_available'] is True
        assert status['registry_available'] is True


class TestCoreIntegration:
    """Tests for core system integration."""
    
    def test_core_initialization_with_tools(self, test_config_file):
        """Test core system initialization with tool manager."""
        # Skip tool validation to avoid dependency issues in tests
        with patch('vuln_scanner.core.core_manager.VulnMinerCore._validate_environment'):
            core = VulnMinerCore(test_config_file, skip_tool_validation=True)
            
            assert core.initialized
            assert core.tool_manager_component is not None
            assert core.tool_manager_component.initialized
    
    def test_get_tool_manager_from_core(self, test_config_file):
        """Test getting tool manager from core system."""
        with patch('vuln_scanner.core.core_manager.VulnMinerCore._validate_environment'):
            core = VulnMinerCore(test_config_file, skip_tool_validation=True)
            
            tool_manager = core.get_tool_manager()
            assert tool_manager is not None
    
    def test_system_status_includes_tools(self, test_config_file):
        """Test that system status includes tool information."""
        with patch('vuln_scanner.core.core_manager.VulnMinerCore._validate_environment'):
            core = VulnMinerCore(test_config_file, skip_tool_validation=True)
            
            status = core.get_system_status()
            
            assert 'tool_manager' in status
            assert isinstance(status['tool_manager'], dict)
    
    def test_health_check_includes_tools(self, test_config_file):
        """Test that health check includes tool manager."""
        with patch('vuln_scanner.core.core_manager.VulnMinerCore._validate_environment'):
            with patch('asyncio.run') as mock_run:
                # Mock the async health check
                mock_run.return_value = {
                    'healthy': True,
                    'checks': {
                        'tool_manager': {'status': 'healthy', 'message': 'Test OK'},
                        'registry': {'status': 'healthy', 'message': 'Test OK'},
                        'tools': {'status': 'healthy', 'message': 'Test OK'}
                    }
                }
                
                core = VulnMinerCore(test_config_file, skip_tool_validation=True)
                health = core.health_check()
                
                assert 'tool_manager_component' in health['checks']
                # The mocked health check should be called
                mock_run.assert_called()
    
    def test_component_registration(self, test_config_file):
        """Test that tool manager is properly registered as a component."""
        with patch('vuln_scanner.core.core_manager.VulnMinerCore._validate_environment'):
            core = VulnMinerCore(test_config_file, skip_tool_validation=True)
            
            # Check that tool manager is in the component manager
            component_status = core.component_manager.get_component_status()
            
            assert 'tool_manager' in component_status
            assert component_status['tool_manager']['initialized']
            assert not component_status['tool_manager']['shutdown']


class TestConfigurationIntegration:
    """Tests for configuration integration."""
    
    def test_tool_configuration_loading(self, test_config_file):
        """Test that tool configurations are properly loaded."""
        with patch('vuln_scanner.core.core_manager.VulnMinerCore._validate_environment'):
            core = VulnMinerCore(test_config_file, skip_tool_validation=True)
            
            # Check that tool configurations are loaded
            tools_config = core.get_config('tools')
            assert isinstance(tools_config, dict)
            assert 'nmap' in tools_config
            assert 'nuclei' in tools_config
    
    def test_tool_manager_uses_config(self, test_config_file):
        """Test that tool manager uses configuration properly."""
        with patch('vuln_scanner.core.core_manager.VulnMinerCore._validate_environment'):
            core = VulnMinerCore(test_config_file, skip_tool_validation=True)
            
            tool_manager = core.get_tool_manager()
            
            # Check that config is passed to tool manager
            assert tool_manager.config is not None
            assert 'tools' in tool_manager.config
    
    def test_database_configuration(self, test_config_file):
        """Test that database configuration is applied."""
        with patch('vuln_scanner.core.core_manager.VulnMinerCore._validate_environment'):
            core = VulnMinerCore(test_config_file, skip_tool_validation=True)
            
            tool_manager = core.get_tool_manager()
            
            # Should use in-memory database for testing
            assert tool_manager.db_path == ':memory:'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])