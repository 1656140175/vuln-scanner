"""Tests for configuration management system."""

import pytest
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, mock_open

from vuln_scanner.core.config import ConfigManager, ConfigValidator
from vuln_scanner.core.exceptions import ConfigurationError, ConfigValidationError


class TestConfigManager:
    """Test cases for ConfigManager."""
    
    def test_init_without_config_file(self):
        """Test initialization without config file."""
        with patch('pathlib.Path.exists', return_value=False):
            config_manager = ConfigManager()
            assert config_manager.config == {}
    
    def test_init_with_config_file(self, temp_dir, test_config):
        """Test initialization with valid config file."""
        config_file = temp_dir / 'config.yml'
        with open(config_file, 'w') as f:
            yaml.dump(test_config, f)
        
        config_manager = ConfigManager(str(config_file))
        assert config_manager.get('system.version') == '1.0.0'
        assert config_manager.get('system.environment') == 'testing'
    
    def test_get_configuration_value(self, test_config):
        """Test getting configuration values."""
        with patch.object(ConfigManager, '_load_configuration'):
            config_manager = ConfigManager()
            config_manager.config = test_config
            
            # Test nested key access
            assert config_manager.get('system.version') == '1.0.0'
            assert config_manager.get('security.authorization.enabled') is True
            
            # Test default values
            assert config_manager.get('nonexistent.key', 'default') == 'default'
            assert config_manager.get('nonexistent.key') is None
    
    def test_set_configuration_value(self, test_config):
        """Test setting configuration values."""
        with patch.object(ConfigManager, '_load_configuration'):
            config_manager = ConfigManager()
            config_manager.config = test_config
            
            # Set new value
            config_manager.set('system.new_key', 'new_value')
            assert config_manager.get('system.new_key') == 'new_value'
            
            # Override existing value
            config_manager.set('system.version', '2.0.0')
            assert config_manager.get('system.version') == '2.0.0'
    
    def test_get_section(self, test_config):
        """Test getting configuration sections."""
        with patch.object(ConfigManager, '_load_configuration'):
            config_manager = ConfigManager()
            config_manager.config = test_config
            
            system_section = config_manager.get_section('system')
            assert system_section['version'] == '1.0.0'
            assert system_section['environment'] == 'testing'
            
            # Test non-existent section
            empty_section = config_manager.get_section('nonexistent')
            assert empty_section == {}
    
    def test_deep_merge(self):
        """Test deep merge functionality."""
        with patch.object(ConfigManager, '_load_configuration'):
            config_manager = ConfigManager()
            
            base = {
                'level1': {
                    'level2': {
                        'key1': 'value1',
                        'key2': 'value2'
                    }
                }
            }
            
            update = {
                'level1': {
                    'level2': {
                        'key2': 'updated_value2',
                        'key3': 'value3'
                    }
                }
            }
            
            config_manager._deep_merge(base, update)
            
            assert base['level1']['level2']['key1'] == 'value1'
            assert base['level1']['level2']['key2'] == 'updated_value2'
            assert base['level1']['level2']['key3'] == 'value3'
    
    def test_environment_variable_override(self):
        """Test environment variable configuration override."""
        with patch.dict('os.environ', {
            'VULN_MINER_DEBUG': 'false',
            'VULN_MINER_LOG_LEVEL': 'ERROR',
            'VULN_MINER_MAX_CONCURRENT': '5'
        }):
            with patch('pathlib.Path.exists', return_value=False):
                config_manager = ConfigManager()
                config_manager._load_environment_variables()
                
                assert config_manager.get('system.debug') is False
                assert config_manager.get('logging.level') == 'ERROR'
                assert config_manager.get('system.max_concurrent_scans') == 5
    
    def test_convert_env_value(self):
        """Test environment variable value conversion."""
        with patch.object(ConfigManager, '_load_configuration'):
            config_manager = ConfigManager()
            
            # Test boolean conversion
            assert config_manager._convert_env_value('true') is True
            assert config_manager._convert_env_value('false') is False
            assert config_manager._convert_env_value('True') is True
            assert config_manager._convert_env_value('FALSE') is False
            
            # Test numeric conversion
            assert config_manager._convert_env_value('42') == 42
            assert config_manager._convert_env_value('3.14') == 3.14
            
            # Test string values
            assert config_manager._convert_env_value('hello') == 'hello'
    
    def test_invalid_yaml_file(self, temp_dir):
        """Test handling of invalid YAML file."""
        config_file = temp_dir / 'invalid.yml'
        with open(config_file, 'w') as f:
            f.write("invalid: yaml: content: [")  # Invalid YAML
        
        with pytest.raises(ConfigurationError):
            ConfigManager(str(config_file))
    
    def test_validation_integration(self, temp_dir, test_config):
        """Test integration with configuration validator."""
        config_file = temp_dir / 'config.yml'
        with open(config_file, 'w') as f:
            yaml.dump(test_config, f)
        
        config_manager = ConfigManager(str(config_file))
        errors = config_manager.validate()
        
        # Should have no validation errors for valid config
        assert len(errors) == 0


class TestConfigValidator:
    """Test cases for ConfigValidator."""
    
    def test_valid_configuration(self, test_config):
        """Test validation of valid configuration."""
        validator = ConfigValidator(test_config)
        errors = validator.validate()
        
        assert len(errors) == 0
        assert validator.is_valid()
    
    def test_invalid_system_config(self):
        """Test validation of invalid system configuration."""
        invalid_config = {
            'system': {
                'version': '',  # Invalid: empty version
                'environment': 'invalid',  # Invalid: not in allowed values
                'max_concurrent_scans': -1,  # Invalid: negative value
                'timeout': 0  # Invalid: zero timeout
            }
        }
        
        validator = ConfigValidator(invalid_config)
        errors = validator.validate()
        
        assert len(errors) > 0
        assert not validator.is_valid()
        
        # Check specific error messages
        error_text = ' '.join(errors)
        assert 'version must be a non-empty string' in error_text
        assert 'Environment must be one of' in error_text
        assert 'max_concurrent_scans must be a positive integer' in error_text
        assert 'timeout must be a positive integer' in error_text
    
    def test_invalid_security_config(self):
        """Test validation of invalid security configuration."""
        invalid_config = {
            'security': {
                'authorization': {
                    'enabled': 'not_boolean',  # Invalid: not boolean
                    'allowed_targets': 'not_list'  # Invalid: not list
                },
                'rate_limiting': {
                    'requests_per_minute': 'not_int'  # Invalid: not integer
                },
                'ssl_verification': 'not_boolean'  # Invalid: not boolean
            }
        }
        
        validator = ConfigValidator(invalid_config)
        errors = validator.validate()
        
        assert len(errors) > 0
        error_text = ' '.join(errors)
        assert 'must be a boolean' in error_text
        assert 'must be a list' in error_text
    
    def test_invalid_target_format_validation(self):
        """Test validation of invalid target formats."""
        invalid_config = {
            'security': {
                'authorization': {
                    'enabled': True,
                    'allowed_targets': [
                        'invalid..domain.com',  # Invalid: double dots
                        '256.1.1.1',  # Invalid: IP out of range
                        '192.168.1.0/33',  # Invalid: CIDR out of range
                    ]
                }
            }
        }
        
        validator = ConfigValidator(invalid_config)
        errors = validator.validate()
        
        assert len(errors) > 0
        error_text = ' '.join(errors)
        assert 'Invalid target format' in error_text
    
    def test_logging_config_validation(self):
        """Test logging configuration validation."""
        invalid_config = {
            'logging': {
                'level': 'INVALID_LEVEL',  # Invalid: not in allowed levels
                'file_rotation': 'not_boolean',  # Invalid: not boolean
                'max_file_size': 'invalid_size',  # Invalid: bad size format
                'backup_count': -1  # Invalid: negative count
            }
        }
        
        validator = ConfigValidator(invalid_config)
        errors = validator.validate()
        
        assert len(errors) > 0
        error_text = ' '.join(errors)
        assert 'must be one of' in error_text
        assert 'must be a boolean' in error_text
        assert 'must be a valid size string' in error_text
        assert 'must be a non-negative integer' in error_text
    
    def test_database_config_validation(self):
        """Test database configuration validation."""
        invalid_config = {
            'database': {
                'type': 'invalid_type',  # Invalid: not supported
                'pool_size': 0,  # Invalid: zero pool size
                'timeout': -1  # Invalid: negative timeout
            }
        }
        
        validator = ConfigValidator(invalid_config)
        errors = validator.validate()
        
        assert len(errors) > 0
        error_text = ' '.join(errors)
        assert 'must be one of' in error_text
        assert 'must be a positive integer' in error_text
    
    def test_tools_config_validation(self):
        """Test tools configuration validation."""
        invalid_config = {
            'tools': {
                'nmap': {
                    # Missing path
                    'default_args': 'not_list'  # Invalid: not a list
                },
                'nuclei': {
                    'path': '',  # Invalid: empty path
                    'default_args': ['-c', '10']
                }
            }
        }
        
        validator = ConfigValidator(invalid_config)
        errors = validator.validate()
        
        assert len(errors) > 0
        error_text = ' '.join(errors)
        assert 'path must be specified' in error_text
        assert 'must be a list' in error_text
    
    def test_size_format_validation(self):
        """Test size format validation."""
        validator = ConfigValidator({})
        
        # Valid formats
        assert validator._validate_size_format('10MB')
        assert validator._validate_size_format('1.5GB')
        assert validator._validate_size_format('500KB')
        assert validator._validate_size_format('1024B')
        
        # Invalid formats
        assert not validator._validate_size_format('')
        assert not validator._validate_size_format('10')
        assert not validator._validate_size_format('MB10')
        assert not validator._validate_size_format('10XB')
        assert not validator._validate_size_format('abc MB')
    
    def test_domain_format_validation(self):
        """Test domain name format validation."""
        validator = ConfigValidator({})
        
        # Valid domains
        assert validator._validate_domain_format('example.com')
        assert validator._validate_domain_format('sub.domain.example.com')
        assert validator._validate_domain_format('*.example.com')
        assert validator._validate_domain_format('test-site.com')
        
        # Invalid domains
        assert not validator._validate_domain_format('')
        assert not validator._validate_domain_format('.')
        assert not validator._validate_domain_format('.example.com')
        assert not validator._validate_domain_format('example..com')
        assert not validator._validate_domain_format('-example.com')
        assert not validator._validate_domain_format('example-.com')
        assert not validator._validate_domain_format('a' * 64 + '.com')  # Label too long
    
    def test_target_format_validation(self):
        """Test target format validation."""
        validator = ConfigValidator({})
        
        # Valid targets
        assert validator._validate_target_format('192.168.1.1')
        assert validator._validate_target_format('10.0.0.0/24')
        assert validator._validate_target_format('example.com')
        assert validator._validate_target_format('*.internal.com')
        assert validator._validate_target_format('2001:db8::/32')
        
        # Invalid targets
        assert not validator._validate_target_format('')
        assert not validator._validate_target_format('256.1.1.1')
        assert not validator._validate_target_format('192.168.1.0/33')
        assert not validator._validate_target_format('invalid..domain.com')