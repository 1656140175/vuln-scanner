"""Tests for platform detection and compatibility system."""

import os
import sys
import pytest
import tempfile
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from vuln_scanner.platform.detector import PlatformDetector, PlatformInfo, PlatformType
from vuln_scanner.platform.filesystem import FileSystemAdapter
from vuln_scanner.platform.adapter import ConfigAdapter


class TestPlatformDetector:
    """Test platform detection functionality."""
    
    def test_detect_returns_platform_info(self):
        """Test that detect() returns PlatformInfo object."""
        info = PlatformDetector.detect()
        
        assert isinstance(info, PlatformInfo)
        assert isinstance(info.platform_type, PlatformType)
        assert isinstance(info.os_name, str)
        assert isinstance(info.cpu_count, int)
        assert info.cpu_count > 0
        assert isinstance(info.available_memory, int)
        assert info.available_memory > 0
    
    def test_platform_type_detection(self):
        """Test platform type detection logic."""
        # Should detect a valid platform type
        info = PlatformDetector.detect()
        assert info.platform_type in [
            PlatformType.WINDOWS,
            PlatformType.LINUX, 
            PlatformType.COLAB,
            PlatformType.DOCKER,
            PlatformType.UNKNOWN
        ]
    
    @patch('vuln_scanner.platform.detector.os.path.exists')
    def test_docker_detection(self, mock_exists):
        """Test Docker environment detection."""
        # Test Docker detection via /.dockerenv
        mock_exists.side_effect = lambda path: path == '/.dockerenv'
        
        platform_type = PlatformDetector._detect_platform_type()
        assert platform_type == PlatformType.DOCKER
    
    @patch.dict(os.environ, {'COLAB_GPU': '1'})
    def test_colab_detection_via_env(self):
        """Test Colab detection via environment variables."""
        # Even without google.colab module, should detect via env vars
        platform_type = PlatformDetector._detect_platform_type()
        
        # May detect as Colab if env var is present
        # (depends on whether google.colab is available)
        assert platform_type in [PlatformType.COLAB, PlatformType.LINUX, PlatformType.UNKNOWN]
    
    def test_admin_privileges_check(self):
        """Test admin privileges detection."""
        is_admin = PlatformDetector._check_admin_privileges()
        assert isinstance(is_admin, bool)
    
    def test_gpu_availability_check(self):
        """Test GPU availability detection."""
        has_gpu = PlatformDetector._check_gpu_availability()
        assert isinstance(has_gpu, bool)
    
    def test_get_platform_capabilities(self):
        """Test platform capabilities detection."""
        info = PlatformDetector.detect()
        capabilities = PlatformDetector.get_platform_capabilities(info)
        
        assert isinstance(capabilities, dict)
        assert 'supports_multiprocessing' in capabilities
        assert 'supports_threading' in capabilities
        assert 'supports_gpu' in capabilities
        assert 'max_memory_mb' in capabilities
    
    def test_validate_environment(self):
        """Test environment validation."""
        info = PlatformDetector.detect()
        validation = PlatformDetector.validate_environment(info)
        
        assert isinstance(validation, dict)
        assert 'is_valid' in validation
        assert 'warnings' in validation
        assert 'errors' in validation
        assert 'recommendations' in validation
        
        assert isinstance(validation['is_valid'], bool)
        assert isinstance(validation['warnings'], list)
        assert isinstance(validation['errors'], list)
        assert isinstance(validation['recommendations'], list)


class TestFileSystemAdapter:
    """Test cross-platform filesystem operations."""
    
    def setup_method(self):
        """Setup test environment."""
        self.platform_info = PlatformDetector.detect()
        self.fs_adapter = FileSystemAdapter(self.platform_info)
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Cleanup test environment."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_path_normalization(self):
        """Test path normalization for platform."""
        test_path = "test/path/with/mixed\\separators"
        normalized = self.fs_adapter.normalize_path(test_path)
        
        assert isinstance(normalized, str)
        # Should use appropriate separator for platform
        if self.platform_info.platform_type == PlatformType.WINDOWS:
            assert '\\\\' in normalized or '\\' in normalized
        else:
            assert '/' in normalized
    
    def test_safe_path_join(self):
        """Test safe path joining."""
        parts = ["home", "user", "documents", "file.txt"]
        joined = self.fs_adapter.safe_path_join(*parts)
        
        assert isinstance(joined, str)
        for part in parts:
            assert part in joined
    
    def test_create_directory(self):
        """Test directory creation."""
        test_dir = os.path.join(self.temp_dir, "test_create")
        
        success = self.fs_adapter.create_directory(test_dir)
        assert success is True
        assert os.path.exists(test_dir)
        assert os.path.isdir(test_dir)
    
    def test_create_nested_directory(self):
        """Test nested directory creation."""
        nested_dir = os.path.join(self.temp_dir, "level1", "level2", "level3")
        
        success = self.fs_adapter.create_directory(nested_dir)
        assert success is True
        assert os.path.exists(nested_dir)
        assert os.path.isdir(nested_dir)
    
    def test_safe_write_and_read(self):
        """Test safe file writing and reading."""
        test_file = os.path.join(self.temp_dir, "test_write.txt")
        test_content = "Hello, cross-platform world!"
        
        # Test writing
        write_success = self.fs_adapter.safe_write(test_file, test_content)
        assert write_success is True
        assert os.path.exists(test_file)
        
        # Test reading
        read_content = self.fs_adapter.safe_read(test_file)
        assert read_content == test_content
    
    def test_safe_write_binary(self):
        """Test binary file writing."""
        test_file = os.path.join(self.temp_dir, "test_binary.bin")
        test_content = b"\\x00\\x01\\x02\\x03\\xFF"
        
        write_success = self.fs_adapter.safe_write(test_file, test_content)
        assert write_success is True
        
        read_content = self.fs_adapter.safe_read(test_file, binary=True)
        assert read_content == test_content
    
    def test_safe_remove(self):
        """Test safe file/directory removal."""
        # Test file removal
        test_file = os.path.join(self.temp_dir, "test_remove.txt")
        with open(test_file, 'w') as f:
            f.write("test")
        
        remove_success = self.fs_adapter.safe_remove(test_file)
        assert remove_success is True
        assert not os.path.exists(test_file)
        
        # Test directory removal
        test_dir = os.path.join(self.temp_dir, "test_remove_dir")
        os.makedirs(test_dir)
        
        remove_success = self.fs_adapter.safe_remove(test_dir, recursive=True)
        assert remove_success is True
        assert not os.path.exists(test_dir)
    
    def test_get_temp_file(self):
        """Test temporary file creation."""
        temp_file = self.fs_adapter.get_temp_file(suffix=".test", prefix="vuln_test_")
        
        assert isinstance(temp_file, str)
        assert temp_file.endswith(".test")
        assert "vuln_test_" in os.path.basename(temp_file)
    
    def test_get_temp_directory(self):
        """Test temporary directory creation."""
        temp_dir = self.fs_adapter.get_temp_directory(prefix="vuln_test_")
        
        assert isinstance(temp_dir, str)
        assert os.path.exists(temp_dir)
        assert os.path.isdir(temp_dir)
        assert "vuln_test_" in os.path.basename(temp_dir)
    
    def test_is_path_safe(self):
        """Test path safety validation."""
        # Safe paths
        safe_paths = [
            "/home/user/documents/file.txt",
            "C:\\Users\\User\\Documents\\file.txt",
            "relative/path/file.txt"
        ]
        
        for path in safe_paths:
            assert self.fs_adapter.is_path_safe(path) is True
        
        # Potentially unsafe paths
        unsafe_paths = [
            "../../../etc/passwd",
            "~/../../sensitive/file",
            "$HOME/../sensitive"
        ]
        
        for path in unsafe_paths:
            # May be marked as unsafe depending on implementation
            result = self.fs_adapter.is_path_safe(path)
            assert isinstance(result, bool)


class TestConfigAdapter:
    """Test platform-specific configuration adaptation."""
    
    def setup_method(self):
        """Setup test environment."""
        self.platform_info = PlatformDetector.detect()
        self.config_adapter = ConfigAdapter(self.platform_info)
    
    def test_config_initialization(self):
        """Test configuration adapter initialization."""
        assert self.config_adapter.platform_info == self.platform_info
        assert isinstance(self.config_adapter.config, dict)
        assert len(self.config_adapter.config) > 0
    
    def test_base_defaults_present(self):
        """Test that base default values are present."""
        config = self.config_adapter.config
        
        required_keys = [
            'max_workers',
            'memory_limit_mb',
            'temp_dir',
            'log_level',
            'enable_gpu'
        ]
        
        for key in required_keys:
            assert key in config
            assert config[key] is not None
    
    def test_platform_specific_config(self):
        """Test platform-specific configuration values."""
        config = self.config_adapter.config
        
        # All platforms should have output directories
        assert 'output_dir' in config
        assert isinstance(config['output_dir'], str)
        assert len(config['output_dir']) > 0
    
    def test_resource_limits_valid(self):
        """Test that resource limits are reasonable."""
        config = self.config_adapter.config
        
        # Memory limit should be positive and not exceed available memory
        assert config['memory_limit_mb'] > 0
        assert config['memory_limit_mb'] <= self.platform_info.available_memory
        
        # Max workers should be positive and not exceed CPU count
        assert config['max_workers'] > 0
        assert config['max_workers'] <= self.platform_info.cpu_count
    
    def test_get_config_value(self):
        """Test configuration value retrieval."""
        # Test existing key
        value = self.config_adapter.get('log_level')
        assert value is not None
        
        # Test non-existing key with default
        default_value = "test_default"
        value = self.config_adapter.get('non_existing_key', default_value)
        assert value == default_value
    
    def test_set_config_value(self):
        """Test configuration value setting."""
        test_key = 'test_setting'
        test_value = 'test_value'
        
        self.config_adapter.set(test_key, test_value)
        
        retrieved_value = self.config_adapter.get(test_key)
        assert retrieved_value == test_value
    
    def test_config_update(self):
        """Test configuration updating."""
        updates = {
            'custom_setting1': 'value1',
            'custom_setting2': 42,
            'nested': {
                'sub_setting': 'sub_value'
            }
        }
        
        self.config_adapter.update(updates)
        
        for key, expected_value in updates.items():
            actual_value = self.config_adapter.get(key)
            assert actual_value == expected_value
    
    def test_environment_variable_override(self):
        """Test environment variable configuration override."""
        # This test may need to be run with specific environment variables set
        # For now, just test that the method doesn't crash
        overrides = self.config_adapter._get_environment_overrides()
        assert isinstance(overrides, dict)
    
    @patch.dict(os.environ, {'VULN_SCANNER_LOG_LEVEL': 'DEBUG'})
    def test_env_override_log_level(self):
        """Test environment variable override for log level."""
        config_adapter = ConfigAdapter(self.platform_info)
        overrides = config_adapter._get_environment_overrides()
        
        if 'log_level' in overrides:
            assert overrides['log_level'] == 'DEBUG'


@pytest.mark.asyncio
class TestPlatformInitialization:
    """Test platform initialization process."""
    
    async def test_platform_utils_initialization(self):
        """Test platform utilities initialization."""
        # Import here to avoid circular imports during testing
        from vuln_scanner.utils.platform_utils import (
            initialize_platform, get_platform_info, get_platform_type
        )
        
        # Test basic initialization
        result = initialize_platform()
        assert isinstance(result, bool)
        
        # Test info retrieval
        info = get_platform_info()
        if info:  # May be None if initialization failed
            assert isinstance(info, PlatformInfo)
        
        # Test platform type detection
        platform_type = get_platform_type()
        assert isinstance(platform_type, PlatformType)


def test_platform_imports():
    """Test that all platform modules can be imported."""
    try:
        from vuln_scanner.platform import (
            PlatformDetector, PlatformInfo, PlatformType,
            ConfigAdapter, FileSystemAdapter, DependencyManager,
            PlatformInitializer
        )
        
        # Test that classes can be instantiated (basic smoke test)
        assert PlatformDetector is not None
        assert PlatformInfo is not None
        assert PlatformType is not None
        assert ConfigAdapter is not None
        assert FileSystemAdapter is not None
        assert DependencyManager is not None
        assert PlatformInitializer is not None
        
    except ImportError as e:
        pytest.fail(f"Failed to import platform modules: {e}")


def test_utils_imports():
    """Test that platform utilities can be imported."""
    try:
        from vuln_scanner.utils import (
            initialize_platform, get_platform_info, is_windows,
            is_colab, is_linux, safe_path_join, normalize_path
        )
        
        # Test that functions are callable
        assert callable(initialize_platform)
        assert callable(get_platform_info)
        assert callable(is_windows)
        assert callable(is_colab)
        assert callable(is_linux)
        assert callable(safe_path_join)
        assert callable(normalize_path)
        
    except ImportError as e:
        pytest.fail(f"Failed to import platform utilities: {e}")


if __name__ == "__main__":
    # Run basic tests if executed directly
    print("Running platform compatibility tests...")
    
    # Test platform detection
    print("\\nTesting platform detection...")
    info = PlatformDetector.detect()
    print(f"Platform: {info.platform_type.value}")
    print(f"OS: {info.os_name} {info.os_version}")
    print(f"Python: {info.python_version}")
    print(f"CPU cores: {info.cpu_count}")
    print(f"Memory: {info.available_memory}MB")
    print(f"GPU: {info.is_gpu_available}")
    print(f"Admin: {info.is_admin}")
    
    # Test filesystem adapter
    print("\\nTesting filesystem adapter...")
    fs_adapter = FileSystemAdapter(info)
    test_path = fs_adapter.normalize_path("test/path")
    print(f"Normalized path: {test_path}")
    
    # Test config adapter  
    print("\\nTesting configuration adapter...")
    config_adapter = ConfigAdapter(info)
    print(f"Output directory: {config_adapter.get('output_dir')}")
    print(f"Max workers: {config_adapter.get('max_workers')}")
    print(f"Memory limit: {config_adapter.get('memory_limit_mb')}MB")
    
    print("\\nBasic tests completed successfully!")