#!/usr/bin/env python3
"""Simple test script for platform compatibility system."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_platform_detection():
    """Test platform detection functionality."""
    print("Testing platform detection...")
    
    try:
        from vuln_scanner.platform.detector import PlatformDetector, PlatformInfo, PlatformType
        
        # Test detection
        info = PlatformDetector.detect()
        print(f"✓ Platform detected: {info.platform_type.value}")
        print(f"✓ OS: {info.os_name} {info.os_version}")
        print(f"✓ Python: {info.python_version}")
        print(f"✓ CPU cores: {info.cpu_count}")
        print(f"✓ Available memory: {info.available_memory}MB")
        print(f"✓ GPU available: {info.is_gpu_available}")
        print(f"✓ Admin privileges: {info.is_admin}")
        print(f"✓ Notebook environment: {info.is_notebook}")
        print(f"✓ Architecture: {info.architecture}")
        
        # Test capabilities
        capabilities = PlatformDetector.get_platform_capabilities(info)
        print(f"✓ Platform capabilities: {len(capabilities)} detected")
        
        # Test validation
        validation = PlatformDetector.validate_environment(info)
        print(f"✓ Environment valid: {validation['is_valid']}")
        if validation['warnings']:
            print(f"  Warnings: {len(validation['warnings'])}")
        if validation['errors']:
            print(f"  Errors: {len(validation['errors'])}")
        
        return True
        
    except Exception as e:
        print(f"✗ Platform detection failed: {e}")
        return False


def test_filesystem_adapter():
    """Test filesystem adapter functionality."""
    print("\\nTesting filesystem adapter...")
    
    try:
        from vuln_scanner.platform.detector import PlatformDetector
        from vuln_scanner.platform.filesystem import FileSystemAdapter
        
        info = PlatformDetector.detect()
        fs_adapter = FileSystemAdapter(info)
        
        # Test path normalization
        test_path = "test/path/with/mixed\\\\separators"
        normalized = fs_adapter.normalize_path(test_path)
        print(f"✓ Path normalized: {test_path} -> {normalized}")
        
        # Test path joining
        parts = ["home", "user", "documents"]
        joined = fs_adapter.safe_path_join(*parts)
        print(f"✓ Path joined: {parts} -> {joined}")
        
        # Test temp file creation
        temp_file = fs_adapter.get_temp_file(suffix=".test", prefix="vuln_test_")
        print(f"✓ Temp file created: {temp_file}")
        
        # Test temp directory creation
        temp_dir = fs_adapter.get_temp_directory(prefix="vuln_test_")
        print(f"✓ Temp directory created: {temp_dir}")
        
        # Test path safety
        safe_path = "safe/relative/path.txt"
        is_safe = fs_adapter.is_path_safe(safe_path)
        print(f"✓ Path safety check: {safe_path} -> {is_safe}")
        
        return True
        
    except Exception as e:
        print(f"✗ Filesystem adapter test failed: {e}")
        return False


def test_config_adapter():
    """Test configuration adapter functionality."""
    print("\\nTesting configuration adapter...")
    
    try:
        from vuln_scanner.platform.detector import PlatformDetector
        from vuln_scanner.platform.adapter import ConfigAdapter
        
        info = PlatformDetector.detect()
        config_adapter = ConfigAdapter(info)
        
        # Test basic config access
        output_dir = config_adapter.get('output_dir')
        print(f"✓ Output directory: {output_dir}")
        
        max_workers = config_adapter.get('max_workers')
        print(f"✓ Max workers: {max_workers}")
        
        memory_limit = config_adapter.get('memory_limit_mb')
        print(f"✓ Memory limit: {memory_limit}MB")
        
        # Test config setting
        test_key = 'test_setting'
        test_value = 'test_value'
        config_adapter.set(test_key, test_value)
        retrieved = config_adapter.get(test_key)
        print(f"✓ Config set/get: {test_key} -> {retrieved}")
        
        # Test config update
        updates = {'custom_setting': 'custom_value'}
        config_adapter.update(updates)
        print(f"✓ Config updated with: {updates}")
        
        return True
        
    except Exception as e:
        print(f"✗ Configuration adapter test failed: {e}")
        return False


def test_windows_utils():
    """Test Windows-specific utilities."""
    if not sys.platform.startswith('win'):
        print("\\nSkipping Windows utilities test (not on Windows)")
        return True
        
    print("\\nTesting Windows utilities...")
    
    try:
        from vuln_scanner.platform.windows import WindowsUtils
        
        # Test Windows detection
        is_windows = WindowsUtils.is_windows()
        print(f"✓ Windows detected: {is_windows}")
        
        # Test admin check
        is_admin = WindowsUtils.is_admin()
        print(f"✓ Admin privileges: {is_admin}")
        
        # Test system info
        system_info = WindowsUtils.get_system_info()
        print(f"✓ System info collected: {len(system_info)} properties")
        
        # Test features check
        features = WindowsUtils.check_required_features()
        print(f"✓ Features checked: {len(features)} features")
        
        return True
        
    except Exception as e:
        print(f"✗ Windows utilities test failed: {e}")
        return False


def test_dependency_manager():
    """Test dependency manager functionality."""
    print("\\nTesting dependency manager...")
    
    try:
        from vuln_scanner.platform.detector import PlatformDetector
        from vuln_scanner.platform.dependency_manager import DependencyManager
        
        info = PlatformDetector.detect()
        dep_manager = DependencyManager(info)
        
        # Test package requirements
        packages = dep_manager.get_required_packages()
        print(f"✓ Required packages: {len(packages)} packages")
        
        # Test installed packages check
        installed = dep_manager.get_installed_packages()
        print(f"✓ Installed packages: {len(installed)} found")
        
        return True
        
    except Exception as e:
        print(f"✗ Dependency manager test failed: {e}")
        return False


def main():
    """Run all platform compatibility tests."""
    print("=" * 60)
    print("PLATFORM COMPATIBILITY TESTS")
    print("=" * 60)
    
    tests = [
        test_platform_detection,
        test_filesystem_adapter,
        test_config_adapter,
        test_windows_utils,
        test_dependency_manager
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test failed with exception: {e}")
    
    print("\\n" + "=" * 60)
    print(f"RESULTS: {passed}/{total} tests passed")
    print("=" * 60)
    
    if passed == total:
        print("🎉 All platform compatibility tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed. Check implementation.")
        return 1


if __name__ == "__main__":
    sys.exit(main())