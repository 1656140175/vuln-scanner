"""Test configuration and utilities for VulnMiner test suite."""

import os
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any
import pytest


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_config() -> Dict[str, Any]:
    """Basic test configuration."""
    return {
        'system': {
            'version': '1.0.0',
            'environment': 'testing',
            'debug': True,
            'max_concurrent_scans': 2,
            'timeout': 60
        },
        'security': {
            'authorization': {
                'enabled': True,
                'whitelist_only': True,
                'allowed_targets': ['127.0.0.1', 'localhost']
            },
            'rate_limiting': {
                'enabled': True,
                'requests_per_minute': 10,
                'burst_limit': 5
            },
            'ssl_verification': True
        },
        'logging': {
            'level': 'ERROR',  # Reduce noise in tests
            'format': '%(message)s',
            'file_rotation': False,
            'max_file_size': '1MB',
            'backup_count': 1
        },
        'database': {
            'type': 'sqlite',
            'path': ':memory:',  # In-memory database for tests
            'pool_size': 5,
            'timeout': 10
        },
        'tools': {
            'nmap': {
                'path': 'nmap',
                'default_args': ['-sS', '-F'],
                'timeout': 30
            },
            'nuclei': {
                'path': 'nuclei',
                'default_args': ['-c', '5'],
                'timeout': 60
            }
        }
    }


@pytest.fixture
def config_file(temp_dir, test_config):
    """Create temporary configuration file."""
    import yaml
    
    config_file = temp_dir / 'test_config.yml'
    with open(config_file, 'w') as f:
        yaml.dump(test_config, f)
    
    return config_file


def create_test_dirs(base_dir: Path) -> None:
    """Create test directory structure."""
    dirs = ['logs', 'data', 'reports', 'config']
    for dir_name in dirs:
        (base_dir / dir_name).mkdir(exist_ok=True)