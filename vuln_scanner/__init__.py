"""VulnMiner - Advanced Automated Vulnerability Scanning System

A comprehensive vulnerability scanning framework designed for authorized 
security testing and penetration testing activities.

This package provides:
- Core framework for vulnerability scanning
- Security controls and authorization management  
- Comprehensive logging and audit trails
- Tool integration and lifecycle management
- Extensible scanner architecture

IMPORTANT: This tool is intended for authorized security testing only.
Ensure you have proper authorization before scanning any targets.
"""

__version__ = "1.0.0"
__author__ = "VulnMiner Development Team"
__description__ = "Advanced Automated Vulnerability Scanning System"
__license__ = "MIT"

from .core import VulnMinerCore
from .core.exceptions import VulnMinerException, VulnMinerError

__all__ = [
    'VulnMinerCore',
    'VulnMinerException',
    'VulnMinerError',
    '__version__'
]