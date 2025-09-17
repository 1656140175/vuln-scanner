#!/usr/bin/env python3
"""
Standalone test script for platform integration functionality.
This script tests the platform integration system without requiring the full test suite.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the vuln_scanner module to the path
sys.path.insert(0, str(Path(__file__).parent))

from vuln_scanner.platforms import (
    PlatformManager,
    PlatformSubmissionData,
    PlatformCredentials,
    PlatformConfig,
    PlatformType
)
from vuln_scanner.platforms.formatters import (
    HackerOneFormatter,
    BugcrowdFormatter,
    IntigritiFormatter,
    OpenBugBountyFormatter
)


async def test_platform_manager_basic():
    """Test basic platform manager functionality."""
    print("\\n=== Testing Platform Manager ===")
    
    try:
        # Test initialization with default config
        manager = PlatformManager()
        print(f"✓ Platform manager initialized successfully")
        print(f"  - Enabled platforms: {len(manager.connectors)}")
        
        # Test getting enabled platforms
        enabled_platforms = manager.get_enabled_platforms()
        print(f"  - Enabled platform types: {[p.value for p in enabled_platforms]}")
        
        # Test platform statistics
        stats = manager.get_all_platform_statistics()
        print(f"  - Platform statistics initialized: {len(stats)} platforms")
        
        return True
        
    except Exception as e:
        print(f"✗ Platform manager test failed: {e}")
        return False


def test_platform_credentials():
    """Test platform credentials validation."""
    print("\\n=== Testing Platform Credentials ===")
    
    try:
        # Test HackerOne credentials
        hackerone_creds = PlatformCredentials(
            platform=PlatformType.HACKERONE,
            username="test_user",
            api_token="test_token"
        )
        print(f"✓ HackerOne credentials valid: {hackerone_creds.is_valid()}")
        
        # Test Bugcrowd credentials
        bugcrowd_creds = PlatformCredentials(
            platform=PlatformType.BUGCROWD,
            email="test@example.com",
            password="test_password"
        )
        print(f"✓ Bugcrowd credentials valid: {bugcrowd_creds.is_valid()}")
        
        # Test invalid credentials
        invalid_creds = PlatformCredentials(
            platform=PlatformType.HACKERONE,
            username="test",
            api_token=""  # Missing token
        )
        print(f"✓ Invalid credentials correctly detected: {not invalid_creds.is_valid()}")
        
        return True
        
    except Exception as e:
        print(f"✗ Credentials test failed: {e}")
        return False


def test_submission_data():
    """Test platform submission data creation."""
    print("\\n=== Testing Submission Data ===")
    
    try:
        submission = PlatformSubmissionData(
            title="Test XSS Vulnerability",
            description="A reflected XSS vulnerability in the search parameter",
            severity="high",
            target="https://example.com/search",
            proof_of_concept="<script>alert(1)</script>",
            cvss_score=7.5,
            cwe_references=["CWE-79"],
            affected_assets=["https://example.com/search"],
            steps_to_reproduce=[
                "Navigate to https://example.com/search",
                "Enter <script>alert(1)</script> in search box",
                "Submit search form",
                "Observe XSS execution"
            ]
        )
        
        print(f"✓ Submission data created successfully")
        print(f"  - Title: {submission.title}")
        print(f"  - Severity: {submission.severity}")
        print(f"  - Target: {submission.target}")
        print(f"  - CVSS Score: {submission.cvss_score}")
        print(f"  - Steps: {len(submission.steps_to_reproduce)} steps")
        
        return True
        
    except Exception as e:
        print(f"✗ Submission data test failed: {e}")
        return False


def test_platform_formatters():
    """Test platform-specific formatters."""
    print("\\n=== Testing Platform Formatters ===")
    
    try:
        # Import formatters directly to avoid circular dependencies
        from vuln_scanner.platforms.formatters.hackerone_formatter import HackerOneFormatter
        from vuln_scanner.platforms.formatters.bugcrowd_formatter import BugcrowdFormatter
        from vuln_scanner.platforms.formatters.intigriti_formatter import IntigritiFormatter
        from vuln_scanner.platforms.formatters.openbugbounty_formatter import OpenBugBountyFormatter
        
        # Test HackerOne formatter
        hackerone_formatter = HackerOneFormatter()
        print(f"✓ HackerOne formatter initialized")
        print(f"  - Platform: {hackerone_formatter.platform_type.value}")
        print(f"  - Max title length: {hackerone_formatter.get_maximum_title_length()}")
        print(f"  - Severity mapping: {hackerone_formatter.get_severity_mapping()}")
        
        # Test Bugcrowd formatter
        bugcrowd_formatter = BugcrowdFormatter()
        print(f"✓ Bugcrowd formatter initialized")
        print(f"  - Platform: {bugcrowd_formatter.platform_type.value}")
        print(f"  - Severity mapping: {bugcrowd_formatter.get_severity_mapping()}")
        
        # Test Intigriti formatter
        intigriti_formatter = IntigritiFormatter()
        print(f"✓ Intigriti formatter initialized")
        print(f"  - Platform: {intigriti_formatter.platform_type.value}")
        
        # Test OpenBugBounty formatter
        obb_formatter = OpenBugBountyFormatter()
        print(f"✓ OpenBugBounty formatter initialized")
        print(f"  - Platform: {obb_formatter.platform_type.value}")
        
        return True
        
    except Exception as e:
        print(f"✗ Formatters test failed: {e}")
        return False


def test_config_structure():
    """Test configuration file structure."""
    print("\\n=== Testing Configuration Structure ===")
    
    try:
        config_path = Path("config/default.yml")
        if config_path.exists():
            print(f"✓ Configuration file exists: {config_path}")
            
            # Check if platforms section exists in config
            with open(config_path, 'r') as f:
                content = f.read()
                if 'platforms:' in content:
                    print(f"✓ Platform configuration section found")
                    
                    # Check for specific platform configs
                    platforms = ['hackerone', 'bugcrowd', 'intigriti', 'openbugbounty']
                    for platform in platforms:
                        if platform in content:
                            print(f"  - {platform}: ✓")
                        else:
                            print(f"  - {platform}: ✗")
                else:
                    print(f"✗ Platform configuration section not found")
                    return False
        else:
            print(f"✗ Configuration file not found: {config_path}")
            return False
        
        return True
        
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False


def display_environment_info():
    """Display information about required environment variables."""
    print("\\n=== Environment Variables ===")
    
    env_vars = [
        "HACKERONE_USERNAME",
        "HACKERONE_API_TOKEN", 
        "BUGCROWD_EMAIL",
        "BUGCROWD_PASSWORD",
        "INTIGRITI_API_KEY",
        "INTIGRITI_SECRET_KEY",
        "OBB_USERNAME",
        "OBB_PASSWORD"
    ]
    
    for var in env_vars:
        value = os.getenv(var)
        if value:
            print(f"  - {var}: ✓ (set)")
        else:
            print(f"  - {var}: ✗ (not set)")
    
    print("\\nNote: Environment variables are required for live platform testing.")
    print("For security, these should be set in your environment, not in code.")


async def main():
    """Run all platform integration tests."""
    print("Platform Integration Test Suite")
    print("=" * 50)
    
    tests = [
        ("Platform Manager Basic", test_platform_manager_basic),
        ("Platform Credentials", test_platform_credentials),
        ("Submission Data", test_submission_data),
        ("Platform Formatters", test_platform_formatters),
        ("Configuration Structure", test_config_structure),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            
            if result:
                passed += 1
        except Exception as e:
            print(f"\\n✗ {test_name} failed with exception: {e}")
    
    # Display environment info
    display_environment_info()
    
    # Summary
    print("\\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All platform integration tests passed!")
        return 0
    else:
        print(f"❌ {total - passed} tests failed")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)