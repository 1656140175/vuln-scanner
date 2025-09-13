"""Tests for security framework components."""

import pytest
import time
from unittest.mock import Mock, patch

from vuln_scanner.core.security import (
    SecurityController, AuthorizationManager, RateLimiter
)
from vuln_scanner.core.exceptions import UnauthorizedTargetError, RateLimitExceededError


class TestAuthorizationManager:
    """Test cases for AuthorizationManager."""
    
    def test_init_with_config(self, test_config):
        """Test initialization with configuration."""
        auth_manager = AuthorizationManager(test_config)
        
        assert auth_manager.enabled is True
        assert auth_manager.whitelist_only is True
        assert '127.0.0.1' in auth_manager.allowed_targets
        assert 'localhost' in auth_manager.allowed_targets
    
    def test_disabled_authorization(self):
        """Test behavior when authorization is disabled."""
        config = {
            'security': {
                'authorization': {
                    'enabled': False
                }
            }
        }
        
        auth_manager = AuthorizationManager(config)
        
        # Should allow any target when disabled
        assert auth_manager.is_target_authorized('any.target.com') is True
        assert auth_manager.is_target_authorized('192.168.1.100') is True
    
    def test_ip_address_authorization(self):
        """Test IP address authorization."""
        config = {
            'security': {
                'authorization': {
                    'enabled': True,
                    'whitelist_only': True,
                    'allowed_targets': [
                        '192.168.1.1',
                        '10.0.0.0/24',
                        '2001:db8::/32'
                    ]
                }
            }
        }
        
        auth_manager = AuthorizationManager(config)
        
        # Test exact IP match
        assert auth_manager.is_target_authorized('192.168.1.1') is True
        assert auth_manager.is_target_authorized('192.168.1.2') is False
        
        # Test CIDR range
        assert auth_manager.is_target_authorized('10.0.0.50') is True
        assert auth_manager.is_target_authorized('10.0.1.50') is False
        
        # Test IPv6
        assert auth_manager.is_target_authorized('2001:db8::1') is True
        assert auth_manager.is_target_authorized('2001:db9::1') is False
    
    def test_domain_authorization(self):
        """Test domain name authorization."""
        config = {
            'security': {
                'authorization': {
                    'enabled': True,
                    'whitelist_only': True,
                    'allowed_targets': [
                        'example.com',
                        '*.internal.com',
                        'test.domain.org'
                    ]
                }
            }
        }
        
        auth_manager = AuthorizationManager(config)
        
        # Test exact domain match
        assert auth_manager.is_target_authorized('example.com') is True
        assert auth_manager.is_target_authorized('other.com') is False
        
        # Test wildcard domain
        assert auth_manager.is_target_authorized('sub.internal.com') is True
        assert auth_manager.is_target_authorized('internal.com') is True
        assert auth_manager.is_target_authorized('sub.external.com') is False
        
        # Test subdomain
        assert auth_manager.is_target_authorized('test.domain.org') is True
        assert auth_manager.is_target_authorized('other.domain.org') is False
    
    def test_url_target_extraction(self):
        """Test target extraction from URLs."""
        config = {
            'security': {
                'authorization': {
                    'enabled': True,
                    'whitelist_only': True,
                    'allowed_targets': ['example.com']
                }
            }
        }
        
        auth_manager = AuthorizationManager(config)
        
        # Test URL extraction
        assert auth_manager.is_target_authorized('https://example.com/path') is True
        assert auth_manager.is_target_authorized('http://example.com:8080/path') is True
        assert auth_manager.is_target_authorized('https://other.com/path') is False
    
    def test_port_handling(self):
        """Test handling of targets with ports."""
        config = {
            'security': {
                'authorization': {
                    'enabled': True,
                    'whitelist_only': True,
                    'allowed_targets': ['192.168.1.1', 'example.com']
                }
            }
        }
        
        auth_manager = AuthorizationManager(config)
        
        # Test IP with port
        assert auth_manager.is_target_authorized('192.168.1.1:8080') is True
        assert auth_manager.is_target_authorized('192.168.1.2:8080') is False
        
        # Test domain with port
        assert auth_manager.is_target_authorized('example.com:443') is True
        assert auth_manager.is_target_authorized('other.com:443') is False
    
    def test_localhost_detection(self):
        """Test localhost detection."""
        auth_manager = AuthorizationManager({'security': {}})
        
        # Test various localhost formats
        assert auth_manager.is_localhost('localhost') is True
        assert auth_manager.is_localhost('127.0.0.1') is True
        assert auth_manager.is_localhost('::1') is True
        assert auth_manager.is_localhost('0.0.0.0') is True
        
        # Test non-localhost
        assert auth_manager.is_localhost('example.com') is False
        assert auth_manager.is_localhost('192.168.1.1') is False
    
    def test_private_ip_detection(self):
        """Test private IP address detection."""
        auth_manager = AuthorizationManager({'security': {}})
        
        # Test private IP ranges
        assert auth_manager.is_private_ip('192.168.1.1') is True
        assert auth_manager.is_private_ip('10.0.0.1') is True
        assert auth_manager.is_private_ip('172.16.0.1') is True
        
        # Test public IPs
        assert auth_manager.is_private_ip('8.8.8.8') is False
        assert auth_manager.is_private_ip('1.1.1.1') is False
        
        # Test domains (should return False)
        assert auth_manager.is_private_ip('example.com') is False
    
    def test_add_remove_targets(self):
        """Test adding and removing targets."""
        config = {
            'security': {
                'authorization': {
                    'enabled': True,
                    'whitelist_only': True,
                    'allowed_targets': ['127.0.0.1']
                }
            }
        }
        
        auth_manager = AuthorizationManager(config)
        
        # Initially only localhost is allowed
        assert auth_manager.is_target_authorized('example.com') is False
        
        # Add new target
        assert auth_manager.add_allowed_target('example.com') is True
        assert auth_manager.is_target_authorized('example.com') is True
        
        # Remove target
        assert auth_manager.remove_allowed_target('example.com') is True
        assert auth_manager.is_target_authorized('example.com') is False
        
        # Try to remove non-existent target
        assert auth_manager.remove_allowed_target('nonexistent.com') is False
        
        # Try to add invalid target
        assert auth_manager.add_allowed_target('invalid..domain') is False


class TestRateLimiter:
    """Test cases for RateLimiter."""
    
    def test_init_with_config(self, test_config):
        """Test initialization with configuration."""
        rate_limiter = RateLimiter(test_config)
        
        assert rate_limiter.config.enabled is True
        assert rate_limiter.config.requests_per_minute == 10
    
    def test_disabled_rate_limiting(self):
        """Test behavior when rate limiting is disabled."""
        config = {
            'security': {
                'rate_limiting': {
                    'enabled': False
                }
            }
        }
        
        rate_limiter = RateLimiter(config)
        
        # Should always allow when disabled
        allowed, info = rate_limiter.check_rate_limit('any.target.com')
        assert allowed is True
        assert info['reason'] == 'rate_limiting_disabled'
    
    def test_basic_rate_limiting(self):
        """Test basic rate limiting functionality."""
        config = {
            'security': {
                'rate_limiting': {
                    'enabled': True,
                    'requests_per_minute': 5
                }
            }
        }
        
        rate_limiter = RateLimiter(config)
        target = 'test.example.com'
        
        # First 5 requests should be allowed
        for i in range(5):
            allowed, info = rate_limiter.check_rate_limit(target)
            assert allowed is True
        
        # 6th request should be denied
        allowed, info = rate_limiter.check_rate_limit(target)
        assert allowed is False
        assert info['reason'] == 'target_rate_limit_exceeded'
    
    def test_per_target_rate_limiting(self):
        """Test per-target rate limiting."""
        config = {
            'security': {
                'rate_limiting': {
                    'enabled': True,
                    'requests_per_minute': 10
                }
            }
        }
        
        rate_limiter = RateLimiter(config)
        target1 = 'test1.example.com'
        target2 = 'test2.example.com'
        
        # Use up target1's limit
        for i in range(5):  # Half of global limit for per-target
            allowed, info = rate_limiter.check_rate_limit(target1)
            assert allowed is True
        
        # target1 should be rate limited
        allowed, info = rate_limiter.check_rate_limit(target1)
        assert allowed is False
        
        # target2 should still be allowed
        allowed, info = rate_limiter.check_rate_limit(target2)
        assert allowed is True
    
    def test_global_rate_limiting(self):
        """Test global rate limiting."""
        config = {
            'security': {
                'rate_limiting': {
                    'enabled': True,
                    'requests_per_minute': 3
                }
            }
        }
        
        rate_limiter = RateLimiter(config)
        
        # Use up global limit with different targets
        targets = ['target1.com', 'target2.com', 'target3.com']
        for target in targets:
            allowed, info = rate_limiter.check_rate_limit(target)
            assert allowed is True
        
        # Any additional request should be denied due to global limit
        allowed, info = rate_limiter.check_rate_limit('target4.com')
        assert allowed is False
        assert info['reason'] == 'global_rate_limit_exceeded'
    
    def test_rate_limit_reset(self):
        """Test rate limit reset functionality."""
        config = {
            'security': {
                'rate_limiting': {
                    'enabled': True,
                    'requests_per_minute': 2
                }
            }
        }
        
        rate_limiter = RateLimiter(config)
        target = 'test.example.com'
        
        # Use up the limit
        for i in range(2):
            allowed, info = rate_limiter.check_rate_limit(target)
            assert allowed is True
        
        # Should be rate limited
        allowed, info = rate_limiter.check_rate_limit(target)
        assert allowed is False
        
        # Reset the limit
        assert rate_limiter.reset_limits(target=target) is True
        
        # Should be allowed again
        allowed, info = rate_limiter.check_rate_limit(target)
        assert allowed is True
    
    def test_user_rate_limiting(self):
        """Test per-user rate limiting."""
        config = {
            'security': {
                'rate_limiting': {
                    'enabled': True,
                    'requests_per_minute': 10
                }
            }
        }
        
        rate_limiter = RateLimiter(config)
        target = 'test.example.com'
        user = 'test_user'
        
        # Use up user's limit (80% of global limit)
        for i in range(8):
            allowed, info = rate_limiter.check_rate_limit(target, user)
            assert allowed is True
        
        # User should be rate limited
        allowed, info = rate_limiter.check_rate_limit(target, user)
        assert allowed is False
        assert info['reason'] == 'user_rate_limit_exceeded'
    
    def test_get_stats(self):
        """Test getting rate limiter statistics."""
        config = {
            'security': {
                'rate_limiting': {
                    'enabled': True,
                    'requests_per_minute': 10
                }
            }
        }
        
        rate_limiter = RateLimiter(config)
        
        # Make some requests
        rate_limiter.check_rate_limit('target1.com')
        rate_limiter.check_rate_limit('target2.com', 'user1')
        
        stats = rate_limiter.get_stats()
        
        assert stats['enabled'] is True
        assert stats['requests_per_minute_limit'] == 10
        assert stats['current_global_requests'] == 2
        assert 'target_stats' in stats


class TestSecurityController:
    """Test cases for SecurityController."""
    
    def test_init_with_config(self, test_config):
        """Test initialization with configuration."""
        controller = SecurityController(test_config)
        
        assert controller.authorization is not None
        assert controller.rate_limiter is not None
    
    def test_validate_authorized_target(self, test_config):
        """Test validation of authorized target."""
        controller = SecurityController(test_config)
        
        # Should pass all validations for authorized target
        allowed, info = controller.validate_scan_request(
            target='127.0.0.1',
            scan_type='standard',
            user='test_user'
        )
        
        assert allowed is True
        assert info['validations']['authorization']['passed'] is True
        assert info['validations']['rate_limit']['passed'] is True
    
    def test_validate_unauthorized_target(self, test_config):
        """Test validation of unauthorized target."""
        controller = SecurityController(test_config)
        
        # Should fail authorization for unauthorized target
        allowed, info = controller.validate_scan_request(
            target='unauthorized.com',
            scan_type='standard',
            user='test_user'
        )
        
        assert allowed is False
        assert info['validations']['authorization']['passed'] is False
    
    def test_validate_with_rate_limit_exceeded(self, test_config):
        """Test validation with rate limit exceeded."""
        # Set very low rate limit for testing
        test_config['security']['rate_limiting']['requests_per_minute'] = 1
        
        controller = SecurityController(test_config)
        
        # First request should pass
        allowed, info = controller.validate_scan_request(
            target='127.0.0.1',
            scan_type='standard',
            user='test_user'
        )
        assert allowed is True
        
        # Second request should fail due to rate limit
        allowed, info = controller.validate_scan_request(
            target='127.0.0.1',
            scan_type='standard',
            user='test_user'
        )
        assert allowed is False
        assert info['validations']['rate_limit']['passed'] is False
    
    def test_scan_type_restrictions(self, test_config):
        """Test scan type restrictions."""
        # Add scan restrictions to config
        test_config['security']['scan_restrictions'] = {
            'forbidden_scan_types': ['dos', 'exploit']
        }
        
        controller = SecurityController(test_config)
        
        # Standard scan should be allowed
        allowed, info = controller.validate_scan_request(
            target='127.0.0.1',
            scan_type='standard',
            user='test_user'
        )
        assert allowed is True
        
        # Forbidden scan type should be denied
        allowed, info = controller.validate_scan_request(
            target='127.0.0.1',
            scan_type='dos',
            user='test_user'
        )
        assert allowed is False
        assert info['validations']['scan_type']['passed'] is False
    
    def test_target_safety_validation(self, test_config):
        """Test target safety validation."""
        # Disable localhost scanning
        test_config['security']['target_safety'] = {
            'allow_localhost': False,
            'allow_private_networks': True
        }
        
        controller = SecurityController(test_config)
        
        # Localhost should be denied
        allowed, info = controller.validate_scan_request(
            target='localhost',
            scan_type='standard',
            user='test_user'
        )
        assert allowed is False
        assert info['validations']['target_safety']['passed'] is False
    
    def test_add_remove_authorized_target(self, test_config):
        """Test adding and removing authorized targets."""
        controller = SecurityController(test_config)
        
        # Initially unauthorized
        allowed, info = controller.validate_scan_request(
            target='new.example.com',
            scan_type='standard'
        )
        assert allowed is False
        
        # Add target
        success = controller.add_authorized_target('new.example.com', 'admin')
        assert success is True
        
        # Should now be authorized
        allowed, info = controller.validate_scan_request(
            target='new.example.com',
            scan_type='standard'
        )
        assert allowed is True
        
        # Remove target
        success = controller.remove_authorized_target('new.example.com', 'admin')
        assert success is True
        
        # Should be unauthorized again
        allowed, info = controller.validate_scan_request(
            target='new.example.com',
            scan_type='standard'
        )
        assert allowed is False
    
    def test_get_security_status(self, test_config):
        """Test getting security status."""
        controller = SecurityController(test_config)
        
        status = controller.get_security_status()
        
        assert 'authorization' in status
        assert 'rate_limiting' in status
        assert 'security_config' in status
        
        assert status['authorization']['enabled'] is True
        assert status['rate_limiting']['enabled'] is True
    
    def test_reset_rate_limits(self, test_config):
        """Test resetting rate limits."""
        # Set low rate limit
        test_config['security']['rate_limiting']['requests_per_minute'] = 1
        
        controller = SecurityController(test_config)
        target = '127.0.0.1'
        
        # Use up rate limit
        controller.validate_scan_request(target, 'standard')
        
        # Should be rate limited
        allowed, info = controller.validate_scan_request(target, 'standard')
        assert allowed is False
        
        # Reset rate limits
        success = controller.reset_rate_limits(target=target)
        assert success is True
        
        # Should be allowed again
        allowed, info = controller.validate_scan_request(target, 'standard')
        assert allowed is True