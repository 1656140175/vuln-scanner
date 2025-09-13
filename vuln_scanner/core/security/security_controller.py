"""Main security controller that coordinates all security components."""

from typing import Dict, Any, Optional, Tuple, List
import logging

from .authorization import AuthorizationManager
from .rate_limiter import RateLimiter


class SecurityController:
    """Main security controller that coordinates authorization, rate limiting, and other security features."""
    
    def __init__(self, config: Dict[str, Any], logger_manager=None):
        """Initialize security controller.
        
        Args:
            config: Configuration dictionary
            logger_manager: Logger manager instance
        """
        self.config = config
        self.security_config = config.get('security', {})
        
        # Initialize components
        self.authorization = AuthorizationManager(config)
        self.rate_limiter = RateLimiter(config)
        
        # Set up logging
        if logger_manager:
            self.logger = logger_manager.get_logger('security')
        else:
            self.logger = logging.getLogger('vuln_miner.security')
    
    def validate_scan_request(self, target: str, scan_type: str, 
                            user: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        """Validate a scan request against all security policies.
        
        Args:
            target: Target to scan
            scan_type: Type of scan being performed
            user: User making the request
            
        Returns:
            Tuple of (allowed, validation_info)
        """
        validation_info = {
            'target': target,
            'scan_type': scan_type,
            'user': user,
            'validations': {}
        }
        
        # Check authorization
        if not self.authorization.is_target_authorized(target):
            validation_info['validations']['authorization'] = {
                'passed': False,
                'reason': 'target_not_authorized',
                'message': f"Target '{target}' is not in the authorized whitelist"
            }
            
            self.logger.warning("Unauthorized scan attempt blocked", extra={
                'target': target,
                'user': user,
                'scan_type': scan_type,
                'reason': 'target_not_authorized'
            })
            
            return False, validation_info
        
        validation_info['validations']['authorization'] = {
            'passed': True,
            'message': 'Target is authorized'
        }
        
        # Check rate limits
        rate_allowed, rate_info = self.rate_limiter.check_rate_limit(target, user)
        if not rate_allowed:
            validation_info['validations']['rate_limit'] = {
                'passed': False,
                'reason': rate_info.get('reason'),
                'message': f"Rate limit exceeded: {rate_info.get('reason')}",
                'details': rate_info
            }
            
            self.logger.warning("Scan request blocked by rate limit", extra={
                'target': target,
                'user': user,
                'scan_type': scan_type,
                'rate_limit_info': rate_info
            })
            
            return False, validation_info
        
        validation_info['validations']['rate_limit'] = {
            'passed': True,
            'message': 'Rate limit check passed',
            'details': rate_info
        }
        
        # Check scan type restrictions
        scan_allowed, scan_info = self._validate_scan_type(scan_type, target)
        if not scan_allowed:
            validation_info['validations']['scan_type'] = scan_info
            
            self.logger.warning("Scan request blocked by scan type restriction", extra={
                'target': target,
                'user': user,
                'scan_type': scan_type,
                'scan_restriction_info': scan_info
            })
            
            return False, validation_info
        
        validation_info['validations']['scan_type'] = scan_info
        
        # Check target safety (localhost, private IPs, etc.)
        safety_allowed, safety_info = self._validate_target_safety(target)
        if not safety_allowed:
            validation_info['validations']['target_safety'] = safety_info
            
            self.logger.warning("Scan request blocked by target safety check", extra={
                'target': target,
                'user': user,
                'scan_type': scan_type,
                'safety_info': safety_info
            })
            
            return False, validation_info
        
        validation_info['validations']['target_safety'] = safety_info
        
        # All validations passed
        self.logger.info("Scan request validated successfully", extra={
            'target': target,
            'user': user,
            'scan_type': scan_type,
            'validation_info': validation_info
        })
        
        return True, validation_info
    
    def _validate_scan_type(self, scan_type: str, target: str) -> Tuple[bool, Dict[str, Any]]:
        """Validate scan type restrictions.
        
        Args:
            scan_type: Type of scan being performed
            target: Target being scanned
            
        Returns:
            Tuple of (allowed, info)
        """
        # Get scan type restrictions from config
        scan_restrictions = self.security_config.get('scan_restrictions', {})
        
        # Check if scan type is allowed
        allowed_scans = scan_restrictions.get('allowed_scan_types', [])
        if allowed_scans and scan_type not in allowed_scans:
            return False, {
                'passed': False,
                'reason': 'scan_type_not_allowed',
                'message': f"Scan type '{scan_type}' is not in allowed list: {allowed_scans}",
                'allowed_types': allowed_scans
            }
        
        # Check if scan type is forbidden
        forbidden_scans = scan_restrictions.get('forbidden_scan_types', [])
        if scan_type in forbidden_scans:
            return False, {
                'passed': False,
                'reason': 'scan_type_forbidden',
                'message': f"Scan type '{scan_type}' is explicitly forbidden",
                'forbidden_types': forbidden_scans
            }
        
        # Check aggressive scan restrictions
        aggressive_scans = scan_restrictions.get('aggressive_scan_types', [])
        if scan_type in aggressive_scans:
            # Only allow aggressive scans on explicitly authorized targets
            if not self._is_target_explicitly_authorized_for_aggressive_scans(target):
                return False, {
                    'passed': False,
                    'reason': 'aggressive_scan_not_authorized',
                    'message': f"Aggressive scan type '{scan_type}' requires explicit authorization for target",
                    'scan_type': scan_type
                }
        
        return True, {
            'passed': True,
            'message': f"Scan type '{scan_type}' is allowed",
            'scan_type': scan_type
        }
    
    def _validate_target_safety(self, target: str) -> Tuple[bool, Dict[str, Any]]:
        """Validate target safety (localhost, private networks, etc.).
        
        Args:
            target: Target to validate
            
        Returns:
            Tuple of (allowed, info)
        """
        safety_config = self.security_config.get('target_safety', {})
        
        # Check localhost restrictions
        if self.authorization.is_localhost(target):
            allow_localhost = safety_config.get('allow_localhost', False)
            if not allow_localhost:
                return False, {
                    'passed': False,
                    'reason': 'localhost_not_allowed',
                    'message': 'Scanning localhost is not allowed by security policy',
                    'target_type': 'localhost'
                }
        
        # Check private IP restrictions
        if self.authorization.is_private_ip(target):
            allow_private = safety_config.get('allow_private_networks', True)
            if not allow_private:
                return False, {
                    'passed': False,
                    'reason': 'private_network_not_allowed',
                    'message': 'Scanning private networks is not allowed by security policy',
                    'target_type': 'private_network'
                }
        
        return True, {
            'passed': True,
            'message': 'Target safety validation passed',
            'target_type': self._get_target_type(target)
        }
    
    def _is_target_explicitly_authorized_for_aggressive_scans(self, target: str) -> bool:
        """Check if target is explicitly authorized for aggressive scans.
        
        Args:
            target: Target to check
            
        Returns:
            True if authorized for aggressive scans
        """
        aggressive_targets = self.security_config.get('aggressive_scan_targets', [])
        return target in aggressive_targets
    
    def _get_target_type(self, target: str) -> str:
        """Get target type classification.
        
        Args:
            target: Target to classify
            
        Returns:
            Target type string
        """
        if self.authorization.is_localhost(target):
            return 'localhost'
        elif self.authorization.is_private_ip(target):
            return 'private_network'
        else:
            return 'public'
    
    def add_authorized_target(self, target: str, user: Optional[str] = None) -> bool:
        """Add target to authorized list.
        
        Args:
            target: Target to authorize
            user: User making the request
            
        Returns:
            True if successfully added
        """
        success = self.authorization.add_allowed_target(target)
        
        if success:
            self.logger.info("Target added to authorized list", extra={
                'target': target,
                'user': user,
                'action': 'add_authorized_target'
            })
        else:
            self.logger.warning("Failed to add target to authorized list", extra={
                'target': target,
                'user': user,
                'action': 'add_authorized_target',
                'reason': 'invalid_target_format'
            })
        
        return success
    
    def remove_authorized_target(self, target: str, user: Optional[str] = None) -> bool:
        """Remove target from authorized list.
        
        Args:
            target: Target to remove
            user: User making the request
            
        Returns:
            True if successfully removed
        """
        success = self.authorization.remove_allowed_target(target)
        
        if success:
            self.logger.info("Target removed from authorized list", extra={
                'target': target,
                'user': user,
                'action': 'remove_authorized_target'
            })
        
        return success
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status and statistics.
        
        Returns:
            Dictionary with security status information
        """
        return {
            'authorization': {
                'enabled': self.authorization.enabled,
                'whitelist_only': self.authorization.whitelist_only,
                'authorized_targets_count': len(self.authorization.get_allowed_targets()),
            },
            'rate_limiting': self.rate_limiter.get_stats(),
            'security_config': {
                'ssl_verification': self.security_config.get('ssl_verification', True),
                'scan_restrictions': self.security_config.get('scan_restrictions', {}),
                'target_safety': self.security_config.get('target_safety', {}),
            }
        }
    
    def reset_rate_limits(self, target: Optional[str] = None, user: Optional[str] = None) -> bool:
        """Reset rate limits.
        
        Args:
            target: Specific target to reset (optional)
            user: Specific user to reset (optional)
            
        Returns:
            True if reset was performed
        """
        success = self.rate_limiter.reset_limits(target, user)
        
        if success:
            self.logger.info("Rate limits reset", extra={
                'target': target,
                'user': user,
                'action': 'reset_rate_limits'
            })
        
        return success