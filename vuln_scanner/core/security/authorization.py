"""Authorization manager for target validation and access control."""

import ipaddress
import re
from typing import Set, List, Optional, Dict, Any
from urllib.parse import urlparse


class AuthorizationManager:
    """Manages authorization and access control for scan targets."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize authorization manager.
        
        Args:
            config: Configuration dictionary containing security settings
        """
        self.config = config
        security_config = config.get('security', {})
        auth_config = security_config.get('authorization', {})
        
        self.enabled = auth_config.get('enabled', True)
        self.whitelist_only = auth_config.get('whitelist_only', True)
        self.allowed_targets = set(auth_config.get('allowed_targets', []))
        
        # Parse allowed targets for efficient matching
        self._ip_ranges: List[ipaddress.IPv4Network] = []
        self._ipv6_ranges: List[ipaddress.IPv6Network] = []
        self._domains: Set[str] = set()
        self._wildcard_domains: List[str] = []
        
        self._parse_allowed_targets()
    
    def _parse_allowed_targets(self) -> None:
        """Parse and categorize allowed targets for efficient matching."""
        for target in self.allowed_targets:
            try:
                # Try to parse as IP network (CIDR)
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    if network.version == 4:
                        self._ip_ranges.append(network)
                    else:
                        self._ipv6_ranges.append(network)
                    continue
                
                # Try to parse as single IP address
                try:
                    addr = ipaddress.ip_address(target)
                    if addr.version == 4:
                        self._ip_ranges.append(ipaddress.IPv4Network(f"{addr}/32"))
                    else:
                        self._ipv6_ranges.append(ipaddress.IPv6Network(f"{addr}/128"))
                    continue
                except ValueError:
                    pass
                
                # Handle as domain
                if target.startswith('*.'):
                    self._wildcard_domains.append(target[2:])
                else:
                    self._domains.add(target)
                    
            except ValueError:
                # Treat as domain if IP parsing fails
                if target.startswith('*.'):
                    self._wildcard_domains.append(target[2:])
                else:
                    self._domains.add(target)
    
    def is_target_authorized(self, target: str) -> bool:
        """Check if target is authorized for scanning.
        
        Args:
            target: Target to validate (IP, domain, or URL)
            
        Returns:
            True if target is authorized, False otherwise
        """
        if not self.enabled:
            return True
        
        if not self.whitelist_only:
            # In non-whitelist mode, check against blacklist (not implemented yet)
            return True
        
        # Parse target to extract hostname/IP
        hostname = self._extract_hostname(target)
        if not hostname:
            return False
        
        # Check against allowed targets
        return self._is_hostname_allowed(hostname)
    
    def _extract_hostname(self, target: str) -> Optional[str]:
        """Extract hostname from target string.
        
        Args:
            target: Target string (IP, domain, or URL)
            
        Returns:
            Extracted hostname or None if invalid
        """
        # Handle URLs
        if '://' in target:
            try:
                parsed = urlparse(target)
                return parsed.hostname
            except Exception:
                return None
        
        # Handle port specifications
        if ':' in target and not self._is_ipv6(target):
            target = target.split(':')[0]
        
        return target.strip()
    
    def _is_ipv6(self, target: str) -> bool:
        """Check if target appears to be IPv6 address.
        
        Args:
            target: Target string to check
            
        Returns:
            True if appears to be IPv6, False otherwise
        """
        return target.count(':') > 1
    
    def _is_hostname_allowed(self, hostname: str) -> bool:
        """Check if hostname is in allowed list.
        
        Args:
            hostname: Hostname to check
            
        Returns:
            True if allowed, False otherwise
        """
        # Try to parse as IP address first
        try:
            addr = ipaddress.ip_address(hostname)
            return self._is_ip_allowed(addr)
        except ValueError:
            pass
        
        # Check exact domain match
        if hostname in self._domains:
            return True
        
        # Check wildcard domain matches
        for wildcard_domain in self._wildcard_domains:
            if hostname.endswith(f'.{wildcard_domain}') or hostname == wildcard_domain:
                return True
        
        return False
    
    def _is_ip_allowed(self, ip_addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Check if IP address is in allowed ranges.
        
        Args:
            ip_addr: IP address to check
            
        Returns:
            True if allowed, False otherwise
        """
        if ip_addr.version == 4:
            for network in self._ip_ranges:
                if ip_addr in network:
                    return True
        else:
            for network in self._ipv6_ranges:
                if ip_addr in network:
                    return True
        
        return False
    
    def add_allowed_target(self, target: str) -> bool:
        """Add target to allowed list.
        
        Args:
            target: Target to add
            
        Returns:
            True if successfully added, False if invalid format
        """
        if not self._validate_target_format(target):
            return False
        
        self.allowed_targets.add(target)
        self._parse_allowed_targets()  # Re-parse all targets
        return True
    
    def remove_allowed_target(self, target: str) -> bool:
        """Remove target from allowed list.
        
        Args:
            target: Target to remove
            
        Returns:
            True if successfully removed, False if not found
        """
        if target in self.allowed_targets:
            self.allowed_targets.remove(target)
            self._parse_allowed_targets()  # Re-parse all targets
            return True
        return False
    
    def _validate_target_format(self, target: str) -> bool:
        """Validate target format.
        
        Args:
            target: Target to validate
            
        Returns:
            True if valid format, False otherwise
        """
        try:
            # Check if it's an IP address or CIDR
            if '/' in target:
                ipaddress.ip_network(target, strict=False)
                return True
            
            try:
                ipaddress.ip_address(target)
                return True
            except ValueError:
                pass
            
            # Check if it's a valid domain format
            return self._validate_domain_format(target)
            
        except ValueError:
            return False
    
    def _validate_domain_format(self, domain: str) -> bool:
        """Validate domain name format.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            True if valid domain format, False otherwise
        """
        if not domain:
            return False
        
        # Allow wildcard domains
        if domain.startswith('*.'):
            domain = domain[2:]
        
        # Basic domain validation
        if len(domain) > 253:
            return False
        
        # Domain name regex pattern
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        return bool(domain_pattern.match(domain))
    
    def get_allowed_targets(self) -> Set[str]:
        """Get set of all allowed targets.
        
        Returns:
            Set of allowed target strings
        """
        return self.allowed_targets.copy()
    
    def is_private_ip(self, target: str) -> bool:
        """Check if target is a private IP address.
        
        Args:
            target: Target to check
            
        Returns:
            True if private IP, False otherwise
        """
        hostname = self._extract_hostname(target)
        if not hostname:
            return False
        
        try:
            addr = ipaddress.ip_address(hostname)
            return addr.is_private
        except ValueError:
            return False
    
    def is_localhost(self, target: str) -> bool:
        """Check if target refers to localhost.
        
        Args:
            target: Target to check
            
        Returns:
            True if localhost, False otherwise
        """
        hostname = self._extract_hostname(target)
        if not hostname:
            return False
        
        localhost_names = {'localhost', '127.0.0.1', '::1', '0.0.0.0'}
        
        if hostname.lower() in localhost_names:
            return True
        
        try:
            addr = ipaddress.ip_address(hostname)
            return addr.is_loopback
        except ValueError:
            return False