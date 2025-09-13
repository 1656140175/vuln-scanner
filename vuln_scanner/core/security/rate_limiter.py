"""Rate limiter for controlling scan frequency and preventing abuse."""

import time
from collections import defaultdict, deque
from typing import Dict, Any, Optional, Tuple
import threading
from dataclasses import dataclass


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    enabled: bool = True
    requests_per_minute: int = 60
    burst_limit: int = 10
    cleanup_interval: int = 300  # seconds


class RateLimiter:
    """Thread-safe rate limiter for controlling request frequency."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize rate limiter.
        
        Args:
            config: Configuration dictionary containing rate limiting settings
        """
        rate_config = config.get('security', {}).get('rate_limiting', {})
        
        self.config = RateLimitConfig(
            enabled=rate_config.get('enabled', True),
            requests_per_minute=rate_config.get('requests_per_minute', 60),
            burst_limit=rate_config.get('burst_limit', 10),
            cleanup_interval=rate_config.get('cleanup_interval', 300)
        )
        
        # Track requests per target
        self._target_requests: Dict[str, deque] = defaultdict(deque)
        
        # Track requests per user (if user tracking is enabled)
        self._user_requests: Dict[str, deque] = defaultdict(deque)
        
        # Global request tracking
        self._global_requests: deque = deque()
        
        # Thread lock for thread safety
        self._lock = threading.RLock()
        
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_old_requests, daemon=True)
        self._cleanup_thread.start()
        
        # Track last cleanup time
        self._last_cleanup = time.time()
    
    def check_rate_limit(self, target: str, user: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        """Check if request is within rate limits.
        
        Args:
            target: Target being accessed
            user: User making the request (optional)
            
        Returns:
            Tuple of (allowed, limit_info) where limit_info contains details about limits
        """
        if not self.config.enabled:
            return True, {'reason': 'rate_limiting_disabled'}
        
        current_time = time.time()
        
        with self._lock:
            # Check global rate limit
            global_allowed, global_info = self._check_global_limit(current_time)
            if not global_allowed:
                return False, global_info
            
            # Check per-target rate limit
            target_allowed, target_info = self._check_target_limit(target, current_time)
            if not target_allowed:
                return False, target_info
            
            # Check per-user rate limit if user is specified
            if user:
                user_allowed, user_info = self._check_user_limit(user, current_time)
                if not user_allowed:
                    return False, user_info
            
            # All checks passed, record the request
            self._record_request(target, user, current_time)
            
            return True, {
                'allowed': True,
                'global_requests_remaining': self._get_requests_remaining(self._global_requests, current_time),
                'target_requests_remaining': self._get_requests_remaining(self._target_requests[target], current_time),
            }
    
    def _check_global_limit(self, current_time: float) -> Tuple[bool, Dict[str, Any]]:
        """Check global rate limit.
        
        Args:
            current_time: Current timestamp
            
        Returns:
            Tuple of (allowed, info)
        """
        # Clean old requests
        self._clean_old_requests(self._global_requests, current_time)
        
        # Check minute limit
        if len(self._global_requests) >= self.config.requests_per_minute:
            return False, {
                'reason': 'global_rate_limit_exceeded',
                'limit_type': 'global',
                'requests_per_minute': self.config.requests_per_minute,
                'current_requests': len(self._global_requests),
                'reset_time': self._get_reset_time(self._global_requests)
            }
        
        return True, {}
    
    def _check_target_limit(self, target: str, current_time: float) -> Tuple[bool, Dict[str, Any]]:
        """Check per-target rate limit.
        
        Args:
            target: Target being checked
            current_time: Current timestamp
            
        Returns:
            Tuple of (allowed, info)
        """
        target_requests = self._target_requests[target]
        self._clean_old_requests(target_requests, current_time)
        
        # Per-target limit is half of global limit
        target_limit = max(1, self.config.requests_per_minute // 2)
        
        if len(target_requests) >= target_limit:
            return False, {
                'reason': 'target_rate_limit_exceeded',
                'limit_type': 'target',
                'target': target,
                'requests_per_minute': target_limit,
                'current_requests': len(target_requests),
                'reset_time': self._get_reset_time(target_requests)
            }
        
        return True, {}
    
    def _check_user_limit(self, user: str, current_time: float) -> Tuple[bool, Dict[str, Any]]:
        """Check per-user rate limit.
        
        Args:
            user: User being checked
            current_time: Current timestamp
            
        Returns:
            Tuple of (allowed, info)
        """
        user_requests = self._user_requests[user]
        self._clean_old_requests(user_requests, current_time)
        
        # Per-user limit is 80% of global limit
        user_limit = max(1, int(self.config.requests_per_minute * 0.8))
        
        if len(user_requests) >= user_limit:
            return False, {
                'reason': 'user_rate_limit_exceeded',
                'limit_type': 'user',
                'user': user,
                'requests_per_minute': user_limit,
                'current_requests': len(user_requests),
                'reset_time': self._get_reset_time(user_requests)
            }
        
        return True, {}
    
    def _record_request(self, target: str, user: Optional[str], current_time: float) -> None:
        """Record a request for rate limiting tracking.
        
        Args:
            target: Target of the request
            user: User making the request
            current_time: Current timestamp
        """
        # Record global request
        self._global_requests.append(current_time)
        
        # Record per-target request
        self._target_requests[target].append(current_time)
        
        # Record per-user request
        if user:
            self._user_requests[user].append(current_time)
    
    def _clean_old_requests(self, requests: deque, current_time: float) -> None:
        """Remove requests older than 1 minute.
        
        Args:
            requests: Deque of request timestamps
            current_time: Current timestamp
        """
        cutoff_time = current_time - 60  # 60 seconds
        
        while requests and requests[0] < cutoff_time:
            requests.popleft()
    
    def _get_requests_remaining(self, requests: deque, current_time: float) -> int:
        """Get number of requests remaining in current window.
        
        Args:
            requests: Deque of request timestamps
            current_time: Current timestamp
            
        Returns:
            Number of requests remaining
        """
        self._clean_old_requests(requests, current_time)
        return max(0, self.config.requests_per_minute - len(requests))
    
    def _get_reset_time(self, requests: deque) -> Optional[float]:
        """Get timestamp when rate limit will reset.
        
        Args:
            requests: Deque of request timestamps
            
        Returns:
            Reset timestamp or None if no requests
        """
        if not requests:
            return None
        return requests[0] + 60  # Reset when oldest request is 60 seconds old
    
    def _cleanup_old_requests(self) -> None:
        """Background thread to clean up old request data."""
        while True:
            try:
                time.sleep(self.config.cleanup_interval)
                current_time = time.time()
                
                with self._lock:
                    # Clean global requests
                    self._clean_old_requests(self._global_requests, current_time)
                    
                    # Clean target requests and remove empty entries
                    targets_to_remove = []
                    for target, requests in self._target_requests.items():
                        self._clean_old_requests(requests, current_time)
                        if not requests:
                            targets_to_remove.append(target)
                    
                    for target in targets_to_remove:
                        del self._target_requests[target]
                    
                    # Clean user requests and remove empty entries
                    users_to_remove = []
                    for user, requests in self._user_requests.items():
                        self._clean_old_requests(requests, current_time)
                        if not requests:
                            users_to_remove.append(user)
                    
                    for user in users_to_remove:
                        del self._user_requests[user]
                    
                    self._last_cleanup = current_time
                        
            except Exception:
                # Ignore exceptions in cleanup thread
                pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current rate limiting statistics.
        
        Returns:
            Dictionary with current statistics
        """
        current_time = time.time()
        
        with self._lock:
            # Clean before getting stats
            self._clean_old_requests(self._global_requests, current_time)
            
            stats = {
                'enabled': self.config.enabled,
                'requests_per_minute_limit': self.config.requests_per_minute,
                'current_global_requests': len(self._global_requests),
                'global_requests_remaining': self._get_requests_remaining(self._global_requests, current_time),
                'active_targets': len([t for t, reqs in self._target_requests.items() if reqs]),
                'active_users': len([u for u, reqs in self._user_requests.items() if reqs]),
                'last_cleanup': self._last_cleanup,
            }
            
            # Add target-specific stats
            target_stats = {}
            for target, requests in self._target_requests.items():
                if requests:
                    self._clean_old_requests(requests, current_time)
                    if requests:  # Still has requests after cleaning
                        target_stats[target] = {
                            'current_requests': len(requests),
                            'requests_remaining': self._get_requests_remaining(requests, current_time),
                        }
            
            stats['target_stats'] = target_stats
            
            return stats
    
    def reset_limits(self, target: Optional[str] = None, user: Optional[str] = None) -> bool:
        """Reset rate limits for specific target or user.
        
        Args:
            target: Target to reset (optional)
            user: User to reset (optional)
            
        Returns:
            True if reset was performed
        """
        with self._lock:
            if target and target in self._target_requests:
                self._target_requests[target].clear()
                return True
            
            if user and user in self._user_requests:
                self._user_requests[user].clear()
                return True
            
            if not target and not user:
                # Reset all limits
                self._global_requests.clear()
                self._target_requests.clear()
                self._user_requests.clear()
                return True
        
        return False