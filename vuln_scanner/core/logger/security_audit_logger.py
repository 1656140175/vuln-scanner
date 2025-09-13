"""Security audit logger for VulnMiner system."""

import logging
from datetime import datetime
from typing import Dict, Any, Optional, List


class SecurityAuditLogger:
    """Specialized logger for security audit events."""
    
    def __init__(self, logger_manager):
        """Initialize security audit logger.
        
        Args:
            logger_manager: LoggerManager instance
        """
        self.logger = logger_manager.get_logger('security')
        self.general_logger = logger_manager.get_logger('general')
    
    def log_scan_start(self, target: str, scan_type: str, user: Optional[str] = None, 
                      scan_id: Optional[str] = None, **kwargs) -> None:
        """Log scan start event.
        
        Args:
            target: Target being scanned
            scan_type: Type of scan being performed
            user: User initiating the scan
            scan_id: Unique scan identifier
            **kwargs: Additional context data
        """
        self.logger.info("Scan operation started", extra={
            'event_type': 'scan_start',
            'target': target,
            'scan_type': scan_type,
            'user': user,
            'scan_id': scan_id,
            'timestamp': datetime.utcnow().isoformat(),
            'event_category': 'security_audit',
            **kwargs
        })
    
    def log_scan_complete(self, target: str, scan_type: str, duration: float,
                         vulnerabilities_found: int, scan_id: Optional[str] = None,
                         **kwargs) -> None:
        """Log scan completion event.
        
        Args:
            target: Target that was scanned
            scan_type: Type of scan performed
            duration: Scan duration in seconds
            vulnerabilities_found: Number of vulnerabilities found
            scan_id: Unique scan identifier
            **kwargs: Additional context data
        """
        self.logger.info("Scan operation completed", extra={
            'event_type': 'scan_complete',
            'target': target,
            'scan_type': scan_type,
            'duration_seconds': duration,
            'vulnerabilities_found': vulnerabilities_found,
            'scan_id': scan_id,
            'timestamp': datetime.utcnow().isoformat(),
            'event_category': 'security_audit',
            **kwargs
        })
    
    def log_vulnerability_found(self, vulnerability_data: Dict[str, Any],
                              scan_id: Optional[str] = None) -> None:
        """Log vulnerability detection event.
        
        Args:
            vulnerability_data: Detailed vulnerability information
            scan_id: Unique scan identifier
        """
        self.logger.warning("Vulnerability detected", extra={
            'event_type': 'vulnerability_detected',
            'severity': vulnerability_data.get('severity', 'unknown'),
            'target': vulnerability_data.get('target'),
            'vuln_type': vulnerability_data.get('type'),
            'vuln_name': vulnerability_data.get('name'),
            'cvss_score': vulnerability_data.get('cvss_score'),
            'cve_id': vulnerability_data.get('cve_id'),
            'scan_id': scan_id,
            'timestamp': datetime.utcnow().isoformat(),
            'event_category': 'vulnerability',
            'vulnerability_details': vulnerability_data
        })
    
    def log_access_denied(self, target: str, reason: str, user: Optional[str] = None,
                         **kwargs) -> None:
        """Log access denied event.
        
        Args:
            target: Target that was denied access to
            reason: Reason for denial
            user: User who was denied access
            **kwargs: Additional context data
        """
        self.logger.error("Access denied to target", extra={
            'event_type': 'access_denied',
            'target': target,
            'reason': reason,
            'user': user,
            'timestamp': datetime.utcnow().isoformat(),
            'event_category': 'security_violation',
            **kwargs
        })
    
    def log_tool_execution(self, tool_name: str, command: str, target: str,
                          exit_code: int, duration: float, 
                          scan_id: Optional[str] = None, **kwargs) -> None:
        """Log tool execution event.
        
        Args:
            tool_name: Name of tool executed
            command: Command that was executed
            target: Target the tool was run against
            exit_code: Exit code of the tool
            duration: Execution duration in seconds
            scan_id: Unique scan identifier
            **kwargs: Additional context data
        """
        level = logging.INFO if exit_code == 0 else logging.WARNING
        
        self.logger.log(level, "Security tool executed", extra={
            'event_type': 'tool_execution',
            'tool_name': tool_name,
            'command': command,
            'target': target,
            'exit_code': exit_code,
            'duration_seconds': duration,
            'scan_id': scan_id,
            'timestamp': datetime.utcnow().isoformat(),
            'event_category': 'tool_usage',
            'success': exit_code == 0,
            **kwargs
        })
    
    def log_configuration_change(self, section: str, key: str, old_value: Any,
                               new_value: Any, user: Optional[str] = None,
                               **kwargs) -> None:
        """Log configuration change event.
        
        Args:
            section: Configuration section that changed
            key: Configuration key that changed
            old_value: Previous value
            new_value: New value
            user: User who made the change
            **kwargs: Additional context data
        """
        self.logger.info("Configuration changed", extra={
            'event_type': 'config_change',
            'config_section': section,
            'config_key': key,
            'old_value': str(old_value),
            'new_value': str(new_value),
            'user': user,
            'timestamp': datetime.utcnow().isoformat(),
            'event_category': 'system_change',
            **kwargs
        })
    
    def log_system_error(self, error: Exception, context: str,
                        scan_id: Optional[str] = None, **kwargs) -> None:
        """Log system error event.
        
        Args:
            error: Exception that occurred
            context: Context where error occurred
            scan_id: Unique scan identifier if applicable
            **kwargs: Additional context data
        """
        self.logger.error("System error occurred", extra={
            'event_type': 'system_error',
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context,
            'scan_id': scan_id,
            'timestamp': datetime.utcnow().isoformat(),
            'event_category': 'system_error',
            **kwargs
        }, exc_info=True)
    
    def log_rate_limit_exceeded(self, target: str, user: Optional[str] = None,
                              requests_count: Optional[int] = None,
                              time_window: Optional[str] = None, **kwargs) -> None:
        """Log rate limit exceeded event.
        
        Args:
            target: Target that triggered rate limit
            user: User who exceeded rate limit
            requests_count: Number of requests made
            time_window: Time window for rate limit
            **kwargs: Additional context data
        """
        self.logger.warning("Rate limit exceeded", extra={
            'event_type': 'rate_limit_exceeded',
            'target': target,
            'user': user,
            'requests_count': requests_count,
            'time_window': time_window,
            'timestamp': datetime.utcnow().isoformat(),
            'event_category': 'rate_limiting',
            **kwargs
        })
    
    def log_user_action(self, action: str, user: str, target: Optional[str] = None,
                       details: Optional[Dict[str, Any]] = None, **kwargs) -> None:
        """Log user action event.
        
        Args:
            action: Action performed by user
            user: User who performed action
            target: Target of the action if applicable
            details: Additional action details
            **kwargs: Additional context data
        """
        self.logger.info("User action performed", extra={
            'event_type': 'user_action',
            'action': action,
            'user': user,
            'target': target,
            'action_details': details or {},
            'timestamp': datetime.utcnow().isoformat(),
            'event_category': 'user_activity',
            **kwargs
        })
    
    def query_events(self, event_type: Optional[str] = None,
                    start_time: Optional[datetime] = None,
                    end_time: Optional[datetime] = None,
                    target: Optional[str] = None) -> List[Dict[str, Any]]:
        """Query audit events (placeholder for future implementation).
        
        Args:
            event_type: Filter by event type
            start_time: Filter by start time
            end_time: Filter by end time
            target: Filter by target
            
        Returns:
            List of matching audit events
            
        Note:
            This is a placeholder method. Full implementation would require
            integration with a log aggregation system or database.
        """
        # This would typically query a log aggregation system or database
        self.general_logger.info("Audit event query requested", extra={
            'event_type': event_type,
            'start_time': start_time.isoformat() if start_time else None,
            'end_time': end_time.isoformat() if end_time else None,
            'target': target
        })
        
        # Return empty list as placeholder
        return []