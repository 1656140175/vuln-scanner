"""Monitoring and health check system for progress management."""

import asyncio
import logging
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from collections import deque

from .models import (
    ProgressState, TaskStatus, HealthStatus, ResourceMetrics,
    PhaseProgress
)
from .manager import ProgressManager
from .queue import TaskQueue
from .storage.base import ProgressStorage
from ..core.scanning.data_structures import ScanPhase
from ..core.exceptions import BaseException


logger = logging.getLogger(__name__)


class class MonitoringException(BaseException):(VulnMinerException):
    """Monitoring system specific exceptions."""
    pass


@dataclass
class AlertThreshold:
    """Alert threshold configuration."""
    metric_name: str
    warning_threshold: float
    critical_threshold: float
    duration_threshold: timedelta = timedelta(minutes=5)  # Time before triggering alert
    enabled: bool = True


@dataclass
class Alert:
    """System alert representation."""
    alert_id: str
    alert_type: str
    severity: str  # info, warning, critical
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    task_id: Optional[str] = None
    metric_value: Optional[float] = None
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'alert_id': self.alert_id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'message': self.message,
            'timestamp': self.timestamp.isoformat(),
            'task_id': self.task_id,
            'metric_value': self.metric_value,
            'resolved': self.resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }


class ProgressMonitor:
    """Monitoring system for progress management health and performance."""
    
    def __init__(self, progress_manager: Optional[ProgressManager] = None,
                 task_queue: Optional[TaskQueue] = None,
                 storage: Optional[ProgressStorage] = None):
        """Initialize progress monitor.
        
        Args:
            progress_manager: ProgressManager instance to monitor
            task_queue: TaskQueue instance to monitor
            storage: Storage backend to monitor
        """
        self.progress_manager = progress_manager
        self.task_queue = task_queue
        self.storage = storage
        
        # Monitoring configuration
        self.monitor_interval = timedelta(seconds=30)
        self.resource_check_interval = timedelta(seconds=60)
        self.stuck_task_threshold = timedelta(minutes=10)
        self.max_alerts = 1000
        
        # Alert thresholds
        self.alert_thresholds = {
            'cpu_usage': AlertThreshold('cpu_usage', 70.0, 90.0),
            'memory_usage': AlertThreshold('memory_usage', 80.0, 95.0),
            'disk_usage': AlertThreshold('disk_usage', 85.0, 95.0),
            'queue_size': AlertThreshold('queue_size', 20.0, 50.0),
            'failed_task_rate': AlertThreshold('failed_task_rate', 0.1, 0.3),  # 10% and 30%
            'task_timeout_rate': AlertThreshold('task_timeout_rate', 0.05, 0.2)  # 5% and 20%
        }
        
        # Monitoring state
        self.alerts: deque = deque(maxlen=self.max_alerts)
        self.alert_handlers: List[Callable] = []
        self.metric_history: Dict[str, deque] = {
            'cpu_usage': deque(maxlen=100),
            'memory_usage': deque(maxlen=100),
            'disk_usage': deque(maxlen=100),
            'active_tasks': deque(maxlen=100),
            'queue_size': deque(maxlen=100)
        }
        
        # Background tasks
        self._monitoring_tasks: List[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()
        self._initialized = False
        
        # Performance tracking
        self.last_check_time = datetime.now()
        self.check_count = 0
        self.alert_count = 0
    
    async def initialize(self) -> None:
        """Initialize monitoring system."""
        if self._initialized:
            return
        
        logger.info("Initializing progress monitor")
        
        # Start background monitoring tasks
        self._monitoring_tasks = [
            asyncio.create_task(self._health_check_loop(), name="HealthCheckLoop"),
            asyncio.create_task(self._resource_monitor_loop(), name="ResourceMonitorLoop"),
            asyncio.create_task(self._task_monitor_loop(), name="TaskMonitorLoop")
        ]
        
        self._initialized = True
        logger.info("Progress monitor initialized")
    
    async def shutdown(self) -> None:
        """Shutdown monitoring system."""
        if not self._initialized:
            return
        
        logger.info("Shutting down progress monitor")
        
        # Signal shutdown
        self._shutdown_event.set()
        
        # Cancel monitoring tasks
        for task in self._monitoring_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self._monitoring_tasks, return_exceptions=True)
        
        self._initialized = False
        logger.info("Progress monitor shutdown complete")
    
    async def monitor_task_health(self, task_id: str) -> HealthStatus:
        """Monitor health of a specific task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            HealthStatus object
        """
        try:
            if not self.progress_manager:
                return HealthStatus(
                    task_id=task_id,
                    is_healthy=False,
                    warnings=["No progress manager available"]
                )
            
            # Get task progress
            progress_state = await self.progress_manager.get_progress(task_id)
            if not progress_state:
                return HealthStatus(
                    task_id=task_id,
                    is_healthy=False,
                    warnings=["Task not found"]
                )
            
            # Check task health
            is_healthy = True
            warnings = []
            performance_score = 1.0
            
            # Check for stalled progress
            time_since_update = datetime.now() - progress_state.last_update
            if time_since_update > self.stuck_task_threshold:
                is_healthy = False
                warnings.append(f"No progress update for {time_since_update}")
                performance_score *= 0.3
            
            # Check for excessive errors
            all_errors = progress_state.get_all_errors()
            if len(all_errors) > 10:
                warnings.append(f"High error count: {len(all_errors)}")
                performance_score *= 0.7
            
            # Check phase progress consistency
            active_phases = progress_state.get_active_phases()
            if len(active_phases) > 2:  # Too many concurrent phases
                warnings.append(f"Too many active phases: {len(active_phases)}")
                performance_score *= 0.8
            
            # Check if task is running too long
            if progress_state.start_time:
                runtime = datetime.now() - progress_state.start_time
                if runtime > timedelta(hours=4):  # Configurable threshold
                    warnings.append(f"Long running task: {runtime}")
                    performance_score *= 0.9
            
            # Get resource usage for this task (if available)
            resource_usage = await self._get_task_resource_usage(task_id)
            
            return HealthStatus(
                task_id=task_id,
                is_healthy=is_healthy,
                warnings=warnings,
                resource_usage=resource_usage,
                performance_score=performance_score
            )
            
        except Exception as e:
            logger.error(f"Failed to monitor task health {task_id}: {e}")
            return HealthStatus(
                task_id=task_id,
                is_healthy=False,
                warnings=[f"Health check failed: {str(e)}"]
            )
    
    async def detect_stuck_tasks(self) -> List[str]:
        """Detect tasks that appear to be stuck.
        
        Returns:
            List of stuck task IDs
        """
        stuck_tasks = []
        
        try:
            if not self.progress_manager:
                return stuck_tasks
            
            # Get all active tasks
            active_task_ids = await self.progress_manager.list_tasks(TaskStatus.RUNNING)
            
            for task_id in active_task_ids:
                progress_state = await self.progress_manager.get_progress(task_id)
                if not progress_state:
                    continue
                
                # Check if task hasn't been updated recently
                time_since_update = datetime.now() - progress_state.last_update
                if time_since_update > self.stuck_task_threshold:
                    stuck_tasks.append(task_id)
                    
                    # Create alert for stuck task
                    await self._create_alert(
                        alert_type="stuck_task",
                        severity="warning",
                        message=f"Task {task_id} appears stuck (no update for {time_since_update})",
                        task_id=task_id
                    )
            
            if stuck_tasks:
                logger.warning(f"Detected {len(stuck_tasks)} stuck tasks")
            
            return stuck_tasks
            
        except Exception as e:
            logger.error(f"Failed to detect stuck tasks: {e}")
            return []
    
    async def monitor_resource_usage(self) -> ResourceMetrics:
        """Monitor system resource usage.
        
        Returns:
            ResourceMetrics object
        """
        try:
            # Get CPU usage
            cpu_usage = psutil.cpu_percent(interval=1)
            
            # Get memory usage
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
            
            # Get disk usage
            disk = psutil.disk_usage('/')
            disk_usage = disk.percent
            
            # Get network I/O
            network_io = psutil.net_io_counters()
            network_data = {
                'bytes_sent': network_io.bytes_sent,
                'bytes_recv': network_io.bytes_recv,
                'packets_sent': network_io.packets_sent,
                'packets_recv': network_io.packets_recv
            }
            
            # Get active connections (approximate)
            active_connections = len(psutil.net_connections())
            
            resource_metrics = ResourceMetrics(
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                disk_usage=disk_usage,
                network_io=network_data,
                active_connections=active_connections
            )
            
            # Store in history
            self.metric_history['cpu_usage'].append(cpu_usage)
            self.metric_history['memory_usage'].append(memory_usage)
            self.metric_history['disk_usage'].append(disk_usage)
            
            # Check thresholds and create alerts
            await self._check_resource_thresholds(resource_metrics)
            
            return resource_metrics
            
        except Exception as e:
            logger.error(f"Failed to monitor resource usage: {e}")
            return ResourceMetrics()
    
    async def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status.
        
        Returns:
            Dictionary containing system health information
        """
        try:
            health_data = {
                'timestamp': datetime.now().isoformat(),
                'overall_health': 'healthy',
                'components': {},
                'alerts': {
                    'total_alerts': len(self.alerts),
                    'unresolved_alerts': len([a for a in self.alerts if not a.resolved]),
                    'critical_alerts': len([a for a in self.alerts if a.severity == 'critical' and not a.resolved])
                },
                'metrics': {}
            }
            
            # Check progress manager health
            if self.progress_manager:
                try:
                    # Simple health check - try to get storage stats
                    if self.progress_manager.storage:
                        storage_healthy = await self.progress_manager.storage.health_check()
                        health_data['components']['progress_manager'] = 'healthy' if storage_healthy else 'unhealthy'
                    else:
                        health_data['components']['progress_manager'] = 'healthy'
                except Exception as e:
                    health_data['components']['progress_manager'] = 'unhealthy'
                    logger.error(f"Progress manager health check failed: {e}")
            
            # Check task queue health
            if self.task_queue:
                try:
                    queue_status = await self.task_queue.get_queue_status()
                    health_data['components']['task_queue'] = queue_status.queue_health
                    health_data['metrics']['queue_utilization'] = queue_status.utilization_percentage
                except Exception as e:
                    health_data['components']['task_queue'] = 'unhealthy'
                    logger.error(f"Task queue health check failed: {e}")
            
            # Check storage health
            if self.storage:
                try:
                    storage_healthy = await self.storage.health_check()
                    health_data['components']['storage'] = 'healthy' if storage_healthy else 'unhealthy'
                except Exception as e:
                    health_data['components']['storage'] = 'unhealthy'
                    logger.error(f"Storage health check failed: {e}")
            
            # Get resource metrics
            resource_metrics = await self.monitor_resource_usage()
            health_data['metrics']['resources'] = resource_metrics.to_dict()
            
            # Determine overall health
            component_health = list(health_data['components'].values())
            critical_alerts = health_data['alerts']['critical_alerts']
            
            if 'unhealthy' in component_health or critical_alerts > 0:
                health_data['overall_health'] = 'unhealthy'
            elif 'degraded' in component_health:
                health_data['overall_health'] = 'degraded'
            
            return health_data
            
        except Exception as e:
            logger.error(f"Failed to get system health: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'overall_health': 'unhealthy',
                'error': str(e)
            }
    
    async def add_alert_handler(self, handler: Callable[[Alert], Any]) -> None:
        """Add alert handler callback.
        
        Args:
            handler: Callback function for handling alerts
        """
        self.alert_handlers.append(handler)
    
    async def remove_alert_handler(self, handler: Callable[[Alert], Any]) -> None:
        """Remove alert handler callback.
        
        Args:
            handler: Callback function to remove
        """
        if handler in self.alert_handlers:
            self.alert_handlers.remove(handler)
    
    async def get_alerts(self, resolved: Optional[bool] = None,
                        severity: Optional[str] = None,
                        task_id: Optional[str] = None,
                        limit: int = 100) -> List[Alert]:
        """Get alerts with optional filtering.
        
        Args:
            resolved: Filter by resolved status (optional)
            severity: Filter by severity level (optional)
            task_id: Filter by task ID (optional)
            limit: Maximum number of alerts to return
            
        Returns:
            List of Alert objects
        """
        alerts = list(self.alerts)
        
        # Apply filters
        if resolved is not None:
            alerts = [a for a in alerts if a.resolved == resolved]
        
        if severity is not None:
            alerts = [a for a in alerts if a.severity == severity]
        
        if task_id is not None:
            alerts = [a for a in alerts if a.task_id == task_id]
        
        # Sort by timestamp (newest first) and limit
        alerts.sort(key=lambda x: x.timestamp, reverse=True)
        return alerts[:limit]
    
    async def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert.
        
        Args:
            alert_id: Alert identifier
            
        Returns:
            True if alert was found and resolved
        """
        for alert in self.alerts:
            if alert.alert_id == alert_id and not alert.resolved:
                alert.resolved = True
                alert.resolved_at = datetime.now()
                logger.info(f"Resolved alert {alert_id}")
                return True
        
        return False
    
    # Private methods
    
    async def _health_check_loop(self) -> None:
        """Background loop for health checks."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.monitor_interval.total_seconds()
                )
                break  # Shutdown event was set
                
            except asyncio.TimeoutError:
                # Perform health checks
                await self._perform_health_checks()
    
    async def _resource_monitor_loop(self) -> None:
        """Background loop for resource monitoring."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.resource_check_interval.total_seconds()
                )
                break  # Shutdown event was set
                
            except asyncio.TimeoutError:
                # Monitor resources
                await self.monitor_resource_usage()
    
    async def _task_monitor_loop(self) -> None:
        """Background loop for task monitoring."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.monitor_interval.total_seconds()
                )
                break  # Shutdown event was set
                
            except asyncio.TimeoutError:
                # Check for stuck tasks
                await self.detect_stuck_tasks()
                
                # Monitor task queue if available
                if self.task_queue:
                    await self._monitor_task_queue()
    
    async def _perform_health_checks(self) -> None:
        """Perform comprehensive health checks."""
        try:
            self.check_count += 1
            
            # Check system health
            health_data = await self.get_system_health()
            
            # Log health status periodically
            if self.check_count % 10 == 0:  # Every 10 checks
                logger.info(f"System health: {health_data['overall_health']}")
            
        except Exception as e:
            logger.error(f"Error in health check loop: {e}")
    
    async def _monitor_task_queue(self) -> None:
        """Monitor task queue health."""
        try:
            if not self.task_queue:
                return
            
            queue_status = await self.task_queue.get_queue_status()
            
            # Store queue size in history
            self.metric_history['queue_size'].append(queue_status.pending_count)
            self.metric_history['active_tasks'].append(queue_status.running_count)
            
            # Check for queue size alerts
            if queue_status.pending_count > self.alert_thresholds['queue_size'].warning_threshold:
                severity = 'critical' if queue_status.pending_count > self.alert_thresholds['queue_size'].critical_threshold else 'warning'
                await self._create_alert(
                    alert_type="high_queue_size",
                    severity=severity,
                    message=f"Queue size is high: {queue_status.pending_count} pending tasks",
                    metric_value=queue_status.pending_count
                )
            
            # Check task queue statistics
            stats = await self.task_queue.get_statistics()
            
            # Calculate failure rate
            total_tasks = stats['statistics']['total_completed'] + stats['statistics']['total_failed']
            if total_tasks > 0:
                failure_rate = stats['statistics']['total_failed'] / total_tasks
                
                if failure_rate > self.alert_thresholds['failed_task_rate'].warning_threshold:
                    severity = 'critical' if failure_rate > self.alert_thresholds['failed_task_rate'].critical_threshold else 'warning'
                    await self._create_alert(
                        alert_type="high_failure_rate",
                        severity=severity,
                        message=f"High task failure rate: {failure_rate:.2%}",
                        metric_value=failure_rate
                    )
            
        except Exception as e:
            logger.error(f"Error monitoring task queue: {e}")
    
    async def _check_resource_thresholds(self, resource_metrics: ResourceMetrics) -> None:
        """Check resource usage against thresholds and create alerts."""
        try:
            # Check CPU usage
            if resource_metrics.cpu_usage > self.alert_thresholds['cpu_usage'].warning_threshold:
                severity = 'critical' if resource_metrics.cpu_usage > self.alert_thresholds['cpu_usage'].critical_threshold else 'warning'
                await self._create_alert(
                    alert_type="high_cpu_usage",
                    severity=severity,
                    message=f"High CPU usage: {resource_metrics.cpu_usage:.1f}%",
                    metric_value=resource_metrics.cpu_usage
                )
            
            # Check memory usage
            if resource_metrics.memory_usage > self.alert_thresholds['memory_usage'].warning_threshold:
                severity = 'critical' if resource_metrics.memory_usage > self.alert_thresholds['memory_usage'].critical_threshold else 'warning'
                await self._create_alert(
                    alert_type="high_memory_usage",
                    severity=severity,
                    message=f"High memory usage: {resource_metrics.memory_usage:.1f}%",
                    metric_value=resource_metrics.memory_usage
                )
            
            # Check disk usage
            if resource_metrics.disk_usage > self.alert_thresholds['disk_usage'].warning_threshold:
                severity = 'critical' if resource_metrics.disk_usage > self.alert_thresholds['disk_usage'].critical_threshold else 'warning'
                await self._create_alert(
                    alert_type="high_disk_usage",
                    severity=severity,
                    message=f"High disk usage: {resource_metrics.disk_usage:.1f}%",
                    metric_value=resource_metrics.disk_usage
                )
            
        except Exception as e:
            logger.error(f"Error checking resource thresholds: {e}")
    
    async def _create_alert(self, alert_type: str, severity: str, message: str,
                          task_id: Optional[str] = None, 
                          metric_value: Optional[float] = None) -> None:
        """Create and process a new alert."""
        try:
            alert = Alert(
                alert_id=f"{alert_type}_{datetime.now().timestamp()}",
                alert_type=alert_type,
                severity=severity,
                message=message,
                task_id=task_id,
                metric_value=metric_value
            )
            
            # Add to alerts deque
            self.alerts.append(alert)
            self.alert_count += 1
            
            # Log alert
            logger.warning(f"ALERT [{severity.upper()}] {alert_type}: {message}")
            
            # Notify alert handlers
            for handler in self.alert_handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(alert)
                    else:
                        handler(alert)
                except Exception as e:
                    logger.error(f"Error in alert handler: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
    
    async def _get_task_resource_usage(self, task_id: str) -> Optional[ResourceMetrics]:
        """Get resource usage for a specific task."""
        # This would require tracking process IDs for tasks
        # For now, return None - could be implemented later
        return None
    
    async def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get monitoring system statistics.
        
        Returns:
            Dictionary containing monitoring statistics
        """
        current_time = datetime.now()
        uptime = current_time - self.last_check_time if hasattr(self, 'last_check_time') else timedelta()
        
        return {
            'uptime': uptime.total_seconds(),
            'check_count': self.check_count,
            'alert_count': self.alert_count,
            'unresolved_alerts': len([a for a in self.alerts if not a.resolved]),
            'metric_history_size': {
                metric: len(history) for metric, history in self.metric_history.items()
            },
            'alert_handlers': len(self.alert_handlers),
            'thresholds': {
                name: {
                    'warning': threshold.warning_threshold,
                    'critical': threshold.critical_threshold,
                    'enabled': threshold.enabled
                }
                for name, threshold in self.alert_thresholds.items()
            }
        }