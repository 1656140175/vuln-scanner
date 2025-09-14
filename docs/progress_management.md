# Progress Management System

The Progress Management System provides comprehensive real-time progress tracking, state persistence, checkpoint/resume functionality, and performance monitoring for vulnerability scanning operations.

## Overview

The system consists of several key components working together to provide a robust progress management solution:

- **ProgressManager**: Core task lifecycle management
- **TaskQueue**: Concurrent task execution with priority support
- **ProgressStorage**: Persistent state storage (SQLite/Redis)
- **ProgressEventBus**: Real-time event system
- **CheckpointManager**: Fault-tolerant state persistence
- **ProgressEstimator**: ML-based duration prediction
- **ProgressMonitor**: System health and performance monitoring
- **WebSocket Support**: Real-time progress streaming
- **REST API**: HTTP endpoints for integration
- **CLI Interface**: Command-line progress management

## Quick Start

### Basic Usage

```python
from vuln_scanner.core.progress_manager import initialize_progress_system
from vuln_scanner.progress.queue import ScanConfig, TaskPriority

# Initialize the progress system
config = {
    "storage": {"type": "sqlite", "path": "data/progress.db"},
    "task_queue": {"enabled": True, "max_concurrent": 5}
}

progress_factory = await initialize_progress_system(config)
progress_manager = progress_factory.get_progress_manager()
task_queue = progress_factory.get_task_queue()

# Create and submit a scan task
scan_config = ScanConfig(
    scan_id="scan-001",
    scan_profile="comprehensive",
    target_info={"target": "example.com", "type": "domain"},
    priority=TaskPriority.HIGH
)

task_id = await task_queue.submit_task(scan_config)
print(f"Task submitted: {task_id}")

# Monitor progress
progress_state = await progress_manager.get_progress(task_id)
print(f"Overall progress: {progress_state.overall_progress:.1f}%")
```

### Integration with Scan Engine

```python
from vuln_scanner.core.scanning.progress_integration import ProgressTrackingMixin

class MyScanEngine(ProgressTrackingMixin, BaseScanEngine):
    async def scan_target(self, target):
        # Create progress tracking
        async with self.progress_tracked_scan(
            scan_id="scan-001",
            scan_profile="normal", 
            target_info={"target": target}
        ) as progress_task_id:
            
            # Update progress during scanning
            await self.update_scan_progress(
                scan_id="scan-001",
                phase=ScanPhase.DISCOVERY,
                progress=25.0,
                current_step="Discovering subdomains"
            )
            
            # Create checkpoints
            await self.create_scan_checkpoint("scan-001", {"phase_data": "discovery_results"})
            
            # Complete phases
            await self.complete_scan_phase("scan-001", ScanPhase.DISCOVERY)
```

## Core Components

### ProgressManager

The `ProgressManager` handles the complete lifecycle of scanning tasks:

- **Task Creation**: Create new tasks with metadata
- **Lifecycle Management**: Start, pause, resume, cancel tasks
- **Progress Updates**: Real-time progress tracking by phase
- **State Persistence**: Automatic state saving
- **Checkpoint Creation**: Manual and automatic checkpoints

```python
# Create a task
task_id = await progress_manager.create_task(
    scan_id="scan-123",
    scan_profile="thorough",
    target_info={"target": "example.com", "type": "domain"},
    metadata={"user": "security-team", "priority": "high"}
)

# Start the task
await progress_manager.start_task(task_id)

# Update progress
await progress_manager.update_progress(
    task_id=task_id,
    phase=ScanPhase.RECONNAISSANCE,
    progress=75.0,
    current_step="Gathering OSINT data",
    total_steps=10,
    metadata={"tool": "recon-ng"}
)

# Create checkpoint
checkpoint_id = await progress_manager.checkpoint(task_id, {"recon_data": results})

# Complete a phase
await progress_manager.complete_phase(task_id, ScanPhase.RECONNAISSANCE)
```

### TaskQueue

The `TaskQueue` manages concurrent execution of multiple scanning tasks:

- **Priority Scheduling**: High, normal, low priority queuing
- **Concurrency Control**: Configurable concurrent task limits
- **Retry Logic**: Automatic retry with exponential backoff
- **Dependency Management**: Task dependency resolution
- **Resource Management**: Queue health and utilization monitoring

```python
# Configure task queue
task_queue = TaskQueue(max_concurrent=3, progress_manager=progress_manager)
await task_queue.initialize()

# Create scan configuration
scan_config = ScanConfig(
    scan_id="scan-456",
    scan_profile="quick",
    target_info={"target": "192.168.1.1", "type": "ip"},
    priority=TaskPriority.CRITICAL,
    timeout=timedelta(hours=1),
    max_retries=2
)

# Submit task
task_id = await task_queue.submit_task(scan_config)

# Monitor queue
queue_status = await task_queue.get_queue_status()
print(f"Queue utilization: {queue_status.utilization_percentage:.1f}%")
```

### Checkpoint System

The checkpoint system provides fault-tolerant state persistence with phase-specific strategies:

```python
from vuln_scanner.progress.checkpoint import CheckpointManager

checkpoint_manager = CheckpointManager(storage)

# Create checkpoint with phase-specific data
checkpoint_id = await checkpoint_manager.create_checkpoint(
    task_id="task-123",
    phase=ScanPhase.VULNERABILITY_SCAN,
    phase_data={
        "vulnerabilities_found": [
            {"cve": "CVE-2023-1234", "severity": "high"},
            {"cve": "CVE-2023-5678", "severity": "medium"}
        ],
        "scan_coverage": {"ports_scanned": 1000, "services_identified": 15}
    },
    progress_state=current_progress_state
)

# Restore from checkpoint
restored_data = await checkpoint_manager.restore_from_checkpoint(checkpoint_id)

# List checkpoints for a task
checkpoints = await checkpoint_manager.list_checkpoints("task-123")
```

### Progress Estimation

The estimation system provides ML-based duration prediction:

```python
from vuln_scanner.progress.estimator import ProgressEstimator, ComplexityMetrics

estimator = ProgressEstimator()

# Define target complexity
complexity = ComplexityMetrics(
    target_count=1,
    port_count=65535,
    service_count=20,
    subdomain_count=50,
    technology_count=10,
    vulnerability_count=15
)

# Get duration estimate
estimate = await estimator.estimate_total_duration(
    complexity_metrics=complexity,
    scan_profile="comprehensive"
)

print(f"Estimated duration: {estimate['total_estimated_duration']:.0f} seconds")
print(f"With buffer: {estimate['buffered_duration']:.0f} seconds")
print(f"Confidence: {estimate['average_confidence']*100:.1f}%")

# Per-phase estimates
for phase_name, phase_data in estimate['phase_estimates'].items():
    duration = timedelta(seconds=phase_data['estimated_duration'])
    print(f"{phase_name}: {duration} (confidence: {phase_data['confidence']*100:.1f}%)")
```

### Real-time Monitoring

The monitoring system provides health checks and alerting:

```python
from vuln_scanner.progress.monitor import ProgressMonitor

monitor = ProgressMonitor(progress_manager, task_queue)
await monitor.initialize()

# Monitor system health
health_data = await monitor.get_system_health()
print(f"System health: {health_data['overall_health']}")

# Monitor task health
health_status = await monitor.monitor_task_health("task-123")
if not health_status.is_healthy:
    print(f"Task warnings: {health_status.warnings}")

# Detect stuck tasks
stuck_tasks = await monitor.detect_stuck_tasks()
if stuck_tasks:
    print(f"Stuck tasks detected: {stuck_tasks}")

# Resource monitoring
resources = await monitor.monitor_resource_usage()
print(f"CPU: {resources.cpu_usage:.1f}%, Memory: {resources.memory_usage:.1f}%")
```

## WebSocket Real-time Updates

The system supports WebSocket connections for real-time progress streaming:

```javascript
// Connect to WebSocket
const ws = new WebSocket('ws://localhost:8000/api/v1/ws?subscription=all');

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    switch(data.type) {
        case 'progress_update':
            console.log(`Task ${data.task_id}: ${data.data.overall_progress}%`);
            updateProgressBar(data.task_id, data.data.overall_progress);
            break;
            
        case 'health_update':
            updateSystemStatus(data.data);
            break;
            
        case 'alert':
            showAlert(data.data);
            break;
    }
};

// Subscribe to specific task
const taskWs = new WebSocket('ws://localhost:8000/api/v1/ws?subscription=task&task_id=task-123');
```

## REST API

The system provides comprehensive REST API endpoints:

### Task Management

```bash
# Create task
curl -X POST http://localhost:8000/api/v1/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "scan-789",
    "scan_profile": "normal",
    "target_info": {"target": "example.com", "type": "domain"},
    "priority": "high"
  }'

# Get task progress
curl http://localhost:8000/api/v1/tasks/task-123/progress

# Pause/Resume/Cancel task
curl -X POST http://localhost:8000/api/v1/tasks/task-123/pause
curl -X POST http://localhost:8000/api/v1/tasks/task-123/resume
curl -X POST http://localhost:8000/api/v1/tasks/task-123/cancel

# List tasks
curl http://localhost:8000/api/v1/tasks?status=running
```

### Queue Management

```bash
# Get queue status
curl http://localhost:8000/api/v1/queue/status

# Get queue statistics
curl http://localhost:8000/api/v1/queue/statistics
```

### Health Monitoring

```bash
# System health
curl http://localhost:8000/api/v1/health

# Task health
curl http://localhost:8000/api/v1/health/tasks/task-123

# System alerts
curl http://localhost:8000/api/v1/alerts?severity=critical&resolved=false
```

### Duration Estimation

```bash
# Estimate scan duration
curl -X POST http://localhost:8000/api/v1/estimate/duration \
  -H "Content-Type: application/json" \
  -d '{
    "target_count": 1,
    "port_count": 1000,
    "service_count": 10,
    "subdomain_count": 20,
    "scan_profile": "comprehensive"
  }'
```

## CLI Interface

Command-line interface for progress management:

```bash
# Show task progress
vuln-miner progress show task-123
vuln-miner progress show task-123 --follow  # Real-time following

# List tasks
vuln-miner progress list
vuln-miner progress list --status running --limit 10

# Task control
vuln-miner progress pause task-123
vuln-miner progress resume task-123
vuln-miner progress cancel task-123

# Queue management
vuln-miner progress queue status

# Health monitoring
vuln-miner progress health status
vuln-miner progress health alerts --severity critical
```

## Configuration

Complete system configuration example:

```yaml
# config/progress.yml
progress_system:
  storage:
    type: "sqlite"  # or "redis"
    path: "data/progress.db"
    # redis_url: "redis://localhost:6379/0"
  
  progress_manager:
    checkpoint_interval: 30  # seconds
    auto_cleanup_hours: 24
    max_concurrent_tasks: 10
  
  task_queue:
    enabled: true
    max_concurrent: 5
    worker_timeout: 7200  # 2 hours
  
  progress_monitor:
    enabled: true
    monitor_interval: 30  # seconds
    resource_check_interval: 60
    stuck_task_threshold: 600  # 10 minutes
    
    alert_thresholds:
      cpu_usage: {warning: 70.0, critical: 90.0}
      memory_usage: {warning: 80.0, critical: 95.0}
      disk_usage: {warning: 85.0, critical: 95.0}
  
  progress_estimator:
    enabled: true
    max_historical_samples: 100
    
  websocket:
    enabled: true
    max_connections: 100
    ping_interval: 30
  
  event_bus:
    max_event_history: 1000
    cleanup_interval: 3600  # 1 hour
```

## Performance Considerations

### Optimization Tips

1. **Database Performance**:
   - Use connection pooling for high-throughput scenarios
   - Regular cleanup of old completed tasks
   - Index optimization for frequent queries

2. **Memory Management**:
   - Limit event history size
   - Cleanup completed tasks periodically
   - Monitor WebSocket connection counts

3. **Concurrency Tuning**:
   - Adjust `max_concurrent` based on system resources
   - Configure appropriate timeouts
   - Monitor queue health and utilization

4. **Checkpoint Strategy**:
   - Balance checkpoint frequency vs. performance
   - Use phase-specific checkpoint strategies
   - Cleanup old checkpoints regularly

### Scaling Considerations

- **Horizontal Scaling**: Use Redis backend for distributed deployments
- **Load Balancing**: Multiple API instances with shared storage
- **Resource Monitoring**: Implement comprehensive resource tracking
- **Database Sharding**: Partition tasks by scan_id or time ranges

## Error Handling

The system provides comprehensive error handling and recovery:

```python
from vuln_scanner.progress.models import ProgressError

# Handle recoverable errors
try:
    await scan_operation()
except RecoverableError as e:
    error = ProgressError(
        phase=current_phase,
        error_type="recoverable_error",
        message=str(e),
        recoverable=True
    )
    await progress_manager.add_phase_error(task_id, current_phase, error)
    # Continue with retry logic

# Handle fatal errors  
except FatalError as e:
    await progress_manager.fail_task(task_id, str(e), current_phase)
    raise
```

## Security Considerations

- **Input Validation**: All API inputs are validated
- **Rate Limiting**: WebSocket connections are rate limited
- **Access Control**: Implement authentication for sensitive operations
- **Data Sanitization**: Scan results are sanitized before storage
- **Audit Logging**: All operations are logged for security audits

## Integration Examples

### FastAPI Integration

```python
from fastapi import FastAPI
from vuln_scanner.progress.api import ProgressAPI

app = FastAPI()

# Initialize progress system
progress_factory = await initialize_progress_system()
progress_api = ProgressAPI(
    progress_manager=progress_factory.get_progress_manager(),
    task_queue=progress_factory.get_task_queue(),
    progress_monitor=progress_factory.get_progress_monitor(),
    websocket_manager=progress_factory.get_websocket_manager()
)

# Include progress API routes
app.include_router(progress_api.router)
```

### Custom Event Handlers

```python
async def custom_alert_handler(alert):
    """Custom alert handler."""
    if alert.severity == "critical":
        # Send email notification
        await send_email_alert(alert)
    
    # Log to external system
    await log_to_external_system(alert.to_dict())

# Register custom handlers
monitor = progress_factory.get_progress_monitor()
await monitor.add_alert_handler(custom_alert_handler)
```

This comprehensive progress management system provides enterprise-grade functionality for tracking, monitoring, and managing vulnerability scanning operations with high reliability and performance.