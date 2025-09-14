"""Tests for the progress management system."""

import pytest
import asyncio
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from vuln_scanner.progress.models import ProgressState, TaskStatus, PhaseProgress, ProgressError
from vuln_scanner.progress.manager import ProgressManager
from vuln_scanner.progress.queue import TaskQueue, ScanConfig, TaskPriority
from vuln_scanner.progress.storage.sqlite import SqliteProgressStorage
from vuln_scanner.progress.events import ProgressEventBus, ProgressEvent, ProgressEventType
from vuln_scanner.progress.monitor import ProgressMonitor
from vuln_scanner.progress.estimator import ProgressEstimator, ComplexityMetrics
from vuln_scanner.progress.checkpoint import CheckpointManager
from vuln_scanner.core.scanning.data_structures import ScanPhase
from vuln_scanner.core.progress_manager import ProgressManagerFactory


class TestProgressModels:
    """Test progress data models."""
    
    def test_progress_state_creation(self):
        """Test ProgressState creation and initialization."""
        progress_state = ProgressState(
            task_id="test-task-1",
            scan_id="scan-123",
            scan_profile="normal",
            target_info={"target": "example.com", "type": "domain"}
        )
        
        assert progress_state.task_id == "test-task-1"
        assert progress_state.scan_id == "scan-123"
        assert progress_state.status == TaskStatus.PENDING
        assert progress_state.overall_progress == 0.0
        assert len(progress_state.phase_progress) == len(ScanPhase)
        
        # Test phase progress initialization
        for phase in ScanPhase:
            assert phase in progress_state.phase_progress
            assert progress_state.phase_progress[phase].phase == phase
    
    def test_progress_state_phase_update(self):
        """Test updating phase progress."""
        progress_state = ProgressState(
            task_id="test-task-1",
            scan_id="scan-123",
            scan_profile="normal",
            target_info={"target": "example.com"}
        )
        
        # Update discovery phase progress
        progress_state.update_phase_progress(
            phase=ScanPhase.DISCOVERY,
            completed=5,
            total=10,
            current_step="Discovering subdomains",
            metadata={"tool": "subfinder"}
        )
        
        discovery_progress = progress_state.get_phase_progress(ScanPhase.DISCOVERY)
        assert discovery_progress.completed_steps == 5
        assert discovery_progress.total_steps == 10
        assert discovery_progress.progress_percentage == 50.0
        assert discovery_progress.current_step == "Discovering subdomains"
        assert discovery_progress.status == TaskStatus.RUNNING
        assert discovery_progress.metadata["tool"] == "subfinder"
        
        # Test overall progress calculation
        assert progress_state.overall_progress > 0
    
    def test_progress_state_error_handling(self):
        """Test adding errors to progress state."""
        progress_state = ProgressState(
            task_id="test-task-1",
            scan_id="scan-123", 
            scan_profile="normal",
            target_info={"target": "example.com"}
        )
        
        error = ProgressError(
            phase=ScanPhase.DISCOVERY,
            error_type="connection_error",
            message="Failed to connect to target",
            recoverable=False
        )
        
        progress_state.add_phase_error(ScanPhase.DISCOVERY, error)
        
        discovery_progress = progress_state.get_phase_progress(ScanPhase.DISCOVERY)
        assert len(discovery_progress.errors) == 1
        assert discovery_progress.errors[0].message == "Failed to connect to target"
        assert discovery_progress.status == TaskStatus.FAILED
    
    def test_progress_state_serialization(self):
        """Test serialization and deserialization."""
        progress_state = ProgressState(
            task_id="test-task-1",
            scan_id="scan-123",
            scan_profile="normal",
            target_info={"target": "example.com"}
        )
        
        progress_state.update_phase_progress(ScanPhase.DISCOVERY, 3, 10, "Testing")
        
        # Test to_dict
        data = progress_state.to_dict()
        assert data["task_id"] == "test-task-1"
        assert data["scan_id"] == "scan-123"
        assert "phase_progress" in data
        
        # Test from_dict
        restored_state = ProgressState.from_dict(data)
        assert restored_state.task_id == progress_state.task_id
        assert restored_state.scan_id == progress_state.scan_id
        assert restored_state.overall_progress == progress_state.overall_progress
        
        restored_discovery = restored_state.get_phase_progress(ScanPhase.DISCOVERY)
        original_discovery = progress_state.get_phase_progress(ScanPhase.DISCOVERY)
        assert restored_discovery.completed_steps == original_discovery.completed_steps
        assert restored_discovery.current_step == original_discovery.current_step


@pytest.mark.asyncio
class TestProgressStorage:
    """Test progress storage implementations."""
    
    async def test_sqlite_storage_basic_operations(self):
        """Test basic SQLite storage operations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_progress.db"
            storage = SqliteProgressStorage(str(db_path))
            
            try:
                await storage.initialize()
                
                # Test saving progress
                progress_state = ProgressState(
                    task_id="test-task-1",
                    scan_id="scan-123",
                    scan_profile="normal",
                    target_info={"target": "example.com"}
                )
                
                await storage.save_progress(progress_state)
                
                # Test loading progress
                loaded_progress = await storage.load_progress("test-task-1")
                assert loaded_progress is not None
                assert loaded_progress.task_id == "test-task-1"
                assert loaded_progress.scan_id == "scan-123"
                
                # Test listing tasks
                active_tasks = await storage.list_active_tasks()
                assert "test-task-1" not in active_tasks  # Should be pending, not active
                
                pending_tasks = await storage.list_tasks_by_status("pending")
                assert "test-task-1" in pending_tasks
                
                # Test deleting progress
                deleted = await storage.delete_progress("test-task-1")
                assert deleted is True
                
                # Verify deletion
                loaded_progress = await storage.load_progress("test-task-1")
                assert loaded_progress is None
                
            finally:
                await storage.cleanup()
    
    async def test_sqlite_storage_checkpoint_operations(self):
        """Test checkpoint operations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_progress.db"
            storage = SqliteProgressStorage(str(db_path))
            
            try:
                await storage.initialize()
                
                from vuln_scanner.progress.models import CheckpointInfo
                
                # Create and save checkpoint
                checkpoint = CheckpointInfo(
                    task_id="test-task-1",
                    phase=ScanPhase.DISCOVERY,
                    phase_data={"discovered_targets": ["example.com", "sub.example.com"]},
                    metadata={"checkpoint_type": "test"}
                )
                
                await storage.save_checkpoint(checkpoint)
                
                # Test loading checkpoint
                loaded_checkpoint = await storage.load_checkpoint(checkpoint.checkpoint_id)
                assert loaded_checkpoint is not None
                assert loaded_checkpoint.task_id == "test-task-1"
                assert loaded_checkpoint.phase == ScanPhase.DISCOVERY
                assert loaded_checkpoint.phase_data["discovered_targets"] == ["example.com", "sub.example.com"]
                
                # Test listing checkpoints
                checkpoints = await storage.list_checkpoints("test-task-1")
                assert len(checkpoints) == 1
                assert checkpoints[0].checkpoint_id == checkpoint.checkpoint_id
                
                # Test getting latest checkpoint
                latest = await storage.get_latest_checkpoint("test-task-1")
                assert latest is not None
                assert latest.checkpoint_id == checkpoint.checkpoint_id
                
            finally:
                await storage.cleanup()


@pytest.mark.asyncio
class TestProgressManager:
    """Test progress manager functionality."""
    
    async def test_progress_manager_task_lifecycle(self):
        """Test complete task lifecycle."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_progress.db"
            storage = SqliteProgressStorage(str(db_path))
            
            progress_manager = ProgressManager(storage=storage)
            
            try:
                await progress_manager.initialize()
                
                # Create task
                task_id = await progress_manager.create_task(
                    scan_id="scan-123",
                    scan_profile="normal",
                    target_info={"target": "example.com"},
                    metadata={"test": True}
                )
                
                assert task_id is not None
                
                # Start task
                await progress_manager.start_task(task_id)
                
                # Check task status
                progress_state = await progress_manager.get_progress(task_id)
                assert progress_state.status == TaskStatus.RUNNING
                assert progress_state.start_time is not None
                
                # Update progress
                await progress_manager.update_progress(
                    task_id=task_id,
                    phase=ScanPhase.DISCOVERY,
                    progress=25.0,
                    current_step="Discovering subdomains",
                    total_steps=10
                )
                
                # Verify progress update
                progress_state = await progress_manager.get_progress(task_id)
                discovery_progress = progress_state.get_phase_progress(ScanPhase.DISCOVERY)
                assert discovery_progress.progress_percentage == 25.0
                assert discovery_progress.current_step == "Discovering subdomains"
                
                # Complete phase
                await progress_manager.complete_phase(task_id, ScanPhase.DISCOVERY)
                
                progress_state = await progress_manager.get_progress(task_id)
                discovery_progress = progress_state.get_phase_progress(ScanPhase.DISCOVERY)
                assert discovery_progress.status == TaskStatus.COMPLETED
                
                # Create checkpoint
                checkpoint_id = await progress_manager.checkpoint(task_id, {"test_data": "value"})
                assert checkpoint_id is not None
                
                # Test pause/resume
                await progress_manager.pause_task(task_id)
                progress_state = await progress_manager.get_progress(task_id)
                assert progress_state.status == TaskStatus.PAUSED
                
                await progress_manager.resume_task(task_id)
                progress_state = await progress_manager.get_progress(task_id)
                assert progress_state.status == TaskStatus.RUNNING
                
                # Test task failure
                await progress_manager.fail_task(task_id, "Test failure", ScanPhase.RECONNAISSANCE)
                progress_state = await progress_manager.get_progress(task_id)
                assert progress_state.status == TaskStatus.FAILED
                
            finally:
                await progress_manager.shutdown()


@pytest.mark.asyncio
class TestTaskQueue:
    """Test task queue functionality."""
    
    async def test_task_queue_basic_operations(self):
        """Test basic task queue operations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_progress.db"
            storage = SqliteProgressStorage(str(db_path))
            progress_manager = ProgressManager(storage=storage)
            
            task_queue = TaskQueue(max_concurrent=2, progress_manager=progress_manager)
            
            try:
                await progress_manager.initialize()
                await task_queue.initialize()
                
                # Create scan configuration
                scan_config = ScanConfig(
                    scan_id="scan-123",
                    scan_profile="normal",
                    target_info={"target": "example.com"},
                    priority=TaskPriority.NORMAL,
                    max_retries=1
                )
                
                # Submit task
                task_id = await task_queue.submit_task(scan_config)
                assert task_id is not None
                
                # Check queue status
                queue_status = await task_queue.get_queue_status()
                assert queue_status.pending_count >= 1 or queue_status.running_count >= 1
                
                # Wait a moment for task to start processing
                await asyncio.sleep(3)
                
                # Check task info
                task_info = await task_queue.get_task_info(task_id)
                assert task_info is not None
                assert task_info["task_id"] == task_id
                
                # Get queue statistics
                stats = await task_queue.get_statistics()
                assert "queue_status" in stats
                assert "statistics" in stats
                assert stats["statistics"]["total_submitted"] >= 1
                
            finally:
                await task_queue.shutdown()
                await progress_manager.shutdown()


@pytest.mark.asyncio
class TestProgressEvents:
    """Test progress event system."""
    
    async def test_event_bus_basic_operations(self):
        """Test basic event bus operations."""
        event_bus = ProgressEventBus()
        
        received_events = []
        
        async def event_handler(event: ProgressEvent):
            received_events.append(event)
        
        # Subscribe to events
        await event_bus.subscribe("task_started", event_handler)
        
        # Emit event
        event = ProgressEvent(
            event_type=ProgressEventType.TASK_STARTED,
            task_id="test-task-1",
            data={"scan_id": "scan-123"}
        )
        
        await event_bus.emit(event)
        
        # Give event time to be processed
        await asyncio.sleep(0.1)
        
        # Verify event was received
        assert len(received_events) == 1
        assert received_events[0].task_id == "test-task-1"
        assert received_events[0].data["scan_id"] == "scan-123"
        
        # Test event history
        history = await event_bus.get_event_history(task_id="test-task-1")
        assert len(history) == 1
        assert history[0].task_id == "test-task-1"
        
        # Test connection stats
        stats = await event_bus.get_connection_stats()
        assert stats["event_history_size"] == 1
        assert stats["subscriber_count"] >= 1


@pytest.mark.asyncio
class TestProgressEstimator:
    """Test progress estimation functionality."""
    
    async def test_progress_estimator_basic_operations(self):
        """Test basic estimation operations."""
        estimator = ProgressEstimator()
        await estimator.initialize()
        
        try:
            # Test complexity metrics
            complexity_metrics = ComplexityMetrics(
                target_count=1,
                port_count=100,
                service_count=5,
                subdomain_count=10,
                technology_count=3,
                vulnerability_count=2
            )
            
            complexity_score = complexity_metrics.calculate_complexity_score()
            assert 0 <= complexity_score <= 10
            
            # Test phase estimation
            phase_estimate = await estimator.estimate_phase_duration(
                phase=ScanPhase.DISCOVERY,
                complexity_metrics=complexity_metrics,
                scan_profile="normal"
            )
            
            assert phase_estimate.phase == ScanPhase.DISCOVERY
            assert phase_estimate.estimated_duration.total_seconds() > 0
            assert 0 <= phase_estimate.confidence <= 1.0
            
            # Test total duration estimation
            total_estimate = await estimator.estimate_total_duration(
                complexity_metrics=complexity_metrics,
                scan_profile="normal"
            )
            
            assert "total_estimated_duration" in total_estimate
            assert "buffered_duration" in total_estimate
            assert "average_confidence" in total_estimate
            assert "phase_estimates" in total_estimate
            
            total_seconds = total_estimate["total_estimated_duration"]
            assert total_seconds > 0
            
        finally:
            # No cleanup needed for estimator
            pass


@pytest.mark.asyncio
class TestProgressMonitor:
    """Test progress monitoring functionality."""
    
    async def test_progress_monitor_basic_operations(self):
        """Test basic monitoring operations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_progress.db"
            storage = SqliteProgressStorage(str(db_path))
            progress_manager = ProgressManager(storage=storage)
            
            monitor = ProgressMonitor(progress_manager=progress_manager)
            
            try:
                await progress_manager.initialize()
                await monitor.initialize()
                
                # Create a test task
                task_id = await progress_manager.create_task(
                    scan_id="scan-123",
                    scan_profile="normal",
                    target_info={"target": "example.com"}
                )
                
                await progress_manager.start_task(task_id)
                
                # Test task health monitoring
                health_status = await monitor.monitor_task_health(task_id)
                assert health_status is not None
                assert health_status.task_id == task_id
                assert isinstance(health_status.is_healthy, bool)
                
                # Test resource monitoring
                resource_metrics = await monitor.monitor_resource_usage()
                assert resource_metrics.cpu_usage >= 0
                assert resource_metrics.memory_usage >= 0
                assert resource_metrics.disk_usage >= 0
                
                # Test system health
                health_data = await monitor.get_system_health()
                assert "overall_health" in health_data
                assert "components" in health_data
                assert "timestamp" in health_data
                
                # Test stuck task detection
                stuck_tasks = await monitor.detect_stuck_tasks()
                assert isinstance(stuck_tasks, list)
                # Should be empty since we just created the task
                
                # Test alerts (should be empty initially)
                alerts = await monitor.get_alerts()
                assert isinstance(alerts, list)
                
                # Test monitoring stats
                stats = await monitor.get_monitoring_stats()
                assert "uptime" in stats
                assert "check_count" in stats
                
            finally:
                await monitor.shutdown()
                await progress_manager.shutdown()


@pytest.mark.asyncio
class TestProgressManagerFactory:
    """Test progress manager factory."""
    
    async def test_factory_initialization(self):
        """Test factory initialization and component creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                "storage": {
                    "type": "sqlite",
                    "path": str(Path(temp_dir) / "test_progress.db")
                },
                "task_queue": {
                    "enabled": True,
                    "max_concurrent": 2
                },
                "progress_monitor": {
                    "enabled": True
                },
                "progress_estimator": {
                    "enabled": True
                },
                "websocket": {
                    "enabled": True
                }
            }
            
            factory = ProgressManagerFactory(config)
            
            try:
                await factory.initialize()
                assert factory.is_initialized()
                
                # Test component access
                progress_manager = factory.get_progress_manager()
                assert progress_manager is not None
                
                task_queue = factory.get_task_queue()
                assert task_queue is not None
                
                progress_monitor = factory.get_progress_monitor()
                assert progress_monitor is not None
                
                progress_estimator = factory.get_progress_estimator()
                assert progress_estimator is not None
                
                websocket_manager = factory.get_websocket_manager()
                assert websocket_manager is not None
                
                event_bus = factory.get_event_bus()
                assert event_bus is not None
                
                storage = factory.get_storage()
                assert storage is not None
                
            finally:
                await factory.shutdown()
                assert not factory.is_initialized()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])