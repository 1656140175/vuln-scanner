"""Basic unit tests for progress management models."""

import pytest
from datetime import datetime, timedelta

from vuln_scanner.progress.models import (
    TaskStatus, ProgressState, PhaseProgress, ProgressError, 
    CheckpointInfo, QueueStatus, ComplexityMetrics
)
from vuln_scanner.core.scanning.data_structures import ScanPhase


class TestTaskStatus:
    """Test TaskStatus enum."""
    
    def test_task_status_values(self):
        """Test TaskStatus enum values."""
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.RUNNING.value == "running"
        assert TaskStatus.PAUSED.value == "paused"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.CANCELLED.value == "cancelled"


class TestProgressError:
    """Test ProgressError model."""
    
    def test_progress_error_creation(self):
        """Test ProgressError creation."""
        error = ProgressError(
            phase=ScanPhase.DISCOVERY,
            error_type="connection_error",
            message="Failed to connect to target",
            recoverable=False
        )
        
        assert error.phase == ScanPhase.DISCOVERY
        assert error.error_type == "connection_error"
        assert error.message == "Failed to connect to target"
        assert error.recoverable is False
        assert error.error_id is not None
        assert error.timestamp is not None
    
    def test_progress_error_serialization(self):
        """Test ProgressError serialization."""
        error = ProgressError(
            phase=ScanPhase.DISCOVERY,
            error_type="test_error",
            message="Test message"
        )
        
        data = error.to_dict()
        assert data["phase"] == "discovery"
        assert data["error_type"] == "test_error"
        assert data["message"] == "Test message"
        assert "timestamp" in data
        assert "error_id" in data
        
        # Test deserialization
        restored_error = ProgressError.from_dict(data)
        assert restored_error.phase == error.phase
        assert restored_error.error_type == error.error_type
        assert restored_error.message == error.message


class TestPhaseProgress:
    """Test PhaseProgress model."""
    
    def test_phase_progress_creation(self):
        """Test PhaseProgress creation."""
        phase_progress = PhaseProgress(phase=ScanPhase.DISCOVERY)
        
        assert phase_progress.phase == ScanPhase.DISCOVERY
        assert phase_progress.status == TaskStatus.PENDING
        assert phase_progress.progress_percentage == 0.0
        assert phase_progress.current_step == ""
        assert phase_progress.total_steps == 0
        assert phase_progress.completed_steps == 0
        assert len(phase_progress.errors) == 0
    
    def test_phase_progress_update(self):
        """Test updating phase progress."""
        phase_progress = PhaseProgress(
            phase=ScanPhase.DISCOVERY,
            total_steps=10
        )
        
        # Update progress
        phase_progress.update_progress(5, "Discovering subdomains", {"tool": "subfinder"})
        
        assert phase_progress.completed_steps == 5
        assert phase_progress.current_step == "Discovering subdomains"
        assert phase_progress.progress_percentage == 50.0
        assert phase_progress.status == TaskStatus.RUNNING
        assert phase_progress.metadata["tool"] == "subfinder"
        
        # Complete progress
        phase_progress.update_progress(10, "Discovery completed")
        assert phase_progress.status == TaskStatus.COMPLETED
        assert phase_progress.progress_percentage == 100.0
    
    def test_phase_progress_error_handling(self):
        """Test adding errors to phase progress."""
        phase_progress = PhaseProgress(phase=ScanPhase.DISCOVERY)
        
        error = ProgressError(
            error_type="connection_error",
            message="Connection failed",
            recoverable=False
        )
        
        phase_progress.add_error(error)
        
        assert len(phase_progress.errors) == 1
        assert phase_progress.status == TaskStatus.FAILED  # Non-recoverable error
    
    def test_phase_progress_time_estimation(self):
        """Test time estimation for phase progress."""
        phase_progress = PhaseProgress(
            phase=ScanPhase.DISCOVERY,
            total_steps=10
        )
        
        # No estimation possible without start time or progress
        estimated = phase_progress.calculate_estimated_completion()
        assert estimated is None
        
        # Set start time and make some progress
        phase_progress.start_time = datetime.now() - timedelta(minutes=5)
        phase_progress.update_progress(5)
        
        # Should now have an estimation
        estimated = phase_progress.calculate_estimated_completion()
        assert estimated is not None
        assert estimated > datetime.now()
    
    def test_phase_progress_serialization(self):
        """Test PhaseProgress serialization."""
        phase_progress = PhaseProgress(
            phase=ScanPhase.DISCOVERY,
            total_steps=10
        )
        phase_progress.update_progress(3, "Testing")
        
        data = phase_progress.to_dict()
        assert data["phase"] == "discovery"
        assert data["completed_steps"] == 3
        assert data["total_steps"] == 10
        assert data["current_step"] == "Testing"
        assert data["progress_percentage"] == 30.0
        
        # Test deserialization
        restored = PhaseProgress.from_dict(data)
        assert restored.phase == phase_progress.phase
        assert restored.completed_steps == phase_progress.completed_steps
        assert restored.current_step == phase_progress.current_step


class TestProgressState:
    """Test ProgressState model."""
    
    def test_progress_state_creation(self):
        """Test ProgressState creation."""
        progress_state = ProgressState(
            task_id="test-task-1",
            scan_id="scan-123",
            scan_profile="normal",
            target_info={"target": "example.com", "type": "domain"}
        )
        
        assert progress_state.task_id == "test-task-1"
        assert progress_state.scan_id == "scan-123"
        assert progress_state.scan_profile == "normal"
        assert progress_state.target_info["target"] == "example.com"
        assert progress_state.status == TaskStatus.PENDING
        assert progress_state.overall_progress == 0.0
        assert progress_state.current_phase is None
        
        # Check that all phases are initialized
        assert len(progress_state.phase_progress) == len(ScanPhase)
        for phase in ScanPhase:
            assert phase in progress_state.phase_progress
    
    def test_progress_state_phase_management(self):
        """Test phase progress management."""
        progress_state = ProgressState(
            task_id="test-task-1",
            scan_id="scan-123",
            scan_profile="normal",
            target_info={"target": "example.com"}
        )
        
        # Update discovery phase
        progress_state.update_phase_progress(
            ScanPhase.DISCOVERY, 5, 10, "Discovering targets"
        )
        
        assert progress_state.current_phase == ScanPhase.DISCOVERY
        assert progress_state.overall_progress > 0
        
        discovery_progress = progress_state.get_phase_progress(ScanPhase.DISCOVERY)
        assert discovery_progress.completed_steps == 5
        assert discovery_progress.total_steps == 10
        assert discovery_progress.progress_percentage == 50.0
        assert discovery_progress.status == TaskStatus.RUNNING
        
        # Complete discovery phase
        progress_state.set_phase_status(ScanPhase.DISCOVERY, TaskStatus.COMPLETED)
        
        discovery_progress = progress_state.get_phase_progress(ScanPhase.DISCOVERY)
        assert discovery_progress.status == TaskStatus.COMPLETED
        
        # Check phase queries
        completed_phases = progress_state.get_completed_phases()
        assert ScanPhase.DISCOVERY in completed_phases
        
        active_phases = progress_state.get_active_phases()
        assert ScanPhase.DISCOVERY not in active_phases
    
    def test_progress_state_error_management(self):
        """Test error management."""
        progress_state = ProgressState(
            task_id="test-task-1",
            scan_id="scan-123",
            scan_profile="normal",
            target_info={"target": "example.com"}
        )
        
        error1 = ProgressError(
            phase=ScanPhase.DISCOVERY,
            error_type="connection_error",
            message="Connection failed"
        )
        
        error2 = ProgressError(
            phase=ScanPhase.RECONNAISSANCE,
            error_type="timeout_error",
            message="Request timed out"
        )
        
        progress_state.add_phase_error(ScanPhase.DISCOVERY, error1)
        progress_state.add_phase_error(ScanPhase.RECONNAISSANCE, error2)
        
        all_errors = progress_state.get_all_errors()
        assert len(all_errors) == 2
        
        failed_phases = progress_state.get_failed_phases()
        assert len(failed_phases) >= 1  # At least one phase should be failed
    
    def test_progress_state_serialization(self):
        """Test ProgressState serialization."""
        progress_state = ProgressState(
            task_id="test-task-1",
            scan_id="scan-123",
            scan_profile="normal",
            target_info={"target": "example.com", "type": "domain"}
        )
        
        progress_state.update_phase_progress(ScanPhase.DISCOVERY, 3, 10, "Testing")
        
        data = progress_state.to_dict()
        assert data["task_id"] == "test-task-1"
        assert data["scan_id"] == "scan-123"
        assert data["scan_profile"] == "normal"
        assert "phase_progress" in data
        assert "overall_progress" in data
        
        # Test deserialization
        restored = ProgressState.from_dict(data)
        assert restored.task_id == progress_state.task_id
        assert restored.scan_id == progress_state.scan_id
        assert restored.overall_progress == progress_state.overall_progress
        
        # Check phase progress is restored
        restored_discovery = restored.get_phase_progress(ScanPhase.DISCOVERY)
        original_discovery = progress_state.get_phase_progress(ScanPhase.DISCOVERY)
        assert restored_discovery.completed_steps == original_discovery.completed_steps


class TestQueueStatus:
    """Test QueueStatus model."""
    
    def test_queue_status_creation(self):
        """Test QueueStatus creation."""
        queue_status = QueueStatus(
            running_count=3,
            pending_count=5,
            completed_count=10,
            failed_count=2,
            total_slots=5,
            available_slots=2,
            queue_health="healthy"
        )
        
        assert queue_status.running_count == 3
        assert queue_status.pending_count == 5
        assert queue_status.completed_count == 10
        assert queue_status.failed_count == 2
        assert queue_status.total_slots == 5
        assert queue_status.available_slots == 2
        assert queue_status.queue_health == "healthy"
    
    def test_queue_status_utilization(self):
        """Test utilization calculation."""
        queue_status = QueueStatus(
            running_count=4,
            total_slots=5
        )
        
        assert queue_status.utilization_percentage == 80.0
        
        # Test with zero slots
        queue_status_empty = QueueStatus(total_slots=0)
        assert queue_status_empty.utilization_percentage == 0.0
    
    def test_queue_status_serialization(self):
        """Test QueueStatus serialization."""
        queue_status = QueueStatus(
            running_count=2,
            pending_count=3,
            total_slots=5
        )
        
        data = queue_status.to_dict()
        assert data["running_count"] == 2
        assert data["pending_count"] == 3
        assert data["total_slots"] == 5
        assert "utilization_percentage" in data


class TestCheckpointInfo:
    """Test CheckpointInfo model."""
    
    def test_checkpoint_info_creation(self):
        """Test CheckpointInfo creation."""
        checkpoint = CheckpointInfo(
            task_id="test-task-1",
            phase=ScanPhase.DISCOVERY,
            phase_data={"discovered_targets": ["example.com"]},
            metadata={"checkpoint_type": "manual"}
        )
        
        assert checkpoint.task_id == "test-task-1"
        assert checkpoint.phase == ScanPhase.DISCOVERY
        assert checkpoint.phase_data["discovered_targets"] == ["example.com"]
        assert checkpoint.metadata["checkpoint_type"] == "manual"
        assert checkpoint.checkpoint_id is not None
        assert checkpoint.timestamp is not None
    
    def test_checkpoint_info_serialization(self):
        """Test CheckpointInfo serialization."""
        checkpoint = CheckpointInfo(
            task_id="test-task-1",
            phase=ScanPhase.DISCOVERY,
            phase_data={"test": "data"}
        )
        
        data = checkpoint.to_dict()
        assert data["task_id"] == "test-task-1"
        assert data["phase"] == "discovery"
        assert data["phase_data"]["test"] == "data"
        assert "checkpoint_id" in data
        assert "timestamp" in data
        
        # Test deserialization
        restored = CheckpointInfo.from_dict(data)
        assert restored.task_id == checkpoint.task_id
        assert restored.phase == checkpoint.phase
        assert restored.phase_data == checkpoint.phase_data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])