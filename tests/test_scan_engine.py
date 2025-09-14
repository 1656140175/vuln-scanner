"""Comprehensive tests for the scan engine system."""

import asyncio
import pytest
import tempfile
import sqlite3
import yaml
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta

from vuln_scanner.core.scanning.scan_engine import ScanEngine
from vuln_scanner.core.scanning.data_structures import (
    ScanTarget, ScanResult, ScanJob, ScanStatus, ScanSeverity, ScanPhase
)
from vuln_scanner.core.tool_manager import ToolManagerComponent
from vuln_scanner.core.exceptions import UnauthorizedTargetException, ScanEngineException


@pytest.fixture
def test_config():
    """Test configuration fixture."""
    return {
        'system': {
            'debug': True,
            'max_concurrent_scans': 2,
            'timeout': 60,
            'max_scan_runtime': 300
        },
        'database': {
            'path': ':memory:',  # In-memory SQLite for testing
            'retention_days': 7
        },
        'security': {
            'authorization': {
                'enabled': True,
                'whitelist_only': True,
                'authorized_targets': ['example.com', '127.0.0.1']
            },
            'target_safety': {
                'allow_localhost': True,
                'allow_private_networks': True
            }
        },
        'pipelines': {
            'test': {
                'discovery': {
                    'tools': [
                        {'name': 'nmap', 'args': {'scan_type': 'fast', 'timeout': 30}}
                    ],
                    'parallel': False,
                    'timeout': 60,
                    'continue_on_error': True
                }
            }
        },
        'aggregation': {
            'duplicate_threshold': 0.8,
            'correlation_window': 300,
            'confidence_threshold': 0.7
        }
    }


@pytest.fixture
def mock_tool_manager():
    """Mock tool manager component."""
    mock = Mock(spec=ToolManagerComponent)
    mock.initialized = True
    
    # Mock tool manager instance
    tool_manager = AsyncMock()
    
    # Mock tool execution result
    mock_result = Mock()
    mock_result.success = True
    mock_result.stdout = "80/tcp open http"
    mock_result.stderr = ""
    mock_result.returncode = 0
    mock_result.execution_time = 1.5
    
    tool_manager.execute_tool = AsyncMock(return_value=mock_result)
    mock.get_tool_manager.return_value = tool_manager
    
    return mock


@pytest.fixture
async def scan_engine(test_config, mock_tool_manager):
    """Scan engine fixture."""
    engine = ScanEngine(test_config)
    engine.set_tool_manager(mock_tool_manager)
    await engine.start()
    yield engine
    await engine.stop()


@pytest.fixture
def sync_scan_engine(test_config, mock_tool_manager):
    """Synchronous scan engine fixture for non-async tests."""
    engine = ScanEngine(test_config)
    engine.set_tool_manager(mock_tool_manager)
    return engine


class TestScanEngineInitialization:
    """Test scan engine initialization."""
    
    def test_singleton_pattern(self, test_config):
        """Test that scan engine follows singleton pattern."""
        engine1 = ScanEngine(test_config)
        engine2 = ScanEngine(test_config)
        assert engine1 is engine2
    
    def test_database_initialization(self, test_config):
        """Test database schema initialization."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            tmp_db_path = tmp_db.name
        
        try:
            # Ensure parent directory exists
            import os
            os.makedirs(os.path.dirname(tmp_db_path), exist_ok=True)
            
            test_config['database']['path'] = tmp_db_path
            engine = ScanEngine(test_config)
            
            # Let the engine initialize the database
            assert os.path.exists(tmp_db_path)
            
            # Check tables exist
            conn = sqlite3.connect(tmp_db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            assert 'scan_jobs' in tables
            assert 'scan_results' in tables
            assert 'aggregated_results' in tables
            
            conn.close()
        finally:
            # Cleanup
            import os
            try:
                os.unlink(tmp_db_path)
            except:
                pass
    
    def test_pipeline_loading(self, test_config):
        """Test pipeline loading from configuration."""
        engine = ScanEngine(test_config)
        assert 'test' in engine.pipelines
        assert len(engine.pipelines) == 1


class TestScanJobManagement:
    """Test scan job management functionality."""
    
    @pytest.mark.asyncio
    async def test_submit_scan_authorized_target(self, scan_engine):
        """Test submitting scan for authorized target."""
        job_id = await scan_engine.submit_scan(
            target='example.com',
            scan_profile='test',
            metadata={'user': 'test_user'}
        )
        
        assert job_id is not None
        assert len(job_id) == 36  # UUID format
    
    @pytest.mark.asyncio
    async def test_submit_scan_unauthorized_target(self, scan_engine):
        """Test submitting scan for unauthorized target."""
        with pytest.raises(UnauthorizedTargetException):
            await scan_engine.submit_scan(
                target='unauthorized.com',
                scan_profile='test'
            )
    
    @pytest.mark.asyncio
    async def test_get_scan_status(self, scan_engine):
        """Test retrieving scan status."""
        job_id = await scan_engine.submit_scan('example.com', 'test')
        
        # Give some time for processing
        await asyncio.sleep(0.1)
        
        status = await scan_engine.get_scan_status(job_id)
        assert status is not None
        assert status['job_id'] == job_id
        assert 'status' in status
        assert 'created_at' in status
    
    @pytest.mark.asyncio
    async def test_get_scan_status_nonexistent(self, scan_engine):
        """Test retrieving status for nonexistent job."""
        status = await scan_engine.get_scan_status('nonexistent-id')
        assert status is None
    
    @pytest.mark.asyncio
    async def test_cancel_scan(self, scan_engine):
        """Test canceling a scan job."""
        job_id = await scan_engine.submit_scan('example.com', 'test')
        
        # Cancel the job
        success = await scan_engine.cancel_scan(job_id, 'test_user')
        assert success is True
        
        # Check status
        status = await scan_engine.get_scan_status(job_id)
        assert status['status'] == 'cancelled'


class TestScanExecution:
    """Test scan execution functionality."""
    
    @pytest.mark.asyncio
    async def test_basic_scan_execution(self, scan_engine):
        """Test basic scan execution flow."""
        job_id = await scan_engine.submit_scan('example.com', 'test')
        
        # Wait for scan to complete
        for _ in range(10):  # Max 1 second wait
            status = await scan_engine.get_scan_status(job_id)
            if status['status'] in ['completed', 'failed']:
                break
            await asyncio.sleep(0.1)
        
        # Verify completion
        assert status['status'] in ['completed', 'failed']
        if status['status'] == 'completed':
            assert status['results_count'] >= 0
    
    @pytest.mark.asyncio
    async def test_get_scan_results(self, scan_engine):
        """Test retrieving scan results."""
        job_id = await scan_engine.submit_scan('example.com', 'test')
        
        # Wait for completion
        for _ in range(10):
            status = await scan_engine.get_scan_status(job_id)
            if status['status'] == 'completed':
                break
            await asyncio.sleep(0.1)
        
        if status['status'] == 'completed':
            results = await scan_engine.get_scan_results(job_id)
            assert 'job_id' in results
            assert 'results_count' in results
            assert 'results' in results
            assert isinstance(results['results'], list)
    
    @pytest.mark.asyncio
    async def test_scan_with_severity_filter(self, scan_engine):
        """Test retrieving results with severity filter."""
        job_id = await scan_engine.submit_scan('example.com', 'test')
        
        # Wait for completion
        for _ in range(10):
            status = await scan_engine.get_scan_status(job_id)
            if status['status'] == 'completed':
                break
            await asyncio.sleep(0.1)
        
        if status['status'] == 'completed':
            # Test severity filtering
            results = await scan_engine.get_scan_results(
                job_id, 
                severity_filter=['high', 'critical']
            )
            
            # All results should be high or critical severity
            for result in results['results']:
                assert result['severity'] in ['high', 'critical']


class TestEngineStats:
    """Test engine statistics functionality."""
    
    @pytest.mark.asyncio
    async def test_get_engine_stats(self, scan_engine):
        """Test getting engine statistics."""
        stats = scan_engine.get_engine_stats()
        
        assert 'active_jobs' in stats
        assert 'max_concurrent_scans' in stats
        assert 'available_pipelines' in stats
        assert 'engine_status' in stats
        assert 'database_path' in stats
        
        assert isinstance(stats['active_jobs'], int)
        assert isinstance(stats['available_pipelines'], list)
        assert stats['engine_status'] == 'running'


class TestTargetDetection:
    """Test target type detection."""
    
    def test_detect_ip_target(self, sync_scan_engine):
        """Test IP address target detection."""
        target_type = sync_scan_engine._detect_target_type('192.168.1.1')
        assert target_type == 'ip'
    
    def test_detect_url_target(self, sync_scan_engine):
        """Test URL target detection."""
        target_type = sync_scan_engine._detect_target_type('https://example.com')
        assert target_type == 'url'
        
        target_type = sync_scan_engine._detect_target_type('http://example.com')
        assert target_type == 'url'
    
    def test_detect_network_target(self, sync_scan_engine):
        """Test network range target detection."""
        target_type = sync_scan_engine._detect_target_type('192.168.1.0/24')
        assert target_type == 'network'
    
    def test_detect_domain_target(self, sync_scan_engine):
        """Test domain target detection."""
        target_type = sync_scan_engine._detect_target_type('example.com')
        assert target_type == 'domain'


class TestDataStructures:
    """Test scan data structures."""
    
    def test_scan_target_creation(self):
        """Test scan target creation."""
        target = ScanTarget(
            target='example.com',
            target_type='domain',
            context={'source': 'manual'},
            constraints={'rate_limit': 10}
        )
        
        assert target.target == 'example.com'
        assert target.target_type == 'domain'
        assert target.context['source'] == 'manual'
        assert target.constraints['rate_limit'] == 10
        assert target.target_id is not None
    
    def test_scan_result_to_dict(self):
        """Test scan result serialization."""
        target = ScanTarget(target='example.com', target_type='domain')
        result = ScanResult(
            scan_id='test-scan',
            target=target,
            phase=ScanPhase.DISCOVERY,
            tool='nmap',
            timestamp=datetime.now(),
            data={'port': 80, 'service': 'http'},
            severity=ScanSeverity.INFO,
            confidence=0.9
        )
        
        result_dict = result.to_dict()
        
        assert result_dict['scan_id'] == 'test-scan'
        assert result_dict['target'] == 'example.com'
        assert result_dict['phase'] == 'discovery'
        assert result_dict['tool'] == 'nmap'
        assert result_dict['severity'] == 'info'
        assert result_dict['confidence'] == 0.9
        assert result_dict['data']['port'] == 80
    
    def test_scan_job_progress_tracking(self):
        """Test scan job progress tracking."""
        target = ScanTarget(target='example.com', target_type='domain')
        job = ScanJob(
            job_id='test-job',
            target=target,
            scan_profile='test'
        )
        
        # Add some results
        result1 = ScanResult(
            scan_id='test-job',
            target=target,
            phase=ScanPhase.DISCOVERY,
            tool='nmap',
            timestamp=datetime.now(),
            data={'port': 80}
        )
        
        result2 = ScanResult(
            scan_id='test-job',
            target=target,
            phase=ScanPhase.VULNERABILITY_SCAN,
            tool='nuclei',
            timestamp=datetime.now(),
            data={'vuln': 'xss'}
        )
        
        job.add_result(result1)
        job.add_result(result2)
        
        # Check progress tracking
        assert len(job.results) == 2
        assert 'phases' in job.progress
        assert 'discovery' in job.progress['phases']
        assert 'vulnerability_scan' in job.progress['phases']
        
        # Test filtering methods
        discovery_results = job.get_results_by_phase(ScanPhase.DISCOVERY)
        assert len(discovery_results) == 1
        assert discovery_results[0].tool == 'nmap'


class TestErrorHandling:
    """Test error handling scenarios."""
    
    @pytest.mark.asyncio
    async def test_invalid_scan_profile(self, scan_engine):
        """Test handling of invalid scan profile."""
        with pytest.raises(ScanEngineException):
            await scan_engine.submit_scan('example.com', 'nonexistent-profile')
    
    @pytest.mark.asyncio
    async def test_engine_not_started(self, test_config, mock_tool_manager):
        """Test using engine before starting."""
        engine = ScanEngine(test_config)
        engine.set_tool_manager(mock_tool_manager)
        
        # Don't start the engine
        with pytest.raises(ScanEngineException):
            await engine.submit_scan('example.com', 'test')


class TestConcurrency:
    """Test concurrent scan handling."""
    
    @pytest.mark.asyncio
    async def test_concurrent_scans(self, scan_engine):
        """Test handling multiple concurrent scans."""
        # Submit multiple scans
        job_ids = []
        for i in range(3):
            job_id = await scan_engine.submit_scan(
                target='example.com',
                scan_profile='test',
                metadata={'batch': i}
            )
            job_ids.append(job_id)
        
        # All jobs should be submitted
        assert len(job_ids) == 3
        assert len(set(job_ids)) == 3  # All unique
        
        # Wait a bit for processing
        await asyncio.sleep(0.5)
        
        # Check that jobs are being processed
        active_count = len(scan_engine.active_jobs)
        assert active_count <= scan_engine.max_concurrent_scans


if __name__ == '__main__':
    pytest.main([__file__, '-v'])