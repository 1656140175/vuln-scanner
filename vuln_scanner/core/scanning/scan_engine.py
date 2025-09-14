"""Main scan engine orchestrating vulnerability scans."""

import asyncio
import sqlite3
import json
import uuid
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, AsyncGenerator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

from .data_structures import (
    ScanPhase, ScanStatus, ScanSeverity, ScanTarget, ScanResult, ScanJob
)
from .pipeline import ScanPipeline
from .result_aggregator import ResultAggregator
from ..exceptions import ScanEngineException, UnauthorizedTargetException
from ..security.security_controller import SecurityController


class ScanEngineError(ScanEngineException):
    """Scan engine specific errors."""
    pass


class ScanEngine:
    """Main scan engine orchestrating vulnerability scans."""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, config: Dict[str, Any]):
        """Singleton pattern implementation."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize scan engine.
        
        Args:
            config: System configuration
        """
        # Prevent re-initialization
        if hasattr(self, 'initialized'):
            return
        
        self.config = config
        self.logger = logging.getLogger('scan_engine')
        
        # Database configuration
        self.db_path = config.get('database', {}).get('path', 'data/scans.db')
        self._db_lock = threading.RLock()
        
        # Engine configuration
        self.max_concurrent_scans = config.get('system', {}).get('max_concurrent_scans', 5)
        
        # Core components
        self.security_controller = SecurityController(config)
        self.result_aggregator = ResultAggregator(config)
        
        # Pipeline management
        self.pipelines: Dict[str, ScanPipeline] = {}
        
        # Job management
        self.active_jobs: Dict[str, ScanJob] = {}
        self.job_queue: asyncio.Queue = None  # Will be initialized in start()
        self.executor = ThreadPoolExecutor(max_workers=self.max_concurrent_scans)
        
        # Background tasks
        self._background_tasks: List[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()
        self.scheduler_task: Optional[asyncio.Task] = None
        
        # Component dependencies (will be injected)
        self.tool_manager_component = None
        
        # Initialize
        self._init_database()
        self._load_pipelines()
        
        self.initialized = True
        self.logger.info("Scan engine initialized successfully")
    
    def set_tool_manager(self, tool_manager_component) -> None:
        """Set tool manager component dependency.
        
        Args:
            tool_manager_component: ToolManagerComponent instance
        """
        self.tool_manager_component = tool_manager_component
        self.logger.info("Tool manager component injected")
    
    def _init_database(self) -> None:
        """Initialize scan database schema."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with self._db_lock:
            conn = sqlite3.connect(self.db_path)
            try:
                # Create scan jobs table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS scan_jobs (
                        job_id TEXT PRIMARY KEY,
                        target TEXT NOT NULL,
                        target_type TEXT NOT NULL,
                        target_id TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        started_at TEXT,
                        completed_at TEXT,
                        metadata TEXT,
                        progress TEXT,
                        error_message TEXT
                    )
                ''')
                
                # Create scan results table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        target TEXT NOT NULL,
                        target_id TEXT NOT NULL,
                        phase TEXT NOT NULL,
                        tool TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        data TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        false_positive_likelihood REAL NOT NULL,
                        FOREIGN KEY (scan_id) REFERENCES scan_jobs (job_id)
                    )
                ''')
                
                # Create aggregated results table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS aggregated_results (
                        job_id TEXT PRIMARY KEY,
                        aggregation_data TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (job_id) REFERENCES scan_jobs (job_id)
                    )
                ''')
                
                # Create indexes for performance
                conn.execute('CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_scan_results_target ON scan_results(target)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_scan_results_severity ON scan_results(severity)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_scan_results_timestamp ON scan_results(timestamp)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at)')
                
                conn.commit()
                self.logger.info("Database schema initialized")
                
            finally:
                conn.close()
    
    def _load_pipelines(self) -> None:
        """Load scan pipelines from configuration."""
        pipeline_configs = self.config.get('pipelines', {})
        
        for pipeline_name in pipeline_configs:
            try:
                pipeline = ScanPipeline(pipeline_name, self.config)
                self.pipelines[pipeline_name] = pipeline
                self.logger.info(f"Loaded pipeline: {pipeline_name}")
            except Exception as e:
                self.logger.error(f"Failed to load pipeline {pipeline_name}: {e}")
        
        if not self.pipelines:
            # Create default pipeline if none configured
            self._create_default_pipeline()
        
        self.logger.info(f"Loaded {len(self.pipelines)} scan pipelines")
    
    def _create_default_pipeline(self) -> None:
        """Create a default scan pipeline."""
        default_config = {
            'pipelines': {
                'default': {
                    'discovery': {
                        'tools': [
                            {
                                'name': 'nmap',
                                'args': {'scan_type': 'fast', 'timeout': 60}
                            }
                        ],
                        'parallel': False,
                        'timeout': 120
                    },
                    'vulnerability_scan': {
                        'tools': [
                            {
                                'name': 'nuclei',
                                'args': {'severity': 'medium,high,critical', 'timeout': 300}
                            }
                        ],
                        'parallel': False,
                        'timeout': 400
                    }
                }
            }
        }
        
        # Merge with existing config
        if 'pipelines' not in self.config:
            self.config['pipelines'] = {}
        self.config['pipelines'].update(default_config['pipelines'])
        
        # Create pipeline
        self.pipelines['default'] = ScanPipeline('default', self.config)
        self.logger.info("Created default scan pipeline")
    
    async def start(self) -> None:
        """Start scan engine and background services."""
        if self.scheduler_task:
            self.logger.warning("Scan engine already started")
            return
        
        # Initialize async components
        self.job_queue = asyncio.Queue()
        
        # Start job scheduler
        self.scheduler_task = asyncio.create_task(self._job_scheduler())
        self._background_tasks.append(self.scheduler_task)
        
        # Start cleanup task
        cleanup_task = asyncio.create_task(self._cleanup_loop())
        self._background_tasks.append(cleanup_task)
        
        # Start health monitoring task
        health_task = asyncio.create_task(self._health_monitor_loop())
        self._background_tasks.append(health_task)
        
        self.logger.info("Scan engine started successfully")
    
    async def stop(self) -> None:
        """Stop scan engine and cleanup resources."""
        self.logger.info("Stopping scan engine")
        
        # Signal shutdown
        self._shutdown_event.set()
        
        # Cancel all active jobs
        for job in self.active_jobs.values():
            if job.status == ScanStatus.RUNNING:
                job.status = ScanStatus.CANCELLED
                self._update_job(job)
        
        # Wait for background tasks
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        # Clear state
        self.active_jobs.clear()
        self._background_tasks.clear()
        self.scheduler_task = None
        
        self.logger.info("Scan engine stopped")
    
    async def submit_scan(self, target: str, scan_profile: str = "default",
                         metadata: Optional[Dict[str, Any]] = None,
                         user: Optional[str] = None) -> str:
        """Submit a new scan job.
        
        Args:
            target: Target to scan
            scan_profile: Scan profile to use
            metadata: Additional metadata for the scan
            user: User submitting the scan
            
        Returns:
            Scan job ID
            
        Raises:
            UnauthorizedTargetException: If target is not authorized
            ScanEngineError: If scan submission fails
        """
        self.logger.info(f"Submitting scan for target: {target}, profile: {scan_profile}")
        
        # Validate scan request through security controller
        allowed, validation_info = self.security_controller.validate_scan_request(
            target, scan_profile, user
        )
        
        if not allowed:
            error_msg = f"Scan request rejected: {validation_info.get('validations', {})}"
            self.logger.error(error_msg)
            raise UnauthorizedTargetException(error_msg)
        
        # Validate scan profile exists
        if scan_profile not in self.pipelines:
            raise ScanEngineError(f"Unknown scan profile: {scan_profile}")
        
        # Create scan target
        scan_target = ScanTarget(
            target=target,
            target_type=self._detect_target_type(target),
            context=metadata or {},
            constraints=validation_info
        )
        
        # Create scan job
        job = ScanJob(
            job_id=str(uuid.uuid4()),
            target=scan_target,
            scan_profile=scan_profile,
            metadata={
                'user': user,
                'validation_info': validation_info,
                'tool_manager_component': self.tool_manager_component,
                **(metadata or {})
            }
        )
        
        # Save job to database
        self._save_job(job)
        
        # Add to queue
        if self.job_queue:
            await self.job_queue.put(job)
        else:
            raise ScanEngineError("Scan engine not started")
        
        self.logger.info(f"Scan job {job.job_id} submitted successfully")
        return job.job_id
    
    async def get_scan_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get scan job status.
        
        Args:
            job_id: Scan job ID
            
        Returns:
            Job status information or None if not found
        """
        # Check active jobs first
        job = self.active_jobs.get(job_id)
        if not job:
            # Load from database
            job = self._load_job(job_id)
        
        if not job:
            return None
        
        status_info = job.to_dict()
        
        # Add real-time progress for running jobs
        if job.status == ScanStatus.RUNNING and job_id in self.active_jobs:
            status_info['real_time_progress'] = self._calculate_real_time_progress(job)
        
        return status_info
    
    async def get_scan_results(self, job_id: str, 
                              severity_filter: Optional[List[str]] = None,
                              aggregated: bool = False) -> Dict[str, Any]:
        """Get scan results.
        
        Args:
            job_id: Scan job ID
            severity_filter: Optional severity filter
            aggregated: Whether to return aggregated results
            
        Returns:
            Scan results dictionary
        """
        if aggregated:
            return self._get_aggregated_results(job_id)
        
        results = self._load_results(job_id, severity_filter)
        
        return {
            'job_id': job_id,
            'results_count': len(results),
            'results': [result.to_dict() for result in results],
            'retrieved_at': datetime.now().isoformat()
        }
    
    async def cancel_scan(self, job_id: str, user: Optional[str] = None) -> bool:
        """Cancel a running scan.
        
        Args:
            job_id: Scan job ID to cancel
            user: User requesting cancellation
            
        Returns:
            True if cancellation was successful
        """
        self.logger.info(f"Cancelling scan job: {job_id}")
        
        # Check if job is active
        job = self.active_jobs.get(job_id)
        if not job:
            # Try to load from database
            job = self._load_job(job_id)
            if not job:
                return False
        
        # Can only cancel pending or running jobs
        if job.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
            self.logger.warning(f"Cannot cancel job {job_id} in status {job.status}")
            return False
        
        # Update job status
        job.status = ScanStatus.CANCELLED
        job.error_message = f"Cancelled by {user or 'system'}"
        job.completed_at = datetime.now()
        
        self._update_job(job)
        
        self.logger.info(f"Scan job {job_id} cancelled successfully")
        return True
    
    async def _job_scheduler(self) -> None:
        """Main job scheduler loop."""
        self.logger.info("Job scheduler started")
        
        while not self._shutdown_event.is_set():
            try:
                # Check if we can start new jobs
                if len(self.active_jobs) >= self.max_concurrent_scans:
                    await asyncio.sleep(1)
                    continue
                
                # Get next job from queue
                try:
                    job = await asyncio.wait_for(self.job_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                
                # Start job execution
                self.logger.info(f"Starting scan job: {job.job_id}")
                task = asyncio.create_task(self._execute_scan(job))
                self.active_jobs[job.job_id] = job
                
                # Handle task completion
                def cleanup_job(task_ref):
                    if job.job_id in self.active_jobs:
                        del self.active_jobs[job.job_id]
                
                task.add_done_callback(cleanup_job)
                
            except Exception as e:
                self.logger.error(f"Error in job scheduler: {e}")
                await asyncio.sleep(5)  # Back off on errors
        
        self.logger.info("Job scheduler stopped")
    
    async def _execute_scan(self, job: ScanJob) -> None:
        """Execute a scan job.
        
        Args:
            job: Scan job to execute
        """
        self.logger.info(f"Executing scan job {job.job_id} for target: {job.target.target}")
        
        try:
            # Update job status
            job.status = ScanStatus.RUNNING
            job.started_at = datetime.now()
            self._update_job(job)
            
            # Get pipeline
            pipeline = self.pipelines.get(job.scan_profile)
            if not pipeline:
                raise ScanEngineError(f"Pipeline not found: {job.scan_profile}")
            
            # Execute pipeline
            async for result in pipeline.execute(job.target, job):
                # Save result immediately
                job.add_result(result)
                self._save_result(result)
                
                # Check for cancellation
                if job.status == ScanStatus.CANCELLED:
                    self.logger.info(f"Scan job {job.job_id} was cancelled")
                    break
            
            # Mark as completed if not cancelled
            if job.status != ScanStatus.CANCELLED:
                job.status = ScanStatus.COMPLETED
                job.completed_at = datetime.now()
                
                # Generate aggregated results
                await self._generate_aggregated_results(job)
            
        except Exception as e:
            self.logger.error(f"Scan job {job.job_id} failed: {e}")
            job.status = ScanStatus.FAILED
            job.error_message = str(e)
            job.completed_at = datetime.now()
        
        finally:
            self._update_job(job)
            self.logger.info(f"Scan job {job.job_id} finished with status: {job.status}")
    
    async def _generate_aggregated_results(self, job: ScanJob) -> None:
        """Generate and save aggregated results for a completed job.
        
        Args:
            job: Completed scan job
        """
        try:
            self.logger.info(f"Generating aggregated results for job {job.job_id}")
            
            aggregation = self.result_aggregator.aggregate_job_results(job)
            
            # Save to database
            with self._db_lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    conn.execute('''
                        INSERT OR REPLACE INTO aggregated_results 
                        (job_id, aggregation_data, created_at)
                        VALUES (?, ?, ?)
                    ''', (
                        job.job_id,
                        json.dumps(aggregation),
                        datetime.now().isoformat()
                    ))
                    conn.commit()
                finally:
                    conn.close()
            
            self.logger.info(f"Aggregated results saved for job {job.job_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to generate aggregated results for job {job.job_id}: {e}")
    
    async def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                if self._shutdown_event.is_set():
                    break
                
                await self._cleanup_old_data()
                
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(300)  # Back off on errors
    
    async def _cleanup_old_data(self) -> None:
        """Cleanup old scan data based on retention policy."""
        retention_days = self.config.get('database', {}).get('retention_days', 90)
        cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()
        
        try:
            with self._db_lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    # Clean up old results
                    cursor = conn.execute(
                        'DELETE FROM scan_results WHERE timestamp < ?',
                        (cutoff_date,)
                    )
                    results_deleted = cursor.rowcount
                    
                    # Clean up old aggregated results
                    cursor = conn.execute(
                        'DELETE FROM aggregated_results WHERE created_at < ?',
                        (cutoff_date,)
                    )
                    agg_deleted = cursor.rowcount
                    
                    # Clean up old jobs
                    cursor = conn.execute(
                        'DELETE FROM scan_jobs WHERE created_at < ?',
                        (cutoff_date,)
                    )
                    jobs_deleted = cursor.rowcount
                    
                    conn.commit()
                    
                    if results_deleted > 0 or agg_deleted > 0 or jobs_deleted > 0:
                        self.logger.info(
                            f"Cleanup completed: {jobs_deleted} jobs, "
                            f"{results_deleted} results, {agg_deleted} aggregations deleted"
                        )
                        
                finally:
                    conn.close()
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
    
    async def _health_monitor_loop(self) -> None:
        """Background health monitoring loop."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                if self._shutdown_event.is_set():
                    break
                
                await self._perform_health_check()
                
            except Exception as e:
                self.logger.error(f"Error in health monitor: {e}")
                await asyncio.sleep(60)
    
    async def _perform_health_check(self) -> None:
        """Perform health check on scan engine components."""
        # Check for stuck jobs
        stuck_jobs = []
        current_time = datetime.now()
        
        for job in self.active_jobs.values():
            if job.status == ScanStatus.RUNNING and job.started_at:
                runtime = (current_time - job.started_at).total_seconds()
                max_runtime = self.config.get('system', {}).get('max_scan_runtime', 3600)  # 1 hour default
                
                if runtime > max_runtime:
                    stuck_jobs.append(job.job_id)
        
        # Handle stuck jobs
        for job_id in stuck_jobs:
            self.logger.warning(f"Detected stuck job: {job_id}, marking as failed")
            job = self.active_jobs[job_id]
            job.status = ScanStatus.FAILED
            job.error_message = "Job timeout - exceeded maximum runtime"
            job.completed_at = current_time
            self._update_job(job)
    
    def _detect_target_type(self, target: str) -> str:
        """Detect target type from target string.
        
        Args:
            target: Target string
            
        Returns:
            Target type classification
        """
        import ipaddress
        from urllib.parse import urlparse
        
        # URL detection
        if target.startswith(('http://', 'https://')):
            return 'url'
        
        # IP address detection
        try:
            ipaddress.ip_address(target)
            return 'ip'
        except ValueError:
            pass
        
        # Network range detection
        if '/' in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return 'network'
            except ValueError:
                pass
        
        # Default to domain
        return 'domain'
    
    def _calculate_real_time_progress(self, job: ScanJob) -> Dict[str, Any]:
        """Calculate real-time progress for running job.
        
        Args:
            job: Running scan job
            
        Returns:
            Real-time progress information
        """
        progress = {
            'current_phase': job.progress.get('current_phase', 'unknown'),
            'phase_index': job.progress.get('phase_index', 0),
            'total_phases': job.progress.get('total_phases', 0),
            'results_so_far': len(job.results),
            'runtime_seconds': 0
        }
        
        if job.started_at:
            progress['runtime_seconds'] = (datetime.now() - job.started_at).total_seconds()
        
        return progress
    
    def _save_job(self, job: ScanJob) -> None:
        """Save scan job to database.
        
        Args:
            job: Scan job to save
        """
        with self._db_lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute('''
                    INSERT INTO scan_jobs 
                    (job_id, target, target_type, target_id, scan_profile, status, 
                     created_at, metadata, progress)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    job.job_id,
                    job.target.target,
                    job.target.target_type,
                    job.target.target_id,
                    job.scan_profile,
                    job.status.value,
                    job.created_at.isoformat(),
                    json.dumps(job.metadata),
                    json.dumps(job.progress)
                ))
                conn.commit()
            finally:
                conn.close()
    
    def _update_job(self, job: ScanJob) -> None:
        """Update scan job in database.
        
        Args:
            job: Scan job to update
        """
        with self._db_lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute('''
                    UPDATE scan_jobs 
                    SET status=?, started_at=?, completed_at=?, 
                        error_message=?, progress=?
                    WHERE job_id=?
                ''', (
                    job.status.value,
                    job.started_at.isoformat() if job.started_at else None,
                    job.completed_at.isoformat() if job.completed_at else None,
                    job.error_message,
                    json.dumps(job.progress),
                    job.job_id
                ))
                conn.commit()
            finally:
                conn.close()
    
    def _load_job(self, job_id: str) -> Optional[ScanJob]:
        """Load scan job from database.
        
        Args:
            job_id: Job ID to load
            
        Returns:
            Loaded scan job or None if not found
        """
        with self._db_lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute('''
                    SELECT target, target_type, target_id, scan_profile, status,
                           created_at, started_at, completed_at, metadata, 
                           progress, error_message
                    FROM scan_jobs WHERE job_id = ?
                ''', (job_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Reconstruct scan target
                metadata = json.loads(row[8]) if row[8] else {}
                target = ScanTarget(
                    target=row[0],
                    target_type=row[1],
                    context=metadata.get('context', {}),
                    constraints=metadata.get('constraints', {})
                )
                target.target_id = row[2]  # Restore saved target_id
                
                # Reconstruct scan job
                job = ScanJob(
                    job_id=job_id,
                    target=target,
                    scan_profile=row[3],
                    status=ScanStatus(row[4]),
                    created_at=datetime.fromisoformat(row[5]),
                    started_at=datetime.fromisoformat(row[6]) if row[6] else None,
                    completed_at=datetime.fromisoformat(row[7]) if row[7] else None,
                    metadata=metadata,
                    progress=json.loads(row[9]) if row[9] else {},
                    error_message=row[10]
                )
                
                return job
                
            finally:
                conn.close()
    
    def _save_result(self, result: ScanResult) -> None:
        """Save scan result to database.
        
        Args:
            result: Scan result to save
        """
        with self._db_lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute('''
                    INSERT INTO scan_results 
                    (scan_id, target, target_id, phase, tool, timestamp, data, 
                     severity, confidence, false_positive_likelihood)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result.scan_id,
                    result.target.target,
                    result.target.target_id,
                    result.phase.value,
                    result.tool,
                    result.timestamp.isoformat(),
                    json.dumps(result.data),
                    result.severity.value,
                    result.confidence,
                    result.false_positive_likelihood
                ))
                conn.commit()
            finally:
                conn.close()
    
    def _load_results(self, job_id: str, 
                     severity_filter: Optional[List[str]] = None) -> List[ScanResult]:
        """Load scan results from database.
        
        Args:
            job_id: Job ID to load results for
            severity_filter: Optional severity filter
            
        Returns:
            List of scan results
        """
        with self._db_lock:
            conn = sqlite3.connect(self.db_path)
            try:
                query = '''
                    SELECT target, target_id, phase, tool, timestamp, data,
                           severity, confidence, false_positive_likelihood
                    FROM scan_results WHERE scan_id = ?
                '''
                params = [job_id]
                
                if severity_filter:
                    placeholders = ','.join('?' for _ in severity_filter)
                    query += f' AND severity IN ({placeholders})'
                    params.extend(severity_filter)
                
                query += ' ORDER BY timestamp'
                
                cursor = conn.execute(query, params)
                results = []
                
                for row in cursor:
                    # Reconstruct target (simplified)
                    target = ScanTarget(target=row[0], target_type='unknown')
                    target.target_id = row[1]
                    
                    result = ScanResult(
                        scan_id=job_id,
                        target=target,
                        phase=ScanPhase(row[2]),
                        tool=row[3],
                        timestamp=datetime.fromisoformat(row[4]),
                        data=json.loads(row[5]),
                        severity=ScanSeverity(row[6]),
                        confidence=row[7],
                        false_positive_likelihood=row[8]
                    )
                    results.append(result)
                
                return results
                
            finally:
                conn.close()
    
    def _get_aggregated_results(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get aggregated results for a job.
        
        Args:
            job_id: Job ID to get aggregated results for
            
        Returns:
            Aggregated results dictionary or None if not found
        """
        with self._db_lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute(
                    'SELECT aggregation_data FROM aggregated_results WHERE job_id = ?',
                    (job_id,)
                )
                row = cursor.fetchone()
                
                if row:
                    return json.loads(row[0])
                return None
                
            finally:
                conn.close()
    
    def get_engine_stats(self) -> Dict[str, Any]:
        """Get scan engine statistics.
        
        Returns:
            Engine statistics dictionary
        """
        stats = {
            'active_jobs': len(self.active_jobs),
            'max_concurrent_scans': self.max_concurrent_scans,
            'available_pipelines': list(self.pipelines.keys()),
            'engine_status': 'running' if self.scheduler_task else 'stopped',
            'database_path': self.db_path
        }
        
        # Add database statistics
        try:
            with self._db_lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    # Count jobs by status
                    cursor = conn.execute(
                        'SELECT status, COUNT(*) FROM scan_jobs GROUP BY status'
                    )
                    job_counts = dict(cursor.fetchall())
                    stats['job_counts_by_status'] = job_counts
                    
                    # Count total results
                    cursor = conn.execute('SELECT COUNT(*) FROM scan_results')
                    stats['total_results'] = cursor.fetchone()[0]
                    
                finally:
                    conn.close()
        except Exception as e:
            stats['database_error'] = str(e)
        
        return stats