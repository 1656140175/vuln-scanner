"""REST API interfaces for progress management."""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from fastapi import APIRouter, HTTPException, Query, Path, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from .manager import ProgressManager
from .queue import TaskQueue, ScanConfig, TaskPriority
from .monitor import ProgressMonitor
from .estimator import ProgressEstimator, ComplexityMetrics
from .websocket import ProgressWebSocketManager, websocket_connection
from .models import TaskStatus, ProgressState
from ..core.scanning.data_structures import ScanPhase
from ..core.exceptions import BaseException


logger = logging.getLogger(__name__)


class class APIException(BaseException):(VulnMinerException):
    """API specific exceptions."""
    pass


# Pydantic models for request/response validation

class TaskCreateRequest(BaseModel):
    """Request model for creating a new task."""
    scan_id: str = Field(..., description="Unique scan identifier")
    scan_profile: str = Field(..., description="Scan profile name")
    target_info: Dict[str, Any] = Field(..., description="Target information")
    priority: str = Field("normal", description="Task priority (low, normal, high, critical)")
    timeout_hours: Optional[float] = Field(2.0, description="Task timeout in hours")
    max_retries: int = Field(3, description="Maximum retry attempts")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class TaskResponse(BaseModel):
    """Response model for task information."""
    task_id: str
    scan_id: str
    scan_profile: str
    status: str
    overall_progress: float
    current_phase: Optional[str]
    start_time: Optional[str]
    estimated_completion: Optional[str]
    last_update: str
    phase_progress: Dict[str, Any]


class QueueStatusResponse(BaseModel):
    """Response model for queue status."""
    running_count: int
    pending_count: int
    completed_count: int
    failed_count: int
    total_slots: int
    available_slots: int
    queue_health: str
    utilization_percentage: float


class HealthCheckResponse(BaseModel):
    """Response model for health check."""
    overall_health: str
    timestamp: str
    components: Dict[str, str]
    alerts: Dict[str, int]
    metrics: Dict[str, Any]


class EstimationRequest(BaseModel):
    """Request model for duration estimation."""
    target_count: int = Field(1, description="Number of targets")
    port_count: int = Field(0, description="Number of ports to scan")
    service_count: int = Field(0, description="Number of services detected")
    subdomain_count: int = Field(0, description="Number of subdomains")
    technology_count: int = Field(0, description="Number of technologies")
    vulnerability_count: int = Field(0, description="Expected number of vulnerabilities")
    scan_profile: str = Field("normal", description="Scan profile")


class ProgressAPI:
    """REST API for progress management."""
    
    def __init__(self, progress_manager: ProgressManager,
                 task_queue: Optional[TaskQueue] = None,
                 progress_monitor: Optional[ProgressMonitor] = None,
                 progress_estimator: Optional[ProgressEstimator] = None,
                 websocket_manager: Optional[ProgressWebSocketManager] = None):
        """Initialize progress API.
        
        Args:
            progress_manager: ProgressManager instance
            task_queue: TaskQueue instance (optional)
            progress_monitor: ProgressMonitor instance (optional)
            progress_estimator: ProgressEstimator instance (optional)
            websocket_manager: WebSocket manager instance (optional)
        """
        self.progress_manager = progress_manager
        self.task_queue = task_queue
        self.progress_monitor = progress_monitor
        self.progress_estimator = progress_estimator
        self.websocket_manager = websocket_manager
        
        self.router = APIRouter(prefix="/api/v1", tags=["progress"])
        self._setup_routes()
    
    def _setup_routes(self) -> None:
        """Set up API routes."""
        
        @self.router.post("/tasks", response_model=Dict[str, str])
        async def create_task(request: TaskCreateRequest):
            """Create a new scanning task."""
            try:
                # Convert priority string to enum
                try:
                    priority = TaskPriority[request.priority.upper()]
                except KeyError:
                    raise HTTPException(status_code=400, detail=f"Invalid priority: {request.priority}")
                
                # Create scan configuration
                scan_config = ScanConfig(
                    scan_id=request.scan_id,
                    scan_profile=request.scan_profile,
                    target_info=request.target_info,
                    priority=priority,
                    timeout=timedelta(hours=request.timeout_hours) if request.timeout_hours else None,
                    max_retries=request.max_retries,
                    metadata=request.metadata or {}
                )
                
                # Submit to queue if available, otherwise create directly
                if self.task_queue:
                    task_id = await self.task_queue.submit_task(scan_config)
                else:
                    task_id = await self.progress_manager.create_task(
                        scan_id=request.scan_id,
                        scan_profile=request.scan_profile,
                        target_info=request.target_info,
                        metadata=request.metadata
                    )
                
                return {"task_id": task_id, "status": "created"}
                
            except Exception as e:
                logger.error(f"Failed to create task: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.get("/tasks/{task_id}/progress", response_model=TaskResponse)
        async def get_task_progress(task_id: str = Path(..., description="Task identifier")):
            """Get progress information for a specific task."""
            try:
                progress_state = await self.progress_manager.get_progress(task_id)
                if not progress_state:
                    raise HTTPException(status_code=404, detail="Task not found")
                
                return TaskResponse(
                    task_id=progress_state.task_id,
                    scan_id=progress_state.scan_id,
                    scan_profile=progress_state.scan_profile,
                    status=progress_state.status.value,
                    overall_progress=progress_state.overall_progress,
                    current_phase=progress_state.current_phase.value if progress_state.current_phase else None,
                    start_time=progress_state.start_time.isoformat() if progress_state.start_time else None,
                    estimated_completion=progress_state.estimated_completion.isoformat() 
                                       if progress_state.estimated_completion else None,
                    last_update=progress_state.last_update.isoformat(),
                    phase_progress={
                        phase.value: {
                            "progress": prog.progress_percentage,
                            "status": prog.status.value,
                            "current_step": prog.current_step,
                            "completed_steps": prog.completed_steps,
                            "total_steps": prog.total_steps
                        }
                        for phase, prog in progress_state.phase_progress.items()
                    }
                )
                
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to get task progress: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.post("/tasks/{task_id}/pause")
        async def pause_task(task_id: str = Path(..., description="Task identifier")):
            """Pause a running task."""
            try:
                await self.progress_manager.pause_task(task_id)
                return {"status": "paused", "task_id": task_id}
                
            except Exception as e:
                logger.error(f"Failed to pause task {task_id}: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.post("/tasks/{task_id}/resume")
        async def resume_task(task_id: str = Path(..., description="Task identifier")):
            """Resume a paused task."""
            try:
                await self.progress_manager.resume_task(task_id)
                return {"status": "resumed", "task_id": task_id}
                
            except Exception as e:
                logger.error(f"Failed to resume task {task_id}: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.post("/tasks/{task_id}/cancel")
        async def cancel_task(task_id: str = Path(..., description="Task identifier")):
            """Cancel a task."""
            try:
                # Cancel in progress manager
                await self.progress_manager.cancel_task(task_id)
                
                # Cancel in queue if available
                if self.task_queue:
                    await self.task_queue.cancel_task(task_id)
                
                return {"status": "cancelled", "task_id": task_id}
                
            except Exception as e:
                logger.error(f"Failed to cancel task {task_id}: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.get("/tasks", response_model=List[Dict[str, Any]])
        async def list_tasks(status: Optional[str] = Query(None, description="Filter by task status")):
            """List tasks with optional status filter."""
            try:
                # Get task IDs from progress manager
                if status:
                    try:
                        task_status = TaskStatus(status.lower())
                        task_ids = await self.progress_manager.list_tasks(task_status)
                    except ValueError:
                        raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
                else:
                    task_ids = await self.progress_manager.list_tasks()
                
                # Get detailed information for each task
                tasks = []
                for task_id in task_ids:
                    progress_state = await self.progress_manager.get_progress(task_id)
                    if progress_state:
                        tasks.append({
                            "task_id": progress_state.task_id,
                            "scan_id": progress_state.scan_id,
                            "status": progress_state.status.value,
                            "overall_progress": progress_state.overall_progress,
                            "last_update": progress_state.last_update.isoformat()
                        })
                
                return tasks
                
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to list tasks: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.get("/queue/status", response_model=QueueStatusResponse)
        async def get_queue_status():
            """Get task queue status."""
            if not self.task_queue:
                raise HTTPException(status_code=503, detail="Task queue not available")
            
            try:
                queue_status = await self.task_queue.get_queue_status()
                return QueueStatusResponse(**queue_status.to_dict())
                
            except Exception as e:
                logger.error(f"Failed to get queue status: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.get("/queue/statistics")
        async def get_queue_statistics():
            """Get detailed queue statistics."""
            if not self.task_queue:
                raise HTTPException(status_code=503, detail="Task queue not available")
            
            try:
                return await self.task_queue.get_statistics()
                
            except Exception as e:
                logger.error(f"Failed to get queue statistics: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.get("/health", response_model=HealthCheckResponse)
        async def health_check():
            """Get system health status."""
            if not self.progress_monitor:
                raise HTTPException(status_code=503, detail="Progress monitor not available")
            
            try:
                health_data = await self.progress_monitor.get_system_health()
                return HealthCheckResponse(**health_data)
                
            except Exception as e:
                logger.error(f"Failed to get system health: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.get("/health/tasks/{task_id}")
        async def get_task_health(task_id: str = Path(..., description="Task identifier")):
            """Get health status for a specific task."""
            if not self.progress_monitor:
                raise HTTPException(status_code=503, detail="Progress monitor not available")
            
            try:
                health_status = await self.progress_monitor.monitor_task_health(task_id)
                if not health_status:
                    raise HTTPException(status_code=404, detail="Task not found")
                
                return health_status.to_dict()
                
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to get task health: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.post("/tasks/{task_id}/checkpoint")
        async def create_checkpoint(task_id: str = Path(..., description="Task identifier")):
            """Create a checkpoint for a task."""
            try:
                checkpoint_id = await self.progress_manager.checkpoint(task_id)
                return {"checkpoint_id": checkpoint_id, "task_id": task_id}
                
            except Exception as e:
                logger.error(f"Failed to create checkpoint for task {task_id}: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.post("/estimate/duration")
        async def estimate_duration(request: EstimationRequest):
            """Estimate scan duration based on complexity metrics."""
            if not self.progress_estimator:
                raise HTTPException(status_code=503, detail="Progress estimator not available")
            
            try:
                complexity_metrics = ComplexityMetrics(
                    target_count=request.target_count,
                    port_count=request.port_count,
                    service_count=request.service_count,
                    subdomain_count=request.subdomain_count,
                    technology_count=request.technology_count,
                    vulnerability_count=request.vulnerability_count
                )
                
                estimate = await self.progress_estimator.estimate_total_duration(
                    complexity_metrics=complexity_metrics,
                    scan_profile=request.scan_profile
                )
                
                return estimate
                
            except Exception as e:
                logger.error(f"Failed to estimate duration: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.get("/alerts")
        async def get_alerts(resolved: Optional[bool] = Query(None, description="Filter by resolved status"),
                           severity: Optional[str] = Query(None, description="Filter by severity"),
                           limit: int = Query(100, description="Maximum number of alerts")):
            """Get system alerts."""
            if not self.progress_monitor:
                raise HTTPException(status_code=503, detail="Progress monitor not available")
            
            try:
                alerts = await self.progress_monitor.get_alerts(
                    resolved=resolved,
                    severity=severity,
                    limit=limit
                )
                
                return [alert.to_dict() for alert in alerts]
                
            except Exception as e:
                logger.error(f"Failed to get alerts: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket,
                                   subscription: str = Query("all", description="Subscription type"),
                                   task_id: Optional[str] = Query(None, description="Task ID for task-specific subscription")):
            """WebSocket endpoint for real-time progress updates."""
            if not self.websocket_manager:
                await websocket.close(code=1000, reason="WebSocket not available")
                return
            
            async with websocket_connection(self.websocket_manager, websocket, subscription, task_id):
                try:
                    while True:
                        # Handle incoming messages from client
                        message = await websocket.receive_text()
                        await self.websocket_manager.handle_client_message(websocket, message)
                        
                except WebSocketDisconnect:
                    pass
                except Exception as e:
                    logger.error(f"WebSocket error: {e}")
        
        @self.router.get("/stats")
        async def get_system_statistics():
            """Get comprehensive system statistics."""
            try:
                stats = {
                    "timestamp": datetime.now().isoformat(),
                    "components": {}
                }
                
                # Progress manager stats
                if self.progress_manager:
                    stats["components"]["progress_manager"] = {
                        "active_tasks": len(self.progress_manager.active_tasks),
                        "initialized": self.progress_manager._initialized
                    }
                
                # Task queue stats
                if self.task_queue:
                    stats["components"]["task_queue"] = await self.task_queue.get_statistics()
                
                # Monitor stats
                if self.progress_monitor:
                    stats["components"]["monitor"] = await self.progress_monitor.get_monitoring_stats()
                
                # Estimator stats
                if self.progress_estimator:
                    stats["components"]["estimator"] = await self.progress_estimator.get_estimation_stats()
                
                # WebSocket stats
                if self.websocket_manager:
                    stats["components"]["websocket"] = await self.websocket_manager.get_connection_stats()
                
                return stats
                
            except Exception as e:
                logger.error(f"Failed to get system statistics: {e}")
                raise HTTPException(status_code=500, detail=str(e))