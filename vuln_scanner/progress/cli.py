"""Command line interface for progress management."""

import asyncio
import json
import sys
import click
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.tree import Tree

from .manager import ProgressManager
from .queue import TaskQueue, ScanConfig, TaskPriority
from .monitor import ProgressMonitor
from .estimator import ProgressEstimator, ComplexityMetrics
from .models import TaskStatus
from ..core.scanning.data_structures import ScanPhase


console = Console()


class ProgressCLI:
    """Command line interface for progress management."""
    
    def __init__(self, progress_manager: Optional[ProgressManager] = None,
                 task_queue: Optional[TaskQueue] = None,
                 progress_monitor: Optional[ProgressMonitor] = None,
                 progress_estimator: Optional[ProgressEstimator] = None):
        """Initialize progress CLI.
        
        Args:
            progress_manager: ProgressManager instance
            task_queue: TaskQueue instance (optional)
            progress_monitor: ProgressMonitor instance (optional)
            progress_estimator: ProgressEstimator instance (optional)
        """
        self.progress_manager = progress_manager
        self.task_queue = task_queue
        self.progress_monitor = progress_monitor
        self.progress_estimator = progress_estimator
    
    # Task management commands
    
    async def create_task(self, scan_id: str, scan_profile: str, 
                         target: str, target_type: str = "domain",
                         priority: str = "normal", timeout_hours: float = 2.0) -> None:
        """Create a new scanning task."""
        try:
            if not self.progress_manager:
                console.print("[red]Progress manager not available[/red]")
                return
            
            # Prepare target info
            target_info = {
                "target": target,
                "target_type": target_type,
                "created_at": datetime.now().isoformat()
            }
            
            # Create task
            if self.task_queue:
                # Use task queue if available
                priority_enum = TaskPriority[priority.upper()]
                scan_config = ScanConfig(
                    scan_id=scan_id,
                    scan_profile=scan_profile,
                    target_info=target_info,
                    priority=priority_enum,
                    timeout=timedelta(hours=timeout_hours)
                )
                task_id = await self.task_queue.submit_task(scan_config)
                console.print(f"[green]Task {task_id} submitted to queue[/green]")
            else:
                # Create directly
                task_id = await self.progress_manager.create_task(
                    scan_id=scan_id,
                    scan_profile=scan_profile,
                    target_info=target_info
                )
                console.print(f"[green]Task {task_id} created[/green]")
            
            # Show task information
            await self._show_task_info(task_id)
            
        except Exception as e:
            console.print(f"[red]Failed to create task: {e}[/red]")
    
    async def show_progress(self, task_id: str, follow: bool = False) -> None:
        """Show progress for a specific task."""
        if not self.progress_manager:
            console.print("[red]Progress manager not available[/red]")
            return
        
        if follow:
            await self._follow_progress(task_id)
        else:
            await self._show_task_progress(task_id)
    
    async def list_tasks(self, status: Optional[str] = None, limit: int = 20) -> None:
        """List tasks with optional status filter."""
        try:
            if not self.progress_manager:
                console.print("[red]Progress manager not available[/red]")
                return
            
            # Get task list
            if status:
                task_status = TaskStatus(status.lower())
                task_ids = await self.progress_manager.list_tasks(task_status)
            else:
                task_ids = await self.progress_manager.list_tasks()
            
            if not task_ids:
                console.print("[yellow]No tasks found[/yellow]")
                return
            
            # Create table
            table = Table(title="Tasks")
            table.add_column("Task ID", style="cyan", no_wrap=True)
            table.add_column("Scan ID", style="green")
            table.add_column("Profile", style="blue")
            table.add_column("Status", style="magenta")
            table.add_column("Progress", style="yellow")
            table.add_column("Phase", style="cyan")
            table.add_column("Last Update", style="white")
            
            # Add rows (limit to prevent overwhelming output)
            for task_id in task_ids[:limit]:
                progress_state = await self.progress_manager.get_progress(task_id)
                if progress_state:
                    # Format progress
                    progress_str = f"{progress_state.overall_progress:.1f}%"
                    
                    # Format status with color
                    status_color = {
                        "pending": "white",
                        "running": "green",
                        "paused": "yellow",
                        "completed": "blue",
                        "failed": "red",
                        "cancelled": "gray"
                    }.get(progress_state.status.value, "white")
                    
                    status_str = f"[{status_color}]{progress_state.status.value}[/{status_color}]"
                    
                    # Current phase
                    phase_str = progress_state.current_phase.value if progress_state.current_phase else "None"
                    
                    # Format last update
                    time_ago = datetime.now() - progress_state.last_update
                    if time_ago.total_seconds() < 60:
                        time_str = "Just now"
                    elif time_ago.total_seconds() < 3600:
                        time_str = f"{int(time_ago.total_seconds() / 60)}m ago"
                    else:
                        time_str = f"{int(time_ago.total_seconds() / 3600)}h ago"
                    
                    table.add_row(
                        task_id[:8] + "...",
                        progress_state.scan_id,
                        progress_state.scan_profile,
                        status_str,
                        progress_str,
                        phase_str,
                        time_str
                    )
            
            console.print(table)
            
            if len(task_ids) > limit:
                console.print(f"[yellow]Showing {limit} of {len(task_ids)} tasks. Use --limit to show more.[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Failed to list tasks: {e}[/red]")
    
    async def pause_task(self, task_id: str) -> None:
        """Pause a running task."""
        try:
            if not self.progress_manager:
                console.print("[red]Progress manager not available[/red]")
                return
            
            await self.progress_manager.pause_task(task_id)
            console.print(f"[yellow]Task {task_id} paused[/yellow]")
            
        except Exception as e:
            console.print(f"[red]Failed to pause task: {e}[/red]")
    
    async def resume_task(self, task_id: str) -> None:
        """Resume a paused task."""
        try:
            if not self.progress_manager:
                console.print("[red]Progress manager not available[/red]")
                return
            
            await self.progress_manager.resume_task(task_id)
            console.print(f"[green]Task {task_id} resumed[/green]")
            
        except Exception as e:
            console.print(f"[red]Failed to resume task: {e}[/red]")
    
    async def cancel_task(self, task_id: str) -> None:
        """Cancel a task."""
        try:
            if not self.progress_manager:
                console.print("[red]Progress manager not available[/red]")
                return
            
            await self.progress_manager.cancel_task(task_id)
            console.print(f"[red]Task {task_id} cancelled[/red]")
            
        except Exception as e:
            console.print(f"[red]Failed to cancel task: {e}[/red]")
    
    # Queue management commands
    
    async def show_queue_status(self) -> None:
        """Show task queue status."""
        try:
            if not self.task_queue:
                console.print("[red]Task queue not available[/red]")
                return
            
            queue_status = await self.task_queue.get_queue_status()
            
            # Create status panel
            status_text = f"""
[bold]Queue Status:[/bold] {queue_status.queue_health}
[bold]Utilization:[/bold] {queue_status.utilization_percentage:.1f}%

[cyan]Running:[/cyan] {queue_status.running_count}/{queue_status.total_slots}
[yellow]Pending:[/yellow] {queue_status.pending_count}
[green]Completed:[/green] {queue_status.completed_count}
[red]Failed:[/red] {queue_status.failed_count}

[bold]Available Slots:[/bold] {queue_status.available_slots}
            """
            
            console.print(Panel(status_text.strip(), title="Task Queue Status"))
            
            # Show detailed statistics
            stats = await self.task_queue.get_statistics()
            
            stats_text = f"""
[bold]Total Submitted:[/bold] {stats['statistics']['total_submitted']}
[bold]Total Completed:[/bold] {stats['statistics']['total_completed']}
[bold]Total Failed:[/bold] {stats['statistics']['total_failed']}
[bold]Total Retried:[/bold] {stats['statistics']['total_retried']}
[bold]Average Execution Time:[/bold] {stats['average_execution_time']:.1f}s
[bold]Workers Active:[/bold] {stats['workers_active']}
[bold]Queue Paused:[/bold] {stats['is_paused']}
            """
            
            console.print(Panel(stats_text.strip(), title="Queue Statistics"))
            
        except Exception as e:
            console.print(f"[red]Failed to get queue status: {e}[/red]")
    
    async def clear_queue(self, status: str) -> None:
        """Clear tasks from queue by status."""
        try:
            if not self.task_queue:
                console.print("[red]Task queue not available[/red]")
                return
            
            # This would need to be implemented in TaskQueue
            console.print(f"[yellow]Queue clearing by status '{status}' not yet implemented[/yellow]")
            
        except Exception as e:
            console.print(f"[red]Failed to clear queue: {e}[/red]")
    
    # Health monitoring commands
    
    async def show_health(self) -> None:
        """Show system health status."""
        try:
            if not self.progress_monitor:
                console.print("[red]Progress monitor not available[/red]")
                return
            
            health_data = await self.progress_monitor.get_system_health()
            
            # Overall health
            health_color = {
                "healthy": "green",
                "degraded": "yellow", 
                "unhealthy": "red"
            }.get(health_data["overall_health"], "white")
            
            console.print(f"[bold]System Health:[/bold] [{health_color}]{health_data['overall_health'].upper()}[/{health_color}]")
            
            # Component health
            if "components" in health_data:
                table = Table(title="Component Health")
                table.add_column("Component", style="cyan")
                table.add_column("Status", style="magenta")
                
                for component, status in health_data["components"].items():
                    status_color = {
                        "healthy": "green",
                        "degraded": "yellow",
                        "unhealthy": "red"
                    }.get(status, "white")
                    
                    table.add_row(
                        component,
                        f"[{status_color}]{status}[/{status_color}]"
                    )
                
                console.print(table)
            
            # Alerts summary
            if "alerts" in health_data:
                alerts = health_data["alerts"]
                alerts_text = f"""
[bold]Total Alerts:[/bold] {alerts['total_alerts']}
[bold]Unresolved:[/bold] {alerts['unresolved_alerts']}
[bold]Critical:[/bold] {alerts['critical_alerts']}
                """
                console.print(Panel(alerts_text.strip(), title="Alerts"))
            
            # Resource metrics
            if "metrics" in health_data and "resources" in health_data["metrics"]:
                resources = health_data["metrics"]["resources"]
                resource_text = f"""
[bold]CPU Usage:[/bold] {resources.get('cpu_usage', 0):.1f}%
[bold]Memory Usage:[/bold] {resources.get('memory_usage', 0):.1f}%
[bold]Disk Usage:[/bold] {resources.get('disk_usage', 0):.1f}%
[bold]Active Connections:[/bold] {resources.get('active_connections', 0)}
                """
                console.print(Panel(resource_text.strip(), title="Resource Usage"))
            
        except Exception as e:
            console.print(f"[red]Failed to get system health: {e}[/red]")
    
    async def show_alerts(self, resolved: Optional[bool] = None, 
                         severity: Optional[str] = None, limit: int = 20) -> None:
        """Show system alerts."""
        try:
            if not self.progress_monitor:
                console.print("[red]Progress monitor not available[/red]")
                return
            
            alerts = await self.progress_monitor.get_alerts(
                resolved=resolved,
                severity=severity,
                limit=limit
            )
            
            if not alerts:
                console.print("[yellow]No alerts found[/yellow]")
                return
            
            table = Table(title="System Alerts")
            table.add_column("Severity", style="magenta")
            table.add_column("Type", style="cyan")
            table.add_column("Message", style="white")
            table.add_column("Time", style="blue")
            table.add_column("Status", style="green")
            
            for alert in alerts:
                severity_color = {
                    "info": "blue",
                    "warning": "yellow",
                    "critical": "red"
                }.get(alert.severity, "white")
                
                status_str = "Resolved" if alert.resolved else "Active"
                status_color = "green" if alert.resolved else "red"
                
                # Format timestamp
                alert_time = datetime.fromisoformat(alert.timestamp.replace('Z', '+00:00'))
                time_str = alert_time.strftime("%H:%M:%S")
                
                table.add_row(
                    f"[{severity_color}]{alert.severity.upper()}[/{severity_color}]",
                    alert.alert_type,
                    alert.message[:60] + "..." if len(alert.message) > 60 else alert.message,
                    time_str,
                    f"[{status_color}]{status_str}[/{status_color}]"
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Failed to get alerts: {e}[/red]")
    
    # Estimation commands
    
    async def estimate_duration(self, target_count: int = 1, port_count: int = 0,
                              service_count: int = 0, subdomain_count: int = 0,
                              technology_count: int = 0, vulnerability_count: int = 0,
                              scan_profile: str = "normal") -> None:
        """Estimate scan duration based on complexity."""
        try:
            if not self.progress_estimator:
                console.print("[red]Progress estimator not available[/red]")
                return
            
            complexity_metrics = ComplexityMetrics(
                target_count=target_count,
                port_count=port_count,
                service_count=service_count,
                subdomain_count=subdomain_count,
                technology_count=technology_count,
                vulnerability_count=vulnerability_count
            )
            
            estimate = await self.progress_estimator.estimate_total_duration(
                complexity_metrics=complexity_metrics,
                scan_profile=scan_profile
            )
            
            # Display results
            total_seconds = estimate["total_estimated_duration"]
            buffered_seconds = estimate["buffered_duration"]
            
            total_time = timedelta(seconds=total_seconds)
            buffered_time = timedelta(seconds=buffered_seconds)
            
            estimate_text = f"""
[bold]Complexity Score:[/bold] {complexity_metrics.calculate_complexity_score():.1f}/10.0

[bold]Estimated Duration:[/bold] {self._format_duration(total_time)}
[bold]With Buffer:[/bold] {self._format_duration(buffered_time)}
[bold]Buffer Factor:[/bold] {estimate['buffer_multiplier']:.1f}x
[bold]Confidence:[/bold] {estimate['average_confidence']*100:.1f}%

[bold]Estimated Completion:[/bold] {estimate['estimated_completion']}
            """
            
            console.print(Panel(estimate_text.strip(), title=f"Duration Estimate ({scan_profile} profile)"))
            
            # Show per-phase estimates
            if "phase_estimates" in estimate:
                table = Table(title="Phase Estimates")
                table.add_column("Phase", style="cyan")
                table.add_column("Duration", style="green")
                table.add_column("Confidence", style="yellow")
                
                for phase_name, phase_data in estimate["phase_estimates"].items():
                    duration = timedelta(seconds=phase_data["estimated_duration"])
                    confidence = phase_data["confidence"] * 100
                    
                    table.add_row(
                        phase_name.replace("_", " ").title(),
                        self._format_duration(duration),
                        f"{confidence:.1f}%"
                    )
                
                console.print(table)
            
        except Exception as e:
            console.print(f"[red]Failed to estimate duration: {e}[/red]")
    
    # Private helper methods
    
    async def _show_task_info(self, task_id: str) -> None:
        """Show detailed task information."""
        try:
            progress_state = await self.progress_manager.get_progress(task_id)
            if not progress_state:
                console.print(f"[red]Task {task_id} not found[/red]")
                return
            
            info_text = f"""
[bold]Task ID:[/bold] {progress_state.task_id}
[bold]Scan ID:[/bold] {progress_state.scan_id}
[bold]Profile:[/bold] {progress_state.scan_profile}
[bold]Status:[/bold] {progress_state.status.value}
[bold]Progress:[/bold] {progress_state.overall_progress:.1f}%
[bold]Current Phase:[/bold] {progress_state.current_phase.value if progress_state.current_phase else "None"}
[bold]Target:[/bold] {progress_state.target_info.get('target', 'Unknown')}
            """
            
            console.print(Panel(info_text.strip(), title="Task Information"))
            
        except Exception as e:
            console.print(f"[red]Failed to get task info: {e}[/red]")
    
    async def _show_task_progress(self, task_id: str) -> None:
        """Show detailed progress for a task."""
        try:
            progress_state = await self.progress_manager.get_progress(task_id)
            if not progress_state:
                console.print(f"[red]Task {task_id} not found[/red]")
                return
            
            # Show overall progress
            console.print(f"[bold]Task {task_id[:8]}...[/bold]")
            console.print(f"Status: {progress_state.status.value} | Progress: {progress_state.overall_progress:.1f}%")
            
            # Show phase progress
            table = Table(title="Phase Progress")
            table.add_column("Phase", style="cyan")
            table.add_column("Status", style="magenta") 
            table.add_column("Progress", style="green")
            table.add_column("Current Step", style="yellow")
            table.add_column("Steps", style="blue")
            
            for phase, phase_progress in progress_state.phase_progress.items():
                status_color = {
                    "pending": "white",
                    "running": "green",
                    "paused": "yellow",
                    "completed": "blue",
                    "failed": "red"
                }.get(phase_progress.status.value, "white")
                
                table.add_row(
                    phase.value.replace("_", " ").title(),
                    f"[{status_color}]{phase_progress.status.value}[/{status_color}]",
                    f"{phase_progress.progress_percentage:.1f}%",
                    phase_progress.current_step[:30] + "..." if len(phase_progress.current_step) > 30 else phase_progress.current_step,
                    f"{phase_progress.completed_steps}/{phase_progress.total_steps}"
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Failed to show task progress: {e}[/red]")
    
    async def _follow_progress(self, task_id: str) -> None:
        """Follow progress in real-time."""
        try:
            console.print(f"[yellow]Following progress for task {task_id[:8]}... (Press Ctrl+C to stop)[/yellow]")
            
            with Live(refresh_per_second=2) as live:
                while True:
                    try:
                        progress_state = await self.progress_manager.get_progress(task_id)
                        if not progress_state:
                            live.update("[red]Task not found[/red]")
                            break
                        
                        # Create progress display
                        layout = Layout()
                        
                        # Task info
                        info_panel = Panel(
                            f"Task: {task_id[:8]}...\n"
                            f"Status: {progress_state.status.value}\n"
                            f"Overall: {progress_state.overall_progress:.1f}%\n"
                            f"Phase: {progress_state.current_phase.value if progress_state.current_phase else 'None'}",
                            title="Task Information"
                        )
                        
                        # Phase progress bars
                        progress_bars = Progress(
                            TextColumn("[progress.description]{task.description}"),
                            BarColumn(),
                            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                            TimeElapsedColumn()
                        )
                        
                        for phase, phase_progress in progress_state.phase_progress.items():
                            task_id_prog = progress_bars.add_task(
                                phase.value.replace("_", " ").title(),
                                total=100,
                                completed=phase_progress.progress_percentage
                            )
                        
                        layout.split_column(
                            Layout(info_panel, size=6),
                            Layout(progress_bars)
                        )
                        
                        live.update(layout)
                        
                        # Check if completed
                        if progress_state.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
                            console.print(f"[green]Task {progress_state.status.value}[/green]")
                            break
                        
                        await asyncio.sleep(2)
                        
                    except KeyboardInterrupt:
                        console.print("[yellow]Progress following stopped[/yellow]")
                        break
                        
        except Exception as e:
            console.print(f"[red]Failed to follow progress: {e}[/red]")
    
    def _format_duration(self, duration: timedelta) -> str:
        """Format duration in a human-readable way."""
        total_seconds = int(duration.total_seconds())
        
        if total_seconds < 60:
            return f"{total_seconds}s"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f"{minutes}m {seconds}s"
        else:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m"


# Click CLI commands

@click.group()
@click.pass_context
def progress(ctx):
    """Progress management commands."""
    # Initialize CLI instance (would be properly initialized in main app)
    ctx.ensure_object(dict)
    ctx.obj['cli'] = ProgressCLI()

@progress.command()
@click.argument('task_id')
@click.option('--follow', '-f', is_flag=True, help='Follow progress in real-time')
@click.pass_context
def show(ctx, task_id, follow):
    """Show progress for a specific task."""
    cli = ctx.obj['cli']
    asyncio.run(cli.show_progress(task_id, follow))

@progress.command()
@click.option('--status', '-s', help='Filter by status')
@click.option('--limit', '-l', default=20, help='Maximum number of tasks to show')
@click.pass_context
def list(ctx, status, limit):
    """List tasks."""
    cli = ctx.obj['cli']
    asyncio.run(cli.list_tasks(status, limit))

@progress.command()
@click.argument('task_id')
@click.pass_context
def pause(ctx, task_id):
    """Pause a task."""
    cli = ctx.obj['cli']
    asyncio.run(cli.pause_task(task_id))

@progress.command()
@click.argument('task_id')
@click.pass_context
def resume(ctx, task_id):
    """Resume a task."""
    cli = ctx.obj['cli']
    asyncio.run(cli.resume_task(task_id))

@progress.command()
@click.argument('task_id')
@click.pass_context
def cancel(ctx, task_id):
    """Cancel a task."""
    cli = ctx.obj['cli']
    asyncio.run(cli.cancel_task(task_id))

@progress.group()
def queue():
    """Task queue management commands."""
    pass

@queue.command('status')
@click.pass_context
def queue_status(ctx):
    """Show queue status."""
    cli = ctx.obj['cli']
    asyncio.run(cli.show_queue_status())

@progress.group()
def health():
    """Health monitoring commands."""
    pass

@health.command('status')
@click.pass_context
def health_status(ctx):
    """Show system health."""
    cli = ctx.obj['cli']
    asyncio.run(cli.show_health())

@health.command('alerts')
@click.option('--resolved', is_flag=True, help='Show only resolved alerts')
@click.option('--severity', help='Filter by severity')
@click.option('--limit', default=20, help='Maximum number of alerts')
@click.pass_context
def show_alerts(ctx, resolved, severity, limit):
    """Show system alerts."""
    cli = ctx.obj['cli']
    asyncio.run(cli.show_alerts(resolved, severity, limit))


if __name__ == '__main__':
    progress()