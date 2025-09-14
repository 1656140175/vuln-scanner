"""SQLite implementation of progress storage."""

import asyncio
import aiosqlite
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from .base import ProgressStorage
from ..models import ProgressState, CheckpointInfo
from ...core.exceptions import BaseException


logger = logging.getLogger(__name__)


class SqliteStorageException(BaseException):
    """SQLite storage specific exceptions."""
    pass


class SqliteProgressStorage(ProgressStorage):
    """SQLite implementation of progress storage."""
    
    def __init__(self, db_path: str = "data/progress.db"):
        """Initialize SQLite storage.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection: Optional[aiosqlite.Connection] = None
        self._initialized = False
        self._lock = asyncio.Lock()
    
    async def initialize(self) -> None:
        """Initialize SQLite database and create tables."""
        if self._initialized:
            return
        
        async with self._lock:
            if self._initialized:
                return
            
            try:
                self._connection = await aiosqlite.connect(str(self.db_path))
                await self._create_tables()
                self._initialized = True
                logger.info(f"SQLite progress storage initialized at {self.db_path}")
            except Exception as e:
                raise SqliteStorageException(f"Failed to initialize SQLite storage: {e}") from e
    
    async def cleanup(self) -> None:
        """Cleanup SQLite connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None
            self._initialized = False
            logger.info("SQLite progress storage cleaned up")
    
    async def _create_tables(self) -> None:
        """Create necessary database tables."""
        if not self._connection:
            raise SqliteStorageException("Database not initialized")
        
        # Progress states table
        await self._connection.execute('''
            CREATE TABLE IF NOT EXISTS progress_states (
                task_id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                scan_profile TEXT NOT NULL,
                target_info TEXT NOT NULL,
                current_phase TEXT,
                phase_progress TEXT NOT NULL,
                overall_progress REAL DEFAULT 0.0,
                status TEXT NOT NULL DEFAULT 'pending',
                start_time TEXT,
                estimated_completion TEXT,
                actual_completion TEXT,
                last_checkpoint TEXT,
                last_update TEXT NOT NULL,
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Checkpoints table
        await self._connection.execute('''
            CREATE TABLE IF NOT EXISTS checkpoints (
                checkpoint_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                progress_state TEXT,
                phase_data TEXT NOT NULL DEFAULT '{}',
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes
        await self._connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_progress_status ON progress_states(status)
        ''')
        
        await self._connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_progress_last_update ON progress_states(last_update)
        ''')
        
        await self._connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_checkpoints_task_id ON checkpoints(task_id)
        ''')
        
        await self._connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_checkpoints_timestamp ON checkpoints(timestamp)
        ''')
        
        await self._connection.commit()
    
    async def _ensure_initialized(self) -> None:
        """Ensure storage is initialized."""
        if not self._initialized:
            await self.initialize()
    
    async def save_progress(self, progress: ProgressState) -> None:
        """Save progress state to SQLite."""
        await self._ensure_initialized()
        
        try:
            progress_data = progress.to_dict()
            
            await self._connection.execute('''
                INSERT OR REPLACE INTO progress_states (
                    task_id, scan_id, scan_profile, target_info, current_phase,
                    phase_progress, overall_progress, status, start_time,
                    estimated_completion, actual_completion, last_checkpoint,
                    last_update, metadata, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                progress.task_id,
                progress.scan_id,
                progress.scan_profile,
                json.dumps(progress.target_info),
                progress_data.get('current_phase'),
                json.dumps(progress_data['phase_progress']),
                progress.overall_progress,
                progress.status.value,
                progress_data.get('start_time'),
                progress_data.get('estimated_completion'),
                progress_data.get('actual_completion'),
                progress_data.get('last_checkpoint'),
                progress_data['last_update'],
                json.dumps(progress.metadata)
            ))
            
            await self._connection.commit()
            logger.debug(f"Saved progress for task {progress.task_id}")
            
        except Exception as e:
            await self._connection.rollback()
            raise SqliteStorageException(f"Failed to save progress: {e}") from e
    
    async def load_progress(self, task_id: str) -> Optional[ProgressState]:
        """Load progress state from SQLite."""
        await self._ensure_initialized()
        
        try:
            cursor = await self._connection.execute('''
                SELECT task_id, scan_id, scan_profile, target_info, current_phase,
                       phase_progress, overall_progress, status, start_time,
                       estimated_completion, actual_completion, last_checkpoint,
                       last_update, metadata
                FROM progress_states 
                WHERE task_id = ?
            ''', (task_id,))
            
            row = await cursor.fetchone()
            if not row:
                return None
            
            # Reconstruct progress state
            progress_data = {
                'task_id': row[0],
                'scan_id': row[1],
                'scan_profile': row[2],
                'target_info': json.loads(row[3]),
                'current_phase': row[4],
                'phase_progress': json.loads(row[5]),
                'overall_progress': row[6],
                'status': row[7],
                'start_time': row[8],
                'estimated_completion': row[9],
                'actual_completion': row[10],
                'last_checkpoint': row[11],
                'last_update': row[12],
                'metadata': json.loads(row[13])
            }
            
            return ProgressState.from_dict(progress_data)
            
        except Exception as e:
            raise SqliteStorageException(f"Failed to load progress: {e}") from e
    
    async def delete_progress(self, task_id: str) -> bool:
        """Delete progress state from SQLite."""
        await self._ensure_initialized()
        
        try:
            cursor = await self._connection.execute('''
                DELETE FROM progress_states WHERE task_id = ?
            ''', (task_id,))
            
            await self._connection.commit()
            deleted = cursor.rowcount > 0
            
            if deleted:
                logger.debug(f"Deleted progress for task {task_id}")
            
            return deleted
            
        except Exception as e:
            await self._connection.rollback()
            raise SqliteStorageException(f"Failed to delete progress: {e}") from e
    
    async def list_active_tasks(self) -> List[str]:
        """Get list of active task IDs."""
        return await self.list_tasks_by_status("running")
    
    async def list_tasks_by_status(self, status: str) -> List[str]:
        """Get list of task IDs by status."""
        await self._ensure_initialized()
        
        try:
            cursor = await self._connection.execute('''
                SELECT task_id FROM progress_states WHERE status = ?
                ORDER BY last_update DESC
            ''', (status,))
            
            rows = await cursor.fetchall()
            return [row[0] for row in rows]
            
        except Exception as e:
            raise SqliteStorageException(f"Failed to list tasks by status: {e}") from e
    
    async def cleanup_completed_tasks(self, older_than: datetime) -> int:
        """Clean up completed tasks older than specified time."""
        await self._ensure_initialized()
        
        try:
            cursor = await self._connection.execute('''
                DELETE FROM progress_states 
                WHERE status IN ('completed', 'failed', 'cancelled') 
                  AND last_update < ?
            ''', (older_than.isoformat(),))
            
            await self._connection.commit()
            deleted_count = cursor.rowcount
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} completed tasks")
            
            return deleted_count
            
        except Exception as e:
            await self._connection.rollback()
            raise SqliteStorageException(f"Failed to cleanup completed tasks: {e}") from e
    
    async def save_checkpoint(self, checkpoint: CheckpointInfo) -> None:
        """Save checkpoint information."""
        await self._ensure_initialized()
        
        try:
            checkpoint_data = checkpoint.to_dict()
            
            await self._connection.execute('''
                INSERT OR REPLACE INTO checkpoints (
                    checkpoint_id, task_id, phase, timestamp,
                    progress_state, phase_data, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                checkpoint.checkpoint_id,
                checkpoint.task_id,
                checkpoint.phase.value,
                checkpoint_data['timestamp'],
                json.dumps(checkpoint.progress_state) if checkpoint.progress_state else None,
                json.dumps(checkpoint.phase_data),
                json.dumps(checkpoint.metadata)
            ))
            
            await self._connection.commit()
            logger.debug(f"Saved checkpoint {checkpoint.checkpoint_id} for task {checkpoint.task_id}")
            
        except Exception as e:
            await self._connection.rollback()
            raise SqliteStorageException(f"Failed to save checkpoint: {e}") from e
    
    async def load_checkpoint(self, checkpoint_id: str) -> Optional[CheckpointInfo]:
        """Load checkpoint information."""
        await self._ensure_initialized()
        
        try:
            cursor = await self._connection.execute('''
                SELECT checkpoint_id, task_id, phase, timestamp,
                       progress_state, phase_data, metadata
                FROM checkpoints 
                WHERE checkpoint_id = ?
            ''', (checkpoint_id,))
            
            row = await cursor.fetchone()
            if not row:
                return None
            
            checkpoint_data = {
                'checkpoint_id': row[0],
                'task_id': row[1],
                'phase': row[2],
                'timestamp': row[3],
                'progress_state': json.loads(row[4]) if row[4] else None,
                'phase_data': json.loads(row[5]),
                'metadata': json.loads(row[6])
            }
            
            return CheckpointInfo.from_dict(checkpoint_data)
            
        except Exception as e:
            raise SqliteStorageException(f"Failed to load checkpoint: {e}") from e
    
    async def list_checkpoints(self, task_id: str) -> List[CheckpointInfo]:
        """List all checkpoints for a task."""
        await self._ensure_initialized()
        
        try:
            cursor = await self._connection.execute('''
                SELECT checkpoint_id, task_id, phase, timestamp,
                       progress_state, phase_data, metadata
                FROM checkpoints 
                WHERE task_id = ?
                ORDER BY timestamp DESC
            ''', (task_id,))
            
            rows = await cursor.fetchall()
            checkpoints = []
            
            for row in rows:
                checkpoint_data = {
                    'checkpoint_id': row[0],
                    'task_id': row[1],
                    'phase': row[2],
                    'timestamp': row[3],
                    'progress_state': json.loads(row[4]) if row[4] else None,
                    'phase_data': json.loads(row[5]),
                    'metadata': json.loads(row[6])
                }
                checkpoints.append(CheckpointInfo.from_dict(checkpoint_data))
            
            return checkpoints
            
        except Exception as e:
            raise SqliteStorageException(f"Failed to list checkpoints: {e}") from e
    
    async def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """Delete checkpoint from storage."""
        await self._ensure_initialized()
        
        try:
            cursor = await self._connection.execute('''
                DELETE FROM checkpoints WHERE checkpoint_id = ?
            ''', (checkpoint_id,))
            
            await self._connection.commit()
            deleted = cursor.rowcount > 0
            
            if deleted:
                logger.debug(f"Deleted checkpoint {checkpoint_id}")
            
            return deleted
            
        except Exception as e:
            await self._connection.rollback()
            raise SqliteStorageException(f"Failed to delete checkpoint: {e}") from e
    
    async def get_latest_checkpoint(self, task_id: str) -> Optional[CheckpointInfo]:
        """Get the most recent checkpoint for a task."""
        await self._ensure_initialized()
        
        try:
            cursor = await self._connection.execute('''
                SELECT checkpoint_id, task_id, phase, timestamp,
                       progress_state, phase_data, metadata
                FROM checkpoints 
                WHERE task_id = ?
                ORDER BY timestamp DESC
                LIMIT 1
            ''', (task_id,))
            
            row = await cursor.fetchone()
            if not row:
                return None
            
            checkpoint_data = {
                'checkpoint_id': row[0],
                'task_id': row[1],
                'phase': row[2],
                'timestamp': row[3],
                'progress_state': json.loads(row[4]) if row[4] else None,
                'phase_data': json.loads(row[5]),
                'metadata': json.loads(row[6])
            }
            
            return CheckpointInfo.from_dict(checkpoint_data)
            
        except Exception as e:
            raise SqliteStorageException(f"Failed to get latest checkpoint: {e}") from e
    
    async def update_task_metadata(self, task_id: str, metadata: Dict[str, Any]) -> None:
        """Update task metadata."""
        await self._ensure_initialized()
        
        try:
            await self._connection.execute('''
                UPDATE progress_states 
                SET metadata = ?, updated_at = CURRENT_TIMESTAMP
                WHERE task_id = ?
            ''', (json.dumps(metadata), task_id))
            
            await self._connection.commit()
            logger.debug(f"Updated metadata for task {task_id}")
            
        except Exception as e:
            await self._connection.rollback()
            raise SqliteStorageException(f"Failed to update task metadata: {e}") from e
    
    async def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        await self._ensure_initialized()
        
        try:
            # Get task counts by status
            cursor = await self._connection.execute('''
                SELECT status, COUNT(*) FROM progress_states GROUP BY status
            ''')
            status_counts = {row[0]: row[1] for row in await cursor.fetchall()}
            
            # Get total checkpoint count
            cursor = await self._connection.execute('SELECT COUNT(*) FROM checkpoints')
            checkpoint_count = (await cursor.fetchone())[0]
            
            # Get database file size
            db_size = self.db_path.stat().st_size if self.db_path.exists() else 0
            
            return {
                'healthy': True,
                'status_counts': status_counts,
                'total_checkpoints': checkpoint_count,
                'database_size_bytes': db_size,
                'database_path': str(self.db_path)
            }
            
        except Exception as e:
            logger.error(f"Failed to get storage stats: {e}")
            return {
                'healthy': False,
                'error': str(e)
            }