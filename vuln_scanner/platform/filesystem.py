"""Cross-platform filesystem operations and path management."""

import os
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Union, List
import logging
from .detector import PlatformInfo, PlatformType

logger = logging.getLogger(__name__)


class FileSystemAdapter:
    """Cross-platform file system operations adapter."""
    
    def __init__(self, platform_info: PlatformInfo):
        """Initialize filesystem adapter.
        
        Args:
            platform_info: Platform information
        """
        self.platform_info = platform_info
        self.path_separator = self._get_path_separator()
        self.max_path_length = self._get_max_path_length()
    
    def _get_path_separator(self) -> str:
        """Get platform-appropriate path separator.
        
        Returns:
            str: Path separator for the platform
        """
        if self.platform_info.platform_type == PlatformType.WINDOWS:
            return "\\\\"
        return "/"
    
    def _get_max_path_length(self) -> int:
        """Get maximum path length for the platform.
        
        Returns:
            int: Maximum path length
        """
        if self.platform_info.platform_type == PlatformType.WINDOWS:
            return 260  # Windows traditional limit
        return 4096  # Unix-like systems
    
    def normalize_path(self, path: Union[str, Path]) -> str:
        """Normalize path for the current platform.
        
        Args:
            path: Path to normalize
            
        Returns:
            str: Normalized path
        """
        # Convert to string if Path object
        path_str = str(path)
        
        # Normalize path separators
        if self.platform_info.platform_type == PlatformType.WINDOWS:
            normalized = path_str.replace('/', '\\\\')
        else:
            normalized = path_str.replace('\\\\', '/')
        
        # Handle Windows long path limitation
        if self.platform_info.platform_type == PlatformType.WINDOWS:
            if len(normalized) > self.max_path_length:
                # Use long path prefix for Windows
                if not normalized.startswith('\\\\\\\\?\\\\'):
                    abs_path = os.path.abspath(normalized)
                    normalized = f'\\\\\\\\?\\\\{abs_path}'
        
        return normalized
    
    def safe_path_join(self, *parts: str) -> str:
        """Safely join path components.
        
        Args:
            *parts: Path components to join
            
        Returns:
            str: Joined and normalized path
        """
        # Use pathlib for cross-platform joining
        path = Path()
        for part in parts:
            if part:
                path = path / part
        
        return self.normalize_path(path)
    
    def create_directory(self, path: Union[str, Path], mode: int = 0o755, 
                        parents: bool = True, exist_ok: bool = True) -> bool:
        """Create directory with proper permissions.
        
        Args:
            path: Directory path to create
            mode: Directory permissions (Unix only)
            parents: Create parent directories
            exist_ok: Don't raise error if directory exists
            
        Returns:
            bool: True if successful
        """
        try:
            normalized_path = self.normalize_path(path)
            
            if self.platform_info.platform_type == PlatformType.WINDOWS:
                # Windows doesn't use Unix-style permissions
                os.makedirs(normalized_path, exist_ok=exist_ok)
            else:
                os.makedirs(normalized_path, mode=mode, exist_ok=exist_ok)
            
            logger.debug(f"Created directory: {normalized_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create directory {path}: {e}")
            return False
    
    def safe_remove(self, path: Union[str, Path], recursive: bool = False) -> bool:
        """Safely remove file or directory.
        
        Args:
            path: Path to remove
            recursive: Remove directory recursively
            
        Returns:
            bool: True if successful
        """
        try:
            normalized_path = self.normalize_path(path)
            
            if not os.path.exists(normalized_path):
                return True
            
            if os.path.isfile(normalized_path):
                # Handle read-only files on Windows
                if self.platform_info.platform_type == PlatformType.WINDOWS:
                    os.chmod(normalized_path, 0o777)
                os.remove(normalized_path)
            elif os.path.isdir(normalized_path) and recursive:
                if self.platform_info.platform_type == PlatformType.WINDOWS:
                    # Handle Windows-specific removal issues
                    self._remove_directory_windows(normalized_path)
                else:
                    shutil.rmtree(normalized_path)
            
            logger.debug(f"Removed: {normalized_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove {path}: {e}")
            return False
    
    def _remove_directory_windows(self, path: str) -> None:
        """Windows-specific directory removal.
        
        Args:
            path: Directory path to remove
        """
        def handle_remove_readonly(func, path, exc):
            """Handle read-only files during removal."""
            if os.path.exists(path):
                os.chmod(path, 0o777)
                func(path)
        
        shutil.rmtree(path, onerror=handle_remove_readonly)
    
    def get_temp_file(self, suffix: str = "", prefix: str = "vuln_", 
                     directory: Optional[str] = None, delete: bool = True) -> str:
        """Get temporary file path.
        
        Args:
            suffix: File suffix
            prefix: File prefix
            directory: Temp directory (uses system default if None)
            delete: Whether to delete file when closed
            
        Returns:
            str: Temporary file path
        """
        temp_dir = directory or self.platform_info.temp_directory
        
        try:
            fd, path = tempfile.mkstemp(
                suffix=suffix, 
                prefix=prefix, 
                dir=temp_dir
            )
            os.close(fd)
            
            if delete:
                # Register for cleanup
                import atexit
                atexit.register(lambda: self.safe_remove(path))
            
            return self.normalize_path(path)
            
        except Exception as e:
            logger.error(f"Failed to create temp file: {e}")
            # Fallback
            import uuid
            filename = f"{prefix}{uuid.uuid4().hex[:8]}{suffix}"
            return self.safe_path_join(temp_dir, filename)
    
    def get_temp_directory(self, prefix: str = "vuln_", 
                          parent: Optional[str] = None) -> str:
        """Get temporary directory path.
        
        Args:
            prefix: Directory prefix
            parent: Parent directory (uses system temp if None)
            
        Returns:
            str: Temporary directory path
        """
        parent_dir = parent or self.platform_info.temp_directory
        
        try:
            path = tempfile.mkdtemp(prefix=prefix, dir=parent_dir)
            
            # Register for cleanup
            import atexit
            atexit.register(lambda: self.safe_remove(path, recursive=True))
            
            return self.normalize_path(path)
            
        except Exception as e:
            logger.error(f"Failed to create temp directory: {e}")
            # Fallback
            import uuid
            dirname = f"{prefix}{uuid.uuid4().hex[:8]}"
            path = self.safe_path_join(parent_dir, dirname)
            self.create_directory(path)
            return path
    
    def safe_copy(self, src: Union[str, Path], dst: Union[str, Path], 
                 preserve_metadata: bool = True) -> bool:
        """Safely copy file or directory.
        
        Args:
            src: Source path
            dst: Destination path
            preserve_metadata: Preserve file metadata
            
        Returns:
            bool: True if successful
        """
        try:
            src_path = self.normalize_path(src)
            dst_path = self.normalize_path(dst)
            
            # Ensure destination directory exists
            dst_dir = os.path.dirname(dst_path)
            self.create_directory(dst_dir)
            
            if os.path.isfile(src_path):
                if preserve_metadata:
                    shutil.copy2(src_path, dst_path)
                else:
                    shutil.copy(src_path, dst_path)
            elif os.path.isdir(src_path):
                if preserve_metadata:
                    shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
                else:
                    shutil.copytree(src_path, dst_path, 
                                  copy_function=shutil.copy, dirs_exist_ok=True)
            
            logger.debug(f"Copied {src_path} to {dst_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to copy {src} to {dst}: {e}")
            return False
    
    def safe_write(self, path: Union[str, Path], content: Union[str, bytes], 
                  encoding: str = 'utf-8', backup: bool = False) -> bool:
        """Safely write content to file.
        
        Args:
            path: File path
            content: Content to write
            encoding: Text encoding (for string content)
            backup: Create backup of existing file
            
        Returns:
            bool: True if successful
        """
        try:
            normalized_path = self.normalize_path(path)
            
            # Create backup if requested and file exists
            if backup and os.path.exists(normalized_path):
                backup_path = f"{normalized_path}.bak"
                self.safe_copy(normalized_path, backup_path)
            
            # Ensure directory exists
            directory = os.path.dirname(normalized_path)
            self.create_directory(directory)
            
            # Write content
            if isinstance(content, bytes):
                with open(normalized_path, 'wb') as f:
                    f.write(content)
            else:
                with open(normalized_path, 'w', encoding=encoding) as f:
                    f.write(content)
            
            logger.debug(f"Wrote file: {normalized_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to write file {path}: {e}")
            return False
    
    def safe_read(self, path: Union[str, Path], encoding: str = 'utf-8', 
                 binary: bool = False) -> Optional[Union[str, bytes]]:
        """Safely read file content.
        
        Args:
            path: File path
            encoding: Text encoding (for text mode)
            binary: Read in binary mode
            
        Returns:
            File content or None if failed
        """
        try:
            normalized_path = self.normalize_path(path)
            
            if not os.path.exists(normalized_path):
                logger.warning(f"File not found: {normalized_path}")
                return None
            
            if binary:
                with open(normalized_path, 'rb') as f:
                    return f.read()
            else:
                with open(normalized_path, 'r', encoding=encoding) as f:
                    return f.read()
                    
        except Exception as e:
            logger.error(f"Failed to read file {path}: {e}")
            return None
    
    def get_available_space(self, path: Union[str, Path]) -> int:
        """Get available disk space in bytes.
        
        Args:
            path: Path to check
            
        Returns:
            int: Available space in bytes, -1 if unknown
        """
        try:
            normalized_path = self.normalize_path(path)
            
            if self.platform_info.platform_type == PlatformType.WINDOWS:
                import ctypes
                free_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(normalized_path), 
                    ctypes.pointer(free_bytes), 
                    None, 
                    None
                )
                return free_bytes.value
            else:
                # Unix-like systems
                statvfs = os.statvfs(normalized_path)
                return statvfs.f_frsize * statvfs.f_bavail
                
        except Exception as e:
            logger.error(f"Failed to get disk space for {path}: {e}")
            return -1
    
    def is_path_safe(self, path: Union[str, Path]) -> bool:
        """Check if path is safe to use (no path traversal, etc.).
        
        Args:
            path: Path to validate
            
        Returns:
            bool: True if path is safe
        """
        try:
            normalized_path = self.normalize_path(path)
            resolved_path = os.path.realpath(normalized_path)
            
            # Check for path traversal attempts
            dangerous_patterns = ['..', '~', '$']
            path_str = str(path).lower()
            
            for pattern in dangerous_patterns:
                if pattern in path_str:
                    logger.warning(f"Potentially unsafe path pattern '{pattern}' in {path}")
                    return False
            
            # Check path length
            if len(resolved_path) > self.max_path_length:
                if self.platform_info.platform_type != PlatformType.WINDOWS:
                    # Only Windows gets special handling for long paths
                    logger.warning(f"Path too long: {len(resolved_path)} > {self.max_path_length}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to validate path {path}: {e}")
            return False
    
    def get_directory_size(self, path: Union[str, Path]) -> int:
        """Get total size of directory in bytes.
        
        Args:
            path: Directory path
            
        Returns:
            int: Total size in bytes, -1 if failed
        """
        try:
            normalized_path = self.normalize_path(path)
            total_size = 0
            
            for dirpath, dirnames, filenames in os.walk(normalized_path):
                for filename in filenames:
                    file_path = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(file_path)
                    except (OSError, FileNotFoundError):
                        # Skip files we can't access
                        continue
            
            return total_size
            
        except Exception as e:
            logger.error(f"Failed to calculate directory size for {path}: {e}")
            return -1
    
    def list_directory(self, path: Union[str, Path], 
                      include_hidden: bool = False) -> List[str]:
        """List directory contents safely.
        
        Args:
            path: Directory path
            include_hidden: Include hidden files/directories
            
        Returns:
            List of file/directory names
        """
        try:
            normalized_path = self.normalize_path(path)
            
            if not os.path.isdir(normalized_path):
                return []
            
            items = []
            for item in os.listdir(normalized_path):
                # Skip hidden files unless requested
                if not include_hidden and item.startswith('.'):
                    continue
                items.append(item)
            
            return sorted(items)
            
        except Exception as e:
            logger.error(f"Failed to list directory {path}: {e}")
            return []