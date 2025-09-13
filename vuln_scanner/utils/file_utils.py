"""File utility functions for VulnMiner system."""

import os
import json
from pathlib import Path
from typing import Any, Dict, Optional, Union
import tempfile
import shutil

from ..core.exceptions import FileSystemError


def ensure_directory(path: Union[str, Path], mode: int = 0o755) -> Path:
    """Ensure directory exists, creating it if necessary.
    
    Args:
        path: Directory path to ensure
        mode: Directory permissions (default: 0o755)
        
    Returns:
        Path object for the directory
        
    Raises:
        FileSystemError: If directory cannot be created
    """
    path_obj = Path(path)
    
    try:
        path_obj.mkdir(parents=True, exist_ok=True, mode=mode)
        return path_obj
    except OSError as e:
        raise FileSystemError(
            operation="create_directory",
            file_path=str(path_obj),
            system_error=str(e),
            suggestion="Check permissions and disk space"
        )


def safe_write_file(file_path: Union[str, Path], content: str, 
                   encoding: str = 'utf-8', backup: bool = True) -> bool:
    """Safely write content to file with backup and atomic operation.
    
    Args:
        file_path: Path to file to write
        content: Content to write
        encoding: File encoding (default: utf-8)
        backup: Whether to create backup of existing file
        
    Returns:
        True if write was successful
        
    Raises:
        FileSystemError: If write operation fails
    """
    file_path = Path(file_path)
    
    try:
        # Ensure parent directory exists
        ensure_directory(file_path.parent)
        
        # Create backup if file exists
        if backup and file_path.exists():
            backup_path = file_path.with_suffix(f'{file_path.suffix}.backup')
            shutil.copy2(file_path, backup_path)
        
        # Write to temporary file first (atomic operation)
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding=encoding,
            dir=file_path.parent,
            delete=False,
            prefix=f'.{file_path.name}.'
        ) as temp_file:
            temp_file.write(content)
            temp_path = Path(temp_file.name)
        
        # Move temporary file to final location
        shutil.move(str(temp_path), str(file_path))
        
        return True
        
    except Exception as e:
        # Clean up temporary file if it exists
        if 'temp_path' in locals() and temp_path.exists():
            try:
                temp_path.unlink()
            except:
                pass
        
        raise FileSystemError(
            operation="write_file",
            file_path=str(file_path),
            system_error=str(e),
            suggestion="Check file permissions and disk space"
        )


def safe_read_file(file_path: Union[str, Path], encoding: str = 'utf-8') -> str:
    """Safely read content from file.
    
    Args:
        file_path: Path to file to read
        encoding: File encoding (default: utf-8)
        
    Returns:
        File content as string
        
    Raises:
        FileSystemError: If read operation fails
    """
    file_path = Path(file_path)
    
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            return f.read()
    except Exception as e:
        raise FileSystemError(
            operation="read_file",
            file_path=str(file_path),
            system_error=str(e),
            suggestion="Check if file exists and has read permissions"
        )


def safe_write_json(file_path: Union[str, Path], data: Dict[str, Any], 
                   indent: int = 2, backup: bool = True) -> bool:
    """Safely write JSON data to file.
    
    Args:
        file_path: Path to JSON file
        data: Data to write as JSON
        indent: JSON indentation (default: 2)
        backup: Whether to create backup
        
    Returns:
        True if write was successful
        
    Raises:
        FileSystemError: If write operation fails
    """
    try:
        json_content = json.dumps(data, indent=indent, ensure_ascii=False)
        return safe_write_file(file_path, json_content, backup=backup)
    except (TypeError, ValueError) as e:
        raise FileSystemError(
            operation="write_json",
            file_path=str(file_path),
            system_error=f"JSON serialization error: {e}",
            suggestion="Check data structure for JSON compatibility"
        )


def safe_read_json(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Safely read JSON data from file.
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        Parsed JSON data
        
    Raises:
        FileSystemError: If read operation fails
    """
    try:
        content = safe_read_file(file_path)
        return json.loads(content)
    except json.JSONDecodeError as e:
        raise FileSystemError(
            operation="read_json",
            file_path=str(file_path),
            system_error=f"JSON parse error: {e}",
            suggestion="Check JSON file syntax and format"
        )


def get_file_size(file_path: Union[str, Path]) -> int:
    """Get file size in bytes.
    
    Args:
        file_path: Path to file
        
    Returns:
        File size in bytes
        
    Raises:
        FileSystemError: If file access fails
    """
    file_path = Path(file_path)
    
    try:
        return file_path.stat().st_size
    except OSError as e:
        raise FileSystemError(
            operation="get_file_size",
            file_path=str(file_path),
            system_error=str(e),
            suggestion="Check if file exists and is accessible"
        )


def is_writable(path: Union[str, Path]) -> bool:
    """Check if path is writable.
    
    Args:
        path: Path to check
        
    Returns:
        True if writable, False otherwise
    """
    try:
        path = Path(path)
        if path.is_file():
            return os.access(path, os.W_OK)
        elif path.is_dir():
            # Try creating a temporary file
            test_file = path / '.write_test'
            try:
                test_file.touch()
                test_file.unlink()
                return True
            except:
                return False
        else:
            # Path doesn't exist, check parent directory
            return is_writable(path.parent) if path.parent != path else False
    except:
        return False


def cleanup_temp_files(directory: Union[str, Path], 
                      pattern: str = '.tmp_*', 
                      max_age_hours: int = 24) -> int:
    """Clean up temporary files older than specified age.
    
    Args:
        directory: Directory to clean
        pattern: File pattern to match (glob)
        max_age_hours: Maximum age in hours
        
    Returns:
        Number of files cleaned up
    """
    import time
    import glob
    
    directory = Path(directory)
    if not directory.exists():
        return 0
    
    current_time = time.time()
    max_age_seconds = max_age_hours * 3600
    cleaned_count = 0
    
    try:
        for file_path in directory.glob(pattern):
            if file_path.is_file():
                file_age = current_time - file_path.stat().st_mtime
                if file_age > max_age_seconds:
                    try:
                        file_path.unlink()
                        cleaned_count += 1
                    except OSError:
                        # Ignore errors when deleting individual files
                        pass
    except Exception:
        # Ignore errors during cleanup
        pass
    
    return cleaned_count