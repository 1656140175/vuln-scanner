"""Google Colab-specific utilities and environment support."""

import os
import sys
import subprocess
import logging
from typing import Dict, Any, List, Optional, Union
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class ColabUtils:
    """Google Colab-specific utility functions and environment setup."""
    
    @staticmethod
    def is_colab() -> bool:
        """Check if running in Google Colab environment.
        
        Returns:
            bool: True if running in Colab
        """
        try:
            import google.colab  # noqa: F401
            return True
        except ImportError:
            pass
        
        # Check environment variables
        colab_indicators = [
            'COLAB_GPU',
            'COLAB_RELEASE_TAG',
            'COLAB_JUPYTER_IP'
        ]
        
        return any(indicator in os.environ for indicator in colab_indicators)
    
    @staticmethod
    def get_colab_info() -> Dict[str, Any]:
        """Get Colab environment information.
        
        Returns:
            Dict containing Colab environment details
        """
        info = {
            'is_colab': ColabUtils.is_colab(),
            'gpu_available': False,
            'tpu_available': False,
            'drive_mounted': False,
            'pro_features': False
        }
        
        if not ColabUtils.is_colab():
            return info
        
        try:
            # Check GPU availability
            import torch
            info['gpu_available'] = torch.cuda.is_available()
            if info['gpu_available']:
                info['gpu_name'] = torch.cuda.get_device_name(0)
                info['gpu_memory'] = torch.cuda.get_device_properties(0).total_memory
        except ImportError:
            pass
        
        try:
            # Check TPU availability
            import tensorflow as tf
            tpu_devices = tf.config.experimental.list_physical_devices('TPU')
            info['tpu_available'] = len(tpu_devices) > 0
        except ImportError:
            pass
        
        # Check if Google Drive is mounted
        info['drive_mounted'] = os.path.exists('/content/drive')
        
        # Check for Colab Pro features (more RAM/faster GPU)
        try:
            import psutil
            total_ram = psutil.virtual_memory().total // (1024**3)  # GB
            info['total_ram_gb'] = total_ram
            info['pro_features'] = total_ram > 13  # Regular Colab has ~12.7GB
        except ImportError:
            pass
        
        return info
    
    @staticmethod
    def setup_colab_environment(mount_drive: bool = True, 
                               install_system_deps: bool = True) -> Dict[str, Any]:
        """Setup Google Colab environment for vulnerability scanning.
        
        Args:
            mount_drive: Whether to mount Google Drive
            install_system_deps: Whether to install system dependencies
            
        Returns:
            Dict with setup results
        """
        results = {
            'success': True,
            'actions_taken': [],
            'warnings': [],
            'errors': []
        }
        
        if not ColabUtils.is_colab():
            results['success'] = False
            results['errors'].append("Not running in Google Colab")
            return results
        
        try:
            # Mount Google Drive if requested
            if mount_drive:
                if ColabUtils.mount_drive():
                    results['actions_taken'].append("Google Drive mounted")
                else:
                    results['warnings'].append("Failed to mount Google Drive")
            
            # Setup display options for Colab
            ColabUtils.setup_display()
            results['actions_taken'].append("Display options configured")
            
            # Install system dependencies
            if install_system_deps:
                if ColabUtils.install_system_dependencies():
                    results['actions_taken'].append("System dependencies installed")
                else:
                    results['warnings'].append("Some system dependencies failed to install")
            
            # Create working directories
            working_dirs = [
                '/content/vuln_scanner_data',
                '/content/vuln_scanner_output',
                '/content/vuln_scanner_logs'
            ]
            
            for directory in working_dirs:
                os.makedirs(directory, exist_ok=True)
                results['actions_taken'].append(f"Created directory {directory}")
            
            logger.info("Colab environment setup completed")
            
        except Exception as e:
            logger.error(f"Colab environment setup failed: {e}")
            results['success'] = False
            results['errors'].append(str(e))
        
        return results
    
    @staticmethod
    def mount_drive() -> bool:
        """Mount Google Drive in Colab.
        
        Returns:
            bool: True if successful
        """
        if not ColabUtils.is_colab():
            return False
        
        try:
            from google.colab import drive
            drive.mount('/content/drive')
            
            # Verify mount was successful
            if os.path.exists('/content/drive/MyDrive'):
                logger.info("Google Drive mounted successfully")
                return True
            else:
                logger.error("Google Drive mount verification failed")
                return False
                
        except Exception as e:
            logger.error(f"Failed to mount Google Drive: {e}")
            return False
    
    @staticmethod
    def setup_display() -> None:
        """Setup display options and styling for Colab notebooks."""
        if not ColabUtils.is_colab():
            return
        
        try:
            from IPython.display import HTML, display
            import pandas as pd
            
            # Configure pandas display options
            pd.set_option('display.max_columns', None)
            pd.set_option('display.width', None)
            pd.set_option('display.max_colwidth', 100)
            pd.set_option('display.precision', 3)
            
            # Load custom CSS for better display
            css = '''
            <style>
            .vuln-scanner-progress {
                width: 100%;
                height: 20px;
                background-color: #f0f0f0;
                border-radius: 10px;
                overflow: hidden;
                margin: 10px 0;
            }
            .vuln-scanner-progress-fill {
                height: 100%;
                background: linear-gradient(90deg, #4CAF50, #45a049);
                transition: width 0.3s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: bold;
                font-size: 12px;
            }
            .vuln-scanner-info {
                background: #e3f2fd;
                border-left: 4px solid #2196f3;
                padding: 10px;
                margin: 10px 0;
                border-radius: 4px;
            }
            .vuln-scanner-warning {
                background: #fff3e0;
                border-left: 4px solid #ff9800;
                padding: 10px;
                margin: 10px 0;
                border-radius: 4px;
            }
            .vuln-scanner-error {
                background: #ffebee;
                border-left: 4px solid #f44336;
                padding: 10px;
                margin: 10px 0;
                border-radius: 4px;
            }
            .vuln-scanner-success {
                background: #e8f5e8;
                border-left: 4px solid #4caf50;
                padding: 10px;
                margin: 10px 0;
                border-radius: 4px;
            }
            </style>
            '''
            
            display(HTML(css))
            logger.debug("Colab display options configured")
            
        except Exception as e:
            logger.warning(f"Failed to setup display options: {e}")
    
    @staticmethod
    def install_system_dependencies() -> bool:
        """Install required system dependencies in Colab.
        
        Returns:
            bool: True if all installations succeeded
        """
        if not ColabUtils.is_colab():
            return False
        
        # List of required system packages
        system_packages = [
            'chromium-browser',
            'chromium-chromedriver', 
            'fonts-liberation',
            'libasound2',
            'libatk-bridge2.0-0',
            'libdrm2',
            'libgtk-3-0',
            'libnspr4',
            'libnss3',
            'libxss1',
            'libxtst6',
            'xdg-utils',
            'wget',
            'curl',
            'unzip',
            'git'
        ]
        
        success = True
        
        try:
            # Update package list
            logger.info("Updating package list...")
            result = subprocess.run(
                ['apt-get', 'update', '-qq'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                logger.warning(f"Package update had issues: {result.stderr}")
            
            # Install packages
            logger.info("Installing system dependencies...")
            cmd = ['apt-get', 'install', '-y', '-qq'] + system_packages
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode == 0:
                logger.info("System dependencies installed successfully")
            else:
                logger.error(f"Failed to install some dependencies: {result.stderr}")
                success = False
            
        except subprocess.TimeoutExpired:
            logger.error("Timeout installing system dependencies")
            success = False
        except Exception as e:
            logger.error(f"Error installing system dependencies: {e}")
            success = False
        
        return success
    
    @staticmethod
    def create_progress_widget(total: int, description: str = "Progress") -> Optional[str]:
        """Create an interactive progress bar widget.
        
        Args:
            total: Total number of items
            description: Progress description
            
        Returns:
            Progress bar ID for updates, None if failed
        """
        if not ColabUtils.is_colab():
            return None
        
        try:
            from IPython.display import HTML, display
            import uuid
            
            bar_id = f"progress_{uuid.uuid4().hex[:8]}"
            
            html = f'''
            <div class="vuln-scanner-info">
                <div style="font-weight: bold; margin-bottom: 10px;">{description}</div>
                <div class="vuln-scanner-progress" id="{bar_id}_container">
                    <div id="{bar_id}" class="vuln-scanner-progress-fill" style="width: 0%;">
                        0%
                    </div>
                </div>
                <div id="{bar_id}_text" style="margin-top: 5px; font-size: 12px; color: #666;">
                    0 / {total} items completed
                </div>
            </div>
            '''
            
            display(HTML(html))
            return bar_id
            
        except Exception as e:
            logger.warning(f"Failed to create progress widget: {e}")
            return None
    
    @staticmethod
    def update_progress_widget(bar_id: str, current: int, total: int, 
                             message: str = "") -> None:
        """Update progress bar widget.
        
        Args:
            bar_id: Progress bar ID
            current: Current progress
            total: Total items
            message: Optional status message
        """
        if not bar_id or not ColabUtils.is_colab():
            return
        
        try:
            from IPython.display import Javascript, display
            
            percentage = min(100, (current / total) * 100) if total > 0 else 0
            status_text = f"{current} / {total} items completed"
            
            if message:
                status_text += f" - {message}"
            
            js_code = f'''
            try {{
                const progressBar = document.getElementById('{bar_id}');
                const textElement = document.getElementById('{bar_id}_text');
                
                if (progressBar) {{
                    progressBar.style.width = '{percentage}%';
                    progressBar.innerHTML = '{percentage:.1f}%';
                }}
                
                if (textElement) {{
                    textElement.innerHTML = '{status_text}';
                }}
            }} catch (e) {{
                console.log('Progress update error:', e);
            }}
            '''
            
            display(Javascript(js_code))
            
        except Exception as e:
            logger.warning(f"Failed to update progress widget: {e}")
    
    @staticmethod
    def display_message(message: str, msg_type: str = "info") -> None:
        """Display a styled message in Colab.
        
        Args:
            message: Message to display
            msg_type: Message type (info, warning, error, success)
        """
        if not ColabUtils.is_colab():
            print(f"[{msg_type.upper()}] {message}")
            return
        
        try:
            from IPython.display import HTML, display
            
            css_class = f"vuln-scanner-{msg_type}"
            icons = {
                'info': 'ℹ️',
                'warning': '⚠️',
                'error': '❌',
                'success': '✅'
            }
            
            icon = icons.get(msg_type, 'ℹ️')
            
            html = f'''
            <div class="{css_class}">
                <strong>{icon} {msg_type.upper()}</strong><br>
                {message}
            </div>
            '''
            
            display(HTML(html))
            
        except Exception as e:
            logger.warning(f"Failed to display message: {e}")
            print(f"[{msg_type.upper()}] {message}")
    
    @staticmethod
    def install_python_packages(packages: List[str]) -> Dict[str, bool]:
        """Install Python packages in Colab using pip.
        
        Args:
            packages: List of package specifications
            
        Returns:
            Dict mapping package names to installation success
        """
        results = {}
        
        if not ColabUtils.is_colab():
            logger.warning("install_python_packages should only be used in Colab")
        
        for package in packages:
            try:
                # Show installation message
                ColabUtils.display_message(f"Installing {package}...", "info")
                
                cmd = [sys.executable, '-m', 'pip', 'install', '--quiet', package]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                results[package] = result.returncode == 0
                
                if result.returncode == 0:
                    logger.debug(f"Successfully installed {package}")
                else:
                    logger.error(f"Failed to install {package}: {result.stderr}")
                    ColabUtils.display_message(f"Failed to install {package}", "warning")
                    
            except subprocess.TimeoutExpired:
                logger.error(f"Timeout installing {package}")
                results[package] = False
                ColabUtils.display_message(f"Timeout installing {package}", "error")
            except Exception as e:
                logger.error(f"Error installing {package}: {e}")
                results[package] = False
                ColabUtils.display_message(f"Error installing {package}: {e}", "error")
        
        return results
    
    @staticmethod
    def check_colab_limits() -> Dict[str, Any]:
        """Check current Colab resource usage and limits.
        
        Returns:
            Dict with resource information
        """
        limits = {
            'cpu_usage': 0,
            'memory_usage_gb': 0,
            'memory_total_gb': 0,
            'disk_usage_gb': 0,
            'disk_total_gb': 0,
            'session_time_hours': 0,
            'gpu_memory_used_gb': 0,
            'gpu_memory_total_gb': 0
        }
        
        if not ColabUtils.is_colab():
            return limits
        
        try:
            import psutil
            
            # CPU usage
            limits['cpu_usage'] = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            limits['memory_usage_gb'] = round((memory.total - memory.available) / (1024**3), 2)
            limits['memory_total_gb'] = round(memory.total / (1024**3), 2)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            limits['disk_usage_gb'] = round((disk.total - disk.free) / (1024**3), 2)
            limits['disk_total_gb'] = round(disk.total / (1024**3), 2)
            
            # Session time (approximate)
            import time
            uptime = time.time() - psutil.boot_time()
            limits['session_time_hours'] = round(uptime / 3600, 2)
            
        except ImportError:
            logger.warning("psutil not available for resource monitoring")
        
        # GPU memory usage
        try:
            import torch
            if torch.cuda.is_available():
                gpu_memory = torch.cuda.get_device_properties(0).total_memory
                gpu_allocated = torch.cuda.memory_allocated(0)
                
                limits['gpu_memory_total_gb'] = round(gpu_memory / (1024**3), 2)
                limits['gpu_memory_used_gb'] = round(gpu_allocated / (1024**3), 2)
                
        except ImportError:
            pass
        
        return limits
    
    @staticmethod
    def save_to_drive(local_path: str, drive_path: str = None) -> bool:
        """Save file or directory to Google Drive.
        
        Args:
            local_path: Local file/directory path
            drive_path: Target path in Drive (auto-generated if None)
            
        Returns:
            bool: True if successful
        """
        if not ColabUtils.is_colab():
            return False
        
        if not os.path.exists('/content/drive'):
            logger.error("Google Drive not mounted")
            return False
        
        try:
            if drive_path is None:
                # Auto-generate drive path
                filename = os.path.basename(local_path)
                drive_path = f'/content/drive/MyDrive/vuln_scanner_output/{filename}'
            
            # Ensure target directory exists
            target_dir = os.path.dirname(drive_path)
            os.makedirs(target_dir, exist_ok=True)
            
            # Copy to drive
            import shutil
            if os.path.isfile(local_path):
                shutil.copy2(local_path, drive_path)
            else:
                shutil.copytree(local_path, drive_path, dirs_exist_ok=True)
            
            logger.info(f"Saved to Google Drive: {drive_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save to Drive: {e}")
            return False