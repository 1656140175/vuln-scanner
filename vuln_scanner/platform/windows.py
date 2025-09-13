"""Windows-specific utilities and compatibility layer."""

import os
import sys
import subprocess
import logging
from typing import Dict, Any, List, Optional, Union
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class WindowsUtils:
    """Windows-specific utility functions and system operations."""
    
    @staticmethod
    def is_windows() -> bool:
        """Check if running on Windows.
        
        Returns:
            bool: True if Windows
        """
        return sys.platform.startswith('win')
    
    @staticmethod
    def is_admin() -> bool:
        """Check if running with administrator privileges.
        
        Returns:
            bool: True if running as administrator
        """
        if not WindowsUtils.is_windows():
            return False
            
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception as e:
            logger.error(f"Failed to check admin status: {e}")
            return False
    
    @staticmethod
    def run_as_admin(command: Union[str, List[str]], wait: bool = True) -> Optional[int]:
        """Run command with administrator privileges.
        
        Args:
            command: Command to run
            wait: Wait for completion
            
        Returns:
            Return code if wait=True, None otherwise
        """
        if not WindowsUtils.is_windows():
            logger.error("run_as_admin only works on Windows")
            return None
            
        try:
            import ctypes
            from ctypes import wintypes
            
            if isinstance(command, list):
                cmd_str = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in command)
            else:
                cmd_str = command
            
            # Use ShellExecuteW to run as admin
            ret = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",  # Request elevation
                "cmd.exe",
                f"/c {cmd_str}",
                None,
                1  # SW_SHOW
            )
            
            if ret <= 32:
                logger.error(f"Failed to run command as admin: {ret}")
                return None
                
            # If wait is True, we can't easily get the return code
            # since ShellExecuteW doesn't wait
            return 0 if wait else None
            
        except Exception as e:
            logger.error(f"Failed to run as admin: {e}")
            return None
    
    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Get comprehensive Windows system information.
        
        Returns:
            Dict containing system information
        """
        if not WindowsUtils.is_windows():
            return {}
            
        system_info = {
            'platform': 'Windows',
            'admin_privileges': WindowsUtils.is_admin()
        }
        
        try:
            # Try to use wmi for detailed info
            import wmi
            c = wmi.WMI()
            
            # Operating system info
            for os_info in c.Win32_OperatingSystem():
                system_info.update({
                    'os_name': os_info.Caption,
                    'os_version': os_info.Version,
                    'os_build': os_info.BuildNumber,
                    'total_memory_kb': int(os_info.TotalVisibleMemorySize),
                    'available_memory_kb': int(os_info.FreePhysicalMemory),
                    'architecture': os_info.OSArchitecture
                })
                break
            
            # CPU info
            for cpu_info in c.Win32_Processor():
                system_info.update({
                    'cpu_name': cpu_info.Name.strip(),
                    'cpu_cores': cpu_info.NumberOfCores,
                    'cpu_threads': cpu_info.NumberOfLogicalProcessors,
                    'cpu_architecture': cpu_info.Architecture
                })
                break
            
            # GPU info
            gpu_list = []
            for gpu in c.Win32_VideoController():
                if gpu.Name:
                    gpu_list.append({
                        'name': gpu.Name,
                        'memory_mb': gpu.AdapterRAM // (1024*1024) if gpu.AdapterRAM else None
                    })
            system_info['gpus'] = gpu_list
            
        except ImportError:
            logger.warning("WMI not available, using basic system info")
            # Fallback to basic platform module
            import platform
            system_info.update({
                'os_name': platform.platform(),
                'os_version': platform.version(),
                'cpu_name': platform.processor(),
                'architecture': platform.machine()
            })
        except Exception as e:
            logger.error(f"Failed to get detailed system info: {e}")
        
        return system_info
    
    @staticmethod
    def setup_console_encoding():
        """Setup proper console encoding for Windows.
        
        This fixes Unicode display issues in Windows console.
        """
        if not WindowsUtils.is_windows():
            return
            
        try:
            # Set UTF-8 encoding for stdout/stderr
            import codecs
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
            sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
            
            # Set environment variable
            os.environ['PYTHONIOENCODING'] = 'utf-8'
            
            # Try to set console code page to UTF-8
            subprocess.run(['chcp', '65001'], 
                         capture_output=True, 
                         check=False)
            
            logger.debug("Windows console encoding configured for UTF-8")
            
        except Exception as e:
            logger.warning(f"Failed to setup console encoding: {e}")
    
    @staticmethod
    def add_to_windows_path(directory: str) -> bool:
        """Add directory to Windows PATH environment variable.
        
        Args:
            directory: Directory to add to PATH
            
        Returns:
            bool: True if successful
        """
        if not WindowsUtils.is_windows():
            return False
            
        try:
            current_path = os.environ.get('PATH', '')
            
            # Check if directory is already in PATH
            path_dirs = current_path.split(os.pathsep)
            normalized_dir = os.path.normpath(directory)
            
            for path_dir in path_dirs:
                if os.path.normpath(path_dir) == normalized_dir:
                    logger.debug(f"Directory {directory} already in PATH")
                    return True
            
            # Add to current session PATH
            new_path = f"{current_path}{os.pathsep}{directory}"
            os.environ['PATH'] = new_path
            
            logger.debug(f"Added {directory} to session PATH")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add {directory} to PATH: {e}")
            return False
    
    @staticmethod
    def add_windows_defender_exclusion(path: str) -> bool:
        """Add Windows Defender exclusion for a path.
        
        Args:
            path: Path to exclude from scanning
            
        Returns:
            bool: True if successful
        """
        if not WindowsUtils.is_windows():
            return False
            
        try:
            # Use PowerShell to add exclusion
            cmd = [
                'powershell.exe', 
                '-Command',
                f"Add-MpPreference -ExclusionPath '{path}'"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info(f"Added Windows Defender exclusion for {path}")
                return True
            else:
                logger.error(f"Failed to add exclusion: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Timeout adding Windows Defender exclusion")
            return False
        except Exception as e:
            logger.error(f"Failed to add Windows Defender exclusion: {e}")
            return False
    
    @staticmethod
    def get_windows_version() -> Dict[str, Any]:
        """Get detailed Windows version information.
        
        Returns:
            Dict with version details
        """
        if not WindowsUtils.is_windows():
            return {}
            
        try:
            import winreg
            
            # Read version from registry
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") as key:
                
                version_info = {}
                
                # Get various version fields
                fields = [
                    'ProductName', 'DisplayVersion', 'ReleaseId',
                    'CurrentBuild', 'UBR', 'InstallationType'
                ]
                
                for field in fields:
                    try:
                        value, _ = winreg.QueryValueEx(key, field)
                        version_info[field.lower()] = value
                    except FileNotFoundError:
                        pass
                
                return version_info
                
        except Exception as e:
            logger.error(f"Failed to get Windows version: {e}")
            return {}
    
    @staticmethod
    def check_required_features() -> Dict[str, bool]:
        """Check availability of Windows-specific features.
        
        Returns:
            Dict of feature availability
        """
        features = {
            'powershell': False,
            'wmi': False,
            'windows_defender': False,
            'admin_privileges': WindowsUtils.is_admin(),
            'long_path_support': False
        }
        
        if not WindowsUtils.is_windows():
            return features
        
        # Check PowerShell
        try:
            result = subprocess.run(
                ['powershell.exe', '-Command', 'Get-Host'],
                capture_output=True,
                timeout=10
            )
            features['powershell'] = result.returncode == 0
        except Exception:
            pass
        
        # Check WMI
        try:
            import wmi
            wmi.WMI()
            features['wmi'] = True
        except Exception:
            pass
        
        # Check Windows Defender
        try:
            result = subprocess.run(
                ['powershell.exe', '-Command', 'Get-MpComputerStatus'],
                capture_output=True,
                timeout=10
            )
            features['windows_defender'] = result.returncode == 0
        except Exception:
            pass
        
        # Check long path support
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\\CurrentControlSet\\Control\\FileSystem"
            ) as key:
                value, _ = winreg.QueryValueEx(key, "LongPathsEnabled")
                features['long_path_support'] = bool(value)
        except Exception:
            pass
        
        return features
    
    @staticmethod
    def create_junction(source: str, target: str) -> bool:
        """Create a Windows junction (directory symlink).
        
        Args:
            source: Source directory path
            target: Target junction path
            
        Returns:
            bool: True if successful
        """
        if not WindowsUtils.is_windows():
            return False
            
        try:
            cmd = ['mklink', '/J', target, source]
            
            result = subprocess.run(
                cmd,
                shell=True,  # mklink is a shell builtin
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.debug(f"Created junction {target} -> {source}")
                return True
            else:
                logger.error(f"Failed to create junction: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to create junction: {e}")
            return False
    
    @staticmethod
    def get_installed_programs() -> List[Dict[str, str]]:
        """Get list of installed programs on Windows.
        
        Returns:
            List of program information dicts
        """
        if not WindowsUtils.is_windows():
            return []
            
        programs = []
        
        try:
            import winreg
            
            # Check both 32-bit and 64-bit program locations
            registry_paths = [
                r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
            ]
            
            for registry_path in registry_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path) as key:
                        i = 0
                        while True:
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, subkey_name) as subkey:
                                    program_info = {}
                                    
                                    # Get program details
                                    fields = ['DisplayName', 'DisplayVersion', 'Publisher']
                                    for field in fields:
                                        try:
                                            value, _ = winreg.QueryValueEx(subkey, field)
                                            program_info[field.lower()] = value
                                        except FileNotFoundError:
                                            pass
                                    
                                    if program_info.get('displayname'):
                                        programs.append(program_info)
                                
                                i += 1
                                
                            except OSError:
                                break
                                
                except FileNotFoundError:
                    # Registry path doesn't exist
                    continue
                    
        except Exception as e:
            logger.error(f"Failed to get installed programs: {e}")
        
        return programs
    
    @staticmethod
    def install_chocolatey() -> bool:
        """Install Chocolatey package manager if not present.
        
        Returns:
            bool: True if successful or already installed
        """
        if not WindowsUtils.is_windows():
            return False
        
        # Check if already installed
        try:
            result = subprocess.run(
                ['choco', '--version'],
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.debug("Chocolatey already installed")
                return True
        except Exception:
            pass
        
        # Install Chocolatey
        try:
            install_script = '''
            Set-ExecutionPolicy Bypass -Scope Process -Force;
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
            iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            '''
            
            cmd = ['powershell.exe', '-Command', install_script]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode == 0:
                logger.info("Chocolatey installed successfully")
                return True
            else:
                logger.error(f"Failed to install Chocolatey: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Timeout installing Chocolatey")
            return False
        except Exception as e:
            logger.error(f"Failed to install Chocolatey: {e}")
            return False
    
    @staticmethod
    def setup_windows_environment(working_dir: str) -> Dict[str, Any]:
        """Setup Windows environment for vulnerability scanning.
        
        Args:
            working_dir: Working directory path
            
        Returns:
            Dict with setup results
        """
        results = {
            'success': True,
            'actions_taken': [],
            'warnings': [],
            'errors': []
        }
        
        if not WindowsUtils.is_windows():
            results['success'] = False
            results['errors'].append("Not running on Windows")
            return results
        
        try:
            # Setup console encoding
            WindowsUtils.setup_console_encoding()
            results['actions_taken'].append("Configured console encoding")
            
            # Add Windows Defender exclusion for working directory
            if WindowsUtils.add_windows_defender_exclusion(working_dir):
                results['actions_taken'].append(f"Added Defender exclusion for {working_dir}")
            else:
                results['warnings'].append("Could not add Windows Defender exclusion")
            
            # Check admin privileges
            if not WindowsUtils.is_admin():
                results['warnings'].append("Running without administrator privileges")
            
            # Check required features
            features = WindowsUtils.check_required_features()
            missing_features = [k for k, v in features.items() if not v and k != 'admin_privileges']
            
            if missing_features:
                results['warnings'].append(f"Missing features: {', '.join(missing_features)}")
            
            logger.info("Windows environment setup completed")
            
        except Exception as e:
            logger.error(f"Windows environment setup failed: {e}")
            results['success'] = False
            results['errors'].append(str(e))
        
        return results