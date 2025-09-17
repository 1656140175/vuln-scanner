#!/usr/bin/env python3
"""
Tool Installation Helper for VulnMiner
Automatically installs security tools based on platform detection.
"""

import os
import sys
import asyncio
import subprocess
import platform as system_platform
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# Add vuln_scanner to path and import modules
vuln_scanner_path = Path(__file__).parent / "vuln_scanner"
sys.path.insert(0, str(vuln_scanner_path))

try:
    # Import using absolute paths to avoid conflicts with built-in platform module
    import importlib.util
    
    # Load PlatformDetector
    detector_spec = importlib.util.spec_from_file_location(
        "platform_detector", 
        vuln_scanner_path / "platform" / "detector.py"
    )
    detector_module = importlib.util.module_from_spec(detector_spec)
    detector_spec.loader.exec_module(detector_module)
    PlatformDetector = detector_module.PlatformDetector
    
    # Load ToolRegistry  
    registry_spec = importlib.util.spec_from_file_location(
        "tool_registry",
        vuln_scanner_path / "tools" / "registry.py"  
    )
    registry_module = importlib.util.module_from_spec(registry_spec)
    registry_spec.loader.exec_module(registry_module)
    ToolRegistry = registry_module.ToolRegistry
    
except ImportError as e:
    print(f"❌ 导入错误: {e}")
    print("请确保在vuln_miner根目录下运行此脚本")
    sys.exit(1)


class ToolInstaller:
    """Automated security tools installer."""
    
    def __init__(self):
        self.platform_detector = PlatformDetector()
        self.registry = ToolRegistry()
        self.platform_info = self.platform_detector.detect_platform()
        
    def _run_command(self, cmd: List[str], timeout: int = 300) -> Tuple[bool, str, str]:
        """Run system command and return success status and output."""
        try:
            print(f"🔧 Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def _check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is already installed."""
        return shutil.which(tool_name) is not None
    
    def _check_dependency(self, dep: str) -> bool:
        """Check if a dependency is available."""
        if dep == "go":
            return shutil.which("go") is not None
        elif dep == "python3":
            return shutil.which("python3") is not None or shutil.which("python") is not None
        elif dep == "git":
            return shutil.which("git") is not None
        return True
    
    def install_go_tools(self) -> Dict[str, bool]:
        """Install Go-based security tools."""
        results = {}
        
        go_tools = [
            ("nuclei", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"),
            ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
            ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
            ("gobuster", "github.com/OJ/gobuster/v3@latest"),
            ("ffuf", "github.com/ffuf/ffuf/v2@latest")
        ]
        
        # Check if Go is installed
        if not self._check_dependency("go"):
            print("❌ Go is not installed. Please install Go first:")
            print("   Windows: choco install golang")
            print("   Ubuntu/Debian: sudo apt install golang-go")
            print("   macOS: brew install go")
            for tool_name, _ in go_tools:
                results[tool_name] = False
            return results
        
        for tool_name, install_url in go_tools:
            if self._check_tool_installed(tool_name):
                print(f"✅ {tool_name} is already installed")
                results[tool_name] = True
                continue
            
            print(f"📦 Installing {tool_name}...")
            success, stdout, stderr = self._run_command(["go", "install", install_url])
            
            if success and self._check_tool_installed(tool_name):
                print(f"✅ {tool_name} installed successfully")
                results[tool_name] = True
            else:
                print(f"❌ Failed to install {tool_name}")
                if stderr:
                    print(f"   Error: {stderr}")
                results[tool_name] = False
        
        return results
    
    def install_system_packages_windows(self) -> Dict[str, bool]:
        """Install system packages on Windows using Chocolatey."""
        results = {}
        
        # Check if Chocolatey is available
        if not shutil.which("choco"):
            print("❌ Chocolatey is not installed.")
            print("Please install Chocolatey first: https://chocolatey.org/install")
            print("Then run this script again.")
            return {"chocolatey": False}
        
        packages = {
            "nmap": "nmap",
            "git": "git",
            "python": "python3",
            "go": "golang"
        }
        
        for tool_name, package_name in packages.items():
            if self._check_tool_installed(tool_name):
                print(f"✅ {tool_name} is already installed")
                results[tool_name] = True
                continue
            
            print(f"📦 Installing {tool_name} via Chocolatey...")
            success, stdout, stderr = self._run_command(
                ["choco", "install", package_name, "-y"],
                timeout=600
            )
            
            if success:
                print(f"✅ {tool_name} installed successfully")
                results[tool_name] = True
            else:
                print(f"❌ Failed to install {tool_name}")
                if stderr:
                    print(f"   Error: {stderr}")
                results[tool_name] = False
        
        return results
    
    def install_system_packages_linux(self) -> Dict[str, bool]:
        """Install system packages on Linux using apt."""
        results = {}
        
        packages = {
            "nmap": "nmap",
            "git": "git",
            "python3": "python3",
            "pip": "python3-pip",
            "curl": "curl",
            "wget": "wget",
            "go": "golang-go"
        }
        
        # Update package list first
        print("📦 Updating package list...")
        success, _, _ = self._run_command(["sudo", "apt", "update"])
        if not success:
            print("❌ Failed to update package list")
            return {"apt_update": False}
        
        for tool_name, package_name in packages.items():
            if tool_name != "pip" and self._check_tool_installed(tool_name):
                print(f"✅ {tool_name} is already installed")
                results[tool_name] = True
                continue
            
            print(f"📦 Installing {tool_name}...")
            success, stdout, stderr = self._run_command(
                ["sudo", "apt", "install", "-y", package_name],
                timeout=600
            )
            
            if success:
                print(f"✅ {tool_name} installed successfully")
                results[tool_name] = True
            else:
                print(f"❌ Failed to install {tool_name}")
                if stderr:
                    print(f"   Error: {stderr}")
                results[tool_name] = False
        
        return results
    
    def install_system_packages_macos(self) -> Dict[str, bool]:
        """Install system packages on macOS using Homebrew."""
        results = {}
        
        # Check if Homebrew is available
        if not shutil.which("brew"):
            print("❌ Homebrew is not installed.")
            print("Please install Homebrew first:")
            print('/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')
            print("Then run this script again.")
            return {"homebrew": False}
        
        packages = {
            "nmap": "nmap",
            "git": "git",
            "python3": "python@3.9",
            "go": "go"
        }
        
        # Update Homebrew
        print("📦 Updating Homebrew...")
        success, _, _ = self._run_command(["brew", "update"])
        if not success:
            print("⚠️  Homebrew update failed, continuing anyway...")
        
        for tool_name, package_name in packages.items():
            if self._check_tool_installed(tool_name):
                print(f"✅ {tool_name} is already installed")
                results[tool_name] = True
                continue
            
            print(f"📦 Installing {tool_name}...")
            success, stdout, stderr = self._run_command(
                ["brew", "install", package_name],
                timeout=600
            )
            
            if success:
                print(f"✅ {tool_name} installed successfully")
                results[tool_name] = True
            else:
                print(f"❌ Failed to install {tool_name}")
                if stderr:
                    print(f"   Error: {stderr}")
                results[tool_name] = False
        
        return results
    
    def install_python_packages(self) -> Dict[str, bool]:
        """Install Python-based security tools."""
        results = {}
        
        # Check if pip is available
        pip_cmd = "pip3" if shutil.which("pip3") else "pip"
        if not shutil.which(pip_cmd):
            print("❌ pip is not available")
            return {"pip": False}
        
        # Install requirements.txt if it exists
        requirements_file = Path("requirements.txt")
        if requirements_file.exists():
            print("📦 Installing Python requirements...")
            success, stdout, stderr = self._run_command([pip_cmd, "install", "-r", str(requirements_file)])
            if success:
                print("✅ Python requirements installed")
                results["requirements"] = True
            else:
                print("❌ Failed to install Python requirements")
                results["requirements"] = False
        
        return results
    
    def setup_go_environment(self) -> bool:
        """Setup Go environment and PATH."""
        try:
            if self.platform_info.os_name == "windows":
                # Windows Go setup
                go_path = os.path.expanduser("~/go/bin")
                current_path = os.environ.get("PATH", "")
                if go_path not in current_path:
                    print("ℹ️  Please add the following to your PATH:")
                    print(f"   {go_path}")
                    print("   Or restart your terminal after Go installation.")
            else:
                # Unix-like systems Go setup
                go_path = os.path.expanduser("~/go/bin")
                shell_rc = os.path.expanduser("~/.bashrc")
                
                if Path(shell_rc).exists():
                    with open(shell_rc, "r") as f:
                        content = f.read()
                    
                    if "go/bin" not in content:
                        with open(shell_rc, "a") as f:
                            f.write(f"\n# Added by VulnMiner installer\nexport PATH=$PATH:{go_path}\n")
                        print(f"✅ Added Go bin path to {shell_rc}")
                        print("   Please run: source ~/.bashrc")
                    else:
                        print("✅ Go bin path already in ~/.bashrc")
                        
            return True
        except Exception as e:
            print(f"⚠️  Warning: Could not setup Go environment: {e}")
            return False
    
    def verify_installation(self) -> Dict[str, bool]:
        """Verify that tools are properly installed."""
        results = {}
        
        essential_tools = ["nmap", "nuclei", "subfinder", "httpx", "gobuster"]
        optional_tools = ["ffuf", "sqlmap", "amass", "curl", "wget"]
        
        print("\n🔍 Verifying essential tools...")
        for tool in essential_tools:
            if self._check_tool_installed(tool):
                print(f"✅ {tool}")
                results[tool] = True
            else:
                print(f"❌ {tool}")
                results[tool] = False
        
        print("\n🔍 Verifying optional tools...")
        for tool in optional_tools:
            if self._check_tool_installed(tool):
                print(f"✅ {tool}")
                results[tool] = True
            else:
                print(f"❌ {tool}")
                results[tool] = False
        
        return results
    
    def interactive_install(self) -> None:
        """Run interactive installation process."""
        print("🚀 VulnMiner Tool Installation Wizard")
        print("=" * 50)
        print(f"Detected platform: {self.platform_info.os_name} ({self.platform_info.platform})")
        print()
        
        # Install system packages
        if self.platform_info.os_name == "windows":
            print("📦 Installing Windows packages...")
            system_results = self.install_system_packages_windows()
        elif self.platform_info.os_name == "linux":
            print("📦 Installing Linux packages...")
            system_results = self.install_system_packages_linux()
        elif self.platform_info.os_name == "darwin":
            print("📦 Installing macOS packages...")
            system_results = self.install_system_packages_macos()
        else:
            print(f"❌ Unsupported platform: {self.platform_info.os_name}")
            return
        
        # Setup Go environment
        print("\n🔧 Setting up Go environment...")
        self.setup_go_environment()
        
        # Install Go tools
        print("\n📦 Installing Go-based security tools...")
        go_results = self.install_go_tools()
        
        # Install Python packages
        print("\n📦 Installing Python packages...")
        python_results = self.install_python_packages()
        
        # Verify installation
        print("\n🔍 Verifying installation...")
        verification_results = self.verify_installation()
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 INSTALLATION SUMMARY")
        print("=" * 50)
        
        total_tools = len(verification_results)
        successful_tools = sum(1 for success in verification_results.values() if success)
        
        print(f"✅ Successfully installed: {successful_tools}/{total_tools} tools")
        
        if successful_tools == total_tools:
            print("🎉 All tools installed successfully!")
            print("\nYou can now run VulnMiner:")
            print("   start.bat --health-check")
        else:
            print("⚠️  Some tools failed to install. Check the output above for details.")
            print("\nYou can still run VulnMiner with available tools:")
            print("   start.bat --check-deps")


def main():
    """Main entry point for tool installer."""
    installer = ToolInstaller()
    installer.interactive_install()


if __name__ == "__main__":
    main()