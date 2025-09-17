#!/usr/bin/env python3
"""
VulnMiner工具安装助手
自动安装安全工具的简化版本
"""

import os
import sys
import subprocess
import platform as system_platform
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple


class SimpleToolInstaller:
    """简化的工具安装程序."""
    
    def __init__(self):
        self.platform_name = platform.system().lower()
        
    def _run_command(self, cmd: List[str], timeout: int = 300) -> Tuple[bool, str, str]:
        """运行系统命令并返回成功状态和输出."""
        try:
            print(f"🔧 运行中: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "命令超时"
        except Exception as e:
            return False, "", str(e)
    
    def _check_tool_installed(self, tool_name: str) -> bool:
        """检查工具是否已安装."""
        return shutil.which(tool_name) is not None
    
    def install_go_tools(self) -> Dict[str, bool]:
        """安装基于Go的安全工具."""
        results = {}
        
        go_tools = [
            ("nuclei", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"),
            ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
            ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
            ("gobuster", "github.com/OJ/gobuster/v3@latest"),
            ("ffuf", "github.com/ffuf/ffuf/v2@latest")
        ]
        
        # 检查Go是否安装
        if not shutil.which("go"):
            print("❌ 未安装Go。请先安装Go:")
            print("   Windows: choco install golang")
            print("   Ubuntu/Debian: sudo apt install golang-go")
            print("   macOS: brew install go")
            for tool_name, _ in go_tools:
                results[tool_name] = False
            return results
        
        for tool_name, install_url in go_tools:
            if self._check_tool_installed(tool_name):
                print(f"✅ {tool_name} 已安装")
                results[tool_name] = True
                continue
            
            print(f"📦 正在安装 {tool_name}...")
            success, stdout, stderr = self._run_command(["go", "install", install_url])
            
            if success and self._check_tool_installed(tool_name):
                print(f"✅ {tool_name} 安装成功")
                results[tool_name] = True
            else:
                print(f"❌ 安装 {tool_name} 失败")
                if stderr:
                    print(f"   错误: {stderr}")
                results[tool_name] = False
        
        return results
    
    def install_system_packages_windows(self) -> Dict[str, bool]:
        """在Windows上使用Chocolatey安装系统包."""
        results = {}
        
        # 检查Chocolatey是否可用
        if not shutil.which("choco"):
            print("❌ 未安装Chocolatey.")
            print("请先安装Chocolatey: https://chocolatey.org/install")
            print("然后重新运行此脚本.")
            return {"chocolatey": False}
        
        packages = {
            "nmap": "nmap",
            "git": "git",
            "python": "python3",
            "go": "golang"
        }
        
        for tool_name, package_name in packages.items():
            if self._check_tool_installed(tool_name):
                print(f"✅ {tool_name} 已安装")
                results[tool_name] = True
                continue
            
            print(f"📦 通过Chocolatey安装 {tool_name}...")
            success, stdout, stderr = self._run_command(
                ["choco", "install", package_name, "-y"],
                timeout=600
            )
            
            if success:
                print(f"✅ {tool_name} 安装成功")
                results[tool_name] = True
            else:
                print(f"❌ 安装 {tool_name} 失败")
                if stderr:
                    print(f"   错误: {stderr}")
                results[tool_name] = False
        
        return results
    
    def install_system_packages_linux(self) -> Dict[str, bool]:
        """在Linux上使用apt安装系统包."""
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
        
        # 首先更新包列表
        print("📦 更新包列表...")
        success, _, _ = self._run_command(["sudo", "apt", "update"])
        if not success:
            print("❌ 更新包列表失败")
            return {"apt_update": False}
        
        for tool_name, package_name in packages.items():
            if tool_name != "pip" and self._check_tool_installed(tool_name):
                print(f"✅ {tool_name} 已安装")
                results[tool_name] = True
                continue
            
            print(f"📦 安装 {tool_name}...")
            success, stdout, stderr = self._run_command(
                ["sudo", "apt", "install", "-y", package_name],
                timeout=600
            )
            
            if success:
                print(f"✅ {tool_name} 安装成功")
                results[tool_name] = True
            else:
                print(f"❌ 安装 {tool_name} 失败")
                if stderr:
                    print(f"   错误: {stderr}")
                results[tool_name] = False
        
        return results
    
    def install_system_packages_macos(self) -> Dict[str, bool]:
        """在macOS上使用Homebrew安装系统包."""
        results = {}
        
        # 检查Homebrew是否可用
        if not shutil.which("brew"):
            print("❌ 未安装Homebrew.")
            print("请先安装Homebrew:")
            print('/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')
            print("然后重新运行此脚本.")
            return {"homebrew": False}
        
        packages = {
            "nmap": "nmap",
            "git": "git",
            "python3": "python@3.9",
            "go": "go"
        }
        
        # 更新Homebrew
        print("📦 更新Homebrew...")
        success, _, _ = self._run_command(["brew", "update"])
        if not success:
            print("⚠️  Homebrew更新失败，继续安装...")
        
        for tool_name, package_name in packages.items():
            if self._check_tool_installed(tool_name):
                print(f"✅ {tool_name} 已安装")
                results[tool_name] = True
                continue
            
            print(f"📦 安装 {tool_name}...")
            success, stdout, stderr = self._run_command(
                ["brew", "install", package_name],
                timeout=600
            )
            
            if success:
                print(f"✅ {tool_name} 安装成功")
                results[tool_name] = True
            else:
                print(f"❌ 安装 {tool_name} 失败")
                if stderr:
                    print(f"   错误: {stderr}")
                results[tool_name] = False
        
        return results
    
    def setup_go_environment(self) -> bool:
        """设置Go环境和PATH."""
        try:
            if self.platform_name == "windows":
                # Windows Go设置
                go_path = os.path.expanduser("~/go/bin")
                current_path = os.environ.get("PATH", "")
                if go_path not in current_path:
                    print("ℹ️  请将以下路径添加到您的PATH:")
                    print(f"   {go_path}")
                    print("   或在Go安装后重启终端.")
            else:
                # Unix系统Go设置
                go_path = os.path.expanduser("~/go/bin")
                shell_rc = os.path.expanduser("~/.bashrc")
                
                if Path(shell_rc).exists():
                    with open(shell_rc, "r") as f:
                        content = f.read()
                    
                    if "go/bin" not in content:
                        with open(shell_rc, "a") as f:
                            f.write(f"\n# VulnMiner安装程序添加\nexport PATH=$PATH:{go_path}\n")
                        print(f"✅ Go bin路径已添加到 {shell_rc}")
                        print("   请运行: source ~/.bashrc")
                    else:
                        print("✅ Go bin路径已在 ~/.bashrc 中")
                        
            return True
        except Exception as e:
            print(f"⚠️  警告: 无法设置Go环境: {e}")
            return False
    
    def verify_installation(self) -> Dict[str, bool]:
        """验证工具是否正确安装."""
        results = {}
        
        essential_tools = ["nmap", "nuclei", "subfinder", "httpx", "gobuster"]
        optional_tools = ["ffuf", "sqlmap", "amass", "curl", "wget"]
        
        print("\n🔍 验证必需工具...")
        for tool in essential_tools:
            if self._check_tool_installed(tool):
                print(f"✅ {tool}")
                results[tool] = True
            else:
                print(f"❌ {tool}")
                results[tool] = False
        
        print("\n🔍 验证可选工具...")
        for tool in optional_tools:
            if self._check_tool_installed(tool):
                print(f"✅ {tool}")
                results[tool] = True
            else:
                print(f"❌ {tool}")
                results[tool] = False
        
        return results
    
    def interactive_install(self) -> None:
        """运行交互式安装过程."""
        print("🚀 VulnMiner 工具安装向导")
        print("=" * 50)
        print(f"检测到的平台: {self.platform_name}")
        print()
        
        # 安装系统包
        if self.platform_name == "windows":
            print("📦 安装Windows包...")
            system_results = self.install_system_packages_windows()
        elif self.platform_name == "linux":
            print("📦 安装Linux包...")
            system_results = self.install_system_packages_linux()
        elif self.platform_name == "darwin":
            print("📦 安装macOS包...")
            system_results = self.install_system_packages_macos()
        else:
            print(f"❌ 不支持的平台: {self.platform_name}")
            return
        
        # 设置Go环境
        print("\n🔧 设置Go环境...")
        self.setup_go_environment()
        
        # 安装Go工具
        print("\n📦 安装基于Go的安全工具...")
        go_results = self.install_go_tools()
        
        # 验证安装
        print("\n🔍 验证安装...")
        verification_results = self.verify_installation()
        
        # 摘要
        print("\n" + "=" * 50)
        print("📊 安装摘要")
        print("=" * 50)
        
        total_tools = len(verification_results)
        successful_tools = sum(1 for success in verification_results.values() if success)
        
        print(f"✅ 成功安装: {successful_tools}/{total_tools} 个工具")
        
        if successful_tools == total_tools:
            print("🎉 所有工具安装成功!")
            print("\n现在您可以运行VulnMiner:")
            print("   python start.py --health-check")
        else:
            print("⚠️  部分工具安装失败。请检查上面的输出了解详情.")
            print("\n您仍然可以使用可用的工具运行VulnMiner:")
            print("   python start.py --check-deps")


def main():
    """工具安装程序主入口点."""
    installer = SimpleToolInstaller()
    installer.interactive_install()


if __name__ == "__main__":
    main()