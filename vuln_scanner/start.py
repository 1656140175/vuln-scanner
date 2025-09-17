#!/usr/bin/env python3
"""
VulnMiner 系统启动器
高级全自动化漏洞扫描与赏金获取系统

支持两种模式:
- SCAN 模式: 手动目标输入，可选择自动报告提交
- AUTO 模式: 从漏洞赏金平台自动获取目标并自动提交报告

作者: VulnMiner 团队
许可证: MIT
"""

import sys
import os
import asyncio
import argparse
import logging
import time
from pathlib import Path
from typing import Optional, List, Dict, Any

# 获取当前脚本目录并添加到路径
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
sys.path.insert(0, str(parent_dir))
sys.path.insert(0, str(current_dir))

from vuln_scanner.core.config.config_manager import ConfigManager, ConfigurationError
from vuln_scanner.core.logger.logger_manager import LoggerManager
from vuln_scanner.main import validate_configuration, run_health_check, __version__


def setup_logging(debug: bool = False) -> None:
    """设置日志配置."""
    try:
        config = ConfigManager()
        logger_manager = LoggerManager(config.get_section('logging'))
        logger_manager.setup_logging()
        
        if debug:
            logging.getLogger().setLevel(logging.DEBUG)
            
    except Exception as e:
        # 备用日志设置
        logging.basicConfig(
            level=logging.DEBUG if debug else logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logging.warning(f"无法设置高级日志系统: {e}")


def check_dependencies() -> bool:
    """检查必需的依赖是否可用."""
    required_tools = ['nmap', 'nuclei', 'subfinder', 'httpx', 'gobuster']
    missing_tools = []
    
    for tool in required_tools:
        # 检查工具是否在PATH中
        if not any(
            os.access(os.path.join(path, tool), os.X_OK) 
            for path in os.environ["PATH"].split(os.pathsep)
            if os.path.isdir(path)
        ):
            # 在Windows上检查.exe扩展名
            if not any(
                os.access(os.path.join(path, f"{tool}.exe"), os.X_OK) 
                for path in os.environ["PATH"].split(os.pathsep)
                if os.path.isdir(path)
            ):
                missing_tools.append(tool)
    
    if missing_tools:
        print(f"❌ 缺少必需的工具: {', '.join(missing_tools)}")
        print("请在运行VulnMiner前安装缺少的工具.")
        print("运行: python ../install_tools.py --help 获取安装说明.")
        return False
    
    print("✅ 所有必需的工具都已可用")
    return True


def print_banner():
    """打印VulnMiner横幅."""
    banner = """
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███╗   ███╗██╗███╗   ██╗███████╗██████╗ 
██║   ██║██║   ██║██║     ████╗  ██║    ████╗ ████║██║████╗  ██║██╔════╝██╔══██╗
██║   ██║██║   ██║██║     ██╔██╗ ██║    ██╔████╔██║██║██╔██╗ ██║█████╗  ██████╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ██║╚██╔╝██║██║██║╚██╗██║██╔══╝  ██╔══██╗
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ██║ ╚═╝ ██║██║██║ ╚████║███████╗██║  ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

    高级全自动化漏洞扫描与赏金获取系统
    版本: 1.0.0 | 模式: 个人使用 | 平台: 跨平台
    
    🔍 SCAN 模式: 手动目标输入智能扫描
    🤖 AUTO 模式: 漏洞赏金平台自动目标获取
    📊 实时进度跟踪和ML时间估算  
    📋 多格式报告 (PDF, HTML, JSON, SARIF)
    🚀 跨平台支持 (Windows, Linux, Google Colab)
    """
    print(banner)


def print_usage_examples():
    """打印使用示例."""
    examples = """
🚀 快速开始示例:

1. SCAN 模式 - 手动目标扫描:
   python start.py scan --target https://example.com --pipeline quick
   python start.py scan --target https://example.com --pipeline comprehensive --submit

2. AUTO 模式 - 自动化漏洞赏金扫描:
   python start.py auto --platform hackerone --max-targets 5
   python start.py auto --platform bugcrowd --continuous

3. 系统管理:
   python start.py --validate-config
   python start.py --health-check
   python start.py --install-tools

4. 高级扫描:
   python start.py scan --target-list targets.txt --pipeline webapp --format pdf,html
   python start.py scan --target 192.168.1.0/24 --pipeline network --aggressive

📖 详细帮助: python start.py --help
📖 模式专用帮助: python start.py scan --help | python start.py auto --help
    """
    print(examples)


class VulnMinerCLI:
    """VulnMiner命令行界面."""
    
    def __init__(self):
        self.config_manager = None
        self.logger = None
        
    async def initialize(self, config_path: Optional[str] = None):
        """初始化VulnMiner系统."""
        try:
            self.config_manager = ConfigManager(config_path)
            self.logger = logging.getLogger('vulnminer_cli')
            self.logger.info("VulnMiner CLI 初始化完成")
        except Exception as e:
            print(f"❌ 初始化失败: {e}")
            raise
    
    async def health_check(self) -> bool:
        """执行系统健康检查."""
        try:
            print("🔍 执行系统健康检查...")
            
            # 检查配置
            if not self.config_manager:
                print("❌ 配置管理器未初始化")
                return False
            
            validation_errors = self.config_manager.validate()
            if validation_errors:
                print("❌ 配置验证失败:")
                for error in validation_errors:
                    print(f"  - {error}")
                return False
            
            # 检查工具依赖
            if not check_dependencies():
                return False
            
            print("✅ 系统健康检查通过")
            return True
            
        except Exception as e:
            print(f"❌ 健康检查失败: {e}")
            return False
    
    async def run_scan(self, **kwargs) -> Dict[str, Any]:
        """运行扫描模式."""
        print("🔍 启动 SCAN 模式...")
        
        target = kwargs.get('target')
        target_list = kwargs.get('target_list')
        pipeline = kwargs.get('pipeline', 'quick')
        format_list = kwargs.get('format', ['html', 'json'])
        submit = kwargs.get('submit', False)
        aggressive = kwargs.get('aggressive', False)
        
        print(f"目标: {target or target_list}")
        print(f"扫描管道: {pipeline}")
        print(f"报告格式: {', '.join(format_list)}")
        print(f"自动提交: {'是' if submit else '否'}")
        print(f"激进模式: {'是' if aggressive else '否'}")
        
        # 这里应该集成实际的扫描逻辑
        print("⏳ 扫描正在进行中...")
        await asyncio.sleep(2)  # 模拟扫描时间
        
        print("✅ 扫描完成!")
        return {"success": True, "findings": 0}
    
    async def run_auto(self, **kwargs) -> Dict[str, Any]:
        """运行自动模式."""
        print("🤖 启动 AUTO 模式...")
        
        platform = kwargs.get('platform', 'all')
        max_targets = kwargs.get('max_targets', 10)
        continuous = kwargs.get('continuous', False)
        min_reward = kwargs.get('min_reward')
        
        print(f"目标平台: {platform}")
        print(f"最大目标数: {max_targets}")
        print(f"连续模式: {'是' if continuous else '否'}")
        if min_reward:
            print(f"最小奖励: ${min_reward}")
        
        # 这里应该集成实际的自动扫描逻辑
        print("⏳ 正在从漏洞赏金平台获取目标...")
        await asyncio.sleep(2)  # 模拟获取时间
        
        print("✅ 自动扫描完成!")
        return {"success": True, "targets_scanned": max_targets}


async def main():
    """主入口点."""
    parser = argparse.ArgumentParser(
        description="VulnMiner - 高级全自动化漏洞扫描系统",
        epilog="有关特定模式的详细帮助，请使用: python start.py <模式> --help",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--debug', 
        action='store_true',
        help='启用调试日志'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true', 
        help='跳过横幅显示'
    )
    
    parser.add_argument(
        '--check-deps',
        action='store_true',
        help='检查是否已安装必需的工具'
    )
    
    parser.add_argument(
        '--install-tools',
        action='store_true',
        help='启动交互式工具安装程序'
    )
    
    parser.add_argument(
        '--validate-config',
        action='store_true',
        help='验证系统配置'
    )
    
    parser.add_argument(
        '--health-check', 
        action='store_true',
        help='执行系统健康检查'
    )
    
    # 添加子解析器用于scan和auto模式
    subparsers = parser.add_subparsers(dest='mode', help='操作模式')
    
    # SCAN模式子解析器
    scan_parser = subparsers.add_parser(
        'scan', 
        help='手动目标扫描模式'
    )
    scan_parser.add_argument(
        '--target', '-t',
        help='要扫描的目标URL、IP或域名'
    )
    scan_parser.add_argument(
        '--target-list', '-T',
        help='包含目标列表的文件（每行一个）'
    )
    scan_parser.add_argument(
        '--pipeline', '-p',
        choices=['quick', 'comprehensive', 'webapp', 'network'],
        default='quick',
        help='要使用的扫描管道（默认: quick）'
    )
    scan_parser.add_argument(
        '--format', '-f',
        default='html,json',
        help='报告格式（逗号分隔）: pdf,html,json,sarif（默认: html,json）'
    )
    scan_parser.add_argument(
        '--submit',
        action='store_true',
        help='自动将发现提交到配置的漏洞赏金平台'
    )
    scan_parser.add_argument(
        '--aggressive',
        action='store_true', 
        help='启用激进扫描技术（谨慎使用）'
    )
    
    # AUTO模式子解析器  
    auto_parser = subparsers.add_parser(
        'auto',
        help='自动化漏洞赏金扫描模式'
    )
    auto_parser.add_argument(
        '--platform',
        choices=['hackerone', 'bugcrowd', 'intigriti', 'vulbox', 'openbugbounty', 'all'],
        default='all',
        help='目标漏洞赏金平台（默认: all）'
    )
    auto_parser.add_argument(
        '--max-targets',
        type=int,
        default=10,
        help='每个会话扫描的最大目标数（默认: 10）'
    )
    auto_parser.add_argument(
        '--continuous', 
        action='store_true',
        help='以连续模式运行（持续扫描新目标）'
    )
    auto_parser.add_argument(
        '--min-reward',
        type=int,
        help='考虑的最小赏金奖励（美元）'
    )
    
    args = parser.parse_args()
    
    # 设置日志
    setup_logging(args.debug)
    
    # 除非禁用，否则显示横幅
    if not args.no_banner:
        print_banner()
    
    # 处理独立操作
    if args.check_deps:
        sys.exit(0 if check_dependencies() else 1)
    
    if args.install_tools:
        try:
            # 导入并运行工具安装程序
            import subprocess
            install_script = current_dir / "install_tools.py"
            result = subprocess.run([sys.executable, str(install_script)], check=False)
            sys.exit(result.returncode)
        except Exception as e:
            print(f"❌ 工具安装程序不可用: {e}")
            print("请手动安装工具。参见README.md获取安装说明。")
        return
    
    if args.validate_config:
        try:
            if validate_configuration():
                print("✅ 配置有效")
                sys.exit(0)
            else:
                print("❌ 配置验证失败")
                sys.exit(1)
        except Exception as e:
            print(f"❌ 配置错误: {e}")
            sys.exit(1)
        return
    
    if args.health_check:
        try:
            cli = VulnMinerCLI()
            await cli.initialize()
            health_status = await cli.health_check()
            if health_status:
                print("✅ 系统健康检查通过")
                sys.exit(0)
            else:
                print("❌ 系统健康检查失败") 
                sys.exit(1)
        except Exception as e:
            print(f"❌ 健康检查错误: {e}")
            sys.exit(1)
        return
    
    # 如果没有指定模式，显示使用示例
    if not args.mode:
        print_usage_examples()
        return
    
    # 运行扫描前检查依赖
    if not check_dependencies():
        sys.exit(1)
    
    # 初始化并运行VulnMiner CLI
    try:
        cli = VulnMinerCLI()
        await cli.initialize()
        
        if args.mode == 'scan':
            # 验证扫描参数
            if not args.target and not args.target_list:
                print("❌ 错误: scan模式需要--target或--target-list")
                print("示例: python start.py scan --target https://example.com")
                sys.exit(1)
            
            # 准备扫描参数
            scan_args = {
                'mode': 'scan',
                'target': args.target,
                'target_list': args.target_list,
                'pipeline': args.pipeline,
                'format': args.format.split(','),
                'submit': args.submit,
                'aggressive': args.aggressive
            }
            
            result = await cli.run_scan(**scan_args)
            
        elif args.mode == 'auto':
            # 准备auto模式参数
            auto_args = {
                'mode': 'auto',
                'platform': args.platform,
                'max_targets': args.max_targets,
                'continuous': args.continuous,
                'min_reward': args.min_reward
            }
            
            result = await cli.run_auto(**auto_args)
    
    except KeyboardInterrupt:
        print("\n🛑 用户中断")
        sys.exit(0)
    except Exception as e:
        logging.error(f"致命错误: {e}")
        if args.debug:
            raise
        print(f"❌ 致命错误: {e}")
        print("使用--debug标志获取详细错误信息")
        sys.exit(1)


if __name__ == "__main__":
    if sys.version_info < (3, 8):
        print("❌ 需要Python 3.8或更高版本")
        sys.exit(1)
    
    # 处理Windows事件循环问题
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    asyncio.run(main())