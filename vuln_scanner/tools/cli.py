"""CLI commands for tool management."""

import asyncio
import argparse
import json
from pathlib import Path
import sys

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vuln_scanner.core.core_manager import VulnMinerCore
from vuln_scanner.tools.registry import ToolCategory


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description='VulnMiner Tool Manager CLI')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List tools command
    list_parser = subparsers.add_parser('list', help='List available tools')
    list_parser.add_argument('--category', help='Filter by category')
    list_parser.add_argument('--installed-only', action='store_true', 
                           help='Show only installed tools')
    
    # Install command
    install_parser = subparsers.add_parser('install', help='Install tools')
    install_parser.add_argument('tools', nargs='*', help='Tools to install (or all)')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show tool status')
    status_parser.add_argument('tool', nargs='?', help='Specific tool name')
    
    # Execute command
    exec_parser = subparsers.add_parser('execute', help='Execute a tool')
    exec_parser.add_argument('tool', help='Tool name')
    exec_parser.add_argument('args', nargs='*', help='Tool arguments')
    exec_parser.add_argument('--target', help='Target to scan')
    exec_parser.add_argument('--scan-type', help='Scan type')
    
    # Registry commands
    registry_parser = subparsers.add_parser('registry', help='Registry operations')
    registry_subparsers = registry_parser.add_subparsers(dest='registry_action')
    
    registry_subparsers.add_parser('export', help='Export registry documentation')
    registry_subparsers.add_parser('stats', help='Show registry statistics')
    
    # Health check command
    subparsers.add_parser('health', help='Perform system health check')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize core system
    try:
        core = VulnMinerCore(skip_tool_validation=True)
        tool_manager = core.get_tool_manager()
        registry = core.tool_manager_component.get_registry()
        
        if args.command == 'list':
            list_tools(registry, args)
        elif args.command == 'install':
            asyncio.run(install_tools(tool_manager, args))
        elif args.command == 'status':
            show_status(tool_manager, args)
        elif args.command == 'execute':
            asyncio.run(execute_tool(tool_manager, args))
        elif args.command == 'registry':
            handle_registry_commands(registry, args)
        elif args.command == 'health':
            asyncio.run(health_check(core))
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    finally:
        # Cleanup
        if 'core' in locals():
            core.shutdown()


def list_tools(registry, args):
    """List available tools."""
    tools = registry.list_tools()
    
    # Filter by category if specified
    if args.category:
        try:
            category = ToolCategory(args.category.lower())
            tools = [t for t in tools if t.category == category]
        except ValueError:
            print(f"Invalid category: {args.category}")
            print(f"Available categories: {[c.value for c in ToolCategory]}")
            return
    
    if not tools:
        print("No tools found matching criteria")
        return
    
    print(f"{'Name':<15} {'Category':<20} {'Description':<50}")
    print("-" * 85)
    
    for tool in sorted(tools, key=lambda t: t.name):
        category_name = tool.category.value.replace('_', ' ').title()
        description = tool.description[:47] + "..." if len(tool.description) > 50 else tool.description
        print(f"{tool.name:<15} {category_name:<20} {description:<50}")


async def install_tools(tool_manager, args):
    """Install specified tools."""
    if not args.tools or 'all' in args.tools:
        print("Installing all configured tools...")
        results = await tool_manager.install_all_tools()
    else:
        results = {}
        for tool_name in args.tools:
            print(f"Installing {tool_name}...")
            try:
                success = await tool_manager.install_tool(tool_name)
                results[tool_name] = success
            except Exception as e:
                print(f"Error installing {tool_name}: {e}")
                results[tool_name] = False
    
    # Show results
    print("\nInstallation Results:")
    for tool_name, success in results.items():
        status = "✓ SUCCESS" if success else "✗ FAILED"
        print(f"  {tool_name}: {status}")


def show_status(tool_manager, args):
    """Show tool status."""
    if args.tool:
        # Show status for specific tool
        status = tool_manager.get_tool_status(args.tool)
        if status:
            print(f"Tool: {status.name}")
            print(f"Status: {status.status.value}")
            print(f"Version: {status.version or 'Unknown'}")
            print(f"Path: {status.path or 'Not set'}")
            print(f"Last Updated: {status.last_updated or 'Never'}")
        else:
            print(f"Tool '{args.tool}' not found")
    else:
        # Show status for all tools
        tools = tool_manager.list_tools()
        
        print(f"{'Tool':<15} {'Status':<15} {'Version':<15}")
        print("-" * 45)
        
        for tool in sorted(tools, key=lambda t: t.name):
            version = tool.version or 'Unknown'
            status_color = {
                'installed': '✓',
                'not_installed': '✗', 
                'error': '!'
            }.get(tool.status.value, '?')
            
            print(f"{tool.name:<15} {status_color} {tool.status.value:<13} {version:<15}")


async def execute_tool(tool_manager, args):
    """Execute a tool."""
    print(f"Executing {args.tool}...")
    
    try:
        result = await tool_manager.execute_tool(
            args.tool,
            *args.args,
            target=args.target,
            scan_type=args.scan_type
        )
        
        print(f"\nExecution completed:")
        print(f"Success: {result.success}")
        print(f"Return code: {result.returncode}")
        print(f"Execution time: {result.execution_time:.2f}s")
        
        if result.stdout:
            print(f"\nOutput:")
            print(result.stdout)
        
        if result.stderr:
            print(f"\nErrors:")
            print(result.stderr)
        
        if result.error:
            print(f"\nError: {result.error}")
        
    except Exception as e:
        print(f"Error executing tool: {e}")


def handle_registry_commands(registry, args):
    """Handle registry subcommands."""
    if args.registry_action == 'stats':
        stats = registry.get_stats()
        print("Registry Statistics:")
        print(f"Total tools: {stats['total_tools']}")
        print(f"\nBy category:")
        for category, count in stats['categories'].items():
            print(f"  {category.replace('_', ' ').title()}: {count}")
        
        if stats['dependencies']:
            print(f"\nTop dependencies:")
            sorted_deps = sorted(stats['dependencies'].items(), key=lambda x: x[1], reverse=True)
            for dep, count in sorted_deps[:5]:
                print(f"  {dep}: {count} tools")
    
    elif args.registry_action == 'export':
        output_path = Path('docs/tool_registry.md')
        registry.export_markdown_docs(output_path)
        print(f"Documentation exported to {output_path}")


async def health_check(core):
    """Perform system health check."""
    print("Performing system health check...")
    
    health = core.health_check()
    
    print(f"\nOverall Health: {'✓ HEALTHY' if health['healthy'] else '✗ UNHEALTHY'}")
    print("\nComponent Status:")
    
    for component, status in health['checks'].items():
        if isinstance(status, dict) and 'status' in status:
            status_icon = {
                'healthy': '✓',
                'warning': '⚠',
                'failed': '✗',
                'unknown': '?'
            }.get(status['status'], '?')
            
            print(f"  {component}: {status_icon} {status['message']}")
        else:
            # Handle nested status (e.g., tool manager checks)
            if isinstance(status, dict):
                print(f"  {component}:")
                for sub_check, sub_status in status.items():
                    if isinstance(sub_status, dict) and 'status' in sub_status:
                        status_icon = {
                            'healthy': '✓',
                            'warning': '⚠', 
                            'failed': '✗',
                            'unknown': '?'
                        }.get(sub_status['status'], '?')
                        print(f"    {sub_check}: {status_icon} {sub_status['message']}")


if __name__ == '__main__':
    sys.exit(main())