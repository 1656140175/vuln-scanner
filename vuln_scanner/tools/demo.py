"""Demo script showcasing the VulnMiner Tool Lifecycle Management System.

This script demonstrates the key features of the tool management system:
1. Tool registry and discovery
2. Dependency management
3. Automatic tool installation
4. Tool execution and management
5. Usage statistics and monitoring

Run with: python -m vuln_scanner.tools.demo
"""

import asyncio
import sys
from pathlib import Path
import time

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from vuln_scanner.core.core_manager import VulnMinerCore
from vuln_scanner.tools.registry import ToolCategory


async def demo_tool_lifecycle():
    """Demonstrate the complete tool lifecycle management system."""
    
    print("=" * 70)
    print("VulnMiner Tool Lifecycle Management System Demo")
    print("=" * 70)
    
    # Initialize the core system
    print("\n1. Initializing VulnMiner Core System...")
    try:
        core = VulnMinerCore(skip_tool_validation=True)
        print("✓ Core system initialized successfully")
        
        tool_manager = core.get_tool_manager()
        registry = core.tool_manager_component.get_registry()
        
    except Exception as e:
        print(f"✗ Failed to initialize core system: {e}")
        return
    
    # Demonstrate tool registry
    print("\n2. Exploring Tool Registry...")
    tools = registry.list_tools()
    print(f"✓ Found {len(tools)} tools in registry")
    
    # Show tools by category
    print("\nTools by Category:")
    for category in ToolCategory:
        category_tools = registry.get_tools_by_category(category)
        if category_tools:
            print(f"  {category.value.replace('_', ' ').title()}: {len(category_tools)} tools")
    
    # Show some specific tools
    print("\nFeatured Tools:")
    featured_tools = ['nmap', 'nuclei', 'subfinder', 'httpx']
    for tool_name in featured_tools:
        tool_def = registry.get_tool_definition(tool_name)
        if tool_def:
            print(f"  • {tool_def.display_name}: {tool_def.description}")
    
    # Demonstrate dependency management
    print("\n3. Checking Dependencies...")
    dependency_manager = tool_manager.dependency_manager
    
    for tool_name in ['nuclei', 'subfinder']:
        satisfied, missing = await dependency_manager.check_dependencies(tool_name)
        if satisfied:
            print(f"✓ {tool_name}: All dependencies satisfied")
        else:
            print(f"⚠ {tool_name}: Missing dependencies: {', '.join(missing)}")
    
    # Show dependency graph
    print("\nDependency Overview:")
    dep_graph = dependency_manager.get_dependency_graph()
    tools_with_deps = {name: deps for name, deps in dep_graph.items() 
                      if deps and name in featured_tools}
    
    for tool_name, deps in tools_with_deps.items():
        print(f"  {tool_name} → {', '.join(deps)}")
    
    # Demonstrate tool status checking
    print("\n4. Checking Tool Status...")
    print(f"{'Tool':<15} {'Status':<15} {'Version':<15}")
    print("-" * 45)
    
    for tool_name in featured_tools:
        status = tool_manager.get_tool_status(tool_name)
        if status:
            version = status.version or 'Unknown'
            status_icon = {
                'installed': '✓',
                'not_installed': '✗',
                'error': '!'
            }.get(status.status.value, '?')
            print(f"{tool_name:<15} {status_icon} {status.status.value:<13} {version:<15}")
        else:
            print(f"{tool_name:<15} ? Not found      Unknown")
    
    # Demonstrate mock tool installation and execution
    print("\n5. Demonstrating Tool Management...")
    
    # Create a mock tool for demonstration
    from vuln_scanner.tools.base import SecurityTool, ToolStatus, ToolExecutionResult
    
    class DemoTool(SecurityTool):
        """Demo tool for showcase purposes."""
        
        async def install(self) -> bool:
            print(f"  Installing {self.name}...")
            await asyncio.sleep(1)  # Simulate installation time
            self.status = ToolStatus.INSTALLED
            return True
        
        async def update(self) -> bool:
            return await self.install()
        
        async def check_version(self) -> str:
            return "1.0.0-demo" if self.status == ToolStatus.INSTALLED else None
        
        async def validate_installation(self) -> bool:
            return self.status == ToolStatus.INSTALLED
        
        async def execute(self, *args, **kwargs):
            await asyncio.sleep(0.5)  # Simulate execution time
            return ToolExecutionResult(
                tool=self.name,
                success=True,
                returncode=0,
                stdout=f"Demo scan completed for target: {kwargs.get('target', 'localhost')}",
                stderr="",
                execution_time=0.5,
                command=[self.name] + list(args),
                target=kwargs.get('target'),
                scan_type=kwargs.get('scan_type', 'demo')
            )
    
    # Register demo tool
    registry.register_tool_class('demo_tool', DemoTool)
    
    # Install demo tool
    print("Installing demo tool...")
    success = await tool_manager.install_tool('demo_tool')
    if success:
        print("✓ Demo tool installed successfully")
    else:
        print("✗ Demo tool installation failed")
    
    # Execute demo tool
    print("\nExecuting demo tool...")
    result = await tool_manager.execute_tool(
        'demo_tool', 
        'scan', 
        target='demo.example.com',
        scan_type='quick'
    )
    
    if result.success:
        print(f"✓ Execution successful (took {result.execution_time:.2f}s)")
        print(f"  Output: {result.stdout}")
    else:
        print(f"✗ Execution failed: {result.error}")
    
    # Demonstrate usage statistics
    print("\n6. Usage Statistics...")
    
    # Execute a few more times to generate stats
    for i in range(3):
        await tool_manager.execute_tool('demo_tool', f'test_{i}')
    
    stats = tool_manager.get_usage_stats('demo_tool', days=1)
    print(f"Demo Tool Statistics (last 24 hours):")
    print(f"  Total executions: {stats.get('total_executions', 0)}")
    print(f"  Successful: {stats.get('successful_executions', 0)}")
    print(f"  Success rate: {stats.get('success_rate', 0):.1%}")
    print(f"  Average execution time: {stats.get('avg_execution_time', 0):.2f}s")
    
    # Demonstrate system health check
    print("\n7. System Health Check...")
    health = core.health_check()
    
    print(f"Overall system health: {'✓ HEALTHY' if health['healthy'] else '✗ UNHEALTHY'}")
    
    # Show key health metrics
    key_components = ['config_manager', 'tool_manager_component']
    for component in key_components:
        if component in health['checks']:
            status = health['checks'][component]
            if isinstance(status, dict) and 'status' in status:
                status_icon = '✓' if status['status'] == 'healthy' else '✗'
                print(f"  {component}: {status_icon} {status['message']}")
    
    # Show registry statistics
    print("\n8. Registry Statistics...")
    registry_stats = registry.get_stats()
    
    print(f"Registry contains {registry_stats['total_tools']} tools")
    print("Top categories:")
    sorted_categories = sorted(registry_stats['categories'].items(), 
                             key=lambda x: x[1], reverse=True)[:3]
    for category, count in sorted_categories:
        print(f"  {category.replace('_', ' ').title()}: {count} tools")
    
    # Cleanup
    print("\n9. Cleanup...")
    await tool_manager.shutdown()
    core.shutdown()
    print("✓ System shutdown complete")
    
    print("\n" + "=" * 70)
    print("Demo completed successfully!")
    print("The VulnMiner Tool Lifecycle Management System provides:")
    print("• Unified tool registry with 20+ security tools")  
    print("• Automatic dependency management")
    print("• Cross-platform installation support")
    print("• Tool execution with result parsing")
    print("• Usage statistics and monitoring")
    print("• Health checking and status reporting")
    print("• Extensible architecture for custom tools")
    print("=" * 70)


def main():
    """Main entry point for the demo."""
    try:
        asyncio.run(demo_tool_lifecycle())
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\n\nDemo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()