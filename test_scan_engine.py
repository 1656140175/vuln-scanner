#!/usr/bin/env python3
"""Quick test of the scan engine to validate functionality."""

import asyncio
import sys
import yaml
from pathlib import Path

# Add the vuln_scanner package to Python path
sys.path.insert(0, str(Path(__file__).parent))

from vuln_scanner.core.scanning.scan_engine import ScanEngine
from vuln_scanner.core.scanning.data_structures import ScanTarget
from vuln_scanner.core.tool_manager import ToolManagerComponent


async def test_scan_engine():
    """Test basic scan engine functionality."""
    print("Testing scan engine initialization...")
    
    # Load configuration
    config_path = Path("config/default.yml")
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Initialize tool manager component
    tool_manager_component = ToolManagerComponent(config)
    tool_manager_component.initialize()
    
    # Create scan engine
    scan_engine = ScanEngine(config)
    scan_engine.set_tool_manager(tool_manager_component)
    
    print("Starting scan engine...")
    await scan_engine.start()
    
    # Test basic functionality
    print("Getting engine stats...")
    stats = scan_engine.get_engine_stats()
    print(f"Engine stats: {stats}")
    
    print("Available pipelines:", list(scan_engine.pipelines.keys()))
    
    # Clean shutdown
    print("Stopping scan engine...")
    await scan_engine.stop()
    
    print("Test completed successfully!")


if __name__ == "__main__":
    asyncio.run(test_scan_engine())