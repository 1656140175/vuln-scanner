"""Main entry point for VulnMiner system."""

import argparse
import sys
import os
from pathlib import Path
from typing import Optional

from . import VulnMinerCore, __version__
from .core.exceptions import VulnMinerException, ConfigurationError


def create_argument_parser() -> argparse.ArgumentParser:
    """Create command line argument parser.
    
    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        prog='vuln_miner',
        description='VulnMiner - Advanced Automated Vulnerability Scanning System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vuln_miner --config config/custom.yml
  vuln_miner --environment production
  vuln_miner --health-check
  vuln_miner --version

IMPORTANT: This tool is for authorized security testing only.
Ensure you have proper authorization before scanning any targets.
        """
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'VulnMiner {__version__}'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Path to configuration file (overrides default config)',
        metavar='PATH'
    )
    
    parser.add_argument(
        '--environment', '-e',
        type=str,
        choices=['development', 'testing', 'production'],
        help='Environment to run in (overrides config)',
        metavar='ENV'
    )
    
    parser.add_argument(
        '--log-level', '-l',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Logging level (overrides config)',
        metavar='LEVEL'
    )
    
    parser.add_argument(
        '--health-check',
        action='store_true',
        help='Run system health check and exit'
    )
    
    parser.add_argument(
        '--validate-config',
        action='store_true',
        help='Validate configuration files and exit'
    )
    
    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Run in interactive mode'
    )
    
    parser.add_argument(
        '--daemon', '-d',
        action='store_true',
        help='Run as daemon (background service)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Initialize system without starting scans (validation only)'
    )
    
    return parser


def setup_environment(args: argparse.Namespace) -> None:
    """Set up environment variables from command line arguments.
    
    Args:
        args: Parsed command line arguments
    """
    if args.environment:
        os.environ['VULN_MINER_ENV'] = args.environment
    
    if args.log_level:
        os.environ['VULN_MINER_LOG_LEVEL'] = args.log_level


def validate_configuration(config_path: Optional[str] = None) -> bool:
    """Validate configuration files.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        True if configuration is valid, False otherwise
    """
    try:
        # Initialize core just for configuration validation
        with VulnMinerCore(config_path) as core:
            validation_errors = core.config_manager.validate()
            
            if validation_errors:
                print("Configuration validation failed:")
                for error in validation_errors:
                    print(f"  - {error}")
                return False
            else:
                print("Configuration validation passed")
                return True
                
    except VulnMinerException as e:
        print(f"Configuration validation failed: {e}")
        return False


def run_health_check(config_path: Optional[str] = None) -> bool:
    """Run system health check.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        True if system is healthy, False otherwise
    """
    try:
        with VulnMinerCore(config_path) as core:
            health_status = core.health_check()
            
            print(f"System Health Check (VulnMiner {__version__})")
            print("=" * 50)
            print(f"Overall Status: {'HEALTHY' if health_status['healthy'] else 'UNHEALTHY'}")
            print()
            
            for check_name, check_result in health_status['checks'].items():
                status = check_result['status'].upper()
                message = check_result['message']
                print(f"{check_name:20} [{status}] {message}")
            
            return health_status['healthy']
            
    except VulnMinerException as e:
        print(f"Health check failed: {e}")
        return False


def run_interactive_mode(core: VulnMinerCore) -> None:
    """Run in interactive mode.
    
    Args:
        core: Initialized VulnMiner core instance
    """
    print(f"VulnMiner {__version__} - Interactive Mode")
    print("Type 'help' for available commands, 'quit' to exit")
    print()
    
    while True:
        try:
            command = input("vuln_miner> ").strip().lower()
            
            if command in ['quit', 'exit', 'q']:
                break
            elif command == 'help':
                print_interactive_help()
            elif command == 'status':
                show_system_status(core)
            elif command == 'health':
                health_status = core.health_check()
                print(f"System Health: {'HEALTHY' if health_status['healthy'] else 'UNHEALTHY'}")
            elif command == 'config':
                show_configuration(core)
            elif command == 'version':
                print(f"VulnMiner {__version__}")
            elif command == '':
                continue
            else:
                print(f"Unknown command: {command}")
                print("Type 'help' for available commands")
                
        except KeyboardInterrupt:
            print("\nUse 'quit' to exit")
        except EOFError:
            break


def print_interactive_help() -> None:
    """Print interactive mode help."""
    print("Available commands:")
    print("  help     - Show this help message")
    print("  status   - Show system status")
    print("  health   - Run health check")
    print("  config   - Show configuration summary")
    print("  version  - Show version information")
    print("  quit     - Exit interactive mode")


def show_system_status(core: VulnMinerCore) -> None:
    """Show system status information.
    
    Args:
        core: VulnMiner core instance
    """
    status = core.get_system_status()
    
    print("System Status:")
    print(f"  Version: {status['version']}")
    print(f"  Environment: {status['environment']}")
    print(f"  Initialized: {status['initialized']}")
    print(f"  Uptime: {status['uptime_seconds']:.1f} seconds")
    
    if 'components' in status:
        print("  Components:")
        for name, info in status['components'].items():
            state = "READY" if info['initialized'] and not info['shutdown'] else "NOT_READY"
            print(f"    {name}: {state}")


def show_configuration(core: VulnMinerCore) -> None:
    """Show configuration summary.
    
    Args:
        core: VulnMiner core instance
    """
    config = core.config_manager.to_dict()
    
    print("Configuration Summary:")
    print(f"  Environment: {config.get('system', {}).get('environment', 'unknown')}")
    print(f"  Debug Mode: {config.get('system', {}).get('debug', False)}")
    print(f"  Log Level: {config.get('logging', {}).get('level', 'INFO')}")
    print(f"  Security Enabled: {config.get('security', {}).get('authorization', {}).get('enabled', True)}")
    print(f"  Rate Limiting: {config.get('security', {}).get('rate_limiting', {}).get('enabled', True)}")


def main() -> int:
    """Main entry point.
    
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Set up environment
    setup_environment(args)
    
    try:
        # Handle special modes that don't require full initialization
        if args.validate_config:
            return 0 if validate_configuration(args.config) else 1
        
        if args.health_check:
            return 0 if run_health_check(args.config) else 1
        
        # Initialize the core system
        print(f"Initializing VulnMiner {__version__}...")
        
        with VulnMinerCore(args.config) as core:
            print("System initialized successfully")
            
            if args.dry_run:
                print("Dry run completed - system validation passed")
                return 0
            
            if args.interactive:
                run_interactive_mode(core)
            elif args.daemon:
                print("Daemon mode not implemented yet")
                return 1
            else:
                # Default behavior - show status and wait
                show_system_status(core)
                print("System ready. Press Ctrl+C to shutdown.")
                
                try:
                    while not core.shutdown_requested:
                        import time
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\nShutdown requested...")
            
            return 0
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except ConfigurationError as e:
        print(f"Configuration error: {e}")
        if e.suggestion:
            print(f"Suggestion: {e.suggestion}")
        return 2
    except VulnMinerException as e:
        print(f"VulnMiner error: {e}")
        if e.suggestion:
            print(f"Suggestion: {e.suggestion}")
        return 3
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 4


if __name__ == '__main__':
    sys.exit(main())