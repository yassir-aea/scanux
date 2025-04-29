#!/usr/bin/env python3
"""
Command-line interface for scanux
"""

import argparse
import json
import sys
import time
import subprocess
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.table import Table
from rich.prompt import Confirm
from rich import print as rprint

from .core.scanner import Scanner
from .core.reporter import Reporter

console = Console()

def check_dependencies() -> bool:
    """Check if required system dependencies are installed."""
    try:
        subprocess.run(['nmap', '--version'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE,
                      check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        console.print(Panel(
            "[red]Error: nmap is not installed on your system.[/red]\n\n"
            "Please install nmap using your system's package manager:\n"
            "- Ubuntu/Debian: [yellow]sudo apt-get install nmap[/yellow]\n"
            "- CentOS/RHEL: [yellow]sudo yum install nmap[/yellow]\n"
            "- macOS: [yellow]brew install nmap[/yellow]",
            title="Dependency Error",
            border_style="red"
        ))
        return False

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="System security and performance scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  scanux                    # Run all modules with default settings
  scanux --json            # Output results in JSON format
  scanux --yaml            # Output results in YAML format
  scanux --modules system network  # Run only system and network modules
        """
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )
    parser.add_argument(
        "--yaml",
        action="store_true",
        help="Output results in YAML format",
    )
    parser.add_argument(
        "--modules",
        nargs="+",
        choices=["system", "security", "performance", "network"],
        default=["system", "security", "performance", "network"],
        help="Specify which modules to run",
    )
    return parser.parse_args()

def main() -> int:
    """Main entry point."""
    if not check_dependencies():
        sys.exit(1)

    args = parse_args()

    try:
        # Initialize scanner
        scanner = Scanner()
        
        # Run each module
        for module_name in args.modules:
            try:
                module = __import__(f"scanux.modules.{module_name}", fromlist=["Module"]).Module()
                metrics, issues = module.scan()
                scanner.add_module_result(module_name, metrics, issues)
            except Exception as e:
                print(f"Warning: Module {module_name} failed: {str(e)}", file=sys.stderr)
                scanner.add_module_result(module_name, {"error": str(e)}, [])
        
        # Get results and generate report
        results = scanner.get_results()
        reporter = Reporter(results)
        
        # Determine output format
        format_type = "json" if args.json else "yaml" if args.yaml else "text"
        report = reporter.generate(format_type)
        
        # Print report
        print(report)
        
        # Return appropriate exit code based on critical issues
        return 1 if results.get("summary", {}).get("critical_issues", 0) > 0 else 0

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main()) 