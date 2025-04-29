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
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.live import Live
from rich.table import Table
from rich.prompt import Confirm
from rich.box import ROUNDED, HEAVY
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
  scanux --resume          # Show only important security details
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
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Show only important security details (SSH access, violations, security problems)",
    )
    return parser.parse_args()

def create_security_summary(results: Dict) -> str:
    """Create a summary of important security findings"""
    from io import StringIO
    output = StringIO()
    console = Console(file=output, force_terminal=True)
    
    # Create a table for security findings
    table = Table(
        title="Security Summary",
        box=ROUNDED,
        border_style="bright_blue",
        title_style="bold bright_blue"
    )
    
    table.add_column("Category", style="bright_cyan", width=20)
    table.add_column("Status", style="white", width=15)
    table.add_column("Details", style="white", width=45)
    
    # SSH Access Information
    if "network" in results.get("modules", {}):
        network_data = results["modules"]["network"]
        open_ports = network_data.get("metrics", {}).get("open_ports", {})
        ssh_found = False
        
        # Check each IP for SSH ports
        for ip, ports in open_ports.items():
            for port_info in ports:
                if port_info.get("port") == 22 and port_info.get("state") == "open":
                    ssh_found = True
                    table.add_row(
                        "SSH Access",
                        "[yellow]OPEN[/yellow]",
                        f"SSH service is running on {ip}:22"
                    )
        
        if not ssh_found:
            table.add_row(
                "SSH Access",
                "[green]CLOSED[/green]",
                "No SSH service detected"
            )
    
    # Security Violations
    security_data = results.get("modules", {}).get("security", {})
    issues = security_data.get("issues", [])
    high_severity_issues = [issue for issue in issues if issue.get("severity") == "high"]
    
    if high_severity_issues:
        for issue in high_severity_issues:
            table.add_row(
                "Security Violation",
                "[red]HIGH[/red]",
                issue.get("message", "Unknown issue")
            )
    
    # Suspicious Commands/Users
    if "system" in results.get("modules", {}):
        system_data = results["modules"]["system"]
        processes = system_data.get("metrics", {}).get("processes", {})
        if isinstance(processes, dict):  # Add type check
            suspicious_processes = processes.get("high_resource_processes", [])
            if suspicious_processes:
                for proc in suspicious_processes[:5]:  # Show top 5 suspicious processes
                    if isinstance(proc, dict) and (proc.get("cpu_percent", 0) > 50 or proc.get("memory_percent", 0) > 50):
                        table.add_row(
                            "Suspicious Process",
                            "[yellow]WARNING[/yellow]",
                            f"{proc.get('name')} (PID: {proc.get('pid')}) - CPU: {proc.get('cpu_percent')}%, MEM: {proc.get('memory_percent')}%"
                        )
    
    console.print(table)
    return output.getvalue()

def main() -> int:
    """Main entry point."""
    if not check_dependencies():
        sys.exit(1)

    args = parse_args()

    try:
        # Initialize scanner
        scanner = Scanner()
        
        # Create progress display
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Scanning system...", total=None)
            
            # Run each module
            for module_name in args.modules:
                progress.update(task, description=f"[cyan]Running {module_name} module...")
                try:
                    module = __import__(f"scanux.modules.{module_name}", fromlist=["Module"]).Module()
                    metrics, issues = module.scan()
                    scanner.add_module_result(module_name, metrics, issues)
                except Exception as e:
                    print(f"Warning: Module {module_name} failed: {str(e)}", file=sys.stderr)
                    scanner.add_module_result(module_name, {"error": str(e)}, [])
        
        # Get results
        results = scanner.get_results()
        
        if args.resume:
            # Show only important security details
            print(create_security_summary(results))
        else:
            # Generate full report
            reporter = Reporter(results)
            format_type = "json" if args.json else "yaml" if args.yaml else "text"
            report = reporter.generate(format_type)
            print(report)
        
        # Return appropriate exit code based on critical issues
        return 1 if results.get("summary", {}).get("critical_issues", 0) > 0 else 0

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main()) 