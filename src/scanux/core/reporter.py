"""
Enhanced reporter module for generating beautiful and detailed reports
"""

import json
import yaml
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.box import ROUNDED, HEAVY
from rich.style import Style
from rich.theme import Theme
from rich.layout import Layout
from rich.padding import Padding
from rich.align import Align
from rich.columns import Columns

class Reporter:
    """Generates beautifully formatted reports from scan results"""
    
    def __init__(self, data: Dict[str, Any]):
        """Initialize with scan data"""
        self.data = data
        self.console = Console(theme=Theme({
            "title": "bold bright_blue",
            "subtitle": "italic bright_blue",
            "info_style": "bright_cyan",
            "success": "bright_green",
            "warning": "bright_yellow",
            "error": "bright_red",
            "critical": "red bold",
            "header": "bold bright_white",
            "default": "white"
        }))
    
    def generate(self, format_type: str = "text") -> str:
        """Generate a report in the specified format"""
        if format_type == "text":
            return self._generate_text()
        elif format_type == "json":
            return self._generate_json()
        elif format_type == "yaml":
            return self._generate_yaml()
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _generate_text(self) -> str:
        """Generate a beautifully formatted text report"""
        from io import StringIO
        output = StringIO()
        console = Console(file=output, force_terminal=True)
        
        # Header with scan information
        scan_info = self.data.get("scan_info", {})
        header = Table.grid(padding=(0, 1))
        header.add_column(style="bright_blue", justify="center")
        header.add_row(
            f"[title]SCANUX System Scanner v{scan_info.get('version', '1.0.0')}[/]"
        )
        header.add_row(
            f"[subtitle]Scan started at: {scan_info.get('timestamp', 'Unknown')}[/]"
        )
        console.print(header)
        console.print()
        
        # System Information Panel
        sys_info = self.data.get("system_info", {})
        sys_table = self._create_system_info_table(sys_info)
        console.print(Panel(
            sys_table,
            title="[title]System Information[/]",
            border_style="bright_blue",
            box=HEAVY,
            padding=(1, 2)
        ))
        console.print()
        
        # Module Results
        modules = self.data.get("modules", {})
        for module_name, module_data in modules.items():
            module_table = self._create_module_table(module_name, module_data)
            console.print(module_table)
            console.print()
        
        # Summary Panel
        summary = self.data.get("summary", {})
        summary_table = self._create_summary_table(summary)
        console.print(Panel(
            summary_table,
            title="[title]Scan Summary[/]",
            border_style="bright_blue",
            box=HEAVY,
            padding=(1, 2)
        ))
        
        return output.getvalue()
    
    def _create_system_info_table(self, sys_info: Dict[str, Any]) -> Table:
        """Create a table for system information"""
        table = Table(box=ROUNDED, show_header=False, border_style="bright_blue", padding=(0, 1))
        table.add_column("Category", style="bright_cyan", width=15)
        table.add_column("Details", style="white")
        
        os_info = sys_info.get("os", {})
        hw_info = sys_info.get("hardware", {})
        
        table.add_row(
            "Hostname",
            sys_info.get("hostname", "Unknown")
        )
        table.add_row(
            "OS",
            f"{os_info.get('name', 'Unknown')} {os_info.get('version', '')}"
        )
        table.add_row(
            "Architecture",
            os_info.get("architecture", "Unknown")
        )
        
        cpu_info = hw_info.get("cpu_cores", {})
        cpu_freq = hw_info.get("cpu_freq", {})
        table.add_row(
            "CPU",
            f"{hw_info.get('processor', 'Unknown')} ({cpu_info.get('logical', 0)} cores)"
        )
        if cpu_freq:
            table.add_row(
                "CPU Freq",
                f"Current: {cpu_freq.get('current', 'N/A')} | Max: {cpu_freq.get('max', 'N/A')}"
            )
        
        mem_info = hw_info.get("memory", {})
        table.add_row(
            "Memory",
            f"Total: {mem_info.get('total', 'Unknown')} | Used: {mem_info.get('percent', 0)}%"
        )
        
        disk_info = hw_info.get("disk", {})
        table.add_row(
            "Disk",
            f"Total: {disk_info.get('total', 'Unknown')} | Used: {disk_info.get('percent', 0)}%"
        )
        
        return table
    
    def _create_module_table(self, module_name: str, module_data: Dict[str, Any]) -> Table:
        """Create a table for module results"""
        status = module_data.get("status", "unknown")
        status_style = self._get_status_style(status)
        
        table = Table(
            title=f"[title]{module_name.upper()} Module Results[/] {status_style}",
            box=ROUNDED,
            border_style="bright_blue",
            padding=(0, 1),
            width=100
        )
        
        table.add_column("Category", style="bright_cyan", width=20)
        table.add_column("Status", justify="center", width=15)
        table.add_column("Details", style="white", width=35)
        table.add_column("Recommendation", style="white", width=30)
        
        # Add metrics
        metrics = module_data.get("metrics", {})
        for key, value in metrics.items():
            if key == "error":
                table.add_row(
                    Text("Error", style="bright_red"),
                    Text("⚠️", style="bright_red"),
                    Text(str(value), style="bright_red"),
                    Text("Check module configuration", style="bright_red")
                )
                continue
            
            if isinstance(value, dict):
                details = "\n".join(f"{k}: {v}" for k, v in value.items())
            else:
                details = str(value)
            
            status = self._get_metric_status(value)
            recommendation = self._get_recommendation(key, value)
            
            table.add_row(
                Text(key, style="bright_cyan"),
                status,
                Text(details, style="white"),
                Text(recommendation, style="white")
            )
        
        # Add issues
        issues = module_data.get("issues", [])
        for issue in issues:
            severity = issue.get("severity", "low")
            message = issue.get("message", "")
            symbol = self._get_severity_symbol(severity)
            severity_style = self._get_severity_style(severity)
            
            table.add_row(
                Text("Issue", style="bright_red"),
                Text(symbol, style=severity_style),
                Text(message, style=severity_style),
                Text(self._get_issue_recommendation(severity), style=severity_style)
            )
        
        # Add placeholder if no data
        if not metrics and not issues:
            table.add_row(
                "No data",
                Text("✓", style="bright_green"),
                "No issues or metrics found",
                "System is healthy"
            )
        
        return table
    
    def _create_summary_table(self, summary: Dict[str, Any]) -> Table:
        """Create a summary table"""
        table = Table(box=ROUNDED, show_header=False, border_style="bright_blue", padding=(0, 1))
        table.add_column("Category", style="bright_cyan", width=20)
        table.add_column("Value", style="white")
        
        status = summary.get("overall_status", "unknown")
        status_style = self._get_status_style(status)
        
        table.add_row(
            "Overall Status",
            status_style
        )
        table.add_row(
            "Total Issues",
            str(summary.get("total_issues", 0))
        )
        table.add_row(
            "Critical Issues",
            str(summary.get("critical_issues", 0))
        )
        table.add_row(
            "Modules Scanned",
            str(summary.get("modules_scanned", 0))
        )
        table.add_row(
            "Scan Duration",
            self._get_scan_duration()
        )
        
        return table
    
    def _get_scan_duration(self) -> str:
        """Calculate and format scan duration"""
        try:
            start = datetime.fromisoformat(self.data["scan_info"]["timestamp"])
            end = datetime.fromisoformat(self.data["scan_info"]["end_time"])
            duration = end - start
            return f"{duration.total_seconds():.1f} seconds"
        except (KeyError, ValueError):
            return "Unknown"
    
    def _get_status_style(self, status: str) -> Text:
        """Get styled status text"""
        return {
            "critical": Text("⚠️ CRITICAL", style="critical"),
            "error": Text("⚠ ERROR", style="error"),
            "warning": Text("⚡ WARNING", style="warning"),
            "ok": Text("✓ OK", style="success"),
            "unknown": Text("? UNKNOWN", style="info")
        }.get(status.lower(), Text("? UNKNOWN", style="info"))
    
    def _get_metric_status(self, value: Any) -> Text:
        """Get status indicator for a metric value"""
        if isinstance(value, (int, float)):
            if value > 90:
                return Text("⚠️ CRITICAL", style="critical")
            elif value > 75:
                return Text("⚠ WARNING", style="warning")
            elif value > 50:
                return Text("ℹ️ NOTICE", style="info")
            else:
                return Text("✓ OK", style="success")
        elif isinstance(value, dict):
            return Text("ℹ️ INFO", style="info")
        else:
            return Text("•", style="default")
    
    def _get_severity_symbol(self, severity: str) -> str:
        """Get symbol for severity level"""
        return {
            "critical": "⚠️",
            "high": "⚠",
            "medium": "⚡",
            "low": "ℹ️",
            "info": "•"
        }.get(severity.lower(), "•")
    
    def _get_severity_style(self, severity: str) -> str:
        """Get style for severity level"""
        return {
            "critical": "red bold",
            "high": "bright_red",
            "medium": "bright_yellow",
            "low": "bright_cyan",
            "info": "white"
        }.get(severity.lower(), "white")
    
    def _get_recommendation(self, key: str, value: Any) -> str:
        """Get recommendation based on metric"""
        if isinstance(value, (int, float)):
            if value > 90:
                return "Immediate action required"
            elif value > 75:
                return "Action recommended"
            elif value > 50:
                return "Monitor closely"
            else:
                return "No action needed"
        return "Review if needed"
    
    def _get_issue_recommendation(self, severity: str) -> str:
        """Get recommendation based on issue severity"""
        return {
            "critical": "Fix immediately",
            "high": "Fix as soon as possible",
            "medium": "Plan to fix soon",
            "low": "Fix when convenient",
            "info": "Review if needed"
        }.get(severity.lower(), "Review if needed")
    
    def _generate_json(self) -> str:
        """Generate a JSON report"""
        return json.dumps(self.data, indent=2)
    
    def _generate_yaml(self) -> str:
        """Generate a YAML report"""
        return yaml.dump(self.data, default_flow_style=False) 