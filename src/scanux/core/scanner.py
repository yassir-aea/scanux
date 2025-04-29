"""
Core scanner module for system analysis
"""

import os
import psutil
import platform
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path
from .utils import format_size

class Scanner:
    """Core scanner class that manages module execution and data collection"""
    
    def __init__(self):
        """Initialize scanner with default configuration"""
        self.data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "version": "1.0.23",
                "status": "initializing"
            },
            "system_info": self._get_system_info(),
            "modules": {}
        }
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Collect basic system information"""
        try:
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            cpu_freq = psutil.cpu_freq() if hasattr(psutil, 'cpu_freq') else None
            
            return {
                "hostname": platform.node(),
                "os": {
                    "name": platform.system(),
                    "version": platform.version(),
                    "release": platform.release(),
                    "architecture": platform.machine()
                },
                "hardware": {
                    "processor": platform.processor(),
                    "cpu_cores": {
                        "physical": psutil.cpu_count(logical=False),
                        "logical": psutil.cpu_count()
                    },
                    "cpu_freq": {
                        "current": f"{cpu_freq.current:.1f}MHz" if cpu_freq else "N/A",
                        "min": f"{cpu_freq.min:.1f}MHz" if cpu_freq else "N/A",
                        "max": f"{cpu_freq.max:.1f}MHz" if cpu_freq else "N/A"
                    } if cpu_freq else {},
                    "memory": {
                        "total": format_size(mem.total),
                        "available": format_size(mem.available),
                        "used": format_size(mem.used),
                        "free": format_size(mem.free),
                        "percent": mem.percent
                    },
                    "disk": {
                        "total": format_size(disk.total),
                        "used": format_size(disk.used),
                        "free": format_size(disk.free),
                        "percent": disk.percent
                    }
                },
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
        except Exception as e:
            return {
                "error": str(e),
                "hostname": "Unknown",
                "os": {"name": "Unknown", "version": "Unknown"},
                "hardware": {"processor": "Unknown"}
            }
    
    def add_module_result(self, module_name: str, metrics: Dict[str, Any], issues: List[Dict[str, Any]]) -> None:
        """Add results from a module to the scan data"""
        self.data["modules"][module_name] = {
            "status": "error" if any(i.get("severity") == "critical" for i in issues)
                     else "warning" if issues
                     else "ok",
            "metrics": metrics,
            "issues": issues,
            "timestamp": datetime.now().isoformat()
        }
    
    def get_results(self) -> Dict[str, Any]:
        """Get the complete scan results"""
        self.data["scan_info"]["status"] = "completed"
        self.data["scan_info"]["end_time"] = datetime.now().isoformat()
        
        # Calculate summary statistics
        total_issues = sum(len(m.get("issues", [])) for m in self.data["modules"].values())
        critical_issues = sum(
            sum(1 for i in m.get("issues", []) if i.get("severity") == "critical")
            for m in self.data["modules"].values()
        )
        
        self.data["summary"] = {
            "total_issues": total_issues,
            "critical_issues": critical_issues,
            "modules_scanned": len(self.data["modules"]),
            "overall_status": "critical" if critical_issues > 0 else
                            "warning" if total_issues > 0 else "ok"
        }
        
        return self.data 