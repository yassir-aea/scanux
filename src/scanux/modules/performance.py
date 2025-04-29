"""
Performance module for system performance monitoring
"""

import psutil
import time
from typing import Dict, Any, List, Tuple

class Module:
    """Handles system performance monitoring"""
    
    def __init__(self):
        """Initialize performance module"""
        self.metrics = {}
        self.issues = []
    
    def scan(self) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
        """Run performance checks and return metrics and issues"""
        try:
            self._check_cpu_performance()
            self._check_memory_performance()
            self._check_disk_io()
            self._check_network_io()
            self._check_process_stats()
            
            return self.metrics, self.issues
            
        except Exception as e:
            return {"error": str(e)}, []
    
    def _check_cpu_performance(self):
        """Check CPU performance metrics"""
        cpu_times = psutil.cpu_times_percent(interval=1)
        self.metrics["cpu_performance"] = {
            "user": cpu_times.user,
            "system": cpu_times.system,
            "idle": cpu_times.idle,
            "iowait": getattr(cpu_times, 'iowait', 0),
            "freq": psutil.cpu_freq().current if psutil.cpu_freq() else 0
        }
        
        if cpu_times.idle < 10:
            self.issues.append({
                "severity": "high",
                "message": f"CPU idle time critically low: {cpu_times.idle}%"
            })
    
    def _check_memory_performance(self):
        """Check memory performance metrics"""
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        self.metrics["memory_performance"] = {
            "virtual": {
                "total": vm.total,
                "available": vm.available,
                "used": vm.used,
                "cached": getattr(vm, 'cached', 0),
                "buffers": getattr(vm, 'buffers', 0)
            },
            "swap": {
                "total": swap.total,
                "used": swap.used,
                "free": swap.free
            }
        }
        
        if vm.available < vm.total * 0.1:
            self.issues.append({
                "severity": "high",
                "message": "Available memory critically low"
            })
    
    def _check_disk_io(self):
        """Check disk I/O performance"""
        disk_io = psutil.disk_io_counters()
        if disk_io:
            self.metrics["disk_io"] = {
                "read_bytes": disk_io.read_bytes,
                "write_bytes": disk_io.write_bytes,
                "read_time": disk_io.read_time,
                "write_time": disk_io.write_time
            }
    
    def _check_network_io(self):
        """Check network I/O performance"""
        net_io = psutil.net_io_counters()
        self.metrics["network_io"] = {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "errin": net_io.errin,
            "errout": net_io.errout,
            "dropin": net_io.dropin,
            "dropout": net_io.dropout
        }
        
        if net_io.errin > 0 or net_io.errout > 0:
            self.issues.append({
                "severity": "medium",
                "message": f"Network errors detected: {net_io.errin + net_io.errout} errors"
            })
    
    def _check_process_stats(self):
        """Check process statistics"""
        processes = psutil.process_iter(['name', 'cpu_percent', 'memory_percent'])
        high_resource_procs = []
        
        for proc in processes:
            try:
                if proc.info['cpu_percent'] > 50 or proc.info['memory_percent'] > 50:
                    high_resource_procs.append({
                        'name': proc.info['name'],
                        'cpu_percent': proc.info['cpu_percent'],
                        'memory_percent': proc.info['memory_percent']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        self.metrics["high_resource_processes"] = high_resource_procs
        
        if high_resource_procs:
            self.issues.append({
                "severity": "medium",
                "message": f"Found {len(high_resource_procs)} processes with high resource usage"
            }) 