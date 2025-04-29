"""
Enhanced system module for comprehensive system analysis
"""

import os
import psutil
import platform
import socket
import distro
from typing import Dict, Any, List, Tuple
from datetime import datetime
from ..core.utils import format_size

class Module:
    """Advanced system analysis module"""
    
    def __init__(self):
        """Initialize system module"""
        self.metrics = {}
        self.issues = []
    
    def scan(self) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
        """Run comprehensive system checks"""
        try:
            self._check_system_info()
            self._check_disk_usage()
            self._check_memory_usage()
            self._check_cpu_usage()
            self._check_system_load()
            self._check_network_info()
            self._check_process_info()
            self._check_hardware_info()
            self._check_power_info()
            self._check_temperature()
            
            return self.metrics, self.issues
            
        except Exception as e:
            return {"error": str(e)}, []
    
    def _check_system_info(self):
        """Gather detailed system information"""
        self.metrics["system_info"] = {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "distribution": " ".join(distro.linux_distribution()),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "timezone": datetime.now().astimezone().tzname()
        }
    
    def _check_disk_usage(self):
        """Check disk space usage with detailed metrics"""
        for partition in psutil.disk_partitions(all=True):
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                io_counters = psutil.disk_io_counters(perdisk=True)
                
                disk_name = partition.device.split('/')[-1]
                disk_io = io_counters.get(disk_name, {})
                
                self.metrics[f"disk_usage_{partition.mountpoint}"] = {
                    "device": partition.device,
                    "filesystem": partition.fstype,
                    "mountpoint": partition.mountpoint,
                    "total": format_size(usage.total),
                    "used": format_size(usage.used),
                    "free": format_size(usage.free),
                    "percent": usage.percent,
                    "io_stats": {
                        "read_count": getattr(disk_io, 'read_count', 0),
                        "write_count": getattr(disk_io, 'write_count', 0),
                        "read_bytes": format_size(getattr(disk_io, 'read_bytes', 0)),
                        "write_bytes": format_size(getattr(disk_io, 'write_bytes', 0))
                    } if disk_io else {}
                }
                
                # Check disk health
                if usage.percent > 90:
                    self.issues.append({
                        "severity": "high",
                        "message": f"Critical disk usage on {partition.mountpoint}: {usage.percent}%"
                    })
                elif usage.percent > 80:
                    self.issues.append({
                        "severity": "medium",
                        "message": f"High disk usage on {partition.mountpoint}: {usage.percent}%"
                    })
            except (PermissionError, OSError):
                continue
    
    def _check_memory_usage(self):
        """Check detailed memory usage"""
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        self.metrics["memory"] = {
            "total": format_size(memory.total),
            "available": format_size(memory.available),
            "used": format_size(memory.used),
            "free": format_size(memory.free),
            "percent": memory.percent,
            "active": format_size(memory.active),
            "inactive": format_size(memory.inactive),
            "buffers": format_size(getattr(memory, 'buffers', 0)),
            "cached": format_size(getattr(memory, 'cached', 0)),
            "swap": {
                "total": format_size(swap.total),
                "used": format_size(swap.used),
                "free": format_size(swap.free),
                "percent": swap.percent,
                "sin": format_size(swap.sin),
                "sout": format_size(swap.sout)
            }
        }
        
        # Memory health checks
        if memory.percent > 90:
            self.issues.append({
                "severity": "high",
                "message": f"Critical memory usage: {memory.percent}%"
            })
        elif memory.percent > 80:
            self.issues.append({
                "severity": "medium",
                "message": f"High memory usage: {memory.percent}%"
            })
        
        if swap.percent > 80:
            self.issues.append({
                "severity": "medium",
                "message": f"High swap usage: {swap.percent}%"
            })
    
    def _check_cpu_usage(self):
        """Check detailed CPU metrics"""
        cpu_freq = psutil.cpu_freq(percpu=True) if hasattr(psutil, 'cpu_freq') else None
        cpu_stats = psutil.cpu_stats() if hasattr(psutil, 'cpu_stats') else None
        
        self.metrics["cpu"] = {
            "percent": psutil.cpu_percent(interval=1),
            "count": {
                "physical": psutil.cpu_count(logical=False),
                "logical": psutil.cpu_count()
            },
            "frequencies": [
                {
                    "current": freq.current,
                    "min": freq.min,
                    "max": freq.max
                } for freq in cpu_freq
            ] if cpu_freq else [],
            "stats": {
                "ctx_switches": cpu_stats.ctx_switches,
                "interrupts": cpu_stats.interrupts,
                "soft_interrupts": cpu_stats.soft_interrupts,
                "syscalls": cpu_stats.syscalls
            } if cpu_stats else {},
            "per_cpu_percent": psutil.cpu_percent(interval=1, percpu=True)
        }
        
        # CPU health checks
        if self.metrics["cpu"]["percent"] > 90:
            self.issues.append({
                "severity": "high",
                "message": f"Critical CPU usage: {self.metrics['cpu']['percent']}%"
            })
        elif self.metrics["cpu"]["percent"] > 80:
            self.issues.append({
                "severity": "medium",
                "message": f"High CPU usage: {self.metrics['cpu']['percent']}%"
            })
    
    def _check_system_load(self):
        """Check system load with detailed metrics"""
        load1, load5, load15 = os.getloadavg()
        cpu_count = psutil.cpu_count()
        
        self.metrics["load_average"] = {
            "1min": load1,
            "5min": load5,
            "15min": load15,
            "per_cpu": {
                "1min": load1 / cpu_count,
                "5min": load5 / cpu_count,
                "15min": load15 / cpu_count
            }
        }
        
        # Load average health checks
        if load5 > cpu_count * 2:
            self.issues.append({
                "severity": "high",
                "message": f"Critical system load: {load5} (5min average)"
            })
        elif load5 > cpu_count:
            self.issues.append({
                "severity": "medium",
                "message": f"High system load: {load5} (5min average)"
            })
    
    def _check_network_info(self):
        """Gather detailed network information"""
        net_io = psutil.net_io_counters(pernic=True)
        net_connections = psutil.net_connections()
        
        self.metrics["network"] = {
            "interfaces": {},
            "connections": {
                "established": len([conn for conn in net_connections if conn.status == 'ESTABLISHED']),
                "listen": len([conn for conn in net_connections if conn.status == 'LISTEN']),
                "total": len(net_connections)
            }
        }
        
        for interface, addrs in psutil.net_if_addrs().items():
            interface_metrics = {
                "addresses": [],
                "stats": {}
            }
            
            for addr in addrs:
                addr_info = {
                    "family": str(addr.family),
                    "address": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast if hasattr(addr, 'broadcast') else None
                }
                interface_metrics["addresses"].append(addr_info)
            
            if interface in net_io:
                stats = net_io[interface]
                interface_metrics["stats"] = {
                    "bytes_sent": format_size(stats.bytes_sent),
                    "bytes_recv": format_size(stats.bytes_recv),
                    "packets_sent": stats.packets_sent,
                    "packets_recv": stats.packets_recv,
                    "errin": stats.errin,
                    "errout": stats.errout,
                    "dropin": stats.dropin,
                    "dropout": stats.dropout
                }
            
            self.metrics["network"]["interfaces"][interface] = interface_metrics
    
    def _check_process_info(self):
        """Gather process information"""
        processes = []
        total_threads = 0
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
            try:
                pinfo = proc.info
                if pinfo['cpu_percent'] > 5 or pinfo['memory_percent'] > 5:
                    processes.append({
                        "pid": pinfo['pid'],
                        "name": pinfo['name'],
                        "username": pinfo['username'],
                        "cpu_percent": pinfo['cpu_percent'],
                        "memory_percent": pinfo['memory_percent'],
                        "status": pinfo['status']
                    })
                total_threads += proc.num_threads()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        self.metrics["processes"] = {
            "total": len(psutil.pids()),
            "running": len([p for p in processes if p['status'] == 'running']),
            "sleeping": len([p for p in processes if p['status'] == 'sleeping']),
            "total_threads": total_threads,
            "high_resource_processes": sorted(processes, 
                key=lambda x: (x['cpu_percent'] + x['memory_percent']), 
                reverse=True)[:10]
        }
    
    def _check_hardware_info(self):
        """Gather hardware information"""
        self.metrics["hardware"] = {
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "uptime": int(datetime.now().timestamp() - psutil.boot_time())
        }
        
        # Add CPU frequency information if available
        try:
            cpu_freq = psutil.cpu_freq()
            if cpu_freq:
                self.metrics["hardware"]["cpu_freq"] = {
                    "current": f"{cpu_freq.current:.1f}MHz",
                    "min": f"{cpu_freq.min:.1f}MHz",
                    "max": f"{cpu_freq.max:.1f}MHz"
                }
        except Exception:
            pass
    
    def _check_power_info(self):
        """Check power information if available"""
        try:
            battery = psutil.sensors_battery()
            if battery:
                self.metrics["power"] = {
                    "battery_percent": battery.percent,
                    "power_plugged": battery.power_plugged,
                    "time_left": str(datetime.timedelta(seconds=battery.secsleft)) if battery.secsleft > 0 else "unknown"
                }
                
                if not battery.power_plugged and battery.percent < 20:
                    self.issues.append({
                        "severity": "high",
                        "message": f"Low battery: {battery.percent}%"
                    })
        except Exception:
            pass
    
    def _check_temperature(self):
        """Check system temperatures if available"""
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                self.metrics["temperature"] = {}
                for name, entries in temps.items():
                    self.metrics["temperature"][name] = [
                        {
                            "label": temp.label,
                            "current": temp.current,
                            "high": temp.high,
                            "critical": temp.critical
                        } for temp in entries
                    ]
                    
                    # Check for high temperatures
                    for temp in entries:
                        if temp.critical and temp.current >= temp.critical:
                            self.issues.append({
                                "severity": "high",
                                "message": f"Critical temperature for {name} ({temp.label}): {temp.current}°C"
                            })
                        elif temp.high and temp.current >= temp.high:
                            self.issues.append({
                                "severity": "medium",
                                "message": f"High temperature for {name} ({temp.label}): {temp.current}°C"
                            })
        except Exception:
            pass 