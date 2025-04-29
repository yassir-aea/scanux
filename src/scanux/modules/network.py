"""
Enhanced network module for comprehensive network analysis and security scanning
"""

import socket
import nmap
import netifaces
import psutil
import subprocess
import re
from typing import Dict, Any, List, Tuple
from ipaddress import ip_address, ip_network
import ssl
from datetime import datetime

class Module:
    """Advanced network analysis and security module"""
    
    def __init__(self):
        """Initialize network module"""
        self.metrics = {}
        self.issues = []
        self.nm = nmap.PortScanner()
    
    def scan(self) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
        """Run comprehensive network security checks"""
        try:
            self._scan_interfaces()
            self._scan_open_ports()
            self._check_network_security()
            self._analyze_connections()
            self._check_dns_settings()
            self._check_routing_table()
            self._check_firewall_status()
            self._check_network_services()
            self._analyze_bandwidth()
            self._check_ssl_certificates()
            
            return self.metrics, self.issues
        except Exception as e:
            return {"error": str(e)}, []
    
    def _scan_interfaces(self):
        """Analyze network interfaces and their configuration"""
        interfaces = {}
        
        for iface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(iface)
                interface_info = {
                    "name": iface,
                    "ipv4": [],
                    "ipv6": [],
                    "mac": None,
                    "status": "down",
                    "mtu": None,
                    "speed": None,
                    "duplex": None
                }
                
                # Get IPv4 addresses
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        interface_info["ipv4"].append({
                            "address": addr.get("addr"),
                            "netmask": addr.get("netmask"),
                            "broadcast": addr.get("broadcast")
                        })
                
                # Get IPv6 addresses
                if netifaces.AF_INET6 in addrs:
                    for addr in addrs[netifaces.AF_INET6]:
                        interface_info["ipv6"].append({
                            "address": addr.get("addr"),
                            "netmask": addr.get("netmask"),
                            "scope": addr.get("scope")
                        })
                
                # Get MAC address
                if netifaces.AF_LINK in addrs:
                    interface_info["mac"] = addrs[netifaces.AF_LINK][0].get("addr")
                
                # Get interface status and additional info
                try:
                    stats = psutil.net_if_stats()[iface]
                    interface_info.update({
                        "status": "up" if stats.isup else "down",
                        "mtu": stats.mtu,
                        "speed": f"{stats.speed}Mbps" if stats.speed > 0 else "unknown",
                        "duplex": stats.duplex if hasattr(stats, "duplex") else "unknown"
                    })
                except Exception:
                    pass
                
                interfaces[iface] = interface_info
                
                # Check for security issues
                self._check_interface_security(interface_info)
                
            except Exception as e:
                self.issues.append({
                    "severity": "low",
                    "message": f"Error analyzing interface {iface}: {str(e)}"
                })
        
        self.metrics["interfaces"] = interfaces
    
    def _scan_open_ports(self):
        """Perform comprehensive port scanning"""
        open_ports = {}
        suspicious_ports = set([21, 23, 445, 135, 137, 138, 139, 1433, 3306, 3389])
        
        for iface in self.metrics["interfaces"]:
            for ip_info in self.metrics["interfaces"][iface]["ipv4"]:
                ip = ip_info["address"]
                if self._is_private_ip(ip):
                    try:
                        # Fast SYN scan for most common ports
                        self.nm.scan(ip, arguments="-sS -F -T4")
                        
                        if ip in self.nm.all_hosts():
                            open_ports[ip] = []
                            for port in self.nm[ip]["tcp"]:
                                port_info = self.nm[ip]["tcp"][port]
                                port_data = {
                                    "port": port,
                                    "state": port_info["state"],
                                    "service": port_info["name"],
                                    "version": port_info.get("version", ""),
                                    "product": port_info.get("product", "")
                                }
                                open_ports[ip].append(port_data)
                                
                                # Check for suspicious ports
                                if port in suspicious_ports:
                                    self.issues.append({
                                        "severity": "high",
                                        "message": f"Suspicious port {port} ({port_info['name']}) open on {ip}"
                                    })
                                
                                # Check for potentially vulnerable services
                                if port_info["state"] == "open" and not port_info.get("version"):
                                    self.issues.append({
                                        "severity": "medium",
                                        "message": f"Unknown service version on port {port} ({ip})"
                                    })
                    
                    except Exception as e:
                        self.issues.append({
                            "severity": "low",
                            "message": f"Error scanning ports on {ip}: {str(e)}"
                        })
        
        self.metrics["open_ports"] = open_ports
    
    def _check_network_security(self):
        """Analyze network security configuration"""
        security_checks = {
            "ipv6_enabled": False,
            "default_gateway": None,
            "dns_servers": [],
            "arp_cache": [],
            "routing_entries": 0,
            "firewall_enabled": False,
            "network_services": []
        }
        
        # Check IPv6 status
        for iface in self.metrics["interfaces"].values():
            if iface["ipv6"]:
                security_checks["ipv6_enabled"] = True
                break
        
        # Get default gateway
        try:
            gws = netifaces.gateways()
            default_gw = gws.get("default", {}).get(netifaces.AF_INET, [None])[0]
            security_checks["default_gateway"] = default_gw
        except Exception:
            pass
        
        # Get DNS servers
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        security_checks["dns_servers"].append(line.split()[1])
        except Exception:
            pass
        
        # Check ARP cache
        try:
            arp_output = subprocess.check_output(["arp", "-a"]).decode()
            security_checks["arp_cache"] = self._parse_arp_output(arp_output)
        except Exception:
            pass
        
        self.metrics["security"] = security_checks
    
    def _analyze_connections(self):
        """Analyze active network connections"""
        connections = {
            "established": [],
            "listening": [],
            "total": 0,
            "foreign_connections": [],
            "protocols": {
                "tcp": 0,
                "udp": 0,
                "tcp6": 0,
                "udp6": 0
            }
        }
        
        try:
            for conn in psutil.net_connections(kind="all"):
                conn_type = "established" if conn.status == "ESTABLISHED" else "listening"
                
                if conn.laddr:
                    local_ip = conn.laddr.ip
                    local_port = conn.laddr.port
                    
                    connection_info = {
                        "local_address": f"{local_ip}:{local_port}",
                        "foreign_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": conn.status,
                        "pid": conn.pid,
                        "program": self._get_process_name(conn.pid) if conn.pid else None
                    }
                    
                    if conn_type == "established":
                        connections["established"].append(connection_info)
                        if conn.raddr and not self._is_private_ip(conn.raddr.ip):
                            connections["foreign_connections"].append(connection_info)
                    else:
                        connections["listening"].append(connection_info)
                    
                    # Update protocol counters
                    if conn.type == socket.SOCK_STREAM:
                        if ":" in local_ip:
                            connections["protocols"]["tcp6"] += 1
                        else:
                            connections["protocols"]["tcp"] += 1
                    elif conn.type == socket.SOCK_DGRAM:
                        if ":" in local_ip:
                            connections["protocols"]["udp6"] += 1
                        else:
                            connections["protocols"]["udp"] += 1
            
            connections["total"] = len(connections["established"]) + len(connections["listening"])
            
            # Check for security issues
            if len(connections["foreign_connections"]) > 10:
                self.issues.append({
                    "severity": "medium",
                    "message": f"High number of foreign connections: {len(connections['foreign_connections'])}"
                })
            
        except Exception as e:
            self.issues.append({
                "severity": "low",
                "message": f"Error analyzing connections: {str(e)}"
            })
        
        self.metrics["connections"] = connections
    
    def _check_dns_settings(self):
        """Analyze DNS configuration and performance"""
        dns_metrics = {
            "servers": [],
            "response_times": {},
            "issues": []
        }
        
        test_domains = ["google.com", "amazon.com", "microsoft.com"]
        
        try:
            # Get DNS servers
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns_metrics["servers"].append(line.split()[1])
            
            # Test DNS resolution
            for domain in test_domains:
                try:
                    start_time = time.time()
                    socket.gethostbyname(domain)
                    response_time = (time.time() - start_time) * 1000
                    dns_metrics["response_times"][domain] = f"{response_time:.2f}ms"
                    
                    if response_time > 1000:
                        self.issues.append({
                            "severity": "medium",
                            "message": f"Slow DNS resolution for {domain}: {response_time:.2f}ms"
                        })
                except Exception as e:
                    dns_metrics["issues"].append(f"Failed to resolve {domain}: {str(e)}")
                    self.issues.append({
                        "severity": "high",
                        "message": f"DNS resolution failure for {domain}"
                    })
        
        except Exception as e:
            self.issues.append({
                "severity": "medium",
                "message": f"Error checking DNS settings: {str(e)}"
            })
        
        self.metrics["dns"] = dns_metrics
    
    def _check_routing_table(self):
        """Analyze routing table configuration"""
        routing = {
            "default_gateway": None,
            "routes": [],
            "static_routes": 0
        }
        
        try:
            # Get routing table
            output = subprocess.check_output(["netstat", "-rn"]).decode()
            routes = self._parse_routing_table(output)
            routing["routes"] = routes
            
            # Analyze routes
            for route in routes:
                if route.get("destination") == "default":
                    routing["default_gateway"] = route.get("gateway")
                if route.get("flags", "").lower().find("s") != -1:
                    routing["static_routes"] += 1
            
            # Check for routing issues
            if not routing["default_gateway"]:
                self.issues.append({
                    "severity": "high",
                    "message": "No default gateway configured"
                })
            
            if routing["static_routes"] > 10:
                self.issues.append({
                    "severity": "medium",
                    "message": f"High number of static routes: {routing['static_routes']}"
                })
        
        except Exception as e:
            self.issues.append({
                "severity": "low",
                "message": f"Error analyzing routing table: {str(e)}"
            })
        
        self.metrics["routing"] = routing
    
    def _check_firewall_status(self):
        """Check firewall configuration and status"""
        firewall = {
            "enabled": False,
            "type": None,
            "rules_count": 0,
            "default_policy": None
        }
        
        try:
            # Try iptables
            try:
                output = subprocess.check_output(["iptables", "-L", "-n"]).decode()
                firewall["type"] = "iptables"
                firewall["enabled"] = True
                firewall["rules_count"] = len(re.findall(r"Chain", output))
                
                # Check default policies
                chains = re.findall(r"Chain (\w+) \(policy (\w+)\)", output)
                if chains:
                    firewall["default_policy"] = {chain: policy for chain, policy in chains}
                
                # Check for potentially dangerous rules
                if "ACCEPT" in output and "0.0.0.0/0" in output:
                    self.issues.append({
                        "severity": "high",
                        "message": "Potentially dangerous firewall rule: ACCEPT from any source"
                    })
            
            except Exception:
                # Try ufw
                try:
                    output = subprocess.check_output(["ufw", "status"]).decode()
                    firewall["type"] = "ufw"
                    firewall["enabled"] = "active" in output.lower()
                    firewall["rules_count"] = len(re.findall(r"ALLOW|DENY", output))
                except Exception:
                    pass
        
        except Exception as e:
            self.issues.append({
                "severity": "medium",
                "message": f"Error checking firewall status: {str(e)}"
            })
        
        if not firewall["enabled"]:
            self.issues.append({
                "severity": "high",
                "message": "Firewall is not enabled"
            })
        
        self.metrics["firewall"] = firewall
    
    def _check_network_services(self):
        """Analyze running network services"""
        services = {
            "listening": [],
            "potentially_dangerous": [],
            "unidentified": []
        }
        
        dangerous_ports = {
            21: "FTP",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            137: "NetBIOS",
            139: "NetBIOS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP"
        }
        
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN":
                    service = {
                        "port": conn.laddr.port,
                        "address": conn.laddr.ip,
                        "pid": conn.pid,
                        "program": self._get_process_name(conn.pid) if conn.pid else "unknown"
                    }
                    
                    services["listening"].append(service)
                    
                    # Check for dangerous services
                    if service["port"] in dangerous_ports:
                        service["service_name"] = dangerous_ports[service["port"]]
                        services["potentially_dangerous"].append(service)
                        self.issues.append({
                            "severity": "high",
                            "message": f"Potentially dangerous service {service['service_name']} running on port {service['port']}"
                        })
                    
                    # Check for unidentified services
                    if service["program"] == "unknown":
                        services["unidentified"].append(service)
                        self.issues.append({
                            "severity": "medium",
                            "message": f"Unidentified service on port {service['port']}"
                        })
        
        except Exception as e:
            self.issues.append({
                "severity": "low",
                "message": f"Error analyzing network services: {str(e)}"
            })
        
        self.metrics["services"] = services
    
    def _analyze_bandwidth(self):
        """Analyze network bandwidth usage"""
        bandwidth = {
            "interfaces": {},
            "total": {
                "bytes_sent": 0,
                "bytes_recv": 0,
                "packets_sent": 0,
                "packets_recv": 0
            }
        }
        
        try:
            # Get network I/O counters for all interfaces
            net_io = psutil.net_io_counters(pernic=True)
            
            for interface, stats in net_io.items():
                interface_stats = {
                    "bytes_sent": stats.bytes_sent,
                    "bytes_recv": stats.bytes_recv,
                    "packets_sent": stats.packets_sent,
                    "packets_recv": stats.packets_recv,
                    "errors_in": stats.errin,
                    "errors_out": stats.errout,
                    "drops_in": stats.dropin,
                    "drops_out": stats.dropout
                }
                
                bandwidth["interfaces"][interface] = interface_stats
                
                # Update totals
                bandwidth["total"]["bytes_sent"] += stats.bytes_sent
                bandwidth["total"]["bytes_recv"] += stats.bytes_recv
                bandwidth["total"]["packets_sent"] += stats.packets_sent
                bandwidth["total"]["packets_recv"] += stats.packets_recv
                
                # Check for errors
                if stats.errin > 0 or stats.errout > 0:
                    self.issues.append({
                        "severity": "medium",
                        "message": f"Network errors detected on interface {interface}"
                    })
                
                if stats.dropin > 0 or stats.dropout > 0:
                    self.issues.append({
                        "severity": "medium",
                        "message": f"Packet drops detected on interface {interface}"
                    })
        
        except Exception as e:
            self.issues.append({
                "severity": "low",
                "message": f"Error analyzing bandwidth usage: {str(e)}"
            })
        
        self.metrics["bandwidth"] = bandwidth
    
    def _check_ssl_certificates(self):
        """Check SSL/TLS certificates on listening ports"""
        certificates = {
            "valid": [],
            "expired": [],
            "self_signed": [],
            "issues": []
        }
        
        try:
            for service in self.metrics.get("services", {}).get("listening", []):
                try:
                    if service["port"] in [443, 8443]:
                        context = ssl.create_default_context()
                        with socket.create_connection((service["address"], service["port"])) as sock:
                            with context.wrap_socket(sock, server_hostname=service["address"]) as ssock:
                                cert = ssock.getpeercert()
                                
                                cert_info = {
                                    "subject": dict(x[0] for x in cert["subject"]),
                                    "issuer": dict(x[0] for x in cert["issuer"]),
                                    "version": cert["version"],
                                    "serialNumber": cert["serialNumber"],
                                    "notBefore": cert["notBefore"],
                                    "notAfter": cert["notAfter"]
                                }
                                
                                # Check certificate validity
                                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                                if not_after < datetime.now():
                                    certificates["expired"].append(cert_info)
                                    self.issues.append({
                                        "severity": "high",
                                        "message": f"Expired SSL certificate found on port {service['port']}"
                                    })
                                else:
                                    certificates["valid"].append(cert_info)
                                
                                # Check for self-signed certificates
                                if cert_info["subject"] == cert_info["issuer"]:
                                    certificates["self_signed"].append(cert_info)
                                    self.issues.append({
                                        "severity": "medium",
                                        "message": f"Self-signed certificate found on port {service['port']}"
                                    })
                
                except Exception as e:
                    certificates["issues"].append({
                        "port": service["port"],
                        "error": str(e)
                    })
        
        except Exception as e:
            self.issues.append({
                "severity": "low",
                "message": f"Error checking SSL certificates: {str(e)}"
            })
        
        self.metrics["certificates"] = certificates
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private"""
        try:
            return ip_address(ip).is_private
        except ValueError:
            return False
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name from PID"""
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"
    
    def _parse_arp_output(self, output: str) -> List[Dict[str, str]]:
        """Parse ARP table output"""
        entries = []
        for line in output.split("\n"):
            if line:
                match = re.search(r"\(([\d\.]+)\) at ([\w:]+)", line)
                if match:
                    entries.append({
                        "ip": match.group(1),
                        "mac": match.group(2)
                    })
        return entries
    
    def _parse_routing_table(self, output: str) -> List[Dict[str, str]]:
        """Parse routing table output"""
        routes = []
        lines = output.split("\n")[2:]  # Skip header lines
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    routes.append({
                        "destination": parts[0],
                        "gateway": parts[1],
                        "flags": parts[2],
                        "interface": parts[-1]
                    })
        return routes 