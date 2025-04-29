"""
Security module for system security checks
"""

import os
import pwd
import grp
import stat
from typing import Dict, Any, List, Tuple
from pathlib import Path

class Module:
    """Handles system security checks"""
    
    def __init__(self):
        """Initialize security module"""
        self.metrics = {}
        self.issues = []
    
    def scan(self) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
        """Run security checks and return metrics and issues"""
        try:
            self._check_root_login()
            self._check_ssh_config()
            self._check_file_permissions()
            self._check_sudo_config()
            self._check_system_updates()
            
            # Create summary after all checks
            self.metrics["summary"] = self.create_security_summary()
            
            return self.metrics, self.issues
            
        except Exception as e:
            return {"error": str(e)}, []
    
    def create_security_summary(self) -> Dict[str, Any]:
        """Create a summary of security issues found during scanning"""
        severity_counts = {
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        # Count issues by severity
        for issue in self.issues:
            severity = issue.get("severity", "low")
            severity_counts[severity] += 1
        
        # Calculate risk score (0-100)
        # High severity issues count for 50 points
        # Medium severity issues count for 30 points
        # Low severity issues count for 20 points
        total_issues = sum(severity_counts.values())
        if total_issues > 0:
            risk_score = min(100, (
                (severity_counts["high"] * 50) +
                (severity_counts["medium"] * 30) +
                (severity_counts["low"] * 20)
            ) / total_issues)
        else:
            risk_score = 0
            
        return {
            "total_issues": total_issues,
            "severity_distribution": severity_counts,
            "risk_score": round(risk_score, 2),
            "status": "critical" if risk_score > 70 else "warning" if risk_score > 30 else "good"
        }
    
    def _check_root_login(self):
        """Check if root login is disabled"""
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                config = f.read()
                if 'PermitRootLogin yes' in config:
                    self.issues.append({
                        "severity": "high",
                        "message": "Root login is enabled via SSH"
                    })
        except FileNotFoundError:
            pass
    
    def _check_ssh_config(self):
        """Check SSH configuration security"""
        ssh_config = Path('/etc/ssh/sshd_config')
        if ssh_config.exists():
            perms = ssh_config.stat().st_mode
            if perms & stat.S_IROTH or perms & stat.S_IWOTH:
                self.issues.append({
                    "severity": "high",
                    "message": "SSH config file has too permissive permissions"
                })
    
    def _check_file_permissions(self):
        """Check important file permissions"""
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/sudoers'
        ]
        
        for file in critical_files:
            try:
                st = os.stat(file)
                if st.st_mode & stat.S_IROTH or st.st_mode & stat.S_IWOTH:
                    self.issues.append({
                        "severity": "high",
                        "message": f"Critical file {file} has unsafe permissions"
                    })
            except FileNotFoundError:
                continue
    
    def _check_sudo_config(self):
        """Check sudo configuration"""
        try:
            with open('/etc/sudoers', 'r') as f:
                content = f.read()
                if 'NOPASSWD: ALL' in content:
                    self.issues.append({
                        "severity": "high",
                        "message": "NOPASSWD:ALL found in sudoers file"
                    })
        except FileNotFoundError:
            pass
    
    def _check_system_updates(self):
        """Check if system updates are available"""
        # This is a placeholder - actual implementation would depend on the OS
        self.metrics["updates_check"] = {
            "last_check": "Not implemented",
            "updates_available": "Unknown"
        } 