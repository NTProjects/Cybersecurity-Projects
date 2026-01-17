"""Forensic Snapshot Module.

Phase 15.2: Threat Hunting & Forensics
- Host state capture
- Process / port snapshots
- Change tracking
"""
from __future__ import annotations

import json
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any


class ForensicSnapshot:
    """
    Captures forensic snapshots of host state.
    
    Phase 15.2: Creates point-in-time snapshots for investigation.
    """
    
    def __init__(self, output_dir: str | Path = "data/forensic_snapshots"):
        """
        Initialize forensic snapshot collector.
        
        Args:
            output_dir: Directory to store snapshots.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def capture_host_snapshot(self, host_id: str) -> dict[str, Any]:
        """
        Capture complete host state snapshot.
        
        Phase 15.2: Captures processes, ports, network connections, etc.
        
        Args:
            host_id: Host identifier.
        
        Returns:
            Dictionary with snapshot metadata.
        """
        timestamp = datetime.utcnow()
        snapshot_id = f"snapshot_{host_id}_{timestamp.strftime('%Y%m%d_%H%M%S')}"
        
        snapshot = {
            "snapshot_id": snapshot_id,
            "host_id": host_id,
            "timestamp": timestamp.isoformat(),
            "system": platform.system(),
            "processes": self._capture_processes(),
            "ports": self._capture_ports(),
            "network_connections": self._capture_network_connections(),
        }
        
        # Save snapshot
        snapshot_file = self.output_dir / f"{snapshot_id}.json"
        with snapshot_file.open("w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
        
        return {
            "snapshot_id": snapshot_id,
            "snapshot_file": str(snapshot_file),
            "timestamp": timestamp.isoformat(),
        }
    
    def _capture_processes(self) -> list[dict[str, Any]]:
        """Capture running processes."""
        processes = []
        system = platform.system().lower()
        
        try:
            if system == "windows":
                # Use tasklist
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if line.strip():
                            parts = line.split(",")
                            if len(parts) >= 2:
                                processes.append({
                                    "name": parts[0].strip('"'),
                                    "pid": parts[1].strip('"'),
                                    "memory": parts[4].strip('"') if len(parts) > 4 else "",
                                })
            else:
                # Use ps (Linux/macOS)
                result = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    lines = result.stdout.split("\n")[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 11:
                                processes.append({
                                    "user": parts[0],
                                    "pid": parts[1],
                                    "cpu": parts[2],
                                    "memory": parts[3],
                                    "command": " ".join(parts[10:]),
                                })
        except Exception:
            pass
        
        return processes
    
    def _capture_ports(self) -> list[dict[str, Any]]:
        """Capture listening ports."""
        ports = []
        system = platform.system().lower()
        
        try:
            if system == "windows":
                # Use netstat
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if "LISTENING" in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                addr_port = parts[1].split(":")
                                if len(addr_port) == 2:
                                    ports.append({
                                        "protocol": parts[0].lower(),
                                        "address": addr_port[0],
                                        "port": addr_port[1],
                                        "pid": parts[-1] if parts else "",
                                    })
            else:
                # Use netstat or ss (Linux)
                result = subprocess.run(
                    ["netstat", "-tuln"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode != 0:
                    # Try ss
                    result = subprocess.run(
                        ["ss", "-tuln"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                
                if result.returncode == 0:
                    for line in result.stdout.split("\n")[1:]:  # Skip header
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 4:
                                addr_port = parts[3].split(":")
                                if len(addr_port) == 2:
                                    ports.append({
                                        "protocol": parts[0],
                                        "address": addr_port[0],
                                        "port": addr_port[1],
                                    })
        except Exception:
            pass
        
        return ports
    
    def _capture_network_connections(self) -> list[dict[str, Any]]:
        """Capture active network connections."""
        connections = []
        system = platform.system().lower()
        
        try:
            if system == "windows":
                # Use netstat
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if "ESTABLISHED" in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                local = parts[1].split(":")
                                remote = parts[2].split(":")
                                if len(local) == 2 and len(remote) == 2:
                                    connections.append({
                                        "protocol": parts[0].lower(),
                                        "local_address": local[0],
                                        "local_port": local[1],
                                        "remote_address": remote[0],
                                        "remote_port": remote[1],
                                        "state": "ESTABLISHED",
                                        "pid": parts[-1] if parts else "",
                                    })
            else:
                # Use netstat or ss
                result = subprocess.run(
                    ["netstat", "-tun"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode != 0:
                    result = subprocess.run(
                        ["ss", "-tun"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                
                if result.returncode == 0:
                    for line in result.stdout.split("\n")[1:]:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 4:
                                local = parts[3].split(":")
                                remote = parts[4].split(":")
                                if len(local) == 2 and len(remote) == 2:
                                    connections.append({
                                        "protocol": parts[0],
                                        "local_address": local[0],
                                        "local_port": local[1],
                                        "remote_address": remote[0],
                                        "remote_port": remote[1],
                                        "state": parts[0] if len(parts) > 0 else "",
                                    })
        except Exception:
            pass
        
        return connections
    
    def compare_snapshots(
        self,
        snapshot_id1: str,
        snapshot_id2: str,
    ) -> dict[str, Any]:
        """
        Compare two snapshots to detect changes.
        
        Phase 15.2: Identifies what changed between snapshots.
        
        Args:
            snapshot_id1: First snapshot ID.
            snapshot_id2: Second snapshot ID.
        
        Returns:
            Dictionary with change analysis.
        """
        snapshot1_file = self.output_dir / f"{snapshot_id1}.json"
        snapshot2_file = self.output_dir / f"{snapshot_id2}.json"
        
        if not snapshot1_file.exists() or not snapshot2_file.exists():
            return {"error": "One or both snapshots not found"}
        
        with snapshot1_file.open("r", encoding="utf-8") as f:
            snap1 = json.load(f)
        with snapshot2_file.open("r", encoding="utf-8") as f:
            snap2 = json.load(f)
        
        changes = {
            "new_processes": [],
            "terminated_processes": [],
            "new_ports": [],
            "closed_ports": [],
            "new_connections": [],
            "closed_connections": [],
        }
        
        # Compare processes
        procs1 = {p.get("pid"): p for p in snap1.get("processes", [])}
        procs2 = {p.get("pid"): p for p in snap2.get("processes", [])}
        
        for pid, proc in procs2.items():
            if pid not in procs1:
                changes["new_processes"].append(proc)
        
        for pid, proc in procs1.items():
            if pid not in procs2:
                changes["terminated_processes"].append(proc)
        
        # Compare ports
        ports1 = {(p.get("port"), p.get("protocol")): p for p in snap1.get("ports", [])}
        ports2 = {(p.get("port"), p.get("protocol")): p for p in snap2.get("ports", [])}
        
        for key, port in ports2.items():
            if key not in ports1:
                changes["new_ports"].append(port)
        
        for key, port in ports1.items():
            if key not in ports2:
                changes["closed_ports"].append(port)
        
        # Compare connections
        conns1 = {
            (c.get("local_port"), c.get("remote_address"), c.get("remote_port")): c
            for c in snap1.get("network_connections", [])
        }
        conns2 = {
            (c.get("local_port"), c.get("remote_address"), c.get("remote_port")): c
            for c in snap2.get("network_connections", [])
        }
        
        for key, conn in conns2.items():
            if key not in conns1:
                changes["new_connections"].append(conn)
        
        for key, conn in conns1.items():
            if key not in conns2:
                changes["closed_connections"].append(conn)
        
        return {
            "snapshot1": snapshot_id1,
            "snapshot2": snapshot_id2,
            "changes": changes,
            "summary": {
                "new_processes": len(changes["new_processes"]),
                "terminated_processes": len(changes["terminated_processes"]),
                "new_ports": len(changes["new_ports"]),
                "closed_ports": len(changes["closed_ports"]),
                "new_connections": len(changes["new_connections"]),
                "closed_connections": len(changes["closed_connections"]),
            },
        }
