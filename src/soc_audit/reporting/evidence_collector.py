"""Evidence Auto-Collection for Audit Artifacts.

Phase 14.2: Compliance & Audit Automation
- "Show me proof" buttons
- Timestamped artifacts
- Exportable audit packets
"""
from __future__ import annotations

import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from soc_audit.core.interfaces import Finding


class EvidenceCollector:
    """
    Collects and packages evidence for audit artifacts.
    
    Phase 14.2: Creates timestamped, exportable audit packets.
    """
    
    def __init__(self, output_dir: str | Path = "data/audit_evidence"):
        """
        Initialize evidence collector.
        
        Args:
            output_dir: Directory to store evidence packages.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def collect_finding_evidence(
        self,
        finding: Finding,
        additional_evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Collect evidence for a finding.
        
        Phase 14.2: Creates evidence package for a finding.
        
        Args:
            finding: Finding object.
            additional_evidence: Additional evidence to include.
        
        Returns:
            Dictionary with evidence package metadata.
        """
        timestamp = datetime.utcnow()
        evidence_id = f"evidence_{timestamp.strftime('%Y%m%d_%H%M%S')}_{hash(finding.title) % 10000:04d}"
        
        evidence_package = {
            "evidence_id": evidence_id,
            "timestamp": timestamp.isoformat(),
            "finding": {
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "evidence": finding.evidence,
                "recommendation": finding.recommendation,
                "control_ids": finding.control_ids,
                "compliance_status": finding.compliance_status,
                "mitre_ids": finding.mitre_ids,
                "rba_score": finding.rba_score,
            },
            "additional_evidence": additional_evidence or {},
        }
        
        # Save evidence package
        evidence_file = self.output_dir / f"{evidence_id}.json"
        with evidence_file.open("w", encoding="utf-8") as f:
            json.dump(evidence_package, f, indent=2)
        
        return {
            "evidence_id": evidence_id,
            "evidence_file": str(evidence_file),
            "timestamp": timestamp.isoformat(),
        }
    
    def create_audit_packet(
        self,
        findings: list[Finding],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Create exportable audit packet (ZIP file).
        
        Phase 14.2: Packages multiple findings into a single audit packet.
        
        Args:
            findings: List of findings to include.
            metadata: Additional metadata (auditor name, date range, etc.).
        
        Returns:
            Path to created audit packet ZIP file.
        """
        timestamp = datetime.utcnow()
        packet_id = f"audit_packet_{timestamp.strftime('%Y%m%d_%H%M%S')}"
        packet_dir = self.output_dir / packet_id
        packet_dir.mkdir(exist_ok=True)
        
        # Create manifest
        manifest = {
            "packet_id": packet_id,
            "created_at": timestamp.isoformat(),
            "finding_count": len(findings),
            "metadata": metadata or {},
            "findings": [],
        }
        
        # Collect evidence for each finding
        for finding in findings:
            evidence_info = self.collect_finding_evidence(finding)
            manifest["findings"].append({
                "title": finding.title,
                "severity": finding.severity,
                "evidence_id": evidence_info["evidence_id"],
            })
        
        # Save manifest
        manifest_file = packet_dir / "manifest.json"
        with manifest_file.open("w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        
        # Create ZIP file
        zip_path = self.output_dir / f"{packet_id}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Add manifest
            zipf.write(manifest_file, "manifest.json")
            
            # Add evidence files
            for finding_info in manifest["findings"]:
                evidence_id = finding_info["evidence_id"]
                evidence_file = self.output_dir / f"{evidence_id}.json"
                if evidence_file.exists():
                    zipf.write(evidence_file, f"evidence/{evidence_id}.json")
        
        # Cleanup temp directory
        import shutil
        shutil.rmtree(packet_dir, ignore_errors=True)
        
        return str(zip_path)
    
    def get_evidence_summary(self, evidence_id: str) -> dict[str, Any] | None:
        """
        Get summary of evidence package.
        
        Phase 14.2: Returns metadata about an evidence package.
        
        Args:
            evidence_id: Evidence package identifier.
        
        Returns:
            Dictionary with evidence summary or None if not found.
        """
        evidence_file = self.output_dir / f"{evidence_id}.json"
        if not evidence_file.exists():
            return None
        
        try:
            with evidence_file.open("r", encoding="utf-8") as f:
                evidence = json.load(f)
            
            return {
                "evidence_id": evidence_id,
                "timestamp": evidence.get("timestamp"),
                "finding_title": evidence.get("finding", {}).get("title"),
                "severity": evidence.get("finding", {}).get("severity"),
                "evidence_file": str(evidence_file),
            }
        except Exception:
            return None
