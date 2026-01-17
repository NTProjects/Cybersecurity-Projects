"""CISA Crosswalk Engine.

Phase 14.1: Compliance & Audit Automation
- CISA Cross-Sector Cybersecurity Performance Goals
- NIST 800-53 mapping
- CIS Controls v8 mapping
"""
from __future__ import annotations

from typing import Any

# CISA Cross-Sector Cybersecurity Performance Goals (CPGs)
CISA_CPGS = {
    "CPG-1": "Account Management",
    "CPG-2": "Access Control",
    "CPG-3": "Data Protection",
    "CPG-4": "Secure Configuration",
    "CPG-5": "Account Monitoring",
    "CPG-6": "Security Awareness",
    "CPG-7": "Data Recovery",
    "CPG-8": "Incident Response",
    "CPG-9": "Network Segmentation",
    "CPG-10": "Supply Chain",
}

# CISA CPG to NIST 800-53 mapping
CISA_TO_NIST = {
    "CPG-1": ["AC-2", "AC-3", "IA-4"],
    "CPG-2": ["AC-3", "AC-4", "AC-5", "AC-6"],
    "CPG-3": ["SC-28", "SC-7", "SC-8"],
    "CPG-4": ["CM-2", "CM-6", "CM-7"],
    "CPG-5": ["AU-2", "AU-3", "AU-6", "AU-12"],
    "CPG-6": ["AT-2", "AT-3", "AT-4"],
    "CPG-7": ["CP-9", "CP-10"],
    "CPG-8": ["IR-4", "IR-5", "IR-6"],
    "CPG-9": ["SC-7", "AC-4"],
    "CPG-10": ["SA-12", "SA-19"],
}

# CISA CPG to CIS Controls v8 mapping
CISA_TO_CIS = {
    "CPG-1": ["CIS-5", "CIS-6"],
    "CPG-2": ["CIS-6", "CIS-7"],
    "CPG-3": ["CIS-3", "CIS-7"],
    "CPG-4": ["CIS-2", "CIS-3"],
    "CPG-5": ["CIS-8", "CIS-10"],
    "CPG-6": ["CIS-14"],
    "CPG-7": ["CIS-11"],
    "CPG-8": ["CIS-19"],
    "CPG-9": ["CIS-9"],
    "CPG-10": ["CIS-18"],
}

# NIST 800-53 to CIS Controls v8 mapping (sample)
NIST_TO_CIS: dict[str, list[str]] = {
    "AC-2": ["CIS-5", "CIS-6"],
    "AC-3": ["CIS-6", "CIS-7"],
    "AC-4": ["CIS-9"],
    "AU-2": ["CIS-8"],
    "CM-2": ["CIS-2"],
    "IR-4": ["CIS-19"],
    # Add more mappings as needed
}


class CISACrosswalkEngine:
    """
    CISA Crosswalk Engine for compliance mapping.
    
    Phase 14.1: Maps findings across CISA CPGs, NIST 800-53, and CIS Controls v8.
    """
    
    def __init__(self):
        """Initialize CISA crosswalk engine."""
        pass
    
    def map_to_cisa_cpg(self, finding: Any) -> list[str]:
        """
        Map a finding to CISA CPGs.
        
        Phase 14.1: Determines which CISA CPGs are relevant to a finding.
        
        Args:
            finding: Finding object with title, description, evidence, etc.
        
        Returns:
            List of CISA CPG identifiers (e.g., ["CPG-1", "CPG-2"]).
        """
        cpg_ids = []
        
        # Map based on finding characteristics
        title_lower = finding.title.lower() if hasattr(finding, "title") else ""
        description_lower = finding.description.lower() if hasattr(finding, "description") else ""
        
        # Account management
        if any(term in title_lower or term in description_lower for term in ["account", "user", "authentication"]):
            cpg_ids.append("CPG-1")
        
        # Access control
        if any(term in title_lower or term in description_lower for term in ["access", "permission", "authorization"]):
            cpg_ids.append("CPG-2")
        
        # Data protection
        if any(term in title_lower or term in description_lower for term in ["data", "encryption", "pii"]):
            cpg_ids.append("CPG-3")
        
        # Secure configuration
        if any(term in title_lower or term in description_lower for term in ["configuration", "hardening", "default"]):
            cpg_ids.append("CPG-4")
        
        # Account monitoring
        if any(term in title_lower or term in description_lower for term in ["monitoring", "logging", "audit"]):
            cpg_ids.append("CPG-5")
        
        # Security awareness
        if any(term in title_lower or term in description_lower for term in ["awareness", "training", "phishing"]):
            cpg_ids.append("CPG-6")
        
        # Data recovery
        if any(term in title_lower or term in description_lower for term in ["backup", "recovery", "restore"]):
            cpg_ids.append("CPG-7")
        
        # Incident response
        if any(term in title_lower or term in description_lower for term in ["incident", "response", "breach"]):
            cpg_ids.append("CPG-8")
        
        # Network segmentation
        if any(term in title_lower or term in description_lower for term in ["network", "firewall", "segmentation"]):
            cpg_ids.append("CPG-9")
        
        # Supply chain
        if any(term in title_lower or term in description_lower for term in ["supply", "chain", "vendor"]):
            cpg_ids.append("CPG-10")
        
        # Also check existing control_ids if present
        if hasattr(finding, "control_ids") and finding.control_ids:
            for control_id in finding.control_ids:
                # Map NIST to CISA
                if control_id.startswith("NIST-"):
                    nist_id = control_id.replace("NIST-", "")
                    for cpg, nist_list in CISA_TO_NIST.items():
                        if nist_id in nist_list and cpg not in cpg_ids:
                            cpg_ids.append(cpg)
                
                # Map CIS to CISA
                if control_id.startswith("CIS-"):
                    cis_id = control_id.replace("CIS-", "")
                    for cpg, cis_list in CISA_TO_CIS.items():
                        if cis_id in cis_list and cpg not in cpg_ids:
                            cpg_ids.append(cpg)
        
        return list(set(cpg_ids))  # Deduplicate
    
    def map_to_nist_800_53(self, cisa_cpg: str) -> list[str]:
        """
        Map CISA CPG to NIST 800-53 controls.
        
        Phase 14.1: Returns NIST 800-53 control IDs for a CISA CPG.
        
        Args:
            cisa_cpg: CISA CPG identifier (e.g., "CPG-1").
        
        Returns:
            List of NIST 800-53 control IDs.
        """
        return CISA_TO_NIST.get(cisa_cpg, [])
    
    def map_to_cis_controls(self, cisa_cpg: str) -> list[str]:
        """
        Map CISA CPG to CIS Controls v8.
        
        Phase 14.1: Returns CIS Controls v8 IDs for a CISA CPG.
        
        Args:
            cisa_cpg: CISA CPG identifier (e.g., "CPG-1").
        
        Returns:
            List of CIS Controls v8 IDs.
        """
        return CISA_TO_CIS.get(cisa_cpg, [])
    
    def crosswalk_finding(self, finding: Any) -> dict[str, Any]:
        """
        Perform full crosswalk for a finding.
        
        Phase 14.1: Maps finding to all compliance frameworks.
        
        Args:
            finding: Finding object.
        
        Returns:
            Dictionary with mappings to all frameworks.
        """
        cisa_cpgs = self.map_to_cisa_cpg(finding)
        
        nist_controls = []
        for cpg in cisa_cpgs:
            nist_controls.extend(self.map_to_nist_800_53(cpg))
        nist_controls = list(set(nist_controls))  # Deduplicate
        
        cis_controls = []
        for cpg in cisa_cpgs:
            cis_controls.extend(self.map_to_cis_controls(cpg))
        cis_controls = list(set(cis_controls))  # Deduplicate
        
        return {
            "cisa_cpgs": cisa_cpgs,
            "nist_800_53": nist_controls,
            "cis_controls_v8": cis_controls,
            "cisa_cpg_names": [CISA_CPGS.get(cpg, cpg) for cpg in cisa_cpgs],
        }
