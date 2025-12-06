import re
import os
from typing import List, Dict, Any
from ssf.core.base import BaseScanner
from rich.console import Console

console = Console()

class SASTScanner:
    def __init__(self, target_path: str, verbose: bool = False):
        self.target_path = target_path
        self.verbose = verbose
        self.findings = []
        
        self.patterns = {
            "hardcoded_secret": [
                (r"(?i)(supabase_key|service_role_key|anon_key)[\s]*[=:]\s*['\"](eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+)['\"]", "Hardcoded Supabase Key"),
                (r"(?i)(service_role)[\s]*[=:]\s*['\"](eyJ[a-zA-Z0-9-_]+)['\"]", "Possible Service Role Key"),
            ],
            "client_side_bypass": [
                (r"supabase\.auth\.admin", "Client-side Admin Auth Usage"),
                (r"supabase\.rpc\(['\"](.*?_admin|.*?_secret)['\"]", "Privileged RPC Call on Client"),
            ],
            "dangerous_function": [
                (r"dangerouslySetInnerHTML", "React Dangerous HTML (XSS Risk)"),
            ],
             "sensitive_info": [
                (r"-----BEGIN PRIVATE KEY-----", "Private Key Found"),
                (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Live Key"),
            ]
        }

    def scan(self) -> Dict[str, Any]:
        console.print(f"[cyan][*] Starting Offline SAST Scan on: {self.target_path}[/]")
        
        if os.path.isfile(self.target_path):
            self._scan_file(self.target_path)
        elif os.path.isdir(self.target_path):
            for root, _, files in os.walk(self.target_path):
                for file in files:
                    if file.endswith(('.js', '.ts', '.jsx', '.tsx', '.py', '.env', '.json')):
                        self._scan_file(os.path.join(root, file))
        
        risk_level = "Low"
        if any(f['severity'] == "Critical" for f in self.findings):
            risk_level = "Critical"
        elif any(f['severity'] == "High" for f in self.findings):
             risk_level = "High"
        elif any(f['severity'] == "Medium" for f in self.findings):
             risk_level = "Medium"

        return {
            "risk_level": risk_level,
            "summary": f"Offline SAST found {len(self.findings)} issues.",
            "findings": self.findings
        }

    def _scan_file(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()
                
                for line_idx, line in enumerate(lines):
                    for rule_type, pattern_list in self.patterns.items():
                        for pattern, name in pattern_list:
                            matches = re.finditer(pattern, line)
                            for match in matches:
                                finding = {
                                    "file": file_path,
                                    "line": line_idx + 1,
                                    "issue": name,
                                    "severity": self._get_severity(rule_type),
                                    "description": f"Matched pattern: {pattern}",
                                    "snippet": line.strip()[:100]  
                                }
                                
                                if "scanners:ignore" in line or "exclude:sast" in line:
                                    continue 
                                
                                self.findings.append(finding)
                                if self.verbose:
                                    console.print(f"[red][!] Found {name} in {file_path}:{line_idx+1}[/]")

        except Exception as e:
            if self.verbose:
                console.print(f"[yellow][!] Could not read {file_path}: {e}[/]")

    def _get_severity(self, rule_type: str) -> str:
        if rule_type == "hardcoded_secret":
            return "Critical"
        elif rule_type == "client_side_bypass":
            return "High"
        elif rule_type == "dangerous_function":
            return "Medium"
        elif rule_type == "sensitive_info":
             return "High"
        return "Low"
