import json
import re
from typing import Dict, List, Optional

class KnowledgeBase:
    def __init__(self):
        self.rules = []

    def load(self, path: str) -> bool:
        """Loads knowledge rules from a JSON file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.rules = data.get("accepted_risks", [])
            return True
        except Exception as e:
            print(f"[!] Error loading knowledge base: {e}")
            return False

    def is_accepted(self, finding: Dict, finding_type: str) -> Optional[str]:
        """
        Checks if a finding is an accepted risk.
        Returns the reason string if accepted, else None.
        """
        target_name = ""
        
        if finding_type == "rls":
            target_name = finding.get("table", "")
        elif finding_type == "storage":
            target_name = finding.get("name", "")
        elif finding_type == "rpc":
            target_name = finding.get("name", "")
        elif finding_type == "functions":
            target_name = finding.get("name", "")
        elif finding_type == "realtime":

            pass

        if not target_name:
            return None

        for rule in self.rules:
            if rule.get("type") != finding_type and rule.get("type") != "*":
                continue

            pattern = rule.get("pattern", "")
            try:
                if re.fullmatch(pattern, target_name):
                    return rule.get("reason", "Accepted Risk")
            except re.error:
                continue
                
        return None
