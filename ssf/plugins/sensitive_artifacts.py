from typing import Dict, Any, List
from ssf.core.base import BaseScanner

class SensitiveArtifactScanner(BaseScanner):
    """
    Plugin to scan for sensitive artifacts that may be exposed via Public URL
    such as .env, .git, or various backup files.
    """

    async def scan(self) -> Dict[str, Any]:
        self.log_info("[*] Starting Sensitive Artifacts Scan...")
        
        artifacts = [
            ".env",
            ".git/HEAD",
            ".gitlab-ci.yml",
            "docker-compose.yml",
            "backup.sql",
            "dump.sql",
            "private_key.pem",
            "id_rsa"
        ]

        found_artifacts = []
        risk_level = "SAFE"

        for file in artifacts:
            try:
                target_url = f"/{file}"
                response = await self.client.get(target_url)

                if response.status_code == 200:
                    if "<html" not in response.text.lower():
                        self.log_risk(f"    [!] FOUND SENSITIVE FILE: {target_url}", "CRITICAL")
                        found_artifacts.append(target_url)
                        risk_level = "CRITICAL"
                    else:
                        self.log_warn(f"    [?] Potential match for {target_url} (Check manually)")
            
            except Exception as e:
                self.log_error(f"Error checking {file}: {e}")

        return {
            "found_artifacts": found_artifacts,
            "risk": risk_level,
            "scanned_files": len(artifacts)
        }