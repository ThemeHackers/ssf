
from typing import Dict, Any, List
import httpx
from core.base import BaseScanner
class DatabaseConfigurationScanner(BaseScanner):
    async def scan(self) -> Dict[str, Any]:
        self.log("[*] Starting Deep Postgres/PostgREST Configuration Scan...", "cyan")
        result = {
            "exposed_system_tables": [],
            "inferred_privileges": [],
            "config_issues": [],
            "risk": "SAFE"
        }
        system_tables = [
            "pg_settings", "pg_roles", "pg_shadow", "pg_authid", 
            "pg_config", "pg_hba_file_rules", "pg_stat_activity"
        ]
        for table in system_tables:
            endpoint = f"/rest/v1/{table}"
            try:
                r = await self.client.get(endpoint, params={"limit": 1})
                if r.status_code in [200, 206]:
                    self.log(f"    [!] EXPOSED SYSTEM TABLE: {table}", "bold red on white")
                    result["exposed_system_tables"].append(table)
                    result["risk"] = "CRITICAL"
            except Exception as e:
                self.log_error(e)
        try:
            r = await self.client.get("/")
            if r.status_code == 200:
                data = r.json()
                if "swagger" in data or "openapi" in data:
                    info = data.get("info", {})
                    desc = info.get("description", "")
                    if "PostgREST" in desc:
                         result["config_issues"].append(f"PostgREST version exposed in root: {info.get('version', 'unknown')}")
        except: pass
        try:
            r = await self.client.get("/rest/v1/", params={"limit": 0}, headers={"Prefer": "count=exact"})
            if "Content-Range" in r.headers:
                pass
        except: pass

        if self.client.config.check_config:
            self.log("[*] Checking PostgREST max_rows configuration...", "cyan")
            # Try to find a valid table to query
            target_table = None
            if result["exposed_system_tables"]:
                target_table = result["exposed_system_tables"][0]
            elif self.context.get("rls_findings"):
                 # Use a table found during RLS scan that is readable
                 for finding in self.context.get("rls_findings"):
                     if finding.get("read"):
                         target_table = finding.get("table")
                         break
            
            if target_table:
                try:
                    # Request a large number of rows
                    limit = 10000
                    self.log(f"    [*] Testing max_rows on table '{target_table}' with limit={limit}...", "cyan")
                    r = await self.client.get(f"/rest/v1/{target_table}", params={"select": "*", "limit": limit})
                    if r.status_code == 200:
                        rows = r.json()
                        count = len(rows)
                        if count >= limit:
                            self.log(f"    [!] HIGH RISK: max_rows seems very high or unlimited! (Returned {count} rows)", "bold red")
                            result["config_issues"].append(f"Potential DoS: max_rows >= {limit}")
                        else:
                            self.log(f"    [+] max_rows check: SAFE. Returned {count} rows (Limit request: {limit})", "green")
                    else:
                        self.log(f"    [!] max_rows check failed: HTTP {r.status_code}", "yellow")
                except Exception as e:
                    self.log_error(e)
            else:
                self.log("    [!] Skipping max_rows check: No readable table found to test against.", "yellow")
        if result["exposed_system_tables"]:
            result["inferred_privileges"].append("Possible Superuser/High Privilege (System Tables Exposed)")
        return result