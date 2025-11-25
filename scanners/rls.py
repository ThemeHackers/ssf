import httpx
from typing import Dict, Any
from core.base import BaseScanner
from core.utils import generate_smart_payload
class RLSScanner(BaseScanner):
    async def scan(self, table: str, table_info: Dict[str, Any]) -> Dict[str, Any]:
        columns = table_info.get("columns", {})
        pk_col = table_info.get("pk", "id")
        self.log(f"[*] Scanning table: {table}", "cyan")
        endpoint = f"/rest/v1/{table}"
        result = {"table": table, "read": False, "write": False, "risk": "SAFE"}
        try:
            r = await self.client.get(endpoint, params={"limit": 1}, headers={"Prefer": "count=exact"})
            if r.status_code in [200, 206]:
                result["read"] = True
                count = r.headers.get("content-range", "unknown").split("/")[-1]
                self.log(f"    [+] Read access confirmed for {table} (Rows: {count})", "green")
            operators = ["gt", "gte", "lt", "lte", "neq", "is"]
            test_col = pk_col
            for op in operators:
                val = "0"
                if op == "is": val = "null"
                elif op == "neq": val = "null"
                params = {test_col: f"{op}.{val}", "limit": 1}
                r_op = await self.client.get(endpoint, params=params, headers={"Prefer": "count=exact"})
                if r_op.status_code in [200, 206]:
                     op_count = r_op.headers.get("content-range", "unknown").split("/")[-1]
                     if op_count != "unknown" and op_count != "0":
                         self.log(f"    [!] Operator Injection '{op}' worked on {table}! (Rows: {op_count})", "bold red")
                         result["read"] = True 
                         result["risk"] = "CRITICAL" 
            discovered_users = self.context.get("users", [])
            if discovered_users:
                self.log(f"    [*] Testing Horizontal Escalation with {len(discovered_users)} leaked IDs...", "cyan")
                for uid in discovered_users[:3]: 
                    target_cols = ["user_id", "owner", "author_id", "id"]
                    for col in target_cols:
                        if col in columns:
                            try:
                                params = {col: f"eq.{uid}", "limit": 1}
                                r_hpe = await self.client.get(endpoint, params=params, headers={"Prefer": "count=exact"})
                                if r_hpe.status_code in [200, 206]:
                                    hpe_count = r_hpe.headers.get("content-range", "unknown").split("/")[-1]
                                    if hpe_count != "unknown" and hpe_count != "0":
                                        self.log(f"    [!] Horizontal Escalation SUCCESS on {table}! (Accessed data for {uid})", "bold red")
                                        result["read"] = True
                                        result["risk"] = "CRITICAL"
                                        break 
                            except: pass
        except: pass
        try:
            payload = generate_smart_payload(columns)
            r = await self.client.post(endpoint, json=payload, headers={"Prefer": "return=representation"})
            if r.status_code == 201:
                result["write"] = True
                self.log(f"    [!] Write access confirmed for {table}", "bold red")
                try:
                    resp_json = r.json()
                    if resp_json and isinstance(resp_json, list) and len(resp_json) > 0:
                        inserted_row = resp_json[0]
                        pk_value = inserted_row.get(pk_col)
                        if pk_value:
                            cleanup_val = f"eq.{pk_value}"
                            await self.client.delete(f"{endpoint}?{pk_col}={cleanup_val}")
                            self.log(f"        [+] Cleanup successful ({pk_col}={pk_value})", "green")
                        else:
                            self.log(f"        [!] Cleanup failed: Could not find PK '{pk_col}' in response", "yellow")
                except Exception as e:
                    self.log(f"        [!] Cleanup failed: {e}", "red")
        except: pass
        if result["write"]: result["risk"] = "CRITICAL"
        elif result["read"]:
            result["risk"] = "HIGH" if any(x in table for x in ["user", "secret", "admin", "key"]) else "MEDIUM"
        return result