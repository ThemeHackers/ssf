import httpx
from typing import Dict, Any
import time
from core.base import BaseScanner
from core.utils import generate_smart_payload
class RLSScanner(BaseScanner):
    def __init__(self, client: httpx.AsyncClient, verbose: bool = False, context: Dict[str, Any] = None, tokens: Dict[str, str] = None):
        super().__init__(client, verbose, context)
        self.tokens = tokens or {}
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
            operators = ["gt", "gte", "lt", "lte", "neq", "is", "ilike", "not.like", "cs", "cd"]
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
                    target_cols = [c for c in columns.keys() if any(x in c.lower() for x in ["user", "owner", "auth", "id"])]
                    if not target_cols:
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
                            except Exception as e:
                                self.log_error(e)
            await self._check_blind_rls(table, pk_col, result)
            if self.tokens:
                await self._check_vertical_escalation(table, endpoint, result)
        except Exception as e:
            self.log_error(e)
        try:
            payload = generate_smart_payload(columns)            
            patch_endpoint = f"{endpoint}?{pk_col}=eq.0" 
            r = await self.client.patch(patch_endpoint, json=payload, headers={"Prefer": "return=representation"})
            if r.status_code in [200, 204, 404]:
                 if r.status_code != 404:
                     result["write"] = True
                     self.log(f"    [!] UPDATE (PATCH) access confirmed for {table}", "bold red")
        except Exception as e:
            self.log_error(e)
        try:
             delete_endpoint = f"{endpoint}?{pk_col}=eq.0"
             r = await self.client.delete(delete_endpoint, headers={"Prefer": "return=representation"})
             if r.status_code in [200, 204, 404]:
                 if r.status_code != 404:
                     result["write"] = True
                     self.log(f"    [!] DELETE access confirmed for {table}", "bold red")
        except Exception as e:
            self.log_error(e)
        try:
            payload = generate_smart_payload(columns)
            r = await self.client.post(endpoint, json=payload, headers={"Prefer": "return=representation"})
            if r.status_code == 201:
                result["write"] = True
                self.log(f"    [!] INSERT (POST) access confirmed for {table}", "bold red")
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
        except Exception as e:
            self.log_error(e)
        if result["write"]: result["risk"] = "CRITICAL"
        elif result["read"]:
            result["risk"] = "HIGH" if any(x in table for x in ["user", "secret", "admin", "key"]) else "MEDIUM"
        return result
    async def _check_blind_rls(self, table: str, pk_col: str, result: Dict[str, Any]):
        self.log(f"    [*] Testing Blind RLS on {table}...", "cyan")
        endpoint = f"/rest/v1/{table}"
        try:
            params = {pk_col: "eq.1", "select": f"{pk_col}::text"} 
            pass
        except: pass
        try:
            start_time = time.time()
            params = {pk_col: "eq.0"} 
            await self.client.get(endpoint, params=params)
            baseline = time.time() - start_time
            start_time = time.time()
            params = {pk_col: "eq.1"}
            await self.client.get(endpoint, params=params)
            target_time = time.time() - start_time
            if target_time > (baseline * 5) and target_time > 0.5:
                 self.log(f"    [?] Possible Blind RLS (Timing) on {table} (Baseline: {baseline:.2f}s, Target: {target_time:.2f}s)", "yellow")
                 if result["risk"] == "SAFE":
                     result["risk"] = "LOW"
        except: pass
    async def _check_vertical_escalation(self, table: str, endpoint: str, result: Dict[str, Any]):
        self.log(f"    [*] Testing Vertical Escalation on {table} with {len(self.tokens)} roles...", "cyan")
        for role, token in self.tokens.items():
            headers = {"Authorization": f"Bearer {token}", "Prefer": "count=exact"}
            try:
                r = await self.client.get(endpoint, params={"limit": 1}, headers=headers)
                can_read = r.status_code in [200, 206]
                if can_read:
                    count = r.headers.get("content-range", "unknown").split("/")[-1]
                    self.log(f"        [+] Role '{role}' can READ {table} (Rows: {count})", "green")
                    if not result["read"]:
                        self.log(f"        [!] Vertical Escalation: Role '{role}' has READ access (Anon does not)", "yellow")
                        result.setdefault("escalation", []).append(f"{role}:READ")
            except Exception as e:
                self.log_error(e)