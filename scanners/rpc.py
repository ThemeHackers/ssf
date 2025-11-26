from typing import List, Dict, Any
from core.base import BaseScanner
import json
import time
from core.utils import generate_smart_payload

class RPCScanner(BaseScanner):
    def extract_rpcs(self, spec: Dict) -> List[Dict]:
        rpcs = []
        if not spec or "paths" not in spec: return rpcs
        for path, path_methods in spec.get("paths", {}).items():
            if path.startswith('/rpc/'):
                rpc_name = path.replace("/rpc/", "")
                for method, method_details in path_methods.items():
                    method_lower = method.lower()
                    if method_lower in ['get', 'post']:
                        required_params = []
                        params_list = method_details.get('parameters', [])
                        if method_lower == 'post':
                            body_param = next((p for p in params_list if p.get('in') == 'body'), None)
                            if body_param and 'schema' in body_param:
                                schema = body_param['schema']
                                if '$ref' in schema:
                                    ref_path = schema['$ref'].split('/')
                                    target = spec
                                    if len(ref_path) > 1 and ref_path[0] == '#':
                                        try:
                                            for c in ref_path[1:]:
                                                target = target[c]
                                            schema = target
                                        except (KeyError, TypeError):
                                            schema = {}
                                if 'properties' in schema:
                                    required_names = schema.get('required', [])
                                    for name, details in schema['properties'].items():
                                        if name in required_names:
                                            details['name'] = name
                                            details['in'] = 'body'
                                            required_params.append(details)
                            else:
                                required_params.extend([p for p in params_list if p.get('in') == 'formData' and p.get('required', False)])
                        elif method_lower == 'get':
                            required_params.extend([p for p in params_list if p.get('in') == 'query' and p.get('required', False)])
                        for param in required_params:
                            if 'in' not in param:
                                param['in'] = 'body' if method_lower == 'post' else 'query'
                        rpcs.append({'name': rpc_name, 'method': method_lower, 'params_spec': required_params})
        unique_rpcs = []
        seen = set()
        for rpc in rpcs:
            key = (rpc['name'], rpc['method'])
            if key not in seen:
                unique_rpcs.append(rpc)
                seen.add(key)
        return unique_rpcs

    def _generate_placeholder(self, param_info: Dict[str, Any]) -> Any:
        p_type = param_info.get('type', 'string')
        p_format = param_info.get('format', '')
        p_in = param_info.get('in', 'query')
        if p_type == 'integer': return 1
        elif p_type == 'number': return 1.0
        elif p_type == 'boolean': return True
        elif p_type == 'array': return ["test"] if p_in == 'body' else "{test}"
        elif p_type == 'string':
            if p_format == 'uuid': return "00000000-0000-0000-0000-000000000000"
            elif p_format in ['date', 'date-time']: return "2024-01-01T00:00:00+00:00"
            elif p_format == 'json': return {"test": "value"}
            return "test_string"
        elif p_type == 'object': return {"test": "value"}
        
        return "test"

    async def scan(self, rpc: Dict) -> Dict[str, Any]:
        endpoint = f"/rest/v1/rpc/{rpc['name']}"
        result = {"name": rpc["name"], "method": rpc["method"].upper(), "executable": False, "leaked_data": False, "sample_rows": [], "sqli_suspected": False}
        self.log(f"[*] Testing RPC: {rpc['name']}", "cyan")
        

        params_data = {}
        query_params = {}
        for param in rpc.get('params_spec', []):
            val = self._generate_placeholder(param)
            if rpc['method'] == 'post':
                params_data[param['name']] = val
            else:
                query_params[param['name']] = str(val).lower() if isinstance(val, bool) else val
        
        try:
            if rpc["method"] == "post":
                r = await self.client.post(endpoint, json=params_data or {}, timeout=15.0)
            else:
                r = await self.client.get(endpoint, params=query_params, timeout=15.0)
            
            if r.status_code in (200, 206):
                result["executable"] = True
                try:
                    data = r.json()
                    if (isinstance(data, list) and data) or (isinstance(data, dict) and data):
                        result["leaked_data"] = True
                        result["sample_rows"] = data[:5] if isinstance(data, list) else [data]
                        self.log(f"[!] DATA LEAK via RPC '{rpc['name']}' → {len(data) if isinstance(data,list) else 1} rows", "bold red")
                        self.context.setdefault("leaked_via_rpc", []).append({"rpc": rpc['name'], "sample": result["sample_rows"]})
                        
                        sample_str = json.dumps(result["sample_rows"])
                        if "rolname" in sample_str or "pg_authid" in sample_str or "passwd" in sample_str:
                             self.log(f"    [!!!] CRITICAL: RPC '{rpc['name']}' exposes SYSTEM TABLES (Possible SECURITY DEFINER Escalation)", "bold red on white")
                             result["risk"] = "CRITICAL"
                except Exception as e:
                    self.log_error(e)
        except Exception as e:
            self.log_error(e)
        except Exception as e:
            self.log_error(e)
            
        if result["executable"]:
            await self._deep_scan_data_access(rpc, result)

            sqli_payloads = ["'", "\"", " OR 1=1", "; DROP TABLE users; --"]
            for param in rpc.get('params_spec', []):
                if param.get('type') == 'string':
                    for payload in sqli_payloads:
                        fuzzed_params = params_data.copy() if rpc['method'] == 'post' else query_params.copy()
                        if rpc['method'] == 'post':
                            fuzzed_params[param['name']] = payload
                        else:
                            fuzzed_params[param['name']] = payload
                        
                        try:
                            if rpc["method"] == "post":
                                r_sqli = await self.client.post(endpoint, json=fuzzed_params, timeout=5.0)
                            else:
                                r_sqli = await self.client.get(endpoint, params=fuzzed_params, timeout=5.0)
                            
                            if r_sqli.status_code == 500 or "syntax error" in r_sqli.text.lower() or "postgres" in r_sqli.text.lower():
                                self.log(f"    [!] Potential SQL Injection in {rpc['name']} (param: {param['name']}) - Verifying...", "yellow")
                                
             
                                try:
                                    sleep_payload = " OR pg_sleep(5)--"
                                    start_time = time.time()
                                    verify_params = fuzzed_params.copy()
                                    verify_params[param['name']] = sleep_payload
                                    
                                    if rpc["method"] == "post":
                                        await self.client.post(endpoint, json=verify_params, timeout=10.0)
                                    else:
                                        await self.client.get(endpoint, params=verify_params, timeout=10.0)
                                    
                                    duration = time.time() - start_time
                                    if duration > 4.5:
                                        self.log(f"    [!!!] CONFIRMED Time-Based SQL Injection in {rpc['name']} ({duration:.2f}s)", "bold red on white")
                                        result["sqli_suspected"] = True
                                        result["risk"] = "CRITICAL"
                                        break
                                except Exception as e:
                                    self.log_error(e)
                                
                                result["sqli_suspected"] = True
                                break
                        except Exception as e:
                            self.log_error(e)
                    if result["sqli_suspected"]: break

        return result

    async def _deep_scan_data_access(self, rpc: Dict, result: Dict):
        """
        Attempts to extract more data by fuzzing parameters with smart payloads.
        """
        self.log(f"    [*] Deep Scanning {rpc['name']} for data leakage...", "cyan")
        endpoint = f"/rest/v1/rpc/{rpc['name']}"

        param_dict = {p['name']: p.get('type', 'string') for p in rpc.get('params_spec', [])}
        smart_payload = generate_smart_payload(param_dict)
        
        for p in rpc.get('params_spec', []):
            if p.get('type') == 'string':
                smart_payload[p['name']] = "%" 
        
        try:
            if rpc["method"] == "post":
                r = await self.client.post(endpoint, json=smart_payload, timeout=10.0)
            else:
                r = await self.client.get(endpoint, params=smart_payload, timeout=10.0)
            
            if r.status_code in (200, 206):
                data = r.json()
                if data:
                    count = len(data) if isinstance(data, list) else 1
                    self.log(f"    [!] DEEP SCAN: Extracted {count} records using smart payload!", "bold red")
                    result["leaked_data"] = True
                    result["sample_rows"] = data[:5] if isinstance(data, list) else [data]
                    
    
                    sample_str = json.dumps(result["sample_rows"])
                    if any(k in sample_str for k in ["password", "secret", "token", "key", "hash", "admin"]):
                         self.log(f"    [!!!] SENSITIVE DATA found in RPC response!", "bold red on white")
                         result["risk"] = "CRITICAL"
        except Exception as e:
            self.log_error(e)