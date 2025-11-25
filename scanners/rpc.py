from typing import List, Dict, Any
from core.base import BaseScanner
import json
from urllib.parse import urlencode
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
        if p_type == 'integer': return 0
        elif p_type == 'number': return 0.0
        elif p_type == 'boolean': return False
        elif p_type == 'array': return "{}" if p_in == 'query' else []
        elif p_type == 'string':
            if p_format == 'uuid': return "00000000-0000-0000-0000-000000000000"
            elif p_format in ['date', 'date-time']: return "2024-01-01T00:00:00+00:00"
            return "test"
        elif p_type == 'object': return {}
        return "test"
    async def scan(self, rpc: Dict) -> Dict[str, Any]:
        endpoint = f"/rest/v1/rpc/{rpc['name']}"
        result = {"name": rpc["name"], "method": rpc["method"].upper(), "executable": False}
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
                payload = params_data if params_data else {}
                r = await self.client.post(endpoint, json=payload)
            else:
                r = await self.client.get(endpoint, params=query_params)
            if r.status_code in (200, 206):
                result["executable"] = True
                result["status"] = r.status_code
                self.log(f"    [!] RPC Executable: {rpc['name']} (Status: {r.status_code})", "bold red")
            elif r.status_code == 400:
                self.log(f"    [?] RPC Bad Request (400): {rpc['name']} (Invalid Params?)", "yellow")
        except: pass
        return result