from typing import Dict, Any
def generate_smart_payload(columns: Dict[str, str]) -> Dict[str, Any]:
    payload = {}
    for col_name, col_type in columns.items():
        col_type = col_type.lower()
        if col_name in ["created_at", "updated_at", "id"]:
            if "uuid" in col_type:
                payload[col_name] = "00000000-0000-0000-0000-000000000000"
            continue
        if any(t in col_type for t in ["int", "float", "number"]):
            payload[col_name] = 1
        elif "bool" in col_type:
            payload[col_name] = True
        elif "json" in col_type:
            payload[col_name] = {"audit_test": True, "nested": {"level": 1}, "tags": ["admin", "test"]}
        elif "array" in col_type:
            payload[col_name] = []
        elif any(t in col_type for t in ["date", "time"]):
            payload[col_name] = "2025-01-01"
        elif "uuid" in col_type:
            payload[col_name] = "00000000-0000-0000-0000-000000000000"
        elif "inet" in col_type or "cidr" in col_type:
            payload[col_name] = "127.0.0.1"
        elif "macaddr" in col_type:
            payload[col_name] = "00:00:00:00:00:00"
        else:
            if "email" in col_name:
                payload[col_name] = "audit_test@example.com"
            else:
                payload[col_name] = "audit_test"
    return payload

import os

def get_code_files(path: str) -> Dict[str, str]:
    """
    Recursively reads code files from a directory or a single file.
    Ignores common non-code directories.
    """
    code_files = {}
    
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                code_files[os.path.basename(path)] = f.read()
        except Exception: pass
        return code_files

    ignore_dirs = {".git", "node_modules", "__pycache__", ".venv", "dist", "build", ".next", ".nuxt"}
    extensions = {".sql", ".js", ".ts", ".jsx", ".tsx", ".py", ".json", ".toml"}
    
    for root, dirs, files in os.walk(path):

        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                full_path = os.path.join(root, file)
                try:
     
                    if os.path.getsize(full_path) < 100 * 1024: 
                        with open(full_path, "r", encoding="utf-8") as f:
   
                            rel_path = os.path.relpath(full_path, path)
                            code_files[rel_path] = f.read()
                except Exception: pass
                
    return code_files