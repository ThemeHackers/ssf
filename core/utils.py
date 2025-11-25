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
            payload[col_name] = {"audit_test": True}
        elif "array" in col_type:
            payload[col_name] = []
        elif any(t in col_type for t in ["date", "time"]):
            payload[col_name] = "2025-01-01"
        elif "uuid" in col_type:
            payload[col_name] = "00000000-0000-0000-0000-000000000000"
        else:
            if "email" in col_name:
                payload[col_name] = "audit_test@example.com"
            else:
                payload[col_name] = "audit_test"
    return payload