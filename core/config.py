import os
import os
from pydantic import BaseModel, Field
from typing import Optional
class TargetConfig(BaseModel):
    url: str
    key: str
    gemini_key: Optional[str] = Field(default=None)
    proxy: Optional[str] = Field(default=None)
    timeout: int = 10
    verbose: bool = False
    @property
    def has_ai(self) -> bool:
        return bool(self.gemini_key)

class Wordlists:
    tables = [
        "users", "profiles", "admin", "secrets", "logs", "transactions",
        "api_keys", "migrations", "user_secrets", "audit_trail", "payments",
        "orders", "settings", "config", "internal", "staff", "employees",
        "roles", "permissions", "invoices", "billing", "customers"
    ]
    functions = [
        "hello", "test", "auth", "user", "payment", "stripe", "webhook", 
        "email", "send-email", "notify", "openai", "ai", "search", "cron",
        "reset_password", "invite_user", "create_user", "delete_user"
    ]
    buckets = [
        "avatars", "files", "images", "public", "documents", "uploads", "assets",
        "private", "backup", "logs", "contracts", "signatures"
    ]