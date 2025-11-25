import os
import os
from pydantic import BaseModel, Field
from typing import Optional
class TargetConfig(BaseModel):
    url: str
    key: str
    gemini_key: Optional[str] = Field(default=None)
    timeout: int = 10
    verbose: bool = False
    @property
    def has_ai(self) -> bool:
        return bool(self.gemini_key)