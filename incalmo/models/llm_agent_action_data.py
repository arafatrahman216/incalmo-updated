from pydantic import BaseModel
from typing import Dict, Any


class LLMAgentActionData(BaseModel):
    action: str
    params: Dict[str, Any]
