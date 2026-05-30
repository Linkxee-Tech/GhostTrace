from typing import Any, Callable
from pydantic import BaseModel

class ToolInfo(BaseModel):
    name: str
    description: str

class Tool:
    def __init__(self, name: str, description: str, func: Callable):
        self.info = ToolInfo(name=name, description=description)
        self.func = func
        
    def run(self, **kwargs) -> Any:
        return self.func(**kwargs)
