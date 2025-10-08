from pydantic import BaseModel
from typing import List, Optional

class ScanIssue(BaseModel):
    key: str
    message: str
    severity: str

class ScanResult(BaseModel):
    bugs: int
    vulnerabilities: int
    code_smells: int
    coverage: Optional[float]
    issues: List[ScanIssue]