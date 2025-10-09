from pydantic import BaseModel
from typing import List, Optional

class ScanIssue(BaseModel):
    key: str
    message: str
    severity: str
    file: Optional[str]
    line: Optional[int]
    start_line: Optional[int]
    end_line: Optional[int]
    code_snippet: Optional[str]  # Changed to Optional

class ScanResult(BaseModel):
    bugs: int
    vulnerabilities: int
    code_smells: int
    coverage: Optional[float]
    issues: List[ScanIssue]