# app/schemas/subdomain.py
from pydantic import BaseModel
from typing import List, Optional, Union
from fastapi import Query

class SubdomainDetail(BaseModel):
    subdomain: str
    record_type: str  # e.g., A, CNAME, MX
    value: Union[str, List[str]]  # IP, CNAME, or redirect URL
    additional_info: Optional[str] = None  # e.g., MX priority, HTTP status, takeover risk

class SubdomainRequest(BaseModel):
    domain: str  # e.g., "example.com"

class SubdomainResponse(BaseModel):
    domain: str
    found_subdomains: List[SubdomainDetail]
    total_subdomains: int
    page: int
    page_size: int
    wildcard_detected: bool