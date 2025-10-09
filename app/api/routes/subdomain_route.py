# app/api/routes/subdomain_route.py
from fastapi import APIRouter, HTTPException
from app.schemas.subdomain_schema import SubdomainRequest, SubdomainResponse
from app.services.subdomain_service import SubdomainService

router = APIRouter(prefix="/subdomain", tags=["Subdomain Enumeration"])

@router.post("/enumerate", response_model=SubdomainResponse)
async def enumerate_subdomains(request: SubdomainRequest):
    """
    Enumerate subdomains for a given domain with detailed DNS information.
    Requires only a domain name; returns paginated results with A, CNAME, MX records, HTTP status, and potential issues.
    """
    try:
        # Clean domain input (remove http:// or https:// if provided)
        domain = request.domain.replace("http://", "").replace("https://", "").split("/")[0]
        result = await SubdomainService.enumerate_subdomains(
            domain=domain,
            subdomains=None,  # Use default common subdomains
            page=1,  # Default page
            page_size=10  # Default page size
        )
        return SubdomainResponse(
            domain=domain,
            found_subdomains=result["found_subdomains"],
            total_subdomains=result["total_subdomains"],
            page=1,
            page_size=10,
            wildcard_detected=result["wildcard_detected"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error enumerating subdomains: {str(e)}")