# app/services/subdomain_service.py
import dns.resolver
import aiohttp
from typing import List, Dict, Optional
from fastapi import HTTPException

class SubdomainService:
    COMMON_SUBDOMAINS = [
        "www", "api", "mail", "ftp", "test", "dev", "staging", "blog", "shop", "admin",
        "vpn", "old", "images", "docs", "unclaimed"
    ]

    @staticmethod
    async def check_http_status(subdomain: str) -> Optional[str]:
        """Check HTTP status for a subdomain."""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"http://{subdomain}", timeout=5, allow_redirects=False) as response:
                    if response.status == 301 or response.status == 302:
                        return f"HTTP {response.status} -> {response.headers.get('Location', 'unknown')}"
                    return f"HTTP {response.status}"
            except Exception:
                return None

    @staticmethod
    async def check_subdomain_takeover(subdomain: str, cname: str) -> Optional[str]:
        """Basic check for dangling CNAME (potential subdomain takeover risk)."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            answers = resolver.resolve(cname, "A")
            if not answers or any(str(rdata) == "0.0.0.0" for rdata in answers):
                return "Possible dangling CNAME/subdomain takeover risk"
        except Exception:
            return None
        return None

    @staticmethod
    async def enumerate_subdomains(
        domain: str,
        subdomains: List[str] = None,
        page: int = 1,
        page_size: int = 10
    ) -> Dict:
        """
        Enumerate subdomains with detailed DNS information.
        Returns paginated results with DNS records and potential issues.
        """
        found_subdomains = []
        wildcard_detected = False
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        subdomains_to_check = subdomains if subdomains else SubdomainService.COMMON_SUBDOMAINS

        try:
            wildcard_domain = f"*.{domain}"
            resolver.resolve(wildcard_domain, "A")
            wildcard_detected = True
        except Exception:
            pass

        for subdomain in subdomains_to_check:
            full_domain = f"{subdomain}.{domain}"
            subdomain_detail = {"subdomain": full_domain, "record_type": "", "value": "", "additional_info": ""}

            try:
                answers = resolver.resolve(full_domain, "A")
                subdomain_detail["record_type"] = "A"
                subdomain_detail["value"] = [str(rdata) for rdata in answers]
                http_status = await SubdomainService.check_http_status(full_domain)
                if http_status:
                    subdomain_detail["additional_info"] = http_status
                found_subdomains.append(subdomain_detail)
                continue
            except Exception:
                pass

            try:
                answers = resolver.resolve(full_domain, "CNAME")
                subdomain_detail["record_type"] = "CNAME"
                subdomain_detail["value"] = str(answers[0].target)
                takeover_risk = await SubdomainService.check_subdomain_takeover(full_domain, subdomain_detail["value"])
                if takeover_risk:
                    subdomain_detail["additional_info"] = takeover_risk
                found_subdomains.append(subdomain_detail)
                continue
            except Exception:
                pass

            try:
                answers = resolver.resolve(full_domain, "MX")
                subdomain_detail["record_type"] = "MX"
                subdomain_detail["value"] = [str(rdata.exchange) for rdata in answers]
                subdomain_detail["additional_info"] = f"MX priority {answers[0].preference}"
                found_subdomains.append(subdomain_detail)
                continue
            except Exception:
                pass

        total_subdomains = len(found_subdomains)
        start = (page - 1) * page_size
        end = start + page_size
        paginated_subdomains = found_subdomains[start:end]

        return {
            "found_subdomains": paginated_subdomains,
            "total_subdomains": total_subdomains,
            "wildcard_detected": wildcard_detected
        }