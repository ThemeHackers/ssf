from typing import Dict, Any, List
from ssf.core.base import BaseScanner

class SecurityHeadersScanner(BaseScanner):
    """
    Plugin to check for missing or insecure HTTP security headers.
    """
    async def scan(self) -> Dict[str, Any]:
        self.log_info("[*] Running Security Headers Plugin...")
        
        target_url = self.context.get('target_url') or self.client.base_url
        findings = {
            "missing_headers": [],
            "weak_headers": [],
            "score": 100
        }

        try:

            response = await self.client.head(str(target_url))
            headers = response.headers

            security_headers = {
                "Strict-Transport-Security": "HSTS not enabled.",
                "Content-Security-Policy": "CSP not configured.",
                "X-Frame-Options": "Clickjacking protection missing.",
                "X-Content-Type-Options": "MIME sniffing protection missing.",
                "Referrer-Policy": "Referrer policy not set.",
                "Permissions-Policy": "Permissions policy not set."
            }

            for header, risk_msg in security_headers.items():
                if header not in headers:
                    findings["missing_headers"].append({
                        "header": header,
                        "risk": "MEDIUM",
                        "description": risk_msg
                    })
                    findings["score"] -= 10
                else:
 
                    value = headers[header]
                    if header == "X-Frame-Options" and value.lower() not in ["deny", "sameorigin"]:
                         findings["weak_headers"].append({
                            "header": header,
                            "value": value,
                            "risk": "LOW",
                            "description": "Weak X-Frame-Options configuration."
                        })
                    elif header == "Strict-Transport-Security" and "max-age" not in value:
                         findings["weak_headers"].append({
                            "header": header,
                            "value": value,
                            "risk": "LOW",
                            "description": "HSTS max-age not found."
                        })

            self.log_info(f"Security Headers Scan Complete. Score: {findings['score']}/100")
            return findings

        except Exception as e:
            self.log_error(f"Security Headers Plugin Failed: {e}")
            return {"error": str(e)}
