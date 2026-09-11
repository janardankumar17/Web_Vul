import requests

def check_headers(url):
    vulnerabilities = []
    try:
        res = requests.get(url, timeout=5)
        headers = res.headers

        security_headers = {
            "Content-Security-Policy": "Implement a strong Content-Security-Policy header to mitigate XSS and data injection.",
            "X-Content-Type-Options": "Add 'X-Content-Type-Options: nosniff' header to prevent MIME sniffing.",
            "Strict-Transport-Security": "Enable HTTPS and set Strict-Transport-Security header to enforce secure connections.",
            "X-Frame-Options": "Set 'X-Frame-Options' header to 'DENY' or 'SAMEORIGIN' to protect against clickjacking."
        }

        for header, recommendation in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    "type": "Missing Security Header",
                    "description": f"{header} header is missing",
                    "risk": "High" if header == "Strict-Transport-Security" else "Medium",
                    "affected_header_or_param": header,
                    "recommendation": recommendation
                })
    except Exception:
        pass
    return vulnerabilities
