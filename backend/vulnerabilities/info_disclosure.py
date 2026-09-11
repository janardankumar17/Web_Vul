import requests
import re

def check_info_disclosure(url):
    vulnerabilities = []
    try:
        res = requests.get(url, timeout=5, allow_redirects=True)
        headers = res.headers

        # 1. Server Header with version numbers
        server = headers.get("Server", "")
        if server:
            # Check if server reveals detailed version e.g. Apache/2.4.41, nginx/1.18.0
            has_version = bool(re.search(r"[\d]+\.[\d]+", server))
            if has_version:
                vulnerabilities.append({
                    "type": "Information Disclosure (Server Banner)",
                    "description": f"Server banner discloses exact software version: '{server}'.",
                    "risk": "Low",
                    "affected_header_or_param": "Server",
                    "recommendation": "Configure web server to suppress detailed version banners (e.g., 'ServerTokens Prod' in Apache, or 'server_tokens off;' in Nginx)."
                })

        # 2. X-Powered-By Header
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            vulnerabilities.append({
                "type": "Information Disclosure (X-Powered-By)",
                "description": f"Application reveals underlying technology stack via 'X-Powered-By: {powered_by}'.",
                "risk": "Low",
                "affected_header_or_param": "X-Powered-By",
                "recommendation": "Disable the X-Powered-By response header in your application framework (e.g., 'expose_php = Off' in php.ini, or 'app.disable(\"x-powered-by\")' in Express)."
            })

        # 3. ASP.NET Version headers
        asp_ver = headers.get("X-AspNet-Version", "")
        if asp_ver:
            vulnerabilities.append({
                "type": "Information Disclosure (ASP.NET Version)",
                "description": f"Application reveals .NET runtime version: '{asp_ver}'.",
                "risk": "Low",
                "affected_header_or_param": "X-AspNet-Version",
                "recommendation": "Remove 'X-AspNet-Version' in web.config by setting '<httpRuntime enableVersionHeader=\"false\" />'."
            })
    except Exception:
        pass

    return vulnerabilities
