import requests

def check_cors(url):
    vulnerabilities = []
    test_origin = "https://attacker.example.com"
    try:
        headers = {
            "Origin": test_origin,
            "User-Agent": "SecurityAuditor/1.0"
        }
        res = requests.get(url, headers=headers, timeout=5)
        allow_origin = res.headers.get("Access-Control-Allow-Origin", "").strip()
        allow_cred = res.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

        # 1. Arbitrary Origin Reflection with Credentials
        if allow_origin == test_origin and allow_cred == "true":
            vulnerabilities.append({
                "type": "CORS Misconfiguration (Arbitrary Origin with Credentials)",
                "description": "Server dynamically reflects arbitrary untrusted Origin header with Access-Control-Allow-Credentials enabled.",
                "risk": "High",
                "affected_header_or_param": "Access-Control-Allow-Origin",
                "recommendation": "Do not dynamically reflect arbitrary Origin headers when credentials are allowed. Validate against a strict origin whitelist."
            })
        # 2. Insecure Wildcard Origin
        elif allow_origin == "*":
            vulnerabilities.append({
                "type": "CORS Misconfiguration (Wildcard Origin)",
                "description": "Server allows all domains via 'Access-Control-Allow-Origin: *'.",
                "risk": "Low",
                "affected_header_or_param": "Access-Control-Allow-Origin",
                "recommendation": "If this endpoint serves sensitive or authenticated data, replace the wildcard '*' with an explicit whitelist of trusted origins."
            })
        # 3. Insecure 'null' Origin
        elif allow_origin == "null":
            vulnerabilities.append({
                "type": "CORS Misconfiguration (Trusted Null Origin)",
                "description": "Server accepts 'Origin: null', which can be triggered by sandboxed iframes or file: URLs.",
                "risk": "Medium",
                "affected_header_or_param": "Access-Control-Allow-Origin",
                "recommendation": "Avoid configuring 'Access-Control-Allow-Origin: null'. Specify explicit trusted domains."
            })
    except Exception:
        pass

    return vulnerabilities
