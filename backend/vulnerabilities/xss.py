import requests

def check_xss(url):
    vulnerabilities = []
    test_payload = "<script>alert('XSS')</script>"
    try:
        if "?" not in url:
            return vulnerabilities

        test_url = url + test_payload
        res = requests.get(test_url, timeout=5)

        if test_payload in res.text:
            vulnerabilities.append({
                "type": "Cross Site Scripting (XSS)",
                "description": "Possible reflected XSS vulnerability detected; script payload was reflected unsanitized in response.",
                "risk": "High",
                "url": test_url,
                "affected_header_or_param": "Query Parameter",
                "recommendation": "Contextually HTML-encode user input before reflecting it in web pages, and implement a strict Content-Security-Policy (CSP)."
            })
    except Exception:
        pass
    return vulnerabilities
