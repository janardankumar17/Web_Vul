import requests
from urllib.parse import urlsplit, urlunsplit

def check_sensitive_files(url):
    vulnerabilities = []
    try:
        parts = urlsplit(url)
        base_origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))

        # List of candidate sensitive files with validation signatures
        targets = [
            {
                "path": "/.env",
                "type": "Exposed Environment File (.env)",
                "risk": "High",
                "signature": lambda text, headers: any(k in text for k in ["DB_", "API_KEY", "SECRET", "APP_ENV", "PASSWORD", "PORT="]) and "text/html" not in headers.get("Content-Type", "").lower(),
                "recommendation": "Restrict web server access to dotfiles (e.g., '.env') or move environment files outside the web root."
            },
            {
                "path": "/.git/HEAD",
                "type": "Exposed Git Repository (.git/HEAD)",
                "risk": "High",
                "signature": lambda text, headers: ("ref: refs/" in text or (len(text.strip()) == 40 and text.strip().isalnum())) and "text/html" not in headers.get("Content-Type", "").lower(),
                "recommendation": "Block HTTP access to the '.git' directory in web server configuration to prevent source code theft."
            },
            {
                "path": "/robots.txt",
                "type": "Sensitive Paths in robots.txt",
                "risk": "Low",
                "signature": lambda text, headers: "Disallow:" in text and any(p in text.lower() for p in ["/admin", "/backup", "/api", "/secret", "/private", "/internal"]),
                "recommendation": "Ensure sensitive administrative directories listed in robots.txt are protected by strong authentication and authorization, not security-by-obscurity."
            }
        ]

        headers = {"User-Agent": "SecurityAuditor/1.0"}

        for t in targets:
            test_url = base_origin + t["path"]
            try:
                res = requests.get(test_url, headers=headers, timeout=4, allow_redirects=False)
                if res.status_code == 200 and t["signature"](res.text, res.headers):
                    vulnerabilities.append({
                        "type": t["type"],
                        "description": f"Sensitive file or path is publicly accessible at {test_url}",
                        "risk": t["risk"],
                        "url": test_url,
                        "recommendation": t["recommendation"]
                    })
            except Exception:
                continue
    except Exception:
        pass

    return vulnerabilities
