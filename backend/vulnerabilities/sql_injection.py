import requests

def check_sql_injection(url):
    vulnerabilities = []
    test_payload = "' OR '1'='1"
    try:
        if "?" not in url:
            return vulnerabilities

        test_url = url + test_payload
        res = requests.get(test_url, timeout=5)

        error_signatures = [
            "you have an error in your sql syntax",
            "sql syntax error",
            "mysql_fetch",
            "syntax error",
            "unclosed quotation mark",
            "quoted string not properly terminated"
        ]

        for sig in error_signatures:
            if sig in res.text.lower():
                vulnerabilities.append({
                    "type": "SQL Injection",
                    "description": "Possible SQL Injection vulnerability detected; database error signatures reflected in response.",
                    "risk": "High",
                    "url": test_url,
                    "affected_header_or_param": "Query Parameter",
                    "recommendation": "Use parameterized queries or prepared statements (e.g. PDO, ORM) to prevent untrusted user input from manipulating SQL execution."
                })
                break
    except Exception:
        pass
    return vulnerabilities
