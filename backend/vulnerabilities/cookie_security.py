import requests

def check_cookies(url):
    vulnerabilities = []
    try:
        # Request with redirection followed
        res = requests.get(url, timeout=5, allow_redirects=True)
        
        # Check all cookies in the jar
        for cookie in res.cookies:
            cookie_name = cookie.name
            is_session = any(k in cookie_name.lower() for k in ["sess", "auth", "token", "jwt", "id", "login"])
            
            # Check HttpOnly
            has_httponly = cookie.has_nonstandard_attr("httponly") or cookie.has_nonstandard_attr("HttpOnly")
            if not has_httponly:
                vulnerabilities.append({
                    "type": "Insecure Cookie (Missing HttpOnly)",
                    "description": f"Cookie '{cookie_name}' is set without the HttpOnly flag, allowing client-side scripts to read it.",
                    "risk": "High" if is_session else "Medium",
                    "affected_header_or_param": cookie_name,
                    "recommendation": f"Add the 'HttpOnly' flag to cookie '{cookie_name}' to prevent theft via Cross-Site Scripting (XSS)."
                })

            # Check Secure flag
            if not cookie.secure:
                vulnerabilities.append({
                    "type": "Insecure Cookie (Missing Secure Flag)",
                    "description": f"Cookie '{cookie_name}' lacks the Secure attribute and may be transmitted over unencrypted HTTP.",
                    "risk": "High" if is_session else "Medium",
                    "affected_header_or_param": cookie_name,
                    "recommendation": f"Ensure cookie '{cookie_name}' includes the 'Secure' directive so it is only transmitted over HTTPS."
                })

            # Check SameSite
            samesite = cookie.get_nonstandard_attr("samesite")
            if not samesite or samesite.lower() not in ["strict", "lax"]:
                vulnerabilities.append({
                    "type": "Insecure Cookie (Missing SameSite Flag)",
                    "description": f"Cookie '{cookie_name}' is missing a strict SameSite attribute (SameSite=Lax or SameSite=Strict).",
                    "risk": "Low",
                    "affected_header_or_param": cookie_name,
                    "recommendation": f"Configure 'SameSite=Lax' or 'SameSite=Strict' on cookie '{cookie_name}' to protect against CSRF attacks."
                })
    except Exception:
        pass

    return vulnerabilities
