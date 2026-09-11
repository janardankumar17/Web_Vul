from datetime import datetime, timezone
import requests
from vulnerabilities.headers import check_headers
from vulnerabilities.sql_injection import check_sql_injection
from vulnerabilities.xss import check_xss
from vulnerabilities.cookie_security import check_cookies
from vulnerabilities.sensitive_files import check_sensitive_files
from vulnerabilities.info_disclosure import check_info_disclosure
from vulnerabilities.cors_misconfig import check_cors
from ai_integration import get_ai_analysis

def check_security_headers(url):
    """Legacy function for backward compatibility"""
    return check_headers(url)

def run_full_scan(url):
    # Run all vulnerability checks
    header_issues = check_headers(url)
    sql_issues = check_sql_injection(url)
    xss_issues = check_xss(url)
    cookie_issues = check_cookies(url)
    sensitive_file_issues = check_sensitive_files(url)
    info_issues = check_info_disclosure(url)
    cors_issues = check_cors(url)

    # Combine all issues
    all_issues = (
        header_issues
        + sql_issues
        + xss_issues
        + cookie_issues
        + sensitive_file_issues
        + info_issues
        + cors_issues
    )

    # Get AI analysis
    ai_summary = get_ai_analysis(all_issues)

    result = {
        "scan_url": url,
        "scan_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "details": all_issues,
        "total_vulnerabilities_found": len(all_issues),
        "high_risk_vulnerabilities": len([i for i in all_issues if i.get("risk") == "High"]),
        "ai_analysis": ai_summary
    }
    return result
