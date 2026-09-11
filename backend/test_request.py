import requests
import sys

def scan_website(url):
    try:
        response = requests.post(
            'http://127.0.0.1:5000/scan',
            json={"url": url},
            timeout=10  # timeout in seconds
        )
        response.raise_for_status()  # Raise error for bad HTTP status
        data = response.json()
        print(f"Scan result for {url}:")
        for detail in data.get('details', []):
            print(f"- [{detail.get('risk', 'Unknown')}] {detail['type']}: {detail['description']}")
            if 'recommendation' in detail:
                print(f"  Recommendation: {detail['recommendation']}")
        print(f"Total vulnerabilities found: {data.get('total_vulnerabilities_found', 0)}")
        print(f"High risk vulnerabilities: {data.get('high_risk_vulnerabilities', 0)}")
        print(f"Scan time: {data.get('scan_time', 'N/A')}")
        print(f"AI Analysis: {data.get('ai_analysis', 'N/A')}")
        print("="*50)

    except requests.exceptions.RequestException as e:
        print(f"Error scanning {url}: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        url_to_scan = sys.argv[1]
    else:
        url_to_scan = input("Enter the website URL to scan: ")
    scan_website(url_to_scan)
