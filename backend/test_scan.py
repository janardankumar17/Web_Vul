import requests

try:
    response = requests.post('http://127.0.0.1:5000/scan', json={'url': 'http://httpbin.org'}, timeout=30)
    print("Response status:", response.status_code)
    print("Response JSON:", response.json())
except Exception as e:
    print("Error:", e)
