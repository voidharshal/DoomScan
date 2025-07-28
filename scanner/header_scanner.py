import requests

def check_security_headers(target_url):
    findings = {}
    headers_to_check = {
        'Strict-Transport-Security': 'HSTS Header',
        'Content-Security-Policy': 'CSP Header',
        'X-Content-Type_Options': 'X-Content-Type-Options Header'
    }

    try:
        response = requests.get(target_url, timeout=5)
        response_headers = response.headers

        for header, name in headers_to_check.items():
            if header in response_headers:
                findings[name] = {
                    'status': 'Present',
                    'message': f"The '{header}' header is present.",
                    'severity': 'Good'
                }
            else:
                findings[name] = {
                    'status': 'Missing',
                    'message': f"The '{header}' is missing, this is risky.",
                    'severity': 'High'
                }
    except requests.exceptions.RequestException as e:
        findings['header_scan_error'] = {
            'status': 'Error',
            'message': f"Could not perform header scan. Error: {e}",
            'severity': 'Info'
        }
    return findings