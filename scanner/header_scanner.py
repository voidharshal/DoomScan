import requests

def check_security_headers(target_url):
    """
    Checks for security headers, cookie flags, and server information.
    """
    findings = {}
    try:
        response = requests.get(target_url, timeout=5)
        headers = response.headers

        # --- 1. Standard Security Headers ---
        headers_to_check = {
            'Strict-Transport-Security': 'HSTS Header',
            'Content-Security-Policy': 'CSP Header',
            'X-Content-Type-Options': 'X-Content-Type-Options Header',
            'X-Frame-Options': 'Clickjacking Protection' # New clickjacking check
        }
        for header, name in headers_to_check.items():
            if header in headers:
                findings[name] = {'status': 'Present', 'message': f"The '{header}' header is present.", 'severity': 'Good'}
            else:
                findings[name] = {'status': 'Missing', 'message': f"The '{header}' header is missing.", 'severity': 'High'}

        # --- 2. Cookie Security Flags ---
        if 'Set-Cookie' in headers:
            cookie = headers['Set-Cookie']
            if 'httponly' not in cookie.lower():
                findings['Cookie Security: HttpOnly'] = {'status': 'Missing', 'message': 'The HttpOnly flag is missing from the Set-Cookie header.', 'severity': 'High'}
            else:
                findings['Cookie Security: HttpOnly'] = {'status': 'Present', 'message': 'The HttpOnly flag is set on the cookie.', 'severity': 'Good'}
            
            if 'secure' not in cookie.lower():
                findings['Cookie Security: Secure'] = {'status': 'Missing', 'message': 'The Secure flag is missing from the Set-Cookie header.', 'severity': 'High'}
            else:
                findings['Cookie Security: Secure'] = {'status': 'Present', 'message': 'The Secure flag is set on the cookie.', 'severity': 'Good'}

        # --- 3. Technology Fingerprinting ---
        if 'Server' in headers:
            findings['Technology: Server'] = {'status': 'Exposed', 'message': f"Server technology identified: {headers['Server']}", 'severity': 'Info'}
        if 'X-Powered-By' in headers:
            findings['Technology: X-Powered-By'] = {'status': 'Exposed', 'message': f"Backend technology identified: {headers['X-Powered-By']}", 'severity': 'Info'}

    except requests.exceptions.RequestException as e:
        findings['header_scan_error'] = {'status': 'Error', 'message': f"Could not perform header scan. Error: {e}", 'severity': 'Info'}
        
    return findings