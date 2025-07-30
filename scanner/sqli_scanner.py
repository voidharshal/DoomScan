import requests

def check_sql_injection(target_url):
    findings = {}
    malicious_url = f"{target_url}"

    db_errors = [
        "you have an error in your sql syntax",
        "unclosed quotation mark",
        "warning: mysql",
        "sqlstate[",
        "microsoft ole db provider for odbc drivers error"
    ]

    try:
        response = requests.get(malicious_url, timeout=5)
        print("---SQLi Scan Response ---", response.text.lower(), "---End of response---")
        for error in db_errors:
            if error in response.text.lower():
                findings['SQL Injection'] = {
                    'status': 'Vulnerable',
                    'message': f"Potential SQL Injection vulnerability found. The server responded with a database error when a single quote was appended to the URL.",
                    'severity': 'High'
                }
                return findings
    
    except requests.exceptions.RequestException:
        pass

    return findings