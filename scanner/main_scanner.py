import requests
from scanner.header_scanner import check_security_headers
from scanner.file_scanner import check_sensitive_files
from scanner.content_scanner import check_page_content

def run_scan(target_url):
    findings = {}

    try:
        response = requests.get(target_url, timeout=5)
        if response.status_code == 200:
            findings['connection_status'] = {
                'status': 'Success',
                'message': f"Successfully connected to {target_url} (Status Code: 200).",
                'severity': 'Info'
            }
            #Header scan
            header_findings = check_security_headers(target_url)
            findings.update(header_findings)

            #Files scan
            file_findings = check_sensitive_files(target_url)
            findings.update(file_findings)

            findings.update(check_page_content(target_url))

        else:
            findings['connection_status'] = {
                'status': 'Failed',
                'message': f"Connected but received an error status code: {requests.status_code}",
                'severity': 'High'
            }
    except requests.exceptions.RequestException as e:
        findings['connection_status'] = {
            'status': 'Failed',
            'message': f"Could not connect to {target_url}. Error: {e}",
            'severity': 'High'
        }


    return findings