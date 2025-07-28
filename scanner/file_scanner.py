import requests
from urllib.parse import urljoin

def check_sensitive_files(target_url):
    findings = {}
    files_to_check = {
        'robots.txt': 'Info',
        'security.txt': 'Info',
        '.git/config': 'High', 
        '.env': 'High'      
    }

    for file_path, severity in files_to_check.items():
        url_to_test = urljoin(target_url, file_path)
        test_name = f"File Check: {file_path}"

        try:
            response = requests.get(url_to_test, timeout=3)
            if response.status_code == 200:
                findings[test_name] = {
                    'status': 'Found',
                    'message': f"The file '{file_path}' was found at {url_to_test}. This could expose sensitive information.",
                    'severity': severity
                }
            else:
                pass

        except requests.exceptions.RequestException:
            pass
    return findings