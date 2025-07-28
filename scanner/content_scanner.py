import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def check_page_content(target_url):
    findings = {}
    try:
        response = requests.get(target_url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')

        if target_url.startswith('https://'):
            for tag in soup.find_all(['img', 'script', 'link'], src=True) + soup.find_all('a', href=True):
                url = tag.get('src') or tag.get('href')
                if url and url.startswith('https://'):
                    findings['Mixed Content'] = {
                        'status': 'Found',
                        'message': f"Insecure resource found on HTTPS page: {url}",
                        'severity': 'High'
                    }
                    break
        
        for form in soup.find_all('form'):
            action = form.get('action')
            if action and action.startswith('https://'):
                findings['Insecure Form'] = {
                    'status':'Found',
                    'message': f"Form submits data over insecure HTTP to: {action}",
                }
                break

    except requests.exceptions.RequestException as e:
        findings['content_scan_error'] = {
            'status': 'Error',
            'message': f"Could not fetch page content for scanning. Error: {e}",
            'severity': 'Info'
        }
    return findings