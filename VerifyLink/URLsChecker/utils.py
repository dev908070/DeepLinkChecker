import requests
import re
from django.conf import settings


def check_content_integrity(post_content):
    # Regular expression to find URLs in post content
    urls = re.findall(r'https?://\S+', post_content)
    flagged_urls = []

    for url in urls:
        try:
            # Send a GET request to the URL
            response = requests.get(url, timeout=5)
            
            # If status is not OK or the response content looks suspicious, flag the URL
            if response.status_code != 200 or "malicious" in response.text.lower():
                flagged_urls.append(url)
            else:
                # Check if URL is safe using VirusTotal API
                if not check_url_with_virustotal(url):
                    flagged_urls.append(url)
                    
        except requests.RequestException as e:
            # If there is a request error, flag the URL
            # print(f"Error accessing {url}: {e}")
            flagged_urls.append(url)

    return flagged_urls

def check_url_with_virustotal(url):
    # Use VirusTotal's API to check URL safety
    vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {
        'apikey': settings.VIRUSTOTAL_API_KEY,
        'resource': url
    }
    try:
        response = requests.get(vt_url, params=params, timeout=5)
        response_data = response.json()
        
        # Analyze the response data
        if response_data['response_code'] == 1:
            # If a positive detection exists, consider the URL unsafe
            if response_data['positives'] > 0:
                return False
            return True
        else:
            # If VirusTotal has no data, treat it as suspicious
            return False

    except requests.RequestException as e:
        # print(f"Error checking URL with VirusTotal: {e}")
        return False

