import requests
import json

class ThreatIntel:
    """
    Checks IP addresses against the AbuseIPDB threat intelligence service.
    """
    def __init__(self, api_key):
        if not api_key:
            print("⚠️ WARNING: AbuseIPDB API key is missing. Threat intelligence feature will be disabled.")
        self.api_key = api_key
        self.base_url = 'https://api.abuseipdb.com/api/v2/check'

    def check_ip(self, ip_address):
        """
        Queries the AbuseIPDB API for a given IP address.
        Returns a dictionary with the abuse score and other details.
        """
        if not self.api_key:
            return None # API key illana, ethuvum panna vendam

        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90', # Pona 90 naal history-ah paaru
            'verbose': True
        }

        try:
            response = requests.get(self.base_url, headers=headers, params=params)
            response.raise_for_status()  # HTTP error vandha exception raise pannum
            
            data = response.json().get('data', {})
            
            # Theva padra details-ah mattum eduthukalam
            intel = {
                'score': data.get('abuseConfidenceScore', 0),
                'country': data.get('countryCode', 'N/A'),
                'isp': data.get('isp', 'Unknown ISP'),
                'total_reports': data.get('totalReports', 0)
            }
            print(f"✅ Threat Intel for {ip_address}: Score {intel['score']}, Country {intel['country']}")
            return intel

        except requests.exceptions.RequestException as e:
            print(f"❌ ERROR: Could not connect to AbuseIPDB. {e}")
            return None
        except json.JSONDecodeError:
            print(f"❌ ERROR: Failed to parse response from AbuseIPDB.")
            return None