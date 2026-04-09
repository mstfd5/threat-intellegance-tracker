import requests
import os
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def get_threat_intel(ip_address):
    # Retrieve the API key securely
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    
    if not api_key:
        print("Error: API key not found. Please check your .env file.")
        return
        
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    parameters = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    try:
        print(f"[*] Fetching threat intelligence for {ip_address}...")
        response = requests.get(url, headers=headers, params=parameters, timeout=10)
        response.raise_for_status() 
        
        report_data = response.json()
        
        # Print the data in a readable (pretty print) format in the terminal
        print("Data fetched successfully:\n")
        print(json.dumps(report_data, indent=4, ensure_ascii=False))
        
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during the request: {e}")

if __name__ == "__main__":
    test_ip = '8.8.8.8' 
    get_threat_intel(test_ip)