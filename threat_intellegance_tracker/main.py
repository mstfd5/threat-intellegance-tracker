import requests
import os
import json
from dotenv import load_dotenv
import database

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
        print(f"Fetching threat intelligence for {ip_address}...")
        response = requests.get(url, headers=headers, params=parameters, timeout=10)
        response.raise_for_status() 
        
        report_data = response.json()
        
        # Print the data in a readable (Pretty Print) format in the terminal
        print("Data fetched successfully:\n")
        print(json.dumps(report_data, indent=4, ensure_ascii=False))
        ip = report_data['data']['ipAddress']
        score = report_data['data']['abuseConfidenceScore']
        country = report_data['data']['countryCode']
        isp = report_data['data']['isp'] 
        database.insert_threat_data(ip, score, country, isp)
        
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during the request: {e}")

if __name__ == "__main__":
    print(r"""
      _____ _                    _     _______             _             
     |_   _| |                  | |   |__   __|           | |            
       | | | |__  _ __ ___  __ _| |_     | |_ __ __ _  ___| | _____ _ __ 
       | | | '_ \| '__/ _ \/ _` | __|    | | '__/ _` |/ __| |/ / _ \ '__|
       | | | | | | | |  __/ (_| | |_     | | | | (_| | (__|   <  __/ |   
       \_/ |_| |_|_|  \___|\__,_|\__|    \_|_|  \__,_|\___|_|\_\___|_|   
    """)
    print("Welcome to Threat Intelligence Tracker v0.1")
    print("-" * 50)

    while True:
        print("\n[Menu]")
        print("1. Scan a new IP address")
        print("2. List recent scans from Local Database") 
        print("3. Exit") 
        
        choice = input("\nSelect an option (1, 2, or 3): ")
        
        if choice == '1':
            target_ip = input("Enter the IP address to scan (e.g., 8.8.8.8): ")
            get_threat_intel(target_ip)
            
        elif choice == '2':
            
            print("\n--- Recent Scans in Database ---")
            records = database.get_recent_threats(5) 
            
            if not records:
                print("No records found in the database yet.")
            else:
                for r in records:
                    print(f"IP: {r[0]:<15} | Risk Score: {r[1]:<3} | Country: {r[2]:<3} | Date: {r[3]}")
            print("-" * 32)
            
        elif choice == '3':
            print("Shutting down the tracker. Stay safe!")
            break
        else:
            print("Invalid input. Please enter 1, 2, or 3.")