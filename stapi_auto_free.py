import requests
import argparse
import datetime
import os
import json

# Replace with your actual SecurityTrails API key
API_KEY = "your_securitytrails_api_key"

# Base URL for SecurityTrails API
BASE_URL = "https://api.securitytrails.com/v1"

def fetch_api_data(endpoint, params=None):
    """Fetch data from SecurityTrails API."""
    url = f"{BASE_URL}/{endpoint}"
    headers = {
        "accept": "application/json",
        "APIKEY": API_KEY
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Error {response.status_code}: {response.json().get('message', 'Unknown error')}")

def run_securitytrails(target):
    """Run SecurityTrails API operations for the given target."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    sanitized_target = target.replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '_')
    output_file = f'{sanitized_target}_{timestamp}.json'

    results = {}

    # DOMAIN - Historical DNS records
    try:
        historical_dns = fetch_api_data(f"history/{sanitized_target}/dns/a")
        results['Historical DNS Records'] = historical_dns
    except Exception as e:
        results['Historical DNS Records Error'] = str(e)

    # DOMAIN - Get Subdomains
    try:
        subdomains = fetch_api_data(f"domain/{sanitized_target}/subdomains")
        results['Subdomains'] = subdomains
    except Exception as e:
        results['Subdomains Error'] = str(e)

    # Write results to JSON file
    with open(output_file, 'w') as outfile:
        json.dump(results, outfile, indent=4)

    print(f"Results saved to {output_file}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automate SecurityTrails API operations for a given target.')
    parser.add_argument('target', help='The target domain or IP address to query')
    args = parser.parse_args()

    target = args.target

    # Ensure target is a valid format
    if not target:
        print("Error: No target specified.")
        exit(1)

    run_securitytrails(target)
