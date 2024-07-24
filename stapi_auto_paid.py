import requests
import argparse
import datetime
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

    # DOMAIN - Current DNS records
    try:
        dns_records = fetch_api_data(f"domain/{sanitized_target}/dns")
        results['Current DNS Records'] = dns_records
    except Exception as e:
        results['Error fetching DNS records'] = str(e)

    # DOMAIN - Historical DNS records
    try:
        historical_dns = fetch_api_data(f"history/{sanitized_target}/dns/a")
        results['Historical DNS Records'] = historical_dns
    except Exception as e:
        results['Error fetching historical DNS records'] = str(e)

    # DOMAIN - Get Subdomains
    try:
        subdomains = fetch_api_data(f"domain/{sanitized_target}/subdomains")
        results['Subdomains'] = subdomains
    except Exception as e:
        results['Error fetching subdomains'] = str(e)

    # DOMAIN WHOIS - Current WHOIS
    try:
        whois_current = fetch_api_data(f"domain/{sanitized_target}/whois")
        results['Current WHOIS'] = whois_current
    except Exception as e:
        results['Error fetching current WHOIS'] = str(e)

    # DOMAIN WHOIS - Historical WHOIS
    try:
        whois_historical = fetch_api_data(f"history/{sanitized_target}/whois")
        results['Historical WHOIS'] = whois_historical
    except Exception as e:
        results['Error fetching historical WHOIS'] = str(e)

    # DOMAIN WHOIS - Reverse WHOIS
    try:
        reverse_whois = fetch_api_data(f"domain/{sanitized_target}/whois")  # Adjust endpoint if needed
        results['Reverse WHOIS'] = reverse_whois
    except Exception as e:
        results['Error fetching reverse WHOIS'] = str(e)

    # DOMAIN WHOIS - WHOIS searching
    try:
        whois_searching = fetch_api_data(f"domain/{sanitized_target}/whois")  # Adjust endpoint if needed
        results['WHOIS Searching'] = whois_searching
    except Exception as e:
        results['Error fetching WHOIS searching'] = str(e)

    # IPS - IP address research
    try:
        ip_research = fetch_api_data(f"ips/{sanitized_target}/whois")
        results['IP Address Research'] = ip_research
    except Exception as e:
        results['Error fetching IP address research'] = str(e)

    # IPS - Reverse DNS searching
    try:
        reverse_dns = fetch_api_data(f"ips/{sanitized_target}/reverse")  # Adjust endpoint if needed
        results['Reverse DNS Searching'] = reverse_dns
    except Exception as e:
        results['Error fetching reverse DNS searching'] = str(e)

    # ADVANCED FEATURES - DSL
    try:
        dsl = fetch_api_data(f"domain/{sanitized_target}/dsl")  # Adjust endpoint if needed
        results['DSL - Domain Specific Language'] = dsl
    except Exception as e:
        results['Error fetching DSL data'] = str(e)

    # ADVANCED FEATURES - Associated domains
    try:
        associated_domains = fetch_api_data(f"domain/{sanitized_target}/associated")
        results['Associated Domains'] = associated_domains
    except Exception as e:
        results['Error fetching associated domains'] = str(e)

    # ADVANCED FEATURES - Consulting services
    try:
        consulting_services = fetch_api_data(f"domain/{sanitized_target}/consulting")  # Adjust endpoint if needed
        results['Consulting Services'] = consulting_services
    except Exception as e:
        results['Error fetching consulting services'] = str(e)

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
