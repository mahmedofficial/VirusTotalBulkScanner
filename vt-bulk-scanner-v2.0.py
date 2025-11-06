import csv
import requests
import os
import time
from ipwhois import IPWhois
from tqdm import tqdm

# API Key for VirusTotal
api = input("API Key: ").strip()

# File Paths
ips_file = 'ips.csv'
asn_file = 'asn_list.csv'
result_file = 'result.txt'

# Function to get ASN from IP using ipwhois
def get_asn(ip):
    try:
        ipwhois = IPWhois(ip)
        result = ipwhois.lookup_rdap()
        return result.get('asn', None)
    except Exception as e:
        print(f"Error getting ASN for IP {ip}: {e}")
        return None

# Load ASN list from file
def load_asn_list(filename):
    asn_list = set()
    try:
        with open(filename, mode='r') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                asn = row['asn']
                if asn:  # Ensure ASN is not empty
                    asn_list.add(asn)
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
    except Exception as e:
        print(f"Error loading ASN list: {e}")
    return asn_list

# Function to scan IP on VirusTotal
def scan_ip_on_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {'x-apikey': api}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            values = response.json()
            malicious = values['data']['attributes']['last_analysis_stats']['malicious']
            as_owner = values['data']['attributes'].get('as_owner', 'Unknown')
            vt_link = f"https://virustotal.com/gui/ip-address/{ip}/detection"

            # Prepare result
            result = f"{ip};{malicious};{as_owner};{vt_link}\n"
            return result
        else:
            print(f"Error scanning IP {ip}: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error during API request for IP {ip}: {e}")
        return None

# Deduplicate IPs from file
def load_unique_ips():
    try:
        with open(ips_file, mode='r') as file:
            csv_reader = csv.DictReader(file)
            raw_ips = [row.get('ip_address') for row in csv_reader if row.get('ip_address')]
        unique_ips = list(set(raw_ips))
        print(f"Found {len(raw_ips)} IPs, {len(unique_ips)} unique after removing duplicates.")
        return unique_ips
    except Exception as e:
        print(f"Error reading IPs from {ips_file}: {e}")
        return []

# Scan IPs (with or without ASN filtering)
def filter_and_scan_ips(check_asn=True):
    unique_ips = load_unique_ips()
    if not unique_ips:
        print("No IPs found to scan.")
        return

    # If ASN filtering is enabled, load ASN list
    asn_list = load_asn_list(asn_file) if check_asn else None
    unmatched_ips = []

    if check_asn:
        print("Filtering IPs using ASN list...")
        for ip in tqdm(unique_ips, desc="Processing IPs", unit="IP"):
            asn = get_asn(ip)
            if asn is None or asn not in asn_list:
                unmatched_ips.append(ip)
    else:
        unmatched_ips = unique_ips[:]  # Scan all IPs

    if not unmatched_ips:
        print("No IPs left to scan after filtering.")
        return

    print("Scanning IPs on VirusTotal...")

    # Delete existing result file if it exists
    if os.path.exists(result_file):
        os.remove(result_file)

    for ip in tqdm(unmatched_ips, desc="Scanning IPs", unit="IP"):
        result = scan_ip_on_virustotal(ip)
        if result:
            with open(result_file, 'a') as final_result:
                final_result.write(result)
        time.sleep(1)  # Avoid API rate limiting

    print("\n*** SCAN FINISHED SUCCESSFULLY ***")
    print(f"👉 All results have been saved to: {result_file}")

# Run the scanning process
if __name__ == "__main__":
    try:
        print("Select scanning mode:")
        print("1. Scan ALL unique IPs (no ASN filtering)")
        print("2. Scan only IPs NOT in ASN list (filter by ASN)")

        choice = input("Enter 1 or 2: ").strip()

        if choice == "1":
            filter_and_scan_ips(check_asn=False)
        elif choice == "2":
            filter_and_scan_ips(check_asn=True)
        else:
            print("Invalid choice. Exiting.")

    except KeyboardInterrupt:
        print("Error: Keyboard Interruption Occurred. Check result.txt for output")
