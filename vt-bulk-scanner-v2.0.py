#!/usr/bin/env python3
"""
VT Bulk Scanner v2.0 - multi API key support + interactive output + malicious count

- Reads multiple API keys from 'api_keys.txt' (one key per line) if VT_API_KEY env var not set.
- Rotates keys automatically when a key hits rate limit (HTTP 429) or unauthorized (HTTP 401).
- Adds interactive choices to control whether to save all IPs or only malicious ones,
  and whether to include detailed location/network fields in the CSV output.
- Shows total number of malicious IPs detected after scan completion.
"""

import csv
import requests
import os
import sys
import time
from ipwhois import IPWhois
from tqdm import tqdm

# ================================
# CONFIGURATION
# ================================
ips_file = 'ips.csv'
asn_file = 'asn_list.csv'
result_file = 'result.csv'
api_keys_file = 'api_keys.txt'  # file containing multiple API keys, one per line

# Output choice flags (defaults; will be set interactively in main())
SAVE_ALL = False        # If True, save every scanned IP (malicious or not). If False, save only malicious > 0.
DETAILED_OUTPUT = False # If True, include extra VT fields (ASN, Network, Country, Region, City, Lat, Lon).

# ================================
# API Key Manager
# ================================
class APIKeyManager:
    """
    Manages one or more API keys and allows rotating to the next key on limit/unauthorized.
    """
    def __init__(self, keys):
        if not keys:
            raise ValueError("No API keys provided to APIKeyManager.")
        self.keys = keys[:]
        self.index = 0
        self.total = len(self.keys)

    def current_key(self):
        return self.keys[self.index]

    def mark_bad_current_key(self):
        if self.total <= 1:
            return False
        bad_key = self.keys.pop(self.index)
        self.keys.append(bad_key)
        self.total = len(self.keys)
        if self.index >= self.total:
            self.index = 0
        return True

# ================================
# KEY LOADING
# ================================
def load_api_keys_from_file(filename):
    keys = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    keys.append(line)
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"Error reading API keys from {filename}: {e}")
        return []
    return keys

def get_api_key():
    env_api = os.environ.get("VT_API_KEY")
    if env_api:
        return APIKeyManager([env_api.strip()])

    file_keys = load_api_keys_from_file(api_keys_file)
    if file_keys:
        print(f"Loaded {len(file_keys)} API key(s) from '{api_keys_file}'.")
        return APIKeyManager(file_keys)

    try:
        api = input("API Key (or create 'api_keys.txt' with one key per line): ").strip()
        if not api:
            print("No API key provided. Exiting.")
            sys.exit(0)
        return APIKeyManager([api])
    except KeyboardInterrupt:
        print("\n⚠️  Input interrupted. Exiting without running the scan.")
        sys.exit(0)

# ================================
# FUNCTION: Get ASN from IP
# ================================
def get_asn(ip):
    try:
        ipwhois = IPWhois(ip)
        result = ipwhois.lookup_rdap()
        return result.get('asn', None)
    except Exception:
        return None

# ================================
# FUNCTION: Load ASN List
# ================================
def load_asn_list(filename):
    asn_list = set()
    try:
        with open(filename, mode='r', newline='', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                asn = row.get('asn')
                if asn:
                    asn_list.add(asn.strip())
    except FileNotFoundError:
        print(f"Warning: ASN list file '{filename}' not found. Continuing without ASN filtering.")
    except Exception as e:
        print(f"Error loading ASN list: {e}")
    return asn_list

# ================================
# FUNCTION: Load Unique IPs
# ================================
def load_unique_ips():
    try:
        with open(ips_file, mode='r', newline='', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            raw_ips = [row.get('ip_address') for row in csv_reader if row.get('ip_address')]
        unique_ips = list(dict.fromkeys(raw_ips))
        print(f"Found {len(raw_ips)} IPs, {len(unique_ips)} unique after removing duplicates.")
        return unique_ips
    except FileNotFoundError:
        print(f"Error: IP list file '{ips_file}' not found. Create '{ips_file}' with header 'ip_address'.")
        return []
    except Exception as e:
        print(f"Error reading IPs from {ips_file}: {e}")
        return []

# ================================
# MAIN SCANNING FUNCTION
# ================================
def filter_and_scan_ips(api_manager, check_asn=True):
    global SAVE_ALL, DETAILED_OUTPUT

    unique_ips = load_unique_ips()
    if not unique_ips:
        print("No IPs found to scan.")
        return

    asn_list = load_asn_list(asn_file) if check_asn else None
    unmatched_ips = []

    if check_asn:
        print("Filtering IPs using ASN list...")
        for ip in tqdm(unique_ips, desc="Processing IPs", unit="IP"):
            asn = get_asn(ip)
            if asn is None or asn not in asn_list:
                unmatched_ips.append(ip)
    else:
        unmatched_ips = unique_ips[:]

    if not unmatched_ips:
        print("No IPs left to scan after filtering.")
        return

    print("Scanning IPs on VirusTotal...")

    if os.path.exists(result_file):
        os.remove(result_file)

    try:
        with open(result_file, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            if DETAILED_OUTPUT:
                writer.writerow([
                    "IP Address", "Malicious Count", "AS Owner", "ASN", "Network",
                    "Country", "VirusTotal Link"
                ])
            else:
                writer.writerow(["IP Address", "Malicious Count", "AS Owner", "VirusTotal Link"])
    except Exception as e:
        print(f"Error creating result file: {e}")
        return

    malicious_count = 0  # <-- Counter added

    try:
        for ip in tqdm(unmatched_ips, desc="Scanning IPs", unit="IP"):
            vt_link = f"https://virustotal.com/gui/ip-address/{ip}/detection"
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {'x-apikey': api_manager.current_key()}

            try:
                response = requests.get(url, headers=headers, timeout=30)
            except requests.exceptions.RequestException as e:
                print(f"\nNetwork error for IP {ip}: {e}")
                time.sleep(1)
                continue

            if response.status_code == 200:
                try:
                    data = response.json().get('data', {}).get('attributes', {})
                    last_stats = data.get('last_analysis_stats', {})
                    malicious = int(last_stats.get('malicious', 0))
                    as_owner = data.get('as_owner', 'Unknown')
                    asn_val = data.get('asn') or ''
                    network = data.get('network', '')
                    country = data.get('country', '')
                except Exception as e:
                    print(f"Error parsing VT response for {ip}: {e}")
                    continue

                should_save = SAVE_ALL or (malicious > 0)
                if malicious > 0:
                    malicious_count += 1

                if should_save:
                    try:
                        with open(result_file, mode='a', newline='', encoding='utf-8') as file:
                            writer = csv.writer(file)
                            if DETAILED_OUTPUT:
                                writer.writerow([
                                    ip, malicious, as_owner, asn_val, network,
                                    country, vt_link
                                ])
                            else:
                                writer.writerow([ip, malicious, as_owner, vt_link])
                    except Exception as e:
                        print(f"Error writing to result file: {e}")

                time.sleep(1)
            elif response.status_code in (401, 429):
                print(f"Rate/Key error {response.status_code} for {ip}. Rotating key...")
                api_manager.mark_bad_current_key()
                time.sleep(1)
            else:
                print(f"Warning: VT returned {response.status_code} for {ip}")
                time.sleep(1)

    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user. Partial results saved in result.csv.")
        return

    print("\n✅ SCAN FINISHED SUCCESSFULLY")
    if malicious_count > 0:
        print(f"👉 Found {malicious_count} malicious IP(s). Results saved to: {result_file}")
    else:
        print("✅ No malicious IPs found in this scan.")
        print(f"Results saved to: {result_file} (only clean IPs if 'Save All' was selected).")

# ================================
# ENTRY POINT
# ================================
def main():
    global SAVE_ALL, DETAILED_OUTPUT

    api_manager = get_api_key()

    try:
        print("\nSelect scanning mode:")
        print("1. Scan ALL unique IPs (no ASN filtering)")
        print("2. Scan only IPs NOT in ASN list (filter by ASN)")
        choice = input("Enter 1 or 2: ").strip()
    except KeyboardInterrupt:
        print("\n⚠️  Input interrupted. Exiting.")
        sys.exit(0)

    try:
        print("\nOutput options:")
        print("1. Save only malicious IPs (default)")
        print("2. Save ALL IPs (malicious + clean)")
        out_choice = input("Enter 1 or 2: ").strip()
        SAVE_ALL = out_choice == "2"

        det_choice = input("Include detailed location and network info in CSV? (y/n): ").strip().lower()
        DETAILED_OUTPUT = det_choice == "y"
    except KeyboardInterrupt:
        print("\n⚠️  Input interrupted. Exiting.")
        sys.exit(0)

    if choice == "1":
        filter_and_scan_ips(api_manager, check_asn=False)
    elif choice == "2":
        filter_and_scan_ips(api_manager, check_asn=True)
    else:
        print("Invalid choice. Exiting.")


if __name__ == "__main__":
    main()
