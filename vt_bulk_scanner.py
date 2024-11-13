import requests
import csv
import time
import json
import os
import sys
from tqdm import tqdm
import re
from datetime import datetime

# Function to load API key from the config file
def load_api_key():
    if os.path.exists("config.json"):
        with open("config.json", "r") as file:
            config = json.load(file)
            return config.get("VT_API_KEY")
    else:
        return None

# Function to save API key to the config file
def save_api_key(api_key):
    config = {"VT_API_KEY": api_key}
    with open("config.json", "w") as file:
        json.dump(config, file)
    print("API Key saved successfully.")

# Function to get the API key, either from the user or from the saved config
def get_api_key():
    api_key = load_api_key()
    
    if api_key:
        print("API Key loaded from config.")
        
        # Loop until the user provides a valid input ('y' or 'n')
        while True:
            update_option = input("Would you like to update the API key? (y/n): ").lower()
            if update_option == 'y':
                api_key = input("Enter your new VirusTotal API Key: ")
                save_api_key(api_key)
                print("API Key updated.")
                break
            elif update_option == 'n':
                print("Keeping the existing API Key.")
                break
            else:
                print("Invalid input. Please enter 'y' to update or 'n' to keep the existing API key.")
                
    else:
        print("No API key found. Please enter your API key.")
        api_key = input("Enter your VirusTotal API Key: ")
        while True:
            save_option = input("Would you like to save this API key for future use? (y/n): ").lower()
            if save_option == 'y':
                save_api_key(api_key)
                break
            elif save_option == 'n':
                print("API Key not saved.")
                break
            else:
                print("Invalid input. Please enter 'y' to save or 'n' to unsave API key.")
    
    return api_key

# VirusTotal API details
VT_API_URL = "https://www.virustotal.com/api/v3"
MAX_RETRIES = 5
RETRY_DELAY = 60

# Query to virus total to get response and error handling
def vt_lookup(item, item_type, VT_API_KEY):
    url = f"{VT_API_URL}/{item_type}/{item}"
    headers = {"x-apikey": VT_API_KEY}

    for attempt in range(1, MAX_RETRIES + 1):
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "Not found"}
        elif response.status_code == 429:
            if attempt == MAX_RETRIES:
                return {"error": "Max retries reached due to rate limit. Exiting..."}
            print(f"Rate limit reached. Retrying in {RETRY_DELAY} seconds... (Attempt {attempt}/{MAX_RETRIES})")
            time.sleep(RETRY_DELAY)
        else:
            return {"error": f"Error {response.status_code}"}
    
    return {"error": "Request failed"}

# Function to determine the item type
def determine_item_type(item):
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    if re.match(ipv4_pattern, item) or re.match(ipv6_pattern, item):
        return "ip_addresses"
    elif len(item) in {32, 40, 64, 96, 128}:
        return "files"
    elif "." in item:
        return "domains"
    return "unknown"

# Function to process each item
def process_item(row, VT_API_KEY):
    item = row[0]
    item_type = determine_item_type(item)
    result = vt_lookup(item, item_type, VT_API_KEY)
    if "error" in result:
        return {"error": result["error"]}
    
    result_data = {
        "item": item,
        "type": item_type,
        "harmless": result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("harmless", 0),
        "malicious": result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
        "suspicious": result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0),
        "undetected": result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("undetected", 0),
        "country": result.get("data", {}).get("attributes", {}).get("country", ""),
        "as_owner": result.get("data", {}).get("attributes", {}).get("as_owner", ""),
        "vt_link": f"https://virustotal.com/gui/{item_type}/{item}/detection",
        "last_analysis_date": datetime.fromtimestamp(
            result.get("data", {}).get("attributes", {}).get("last_analysis_date", 0)
        ).strftime("%Y-%m-%d %H:%M:%S")
    }
    return result_data

# Bulk scan function
def bulk_scan(input_file, output_file, VT_API_KEY):
    print("Scan is running, please wait...")
    with open(input_file, "r") as infile, open(output_file, "w", newline="") as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        headers = ["Item", "Type", "Harmless", "Malicious", "Suspicious", "Undetected", "Country", "AS Owner", "VT LINK", "Last Analysis Date"]
        writer.writerow(headers)

        total_items = sum(1 for row in infile)
        infile.seek(0)
        next(reader, None)

        with tqdm(total=total_items, desc="Scanning items", unit="item") as pbar:
            for row in reader:
                if not row:
                    continue

                # Process the item and retrieve results
                result_data = process_item(row, VT_API_KEY)

                if "error" in result_data:
                    print(f"{result_data["error"]}\nResults saved to {output_file}.")
                    pbar.update(0)  # Update progress bar without changing it
                    pbar.close()  # Close the progress bar to stop further updates
                    sys.exit(1)

                writer.writerow([
                    result_data["item"], result_data["type"], result_data["harmless"],
                    result_data["malicious"], result_data["suspicious"], result_data["undetected"],
                    result_data["country"], result_data["as_owner"], result_data["vt_link"], result_data["last_analysis_date"]
                ])
                pbar.update(1)
    print(f"Scan completed. Results saved to {output_file}.")

# Main program entry point
if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            print("Usage: python3 vt_bulk_scanner.py [input_file_path] [output_file_path]")
            sys.exit(1)

        input_file = sys.argv[1]
        output_file = sys.argv[2]

        print("Loading API key...")
        VT_API_KEY = get_api_key()

        # Start bulk scanning
        bulk_scan(input_file, output_file, VT_API_KEY)

    except KeyboardInterrupt:
        print(f"\nProcess interrupted by the user. Exiting gracefully...\nResults saved to {output_file}.")
        sys.exit(1)