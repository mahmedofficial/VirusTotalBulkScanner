import requests
import csv
import time
import json
import os
import sys
from tqdm import tqdm
import concurrent.futures
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

# Function to get the API key, either from the user or from the saved config
def get_api_key():
    api_key = load_api_key()
    if api_key:
        print("API Key loaded from config.")
    else:
        print("No API key found. Please enter your API key.")
        api_key = input("Enter your VirusTotal API Key: ")
        save_option = input("Would you like to save this API key for future use? (y/n): ")
        if save_option.lower() == 'y':
            save_api_key(api_key)
            print("API Key saved for future use.")
    return api_key

# Replace with your actual VirusTotal API URL
VT_API_URL = "https://www.virustotal.com/api/v3"

# Function to check an item (IP, domain, or hash) against VirusTotal
def vt_lookup(item, item_type, VT_API_KEY):
    url = f"{VT_API_URL}/{item_type}/{item}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "Not found"}
        else:
            return {"error": f"Error {response.status_code}"}
    except Exception as e:
        return {"error": f"Request failed: {str(e)}"}

# Function to determine the type of the item (file hash, domain, or IP)
def determine_item_type(item):
    # Regex pattern for an IPv4 address
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    
    # Regex pattern for an IPv6 address
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    
    # Check if the item matches IPv4 or IPv6 pattern
    if re.match(ipv4_pattern, item) or re.match(ipv6_pattern, item):
        return "ip_addresses"
    elif len(item) in {32, 40, 64, 96, 128}:  # Length for hash types (MD5, SHA1, SHA256, etc.)
        return "files"
    elif "." in item:
        return "domains"
    else:
        return "unknown"

# Function to handle scanning of each item (used for parallel processing)
def process_item(row, VT_API_KEY):
    item = row[0]
    item_type = determine_item_type(item)  # Use the new function to detect the item type
    
    result = vt_lookup(item, item_type, VT_API_KEY)
    
    # Initialize a result dictionary with default values
    result_data = {
        "item": item,
        "type": item_type,
        "harmless": 0,
        "malicious": 0,
        "suspicious": 0,
        "undetected": 0,
        "country": "",
        "as_owner": "",
        "vt_link": "",
        "last_analysis_date": ""
    }
    
    if result.get("error"):
        return result_data  # Return with only the error
    
    # Extract data type from 'data' dictionary
    data_type = result.get("data", {}).get("type", "")

    # Extract the 'attributes' dictionary from 'data'
    attributes = result.get("data", {}).get("attributes", {})

    # Extract last_analysis_date from 'attributes' dictionary
    last_analysis_timestamp = attributes.get("last_analysis_date", "")
    
    # Common fields for all types
    result_data["harmless"] = attributes.get("last_analysis_stats", {}).get("harmless", 0)
    result_data["malicious"] = attributes.get("last_analysis_stats", {}).get("malicious", 0)
    result_data["suspicious"] = attributes.get("last_analysis_stats", {}).get("suspicious", 0)
    result_data["undetected"] = attributes.get("last_analysis_stats", {}).get("undetected", 0)
    result_data["vt_link"] = f"https://virustotal.com/gui/{data_type}/{item}/detection"
    result_data["last_analysis_date"] = datetime.fromtimestamp(last_analysis_timestamp)

    
    # Specific fields based on the item type
    if item_type == "ip_addresses":
        result_data["as_owner"] = attributes.get("as_owner", "")
        result_data["country"] = attributes.get("country", "")
    
    return result_data
    

# Function to handle the bulk scanning process
def bulk_scan(input_file, output_file, VT_API_KEY):
    print("Scan is running, please wait...")

    with open(input_file, "r") as infile, open(output_file, "w", newline="") as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        headers = ["Item", "Type", "Harmless", "Malicious", "Suspicious", "Undetected", "Country", "AS Owner","VT LINK", "Last Analysis Date"]
        writer.writerow(headers)

        # Read all items into memory and filter out empty rows
        items = [row for row in reader if row]  # Only keep non-empty rows

        # Create a progress bar using tqdm with total items to process
        with tqdm(total=len(items), desc="Scanning items", unit="item") as pbar:
            # Use ThreadPoolExecutor to parallelize the scan
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(process_item, row, VT_API_KEY): row for row in items}
                
                # Iterate over completed tasks
                for future in concurrent.futures.as_completed(futures):
                    result_data = future.result()
                    item, item_type, result = result_data["item"], result_data["type"], result_data
                    
                    # Write the result to the CSV
                    writer.writerow([
                        result_data["item"],
                        result_data["type"], 
                        result_data["harmless"],
                        result_data["malicious"],
                        result_data["suspicious"],
                        result_data["undetected"],
                        result_data["country"],
                        result_data["as_owner"],
                        result_data["vt_link"],
                        result_data["last_analysis_date"],
                    ])

                    pbar.update(1)  # Update the progress bar as each item is processed

    print(f"Scan completed. Results saved to {output_file}.")

if __name__ == "__main__":
    # Check if both input and output file paths are provided
    if len(sys.argv) != 3:
        print("Usage: python3 vt_bulk_scanner.py [input_file_path] [output_file_path]")
        sys.exit(1)

    # Get file paths from command-line arguments
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Get API Key (either from the config or by prompting the user)
    VT_API_KEY = get_api_key()

    if not VT_API_KEY:
        print("Error: API Key is required to continue.")
        exit(1)

    # Run the bulk scan
    bulk_scan(input_file, output_file, VT_API_KEY)