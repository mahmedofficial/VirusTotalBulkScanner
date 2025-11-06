# VT Bulk Scanner

A Python-based **bulk VirusTotal IP scanner** with support for **multiple API keys**, **ASN filtering**, and **optional detailed location output**.  
Perfect for cybersecurity analysts, SOC teams, or researchers who need to quickly analyze large IP lists against VirusTotal.

---

## Features

**Bulk Scanning**  
- Scan hundreds of IPs from a CSV list.  
- Automatically removes duplicate entries.  

**Multi-API Key Support**  
- Load multiple VirusTotal API keys from `api_keys.txt`.  
- Automatically rotates keys on rate-limit (429) or unauthorized (401) errors.  

**Filtering**  
- Option to scan **all IPs** or only IPs **not in a known ASN list**.  

**Output Control**  
- Save only malicious IPs or **all IPs** (malicious + clean).  
- Optionally include detailed location and network fields: ASN, AS Owner, Country, Region, City, Latitude, Longitude.  

**Progress Feedback**  
- Interactive prompts and progress bars.  
- Displays total malicious IPs detected at the end.

---

## Input Files

| File | Description | Required |
|------|-------------|----------|
| `ips.csv` | List of IP addresses to scan. Must contain a header `ip_address`. | ✅ |
| `asn_list.csv` | List of trusted ASN numbers for filtering (optional). | ⚙️ Optional |
| `api_keys.txt` | One VirusTotal API key per line. Used if `VT_API_KEY` env var not set. | ⚙️ Optional |

**Example: `ips.csv`**
```csv
ip_address
8.8.8.8
1.1.1.1
192.168.10.20
````

**Example: `asn_list.csv`**

```csv
asn
AS15169
AS13335
```

**Example: `api_keys.txt`**

```
abc123yourfirstapikey
xyz789yoursecondapikey
```

---

## Output

| File         | Description                                                                 |
| ------------ | --------------------------------------------------------------------------- |
| `result.csv` | Generated automatically. Contains all results based on your chosen options. |

**Example (short output mode)**

```csv
IP Address,Malicious Count,AS Owner,VirusTotal Link
8.8.8.8,0,Google LLC,https://virustotal.com/gui/ip-address/8.8.8.8/detection
45.13.104.90,5,Host Europe GmbH,https://virustotal.com/gui/ip-address/45.13.104.90/detection
```

**Example (detailed output mode)**

```csv
IP Address,Malicious Count,AS Owner,ASN,Network,Country,Region,City,Latitude,Longitude,VirusTotal Link
45.13.104.90,5,Host Europe GmbH,AS12345,45.13.104.0/22,DE,NRW,Cologne,50.9375,6.9603,https://virustotal.com/gui/ip-address/45.13.104.90/detection
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/vt-bulk-scanner.git
cd vt-bulk-scanner
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

**Dependencies**

```
requests
tqdm
ipwhois
```

---

## Usage

### 1. Run the scanner

```bash
python vt-bulk-scanner-v2.0.py
```

### 2. Follow the interactive prompts

* Choose scanning mode (all IPs or ASN filtered).
* Choose output type (malicious only or all).
* Optionally include detailed network/location info.

## License

This project is licensed under the **MIT License**.
You are free to use, modify, and distribute it with attribution.
---

**⭐ If this tool helps you, please star the repo!**
