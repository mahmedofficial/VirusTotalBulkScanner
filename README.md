# VirusTotal Bulk Scanner

A Python script to scan IP addresses using [VirusTotal API](https://www.virustotal.com/) with optional ASN filtering.  
This script reads IPs from a CSV file, removes duplicates, and outputs scan results to a file.  

---

## Features

- Scan all unique IP addresses from a CSV file.  
- Optional filtering based on ASN list.  
- Progress tracking with a visual progress bar.  
- Summary report after scanning: total scanned, malicious, and safe IPs.  
- Outputs results to `result.txt` with VirusTotal link for each IP.  

---

## Requirements

- Python 3.8+  
- Install required Python packages using the provided `requirements.txt` file:

```bash
pip install -r requirements.txt
````

---

## Setting up a Python Virtual Environment

It is recommended to use a virtual environment to keep project dependencies isolated.

### 1. Create a virtual environment

```bash
# For Windows
python -m venv venv

# For Linux / Mac
python3 -m venv venv
```

This will create a folder named `venv` containing the isolated environment.

---

### 2. Activate the virtual environment

```bash
# Windows
venv\Scripts\activate

# Linux / Mac
source venv/bin/activate
```

After activation, your terminal prompt should show `(venv)`.

---

### 3. Install required packages

Once the virtual environment is activated:

```bash
pip install -r requirements.txt
```

---

### 4. Deactivate the environment (after use)

```bash
deactivate
```

This returns your terminal to the global Python environment.

---

## CSV File Templates

### ips.csv

```csv
ip_address
8.8.8.8
1.1.1.1
104.16.132.229
185.199.108.153
```

### asn\_list.csv (optional, only if using ASN filtering)

```csv
asn
15169
13335
```

---

## Usage

1. Clone the repository:

```bash
git clone https://github.com/mahmedofficial/VirusTotalBulkScanner.git
cd VirusTotalBulkScanner
```

2. (Optional) Create and activate a virtual environment (see instructions above).

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the script:

```bash
python vt-bulk-scanner.py
```

5. Select scanning mode when prompted:

```
1. Scan ALL unique IPs (no ASN filtering)
2. Scan only IPs NOT in ASN list (filter by ASN)
```

6. Enter your VirusTotal API key.

7. After the scan, check `result.txt` for results:

```bash
type result.txt   # Windows
cat result.txt    # Linux/Mac
```

---

## Output

The `result.txt` file contains scanned IPs in the following format:

```
IP;MaliciousCount;AS_Owner;VirusTotal_Link
```

Example:

```
8.8.8.8;0;Google LLC;https://www.virustotal.com/gui/ip-address/8.8.8.8/detection
1.1.1.1;0;Cloudflare, Inc.;https://www.virustotal.com/gui/ip-address/1.1.1.1/detection
```

---

## Notes

* **Do not commit your VirusTotal API key** to GitHub.
* Large IP lists may hit API rate limits — the script adds a small delay between requests.
* `result.txt` is overwritten on each run.
