# VirusTotal Bulk Scanner

A Python script to scan a list of IP addresses, domains, or file hashes against the VirusTotal API in bulk. The results are saved in a CSV file with key information such as the detection status, country, and other details.

---

## Features

- Bulk scan of IP addresses, domains, and file hashes (MD5, SHA1, SHA256).
- Retrieves key information about each item:
  - Harmless, Malicious, Suspicious, and Undetected counts.
  - Last analysis date.
  - Country (for IPs).
  - AS Owner (for IPs).
- Saves results in a CSV file.
- Supports parallel processing to speed up the scanning process.

---

## Requirements

- Python 3.10+

---

## Setup

1. Clone this repository to your local machine:

```bash
git clone https://github.com/yourusername/VirusTotalBulkScanner.git
cd VirusTotalBulkScanner
```

2. Create an API key in your [VirusTotal account](https://www.virustotal.com/). Once created, you can either:
   - Enter the API key manually when prompted by the script, type `yes`, it will generate a `config.json` file for future use or
   - Save it in a `config.json` file for future use.

The `config.json` file format is as follows:

```json
{
  "VT_API_KEY": "your_virus_total_api_key_here"
}
```

---

## Usage

Run the script from the command line by passing the input CSV file with items to be scanned and the output CSV file where results will be saved:

```bash
python vt_bulk_scanner.py input_file.csv output_file.csv
```

### Input File Format

The input file should be a CSV where each row contains one item to be scanned (e.g., an IP address, domain, or file hash). The file should have no header.

Example (`input_file.csv`):

```csv
8.8.8.8
example.com
d41d8cd98f00b204e9800998ecf8427e
```

### Output File Format

The output file will be a CSV file containing the following columns:

- **Item**: The IP address, domain, or file hash.
- **Type**: The type of item (IP address, domain, file).
- **Harmless**: The number of harmless detections.
- **Malicious**: The number of malicious detections.
- **Suspicious**: The number of suspicious detections.
- **Undetected**: The number of undetected detections.
- **Country**: The country for the IP address.
- **AS Owner**: The Autonomous System owner for the IP address.
- **VT Link**: A link to the VirusTotal page for the item.
- **Last Analysis Date**: The timestamp of the last analysis for the item.

---

## Example

Running the script:

```bash
python vt_bulk_scanner.py input_file.csv output_file.csv
```

This will scan all the items listed in `input_file.csv` and output the results to `output_file.csv`.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contributions

Feel free to fork this repository and submit pull requests. Any contributions are welcome!

---

This README file provides a simple explanation of the usage, setup, and features of the script. It also guides the user on how to get started with the project.
