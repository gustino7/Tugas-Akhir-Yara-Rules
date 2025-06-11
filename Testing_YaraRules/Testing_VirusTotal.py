import os
import requests
import time
import json
from dotenv import load_dotenv

# Konfigurasi
load_dotenv()
API_KEY = os.getenv("API_KEY")
DIRECTORY_PATH = '../Testing_File'
SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
RATE_LIMIT_DELAY = 15  # Rate limit

def scan_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            files = {'file': (os.path.basename(file_path), file)}
            params = {'apikey': API_KEY}
            response = requests.post(SCAN_URL, files=files, params=params)
            return response.json()
    except Exception as e:
        print(f"[!] Error: {file_path} => {str(e)}")
        return None

def get_report(resource):
    params = {'apikey': API_KEY, 'resource': resource}
    response = requests.get(REPORT_URL, params=params)
    return response.json()

def scan_directory(directory):
    results = []  # kumpulkan semua hasil

    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)

            if os.path.getsize(file_path) > 32 * 1024 * 1024:
                results.append({'file_name': filename})
                print(f"[!] Skipped (Too Large): {filename}")
                continue

            print(f"\n[+] Scanning: {filename}")
            scan_result = scan_file(file_path)
            if scan_result and scan_result.get('response_code') == 1:
                resource = scan_result['resource']
                time.sleep(RATE_LIMIT_DELAY)

                report = get_report(resource)
                if report.get('response_code') == 1:
                    scans = report.get('scans', {})

                    result_data = {
                        'file_name': filename,
                        'permalink': report.get('permalink'),
                        'positives': report.get('positives', 0),
                        'total': report.get('total', 0),
                        'detected_by': {
                            vendor: result for vendor, result in scans.items() if result.get('result')
                        }
                    }

                    results.append(result_data)
                    print(f"    Nama File  : {filename}")
                else:
                    print(f"[?] {filename}: Report not ready")
            else:
                print(f"[X] Failed to scan: {filename}")

            time.sleep(RATE_LIMIT_DELAY)

    # Simpan hasil ke file JSON
    os.makedirs("./Report_VirusTotal", exist_ok=True)
    output_file = "./Report_VirusTotal/Report.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"\n[✓] Semua hasil telah disimpan ke '{output_file}'")

if __name__ == "__main__":
    if not os.path.isdir(DIRECTORY_PATH):
        print("Directory not found!")
    else:
        scan_directory(DIRECTORY_PATH)
