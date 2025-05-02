import json
import csv

# Fungsi untuk membaca hash malware dari CSV
def read_malware_hashes(csv_file):
    malware_hashes = set()
    with open(csv_file, mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row:  # Skip baris kosong
                malware_hashes.add(row[0].strip())  # Ambil kolom pertama (hash)
    return malware_hashes

# Fungsi untuk memproses data JSON
def process_vt_data(json_data, malware_hashes):
    results = []
    for item in json_data:
        # Cek jika file_name adalah hash (panjang 64 karakter hex)
        file_name = item.get('file_name', '').strip()
        if (item.get('positives', 0) < 10 and  # Perhatikan typo 'positives' di contoh Anda
            file_name not in malware_hashes):
            
            results.append({
                'file_name': file_name,
                'positives': item.get('positives', 0)
            })
    return results

# Main program
if __name__ == "__main__":
    # File paths
    json_file = './Testing_YaraRules/Report_VirusTotal/Report.json'  # Ganti dengan path file JSON Anda
    csv_file = './ground_truth.csv'        # Ganti dengan path file CSV Anda
    
    # 1. Baca hash malware dari CSV
    try:
        malware_hashes = read_malware_hashes(csv_file)
        print(f"Loaded {len(malware_hashes)} malware hashes from CSV")
    except FileNotFoundError:
        print(f"Error: File {csv_file} not found")
        exit(1)
    
    # 2. Baca data JSON
    try:
        with open(json_file, 'r') as f:
            vt_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File {json_file} not found")
        exit(1)
    
    # 3. Proses data
    filtered_files = process_vt_data(vt_data, malware_hashes)
    
    # 4. Tampilkan hasil
    if filtered_files:
        index = 1
        for file in filtered_files:
            print(f"{index})\t{file['file_name']} | {file['positives']}")
            index += 1
    else:
        print("Tidak ada file yang memenuhi kriteria")