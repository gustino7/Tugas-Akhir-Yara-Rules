import json
from collections import defaultdict

def find_common_strings(string_lists, min_length=5):
    """
    Mencari semua string yang sama dari beberapa list string dengan minimal panjang tertentu
    """
    if not string_lists:
        return []
    
    # Konversi semua list string ke set
    sets = [set(lst) for lst in string_lists if lst]
    
    if not sets:
        return []
    
    # Temukan irisan semua set
    common = set(sets[0])
    for s in sets[1:]:
        common.intersection_update(s)
    
    # Filter berdasarkan panjang minimal
    return [s for s in common if len(s) >= min_length]

def find_strings_in_all_files(data, min_length=5):
    """
    Mencari semua string yang ada di SEMUA file untuk setiap kombinasi section dan encoding
    """
    result = defaultdict(lambda: defaultdict(dict))
    files = list(data.keys())
    
    # Dapatkan semua section dan encoding yang unik
    sections = set()
    encodings = set()
    for file_data in data.values():
        sections.update(file_data.keys())
        for section in file_data:
            encodings.update(file_data[section].keys())
    
    for section in sections:
        for encoding in encodings:
            # Dapatkan file yang memiliki section dan encoding ini
            relevant_files = [
                f for f in files 
                if section in data[f] and encoding in data[f][section]
            ]
            
            # Hanya proses jika ada 2 file atau lebih
            if len(relevant_files) < 2:
                continue
            
            # Ambil semua string dari file yang relevan
            all_strings = [data[f][section][encoding] for f in relevant_files]
            
            # Cari string yang common di SEMUA file
            common_strings = find_common_strings(all_strings, min_length)
            
            if common_strings:
                # Simpan hasil dengan key berupa list semua file yang memiliki string ini
                group_key = "ALL_FILES"
                result[section][encoding][group_key] = {
                    'files': relevant_files,
                    'common_strings': common_strings
                }
    
    return dict(result)

def main(input_file, malware_fam):
    # Load your JSON data
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Process with the new function that only finds strings in ALL files
    matched_strings = find_strings_in_all_files(data)
    
    # Save results
    with open(f'./output_lcs/string_matched2_{malware_fam}.json', 'w') as f:
        json.dump(matched_strings, f, indent=2)
    
    print(f"Matched string results saved to {malware_fam}.json")