import json
from collections import defaultdict
from itertools import combinations

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

def find_all_common_strings(data, min_length=5):
    """
    Mencari semua string yang sama antar file dengan optimasi
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
            
            # Jika kurang dari 2 file, skip
            if len(relevant_files) < 2:
                continue
            
            # Case 1: Cari yang common di semua file
            all_strings = [data[f][section][encoding] for f in relevant_files]
            common_all = find_common_strings(all_strings, min_length)
            
            if common_all:
                group_key = ", ".join(relevant_files)
                result[section][encoding][group_key] = common_all
                continue
            
            # Case 2 & 3: Cari pairwise common
            compared_pairs = set()
            
            for i in range(len(relevant_files)):
                for j in range(i+1, len(relevant_files)):
                    f1, f2 = relevant_files[i], relevant_files[j]
                    pair_key = f"{f1}, {f2}"
                    
                    if pair_key in compared_pairs:
                        continue
                    
                    # Cari common antara dua file ini
                    str1 = data[f1][section][encoding]
                    str2 = data[f2][section][encoding]
                    common_pair = find_common_strings([str1, str2], min_length)
                    
                    if common_pair:
                        result[section][encoding][pair_key] = common_pair
                        compared_pairs.add(pair_key)
    
    return dict(result)

def main(input_file):
    # Load your JSON data
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Process with optimized function
    lcs_results = find_all_common_strings(data)
    
    # Save results
    with open('./output_lcs/LCS_AgentTesla.json', 'w') as f:
        json.dump(lcs_results, f, indent=2)
    
    print("Optimized LCS results saved to lcs_optimized_results.json")