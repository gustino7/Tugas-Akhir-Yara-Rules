import json
from collections import defaultdict
from itertools import combinations

def find_common_strings(string_lists, min_length=5):
    """
    Mencari string yang muncul di semua list dengan panjang minimal tertentu.
    """
    if not string_lists:
        return []
    
    sets = [set(lst) for lst in string_lists if lst]
    if not sets:
        return []
    
    common = set(sets[0])
    for s in sets[1:]:
        common.intersection_update(s)
        if not common:
            return []
    
    return [s for s in common if len(s) >= min_length]

def find_all_common_combinations(data, min_length=5):
    """
    Mencari semua kombinasi file yang memiliki string bersama.
    """
    result = defaultdict(lambda: defaultdict(dict))
    files = list(data.keys())
    
    # Collect all sections and encodings
    sections = set()
    encodings = set()
    for file_data in data.values():
        sections.update(file_data.keys())
        for section in file_data:
            encodings.update(file_data[section].keys())
    
    for section in sections:
        for encoding in encodings:
            # Get files with this section and encoding
            relevant_files = [f for f in files 
                            if section in data[f] and encoding in data[f][section]]
            
            # Check all possible group sizes from largest to smallest
            for group_size in range(len(relevant_files), 1, -1):
                for file_group in combinations(relevant_files, group_size):
                    group_strings = [data[f][section][encoding] for f in file_group]
                    common = find_common_strings(group_strings, min_length)
                    
                    if common:
                        group_key = ", ".join(file_group)
                        result[section][encoding][group_key] = common
                        
                        # Remove these files from further smaller combinations
                        relevant_files = [f for f in relevant_files if f not in file_group]
                        break  # Move to next group size
    
    return dict(result)

def main(input_file, malware_fam):
    # Load data
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Process data
    results = find_all_common_combinations(data, min_length=5)
    
    # Save results
    with open(f'./output_lcs/LCS2_{malware_fam}.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("Hasil semua kombinasi persamaan string tersimpan di LCS2_AgentTesla.json")