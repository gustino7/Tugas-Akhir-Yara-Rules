import json
from collections import defaultdict

def find_common_strings(string_lists, min_length=5):
    """
    Mencari semua string yang sama dari beberapa list string dengan minimal panjang tertentu.
    """
    if not string_lists:
        return []
    
    sets = [set(lst) for lst in string_lists if lst]
    if not sets:
        return []
    
    common = set(sets[0])
    for s in sets[1:]:
        common.intersection_update(s)
    
    return [s for s in common if len(s) >= min_length]

def find_strings_in_all_files(data, min_length=5):
    """
    Mencocokkan string yang dimiliki oleh semua file untuk tiap section dan encoding.
    Output diformat dengan key 'ALL_FILES'.
    """
    result = defaultdict(lambda: defaultdict(dict))
    files = list(data.keys())

    # Ambil semua section dan encoding yang unik
    sections = set()
    encodings = set()
    for file_data in data.values():
        sections.update(file_data.keys())
        for section in file_data:
            encodings.update(file_data[section].keys())

    for section in sections:
        for encoding in encodings:
            relevant_files = [
                f for f in files if section in data[f] and encoding in data[f][section]
            ]
            if len(relevant_files) < 2:
                continue

            all_strings = [data[f][section][encoding] for f in relevant_files]
            common = find_common_strings(all_strings, min_length)

            if common:
                result[section][encoding]["ALL_FILES"] = {
                    "files": relevant_files,
                    "common_strings": common
                }

    return result

def main(input_file, malware_fam):
    # Load your JSON data
    with open(input_file, 'r') as f:
        data = json.load(f)

    # Process with modified matching function
    matched_strings = find_strings_in_all_files(data)

    # Save results
    with open(f'./output_lcs/string_matched_{malware_fam}.json', 'w') as f:
        json.dump(matched_strings, f, indent=2)

    print(f"Matched string results saved to {malware_fam}.json")