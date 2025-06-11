import json
import os
from collections import defaultdict

def find_common_strings(string_lists, min_length=5, max_length=20):
    if not string_lists:
        return []
    
    # Filter empty lists
    valid_lists = [lst for lst in string_lists if lst]
    if not valid_lists:
        return []
    
    # Start with the set of strings from the first list
    common = set(valid_lists[0])
    
    # Find intersection with all other lists
    for s in valid_lists[1:]:
        common.intersection_update(s)
    
    # Filter by minimum length
    return sorted([s for s in common if len(s) >= min_length and len(s) <= max_length])

def find_strings_in_all_files(data, min_length=5, max_length=20):
    result = defaultdict(lambda: defaultdict(dict))
    files = list(data.keys())
    
    if len(files) < 2:
        print("Warning: Need at least 2 files to find common strings")
        return result
    
    # Identify all unique sections and encodings
    sections = set()
    encodings = set()
    
    for file_data in data.values():
        sections.update(file_data.keys())
        for section in file_data:
            if isinstance(file_data[section], dict):  # Ensure it's a dictionary
                encodings.update(file_data[section].keys())
    
    # Process each section and encoding
    for section in sections:
        for encoding in encodings:
            # Find files that have this section and encoding
            relevant_files = [
                f for f in files 
                if section in data[f] and 
                   isinstance(data[f][section], dict) and
                   encoding in data[f][section]
            ]
            
            if len(relevant_files) < 2:
                continue
            
            # Gather all strings for this section/encoding from relevant files
            all_strings = [data[f][section][encoding] for f in relevant_files]
            
            # Find common strings
            common = find_common_strings(all_strings, min_length, max_length)
            
            if common:
                result[section][encoding] = {
                    "files": relevant_files,
                    "files_count": len(relevant_files),
                    "common_strings": common,
                    "strings_count": len(common)
                }
    
    return result

def main(input_file, malware_fam, min_length=5, max_length=20):
    # Load JSON data
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON data: {e}")
        return
    
    # Create output directory if it doesn't exist
    output_dir = './Parser_StringPython/output_compare'
    os.makedirs(output_dir, exist_ok=True)
    
    # Save results
    result = find_strings_in_all_files(data, min_length, max_length)
    output_file = os.path.join(output_dir, f'String_Matched_{malware_fam}.json')
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    # Print summary
    print(f"Hasil pencocokan string disimpan di {output_file}")