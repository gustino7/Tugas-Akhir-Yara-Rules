import json
from itertools import combinations

def longest_common_substring(s1, s2):
    m = [[0] * (1 + len(s2)) for _ in range(1 + len(s1))]
    longest, x_longest = 0, 0
    for x in range(1, 1 + len(s1)):
        for y in range(1, 1 + len(s2)):
            if s1[x - 1] == s2[y - 1]:
                m[x][y] = m[x - 1][y - 1] + 1
                if m[x][y] > longest:
                    longest = m[x][y]
                    x_longest = x
            else:
                m[x][y] = 0
    return s1[x_longest - longest: x_longest]

def find_all_lcs(data):
    result = {}
    files = list(data.keys())
    sections = set()
    
    # Get all unique sections across all files
    for file_data in data.values():
        sections.update(file_data.keys())
    
    for section in sections:
        section_result = {}
        # Get files that have this section
        files_with_section = [f for f in files if section in data[f]]
        
        # For each encoding type in the section (ascii, utf16)
        encodings = set()
        for f in files_with_section:
            encodings.update(data[f][section].keys())
        
        for encoding in encodings:
            encoding_result = {}
            # Get files that have this encoding in this section
            files_with_encoding = [f for f in files_with_section 
                                 if encoding in data[f][section]]
            
            # Compare all pairs
            for f1, f2 in combinations(files_with_encoding, 2):
                str1 = data[f1][section][encoding]
                str2 = data[f2][section][encoding]
                
                lcs = longest_common_substring(str1, str2)
                if lcs:  # Only store if there's a common substring
                    pair_key = f"{f1} vs {f2}"
                    encoding_result[pair_key] = lcs
            
            if encoding_result:
                section_result[encoding] = encoding_result
        
        if section_result:
            result[section] = section_result
    
    return result

# Example usage:
if __name__ == "__main__":
    # Load your JSON data
    with open('./output/LCS_AgentTesla.json', 'r') as f:
        data = json.load(f)
    
    lcs_results = find_all_lcs(data)
    
    # Save results to JSON
    with open('./output/LCS_results.json', 'w') as f:
        json.dump(lcs_results, f, indent=2)
    
    print("LCS results saved to lcs_results.json")