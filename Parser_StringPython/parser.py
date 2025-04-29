import os
import pefile
import re
import json
from collections import defaultdict
import lcs_optimize
import lcs_optimize2
import compare_string
import compare2_string

def extract_ascii_strings(data, min_length=5):
    return re.findall(rb"[ -~]{%d,}" % min_length, data)

def extract_utf16_strings(data, min_length=5):
    pattern = rb"(?:[ -~]\x00){%d,}" % min_length
    raw_matches = re.findall(pattern, data)
    return [match.decode('utf-16le', errors='ignore') for match in raw_matches]

def parse_all_sections(pe):
    section_strings = {}
    # scan all section of pe
    for section in pe.sections:
        name = section.Name.decode(errors='ignore').strip('\x00')
        data = section.get_data()
        ascii_strings = extract_ascii_strings(data)
        utf16_strings = extract_utf16_strings(data)
        section_strings[name] = {
            "ascii": [s.decode(errors='ignore') for s in ascii_strings],
            "utf16": utf16_strings
        }
    return section_strings

def process_directory(path):
    result = {}
    for file in os.listdir(path):
        file_path = os.path.join(path, file)
        if not os.path.isfile(file_path):
            continue
        try:
            pe = pefile.PE(file_path, fast_load=True)
            strings_by_section = parse_all_sections(pe)
            result[file] = strings_by_section
        except Exception as e:
            print(f"Error processing {file}: {e}")
    return result

# Path direktori sample
malware_fam = "AgentTesla" # Ganti sesuai family
folder_path = f"../Sample_Malware/{malware_fam}"  # Ganti sesuai lokasi kamu
output_json = f"./output_parser/String_{malware_fam}.json"

# Jalankan dan simpan ke file JSON
result = process_directory(folder_path)
with open(output_json, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=4, ensure_ascii=False)

print(f"Hasil string per file dan per section disimpan di: {output_json}")

# lcs_optimize.main(output_json, malware_fam)
# lcs_optimize2.main(output_json, malware_fam)
compare_string.main(output_json, malware_fam)
compare2_string.main(output_json, malware_fam)