import os
import pefile
import re
import json
import compare_string

def extract_ascii_strings(data, min_length):
    return re.findall(rb"[ -~]{%d,}" % min_length, data)

def extract_utf16_strings(data, min_length):
    pattern = rb"(?:[ -~]\x00){%d,}" % min_length
    raw_matches = re.findall(pattern, data)
    return [match.decode('utf-16le', errors='ignore') for match in raw_matches]

def parse_all_sections(pe, min_length):
    section_strings = {}
    # scan all section of pe
    for section in pe.sections:
        name = section.Name.decode(errors='ignore').strip('\x00')
        data = section.get_data()
        ascii_strings = extract_ascii_strings(data, min_length)
        utf16_strings = extract_utf16_strings(data, min_length)
        section_strings[name] = {
            "ascii": [s.decode(errors='ignore') for s in ascii_strings],
            "utf16": utf16_strings
        }
    return section_strings

def process_directory(path, min_length):
    result = {}
    for file in os.listdir(path):
        file_path = os.path.join(path, file)
        if not os.path.isfile(file_path):
            continue
        try:
            pe = pefile.PE(file_path, fast_load=True)
            strings_by_section = parse_all_sections(pe, min_length)
            result[file] = strings_by_section
        except Exception as e:
            print(f"Error processing {file}: {e}")
    return result

def main():
    MIN_LENGTH = 5

    malware_fam = "Amadey"
    malware_path = f"./Sample_Malware/{malware_fam}" # Path direktori malware
    output_dir = "./Parser_StringPython/output_parser"
    os.makedirs(output_dir, exist_ok=True)

    # Jalankan dan simpan ke file JSON
    result = process_directory(malware_path, MIN_LENGTH)
    output_file = os.path.join(output_dir, f'String_{malware_fam}.json')
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Hasil penguraian string disimpan di: {output_file}")

    compare_string.main(output_file, malware_fam, MIN_LENGTH)

if __name__ == "__main__":
    main()