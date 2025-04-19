import yara
import os

def apply_yara_rules_to_malware(malware_directory, rules_directory):
    # Mengambil semua file YARA rules dari direktori
    rules_files = [f for f in os.listdir(rules_directory) if f.endswith('.yar') or f.endswith('.yara')]

    # Iterasi melalui setiap file YARA rules
    for rules_file in rules_files:
        index_rules = 1
        rules_path = os.path.join(rules_directory, rules_file)
        print(f'\nLoading rules from: {rules_path}')

        # Print Index Rules
        print(f'Rules path : {rules_path}')
        
        # Muat aturan YARA dari file
        rules = yara.compile(filepath=rules_path)

        # Iterasi melalui semua file malware dalam direktori
        for malware_file in os.listdir(malware_directory):
            malware_path = os.path.join(malware_directory, malware_file)

            # Hanya memeriksa file, abaikan direktori
            if os.path.isfile(malware_path):
                try:
                    # Menerapkan aturan YARA pada file malware
                    matches = rules.match(malware_path)

                    # Jika ada kecocokan, tampilkan hasil
                    if matches:
                        print(f'{index_rules})\tFile: {malware_file} - Matches found in {rules_file}: {matches}')
                        index_rules += 1
                    #else:
                    #    print(f'File: {malware_file} - No matches found in {rules_file}.')
                except Exception as e:
                    print(f'Error processing {malware_file} with rules from {rules_file}: {e}')

if __name__ == '__main__':
    # Tentukan direktori untuk malware dan direktori untuk YARA rules
    malware_directory = './Sample_Malware/Vidar'         # Ganti dengan direktori malware Anda
    rules_directory = './Yara_Rules_Baru/Vidar'            # Ganti dengan direktori yang berisi YARA rules Anda

    # Panggil fungsi untuk menerapkan YARA rules ke malware
    apply_yara_rules_to_malware(malware_directory, rules_directory)
