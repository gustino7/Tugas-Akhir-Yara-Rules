import yara
import os

def apply_yara_rules(testing_directory, rules_directory):
    rules_files = [f for f in os.listdir(rules_directory) if f.endswith('.yar') or f.endswith('.yara')]

    for rules_file in rules_files:
        index_rules = 1
        rules_path = os.path.join(rules_directory, rules_file)
        print(f'\nLoading rules from: {rules_path}')

        print(f'Rules path : {rules_path}')
        rules = yara.compile(filepath=rules_path)

        for file in os.listdir(testing_directory):
            file_path = os.path.join(testing_directory, file)

            if os.path.isfile(file_path):
                try:
                    matches = rules.match(file_path)

                    if matches:
                        print(f'{index_rules})\tFile: {file} - Matches found in {rules_file}: {matches}')
                        index_rules += 1
                except Exception as e:
                    print(f'Error processing {file} with rules from {rules_file}: {e}')

if __name__ == '__main__':
    testing_directory = './Testing_File'
    rules_directory = './Testing_YaraRules/YaraRules_Baru'

    apply_yara_rules(testing_directory, rules_directory)
