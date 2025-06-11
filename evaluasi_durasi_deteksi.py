import yara
import os
import time
from datetime import timedelta

def apply_yara_rules(testing_directory, rules_directory):
    # Start overall timing
    overall_start_time = time.time()
    
    # Get all rules files
    rules_files = [f for f in os.listdir(rules_directory) if f.endswith('.yar') or f.endswith('.yara')]
    total_matches = 0
    
    print(f"\n{'='*60}")
    print(f"Starting malware detection on files in: {testing_directory}")
    print(f"Using YARA rules from: {rules_directory}")
    print(f"{'='*60}")
    
    # Process each rules file
    for rules_file in rules_files:
        index_rules = 1
        rules_path = os.path.join(rules_directory, rules_file)
        
        # Start timing for this rules file
        rules_start_time = time.time()
        
        print(f'\nLoading rules from: {rules_path}')
        
        try:
            rules = yara.compile(filepath=rules_path)
            
            # Keep track of matches per rule file
            file_matches = 0
            
            for file in os.listdir(testing_directory):
                file_path = os.path.join(testing_directory, file)
                if os.path.isfile(file_path):
                    try:
                        matches = rules.match(file_path)
                        if matches:
                            print(f'{index_rules})\tFile: {file} - Matches found in {rules_file}: {matches}')
                            index_rules += 1
                            file_matches += 1
                            total_matches += 1
                    except Exception as e:
                        print(f'Error processing {file} with rules from {rules_file}: {e}')
            
            # Calculate and display timing for this rules file
            rules_time = time.time() - rules_start_time
            print(f"\nRules file '{rules_file}' processing completed:")
            print(f"- Time taken: {format_time(rules_time)}")
            print(f"- Matches found: {file_matches}")
            
        except Exception as e:
            print(f'Error loading rules from {rules_file}: {e}')
    
    # Calculate and display overall timing
    overall_time = time.time() - overall_start_time
    
    print(f"\n{'='*60}")
    print(f"Malware detection completed")
    print(f"Total time: {format_time(overall_time)}")
    print(f"Total matches found: {total_matches}")
    print(f"{'='*60}")

def format_time(seconds):
    """Format seconds into a readable time string"""
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    else:
        return str(timedelta(seconds=int(seconds)))

if __name__ == '__main__':
    testing_directory = './Testing_File'
    rules_directory = './Testing_YaraRules/AllYaraRules_Baru'
    apply_yara_rules(testing_directory, rules_directory)