import yara
import os
import matplotlib.pyplot as plt
import csv
from sklearn.metrics import confusion_matrix, classification_report
import seaborn as sns

def load_ground_truth(csv_path):
    ground_truth = {}
    families = set()
    with open(csv_path, mode='r') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            filename = row['malware']
            family = row['famili']
            ground_truth[filename] = family
            families.add(family)
    families.add("non-malware")
    return ground_truth, sorted(list(families))

def apply_yara_rules(malware_directory, rules_directory, ground_truth_csv):
    ground_truth, all_families = load_ground_truth(ground_truth_csv)
    print(f"Loaded ground truth for {len(ground_truth)} files with {len(all_families)} families.")

    y_true = []
    y_pred = []

    # Kompilasi semua aturan sekaligus
    rule_files = [f for f in os.listdir(rules_directory) if f.endswith('.yar') or f.endswith('.yara')]
    rules_dict = {}
    
    for rule_file in rule_files:
        rule_path = os.path.join(rules_directory, rule_file)
        try:
            rules = yara.compile(filepath=rule_path)
            rules_dict[rule_file] = rules
        except yara.SyntaxError as e:
            print(f"Syntax error in rule file {rule_file}: {e}")
    
    for filename in os.listdir(malware_directory):
        file_path = os.path.join(malware_directory, filename)
        if not os.path.isfile(file_path):
            continue

        true_family = ground_truth.get(filename, "non-malware")
        predicted_family = "non-malware"

        try:
            for rule_file, rules in rules_dict.items():
                matches = rules.match(filepath=file_path)
                if matches:
                    matched_rule_name = matches[0].rule.lower()
                
                    # Map nama rule ke nama famili
                    rule_to_family = {
                        'new_yararules_agenttesla': 'agent tesla',
                        'new_yararules_amadey': 'amadey',
                        'new_yararules_vidar': 'vidar'
                        # Tambahkan jika ada rule lain
                    }

                    predicted_family = rule_to_family.get(matched_rule_name)
                    print(f"\tDetected in {filename} → {predicted_family}")
                    break
        except Exception as e:
            print(f"Error processing {filename}: {e}")
        
        y_true.append(true_family)
        y_pred.append(predicted_family)

    if y_true and y_pred:
        calculate_and_display_metrics(y_true, y_pred, all_families)
    else:
        print("No detection results collected.")

def calculate_and_display_metrics(y_true, y_pred, labels):
    print("\nClassification Report:\n")
    print(classification_report(y_true, y_pred, labels=labels, zero_division=0, digits=4))

    cm = confusion_matrix(y_true, y_pred, labels=labels)
    display_confusion_matrix(cm, labels)

def display_confusion_matrix(cm, labels):
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=labels, yticklabels=labels)
    plt.title('Confusion Matrix (Yara Rules Baru)')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()

if __name__ == '__main__':
    malware_directory = './Testing_File'
    rules_directory = './Testing_YaraRules/AllYaraRules_Baru'
    ground_truth_csv = './ground_truth.csv'

    apply_yara_rules(malware_directory, rules_directory, ground_truth_csv)
