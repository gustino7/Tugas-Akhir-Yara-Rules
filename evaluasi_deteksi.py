import os
import csv
import yara
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report

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
    
    families.discard("non-malware")
    return ground_truth, sorted(list(families))

def calculate_and_display_binary_metrics(y_true, y_pred, target_family, yara_rules):
    # Labels untuk binary classification
    labels = ["malware", "non-malware"]
    
    print(f"\nClassification Report for {target_family}:")
    print("-" * 50)
    print(classification_report(y_true, y_pred, labels=labels, zero_division=0, digits=4))

    cm = confusion_matrix(y_true, y_pred, labels=labels)
    display_binary_confusion_matrix(cm, labels, target_family, yara_rules)

def display_binary_confusion_matrix(cm, labels, target_family, yara_rules):
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=labels, yticklabels=labels, annot_kws={"size": 14})
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    plt.title(f'Confusion Matrix {yara_rules} Famili {target_family.capitalize()}', fontsize=16)
    plt.ylabel('Actual', fontsize=14)
    plt.xlabel('Predicted', fontsize=14)
    plt.tight_layout()
    plt.show()

def apply_yara_rules_overall_binary(malware_directory, rules_directory, ground_truth_csv, yara_rules):
    """
    Fungsi tambahan untuk overall binary classification (malware vs non-malware)
    """
    ground_truth, all_families = load_ground_truth(ground_truth_csv)
    print(f"\n{'='*60}")
    print("Overall Binary Classification: MALWARE vs NON-MALWARE")
    print(f"{'='*60}")

    rule_files = [f for f in os.listdir(rules_directory) if f.endswith('.yar') or f.endswith('.yara')]

    rule_compiled_map = {}
    for rule_file in rule_files:
        rule_path = os.path.join(rules_directory, rule_file)
        try:
            rules = yara.compile(filepath=rule_path)
            family = rule_file.replace('Yara_', '').replace('.yar', '').replace('.yara', '')
            rule_compiled_map[family] = rules
        except yara.SyntaxError as e:
            print(f"Error compiling {rule_file}: {e}")
            continue

    y_true = []
    y_pred = []

    for filename in os.listdir(malware_directory):
        file_path = os.path.join(malware_directory, filename)
        if not os.path.isfile(file_path):
            continue

        # True label: malware (jika ada di ground truth) vs non-malware
        true_family = ground_truth.get(filename, "unknown")
        if true_family in all_families:
            true_label = "malware"
        else:
            true_label = "non-malware"

        # Predicted label: malware (jika ada rule yang mendeteksi) vs non-malware
        predicted_label = "non-malware"
        
        for family, rules in rule_compiled_map.items():
            try:
                matches = rules.match(file_path)
                if matches:
                    predicted_label = "malware"
                    print(f"\tDetected malware in {filename} → {family} ({matches})")
                    break
            except Exception as e:
                print(f"Error processing {filename}: {e}")

        y_true.append(true_label)
        y_pred.append(predicted_label)

    if y_true and y_pred:
        labels = ["malware", "non-malware"]
        print(f"\nOverall Classification Report:")
        print("-" * 50)
        print(classification_report(y_true, y_pred, labels=labels, zero_division=0, digits=4))

        cm = confusion_matrix(y_true, y_pred, labels=labels)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                    xticklabels=labels, yticklabels=labels, annot_kws={"size": 14})
        plt.xticks(fontsize=14)
        plt.yticks(fontsize=14)
        plt.title(f'Confusion Matrix {yara_rules}', fontsize=16)
        plt.ylabel('Actual', fontsize=14)
        plt.xlabel('Predicted', fontsize=14)
        plt.tight_layout()
        plt.show()

if __name__ == '__main__':
    malware_directory = './Testing_File'
    rules_directory = './Testing_YaraRules/AllYaraRules_Baru' # Ubah Yara Rules Publik atau Baru
    yara_rules = 'Yara Rules Baru'
    ground_truth_csv = './ground_truth.csv'
    
    apply_yara_rules_overall_binary(malware_directory, rules_directory, ground_truth_csv, yara_rules)