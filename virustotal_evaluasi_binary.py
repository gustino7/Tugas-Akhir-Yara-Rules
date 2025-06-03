import os
import csv
import json
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report

# ==== 1. Load Ground Truth ====
def load_ground_truth(csv_path):
    ground_truth = {}
    families = set()
    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            malware_hash = row['malware'].strip()
            famili = row['famili'].strip().lower()
            ground_truth[malware_hash] = famili
            families.add(famili)
    
    # Hapus "non-malware" dari families karena kita akan menggunakan binary classification
    families.discard("non-malware")
    return ground_truth, sorted(list(families))

# ==== 2. Load VirusTotal Report ====
def load_virustotal_report(json_path):
    with open(json_path) as f:
        return json.load(f)

# ==== 3. Normalisasi famili ====
def normalize_famili_name(name):
    name = name.lower()
    if 'vidar' in name:
        return 'vidar'
    elif 'agent' in name and 'tesla' in name:
        return 'agent tesla'
    elif 'cobalt' in name:
        return 'cobalt strike'
    elif 'amadey' in name:
        return 'amadey'
    return 'malware'

# ==== 4. Ekstraksi hasil deteksi sebagai prediksi ====
def extract_predicted_famili(report):
    positives = report.get('positives', 0)
    if positives < 1:
        return 'non-malware'
    else:
        detected_by = report.get('detected_by', {})
        for result in detected_by.values():
            if result.get('detected') and result.get('result'):
                return normalize_famili_name(result['result'])

    return 'non-malware'

# ==== 5. Binary Classification untuk setiap famili ====
def evaluate_predictions_binary(vt_reports):
    ground_truth_dict, all_families = load_ground_truth("./ground_truth.csv")
    print(f"Loaded ground truth for {len(ground_truth_dict)} files with {len(all_families)} families.")
    
    # Untuk setiap famili, buat binary classification
    for target_family in all_families:
        print(f"\n{'='*60}")
        print(f"Binary Classification for: {target_family.upper()}")
        print(f"{'='*60}")
        
        y_true = []
        y_pred = []

        for report in vt_reports:
            file_hash = report.get('file_name')
            positives = report.get('positives', 0)

            if not file_hash:
                continue

            # True label: target_family vs non-malware
            gt_famili = normalize_famili_name(ground_truth_dict.get(file_hash, 'unknown'))
            if gt_famili in all_families:
                true_label = "malware"
            else:
                true_label = "non-malware"

            # Predicted label: cek apakah VirusTotal mendeteksi sebagai target_family
            pred_famili = extract_predicted_famili(report)
            print(f'File {file_hash} detected as {pred_famili}')
            if pred_famili == target_family:
                predicted_label = "malware"
            elif pred_famili == 'non-malware':
                predicted_label = "non-malware"

            y_true.append(true_label)
            y_pred.append(predicted_label)

        if y_true and y_pred:
            calculate_and_display_binary_metrics(y_true, y_pred, target_family, "VirusTotal")
        else:
            print(f"No detection results collected for {target_family}.")

# ==== 6. Overall Binary Classification ====
def evaluate_predictions_overall_binary(vt_reports):
    ground_truth_dict, all_families = load_ground_truth("./ground_truth.csv")
    print(f"\n{'='*60}")
    print("Overall Binary Classification: MALWARE vs NON-MALWARE")
    print(f"{'='*60}")
    
    y_true = []
    y_pred = []

    for report in vt_reports:
        file_hash = report.get('file_name')
        positives = report.get('positives', 0)

        if not file_hash:
            continue

        # True label: malware (jika ada di ground truth) vs non-malware
        gt_famili = normalize_famili_name(ground_truth_dict.get(file_hash, 'unknown'))
        if gt_famili in all_families:
            true_label = "malware"
        else:
            true_label = "non-malware"

        # Predicted label: malware (jika VirusTotal mendeteksi) vs non-malware
        if positives >= 1:
            predicted_label = "malware"
        else:
            predicted_label = "non-malware"

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
                    xticklabels=labels, yticklabels=labels,
                    annot_kws={'size': 14})
        plt.xticks(fontsize=14)
        plt.yticks(fontsize=14)
        plt.title('Confusion Matrix VirusTotal Seluruh Famili', fontsize=16)
        plt.ylabel('Actual', fontsize=14)
        plt.xlabel('Predicted', fontsize=14)
        plt.tight_layout()
        plt.show()

# ==== 7. Calculate and Display Binary Metrics ====
def calculate_and_display_binary_metrics(y_true, y_pred, target_family, detection_method="VirusTotal"):
    # Labels untuk binary classification
    labels = ["malware", "non-malware"]
    
    print(f"\nClassification Report for {target_family}:")
    print("-" * 50)
    print(classification_report(y_true, y_pred, labels=labels, zero_division=0, digits=4))

    cm = confusion_matrix(y_true, y_pred, labels=labels)
    display_binary_confusion_matrix(cm, labels, target_family, detection_method)

def display_binary_confusion_matrix(cm, labels, target_family, detection_method="VirusTotal"):
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=labels, yticklabels=labels,
                annot_kws={'size': 14})
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    plt.title(f'Confusion Matrix {detection_method} Famili {target_family.capitalize()}', fontsize=16)
    plt.ylabel('Actual', fontsize=14)
    plt.xlabel('Predicted', fontsize=14)
    plt.tight_layout()
    plt.show()

# ==== 8. Main Program ====
if __name__ == "__main__":
    vt_json_path = "./Testing_YaraRules/Report_VirusTotal/Report.json"
    ground_truth_csv = "./ground_truth.csv"

    if not os.path.exists(vt_json_path) or not os.path.exists(ground_truth_csv):
        print("[!] File JSON atau CSV tidak ditemukan!")
    else:
        vt_reports = load_virustotal_report(vt_json_path)
        
        # Binary classification untuk setiap famili
        evaluate_predictions_binary(vt_reports)
        
        # Overall binary classification (opsional)
        evaluate_predictions_overall_binary(vt_reports)