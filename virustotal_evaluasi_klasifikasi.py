import os
import csv
import json
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report

def load_ground_truth(csv_path):
    ground_truth = {}
    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            malware_hash = row['malware'].strip()
            famili = row['famili'].strip().lower()
            ground_truth[malware_hash] = famili
    return ground_truth

def load_virustotal_report(json_path):
    with open(json_path) as f:
        return json.load(f)

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
    return name

def extract_predicted_famili(report, preferred_vendors=None):
    positives = report.get('positives', 0)
    if positives < 1:
        return 'non-malware'

    detected_by = report.get('detected_by', {})
    if preferred_vendors:
        for vendor in preferred_vendors:
            result = detected_by.get(vendor, {})
            if result.get('detected') and result.get('result'):
                return normalize_famili_name(result['result'])

    for result in detected_by.values():
        if result.get('detected') and result.get('result'):
            return normalize_famili_name(result['result'])

    return 'non-malware'

def reclassify_label(gt_famili):
    famili_list = ['agent tesla', 'amadey', 'vidar', 'cobalt strike']
    if gt_famili in famili_list:
        return gt_famili
    return 'non-malware'

def reclassify_label_predict(gt_famili, pred_famili, positives, is_in_ground_truth):
    if positives < 1 and not is_in_ground_truth:
        return 'non-malware'
    
    famili_list = ['agent tesla', 'amadey', 'vidar', 'cobalt strike']
    if gt_famili == pred_famili and gt_famili in famili_list:
        return gt_famili
    return 'malware'

def evaluate_predictions(vt_reports, ground_truth):
    y_true = []
    y_pred = []

    for report in vt_reports:
        file_hash = report.get('file_name')
        positives = report.get('positives', 0)

        if not file_hash:
            continue

        is_known = file_hash in ground_truth
        gt_famili = normalize_famili_name(ground_truth.get(file_hash, 'unknown'))
        pred_famili = extract_predicted_famili(report)

        y_true.append(reclassify_label(gt_famili))
        y_pred.append(reclassify_label_predict(gt_famili, pred_famili, positives, is_known))

    labels = ['agent tesla', 'amadey', 'vidar', 'cobalt strike', 'non-malware', 'malware']
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    print("[✓] Classification Report:\n")
    print(classification_report(y_true, y_pred, labels=labels, zero_division=0, digits=4))

    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', xticklabels=labels, yticklabels=labels, cmap='Blues', annot_kws={"size": 14})
    plt.xlabel('Predicted',fontsize=14)
    plt.ylabel('Actual',fontsize=14)
    plt.title('Confusion Matrix (Virus Total)', fontsize=16)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    vt_json_path = "./Testing_YaraRules/Report_VirusTotal/Report.json"
    ground_truth_csv = "./ground_truth.csv"

    if not os.path.exists(vt_json_path) or not os.path.exists(ground_truth_csv):
        print("[!] File JSON atau CSV tidak ditemukan!")
    else:
        vt_reports = load_virustotal_report(vt_json_path)
        ground_truth = load_ground_truth(ground_truth_csv)
        evaluate_predictions(vt_reports, ground_truth)
