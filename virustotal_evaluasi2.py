import os
import csv
import json
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report

# ==== 1. Load Ground Truth ====
def load_ground_truth(csv_path):
    ground_truth = {}
    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            malware_hash = row['malware'].strip()
            famili = row['famili'].strip().lower()
            ground_truth[malware_hash] = famili
    return ground_truth

# ==== 2. Load VirusTotal Report ====
def load_virustotal_report(json_path):
    with open(json_path) as f:
        return json.load(f)

# ==== 3. Simplifikasi klasifikasi menjadi malware vs non-malware ====
def simplify_classification(famili, positives=0):
    if positives < 1 or famili == 'non-malware':
        return 'non-malware'
    return 'malware'

# ==== 4. Ekstraksi hasil deteksi sebagai prediksi ====
def extract_detection_result(report):
    positives = report.get('positives', 0)
    if positives < 1:
        return 'non-malware', positives
    return 'malware', positives

# ==== 5. Evaluasi dan tampilkan confusion matrix ====
def evaluate_predictions(vt_reports, ground_truth):
    y_true = []
    y_pred = []

    for report in vt_reports:
        file_hash = report.get('file_name')
        
        if not file_hash:
            continue

        # Menentukan kelas sebenarnya (ground truth)
        if file_hash in ground_truth:
            gt_famili = ground_truth[file_hash]
            true_class = simplify_classification(gt_famili, 1)  # Jika ada di ground truth, dianggap sebagai malware
        else:
            true_class = 'non-malware'
        
        # Menentukan kelas prediksi dari VirusTotal
        pred_class, positives = extract_detection_result(report)
        
        y_true.append(true_class)
        y_pred.append(pred_class)

    # Gunakan hanya dua label: malware dan non-malware
    labels = ['malware', 'non-malware']
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    print("[✓] Classification Report:\n")
    print(classification_report(y_true, y_pred, labels=labels))

    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', xticklabels=labels, yticklabels=labels, cmap='Blues')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix (Virus Total)')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()

# ==== 6. Main Program ====
if __name__ == "__main__":
    vt_json_path = "./Testing_YaraRules/Report_VirusTotal/Report.json"
    ground_truth_csv = "./ground_truth.csv"

    if not os.path.exists(vt_json_path) or not os.path.exists(ground_truth_csv):
        print("[!] File JSON atau CSV tidak ditemukan!")
    else:
        vt_reports = load_virustotal_report(vt_json_path)
        ground_truth = load_ground_truth(ground_truth_csv)
        evaluate_predictions(vt_reports, ground_truth)