import json

with open('./Testing_YaraRules/Report_VirusTotal/Report.json') as f:
    data = json.load(f)
    
missing_positives = [f["file_name"] for f in data if "positives" not in f]

for f in missing_positives:
    print("Files not detected:", f)