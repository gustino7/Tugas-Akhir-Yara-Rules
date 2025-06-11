# Tugas Akhir Forensik Malware dengan Yara Rules
Tugas akhir ini digunakan untuk mendeteksi malware menggunakan Yara Rules. Yara Rules publik yang tersedia di publik akan dioptimasi dengan 3 metode, yaitu pencarian string menggunakan Yargen, pencarian string dengan mencocokan string dari hasil penguraian menggunakan Library pefile pada Python, dan pencarian string secara manual sebagai signature

# Langkah Untuk Menjalankan Yara Rules Hasil dari Penelitian Ini
1. Buat environment variable Python
2. Clone github ini
3. Jalankan command ```pip install yara-python```
4. Jalankan command ```pip install seaborn```
5. Jalankan command ```pip install scikit-learn```

# Yara Rules
Yara Rules yang dibuat dapat mendeteksi keberadaan malware dan klasifikasi malware 

## Jalankan Script Python untuk Mendeteksi Keberadaan Malware
1. ```python implementasi_deteksi.py``` untuk menjalankan yara rules dan menampilkan hasilnya di terminal
2. ```python evaluasi_deteksi.py``` untuk mendapatkan confusion matrix hasil dari deteksi malware
3. ```python evaluasi_durasi_deteksi.py``` untuk mendapatkan waktu deteksi
4. ```python virustotal_evaluasi_deteksi.py``` untuk mendapatkan confusion matrix dari virus total

## Jalankan Script Python untuk Klasifikasi Malware
1. ```python implementasi_klasifikasi.py``` untuk menjalankan yara rules dan menampilkan hasilnya di terminal
2. ```python evaluasi_klasifikasi.py``` untuk mendapatkan confusion matrix hasil dari klasifikasi malware
3. ```python evaluasi_durasi_klasifikasi.py``` untuk mendapatkan waktu klasifikasi
4. ```python virustotal_evaluasi_klasifikasi.py``` untuk mendapatkan confusion matrix dari virus total
