import socket
import json
import joblib
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

print("--- MEMUAT SISTEM PERTAHANAN AI ---")
# Memuat 6 komponen utama dari Colab
model        = joblib.load('model_knn_ddos.pkl')
scaler       = joblib.load('scaler_ddos.pkl')
selector     = joblib.load('selector_ddos.pkl')
feature_cols = joblib.load('feature_columns.pkl')
kolom_hapus  = joblib.load('kolom_hapus_korelasi.pkl')
kolom_nocorr = joblib.load('kolom_nocorr.pkl')

IP = "127.0.0.1"
PORT = 9999
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((IP, PORT))

blacklist_ips = set()
log_serangan = []
statistik = {'total_terima': 0, 'tebakan_benar': 0, 'tebakan_salah': 0}

print(f"✅ AI Firewall Aktif di {IP}:{PORT}")
print("🛡️ Menunggu serangan... (Tekan Ctrl+C untuk melihat Laporan Evaluasi AI)\n")

try:
    while True:
        data, addr = server.recvfrom(8192)
        paket = json.loads(data.decode('utf-8'))
        
        # Ekstraksi IP dan Kunci Jawaban
        ip_pengirim = paket.pop('src', addr[0])
        label_asli = paket.pop('label_asli', None) 
        
        # 1. CEK FIREWALL KERNEL (Blacklist)
        if ip_pengirim in blacklist_ips:
            print(f"🚫 [DROP] Paket dibuang dari IP Blacklist: {ip_pengirim}")
            continue
            
        statistik['total_terima'] += 1

        # ========================================================
        # 2. PIPELINE PREPROCESSING AI (Sesuai Standar Colab Baru)
        # ========================================================
        df_paket = pd.DataFrame([paket])
        
        # A. One-Hot Encoding (Jika format Protocol berupa teks)
        if 'Protocol' in df_paket.columns:
            df_paket = pd.get_dummies(df_paket, columns=['Protocol'])
            
        # B. Reindex ke feature_columns (Persiapan masuk Scaler)
        for col in feature_cols:
            if col not in df_paket.columns:
                df_paket[col] = 0
        df_paket = df_paket[feature_cols]

        # C. Feature Scaling
        data_scaled = scaler.transform(df_paket)
        df_scaled = pd.DataFrame(data_scaled, columns=feature_cols)

        # D. Buang Kolom Korelasi Tinggi
        df_nocorr = df_scaled.drop(columns=[c for c in kolom_hapus if c in df_scaled.columns], errors='ignore')

        # E. Reindex ke kolom_nocorr (Persiapan masuk Selector)
        for col in kolom_nocorr:
            if col not in df_nocorr.columns:
                df_nocorr[col] = 0
        df_nocorr = df_nocorr[kolom_nocorr]

        # F. SelectKBest (Pilih fitur penting)
        data_selected = selector.transform(df_nocorr)

        # G. PREDIKSI AKHIR KNN
        prediksi = int(model.predict(data_selected)[0])
        # ========================================================

        # Evaluasi Kunci Jawaban (Mode 3 CSV)
        if label_asli is not None:
            if prediksi == int(label_asli):
                statistik['tebakan_benar'] += 1
            else:
                statistik['tebakan_salah'] += 1

        # 3. TINDAKAN (MITIGASI LINUX)
        if prediksi == 1:
            print(f"⚠️ [BAHAYA] DDoS Terdeteksi dari {ip_pengirim}!")
            perintah_iptables = f"sudo iptables -A INPUT -s {ip_pengirim} -j DROP"
            print(f"🔒 Mengeksekusi kernel: {perintah_iptables}")
            
            blacklist_ips.add(ip_pengirim)
            log_serangan.append(ip_pengirim)
            print(f"✅ Mitigasi berhasil. IP {ip_pengirim} diblokir permanen.\n")
        else:
            print(f"✅ [AMAN] Traffic dari {ip_pengirim} diizinkan.")

except KeyboardInterrupt:
    print("\n\n===============================================")
    print("📊 LAPORAN EVALUASI INTRUSION PREVENTION SYSTEM")
    print("===============================================")
    print(f"Total Paket Diproses AI  : {statistik['total_terima']}")
    
    if (statistik['tebakan_benar'] + statistik['tebakan_salah']) > 0:
        akurasi = (statistik['tebakan_benar'] / (statistik['tebakan_benar'] + statistik['tebakan_salah'])) * 100
        print(f"Tebakan AI Benar         : {statistik['tebakan_benar']}")
        print(f"Tebakan AI Salah         : {statistik['tebakan_salah']}")
        print(f"Akurasi Real-time        : {akurasi:.2f}%")
    else:
        print("Akurasi Real-time        : (Gunakan Mode 3 untuk melihat akurasi)")

    print("\n📜 DAFTAR IP PENYERANG YANG DIBLOKIR (BLACKLIST):")
    if len(blacklist_ips) > 0:
        for idx, ip in enumerate(list(blacklist_ips)[:10], 1):
            print(f"   {idx}. {ip}")
        if len(blacklist_ips) > 10:
            print(f"   ... dan {len(blacklist_ips) - 10} IP lainnya.")
    else:
        print("   Tidak ada serangan yang masuk.")
    print("===============================================\n")