import socket
import json
import joblib
import pandas as pd
import warnings
import os
warnings.filterwarnings('ignore')

print("--- MEMUAT SISTEM PERTAHANAN AI ---")
model = joblib.load('model_knn_ddos.pkl')
scaler = joblib.load('scaler_ddos.pkl')
feature_cols = joblib.load('feature_columns.pkl')

IP = "127.0.0.1"
PORT = 9999
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((IP, PORT))

# Penyimpanan memori server
blacklist_ips = set()
log_serangan = []
statistik = {'total_terima': 0, 'tebakan_benar': 0, 'tebakan_salah': 0}

print(f"✅ AI Firewall Aktif di {IP}:{PORT}")
print("🛡️ Menunggu serangan... (Tekan Ctrl+C untuk melihat Laporan Evaluasi AI)\n")

try:
    while True:
        data, addr = server.recvfrom(8192)
        paket = json.loads(data.decode('utf-8'))
        
        # Ekstraksi IP dan Kunci Jawaban (jika ada) sebelum masuk ke AI
        ip_pengirim = paket.pop('src', addr[0])
        label_asli = paket.pop('label_asli', None) 
        
        # 1. CEK FIREWALL LEVEL KERNEL (Blacklist)
        if ip_pengirim in blacklist_ips:
            print(f"🚫 [DROP] Paket dibuang dari IP Blacklist: {ip_pengirim}")
            continue
            
        statistik['total_terima'] += 1

        # 2. PREPROCESSING UNTUK AI
        df_paket = pd.DataFrame([paket])
        for col in feature_cols:
            if col not in df_paket.columns:
                df_paket[col] = 0
        df_paket = df_paket[feature_cols]

        # 3. PREDIKSI AI
        data_scaled = scaler.transform(df_paket)
        prediksi = int(model.predict(data_scaled)[0])

        # 4. EVALUASI AKURASI (Jika dikirim dari Mode 3 dataset)
        if label_asli is not None:
            if prediksi == int(label_asli):
                statistik['tebakan_benar'] += 1
            else:
                statistik['tebakan_salah'] += 1

        # 5. TINDAKAN (MITIGASI LINUX)
        if prediksi == 1:
            print(f"⚠️ [BAHAYA] DDoS Terdeteksi dari {ip_pengirim}!")
            
            # Simulasi menjalankan perintah Linux Firewall
            perintah_iptables = f"sudo iptables -A INPUT -s {ip_pengirim} -j DROP"
            print(f"🔒 Mengeksekusi kernel: {perintah_iptables}")
            
            # Menyimpan ke memori
            blacklist_ips.add(ip_pengirim)
            log_serangan.append(ip_pengirim)
            print(f"✅ Mitigasi berhasil. IP {ip_pengirim} diblokir permanen.\n")
        else:
            print(f"✅ [AMAN] Traffic dari {ip_pengirim} diizinkan.")

except KeyboardInterrupt:
    # 6. CETAK RAPOR SAAT SERVER DIMATIKAN
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
        for idx, ip in enumerate(list(blacklist_ips)[:10], 1): # Tampilkan maks 10 IP
            print(f"   {idx}. {ip}")
        if len(blacklist_ips) > 10:
            print(f"   ... dan {len(blacklist_ips) - 10} IP lainnya.")
    else:
        print("   Tidak ada serangan yang masuk.")
    print("===============================================\n")