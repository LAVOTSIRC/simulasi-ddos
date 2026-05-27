import socket
import json
import time
import random
import pandas as pd

IP_SERVER = "127.0.0.1"
PORT_SERVER = 9999
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

data_normal_dummy = {"src": "192.168.1.15", "pktcount": 50, "bytecount": 5000, "dur": 100, "dur_nsec": 500000, "tot_dur": 100.5, "flows": 3, "packetins": 2, "pktperflow": 16, "byteperflow": 1600, "pktrate": 0, "Pairflow": 0, "port_no": 1, "tx_bytes": 2500, "rx_bytes": 2500, "tx_kbps": 0, "rx_kbps": 0, "tot_kbps": 0, "Protocol_UDP": 0}
data_ddos_dummy = {"src": "66.66.66.66", "pktcount": 150000, "bytecount": 80000000, "dur": 2, "dur_nsec": 100000, "tot_dur": 2.1, "flows": 1500, "packetins": 5000, "pktperflow": 10000, "byteperflow": 500000, "pktrate": 5000, "Pairflow": 1, "port_no": 3, "tx_bytes": 40000000, "rx_bytes": 40000000, "tx_kbps": 100000, "rx_kbps": 100000, "tot_kbps": 200000, "Protocol_UDP": 1}

def generate_acak(is_ddos):
    if is_ddos:
        return {"src": f"10.0.0.{random.randint(2, 254)}", "pktcount": random.randint(50000, 200000), "bytecount": random.randint(10000000, 90000000), "dur": random.randint(1, 10), "dur_nsec": random.randint(10000, 100000), "tot_dur": random.uniform(1.0, 10.0), "flows": random.randint(1000, 3000), "packetins": random.randint(1000, 8000), "pktperflow": random.randint(5000, 15000), "byteperflow": random.randint(100000, 800000), "pktrate": random.randint(3000, 8000), "Pairflow": 1, "port_no": random.choice([1, 2, 3, 4]), "tx_bytes": random.randint(10000000, 50000000), "rx_bytes": random.randint(10000000, 50000000), "tx_kbps": random.randint(50000, 200000), "rx_kbps": random.randint(50000, 200000), "tot_kbps": random.randint(100000, 400000), "Protocol_UDP": 1}
    else:
        return {"src": f"192.168.1.{random.randint(10, 50)}", "pktcount": random.randint(10, 500), "bytecount": random.randint(1000, 50000), "dur": random.randint(50, 500), "dur_nsec": random.randint(100000, 900000), "tot_dur": random.uniform(50.0, 500.0), "flows": random.randint(2, 10), "packetins": random.randint(1, 10), "pktperflow": random.randint(10, 100), "byteperflow": random.randint(500, 5000), "pktrate": random.randint(0, 50), "Pairflow": 0, "port_no": random.randint(1, 4), "tx_bytes": random.randint(1000, 20000), "rx_bytes": random.randint(1000, 20000), "tx_kbps": random.randint(0, 100), "rx_kbps": random.randint(0, 100), "tot_kbps": random.randint(0, 200), "Protocol_UDP": random.choice([0, 1])}

print("=======================================")
print("🌐 MULTI-MODE ATTACK SIMULATOR 🌐")
print("=======================================")
print("1. Mode Dummy Statis (Cek fitur Blacklist)")
print("2. Mode Dinamis Acak (Cek ketahanan Server menahan spam)")
print("3. Mode Dataset Asli (CEK AKURASI AI - Pakai CSV Asli)")
pilihan = input("Pilih mode (1/2/3): ")

print("\n[+] Transmisi dimulai... (Tekan Ctrl+C untuk menghentikan)")
time.sleep(1)

try:
    if pilihan == '3':
        df = pd.read_csv('data_simulasi.csv')
        records = df.to_dict(orient='records')
        
        for row in records:
            if row['label_asli'] == 1:
                row['src'] = f"10.0.0.{random.randint(2, 255)}" 
            else:
                row['src'] = f"192.168.1.{random.randint(10, 50)}"
            
            client.sendto(json.dumps(row).encode('utf-8'), (IP_SERVER, PORT_SERVER))
            print(f"-> Mengirim paket dari {row['src']} | Label Asli: {'DDoS' if row['label_asli']==1 else 'Normal'}")
            time.sleep(0.1) 
            
    else:
        while True:
            if pilihan == '1':
                data = data_ddos_dummy if random.random() < 0.3 else data_normal_dummy
            elif pilihan == '2':
                data = generate_acak(is_ddos=(random.random() < 0.3))
            else:
                break
                
            client.sendto(json.dumps(data).encode('utf-8'), (IP_SERVER, PORT_SERVER))
            print(f"-> Mengirim paket dari {data['src']}")
            time.sleep(0.5)

except KeyboardInterrupt:
    print("\n[-] Serangan dihentikan.")