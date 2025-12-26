import subprocess
import json
import sys
import requests
import psutil
import socket
import time
from sklearn.ensemble import IsolationForest

# --- AYARLAR ---
OLLAMA_MODEL = "llama3"   # Kullandığın model (llama3, mistral, gemma vs.)
TRAINING_PACKET_COUNT = 300  # Normali öğrenmek için kaç paket izlesin? (Demo için 300, Gerçek için 2000+)
ANOMALY_CONTAMINATION = 0.05 # Anomali hassasiyeti (%5 sapma)

# --- RENKLER ---
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def get_active_interface():
    """Kullanıcıya aktif ağ kartlarını listeler ve seçtirir."""
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    available = []
    
    print(f"\n{CYAN}--- AĞ ARAYÜZÜ SEÇİMİ ---{RESET}")
    idx = 1
    for int_name, addresses in addrs.items():
        is_up = stats[int_name].isup if int_name in stats else False
        if is_up:
            for addr in addresses:
                if addr.family == socket.AF_INET: # Sadece IPv4 olanlar
                    print(f"[{idx}] {int_name} \t(IP: {addr.address})")
                    available.append(int_name)
                    idx += 1
                    break
    
    if not available:
        print(f"{RED}Hata: Aktif ağ kartı bulunamadı!{RESET}")
        sys.exit()

    while True:
        try:
            sel = int(input(f"\n{YELLOW}Dinlenecek numara (Örn: 1): {RESET}"))
            if 1 <= sel <= len(available):
                return available[sel-1]
        except ValueError:
            pass

def decode_tcp_flags(hex_val):
    """Hex bayrakları (0x0012) okunabilir metne çevirir (SYN+ACK)"""
    try:
        val = int(hex_val, 16)
        flags = []
        if val & 0x02: flags.append("SYN")
        if val & 0x10: flags.append("ACK")
        if val & 0x01: flags.append("FIN")
        if val & 0x04: flags.append("RST")
        if val & 0x08: flags.append("PSH")
        if val & 0x20: flags.append("URG")
        return "+".join(flags) if flags else "OTHER"
    except:
        return "N/A"

def ask_ollama(context_data):
    """Anomali verisini Ollama'ya gönderir ve yorum ister."""
    prompt = f"""
    Sen kıdemli bir Siber Güvenlik Analistisin. Aşağıdaki ağ trafiği anomali tespit sistemim tarafından yakalandı.
    Lütfen teknik verileri incele ve bana Türkçe olarak kısa bir rapor ver.
    
    ANOMALİ DETAYLARI:
    {context_data}
    
    GÖREVİN:
    1. Bu trafik ne olabilir? (Port taraması, DDoS, Veri Sızdırma, Normal Video Akışı vb.)
    2. Tehlikeli mi?
    3. Ne önerirsin? (Sadece 1 cümle öneri)
    
    Cevabı kısa ve profesyonel tut.
    """
    
    try:
        response = requests.post('http://localhost:11434/api/generate', json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        })
        return response.json()['response']
    except Exception as e:
        return f"LLM Bağlantı Hatası: {e}"

def start_sniffer():
    interface = get_active_interface()
    print(f"\n{GREEN}>>> {interface} üzerinde dinleme başlatılıyor...{RESET}")
    print(f"{CYAN}>>> Tshark arka planda çalıştırılıyor...{RESET}")

    # Tshark Komutu: JSON çıktısı (-T ek) ver, sadece belirli alanları al
    cmd = [
        'tshark', '-i', interface, 
        '-T', 'ek', 
        '-e', 'ip.src', '-e', 'ip.dst', 
        '-e', 'frame.len', 
        '-e', 'tcp.dstport', '-e', 'udp.dstport', 
        '-e', 'tcp.flags'
    ]

    # Subprocess ile Tshark'ı başlat
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # ML Modeli Hazırlığı
    model = IsolationForest(contamination=ANOMALY_CONTAMINATION, random_state=42)
    training_data = []
    is_trained = False
    
    print(f"\n{YELLOW}[MOD: EĞİTİM]{RESET} İlk {TRAINING_PACKET_COUNT} paket ile normal ağ davranışı öğreniliyor...")

    try:
        for line in process.stdout:
            try:
                packet = json.loads(line.strip())
                
                # Sadece veri içeren katmanları al
                if 'layers' not in packet: continue
                layers = packet['layers']
                
                # Verileri Çek
                src = layers.get('ip_src', ['Unk'])[0]
                dst = layers.get('ip_dst', ['Unk'])[0]
                length = int(layers.get('frame_len', [0])[0])
                
                # Port ve Flag Belirleme
                port = 0
                flags_hex = "0x00"
                
                if 'tcp_dstport' in layers: 
                    port = int(layers['tcp_dstport'][0])
                    flags_hex = layers.get('tcp_flags', ['0x00'])[0]
                elif 'udp_dstport' in layers: 
                    port = int(layers['udp_dstport'][0])
                
                # ML için özellik vektörü: [Paket Boyutu, Port]
                features = [length, port]
                
                # --- AŞAMA 1: EĞİTİM ---
                if not is_trained:
                    training_data.append(features)
                    sys.stdout.write(f"\rEğitilen: {len(training_data)}/{TRAINING_PACKET_COUNT}")
                    sys.stdout.flush()
                    
                    if len(training_data) >= TRAINING_PACKET_COUNT:
                        print(f"\n\n{GREEN}>>> Model Eğitiliyor... Lütfen bekleyin.{RESET}")
                        model.fit(training_data)
                        is_trained = True
                        training_data = [] # Hafızayı boşalt
                        print(f"{GREEN}>>> SİSTEM AKTİF! CANLI KORUMA BAŞLADI.{RESET}\n")
                    continue

                # --- AŞAMA 2: KORUMA ---
                pred = model.predict([features])[0]
                
                if pred == -1: # Anomali
                    readable_flags = decode_tcp_flags(flags_hex)
                    
                    # Sadece ilginç portları veya dışarı giden trafiği raporla (Gürültüyü azaltmak için)
                    # Örnek: Yerel ağ içi yayınları (Broadcast) görmezden gelebilirsin.
                    
                    print(f"\n{RED}🚨 ANOMALİ TESPİT EDİLDİ!{RESET}")
                    print(f"Paket: {src} -> {dst} | Port: {port} | Boyut: {length} | Flag: {readable_flags}")
                    
                    # LLM Analizi Çağır
                    print(f"{YELLOW}🤖 AI Analiz Ediyor...{RESET}")
                    
                    context = f"""
                    - Kaynak IP: {src}
                    - Hedef IP: {dst}
                    - Hedef Port: {port}
                    - Paket Boyutu: {length} Bytes
                    - TCP Bayrakları: {readable_flags}
                    """
                    
                    explanation = ask_ollama(context)
                    print(f"{CYAN}--- RAPOR ---{RESET}")
                    print(explanation)
                    print(f"{CYAN}-------------{RESET}\n")

            except json.JSONDecodeError:
                continue
            except KeyError:
                continue
                
    except KeyboardInterrupt:
        print(f"\n{RED}Sistem kapatılıyor...{RESET}")
        process.terminate()

if __name__ == "__main__":
    start_sniffer()
