Hibrit AI Tabanlı Saldırı Tespit Sistemi

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![ML](https://img.shields.io/badge/Machine%20Learning-Isolation%20Forest-orange)
![LLM](https://img.shields.io/badge/GenAI-Llama3%20%2F%20GPT-purple)
![Security](https://img.shields.io/badge/Security-Network%20Forensics-red)

> **Matematiksel anomali tespitini (ML), anlamsal tehdit istihbaratıyla (LLM) birleştiren yeni nesil IDS.**

## 📖 Proje Mantığı: "Doktor ve Termometre"

Geleneksel IDS (Saldırı Tespit Sistemleri) genellikle kural tabanlıdır. Bu proje ise iki farklı yapay zeka disiplinini birleştirerek gerçek dünyadaki tehditleri analiz eder.

### 1. Katman: Termometre (Isolation Forest) 🌡️
* **Görevi:** Ağ trafiğindeki matematiksel sapmaları bulmaktır.
* **Nasıl Çalışır:** "Bu paket diğerlerine benzemiyor" der. Örneğin, normalden çok daha kısa sürede, çok fazla paket geldiyse bunu **Anomali (-1)** olarak işaretler.
* **Sınırı:** Bir şeylerin ters gittiğini bilir ama **ne olduğunu bilmez.** (Grip mi? Enfeksiyon mu?)

### 2. Katman: Doktor (LLM - Llama 3 / GPT) 👨‍⚕️
* **Görevi:** Termometrenin bulduğu hastaya teşhis koymaktır.
* **Nasıl Çalışır:** ML modelinden gelen teknik semptomları (TCP Bayrakları, Portlar, Paket Boyutları) alır. Eğitim verisindeki (siber güvenlik makaleleri, CVE veritabanları) bilgileri kullanarak yorumlar.
* **Sonuç:** "Bu sadece bir sapma değil, bu bir **SYN Flood DDoS Saldırısıdır**" der.

---

## 🚀 Özellikler

Bu sistem, LLM'in doğru yorum yapabilmesi için ağ trafiğinden **3 Kritik Semptomu** çıkarır:

* **🚩 TCP Bayrak Analizi:** Sadece `SYN` mi var? `RST` ile mi dönülüyor? (Tarama ve Flood saldırılarını ayırt etmek için kritik).
* **d04;️ Port Hedeflemesi:** Trafik 22 (SSH), 445 (SMB) veya 80 (HTTP) portuna mı gidiyor?
* **📊 Veri Hacmi:** Veri boyutu ve sıklığı, saldırının şiddetini belirler.

### Tespit Edebildiği Örnek Senaryolar
* **Nmap Stealth Scan:** (Semptom: Çok sayıda farklı porta giden tekil SYN paketleri).
* **DDoS / SYN Flood:** (Semptom: Yüksek frekans, ACK bayrağı eksik).
* **Data Exfiltration:** (Semptom: Beklenmedik saatte, bilinmeyen bir IP'ye büyük boyutlu paket gönderimi).
* **Brute Force:** (Semptom: Aynı porta sürekli tekrarlayan küçük paketler).

---

## 🛠️ Kurulum

### Gereksinimler
* Python 3.8+
* **Wireshark / Tshark** (Ağ trafiğini dinlemek için)
* Yerel LLM (Ollama) veya OpenAI API Key

### 1. Repoyu Klonlayın
