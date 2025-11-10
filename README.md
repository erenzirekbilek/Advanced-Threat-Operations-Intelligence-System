# 🛡️ Enterprise Log Analysis and Threat Detection System

![Version](https://img.shields.io/badge/version-2.0-blue)
![Python](https://img.shields.io/badge/python-3.6+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Status](https://img.shields.io/badge/status-production--ready-success)

Advanced-Threat-Operations-Intelligence-System (ATOIS), kurumsal seviyede siber tehdit tespiti, log analizi ve security intelligence sağlamak için geliştirilmiş modüler bir Python platformudur. Sistem, gerçek zamanlı ve geçmişe dönük verileri analiz ederek, şüpheli aktiviteleri otomatik olarak tespit eder ve raporlar.

## 📋 İçindekiler

- [Özellikler](#-özellikler)
- [Kurulum](#-kurulum)
- [Hızlı Başlangıç](#-hızlı-başlangıç)
- [Desteklenen Log Formatları](#-desteklenen-log-formatları)
- [Tehdit Tespit Yetenekleri](#-tehdit-tespit-yetenekleri)
- [Konfigürasyon](#️-konfigürasyon)
- [Kullanım Örnekleri](#-kullanım-örnekleri)
- [Çıktı Formatları](#-çıktı-formatları)
- [Veritabanı Şeması](#-veritabanı-şeması)
- [Performans](#-performans)
- [API Referansı](#-api-referansı)
- [Örnek Senaryolar](#-örnek-senaryolar)
- [Sorun Giderme](#-sorun-giderme)
- [Katkıda Bulunma](#-katkıda-bulunma)
- [Lisans](#-lisans)

---

## ✨ Özellikler

### 🔐 Güvenlik

- Brute-force saldırıları, SQL Injection, XSS, DDoS, Credential Stuffing gibi farklı saldırı türlerini tespit eder.
- Blacklist ve Reputation-based IP kontrolü ile şüpheli kaynakları filtreler.
- **IP İtibar Sistemi**: Dinamik IP reputation scoring (0-100)
- **Otomatik Engelleme**: Threshold-based IP blocking
- **Multi-vector Attack Detection**: Koordineli saldırı tespiti
- **Confidence Scoring**: 0-100% güvenilirlik skorları

### 📊 Analiz

- **İstatistiksel Anomali Tespiti**: Z-score ve IQR yöntemleri
- **Time-Series Analysis**: Zaman serisi pattern recognition
- **Correlation Detection**: Olaylar arası korelasyon analizi
- **Performance Metrics**: Response time, error rate, throughput tracking
- **Traffic Pattern Analysis**: Saatlik/günlük trafik analizi

### 💾 Veri Yönetimi

- **SQLite Database**: Kalıcı veri depolama
- **Historical Tracking**: Tarihsel veri sorguları
- **Efficient Indexing**: Hızlı veritabanı sorguları
- **Data Export**: JSON, CSV, HTML formatlarında export

curl http://localhost:5000/api/threats
curl http://localhost:5000/api/metrics
```

### 🚀 Performans

- **10,000+ logs/second** işleme kapasitesi
- **Memory Efficient**: Batch processing ile düşük bellek kullanımı
- **Streaming Support**: GB seviyesi dosyalar için
- **Gzip Support**: Sıkıştırılmış log dosyaları
- **Concurrent Processing**: Thread-safe operations

### 📈 Raporlama

- **Console Report**: Real-time görsel raporlar
- **JSON Export**: API entegrasyonu için
- **CSV Export**: Excel ve data analysis tools için
- **HTML Dashboard**: İnteraktif web dashboard
- **Automated Recommendations**: Aksiyon önerileri

---

## 📦 Kurulum

### Gereksinimler

```bash
Python 3.6 veya üzeri
