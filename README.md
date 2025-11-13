# 🔍 Packet Sniffer & Analyzer v1.1

Ein fortschrittlicher Python-basierter Packet Sniffer für Netzwerkanalyse und Security Testing. Das Tool ermöglicht die Echtzeit-Analyse von Netzwerkpaketen mit Deep Packet Inspection, Protokoll-Dekodierung und automatischer Credential-Extraktion.

## ✨ Features

### Protokoll-Unterstützung
- **Ethernet**: Layer-2 Frame-Analyse mit MAC-Adressen
- **IPv4**: IP-Header-Parsing mit TTL, Protocol, Source/Destination
- **TCP**: Vollständige TCP-Header-Analyse mit Flags (SYN, ACK, FIN, etc.)
- **UDP**: UDP-Header mit Port und Length Information
- **ICMP**: ICMP-Typen (Echo Request/Reply, Destination Unreachable, etc.)
- **ARP**: ARP Request/Reply Erkennung mit MAC/IP Mapping

### Application Layer Detection
- **HTTP**: Request/Response Parsing (GET, POST, Headers)
- **FTP**: Command/Response Tracking
- **Telnet**: Session Detection
- **SMTP**: Email Protocol Analysis
- **DNS**: DNS Query/Response Detection

### Security Features
- **Credential Extraction**: Automatische Erkennung von Credentials
  - HTTP Basic Authentication (Base64-Dekodierung)
  - FTP Login (USER/PASS Commands)
  - SMTP Authentication
  - Generic Password Pattern Matching (JSON, Form Data)
- **Traffic Statistics**: Detaillierte Protokoll-Verteilung
- **Real-time Alerts**: Sofortige Benachrichtigung bei gefundenen Credentials

### Filtering & Analysis
- **Protocol Filter**: Nur bestimmte Protokolle anzeigen (TCP/UDP/ICMP/ARP)
- **Port Filter**: Traffic nach Port-Nummer filtern
- **IP Filter**: Nur Pakete von/zu bestimmten IPs
- **Verbose Mode**: Detaillierte Packet-Ausgabe mit allen Headers
- **JSON Export**: Speichert Ergebnisse in strukturiertem Format

## 📋 Voraussetzungen

- **Linux** (AF_PACKET Socket Support erforderlich)
- **Python 3.6+**
- **Root-Rechte** (für Raw Socket Access)

## 🚀 Installation

```bash
# Repository klonen
git clone https://github.com/YourUsername/PacketSniffer.git
cd PacketSniffer

# Keine zusätzlichen Dependencies erforderlich (nur Python Standard Library)

# Ausführbar machen
chmod +x packet_sniffer.py
```

## 💻 Usage

### Basis-Verwendung

```bash
# Standard-Modus (alle Pakete, keine Details)
sudo python3 packet_sniffer.py

# Verbose-Modus (zeigt Packet-Details in schönen Boxen!)
sudo python3 packet_sniffer.py -v

# Mit Hex-Dump für Deep Analysis
sudo python3 packet_sniffer.py -v --show-hex
```

### Praktische Beispiele

```bash
# 1. HTTP-Traffic überwachen und Credentials finden
sudo python3 packet_sniffer.py --protocol tcp --port 80 -v

# 2. FTP-Traffic analysieren (Port 21)
sudo python3 packet_sniffer.py --protocol tcp --port 21 -v

# 3. Alle Pakete eines Hosts überwachen
sudo python3 packet_sniffer.py --ip 192.168.1.50 -v

# 4. ICMP-Diagnose (Ping-Monitoring)
sudo python3 packet_sniffer.py --protocol icmp -v

# 5. ARP-Spoofing Detection
sudo python3 packet_sniffer.py --protocol arp -v
```

## 📊 Output-Beispiele

### Verbose TCP-Output (NEU v1.1!)
```
┌────────────────────────────────────────────────────────────────────┐
│ TCP PACKET                                                         │
├────────────────────────────────────────────────────────────────────┤
│ 🔹 [Ethernet] -> [IPv4] -> [TCP] -> [HTTP]                        │
│                                                                    │
│ Source:      192.168.1.100:54321                                  │
│ Destination: 93.184.216.34:80                                     │
│ Sequence:    1234567890                                           │
│ Acknowledge: 0                                                    │
│ Flags:       SYN                                                  │
│ Window:      65535 bytes                                          │
│ Payload:     0 bytes                                              │
└────────────────────────────────────────────────────────────────────┘

[HTTP Request] GET /index.html HTTP/1.1
  Host: example.com
  User-Agent: Mozilla/5.0
```

### Statistik-Output
```
======================================================================
CAPTURE STATISTICS
======================================================================
Total Packets Captured: 1523

Protocol Distribution:
  TCP            :    892 (58.57%)
  UDP            :    421 (27.65%)
  ICMP           :    156 (10.24%)
  ARP            :     54 ( 3.54%)
  HTTP           :    234 (15.36%)
  DNS            :    198 (13.00%)
======================================================================
```

## 🔧 Technische Details

### Architektur

```
┌─────────────────────────────────────────────┐
│          Raw Socket (AF_PACKET)             │
└─────────────────┬───────────────────────────┘
                  │
         ┌────────▼────────┐
         │  Ethernet Frame │
         │  (Layer 2)      │
         └────────┬────────┘
                  │
         ┌────────▼────────┐
         │   IPv4 Header   │
         │   (Layer 3)     │
         └────────┬────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
┌───▼───┐    ┌───▼───┐    ┌───▼───┐
│  TCP  │    │  UDP  │    │ ICMP  │
│(L4)   │    │(L4)   │    │(L3)   │
└───┬───┘    └───┬───┘    └───────┘
    │            │
┌───▼────────────▼───┐
│  HTTP, FTP, SMTP   │
│  (Application L7)  │
└────────────────────┘
```

### Packet-Struken

#### Ethernet Frame (14 Bytes)
```
0                   6                  12        14
+-------------------+------------------+---------+
| Dest MAC (6 byte) | Src MAC (6 byte) | Type(2) |
+-------------------+------------------+---------+
```

### Unterstützte TCP Flags
- **SYN**: Synchronize - Verbindungsaufbau
- **ACK**: Acknowledge - Bestätigung
- **FIN**: Finish - Verbindungsabbau
- **RST**: Reset - Verbindung zurücksetzen
- **PSH**: Push - Daten sofort weiterleiten
- **URG**: Urgent - Dringlichkeits-Pointer

### ICMP Types
| Type | Beschreibung |
|------|--------------|
| 0    | Echo Reply (Ping Response) |
| 3    | Destination Unreachable |
| 4    | Source Quench |
| 5    | Redirect Message |
| 8    | Echo Request (Ping) |
| 11   | Time Exceeded (TTL) |

## 📄 Lizenz

MIT License - Siehe LICENSE Datei für Details

## ⚖️ Disclaimer

Dieses Tool ist für **Bildungs- und Testzwecke** gedacht. Die Entwickler übernehmen keine Haftung für missbräuchliche Verwendung. Nutze dieses Tool nur in Netzwerken, für die du eine ausdrückliche Genehmigung hast.

**Das unerlaubte Abfangen von Netzwerkverkehr ist illegal!**

## 👨‍💻 Author

**Thomas** - [GitHub Profile](https://github.com/ThomasUgh)
