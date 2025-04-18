# Packet Sniffer GUI

A simple network packet sniffer and analyzer built with Python and Tkinter, with optional Scapy integration for advanced features. Capture live network traffic, filter by protocol or custom BPF filters, inspect packet details, save/load PCAP files, and view statistics—all within an easy-to-use GUI.

---

## 🔍 Features

- **Live Packet Capture**: Start/stop capture on any available network interface.
- **Protocol Identification**: Automatically detects Ethernet, ARP, IP, TCP, UDP, ICMP, HTTP, HTTPS, DNS.
- **Filtering**:
  - Text-based filter (source, destination, protocol, info).
  - Protocol selector (TCP, UDP, ICMP, ARP, HTTP, DNS, or All).
- **Packet List**: Treeview table showing packet number, timestamp, source, destination, protocol, length, and brief info.
- **Packet Details**: Dive into raw packet data, hexdump, ASCII, or Scapy layer summary.
- **Save/Load PCAP**: With Scapy installed, save captures to `.pcap` files or load existing PCAPs.
- **Dark/Light Mode**: Toggle UI theme via menu.
- **About Dialog**: Displays version, dependencies, and usage notes.

---

## 🛠️ Requirements

- Python 3.8+
- Tkinter (usually bundled with Python)
- Optional (for full functionality):
  - **Scapy**: `pip install scapy`

---

## 🚀 Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/TheGh0stHicham/packet-sniffer-gui.git
   cd packet-sniffer-gui
   ```

2. **Create a virtual environment (recommended)**

   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/macOS
   venv\Scripts\activate    # Windows
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   # If requirements.txt is not provided, install Scapy manually:
   pip install scapy
   ```

---

## ▶️ Usage

> **Note:** Capturing packets typically requires elevated privileges.

1. **Run the application**

   ```bash
   python packet-sniffer.py
   ```

2. **Select an interface** from the dropdown (e.g., `eth0`, `Wi-Fi`).
3. Click **Start Capture** to begin sniffing traffic.
4. Use **Filter** and **Protocol** dropdown to narrow results.
5. Click on a row in the **Captured Packets** list to view detailed information below.
6. **Save Capture** (`File > Save Capture`) to export to a PCAP file (requires Scapy).
7. **Load Capture** (`File > Load Capture`) to replay a saved PCAP.
8. Toggle **Dark Mode** under `View` menu for low-light environments.

---

## 📷 Screenshots

<div align="center">
  <img src="https://i.ibb.co/VppffrwJ/first.png" alt="Main Window" width="600" />
  <p>Main Window with live capture</p>
</div>

---

## 📝 File Structure

```
packet-sniffer-gui/
├── packet-sniffer.py   # Main application script
├── requirements.txt    # Python dependencies
├── README.md           # Project documentation
└── screenshots/        # Example UI screenshots
    ├── home.png
    └── details.png
```

---

## ⚠️ Permissions

- **Linux/macOS**: Run with `sudo` if necessary to capture raw packets.
- **Windows**: Run as Administrator or enable "Promiscuous Mode" on the network adapter.

---

## 📖 License

This project is licensed under the https://ezzamzami.com.

