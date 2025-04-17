# 🌐 Network Packet Sniffer (Client-Server Based)

Python_Packet_Sniffer is a sleek and functional tool that captures and analyzes network packets using raw sockets, supporting protocols like IP, TCP, and UDP. Built with Python’s socket, tkinter, and threading, it features a real-time GUI for monitoring and exporting data in JSON/CSV. With client-server architecture, it mimics tools like Wireshark in a simpler, educational form.
---

## 🚀 Features

- Real-time packet capturing with client-server architecture
- Detailed packet info: MAC, IP, Protocol, Size, Payload, Timestamp
- Stylish and intuitive GUI using `tkinter`
- Export data as **JSON** or **CSV**
- Protocol-based filtering (TCP, UDP, ICMP, etc.)
- Start, Stop, and Clear Packet Capture with ease

---

## 🛠 How to Run

### 1. Start the Server
python sniffer_server.py

2. Run the Client GUI
python sniffer_client.py

Note: Use sudo for the server if running on Linux to allow raw socket access:
sudo python sniffer_server.py

💻 Tech Stack
Python 3.x
socket, struct, threading, json
tkinter for GUI
csv and filedialog for exporting data

📂 Export Options
JSON: Structured, formatted packet data for APIs or advanced processing.
CSV: Spreadsheet-compatible format for quick inspection and analysis.
