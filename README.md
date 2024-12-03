## Python Packet Sniffer & Analyzer
Eric AhSue

### About
This Python script captures network packets using the Scapy library, extracts Ethernet frame information, and displays them. You can optionally save the captured packets to a PCAP file to anaylze with Wireshark (if needed). This project is for my CSC645 Computer Networks class.

### Requirements
- Python 3.x
- Scapy library

### Usage
```
python3 sniffer.py <iface> [fname]
```
1. <iface>: the network interface to capture packets from (required)
2. <fname>: the file to save the captured packets to in PCAP format

Example Usage:
```
python3 sniffer.py eth0 capture
```

### Output
Details:
- Source Mac Address
- Destination Mac Address
- If applicable:
  - IP Version
  - Source IP Address
  - Destination IP Address
- MAC header (14 bytes)
- Payload data (28 bytes)