# Axon Network Analyzer

A Windows desktop application for passive network traffic analysis.

## Version 1.0
- PySide6 desktop interface with dark charcoal and lime accents.
- Network interface selection and passive live capture through Scapy/Npcap.
- TCP, UDP, DNS, ICMP, ARP and Ethernet protocol identification.
- Packet metadata list, decoded summary pane and quick display filtering.
- Open PCAP/PCAPNG files and save captured packets as PCAP.
- In-memory packet list capped at 10,000 entries.

## Requirements
- Windows 10/11
- Python 3.10+
- Npcap for live packet capture: https://npcap.com/

## Setup
Open PowerShell in this repository folder and run:
    Set-ExecutionPolicy -Scope Process Bypass
    .\setup.ps1

Install Npcap separately. Live capture may require running PowerShell as Administrator. Only monitor networks and interfaces you own or are authorized to inspect.

## Run
    .\run.ps1

Opening existing PCAP files does not require live capture permissions. Capture filters use BPF syntax, such as tcp, udp, or port 53. Axon does not inject, modify, or transmit packets.

## Files
- app.py: application entry point
- axon_analyzer/capture.py: passive capture worker
- axon_analyzer/main_window.py: desktop interface and packet analysis
- requirements.txt: Python dependencies
- setup.ps1 and run.ps1: Windows setup and launch scripts
