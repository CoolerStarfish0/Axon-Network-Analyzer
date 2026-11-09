"""Axon Network Analyzer main window."""
import os
import ipaddress
import re
import subprocess
from datetime import datetime
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QLineEdit, QTableWidget, QTableWidgetItem, QApplication,
    QTextEdit, QFileDialog, QMessageBox, QSplitter, QStatusBar, QHeaderView, QTabWidget, QGroupBox)
from scapy.all import conf, rdpcap, wrpcap, get_if_addr
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
from .capture import CaptureWorker

STYLE = """
QWidget { background:#111512; color:#e6eee8; font-family:'Segoe UI'; font-size:10pt; }
QMainWindow { background:#0c100d; }
QLabel#brand { color:#a5f36b; font-size:23pt; font-weight:700; }
QLabel#muted { color:#91a095; }
QPushButton { background:#202a22; border:1px solid #344438; border-radius:7px; padding:8px 13px; }
QPushButton:hover { border-color:#a5f36b; }
QPushButton#primary { background:#a5f36b; color:#10170e; font-weight:700; }
QComboBox,QLineEdit { background:#171e19; border:1px solid #344438; border-radius:6px; padding:8px; }
QTableWidget,QTextEdit { background:#141a16; border:1px solid #29352c; gridline-color:#263229; selection-background-color:#35552c; }
QHeaderView::section { background:#202a22; color:#a5f36b; border:0; padding:8px; }
QStatusBar { color:#a5f36b; }
"""

def packet_info(packet):
    stamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    src = dst = sport = dport = "—"
    proto = "OTHER"
    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        src, dst = packet[IPv6].src, packet[IPv6].dst
    if TCP in packet:
        proto, sport, dport = "TCP", str(packet[TCP].sport), str(packet[TCP].dport)
    elif UDP in packet:
        proto, sport, dport = "UDP", str(packet[UDP].sport), str(packet[UDP].dport)
    elif ICMP in packet:
        proto = "ICMP"
    elif packet.haslayer("ARP"):
        proto = "ARP"
    elif packet.haslayer("Ether"):
        proto = "ETHERNET"
    if DNS in packet:
        proto = "DNS"
    friendly = {"TCP": "Reliable (TCP)", "UDP": "Fast (UDP)", "DNS": "Website lookup", "ICMP": "Network message", "ARP": "Device discovery", "ETHERNET": "Local network"}
    return [stamp, src, dst, friendly.get(proto, proto), sport, dport, str(len(packet))]

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Axon Network Analyzer")
        self.resize(1180, 760)
        self.worker = None
        self.packets = []
        self.visible_packets = []
        self.website_events = []
        self.ip_search_text = ""
        self.advanced_mode = False
        self.wifi_networks = []
        self.build_ui()
        self.load_interfaces()

    def build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(22, 18, 22, 16)
        head = QHBoxLayout()
        brand_col = QVBoxLayout()
        brand = QLabel("AXON")
        brand.setObjectName("brand")
        sub = QLabel("A FRIENDLIER WAY TO UNDERSTAND YOUR NETWORK")
        sub.setObjectName("muted")
        brand_col.addWidget(brand)
        brand_col.addWidget(sub)
        head.addLayout(brand_col)
        head.addStretch()
        self.live_label = QLabel("● READY")
        self.live_label.setStyleSheet("color:#a5f36b;font-weight:700")
        head.addWidget(self.live_label)
        layout.addLayout(head)

        controls = QHBoxLayout()
        self.interface_box = QComboBox()
        self.interface_box.setMinimumWidth(230)
        self.interface_box.setToolTip("Choose the internet connection you want Axon to monitor.")
        controls.addWidget(QLabel("Your connection"))
        controls.addWidget(self.interface_box, 2)
        self.start_btn = QPushButton("Start monitoring")
        self.start_btn.setObjectName("primary")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        refresh_btn = QPushButton("Refresh connections")
        self.advanced_toggle = QPushButton("Advanced settings  ▾")
        self.advanced_toggle.setCheckable(True)
        controls.addWidget(self.start_btn)
        controls.addWidget(self.stop_btn)
        controls.addWidget(refresh_btn)
        controls.addWidget(self.advanced_toggle)
        layout.addLayout(controls)
        self.capture_filter = QLineEdit()
        self.capture_filter.setPlaceholderText("Traffic filter (BPF), e.g. tcp, udp, or port 53")
        self.capture_filter.setToolTip("BPF is an advanced language for filtering network traffic.")
        self.advanced_panel = QGroupBox("Advanced network settings")
        advanced_layout = QVBoxLayout(self.advanced_panel)
        advanced_layout.addWidget(QLabel("Optional traffic filter"))
        advanced_layout.addWidget(self.capture_filter)
        note = QLabel("TCP = reliable connection  •  UDP = lightweight data transfer  •  Port 53 = commonly used for website lookups (DNS).")
        note.setWordWrap(True)
        advanced_layout.addWidget(note)
        self.advanced_panel.hide()
        layout.addWidget(self.advanced_panel)
        self.advanced_toggle.toggled.connect(self.toggle_advanced)

        actions = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter visible packets by IP, protocol or port…")
        self.count = QLabel("0 packets")
        open_btn, save_btn, clear_btn = QPushButton("Open saved recording"), QPushButton("Save recording"), QPushButton("Clear list")
        actions.addWidget(self.search, 1)
        actions.addWidget(self.count)
        actions.addWidget(open_btn)
        actions.addWidget(save_btn)
        actions.addWidget(clear_btn)
        layout.addLayout(actions)

        split = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["TIME", "FROM", "TO", "CONNECTION TYPE", "FROM PORT", "TO PORT", "DATA (BYTES)"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a row to see what your computer is communicating with.")
        split.addWidget(self.table)
        split.addWidget(self.details)
        split.setSizes([510, 170])
        tabs = QTabWidget()
        packet_tab = QWidget()
        packet_layout = QVBoxLayout(packet_tab)
        packet_layout.setContentsMargins(0, 8, 0, 0)
        packet_layout.addWidget(split)
        tabs.addTab(packet_tab, "Network Activity")

        ip_tab = QWidget()
        ip_layout = QVBoxLayout(ip_tab)
        ip_intro = QLabel(
            "Find IP addresses Axon can legitimately see on this computer's selected connection. "
            "This includes your computer's local address and addresses observed in captured traffic. "
            "It is not a list of every device on your Wi-Fi."
        )
        ip_intro.setWordWrap(True)
        ip_intro.setObjectName("muted")
        ip_layout.addWidget(ip_intro)
        self.local_ip_label = QLabel("Your computer's local IP: Select a connection")
        self.local_ip_label.setStyleSheet("font-size:14pt;font-weight:700;color:#d6ad55;padding:8px;")
        ip_layout.addWidget(self.local_ip_label)
        ip_tools = QHBoxLayout()
        self.ip_search = QLineEdit()
        self.ip_search.setPlaceholderText("Search observed IP addresses…")
        self.copy_ip_btn = QPushButton("Copy selected IP")
        self.refresh_ip_btn = QPushButton("Refresh IP list")
        ip_tools.addWidget(self.ip_search, 1)
        ip_tools.addWidget(self.copy_ip_btn)
        ip_tools.addWidget(self.refresh_ip_btn)
        ip_layout.addLayout(ip_tools)
        self.ip_table = QTableWidget(0, 4)
        self.ip_table.setHorizontalHeaderLabels(["IP ADDRESS", "TRAFFIC SEEN", "LAST OBSERVED", "TYPE"])
        self.ip_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.ip_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ip_table.setSelectionMode(QTableWidget.SingleSelection)
        self.ip_table.verticalHeader().setVisible(False)
        self.ip_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        ip_layout.addWidget(self.ip_table, 1)
        tabs.addTab(ip_tab, "IP Finder")

        wifi_tab = QWidget()
        wifi_layout = QVBoxLayout(wifi_tab)
        wifi_intro = QLabel(
            "Scan nearby Wi-Fi broadcasts and compare network names, router radio IDs (BSSIDs), "
            "signal, channel and security. A nearby scan cannot reveal a router's IP. Axon only "
            "shows IP details for the Wi-Fi network this computer is currently connected to."
        )
        wifi_intro.setWordWrap(True)
        wifi_intro.setObjectName("muted")
        wifi_layout.addWidget(wifi_intro)
        wifi_controls = QHBoxLayout()
        self.wifi_search = QLineEdit()
        self.wifi_search.setPlaceholderText("Filter by Wi-Fi name or BSSID…")
        self.wifi_scan_btn = QPushButton("Scan nearby Wi-Fi")
        self.wifi_scan_btn.setObjectName("primary")
        wifi_controls.addWidget(self.wifi_search, 1)
        wifi_controls.addWidget(self.wifi_scan_btn)
        wifi_layout.addLayout(wifi_controls)
        self.wifi_connection_label = QLabel("Connected Wi-Fi IP details: not checked yet")
        self.wifi_connection_label.setWordWrap(True)
        self.wifi_connection_label.setStyleSheet("font-size:12pt;font-weight:700;color:#d6ad55;padding:8px;")
        wifi_layout.addWidget(self.wifi_connection_label)
        self.wifi_table = QTableWidget(0, 6)
        self.wifi_table.setHorizontalHeaderLabels(["WI-FI NAME", "ROUTER RADIO ID (BSSID)", "SIGNAL", "CHANNEL", "SECURITY", "IP INFORMATION"])
        self.wifi_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.wifi_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.wifi_table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.wifi_table.verticalHeader().setVisible(False)
        self.wifi_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        wifi_layout.addWidget(self.wifi_table, 1)
        tabs.addTab(wifi_tab, "Wi-Fi Radar")

        website_tab = QWidget()
        website_layout = QVBoxLayout(website_tab)
        notice = QLabel(
            "Website Activity shows DNS hostnames observed in packets visible to this computer. "
            "It does not show page contents or full URLs. On most Wi-Fi networks, a normal laptop "
            "cannot see other devices' unicast traffic; whole-network coverage requires authorized "
            "router/DNS logs or monitoring configured by the network administrator."
        )
        notice.setWordWrap(True)
        notice.setObjectName("muted")
        website_layout.addWidget(notice)
        self.website_table = QTableWidget(0, 4)
        self.website_table.setHorizontalHeaderLabels(["TIME", "DEVICE IP", "WEBSITE HOSTNAME", "OBSERVATION"])
        self.website_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.website_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.website_table.verticalHeader().setVisible(False)
        self.website_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        website_layout.addWidget(self.website_table)
        tabs.addTab(website_tab, "Website Lookups")
        layout.addWidget(tabs, 1)
        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Ready. Choose Wi-Fi or a wired connection, then select Start monitoring.")
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        refresh_btn.clicked.connect(self.load_interfaces)
        open_btn.clicked.connect(self.open_pcap)
        save_btn.clicked.connect(self.save_pcap)
        clear_btn.clicked.connect(self.clear_packets)
        self.search.textChanged.connect(self.apply_filter)
        self.table.itemSelectionChanged.connect(self.show_details)
        self.ip_search.textChanged.connect(self.refresh_ip_finder)
        self.refresh_ip_btn.clicked.connect(self.refresh_ip_finder)
        self.copy_ip_btn.clicked.connect(self.copy_selected_ip)
        self.interface_box.currentIndexChanged.connect(self.update_local_ip)
        self.wifi_scan_btn.clicked.connect(self.scan_wifi_networks)
        self.wifi_search.textChanged.connect(self.filter_wifi_networks)
        self.wifi_table.itemSelectionChanged.connect(self.show_wifi_selection)

    def scan_wifi_networks(self):
        """Read nearby Wi-Fi broadcasts using Windows' built-in, read-only netsh scan."""
        self.wifi_scan_btn.setEnabled(False)
        self.wifi_scan_btn.setText("Scanning…")
        QApplication.processEvents()
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "Windows could not scan Wi-Fi networks.").strip()
                self.statusBar().showMessage(detail[:220])
                self.wifi_connection_label.setText("Wi-Fi scan unavailable. Check that Wi-Fi is enabled and the Windows WLAN service is running.")
                return
            connected_ssid, connected_bssid = self.get_connected_wifi()
            wifi_ip, gateway = self.get_wifi_ip_details()
            if connected_ssid:
                self.wifi_connection_label.setText(
                    f"Currently connected: {connected_ssid}  •  Your computer's Wi-Fi IP: {wifi_ip or 'Unavailable'}  •  "
                    f"Router / gateway IP: {gateway or 'Unavailable'}"
                )
            else:
                self.wifi_connection_label.setText("Not connected to a Wi-Fi network. Nearby networks do not expose their IP addresses through a broadcast scan.")

            networks = []
            current = None
            for raw_line in result.stdout.splitlines():
                line = raw_line.strip()
                ssid_match = re.match(r"SSID\s+\d+\s*:\s*(.*)$", line, re.I)
                if ssid_match:
                    current = {"ssid": ssid_match.group(1).strip() or "(Hidden network)", "bssid": "—",
                               "signal": "—", "channel": "—", "security": "Unknown"}
                    networks.append(current)
                    continue
                if current is None:
                    continue
                bssid_match = re.match(r"BSSID\s+\d+\s*:\s*(.*)$", line, re.I)
                if bssid_match:
                    if current["bssid"] != "—":
                        current = {"ssid": current["ssid"], "bssid": "—", "signal": "—",
                                   "channel": "—", "security": current["security"]}
                        networks.append(current)
                    current["bssid"] = bssid_match.group(1).strip()
                    continue
                for key, pattern in (
                    ("signal", r"Signal\s*:\s*(.*)$"),
                    ("channel", r"Channel\s*:\s*(.*)$"),
                    ("security", r"Authentication\s*:\s*(.*)$"),
                ):
                    match = re.match(pattern, line, re.I)
                    if match:
                        current[key] = match.group(1).strip()
                if re.match(r"Encryption\s*:", line, re.I):
                    encryption = line.split(":", 1)[-1].strip()
                    current["security"] = current["security"] + " / " + encryption

            self.wifi_networks = networks
            self.filter_wifi_networks()
            self.statusBar().showMessage(f"Found {len(networks)} nearby Wi-Fi radio entries. IP details are only available for the connected network.")
        except FileNotFoundError:
            self.wifi_connection_label.setText("Wi-Fi scanning is supported on Windows using the built-in netsh command.")
        except subprocess.TimeoutExpired:
            self.wifi_connection_label.setText("The Wi-Fi scan timed out. Try again.")
        except Exception as exc:
            self.wifi_connection_label.setText(f"Wi-Fi scan failed: {exc}")
        finally:
            self.wifi_scan_btn.setEnabled(True)
            self.wifi_scan_btn.setText("Scan nearby Wi-Fi")

    def get_connected_wifi(self):
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=8
            )
            ssid = ""
            bssid = ""
            for line in result.stdout.splitlines():
                match = re.match(r"\s*SSID\s*:\s*(.*)$", line, re.I)
                if match and not line.strip().lower().startswith("bssid"):
                    ssid = match.group(1).strip()
                match = re.match(r"\s*BSSID\s*:\s*(.*)$", line, re.I)
                if match:
                    bssid = match.group(1).strip()
            return ssid, bssid
        except Exception:
            return "", ""

    def get_wifi_ip_details(self):
        """Read only the currently connected Wi-Fi adapter's IP configuration."""
        try:
            interface_result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"], capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=8
            )
            adapter_name = ""
            for line in interface_result.stdout.splitlines():
                match = re.match(r"\s*Name\s*:\s*(.*)$", line, re.I)
                if match:
                    adapter_name = match.group(1).strip()
                    break
            if not adapter_name:
                return "", ""
            config = subprocess.run(
                ["ipconfig", "/all"], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=8
            ).stdout
            lines = config.splitlines()
            section = []
            collecting = False
            for line in lines:
                if re.search(r"adapter\s+.*" + re.escape(adapter_name) + r"\s*:", line, re.I):
                    collecting = True
                    section = []
                    continue
                if collecting and re.search(r"adapter\s+.*:", line, re.I):
                    break
                if collecting:
                    section.append(line)
            wifi_ip = gateway = ""
            for line in section:
                if re.search(r"IPv4 Address", line, re.I):
                    value = line.split(":", 1)[-1].strip().split("(")[0].strip()
                    try:
                        wifi_ip = str(ipaddress.ip_address(value))
                    except ValueError:
                        pass
                elif re.search(r"Default Gateway", line, re.I):
                    value = line.split(":", 1)[-1].strip()
                    try:
                        gateway = str(ipaddress.ip_address(value))
                    except ValueError:
                        pass
            return wifi_ip, gateway
        except Exception:
            return "", ""

    def filter_wifi_networks(self, *_):
        query = self.wifi_search.text().strip().lower()
        networks = getattr(self, "wifi_networks", [])
        connected_ssid, connected_bssid = self.get_connected_wifi()
        _, gateway = self.get_wifi_ip_details() if connected_ssid else ("", "")
        self.wifi_table.setRowCount(0)
        for network in networks:
            searchable = (network["ssid"] + " " + network["bssid"]).lower()
            if query and query not in searchable:
                continue
            is_connected = bool(connected_ssid and (
                network["ssid"] == connected_ssid or
                (connected_bssid and network["bssid"].lower() == connected_bssid.lower())
            ))
            ip_info = f"Gateway: {gateway or 'Unavailable'}" if is_connected else "Not exposed by nearby scan"
            values = (network["ssid"], network["bssid"], network["signal"],
                      network["channel"], network["security"], ip_info)
            row = self.wifi_table.rowCount()
            self.wifi_table.insertRow(row)
            for col, value in enumerate(values):
                self.wifi_table.setItem(row, col, QTableWidgetItem(value))
        self.wifi_table.resizeRowsToContents()

    def show_wifi_selection(self):
        selected = self.wifi_table.selectionModel().selectedRows()
        if not selected:
            return
        names = []
        for index in selected:
            item = self.wifi_table.item(index.row(), 0)
            if item and item.text() not in names:
                names.append(item.text())
        if names:
            suffix = " (multiple networks selected)" if len(names) > 1 else ""
            self.statusBar().showMessage("Selected: " + ", ".join(names[:5]) + suffix)

    def toggle_advanced(self, enabled):
        self.advanced_mode = enabled
        self.advanced_panel.setVisible(enabled)
        self.advanced_toggle.setText("Advanced settings  ▴" if enabled else "Advanced settings  ▾")

    def friendly_interface_name(self, name, description):
        value = (name + " " + description).lower()
        if any(x in value for x in ("wi-fi", "wifi", "wireless", "802.11")): return "Wi-Fi"
        if "ethernet" in value or "gigabit" in value: return "Wired connection (Ethernet)"
        if "loopback" in value: return "This computer only (not internet)"
        if any(x in value for x in ("virtual", "hyper-v", "vmware", "vethernet")): return "Virtual connection (advanced)"
        return "Other network connection"

    def load_interfaces(self):
        previous = self.interface_box.currentData()
        self.interface_box.clear()
        try:
            choices = []
            for name, iface in conf.ifaces.items():
                desc = getattr(iface, "description", "") or ""
                friendly = self.friendly_interface_name(str(name), str(desc))
                label = friendly if friendly in ("Wi-Fi", "Wired connection (Ethernet)", "This computer only (not internet)") else f"{friendly} ({desc or name})"
                choices.append((label, name, friendly))
            choices.sort(key=lambda x: (0 if x[2] in ("Wi-Fi", "Wired connection (Ethernet)") else 2 if "Virtual" in x[2] or "only" in x[2] else 1, x[0]))
            for label, name, _ in choices: self.interface_box.addItem(label, name)
            if previous:
                index = self.interface_box.findData(previous)
                if index >= 0: self.interface_box.setCurrentIndex(index)
        except Exception as exc:
            QMessageBox.warning(self, "Connection error", str(exc))
        if not self.interface_box.count(): self.statusBar().showMessage("No network connections found. Install Npcap for live monitoring.")
        self.update_local_ip()
        self.refresh_ip_finder()

    def start_capture(self):
        iface = self.interface_box.currentData()
        if not iface:
            QMessageBox.warning(self, "No interface", "Select a network interface first.")
            return
        if self.worker and self.worker.isRunning():
            return
        self.worker = CaptureWorker(iface, self.capture_filter.text())
        self.worker.packet_received.connect(self.add_packet)
        self.worker.capture_error.connect(self.capture_error)
        self.worker.capture_stopped.connect(self.capture_finished)
        self.worker.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.live_label.setText("● CAPTURING")
        self.statusBar().showMessage("Axon is monitoring " + self.interface_box.currentText() + ".")

    def stop_capture(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.stop_btn.setEnabled(False)
            self.statusBar().showMessage("Stopping capture…")

    def capture_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.live_label.setText("● READY")

    def capture_error(self, message):
        QMessageBox.warning(self, "Capture error", message + "\n\nOn Windows, install Npcap and try running as Administrator.")

    def add_packet(self, packet):
        self.record_website(packet)
        self.packets.append(packet)
        if len(self.packets) > 10000:
            self.packets.pop(0)
        self.apply_filter()
        if len(self.packets) % 10 == 0:
            self.refresh_ip_finder()

    def record_website(self, packet):
        """Record DNS query hostnames visible on this capture interface."""
        try:
            if DNS not in packet or DNSQR not in packet or int(packet[DNS].qr) != 0:
                return
            question = packet[DNS].qd
            if not question:
                return
            raw_name = question.qname
            if isinstance(raw_name, bytes):
                hostname = raw_name.decode("idna", errors="ignore").rstrip(".")
            else:
                hostname = str(raw_name).rstrip(".")
            if not hostname or " " in hostname:
                return
            device_ip = "Unknown"
            if IP in packet:
                device_ip = packet[IP].src
            elif IPv6 in packet:
                device_ip = packet[IPv6].src
            timestamp = datetime.now().strftime("%H:%M:%S")
            event = (timestamp, device_ip, hostname, "DNS hostname query")
            self.website_events.append(event)
            if len(self.website_events) > 1000:
                self.website_events.pop(0)
            row = self.website_table.rowCount()
            self.website_table.insertRow(row)
            for col, value in enumerate(event):
                self.website_table.setItem(row, col, QTableWidgetItem(value))
            self.website_table.scrollToBottom()
        except Exception:
            return

    def update_local_ip(self, *_):
        iface = self.interface_box.currentData()
        if not iface:
            self.local_ip_label.setText("Your computer's local IP: Not available")
            return
        try:
            address = get_if_addr(iface)
            if not address or address == "0.0.0.0":
                address = "Not available on this connection"
            self.local_ip_label.setText(f"Your computer's local IP: {address}")
        except Exception:
            self.local_ip_label.setText("Your computer's local IP: Not available")

    def refresh_ip_finder(self, *_):
        query = self.ip_search.text().strip().lower()
        found = {}
        for packet in self.packets:
            addresses = []
            if IP in packet:
                addresses.extend((packet[IP].src, packet[IP].dst))
            elif IPv6 in packet:
                addresses.extend((packet[IPv6].src, packet[IPv6].dst))
            try:
                seen_at = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S")
            except Exception:
                seen_at = "Unknown"
            for address in addresses:
                if not address or address in ("0.0.0.0", "::"):
                    continue
                item = found.setdefault(address, {"count": 0, "last": seen_at})
                item["count"] += 1
                item["last"] = seen_at
        local_text = self.local_ip_label.text()
        local_ip = local_text.rsplit(" ", 1)[-1] if ":" in local_text else ""
        try:
            if ipaddress.ip_address(local_ip).version in (4, 6):
                found.setdefault(local_ip, {"count": 0, "last": "—"})
        except ValueError:
            local_ip = ""
        self.ip_table.setRowCount(0)
        for address, data in sorted(found.items(), key=lambda item: item[0]):
            if query and query not in address.lower():
                continue
            row = self.ip_table.rowCount()
            self.ip_table.insertRow(row)
            try:
                kind = "This computer" if address == local_ip else ("Private network" if ipaddress.ip_address(address).is_private else "Public address")
            except ValueError:
                kind = "Address"
            values = (address, str(data["count"]), data["last"], kind)
            for col, value in enumerate(values):
                self.ip_table.setItem(row, col, QTableWidgetItem(value))
        self.ip_table.resizeRowsToContents()

    def copy_selected_ip(self):
        selected = self.ip_table.selectionModel().selectedRows()
        if not selected:
            self.statusBar().showMessage("Select an IP address first.")
            return
        item = self.ip_table.item(selected[0].row(), 0)
        if item:
            QApplication.clipboard().setText(item.text())
            self.statusBar().showMessage("IP address copied.")

    def apply_filter(self):
        query = self.search.text().strip().lower()
        self.visible_packets = []
        self.table.setRowCount(0)
        for packet in self.packets:
            values = packet_info(packet)
            if query and query not in " ".join(values).lower():
                continue
            self.visible_packets.append(packet)
            row = self.table.rowCount()
            self.table.insertRow(row)
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(value))
        self.count.setText(f"{len(self.visible_packets)} / {len(self.packets)} packets")

    def show_details(self):
        selected = self.table.selectionModel().selectedRows()
        if selected and selected[0].row() < len(self.visible_packets):
            packet = self.visible_packets[selected[0].row()]
            info = packet_info(packet)
            protocol = info[3]
            lines = ["WHAT THIS MEANS", f"Axon noticed network activity at {info[0]}.", f"From: {info[1]}", f"To: {info[2]}", f"Connection type: {protocol}", f"Data size: {info[6]} bytes", "", "SIMPLE EXPLANATION"]
            if protocol == "Website lookup": lines.append("Your computer is asking a website-lookup service to find a website's network address.")
            elif "Reliable" in protocol: lines.append("TCP is designed to deliver data reliably and in order.")
            elif "Fast" in protocol: lines.append("UDP is a lightweight way to send data without the same connection setup as TCP.")
            else: lines.append("This is network activity seen by the connection you selected.")
            if self.advanced_mode: lines.extend(["", "ADVANCED PACKET DETAILS", packet.summary(), packet.show(dump=True)])
            self.details.setPlainText("\n".join(lines))

    def open_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open saved network recording", "", "Network recordings (*.pcap *.pcapng);;All files (*)")
        if not path:
            return
        try:
            loaded = rdpcap(path)
            self.packets.extend(list(loaded))
            self.packets = self.packets[-10000:]
            self.apply_filter()
            self.refresh_ip_finder()
            self.statusBar().showMessage(f"Loaded {len(loaded)} packets from {os.path.basename(path)}")
        except Exception as exc:
            QMessageBox.critical(self, "PCAP error", str(exc))

    def save_pcap(self):
        if not self.packets:
            QMessageBox.information(self, "Nothing to save", "Capture or open packets first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save network recording", "axon-recording.pcap", "Network recording (*.pcap)")
        if path:
            try:
                wrpcap(path, self.packets)
                self.statusBar().showMessage(f"Saved {len(self.packets)} packets")
            except Exception as exc:
                QMessageBox.critical(self, "PCAP error", str(exc))

    def clear_packets(self):
        self.packets.clear()
        self.visible_packets.clear()
        self.website_events.clear()
        self.website_table.setRowCount(0)
        self.refresh_ip_finder()
        self.table.setRowCount(0)
        self.details.clear()
        self.count.setText("0 packets")

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(2500)
        event.accept()
