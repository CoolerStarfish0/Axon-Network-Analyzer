"""Axon Network Analyzer main window."""
import os
from datetime import datetime
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QLineEdit, QTableWidget, QTableWidgetItem,
    QTextEdit, QFileDialog, QMessageBox, QSplitter, QStatusBar, QHeaderView)
from scapy.all import conf, rdpcap, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
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
    return [stamp, src, dst, proto, sport, dport, str(len(packet))]

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Axon Network Analyzer")
        self.resize(1180, 760)
        self.worker = None
        self.packets = []
        self.visible_packets = []
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
        sub = QLabel("NETWORK ANALYZER  /  PASSIVE TRAFFIC INSPECTION")
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
        self.interface_box.setMinimumWidth(270)
        self.capture_filter = QLineEdit()
        self.capture_filter.setPlaceholderText("BPF capture filter: tcp, udp, port 53…")
        self.start_btn = QPushButton("Start capture")
        self.start_btn.setObjectName("primary")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        refresh_btn = QPushButton("Refresh")
        controls.addWidget(QLabel("INTERFACE"))
        controls.addWidget(self.interface_box, 2)
        controls.addWidget(self.capture_filter, 3)
        controls.addWidget(self.start_btn)
        controls.addWidget(self.stop_btn)
        controls.addWidget(refresh_btn)
        layout.addLayout(controls)

        actions = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter visible packets by IP, protocol or port…")
        self.count = QLabel("0 packets")
        open_btn, save_btn, clear_btn = QPushButton("Open PCAP"), QPushButton("Save PCAP"), QPushButton("Clear")
        actions.addWidget(self.search, 1)
        actions.addWidget(self.count)
        actions.addWidget(open_btn)
        actions.addWidget(save_btn)
        actions.addWidget(clear_btn)
        layout.addLayout(actions)

        split = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["TIME", "SOURCE", "DESTINATION", "PROTOCOL", "SRC PORT", "DST PORT", "BYTES"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a packet to inspect its decoded summary.")
        split.addWidget(self.table)
        split.addWidget(self.details)
        split.setSizes([510, 170])
        layout.addWidget(split, 1)
        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Ready. Select an interface you are authorized to monitor.")
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        refresh_btn.clicked.connect(self.load_interfaces)
        open_btn.clicked.connect(self.open_pcap)
        save_btn.clicked.connect(self.save_pcap)
        clear_btn.clicked.connect(self.clear_packets)
        self.search.textChanged.connect(self.apply_filter)
        self.table.itemSelectionChanged.connect(self.show_details)

    def load_interfaces(self):
        self.interface_box.clear()
        try:
            for name, iface in conf.ifaces.items():
                desc = getattr(iface, "description", "") or ""
                self.interface_box.addItem(f"{name} — {desc}" if desc else name, name)
        except Exception as exc:
            QMessageBox.warning(self, "Interface error", str(exc))
        if not self.interface_box.count():
            self.statusBar().showMessage("No interfaces found. Install Npcap for Windows capture support.")

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
        self.statusBar().showMessage("Passive capture running on " + str(iface))

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
        self.packets.append(packet)
        if len(self.packets) > 10000:
            self.packets.pop(0)
        self.apply_filter()

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
            self.details.setPlainText(packet.summary() + "\n\n" + packet.show(dump=True))

    def open_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open capture", "", "Capture files (*.pcap *.pcapng);;All files (*)")
        if not path:
            return
        try:
            loaded = rdpcap(path)
            self.packets.extend(list(loaded))
            self.packets = self.packets[-10000:]
            self.apply_filter()
            self.statusBar().showMessage(f"Loaded {len(loaded)} packets from {os.path.basename(path)}")
        except Exception as exc:
            QMessageBox.critical(self, "PCAP error", str(exc))

    def save_pcap(self):
        if not self.packets:
            QMessageBox.information(self, "Nothing to save", "Capture or open packets first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save capture", "axon-capture.pcap", "PCAP files (*.pcap)")
        if path:
            try:
                wrpcap(path, self.packets)
                self.statusBar().showMessage(f"Saved {len(self.packets)} packets")
            except Exception as exc:
                QMessageBox.critical(self, "PCAP error", str(exc))

    def clear_packets(self):
        self.packets.clear()
        self.visible_packets.clear()
        self.table.setRowCount(0)
        self.details.clear()
        self.count.setText("0 packets")

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(2500)
        event.accept()
