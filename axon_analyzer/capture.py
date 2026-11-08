"""Passive packet capture worker using Scapy."""
from PySide6.QtCore import QThread, Signal
from scapy.all import sniff

class CaptureWorker(QThread):
    packet_received = Signal(object)
    capture_error = Signal(str)
    capture_stopped = Signal()

    def __init__(self, interface, bpf_filter="", parent=None):
        super().__init__(parent)
        self.interface = interface
        self.bpf_filter = bpf_filter.strip()
        self._running = False

    def run(self):
        self._running = True
        try:
            while self._running:
                sniff(iface=self.interface, filter=self.bpf_filter or None,
                      prn=self.packet_received.emit, store=False, timeout=1)
        except Exception as exc:
            self.capture_error.emit(str(exc))
        finally:
            self._running = False
            self.capture_stopped.emit()

    def stop(self):
        self._running = False
