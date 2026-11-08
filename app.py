import sys
from PySide6.QtWidgets import QApplication
from axon_analyzer.main_window import MainWindow, STYLE

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("Axon Network Analyzer")
    app.setStyleSheet(STYLE)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
