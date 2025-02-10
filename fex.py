from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QLineEdit, QListWidget, QWidget
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import ctypes
import os

class EverythingSearch:
    def __init__(self, dll_path=None):
        """Initialize Everything SDK."""
        if dll_path is None:
            dll_path = os.path.join(os.getcwd(), "Everything64.dll")  # Update this if needed
        self.everything = ctypes.WinDLL(dll_path)

    def search(self, query):
        """Search files using Everything SDK."""
        try:
            self.everything.Everything_SetSearchW(query)
            self.everything.Everything_QueryW(True)

            num_results = self.everything.Everything_GetNumResults()
            if num_results == 0:
                return ["No results found"]

            results = []
            for i in range(min(num_results, 50)):  # Limit results to avoid overload
                buf = ctypes.create_unicode_buffer(260)
                self.everything.Everything_GetResultFullPathNameW(i, buf, 260)
                results.append(buf.value)

            return results
        except Exception as e:
            return [f"Error: {str(e)}"]


class SearchThread(QThread):
    results_ready = pyqtSignal(list)
    search_canceled = False  # Flag to cancel old searches

    def __init__(self, query):
        super().__init__()
        self.query = query
        self.search_engine = EverythingSearch()

    def run(self):
        if self.search_canceled:
            return  # Stop if an old search is canceled

        results = self.search_engine.search(self.query)

        if not self.search_canceled:  # Only send results if search is still valid
            self.results_ready.emit(results)

class FEXApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("FEX - File Explorer")
        self.setGeometry(200, 200, 600, 400)

        # UI Elements
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search for files...")
        self.search_box.textChanged.connect(self.start_search)

        self.results_list = QListWidget()

        layout.addWidget(self.search_box)
        layout.addWidget(self.results_list)

        self.central_widget.setLayout(layout)

        self.search_thread = None  # Thread reference

    def start_search(self):
        query = self.search_box.text().strip()
        if query:
            self.results_list.clear()
            self.results_list.addItem("Searching...")  # Show loader

            # Cancel previous search safely
            if self.search_thread and self.search_thread.isRunning():
                self.search_thread.search_canceled = True

            # Start new search
            self.search_thread = SearchThread(query)
            self.search_thread.results_ready.connect(self.update_results)
            self.search_thread.start()

    def update_results(self, results):
        self.results_list.clear()
        self.results_list.addItems(results)

if __name__ == "__main__":
    app = QApplication([])
    window = FEXApp()
    window.show()
    app.exec()
