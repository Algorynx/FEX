from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QLineEdit,
    QListWidget, QListWidgetItem, QFileIconProvider, QTreeWidget, QTreeWidgetItem, QMenu,
    QPushButton, QProgressBar, QLabel, QFrame
)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QFileInfo, Qt, QThread, pyqtSignal
import os
import sys
import shutil
import ctypes
import winreg
import subprocess
import psutil

class EverythingSearch:
    def __init__(self, dll_path=None):
        if dll_path is None:
            dll_path = os.path.join(os.getcwd(), "Everything64.dll")
        self.everything = ctypes.WinDLL(dll_path)

    def search(self, query):
        try:
            self.everything.Everything_SetSearchW(query)
            self.everything.Everything_QueryW(True)

            num_results = self.everything.Everything_GetNumResults()
            if num_results == 0:
                return []

            results = []
            for i in range(min(num_results, 50)):
                buf = ctypes.create_unicode_buffer(260)
                self.everything.Everything_GetResultFullPathNameW(i, buf, 260)
                results.append(buf.value)

            return results
        except Exception as e:
            return [f"Error: {str(e)}"]

class SearchThread(QThread):
    results_ready = pyqtSignal(list)

    def __init__(self, query):
        super().__init__()
        self.query = query
        self.search_engine = EverythingSearch()
        self._canceled = False

    def cancel_search(self):
        self._canceled = True  

    def run(self):
        if self._canceled:
            return
        results = self.search_engine.search(self.query)
        if not self._canceled:
            self.results_ready.emit(results)


class FEXApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FEX - File Explorer")
        self.setGeometry(200, 200, 1000, 600)

        # Initialize clipboard tracking
        self.clipboard_files = []
        self.cut_mode = False

        self.init_ui()

    def get_desktop_path(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders") as key:
                desktop, _ = winreg.QueryValueEx(key, "Desktop")
                return os.path.expandvars(desktop)
        except Exception as e:
            print(f"Error detecting Desktop path: {e}")
            return os.path.join(os.path.expanduser("~"), "Desktop")
        

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        
        self.sidebar = QTreeWidget()
        self.sidebar.setHeaderHidden(True)
        self.sidebar.setFixedWidth(250)
        self.populate_sidebar()
        self.sidebar.itemClicked.connect(self.sidebar_navigation)
        main_layout.addWidget(self.sidebar)

        content_layout = QVBoxLayout()
        self.search_box = QLineEdit(self)
        self.search_box.setPlaceholderText("Search for files and folders...")
        self.search_box.textChanged.connect(self.search_files)
        content_layout.addWidget(self.search_box)

        self.file_list = QListWidget()
        content_layout.addWidget(self.file_list)
        main_layout.addLayout(content_layout)
        self.current_directory = None
        
        self.file_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_list.customContextMenuRequested.connect(self.show_context_menu)
        self.file_list.itemDoubleClicked.connect(self.open_selected_file)  # Double-click to open

    def populate_sidebar(self):
        icon_provider = QFileIconProvider()
        user_home = os.path.expanduser("~")
        quick_access_paths = {
            "Desktop": os.path.join(user_home, "Desktop"),
            "Documents": os.path.join(user_home, "Documents"),
            "Downloads": os.path.join(user_home, "Downloads"),
            "Pictures": os.path.join(user_home, "Pictures"),
            "Music": os.path.join(user_home, "Music"),
            "Videos": os.path.join(user_home, "Videos"),
        }
        
        for name, path in quick_access_paths.items():
            if os.path.exists(path):
                item = QTreeWidgetItem([name])
                item.setData(0, Qt.ItemDataRole.UserRole, path)
                item.setIcon(0, icon_provider.icon(QFileInfo(path)))
                self.sidebar.addTopLevelItem(item)
        
        self.add_volume_containers()


    def search_files(self):
        query = self.search_box.text().strip()

        if not query:
            self.file_list.clear()  # Clear results when search bar is empty
            if self.current_directory:
                self.update_content_view(self.current_directory)
            return

        if hasattr(self, "search_thread") and self.search_thread.isRunning():
            self.search_thread.cancel_search()
            self.search_thread.quit()
            self.search_thread.wait()

        self.search_thread = SearchThread(query)
        self.search_thread.results_ready.connect(self.display_search_results)
        self.search_thread.start()


    def display_search_results(self, results):
        self.file_list.clear()
        icon_provider = QFileIconProvider()
        for result in results:
            item = QListWidgetItem(result)
            item.setData(Qt.ItemDataRole.UserRole, result)
            item.setIcon(icon_provider.icon(QFileInfo(result)))
            self.file_list.addItem(item)

    def add_volume_containers(self):
        icon_provider = QFileIconProvider()
        for partition in psutil.disk_partitions():
            drive = partition.device
            if os.path.exists(drive):
                usage = psutil.disk_usage(drive)
                item = QTreeWidgetItem([f"{drive} ({usage.free // (1024**3)}GB free)"])
                item.setData(0, Qt.ItemDataRole.UserRole, drive)
                item.setIcon(0, icon_provider.icon(QFileInfo(drive)))
                
                # Add a progress bar
                progress_bar = QProgressBar()
                progress_bar.setFixedWidth(180)
                progress_bar.setValue(int((usage.used / usage.total) * 100))
                progress_bar.setTextVisible(False)
                
                container = QFrame()
                layout = QVBoxLayout(container)
                layout.addWidget(QLabel(drive))
                layout.addWidget(progress_bar)
                self.sidebar.addTopLevelItem(item)
    
    def sidebar_navigation(self, item):
        directory = item.data(0, Qt.ItemDataRole.UserRole)
        if directory:
            self.update_content_view(directory)
    
    def update_content_view(self, directory):
        self.file_list.clear()
        icon_provider = QFileIconProvider()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    item = QListWidgetItem(entry.name)
                    item.setIcon(icon_provider.icon(QFileInfo(entry.path)))
                    item.setData(Qt.ItemDataRole.UserRole, entry.path)
                    self.file_list.addItem(item)
        except Exception as e:
            self.file_list.addItem(QListWidgetItem(f"Error: {str(e)}"))
            
    def open_selected_file(self, item):
        """Opens the file when double-clicked."""
        file_path = item.data(Qt.ItemDataRole.UserRole)
        if file_path:
            self.open_file(file_path)

    def open_file(self, file_path):
        """Opens a file with admin privileges if needed."""
        try:
            os.startfile(file_path)  # Try opening normally
        except PermissionError:
            print(f"Access denied: {file_path}. Requesting admin access...")
            self.request_admin_access(file_path)
        except Exception as e:
            print(f"Error opening file: {e}")

    def request_admin_access(self, file_path):
        """Requests admin privileges to open a file using UAC."""
        try:
            # Using PowerShell to request admin privileges and open the file
            subprocess.run([
                "powershell",
                "Start-Process", f"'{file_path}'",
                "-Verb", "RunAs"
            ], check=True)
        except Exception as e:
            print(f"Failed to request admin privileges: {e}")
            
    def copy_file(self, file_path):
        """Stores a file path for copying."""
        self.clipboard_files = [file_path]
        self.cut_mode = False

    def cut_file(self, file_path):
        """Stores a file path for cutting."""
        self.clipboard_files = [file_path]
        self.cut_mode = True

    def paste_file(self):
        """Pastes the copied/cut file into the current directory."""
        if not hasattr(self, "clipboard_files") or not self.clipboard_files:
            print("No file to paste.")
            return

        if not self.current_directory:
            print("No destination directory selected.")
            return

        for file_path in self.clipboard_files:
            destination = os.path.join(self.current_directory, os.path.basename(file_path))
            try:
                if self.cut_mode:
                    shutil.move(file_path, destination)
                else:
                    shutil.copy(file_path, destination)
            except Exception as e:
                print(f"Error pasting file: {e}")

        self.clipboard_files.clear()
        self.update_content_view(self.current_directory)


    def show_context_menu(self, position):
        """Display right-click context menu on file items."""
        item = self.file_list.itemAt(position)
        menu = QMenu(self)

        if item:  # File or folder right-clicked
            file_path = item.data(Qt.ItemDataRole.UserRole)
            
            open_action = menu.addAction("Open")
            delete_action = menu.addAction("Delete")
            cut_action = menu.addAction("Cut")
            copy_action = menu.addAction("Copy")

            open_action.triggered.connect(lambda: self.open_file(file_path))
            delete_action.triggered.connect(lambda: self.delete_file(file_path))
            cut_action.triggered.connect(lambda: self.cut_file(file_path))
            copy_action.triggered.connect(lambda: self.copy_file(file_path))

        # Only add Paste option if there's something in clipboard
        if hasattr(self, "clipboard_files") and self.clipboard_files:
            paste_action = menu.addAction("Paste")
            paste_action.triggered.connect(self.paste_file)

        menu.exec(self.file_list.viewport().mapToGlobal(position))  



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FEXApp()
    window.show()
    sys.exit(app.exec())
