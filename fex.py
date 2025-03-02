from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QLineEdit,
    QListWidget, QListWidgetItem, QFileIconProvider, QTreeWidget, QTreeWidgetItem, QMenu,
    QPushButton, QProgressBar, QLabel, QFrame, QMessageBox
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
from functools import partial
import send2trash

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

        # Initialize navigation history
        self.navigation_history = []
        self.current_history_index = -1

        self.init_ui()

    def get_desktop_path(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders") as key:
                desktop, _ = winreg.QueryValueEx(key, "Desktop")
                return os.path.expandvars(desktop)
        except Exception as e:
            print(f"Error detecting Desktop path: {e}")
            return os.path.join(os.path.expanduser("~"), "Desktop")
    
    def get_documents_path(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders") as key:
                documents, _ = winreg.QueryValueEx(key, "Personal")  # "Personal" is the registry key for Documents
                return os.path.expandvars(documents)
        except Exception as e:
            print(f"Error detecting Documents path: {e}")
            return os.path.join(os.path.expanduser("~"), "Documents")
            

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

        # Navigation and search bar layout
        nav_search_layout = QHBoxLayout()

        # Back button
        self.back_button = QPushButton("←")
        self.back_button.setFixedSize(30, 30)
        self.back_button.setToolTip("Back")
        self.back_button.clicked.connect(self.navigate_back)
        nav_search_layout.addWidget(self.back_button)

        # Forward button
        self.forward_button = QPushButton("→")
        self.forward_button.setFixedSize(30, 30)
        self.forward_button.setToolTip("Forward")
        self.forward_button.clicked.connect(self.navigate_forward)
        nav_search_layout.addWidget(self.forward_button)

        # Search bar
        self.search_box = QLineEdit(self)
        self.search_box.setPlaceholderText("Search for files and folders...")
        self.search_box.textChanged.connect(self.search_files)
        nav_search_layout.addWidget(self.search_box)

        content_layout.addLayout(nav_search_layout)

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
        desktop_path = self.get_desktop_path()
        documents_path = self.get_documents_path()
        
        self.quick_access_paths = {
            "Desktop": desktop_path,
            "Documents": documents_path,
            "Downloads": os.path.join(user_home, "Downloads"),
            "Pictures": os.path.join(user_home, "Pictures"),
            "Music": os.path.join(user_home, "Music"),
            "Videos": os.path.join(user_home, "Videos"),
        }
        
        for name, path in self.quick_access_paths.items():
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
        """Handle navigation when a sidebar item is clicked."""
        directory = item.data(0, Qt.ItemDataRole.UserRole)
        if directory:
            # print(f"Navigating to: {directory}")  # Debugging output
            self.update_content_view(directory)

    def update_content_view(self, directory):
        """Update the file list to show the contents of the selected directory."""
        if not os.path.exists(directory) or not os.path.isdir(directory):
            print(f"Directory does not exist or is not accessible: {directory}")
            return
            
        self.current_directory = directory
        self.file_list.clear()
        icon_provider = QFileIconProvider()
        try:
            items = []
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        item = QListWidgetItem(entry.name)
                        item.setIcon(icon_provider.icon(QFileInfo(entry.path)))
                        item.setData(Qt.ItemDataRole.UserRole, entry.path)
                        items.append(item)
                    except Exception as e:
                        print(f"Error processing entry {entry.name}: {e}")
            
            # Sort folders first, then files
            folders = [item for item in items if os.path.isdir(item.data(Qt.ItemDataRole.UserRole))]
            files = [item for item in items if not os.path.isdir(item.data(Qt.ItemDataRole.UserRole))]
            
            # Add sorted items to the list
            for item in sorted(folders, key=lambda x: x.text().lower()) + sorted(files, key=lambda x: x.text().lower()):
                self.file_list.addItem(item)
                
        except PermissionError:
            self.file_list.addItem(QListWidgetItem("Error: Permission denied"))
        except Exception as e:
            self.file_list.addItem(QListWidgetItem(f"Error: {str(e)}"))

        # Update navigation history
        if self.current_history_index == -1 or self.navigation_history[self.current_history_index] != directory:
            self.navigation_history = self.navigation_history[:self.current_history_index + 1]
            self.navigation_history.append(directory)
            self.current_history_index += 1

        self.update_navigation_buttons()
    def update_navigation_buttons(self):
        self.back_button.setEnabled(self.current_history_index > 0)
        self.forward_button.setEnabled(self.current_history_index < len(self.navigation_history) - 1)

    def navigate_back(self):
        if self.current_history_index > 0:
            self.current_history_index -= 1
            self.update_content_view(self.navigation_history[self.current_history_index])

    def navigate_forward(self):
        if self.current_history_index < len(self.navigation_history) - 1:
            self.current_history_index += 1
            self.update_content_view(self.navigation_history[self.current_history_index])

    def open_selected_file(self, item):
        """Opens the file when double-clicked."""
        file_path = item.data(Qt.ItemDataRole.UserRole)
        if file_path:
            if os.path.isdir(file_path):
                self.update_content_view(file_path)
            else:
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
        """Pastes the copied/cut file or folder into the current directory with admin privileges if needed."""
        if not hasattr(self, "clipboard_files") or not self.clipboard_files:
            print("No file or folder to paste.")
            return

        if not self.current_directory:
            print("No destination directory selected.")
            return

        for path in self.clipboard_files:
            destination = os.path.join(self.current_directory, os.path.basename(path))

            try:
                if os.path.isdir(path):  # If it's a folder
                    if self.cut_mode:
                        shutil.move(path, destination)  # Move folder
                    else:
                        shutil.copytree(path, destination, dirs_exist_ok=True)  # Copy folder
                else:  # If it's a file
                    if self.cut_mode:
                        # Move file with PowerShell (bypassing permissions)
                        subprocess.run(["powershell", "Move-Item", f'"{path}"', f'"{destination}"', "-Force", "-ErrorAction", "SilentlyContinue"], check=True)
                    else:
                        # Copy file with PowerShell
                        subprocess.run(["powershell", "Copy-Item", f'"{path}"', f'"{destination}"', "-Force", "-ErrorAction", "SilentlyContinue"], check=True)

                print(f"{'Moved' if self.cut_mode else 'Copied'}: {path} → {destination}")

            except PermissionError:
                print(f"Permission denied: {path}. Trying with PowerShell...")
                try:
                    # Use PowerShell to bypass permission issues
                    if os.path.isdir(path):
                        subprocess.run(["powershell", "Copy-Item", "-Recurse", "-Path", f'"{path}"', "-Destination", f'"{destination}"', "-Force"], check=True)
                    else:
                        subprocess.run(["powershell", "Copy-Item", f'"{path}"', f'"{destination}"', "-Force"], check=True)
                    print(f"Successfully bypassed permission for {path}")
                except Exception as e:
                    print(f"Failed to paste {path}: {e}")

        self.clipboard_files.clear()
        self.update_content_view(self.current_directory)
        
    def normal_delete(self, file_path):
        """Move file or folder to Recycle Bin."""
        reply = QMessageBox.question(
            self,
            "Delete File",
            f"Are you sure you want to delete:\n{file_path}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                send2trash.send2trash(file_path)  # Moves file to Recycle Bin
                self.update_content_view(os.path.dirname(file_path))  # Refresh UI
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete:\n{file_path}\n\n{str(e)}")

    def shred_file(self, file_path):
        """Permanently delete a file by overwriting its content before removal."""
        reply = QMessageBox.question(
            self,
            "Shred File",
            f"⚠ WARNING: This action will permanently delete the file.\n\nAre you sure?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                if os.path.isdir(file_path):
                    os.rmdir(file_path)  # Removes empty directories
                else:
                    # Overwrite file with random data before deletion
                    with open(file_path, "r+b") as file:
                        length = os.path.getsize(file_path)
                        file.seek(0)
                        file.write(os.urandom(length))  # Overwrite with random bytes
                    
                    os.remove(file_path)  # Delete file
                
                self.update_content_view(os.path.dirname(file_path))  # Refresh UI
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to shred file:\n{file_path}\n\n{str(e)}")


    def show_context_menu(self, position):
        """Display right-click context menu on file items."""
        item = self.file_list.itemAt(position)
        menu = QMenu(self)

        if item:  # File or folder right-clicked
            file_path = item.data(Qt.ItemDataRole.UserRole)
            is_directory = os.path.isdir(file_path)

            open_action = menu.addAction("Open")
            delete_action = menu.addAction("Delete (Normal)")
            shred_action = menu.addAction("Shred (Permanent)")
            cut_action = menu.addAction("Cut")
            copy_action = menu.addAction("Copy")

            if is_directory:
                open_action.triggered.connect(lambda: self.update_content_view(file_path))
            else:
                open_action.triggered.connect(lambda: self.open_file(file_path))

            delete_action.triggered.connect(lambda: self.normal_delete(file_path))
            shred_action.triggered.connect(lambda: self.shred_file(file_path))
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
