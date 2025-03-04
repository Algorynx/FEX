from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QLineEdit,
    QListWidget, QListWidgetItem, QFileIconProvider, QTreeWidget, QTreeWidgetItem, QMenu,
    QPushButton, QProgressBar, QLabel, QFrame, QMessageBox, QInputDialog, QDialog, QFileDialog
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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
import zipfile

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
        self.search_engine = None  # Initialize in run() to avoid DLL loading issues
        self._canceled = False

    def cancel_search(self):
        self._canceled = True  

    def run(self):
        if self._canceled:
            return
        try:
            if not self.search_engine:
                self.search_engine = EverythingSearch()
            results = self.search_engine.search(self.query)
            if not self._canceled:
                self.results_ready.emit(results)
        except Exception as e:
            if not self._canceled:
                self.results_ready.emit([f"Error: {str(e)}"])

class CustomFolderBrowser(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Extract Location")
        self.setModal(True)
        self.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(self)
        
        # Path navigation
        nav_layout = QHBoxLayout()
        
        # Back button
        self.back_button = QPushButton("←")
        self.back_button.setFixedSize(30, 30)
        self.back_button.clicked.connect(self.navigate_back)
        nav_layout.addWidget(self.back_button)
        
        # Current path display
        self.path_display = QLineEdit()
        self.path_display.setReadOnly(True)
        nav_layout.addWidget(self.path_display)
        
        layout.addLayout(nav_layout)
        
        # Split view for folders and files
        split_layout = QHBoxLayout()
        
        # Quick access sidebar
        self.sidebar = QTreeWidget()
        self.sidebar.setHeaderHidden(True)
        self.sidebar.setFixedWidth(200)
        split_layout.addWidget(self.sidebar)
        
        # Folder/file list
        self.folder_list = QListWidget()
        split_layout.addWidget(self.folder_list)
        
        layout.addLayout(split_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        select_button = QPushButton("Select")
        select_button.clicked.connect(self.accept)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(select_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)
        
        # Initialize
        self.current_path = None
        self.navigation_history = []
        self.setup_sidebar()
        self.navigate_to(os.path.expanduser("~"))
        
        # Connect signals
        self.sidebar.itemClicked.connect(self.handle_sidebar_click)
        self.folder_list.itemDoubleClicked.connect(self.handle_folder_double_click)

    def setup_sidebar(self):
        """Setup quick access sidebar."""
        icon_provider = QFileIconProvider()
        user_home = os.path.expanduser("~")
        
        # Get Desktop path from registry
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as key:
                desktop_path = os.path.expandvars(winreg.QueryValueEx(key, "Desktop")[0])
        except:
            desktop_path = os.path.join(user_home, "Desktop")

        # Get Documents path from registry
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as key:
                documents_path = os.path.expandvars(winreg.QueryValueEx(key, "Personal")[0])
        except:
            documents_path = os.path.join(user_home, "Documents")
        
        # Common locations with proper path detection
        locations = {
            "Desktop": desktop_path,
            "Documents": documents_path,
            "Downloads": os.path.join(user_home, "Downloads"),
            "Pictures": os.path.join(user_home, "Pictures"),
            "Music": os.path.join(user_home, "Music"),
            "Videos": os.path.join(user_home, "Videos")
        }
        
        # Add locations to sidebar if they exist
        for name, path in locations.items():
            if os.path.exists(path):
                item = QTreeWidgetItem([name])
                item.setData(0, Qt.ItemDataRole.UserRole, path)
                item.setIcon(0, icon_provider.icon(QFileInfo(path)))
                self.sidebar.addTopLevelItem(item)
        
        # Add drives
        for drive in self.get_drives():
            item = QTreeWidgetItem([drive])
            item.setData(0, Qt.ItemDataRole.UserRole, drive)
            item.setIcon(0, icon_provider.icon(QFileInfo(drive)))
            self.sidebar.addTopLevelItem(item)

    def get_drives(self):
        """Get list of available drives."""
        drives = []
        for drive in range(ord('A'), ord('Z') + 1):
            drive_letter = chr(drive) + ":\\"
            if os.path.exists(drive_letter):
                drives.append(drive_letter)
        return drives

    def navigate_to(self, path):
        """Navigate to specified path."""
        try:
            if os.path.exists(path):
                self.folder_list.clear()
                self.current_path = path
                self.path_display.setText(path)
                
                icon_provider = QFileIconProvider()
                
                # Add parent directory option if not at root
                if os.path.dirname(path) != path:
                    item = QListWidgetItem("..")
                    item.setIcon(icon_provider.icon(QFileInfo(os.path.dirname(path))))
                    item.setData(Qt.ItemDataRole.UserRole, os.path.dirname(path))
                    self.folder_list.addItem(item)
                
                # Add folders and files
                try:
                    items = []
                    with os.scandir(path) as entries:
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
                        self.folder_list.addItem(item)
                
                except PermissionError:
                    QMessageBox.warning(self, "Access Denied", "Cannot access this location")
                
                self.navigation_history.append(path)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error accessing path: {str(e)}")

    def navigate_back(self):
        """Navigate to previous directory."""
        if len(self.navigation_history) > 1:
            self.navigation_history.pop()  # Remove current
            previous = self.navigation_history.pop()  # Remove and get previous
            self.navigate_to(previous)

    def handle_sidebar_click(self, item):
        """Handle sidebar item click."""
        path = item.data(0, Qt.ItemDataRole.UserRole)
        if path and os.path.exists(path):
            self.navigate_to(path)

    def handle_folder_double_click(self, item):
        """Handle folder double click."""
        path = item.data(Qt.ItemDataRole.UserRole)
        if path and os.path.exists(path) and os.path.isdir(path):
            self.navigate_to(path)

    def get_selected_path(self):
        """Return currently displayed path."""
        return self.current_path

class ExtractDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Extract To")
        self.setModal(True)
        self.setMinimumWidth(400)
        
        layout = QVBoxLayout(self)
        
        # Path selection
        path_layout = QHBoxLayout()
        self.path_edit = QLineEdit(self)
        self.path_edit.setReadOnly(True)
        path_layout.addWidget(self.path_edit)
        
        browse_button = QPushButton("Browse", self)
        browse_button.clicked.connect(self.browse_path)
        path_layout.addWidget(browse_button)
        
        layout.addLayout(path_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        ok_button = QPushButton("Extract", self)
        ok_button.clicked.connect(self.accept)
        cancel_button = QPushButton("Cancel", self)
        cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

    def browse_path(self):
        """Open custom folder browser dialog."""
        browser = CustomFolderBrowser(self)
        if browser.exec() == QDialog.DialogCode.Accepted:
            selected_path = browser.get_selected_path()
            if selected_path:
                self.path_edit.setText(selected_path)

    def get_extract_path(self):
        """Return the selected extraction path."""
        return self.path_edit.text()

class FEXApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FEX - File Explorer")
        self.setGeometry(200, 200, 1000, 600)

        # Initialize components
        self.encryptor = FileEncryptor()
        self.compressor = FileCompressor()
        self.clipboard_files = []
        self.cut_mode = False
        self.navigation_history = []
        self.current_history_index = -1
        self.current_directory = None
        self.search_thread = None
        self.search_box = None  # Will be initialized in init_ui

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

        # Cancel any existing search
        if self.search_thread and self.search_thread.isRunning():
            self.search_thread.cancel_search()
            self.search_thread.quit()
            self.search_thread.wait()

        # Clear results when search bar is empty
        if not query:
            if self.current_directory:
                self.update_content_view(self.current_directory)
            return

        # Start new search
        self.search_thread = SearchThread(query)
        self.search_thread.results_ready.connect(self.display_search_results)
        self.search_thread.start()

    def display_search_results(self, results):
        """Display search results in the file list."""
        if not isinstance(results, list):
            return

        self.file_list.clear()
        icon_provider = QFileIconProvider()
        
        for result in results:
            if isinstance(result, str):
                if result.startswith("Error:"):
                    QMessageBox.warning(self, "Search Error", result)
                    continue
                    
                item = QListWidgetItem(result)  # Show full path in the list
                item.setToolTip(result)  # Show full path on hover
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
            menu.addSeparator()
            
            # Basic operations
            cut_action = menu.addAction("Cut")
            copy_action = menu.addAction("Copy")
            paste_action = menu.addAction("Paste")
            menu.addSeparator()
            
            delete_action = menu.addAction("Delete (Normal)")
            shred_action = menu.addAction("Shred (Permanent)")
            menu.addSeparator()

            # Compression operations
            if file_path.endswith('.zip'):
                extract_menu = menu.addMenu("Extract")
                extract_here_action = extract_menu.addAction("Extract Here")
                extract_to_action = extract_menu.addAction("Extract To...")
            else:
                compress_action = menu.addAction("Compress")
            menu.addSeparator()

            # Encryption operations
            if not is_directory:  # Only show encryption options for files
                if self.encryptor.is_encrypted_file(file_path):
                    decrypt_action = menu.addAction("Decrypt")
                else:
                    encrypt_action = menu.addAction("Encrypt")

            if is_directory:
                open_action.triggered.connect(lambda: self.update_content_view(file_path))
            else:
                open_action.triggered.connect(lambda: self.open_selected_file(item))

            delete_action.triggered.connect(lambda: self.normal_delete(file_path))
            shred_action.triggered.connect(lambda: self.shred_file(file_path))
            cut_action.triggered.connect(lambda: self.cut_file(file_path))
            copy_action.triggered.connect(lambda: self.copy_file(file_path))
            
            # Connect compression actions
            if file_path.endswith('.zip'):
                extract_here_action.triggered.connect(lambda: self.handle_decompression_here(file_path))
                extract_to_action.triggered.connect(lambda: self.handle_decompression_to(file_path))
            else:
                compress_action.triggered.connect(lambda: self.handle_compression(file_path))
            
            # Connect encryption actions
            if not is_directory:
                if self.encryptor.is_encrypted_file(file_path):
                    decrypt_action.triggered.connect(lambda: self.handle_decryption(file_path))
                else:
                    encrypt_action.triggered.connect(lambda: self.handle_encryption(file_path))

        # Only add Paste option if there's something in clipboard
        if hasattr(self, "clipboard_files") and self.clipboard_files:
            paste_action = menu.addAction("Paste")
            paste_action.triggered.connect(self.paste_file)

        menu.exec(self.file_list.viewport().mapToGlobal(position))

    def handle_decompression_here(self, file_path):
        """Extract ZIP file to current directory."""
        if self.current_directory:
            extracted_path = self.compressor.decompress_file(file_path, self.current_directory, self)
            if extracted_path:
                QMessageBox.information(self, "Success", f"Successfully extracted to: {os.path.basename(extracted_path)}")
                self.update_content_view(self.current_directory)

    def handle_decompression_to(self, file_path):
        """Extract ZIP file to user-selected location."""
        dialog = ExtractDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            extract_path = dialog.get_extract_path()
            if extract_path:
                extracted_path = self.compressor.decompress_file(file_path, extract_path, self)
                if extracted_path:
                    QMessageBox.information(self, "Success", f"Successfully extracted to: {extracted_path}")
                    if extract_path == self.current_directory:
                        self.update_content_view(self.current_directory)

    def handle_compression(self, file_path):
        """Handle file/directory compression."""
        compressed_path = self.compressor.compress_file(file_path, self)
        if compressed_path:
            QMessageBox.information(self, "Success", f"Successfully compressed to: {os.path.basename(compressed_path)}")
            self.update_content_view(os.path.dirname(file_path))

    def handle_encryption(self, file_path):
        """Handle file encryption."""
        encrypted_path = self.encryptor.encrypt_file(file_path, self)
        if encrypted_path:
            QMessageBox.information(self, "Success", f"File encrypted successfully: {os.path.basename(encrypted_path)}")
            self.update_content_view(os.path.dirname(file_path))

    def handle_decryption(self, file_path):
        """Handle file decryption."""
        decrypted_path = self.encryptor.decrypt_file(file_path, self)
        if decrypted_path:
            QMessageBox.information(self, "Success", f"File decrypted successfully: {os.path.basename(decrypted_path)}")
            self.update_content_view(os.path.dirname(file_path))


class FileEncryptor:
    def __init__(self):
        self.salt_size = 16
        self.nonce_size = 12
        self.tag_size = 16
        self.key_length = 32  # 256 bits
        self.iterations = 100000

    def is_encrypted_file(self, file_path):
        """Check if a file is encrypted by checking its extension."""
        return file_path.endswith('.enc')

    def derive_key(self, password, salt):
        """Derive encryption key from password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, file_path, parent=None):
        """Encrypt a file using AES-GCM."""
        try:
            # Get password from user
            password, ok = QInputDialog.getText(
                parent, 'Encryption Password', 
                'Enter password for encryption:', 
                QLineEdit.EchoMode.Password
            )
            if not ok or not password:
                return None

            # Generate salt and derive key
            salt = os.urandom(self.salt_size)
            key = self.derive_key(password, salt)

            # Generate nonce
            nonce = os.urandom(self.nonce_size)
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend()
            ).encryptor()

            # Read file content
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Encrypt data
            encrypted_data = cipher.update(file_data) + cipher.finalize()

            # Create output filename
            encrypted_path = file_path + '.enc'

            # Write encrypted file
            with open(encrypted_path, 'wb') as f:
                # Write salt, nonce, tag, and encrypted data
                f.write(salt)
                f.write(nonce)
                f.write(cipher.tag)
                f.write(encrypted_data)

            return encrypted_path

        except Exception as e:
            QMessageBox.critical(parent, "Error", f"Encryption failed: {str(e)}")
            return None

    def decrypt_file(self, file_path, parent=None):
        """Decrypt an encrypted file."""
        try:
            # Get password from user
            password, ok = QInputDialog.getText(
                parent, 'Decryption Password', 
                'Enter password for decryption:', 
                QLineEdit.EchoMode.Password
            )
            if not ok or not password:
                return None

            # Read encrypted file
            with open(file_path, 'rb') as f:
                # Read salt, nonce, tag
                salt = f.read(self.salt_size)
                nonce = f.read(self.nonce_size)
                tag = f.read(self.tag_size)
                encrypted_data = f.read()

            # Derive key from password and salt
            key = self.derive_key(password, salt)

            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            ).decryptor()

            try:
                # Decrypt data
                decrypted_data = cipher.update(encrypted_data) + cipher.finalize()
            except InvalidTag:
                QMessageBox.critical(parent, "Error", "Invalid password or corrupted file")
                return None

            # Create output filename (remove .enc extension)
            if file_path.endswith('.enc'):
                decrypted_path = file_path[:-4]  # Remove .enc extension
            else:
                # If for some reason the file doesn't end with .enc, append .decrypted
                base_path = os.path.splitext(file_path)[0]  # Remove any existing extension
                decrypted_path = base_path + '.decrypted'

            try:
                # Write decrypted file
                with open(decrypted_path, 'wb') as f:
                    f.write(decrypted_data)
                return decrypted_path
            except PermissionError:
                QMessageBox.critical(parent, "Error", f"Permission denied when saving to {decrypted_path}")
                return None
            except Exception as e:
                QMessageBox.critical(parent, "Error", f"Failed to save decrypted file: {str(e)}")
                return None

        except Exception as e:
            QMessageBox.critical(parent, "Error", f"Decryption failed: {str(e)}")
            return None


class FileCompressor:
    def __init__(self):
        self.compression_level = zipfile.ZIP_DEFLATED

    def compress_file(self, file_path, parent=None):
        """Compress a file or directory using ZIP format."""
        try:
            # Create output filename
            zip_path = file_path + '.zip'
            
            # Create and write to the zip file
            with zipfile.ZipFile(zip_path, 'w', self.compression_level) as zipf:
                if os.path.isfile(file_path):
                    # Add single file to zip
                    zipf.write(file_path, os.path.basename(file_path))
                else:
                    # Add directory contents to zip
                    for root, _, files in os.walk(file_path):
                        for file in files:
                            file_full_path = os.path.join(root, file)
                            # Preserve relative path within the zip
                            arc_name = os.path.relpath(file_full_path, os.path.dirname(file_path))
                            zipf.write(file_full_path, arc_name)
            
            return zip_path
        except Exception as e:
            QMessageBox.critical(parent, "Error", f"Compression failed: {str(e)}")
            return None

    def decompress_file(self, zip_path, extract_path, parent=None):
        """
        Decompress a ZIP file to specified path.
        
        :param zip_path: Path to the ZIP file
        :param extract_path: Path where files should be extracted
        :param parent: Parent window for error messages
        :return: The path where files were extracted
        """
        try:
            # Create output directory if it doesn't exist
            if not os.path.exists(extract_path):
                os.makedirs(extract_path)

            # Extract the zip file
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                zipf.extractall(extract_path)

            return extract_path
        except Exception as e:
            QMessageBox.critical(parent, "Error", f"Decompression failed: {str(e)}")
            return None


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FEXApp()
    window.show()
    sys.exit(app.exec())
