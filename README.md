# File Explorer Application (FEX)

A modern, feature-rich file explorer built with PyQt6, offering advanced functionality including file encryption, compression, and fast search capabilities.

## Table of Contents
- [Architecture Overview](#architecture-overview)
- [Core Components](#core-components)
- [Features](#features)
- [Technical Implementation](#technical-implementation)
- [Security Features](#security-features)

## Architecture Overview

The application follows a modular architecture with several key components:

```
FEX
├── Main Window (FEXApp)
├── Core Components
│   ├── Search Engine (EverythingSearch)
│   ├── File Encryption (FileEncryptor)
│   └── File Compression (FileCompressor)
└── UI Components
    ├── Custom Dialogs
    ├── Context Menus
    └── Navigation Elements
```

## Core Components

### 1. FEXApp Class
The main application window class that orchestrates all components.

**Key Features:**
- File system navigation
- Context menu operations
- Clipboard management
- Navigation history
- File operations (copy, cut, paste, delete)

**Implementation Details:**
- Uses `QMainWindow` as base class
- Implements a dual-pane layout with sidebar and main content
- Manages file operations through context menu actions
- Handles navigation history for back/forward functionality

### 2. EverythingSearch Class
Integrates with Windows' Everything search engine for fast file searching.

**Technical Details:**
- Uses Windows DLL integration via `ctypes`
- Implements asynchronous search through `QThread`
- Returns real-time search results
- Memory-efficient result handling

### 3. FileEncryptor Class
Handles secure file encryption and decryption.

**Security Implementation:**
- Uses AES-GCM for authenticated encryption
- Implements PBKDF2 for key derivation
- Salt and nonce generation for each encryption
- Secure password handling

**Process Flow:**
1. Password collection via secure dialog
2. Key derivation with salt
3. Encryption/Decryption using AES-GCM
4. Secure file handling

### 4. FileCompressor Class
Manages file compression and decompression.

**Features:**
- ZIP format compression
- Directory compression with structure preservation
- Custom extraction location selection
- Progress feedback

**Implementation:**
- Uses Python's `zipfile` module
- Preserves directory structures
- Handles large files efficiently
- Error handling and recovery

### 5. CustomFolderBrowser Class
A custom file browser dialog for selecting directories.

**UI Components:**
- Navigation bar with path display
- Quick access sidebar
- Folder list view
- Back navigation

**Features:**
- Registry-based path detection
- Drive enumeration
- Permission handling
- Sorting and filtering

## Technical Implementation

### Navigation System
```python
def navigate_to(self, path):
    # Updates current path
    # Updates navigation history
    # Refreshes view
```

### File Operations
```python
def handle_file_operation(self, operation, source, target):
    # Validates paths
    # Performs operation
    # Updates UI
    # Handles errors
```

### Search Implementation
```python
class SearchThread(QThread):
    # Asynchronous search
    # Result signaling
    # Error handling
```

## Security Features

### Encryption
- AES-256-GCM encryption
- Secure key derivation (PBKDF2)
- Authenticated encryption
- Secure password handling

### File Operations
- Safe file deletion
- Secure file movement
- Permission checking
- Error recovery

## User Interface

### Context Menu System
The application implements a rich context menu system:
```python
def show_context_menu(self, position):
    # Dynamic menu generation
    # Action handling
    # State management
```

### Navigation Elements
- Back/Forward buttons
- Path navigation
- Quick access sidebar
- Drive listing

## Error Handling

The application implements comprehensive error handling:
- Permission errors
- File access errors
- Encryption/Decryption errors
- Search errors

## Best Practices

### Code Organization
- Modular design
- Clear separation of concerns
- Consistent naming conventions
- Comprehensive documentation

### Performance Optimization
- Asynchronous operations
- Efficient file handling
- Memory management
- UI responsiveness

## Dependencies
- PyQt6: UI framework
- cryptography: Encryption operations
- zipfile: Compression handling
- ctypes: DLL integration
- winreg: Windows registry access

## Installation
1. Install Python 3.8+
2. Install required packages:
   ```bash
   pip install PyQt6 cryptography
   ```
3. Place Everything64.dll in application directory
4. Run main.py

## Usage
- Launch application
- Navigate through files using sidebar or main view
- Use context menu for operations
- Search files using search bar
- Encrypt/Decrypt files as needed
- Compress/Extract files using context menu
