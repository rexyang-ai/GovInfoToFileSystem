# GovInfo Visual Sniffer & Collector Tool

This is a standalone desktop application built with Python and PyQt6 to provide a visual interface for sniffing website structures and generating collection rules.

## Features
- **Visual Browser**: Embedded Chromium browser to navigate target sites.
- **DOM Inspector**: Point-and-click to select elements (Title, Content, etc.).
- **Smart XPath**: Automatically calculates the robust XPath for selected elements.
- **Network Monitor**: Sniffs background API requests (JSON/XHR) to identify data sources.
- **Rule Generation**: Generates rules compatible with the GovInfoToFileSystem backend.

## Requirements
- Python 3.8+
- PyQt6
- PyQt6-WebEngine

## Installation

```bash
pip install -r ../requirements-sniffer.txt
```

## Usage

1. Run the tool:
   ```bash
   python main.py
   ```

2. Enter the target URL in the address bar and click "Go".
3. Click "Start Inspector" to enable DOM highlighting.
4. Hover over the element you want to capture (e.g., Article Title).
5. Click the element. The XPath will appear in the side panel.
6. Verify the "Text Preview" ensures you captured the right data.
7. Click "Save Rule to System" (Functionality to be linked to your specific API).

## Technical Details
- **Frontend**: PyQt6 QWebEngineView.
- **Bridge**: `QWebChannel` facilitates communication between the page JS and Python.
- **Logic**: `inspector.js` handles the DOM traversal and highlighting logic.
