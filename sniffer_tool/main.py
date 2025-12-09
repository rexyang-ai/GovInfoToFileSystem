import sys
import json
import os
import time
import requests
from urllib.parse import urlparse
from PyQt6.QtWidgets import (QApplication, QMainWindow, QToolBar, QLineEdit, 
                             QPushButton, QVBoxLayout, QHBoxLayout, QWidget, 
                             QTextEdit, QLabel, QSplitter, QCheckBox, QMessageBox, 
                             QTabWidget, QListWidget, QInputDialog, QFormLayout)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile, QWebEngineUrlRequestInterceptor, QWebEngineScript
from PyQt6 import QtWebEngineCore
import queue
from PyQt6.QtCore import QUrl, QObject, pyqtSlot, pyqtSignal, Qt, QThread
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtGui import QAction, QIcon

# --- Bridge for JS Communication ---
class Bridge(QObject):
    selection_received = pyqtSignal(str)
    
    @pyqtSlot(str)
    def receive_selection(self, data):
        self.selection_received.emit(data)

# --- Network Interceptor ---
class ApiSniffer(QWebEngineUrlRequestInterceptor):
    def __init__(self, bridge):
        super().__init__()
        # We use a signal from a QObject (bridge) to communicate back to UI thread safe
        self.bridge = bridge
        # Simple rate limiter: max emits per second
        self._current_sec = int(time.time())
        self._emit_count = 0
        self._max_per_sec = 30
        
    def interceptRequest(self, info):
        try:
            url = info.requestUrl().toString()
            method = info.requestMethod().data().decode()
            
            # DEBUG LOGGING - FORCE PRINT
            print(f"DEBUG: Intercepting {method} {url}")

            # 1. Extension Filter
            ignored_exts = [
                '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', 
                '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.webm', '.mp3', '.wav',
                '.map'
            ]
            url_lower = url.lower()
            if any(ext in url_lower for ext in ignored_exts):
                # print(f"DEBUG: Filtered by extension: {url}")
                return
                
            # 2. Scheme Filter
            if url.startswith('data:') or url.startswith('blob:') or url.startswith('file:'):
                return

            # 3. Resource Type Filter
            # In PyQt6, resourceType() returns an enum.
            # We need to be careful with comparison.
            try:
                rtype = info.resourceType()
                # print(f"DEBUG: Resource Type: {rtype} for {url}")
                
                # Check if it is a static resource type
                # enum values:
                # 0: MainFrame, 1: SubFrame, 2: Stylesheet, 3: Script, 4: Image, 5: FontResource
                # 6: SubResource, 7: Object, 8: Media, 9: Worker, 10: SharedWorker
                # 11: Prefetch, 12: Favicon, 13: Xhr, 14: Ping, 15: ServiceWorker, 16: CspReport, 17: PluginResource
                
                # We can try to match by name if int conversion is tricky in python wrapper
                rtype_s = str(rtype).lower()
                
                # Allow scripts and mainframe so JSONP endpoints appear in list
                # Block only obvious static types
                if 'stylesheet' in rtype_s or 'image' in rtype_s or \
                   'font' in rtype_s or 'media' in rtype_s or 'favicon' in rtype_s:
                    return
            except Exception as e:
                # print(f"DEBUG: Resource type check error: {e}")
                pass

            # Emit Signals
            print(f"DEBUG: Emitting signal for {url}")
            self.bridge.network_request_received.emit(method, url)
            
            # Capture Headers
            headers = {}
            try:
                rh = info.requestHeaders()
                for k, v in rh.items():
                    try:
                        ks = k.decode() if hasattr(k, 'decode') else str(k)
                        vs = v.decode() if hasattr(v, 'decode') else str(v)
                        headers[ks] = vs
                    except Exception:
                        pass
                # print(f"DEBUG: Captured headers for {url}: {headers}")
            except Exception:
                pass
                
            try:
                headers_json = json.dumps(headers)
            except Exception:
                headers_json = '{}'
                
            self.bridge.network_request_detailed.emit(method, url, headers_json)
            
        except Exception as e:
            print(f"Interceptor Error: {e}")

class LogWorker(QThread):
    batch_ready = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.q = queue.Queue()
        self.running = True

    def run(self):
        while self.running:
            batch = []
            try:
                item = self.q.get(timeout=0.2)
                batch.append(item)
            except Exception:
                pass
            n = 0
            while not self.q.empty() and n < 200:
                try:
                    batch.append(self.q.get_nowait())
                    n += 1
                except Exception:
                    break
            if batch:
                self.batch_ready.emit(batch)
            self.msleep(200)

    def append(self, text):
        if self.q.qsize() > 5000:
            return
        self.q.put(text)

    def stop(self):
        self.running = False

# Update Bridge to handle network signals too
class EnhancedBridge(QObject):
    selection_received = pyqtSignal(str)
    network_request_received = pyqtSignal(str, str)
    network_request_detailed = pyqtSignal(str, str, str)
    
    @pyqtSlot(str)
    def receive_selection(self, data):
        self.selection_received.emit(data)

    @pyqtSlot(str, str, str)
    def report_xhr(self, method, url, headers_json):
        print(f"DEBUG: JS Proxy reported XHR: {method} {url}")
        self.network_request_detailed.emit(method, url, headers_json)
        # Also emit a basic entry so it appears in Network Monitor list
        self.network_request_received.emit(method, url)
        # We DO NOT emit received to avoid duplicates in the list, unless we are sure ApiSniffer missed it.
        # But since ApiSniffer filters catch XHR/Fetch, we assume it's there.
        # self.network_request_received.emit(method, url)

class CustomWebEnginePage(QWebEnginePage):
    def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
        print(f"JS Console: {message} [Line: {lineNumber}]")

# --- Main Window ---
class VisualSniffer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GovInfo Visual Sniffer & Collector")
        self.resize(1200, 800)
        
        self.is_closing = False
        self.inspector_enabled = False
        self.bridge = EnhancedBridge()
        self.bridge.selection_received.connect(self.on_selection)
        # Use QueuedConnection explicitly for cross-thread signals safety
        self.bridge.network_request_received.connect(self.log_network, Qt.ConnectionType.QueuedConnection)
        self.bridge.network_request_detailed.connect(self.on_network_detailed, Qt.ConnectionType.QueuedConnection)
        
        # Default Enable Network Monitor
        self.network_monitor_enabled = True
        
        self.qwc_injected = False
        self.inspector_injected = False
        self.recent_headers_by_url = {}
        self.last_selection = None
        
        # LogWorker (Deprecated/Unused for now)
        # self.log_worker = LogWorker()
        # self.log_worker.batch_ready.connect(self.add_log_batch, Qt.ConnectionType.QueuedConnection)
        # self.log_worker.start()
        # self.destroyed.connect(self.on_destroyed)
        
        self.setup_ui()
        self.setup_browser()

    def closeEvent(self, event):
        self.is_closing = True
        # Detach interceptor to prevent signals after window closure
        # Since we use defaultProfile, we must clean up
        try:
            if hasattr(self, 'profile') and self.profile:
                self.profile.setUrlRequestInterceptor(None)
        except Exception:
            pass
        try:
            self.bridge.network_request_received.disconnect(self.log_network)
        except Exception:
            pass
        try:
            self.log_worker.stop()
            self.log_worker.wait(1000)
        except Exception:
            pass
        event.accept()

    def on_destroyed(self):
        self.is_closing = True
        try:
            if hasattr(self, 'profile') and self.profile:
                self.profile.setUrlRequestInterceptor(None)
        except Exception:
            pass
        try:
            self.bridge.network_request_received.disconnect(self.log_network)
        except Exception:
            pass
        try:
            self.log_worker.stop()
            self.log_worker.wait(1000)
        except Exception:
            pass
        
    def setup_ui(self):
        # Main Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Toolbar
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        
        # Address Bar
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Enter URL here...")
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        toolbar.addWidget(self.url_bar)
        
        # Go Button
        go_btn = QPushButton("Go")
        go_btn.clicked.connect(self.navigate_to_url)
        toolbar.addWidget(go_btn)
        
        toolbar.addSeparator()
        
        # Inspector Toggle
        self.inspect_btn = QPushButton("Start Inspector")
        self.inspect_btn.setCheckable(True)
        self.inspect_btn.toggled.connect(self.toggle_inspector)
        toolbar.addWidget(self.inspect_btn)

        # Network Monitor Toggle
        self.net_btn = QPushButton("Network On")
        self.net_btn.setCheckable(True)
        self.net_btn.setChecked(True)
        self.net_btn.toggled.connect(self.toggle_network_monitor)
        toolbar.addWidget(self.net_btn)
        
        # Splitter (Browser | Info Panel)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)
        
        # Browser Container (Left Side)
        self.browser_container = QWidget()
        browser_layout = QVBoxLayout(self.browser_container)
        browser_layout.setContentsMargins(0, 0, 0, 0)
        splitter.addWidget(self.browser_container)
        
        # Right Side Container (Info Panel + Common Actions)
        right_side_widget = QWidget()
        right_side_layout = QVBoxLayout(right_side_widget)
        right_side_layout.setContentsMargins(0, 0, 0, 0)
        splitter.addWidget(right_side_widget)
        
        # Info Panel (Tabs)
        self.info_panel = QTabWidget()
        right_side_layout.addWidget(self.info_panel)
        
        # --- Tab 1: DOM Selector ---
        dom_widget = QWidget()
        dom_layout = QFormLayout(dom_widget)
        
        self.tag_label = QLabel("None")
        dom_layout.addRow("Selected Tag:", self.tag_label)
        
        self.xpath_edit = QLineEdit()
        dom_layout.addRow("Full XPath:", self.xpath_edit)
        
        self.smart_xpath_edit = QLineEdit()
        dom_layout.addRow("Smart/Content XPath:", self.smart_xpath_edit)
        
        self.title_xpath_edit = QLineEdit()
        self.title_xpath_edit.setPlaceholderText("Optional: XPath for Title")
        dom_layout.addRow("Title XPath:", self.title_xpath_edit)
        
        self.use_playwright_cb = QCheckBox("Use Playwright (Dynamic Rendering)")
        self.use_playwright_cb.setChecked(True)
        dom_layout.addRow("", self.use_playwright_cb)

        self.text_preview = QTextEdit()
        self.text_preview.setMaximumHeight(100)
        dom_layout.addRow("Text Preview:", self.text_preview)

        # DOM Action Buttons
        self.set_title_btn = QPushButton("设为标题XPath")
        self.set_title_btn.clicked.connect(self.set_title_from_selection)
        self.set_content_btn = QPushButton("设为内容XPath")
        self.set_content_btn.clicked.connect(self.set_content_from_selection)
        self.save_both_btn = QPushButton("保存标题+内容规则")
        self.save_both_btn.setStyleSheet("background-color: #ffc107; color: black;")
        self.save_both_btn.clicked.connect(self.save_title_content_rule)
        
        btn_row = QWidget()
        btn_row_layout = QHBoxLayout(btn_row)
        btn_row_layout.setContentsMargins(0,0,0,0)
        btn_row_layout.addWidget(self.set_title_btn)
        btn_row_layout.addWidget(self.set_content_btn)
        btn_row_layout.addWidget(self.save_both_btn)
        dom_layout.addRow("关联操作:", btn_row)
        
        self.info_panel.addTab(dom_widget, "DOM Inspector")
        
        # --- Tab 2: Network ---
        net_widget = QWidget()
        net_layout = QVBoxLayout(net_widget)
        
        net_layout.addWidget(QLabel("Double click to select API as source:"))
        self.net_list = QListWidget()
        self.net_list.itemDoubleClicked.connect(self.on_net_item_selected)
        net_layout.addWidget(self.net_list)
        
        self.info_panel.addTab(net_widget, "Network Monitor")
        
        # --- Common: Headers & Save ---
        common_widget = QWidget()
        common_layout = QVBoxLayout(common_widget)
        
        common_layout.addWidget(QLabel("Request Headers (JSON):"))
        self.headers_edit = QTextEdit()
        self.headers_edit.setMaximumHeight(80)
        self.headers_edit.setText('{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}')
        common_layout.addWidget(self.headers_edit)
        
        self.save_rule_btn = QPushButton("Save Rule to System")
        self.save_rule_btn.setStyleSheet("background-color: #28a745; color: white; font-weight: bold; padding: 5px;")
        self.save_rule_btn.clicked.connect(self.save_rule)
        common_layout.addWidget(self.save_rule_btn)
        
        self.fill_headers_btn = QPushButton("填充请求Headers")
        self.fill_headers_btn.setStyleSheet("background-color: #17a2b8; color: white;")
        self.fill_headers_btn.clicked.connect(self.fill_headers_from_selected_request)
        common_layout.addWidget(self.fill_headers_btn)
        
        self.fill_page_headers_btn = QPushButton("从当前页面Headers")
        self.fill_page_headers_btn.setStyleSheet("background-color: #6c757d; color: white;")
        self.fill_page_headers_btn.clicked.connect(self.fill_headers_from_current_page)
        common_layout.addWidget(self.fill_page_headers_btn)
        
        right_side_layout.addWidget(common_widget)
        
        # Set initial splitter sizes
        splitter.setSizes([800, 400])

        
    def setup_browser(self):
        self.browser = QWebEngineView()
        self.browser_container.layout().addWidget(self.browser)
        
        # Create custom profile and page to isolate interceptor
        self.profile = QWebEngineProfile("VisualSnifferProfile", self)
        self.interceptor = ApiSniffer(self.bridge)
        self.profile.setUrlRequestInterceptor(self.interceptor)

        self.page = CustomWebEnginePage(self.profile, self)
        self.browser.setPage(self.page)
        
        # Setup WebChannel on custom page
        self.channel = QWebChannel()
        self.channel.registerObject("bridge", self.bridge)
        self.page.setWebChannel(self.channel)
        
        
        
    def inject_qwebchannel(self):
        js_code = '''
            try {
              function loadQWC(){
                try{
                  if (typeof QWebChannel !== 'undefined') { return; }
                  var head = document.head || document.getElementsByTagName('head')[0];
                  if(!head){ return; }
                  var s = document.createElement('script');
                  s.src = 'qrc:///qtwebchannel/qwebchannel.js';
                  s.onload = function(){ window.QWebChannelReady = true; };
                  head.appendChild(s);
                }catch(e){ console.error('qwebchannel load error', e); }
              }
              if(document.readyState === 'loading'){
                document.addEventListener('DOMContentLoaded', loadQWC);
              } else {
                loadQWC();
              }
            } catch(e) { console.error('qwebchannel injection error', e); }
        '''
        script = QWebEngineScript()
        script.setSourceCode(js_code)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        self.profile.scripts().insert(script)
        # Execute immediately for current page
        self.browser.page().runJavaScript(js_code)

    def inject_inspector(self):
        # Load local inspector.js
        try:
            with open('sniffer_tool/inspector.js', 'r', encoding='utf-8') as f:
                js_content = f.read()
                
            script = QWebEngineScript()
            script.setSourceCode(js_content)
            script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentReady)
            script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
            self.profile.scripts().insert(script)
            # Execute immediately for current page
            self.browser.page().runJavaScript(js_content)
        except Exception as e:
            print(f"Failed to load inspector.js: {e}")

    def inject_network_proxy(self):
        js_code = '''
            (function() {
              if (window.networkProxyInjected) return;
              window.networkProxyInjected = true;
              
              function initProxy() {
                  if (typeof qt === 'undefined' || typeof qt.webChannelTransport === 'undefined' || typeof QWebChannel === 'undefined') {
                     setTimeout(initProxy, 100);
                     return;
                  }
                  new QWebChannel(qt.webChannelTransport, function(channel) {
                     var bridge = channel.objects.bridge;
                     
                     // XHR Proxy
                     var originalOpen = XMLHttpRequest.prototype.open;
                     var originalSend = XMLHttpRequest.prototype.send;
                     var originalSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;

                     XMLHttpRequest.prototype.open = function(method, url) {
                        this._method = method;
                        try {
                            this._url = new URL(url, window.location.href).href;
                        } catch(e) {
                            this._url = url;
                        }
                        this._requestHeaders = {};
                        return originalOpen.apply(this, arguments);
                     };

                     XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
                        this._requestHeaders[header] = value;
                        return originalSetRequestHeader.apply(this, arguments);
                     };

                     XMLHttpRequest.prototype.send = function(body) {
                        if (bridge) {
                            try {
                                bridge.report_xhr(this._method, this._url, JSON.stringify(this._requestHeaders));
                            } catch(e) { console.error(e); }
                        }
                        return originalSend.apply(this, arguments);
                     };

                     // Fetch Proxy
                     var originalFetch = window.fetch;
                     window.fetch = function(input, init) {
                        var method = 'GET';
                        var url = input;
                        var headers = {};
                        
                        if (typeof input === 'object' && input.url) {
                            url = input.url;
                            method = input.method || 'GET';
                        }
                        
                        try {
                            url = new URL(url, window.location.href).href;
                        } catch(e) { }

                        if (init) {
                            if (init.method) method = init.method;
                            if (init.headers) headers = init.headers;
                        }
                        
                        if (bridge) {
                             try {
                                var headerObj = {};
                                if (headers instanceof Headers) {
                                    headers.forEach((v, k) => headerObj[k] = v);
                                } else {
                                    headerObj = headers;
                                }
                                bridge.report_xhr(method, url, JSON.stringify(headerObj));
                            } catch(e) { console.error(e); }
                        }
                        
                        return originalFetch.apply(this, arguments);
                     };
                  });
              }
              if(document.readyState === 'loading'){
                document.addEventListener('DOMContentLoaded', initProxy);
              } else {
                initProxy();
              }
            })();
        '''
        script = QWebEngineScript()
        script.setSourceCode(js_code)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        self.profile.scripts().insert(script)
        # Execute immediately for current page
        self.browser.page().runJavaScript(js_code)

    def ensure_network_interceptor_injected(self):
        if not self.qwc_injected:
            self.inject_qwebchannel()
            self.qwc_injected = True
        if not hasattr(self, 'proxy_injected') or not self.proxy_injected:
            self.inject_network_proxy()
            self.proxy_injected = True

    def navigate_to_url(self):
        url = self.url_bar.text()
        if not url.startswith('http'):
            url = 'http://' + url
        self.browser.setUrl(QUrl(url))
        
    def toggle_inspector(self, checked):
        self.inspector_enabled = checked
        if checked:
            self.inspect_btn.setText("Stop Inspector")
            self.ensure_inspector_injected()
            self.browser.page().runJavaScript("window.inspectorEnabled = true;")
        else:
            self.inspect_btn.setText("Start Inspector")
            self.browser.page().runJavaScript("window.inspectorEnabled = false;")

    def toggle_network_monitor(self, checked):
        self.network_monitor_enabled = checked
        self.net_btn.setText("Network On" if checked else "Network Off")
        if checked:
            self.ensure_network_interceptor_injected()

    def ensure_inspector_injected(self):
        if not self.qwc_injected:
            self.inject_qwebchannel()
            self.qwc_injected = True
        if not self.inspector_injected:
            self.inject_inspector()
            self.inspector_injected = True
            
    def on_selection(self, data_str):
        if self.is_closing:
            return
        try:
            data = json.loads(data_str)
            self.last_selection = data
            self.tag_label.setText(f"{data.get('tag')} (Text len: {len(data.get('text', ''))})")
            self.xpath_edit.setText(data.get('xpath'))
            self.smart_xpath_edit.setText(data.get('smart_xpath'))
            self.text_preview.setText(data.get('text'))
            
            # Auto-fill Title XPath if it looks like a title
            if data.get('tag') in ['H1', 'TITLE']:
                self.title_xpath_edit.setText(data.get('smart_xpath'))
                
        except RuntimeError:
            pass
        except Exception as e:
            print(f"Error parsing selection: {e}")
            
    def log_network(self, method, url):
        # print(f"DEBUG: log_network called for {url}")
        if self.is_closing:
            return
        if not self.network_monitor_enabled:
            # print("DEBUG: Network monitor disabled, ignoring")
            return
            
        # Direct UI Update (Bypass LogWorker to fix missing items)
        try:
            item_text = f"[{method}] {url}"
            # Ensure we are on main thread (we are, via QueuedConnection)
            if hasattr(self, 'net_list'):
                self.net_list.addItem(item_text)
                # Auto-scroll if at bottom
                if self.net_list.count() > 0:
                    self.net_list.scrollToBottom()
                
                # Limit size to prevent memory issues
                while self.net_list.count() > 1000:
                    self.net_list.takeItem(0)
        except Exception as e:
            print(f"UI Update Error: {e}")

    def add_log_batch(self, batch):
        if self.is_closing or not batch:
            return
        try:
            if not hasattr(self, 'net_list') or not self.net_list:
                return
            try:
                _ = self.net_list.count()
            except RuntimeError:
                return
            self.net_list.addItems(batch)
            while self.net_list.count() > 2000:
                self.net_list.takeItem(0)
            self.net_list.scrollToBottom()
        except RuntimeError:
            pass
        except Exception:
            pass
        
    def on_net_item_selected(self, item):
        # User double clicked an API
        # Automatically fill headers
        self.fill_headers_from_selected_request()

    def set_title_from_selection(self):
        try:
            if self.last_selection:
                sx = self.last_selection.get('smart_xpath') or ''
                if sx:
                    self.title_xpath_edit.setText(sx)
                    QMessageBox.information(self, "提示", "已设置标题XPath")
        except Exception:
            pass

    def set_content_from_selection(self):
        try:
            if self.last_selection:
                sx = self.last_selection.get('smart_xpath') or ''
                if sx:
                    self.smart_xpath_edit.setText(sx)
                    QMessageBox.information(self, "提示", "已设置内容XPath")
        except Exception:
            pass

    def on_network_detailed(self, method, url, headers_json):
        if self.is_closing:
            return
        try:
            # print(f"DEBUG: Detailed headers received for {url}")
            # Merge headers logic
            old_json = self.recent_headers_by_url.get(url, '{}')
            
            if headers_json == '{}':
                return
            
            if old_json == '{}':
                self.recent_headers_by_url[url] = headers_json
                return
                
            # Try to merge
            try:
                new_h = json.loads(headers_json)
                old_h = json.loads(old_json)
                old_h.update(new_h)
                self.recent_headers_by_url[url] = json.dumps(old_h)
            except:
                # Fallback
                if len(headers_json) > len(old_json):
                    self.recent_headers_by_url[url] = headers_json
        except Exception:
            pass

    def fill_headers_from_selected_request(self):
        try:
            url = ''
            item = self.net_list.currentItem() if hasattr(self, 'net_list') else None
            if item:
                text = item.text()
                if '] ' in text:
                    url = text.split('] ', 1)[1]
            
            # DEBUG LOGGING
            print(f"DEBUG: Selecting URL: {url}")
            keys = list(self.recent_headers_by_url.keys())
            print(f"DEBUG: Available URLs in map: {len(keys)}")
            
            hj = self.recent_headers_by_url.get(url, '') if url else ''
            
            # If headers are found and not empty JSON
            if hj and hj != '{}':
                self.headers_edit.setText(hj)
                try:
                    if url:
                        self.recent_headers_by_url[url] = hj
                except Exception:
                    pass
                QMessageBox.information(self, "提示", f"已填充选中请求的Headers\nURL: {url}")
                return
            
            # Fallback: try same-origin headers
            try:
                parsed = urlparse(url) if url else None
                origin_host = parsed.netloc if parsed else ''
                if origin_host:
                    for k in reversed(keys):
                        try:
                            pk = urlparse(k)
                            if pk.netloc == origin_host:
                                alt = self.recent_headers_by_url.get(k, '')
                                if alt and alt != '{}':
                                    print(f"DEBUG: Using same-origin headers from {k}")
                                    self.headers_edit.setText(alt)
                                    try:
                                        if url:
                                            self.recent_headers_by_url[url] = alt
                                    except Exception:
                                        pass
                                    QMessageBox.information(self, "提示", f"已填充同源请求的Headers\nURL: {k}")
                                    return
                        except Exception:
                            continue
            except Exception:
                pass

            # Final fallback: build best-effort headers from page context
            self.collect_best_effort_headers(url)
            QMessageBox.information(self, "提示", "已填充同源可用请求头（包含 User-Agent/Cookie/Referer 等）。")
        except Exception:
            pass

    def fill_headers_from_current_page(self):
        try:
            url = ''
            try:
                q = self.browser.url()
                url = q.toString() if hasattr(q, 'toString') else str(q)
            except Exception:
                url = ''
            hj = self.recent_headers_by_url.get(url, '') if url else ''
            if hj:
                self.headers_edit.setText(hj)
                try:
                    if url:
                        self.recent_headers_by_url[url] = hj
                except Exception:
                    pass
                QMessageBox.information(self, "提示", "已填充当前页面的Headers")
                return
            self.collect_best_effort_headers(url)
            QMessageBox.information(self, "提示", "已填充同源可用请求头（包含 User-Agent/Cookie/Referer 等）")
        except Exception:
            pass

    def collect_best_effort_headers(self, referer_url):
        try:

            js = """
            (function(){
              var ua = navigator.userAgent || "";
              var ref = window.location.href || "";
              var lang = (navigator.languages && navigator.languages[0]) || navigator.language || "";
              var cookie = document.cookie || "";
              var h = {
                 "User-Agent": ua,
                 "Referer": ref,
                 "Accept": "*/*",
                 "Accept-Language": lang,
                 "Cookie": cookie
              };
              return JSON.stringify(h);
            })();
            """
            def cb(v):
                try:
                    if isinstance(v, str) and v:
                        self.headers_edit.setText(v)
                        try:
                            if referer_url:
                                self.recent_headers_by_url[referer_url] = v
                        except Exception:
                            pass
                    else:
                        self.headers_edit.setText(json.dumps({"User-Agent": ""}))
                except Exception:
                    pass
            self.browser.page().runJavaScript(js, cb)
        except Exception:
            pass

    def save_title_content_rule(self):
        try:
            url_val = self.url_bar.text()
            rule_name, ok = QInputDialog.getText(self, "保存规则", "规则名称:")
            if not ok or not rule_name:
                return
            title_xpath = self.title_xpath_edit.text()
            content_xpath = self.smart_xpath_edit.text()
            if not content_xpath:
                QMessageBox.warning(self, "错误", "请先选择内容XPath")
                return
            if self.use_playwright_cb.isChecked():
                content_xpath = f"DOM:{content_xpath}"
            request_headers = self.headers_edit.toPlainText()
            payload = {
                "url": url_val,
                "rule_name": rule_name,
                "title_xpath": title_xpath,
                "content_xpath": content_xpath,
                "request_headers": request_headers
            }
            api_endpoint = "http://127.0.0.1:5000/rule/save"
            headers = {"X-Internal-Token": "sniffer-secret-123"}
            response = requests.post(api_endpoint, json=payload, headers=headers, timeout=5)
            if response.status_code == 200:
                QMessageBox.information(self, "成功", f"规则 '{rule_name}' 已保存")
            elif response.status_code == 401:
                QMessageBox.warning(self, "鉴权错误", "需要认证或配置内部令牌")
            else:
                try:
                    err_msg = response.json().get('error', response.text)
                except Exception:
                    err_msg = response.text
                QMessageBox.critical(self, "错误", f"保存失败: {err_msg}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"连接错误: {e}")

    def save_rule(self):
        current_tab_idx = self.info_panel.currentIndex()
        url_val = self.url_bar.text()
        
        # Get Rule Name
        rule_name, ok = QInputDialog.getText(self, "Save Rule", "Enter Rule Name:")
        if not ok or not rule_name:
            return

        content_xpath = ""
        title_xpath = self.title_xpath_edit.text()
        request_headers = self.headers_edit.toPlainText()
        
        # Logic: Check which tab is active
        if current_tab_idx == 1: # Network Tab
            item = self.net_list.currentItem()
            if not item:
                QMessageBox.warning(self, "Error", "Please select an API request from the list first.")
                return
            api_url = item.text().split('] ', 1)[1]
            content_xpath = f"API:{api_url}"
        else: # DOM Tab
            xpath = self.smart_xpath_edit.text()
            if not xpath:
                QMessageBox.warning(self, "Error", "No XPath selected")
                return
            
            # Check if Playwright mode is requested
            if self.use_playwright_cb.isChecked():
                content_xpath = f"DOM:{xpath}"
            else:
                content_xpath = xpath
        
        payload = {
            "url": url_val,
            "rule_name": rule_name,
            "title_xpath": title_xpath,
            "content_xpath": content_xpath,
            "request_headers": request_headers
        }
        
        try:
            # Assuming Flask runs on default port 5000
            api_endpoint = "http://127.0.0.1:5000/rule/save"
            
            # Add internal token for auth bypass
            headers = {"X-Internal-Token": "sniffer-secret-123"}
            response = requests.post(api_endpoint, json=payload, headers=headers, timeout=5)
            
            if response.status_code == 200:
                QMessageBox.information(self, "Success", f"Rule '{rule_name}' saved successfully!")
            elif response.status_code == 401:
                 QMessageBox.warning(self, "Auth Error", "Authentication required.\nFor this prototype tool, please ensure the backend '/rule/save' endpoint allows access or you implement API Token auth.")
            else:
                try:
                    err_msg = response.json().get('error', response.text)
                except:
                    err_msg = response.text
                QMessageBox.critical(self, "Error", f"Failed to save rule: {err_msg}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Connection error: {e}")

if __name__ == '__main__':
    # Minimal, compatible flags for Windows/Remote Desktop (NO GPU)
    os.environ.setdefault('QTWEBENGINE_DISABLE_SANDBOX', '1')
    os.environ.setdefault('QT_OPENGL', 'software')
    # Append robust NO-GPU flags
    existing_flags = os.environ.get('QTWEBENGINE_CHROMIUM_FLAGS', '')
    nogpu_flags = [
        '--disable-gpu',
        '--disable-gpu-compositing',
        '--disable-features=UseSkiaRenderer,CanvasOopRasterization,Accelerated2dCanvas,ZeroCopy,VaapiVideoDecoder',
        '--in-process-gpu'
    ]
    # Merge flags without duplicates
    merged = existing_flags.split() + [f for f in nogpu_flags if f not in existing_flags.split()]
    os.environ['QTWEBENGINE_CHROMIUM_FLAGS'] = ' '.join(merged).strip()
    try:
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseSoftwareOpenGL)
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts)
    except Exception:
        pass

    app = QApplication(sys.argv)
    try:
        QtWebEngineCore.initialize()
    except Exception:
        pass
    window = VisualSniffer()
    if len(sys.argv) > 1:
        url = sys.argv[1]
        window.url_bar.setText(url)
    window.show()
    sys.exit(app.exec())
