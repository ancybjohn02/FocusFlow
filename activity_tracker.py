#!/usr/bin/env python3
"""
Comprehensive Activity Tracker
Monitors window activity, browser history, network traffic, and file system changes
"""

import os
import sys
import time
import sqlite3
import threading
import subprocess
from datetime import datetime
from pathlib import Path
import json

# Required installations:
# pip install psutil watchdog scapy

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    from scapy.all import sniff, IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Network monitoring disabled.")

class Colors:
    """Terminal colors for better output formatting"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class WindowMonitor:
    """Monitor active windows and applications"""
    
    def __init__(self):
        self.current_window = None
        self.running = True
    
    def get_active_window_linux(self):
        """Get active window info on Linux"""
        try:
            # Get active window ID
            result = subprocess.run(['xdotool', 'getactivewindow'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                window_id = result.stdout.strip()
                
                # Get window name
                result = subprocess.run(['xdotool', 'getwindowname', window_id], 
                                      capture_output=True, text=True)
                window_name = result.stdout.strip() if result.returncode == 0 else "Unknown"
                
                # Get process info
                result = subprocess.run(['xdotool', 'getwindowpid', window_id], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    pid = int(result.stdout.strip())
                    process = psutil.Process(pid)
                    return {
                        'title': window_name,
                        'process': process.name(),
                        'pid': pid
                    }
        except Exception as e:
            pass
        return None
    
    def get_active_window_mac(self):
        """Get active window info on macOS"""
        try:
            script = '''
            tell application "System Events"
                set frontApp to first application process whose frontmost is true
                set appName to name of frontApp
                try
                    set windowTitle to name of front window of frontApp
                on error
                    set windowTitle to appName
                end try
                return appName & "|" & windowTitle
            end tell
            '''
            result = subprocess.run(['osascript', '-e', script], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                parts = result.stdout.strip().split('|', 1)
                return {
                    'title': parts[1] if len(parts) > 1 else parts[0],
                    'process': parts[0],
                    'pid': None
                }
        except Exception as e:
            pass
        return None
    
    def get_active_window_windows(self):
        """Get active window info on Windows"""
        try:
            import win32gui
            import win32process
            
            hwnd = win32gui.GetForegroundWindow()
            window_title = win32gui.GetWindowText(hwnd)
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            process = psutil.Process(pid)
            
            return {
                'title': window_title,
                'process': process.name(),
                'pid': pid
            }
        except Exception as e:
            pass
        return None
    
    def get_active_window(self):
        """Get active window info cross-platform"""
        system = sys.platform.lower()
        
        if system.startswith('linux'):
            return self.get_active_window_linux()
        elif system.startswith('darwin'):  # macOS
            return self.get_active_window_mac()
        elif system.startswith('win'):
            return self.get_active_window_windows()
        else:
            return None
    
    def start_monitoring(self):
        """Start window monitoring loop"""
        print(f"{Colors.HEADER}🪟 Window Monitor Started{Colors.ENDC}")
        
        while self.running:
            try:
                window_info = self.get_active_window()
                
                if window_info and window_info != self.current_window:
                    self.current_window = window_info
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    
                    print(f"{Colors.OKBLUE}[{timestamp}] WINDOW: {Colors.ENDC}"
                          f"{Colors.BOLD}{window_info['process']}{Colors.ENDC} - "
                          f"{window_info['title'][:60]}...")
                
                time.sleep(2)  # Check every 2 seconds
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{Colors.FAIL}Window monitoring error: {e}{Colors.ENDC}")
                time.sleep(5)

class BrowserHistoryAnalyzer:
    """Analyze browser history from various browsers"""
    
    def __init__(self):
        self.browsers = {
            'Chrome': self.get_chrome_history,
            'Firefox': self.get_firefox_history,
            'Safari': self.get_safari_history,
            'Edge': self.get_edge_history
        }
        self.last_check = {}
    
    def get_chrome_history(self):
        """Get Chrome browser history"""
        paths = []
        
        if sys.platform.startswith('win'):
            paths.append(os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\History'))
        elif sys.platform.startswith('darwin'):
            paths.append(os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/History'))
        else:  # Linux
            paths.append(os.path.expanduser('~/.config/google-chrome/Default/History'))
        
        return self.read_chromium_history(paths)
    
    def get_edge_history(self):
        """Get Edge browser history"""
        paths = []
        
        if sys.platform.startswith('win'):
            paths.append(os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History'))
        elif sys.platform.startswith('darwin'):
            paths.append(os.path.expanduser('~/Library/Application Support/Microsoft Edge/Default/History'))
        else:  # Linux
            paths.append(os.path.expanduser('~/.config/microsoft-edge/Default/History'))
        
        return self.read_chromium_history(paths)
    
    def read_chromium_history(self, paths):
        """Read history from Chromium-based browsers"""
        entries = []
        
        for path in paths:
            if os.path.exists(path):
                try:
                    # Copy to temp file (Chrome locks the original)
                    temp_path = f"{path}.temp"
                    import shutil
                    shutil.copy2(path, temp_path)
                    
                    conn = sqlite3.connect(temp_path)
                    cursor = conn.execute("""
                        SELECT url, title, visit_count, last_visit_time 
                        FROM urls 
                        ORDER BY last_visit_time DESC 
                        LIMIT 50
                    """)
                    
                    for row in cursor.fetchall():
                        # Convert Chrome timestamp to datetime
                        timestamp = datetime.fromtimestamp((row[3] - 11644473600000000) / 1000000)
                        entries.append({
                            'url': row[0],
                            'title': row[1] or 'No Title',
                            'visit_count': row[2],
                            'timestamp': timestamp
                        })
                    
                    conn.close()
                    os.remove(temp_path)
                    break
                    
                except Exception as e:
                    print(f"{Colors.WARNING}Error reading Chrome history: {e}{Colors.ENDC}")
                    try:
                        os.remove(temp_path)
                    except:
                        pass
        
        return entries
    
    def get_firefox_history(self):
        """Get Firefox browser history"""
        entries = []
        
        if sys.platform.startswith('win'):
            profile_path = os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles')
        elif sys.platform.startswith('darwin'):
            profile_path = os.path.expanduser('~/Library/Application Support/Firefox/Profiles')
        else:  # Linux
            profile_path = os.path.expanduser('~/.mozilla/firefox')
        
        if os.path.exists(profile_path):
            for profile_dir in os.listdir(profile_path):
                places_db = os.path.join(profile_path, profile_dir, 'places.sqlite')
                
                if os.path.exists(places_db):
                    try:
                        conn = sqlite3.connect(places_db)
                        cursor = conn.execute("""
                            SELECT h.url, h.title, h.visit_count, h.last_visit_date
                            FROM moz_places h
                            WHERE h.last_visit_date IS NOT NULL
                            ORDER BY h.last_visit_date DESC
                            LIMIT 50
                        """)
                        
                        for row in cursor.fetchall():
                            if row[3]:
                                timestamp = datetime.fromtimestamp(row[3] / 1000000)
                                entries.append({
                                    'url': row[0],
                                    'title': row[1] or 'No Title',
                                    'visit_count': row[2],
                                    'timestamp': timestamp
                                })
                        
                        conn.close()
                        break
                        
                    except Exception as e:
                        print(f"{Colors.WARNING}Error reading Firefox history: {e}{Colors.ENDC}")
        
        return entries
    
    def get_safari_history(self):
        """Get Safari browser history (macOS only)"""
        entries = []
        
        if not sys.platform.startswith('darwin'):
            return entries
        
        history_path = os.path.expanduser('~/Library/Safari/History.db')
        
        if os.path.exists(history_path):
            try:
                conn = sqlite3.connect(history_path)
                cursor = conn.execute("""
                    SELECT url, title, visit_count, visit_time
                    FROM history_visits hv
                    JOIN history_items hi ON hv.history_item = hi.id
                    ORDER BY visit_time DESC
                    LIMIT 50
                """)
                
                for row in cursor.fetchall():
                    # Safari uses different timestamp format
                    timestamp = datetime.fromtimestamp(row[3] + 978307200)  # Safari epoch adjustment
                    entries.append({
                        'url': row[0],
                        'title': row[1] or 'No Title',
                        'visit_count': row[2],
                        'timestamp': timestamp
                    })
                
                conn.close()
                
            except Exception as e:
                print(f"{Colors.WARNING}Error reading Safari history: {e}{Colors.ENDC}")
        
        return entries
    
    def analyze_recent_history(self):
        """Analyze recent browser history"""
        print(f"{Colors.HEADER}🌐 Browser History Analysis{Colors.ENDC}")
        
        for browser_name, get_history_func in self.browsers.items():
            entries = get_history_func()
            
            if entries:
                print(f"\n{Colors.OKCYAN}📊 {browser_name} - Recent Activity:{Colors.ENDC}")
                
                # Show last 10 entries
                for entry in entries[:10]:
                    timestamp = entry['timestamp'].strftime("%H:%M:%S")
                    title = entry['title'][:50] + "..." if len(entry['title']) > 50 else entry['title']
                    domain = entry['url'].split('/')[2] if len(entry['url'].split('/')) > 2 else entry['url']
                    
                    print(f"  [{timestamp}] {Colors.OKGREEN}{domain}{Colors.ENDC} - {title}")

class NetworkMonitor:
    """Monitor network traffic"""
    
    def __init__(self):
        self.running = True
        self.connections = set()
    
    def packet_callback(self, packet):
        """Callback for packet analysis"""
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            
            # Filter out local traffic
            if not (src_ip.startswith('127.') or dst_ip.startswith('127.')):
                connection = f"{dst_ip}:{dst_port}"
                
                if connection not in self.connections:
                    self.connections.add(connection)
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    
                    # Try to identify service by port
                    service = self.identify_service(dst_port)
                    
                    print(f"{Colors.WARNING}[{timestamp}] NETWORK: {Colors.ENDC}"
                          f"{dst_ip}:{dst_port} ({service})")
    
    def identify_service(self, port):
        """Identify service by port number"""
        common_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            53: 'DNS',
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            993: 'IMAPS',
            995: 'POP3S'
        }
        return common_ports.get(port, 'Unknown')
    
    def start_monitoring(self):
        """Start network monitoring"""
        if not SCAPY_AVAILABLE:
            print(f"{Colors.FAIL}Network monitoring unavailable - Scapy not installed{Colors.ENDC}")
            return
        
        print(f"{Colors.HEADER}🌐 Network Monitor Started{Colors.ENDC}")
        print(f"{Colors.WARNING}Note: May require root/admin privileges{Colors.ENDC}")
        
        try:
            sniff(prn=self.packet_callback, store=0)
        except PermissionError:
            print(f"{Colors.FAIL}Permission denied - try running as admin/root{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}Network monitoring error: {e}{Colors.ENDC}")

class FileSystemWatcher:
    """Monitor file system changes"""
    
    def __init__(self, watch_paths=None):
        self.watch_paths = watch_paths or [
            os.path.expanduser('~/Documents'),
            os.path.expanduser('~/Desktop'),
            os.path.expanduser('~/Downloads'),
            os.getcwd()  # Current directory
        ]
        self.observer = Observer()
    
    def start_monitoring(self):
        """Start file system monitoring"""
        print(f"{Colors.HEADER}📁 File System Monitor Started{Colors.ENDC}")
        
        event_handler = FileChangeHandler()
        
        for path in self.watch_paths:
            if os.path.exists(path):
                print(f"  Watching: {path}")
                self.observer.schedule(event_handler, path, recursive=True)
        
        self.observer.start()
        return self.observer

class FileChangeHandler(FileSystemEventHandler):
    """Handle file system events"""
    
    def __init__(self):
        self.ignored_extensions = {'.tmp', '.log', '.swp', '.lock', '.DS_Store'}
        self.last_event_time = {}
    
    def should_ignore(self, path):
        """Check if file should be ignored"""
        file_path = Path(path)
        
        # Ignore system files and temporary files
        if file_path.suffix in self.ignored_extensions:
            return True
        
        if file_path.name.startswith('.'):
            return True
        
        # Rate limiting - ignore rapid successive events
        now = time.time()
        if path in self.last_event_time:
            if now - self.last_event_time[path] < 1:  # 1 second cooldown
                return True
        
        self.last_event_time[path] = now
        return False
    
    def on_modified(self, event):
        if not event.is_directory and not self.should_ignore(event.src_path):
            timestamp = datetime.now().strftime("%H:%M:%S")
            filename = os.path.basename(event.src_path)
            
            print(f"{Colors.OKGREEN}[{timestamp}] FILE MODIFIED: {Colors.ENDC}{filename}")
    
    def on_created(self, event):
        if not event.is_directory and not self.should_ignore(event.src_path):
            timestamp = datetime.now().strftime("%H:%M:%S")
            filename = os.path.basename(event.src_path)
            
            print(f"{Colors.OKCYAN}[{timestamp}] FILE CREATED: {Colors.ENDC}{filename}")
    
    def on_deleted(self, event):
        if not event.is_directory and not self.should_ignore(event.src_path):
            timestamp = datetime.now().strftime("%H:%M:%S")
            filename = os.path.basename(event.src_path)
            
            print(f"{Colors.FAIL}[{timestamp}] FILE DELETED: {Colors.ENDC}{filename}")

class ActivityTracker:
    """Main activity tracker class"""
    
    def __init__(self):
        self.window_monitor = WindowMonitor()
        self.browser_analyzer = BrowserHistoryAnalyzer()
        self.network_monitor = NetworkMonitor()
        self.file_watcher = FileSystemWatcher()
        self.running = True
    
    def start_all_monitors(self):
        """Start all monitoring threads"""
        print(f"{Colors.BOLD}🚀 Activity Tracker Starting...{Colors.ENDC}\n")
        
        # Start file system monitoring
        file_observer = self.file_watcher.start_monitoring()
        
        # Start window monitoring in a thread
        window_thread = threading.Thread(target=self.window_monitor.start_monitoring, daemon=True)
        window_thread.start()
        
        # Start network monitoring in a thread (optional)
        if SCAPY_AVAILABLE:
            network_thread = threading.Thread(target=self.network_monitor.start_monitoring, daemon=True)
            network_thread.start()
        
        # Analyze browser history periodically
        try:
            while self.running:
                time.sleep(30)  # Check browser history every 30 seconds
                self.browser_analyzer.analyze_recent_history()
                print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}🛑 Stopping Activity Tracker...{Colors.ENDC}")
            self.window_monitor.running = False
            self.network_monitor.running = False
            file_observer.stop()
            file_observer.join()

def main():
    """Main function"""
    print(f"{Colors.BOLD}Activity Tracker - System Monitor{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*50}{Colors.ENDC}")
    
    # Check dependencies
    missing_deps = []
    
    try:
        import psutil
    except ImportError:
        missing_deps.append('psutil')
    
    try:
        from watchdog.observers import Observer
    except ImportError:
        missing_deps.append('watchdog')
    
    if missing_deps:
        print(f"{Colors.FAIL}Missing dependencies: {', '.join(missing_deps)}{Colors.ENDC}")
        print(f"Install with: pip install {' '.join(missing_deps)}")
        return
    
    # Check OS-specific tools
    if sys.platform.startswith('linux'):
        if not subprocess.run(['which', 'xdotool'], capture_output=True).returncode == 0:
            print(f"{Colors.WARNING}Warning: xdotool not found. Install with: sudo apt-get install xdotool{Colors.ENDC}")
    
    tracker = ActivityTracker()
    tracker.start_all_monitors()

if __name__ == "__main__":
    main()