#!/usr/bin/env python3
"""
Enhanced Focus Tracker with Time Analysis and Goal-Based Classification
Built on top of the comprehensive activity tracker
"""

import os
import sys
import time
import sqlite3
import threading
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import hashlib

# Your existing imports
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    from scapy.all import sniff, IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Enhanced color scheme
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    # Focus-specific colors
    DIRECT = '\033[92m'      # Green
    PERIPHERAL = '\033[93m'  # Yellow
    INDIRECT = '\033[94m'    # Blue
    DISTRACTION = '\033[91m' # Red

@dataclass
class FocusSession:
    """Data class for focus session tracking"""
    goal: str
    start_time: datetime
    end_time: Optional[datetime] = None
    activities: List = None
    
    def __post_init__(self):
        if self.activities is None:
            self.activities = []
    
    @property
    def duration(self) -> timedelta:
        end = self.end_time or datetime.now()
        return end - self.start_time

@dataclass
class Activity:
    """Individual activity within a focus session"""
    timestamp: datetime
    title: str
    process: str
    url: Optional[str] = None
    classification: str = "UNKNOWN"
    relevance_score: float = 0.0
    duration: Optional[timedelta] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []

class ContentAnalyzer:
    """Analyze content for relevance to study goals"""
    
    def __init__(self):
        # Educational domains and patterns
        self.educational_domains = {
            'youtube.com': 0.7,  # Neutral - depends on content
            'coursera.org': 0.95,
            'edx.org': 0.95,
            'khanacademy.org': 0.95,
            'arxiv.org': 0.90,
            'wikipedia.org': 0.80,
            'stackoverflow.com': 0.85,
            'github.com': 0.80,
            'medium.com': 0.60,  # Depends on content
            'towardsdatascience.com': 0.85,
            'papers.with code.com': 0.90,
            'scholar.google.com': 0.90,
            'researchgate.net': 0.85,
        }
        
        self.distraction_domains = {
            'facebook.com': 0.05,
            'twitter.com': 0.10,
            'instagram.com': 0.05,
            'tiktok.com': 0.05,
            'reddit.com': 0.20,  # Can have educational content
            'netflix.com': 0.05,
            'twitch.tv': 0.10,
            'gaming': 0.15,
        }
        
        # Keywords for different subjects
        self.subject_keywords = {
            'deep_learning': [
                'neural network', 'deep learning', 'machine learning', 'CNN', 'RNN', 'LSTM',
                'transformer', 'attention', 'backpropagation', 'gradient descent', 'tensorflow',
                'pytorch', 'keras', 'artificial intelligence', 'AI', 'computer vision', 'NLP'
            ],
            'astrophysics': [
                'astrophysics', 'cosmology', 'black hole', 'galaxy', 'star formation',
                'dark matter', 'universe', 'astronomy', 'telescope', 'NASA', 'space'
            ],
            'quantum': [
                'quantum computing', 'quantum mechanics', 'qubit', 'superposition',
                'entanglement', 'quantum algorithm', 'quantum physics'
            ]
        }
    
    def extract_domain(self, title: str, process: str) -> str:
        """Extract domain from window title or process"""
        # Common browser title patterns
        browser_patterns = [
            r'- ([^-]+\.com)',  # "Title - domain.com - Browser"
            r'([^|\s]+\.[a-z]{2,4})',  # Basic domain matching
            r'YouTube',  # Direct platform mentions
            r'Wikipedia',
            r'GitHub',
            r'Stack Overflow'
        ]
        
        title_lower = title.lower()
        
        # Direct domain extraction from title
        for pattern in browser_patterns:
            match = re.search(pattern, title, re.IGNORECASE)
            if match:
                return match.group(1).lower()
        
        # Platform detection
        if 'youtube' in title_lower:
            return 'youtube.com'
        elif 'wikipedia' in title_lower:
            return 'wikipedia.org'
        elif 'stack overflow' in title_lower:
            return 'stackoverflow.com'
        elif 'github' in title_lower:
            return 'github.com'
        
        return process.lower()
    
    def calculate_relevance_score(self, title: str, goal: str, domain: str) -> Tuple[float, str]:
        """Calculate how relevant content is to the study goal"""
        title_lower = title.lower()
        goal_lower = goal.lower()
        
        # Base score from domain
        base_score = self.educational_domains.get(domain, 0.5)
        
        # Penalty for known distraction domains
        if domain in self.distraction_domains:
            base_score = self.distraction_domains[domain]
        
        # Content analysis based on goal
        content_score = 0.0
        matching_keywords = []
        
        # Find relevant keyword set based on goal
        goal_keywords = []
        for subject, keywords in self.subject_keywords.items():
            if any(keyword in goal_lower for keyword in keywords):
                goal_keywords.extend(keywords)
                break
        
        # If no predefined keywords, use goal words directly
        if not goal_keywords:
            goal_keywords = goal_lower.split()
        
        # Check for keyword matches in title
        for keyword in goal_keywords:
            if keyword.lower() in title_lower:
                content_score += 0.1
                matching_keywords.append(keyword)
        
        # Combine scores
        final_score = min((base_score + content_score) / 2, 1.0)
        
        # Classification
        if final_score >= 0.8:
            classification = "DIRECT"
        elif final_score >= 0.6:
            classification = "PERIPHERAL"
        elif final_score >= 0.3:
            classification = "INDIRECT"
        else:
            classification = "DISTRACTION"
        
        return final_score, classification

class FocusDatabase:
    """Database management for focus sessions"""
    
    def __init__(self, db_path: str = "focus_tracker.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the focus tracking database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                goal TEXT NOT NULL,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                total_duration INTEGER,
                focus_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Activities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                timestamp TIMESTAMP NOT NULL,
                title TEXT NOT NULL,
                process TEXT NOT NULL,
                url TEXT,
                classification TEXT NOT NULL,
                relevance_score REAL NOT NULL,
                duration INTEGER,
                tags TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_session(self, session: FocusSession) -> int:
        """Save a focus session to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO sessions (goal, start_time, end_time, total_duration)
            VALUES (?, ?, ?, ?)
        ''', (
            session.goal,
            session.start_time,
            session.end_time,
            int(session.duration.total_seconds()) if session.end_time else None
        ))
        
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return session_id
    
    def save_activity(self, session_id: int, activity: Activity):
        """Save an activity to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO activities 
            (session_id, timestamp, title, process, url, classification, 
             relevance_score, duration, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            activity.timestamp,
            activity.title,
            activity.process,
            activity.url,
            activity.classification,
            activity.relevance_score,
            int(activity.duration.total_seconds()) if activity.duration else None,
            ','.join(activity.tags) if activity.tags else None
        ))
        
        conn.commit()
        conn.close()

class EnhancedWindowMonitor:
    """Enhanced window monitor with time tracking and focus analysis"""
    
    def __init__(self, content_analyzer: ContentAnalyzer, database: FocusDatabase):
        self.content_analyzer = content_analyzer
        self.database = database
        self.current_session: Optional[FocusSession] = None
        self.current_activity: Optional[Activity] = None
        self.last_window_info = None
        self.activity_start_time = None
        self.running = True
        
        # Time tracking
        self.session_stats = {
            'DIRECT': timedelta(),
            'PERIPHERAL': timedelta(),
            'INDIRECT': timedelta(),
            'DISTRACTION': timedelta()
        }
        
        # Recent activities for pattern analysis
        self.recent_activities = deque(maxlen=50)
        
        # Context switching tracking
        self.context_switches = 0
        self.last_classification = None
    
    def start_session(self, goal: str):
        """Start a new focus session"""
        if self.current_session:
            self.end_session()
        
        self.current_session = FocusSession(
            goal=goal,
            start_time=datetime.now()
        )
        
        # Reset session stats
        self.session_stats = {k: timedelta() for k in self.session_stats}
        self.context_switches = 0
        self.recent_activities.clear()
        
        print(f"\n{Colors.HEADER}🎯 FOCUS SESSION STARTED{Colors.ENDC}")
        print(f"Goal: {Colors.BOLD}{goal}{Colors.ENDC}")
        print(f"Started: {self.current_session.start_time.strftime('%H:%M:%S')}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    
    def end_session(self):
        """End the current focus session"""
        if not self.current_session:
            return
        
        # Finalize current activity
        if self.current_activity and self.activity_start_time:
            duration = datetime.now() - self.activity_start_time
            self.current_activity.duration = duration
            self.session_stats[self.current_activity.classification] += duration
        
        self.current_session.end_time = datetime.now()
        
        # Save to database
        session_id = self.database.save_session(self.current_session)
        for activity in self.current_session.activities:
            self.database.save_activity(session_id, activity)
        
        # Display session summary
        self.display_session_summary()
        
        self.current_session = None
    
    def get_active_window(self):
        """Get active window info (using your existing cross-platform method)"""
        system = sys.platform.lower()
        
        if system.startswith('linux'):
            return self.get_active_window_linux()
        elif system.startswith('darwin'):
            return self.get_active_window_mac()
        elif system.startswith('win'):
            return self.get_active_window_windows()
        else:
            return None
    
    def get_active_window_linux(self):
        """Linux window detection"""
        try:
            result = subprocess.run(['xdotool', 'getactivewindow'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                window_id = result.stdout.strip()
                
                result = subprocess.run(['xdotool', 'getwindowname', window_id], 
                                      capture_output=True, text=True)
                window_name = result.stdout.strip() if result.returncode == 0 else "Unknown"
                
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
        except Exception:
            pass
        return None
    
    def get_active_window_mac(self):
        """macOS window detection"""
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
        except Exception:
            pass
        return None
    
    def get_active_window_windows(self):
        """Windows window detection"""
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
        except Exception:
            pass
        return None
    
    def process_window_change(self, window_info):
        """Process a window change event"""
        if not self.current_session:
            return
        
        now = datetime.now()
        
        # Finalize previous activity
        if self.current_activity and self.activity_start_time:
            duration = now - self.activity_start_time
            self.current_activity.duration = duration
            self.session_stats[self.current_activity.classification] += duration
            self.current_session.activities.append(self.current_activity)
            self.recent_activities.append(self.current_activity)
        
        # Analyze new activity
        domain = self.content_analyzer.extract_domain(window_info['title'], window_info['process'])
        relevance_score, classification = self.content_analyzer.calculate_relevance_score(
            window_info['title'], 
            self.current_session.goal,
            domain
        )
        
        # Create new activity
        self.current_activity = Activity(
            timestamp=now,
            title=window_info['title'],
            process=window_info['process'],
            url=domain,
            classification=classification,
            relevance_score=relevance_score,
            tags=[domain]
        )
        
        self.activity_start_time = now
        
        # Track context switches
        if self.last_classification and self.last_classification != classification:
            self.context_switches += 1
        self.last_classification = classification
        
        # Display current activity
        self.display_current_activity()
        
        # Check for alerts
        self.check_focus_alerts()
    
    def display_current_activity(self):
        """Display current activity with focus classification"""
        if not self.current_activity:
            return
        
        timestamp = self.current_activity.timestamp.strftime("%H:%M:%S")
        classification = self.current_activity.classification
        score = self.current_activity.relevance_score
        title = self.current_activity.title[:60] + "..." if len(self.current_activity.title) > 60 else self.current_activity.title
        
        # Color coding based on classification
        color = {
            'DIRECT': Colors.DIRECT,
            'PERIPHERAL': Colors.WARNING,
            'INDIRECT': Colors.OKBLUE,
            'DISTRACTION': Colors.FAIL
        }.get(classification, Colors.ENDC)
        
        emoji = {
            'DIRECT': '🟢',
            'PERIPHERAL': '🟡',
            'INDIRECT': '🟠',
            'DISTRACTION': '🔴'
        }.get(classification, '⚪')
        
        print(f"\n{color}[{timestamp}] {emoji} {classification} ({score:.2f}){Colors.ENDC}")
        print(f"🌐 {self.current_activity.process}: \"{title}\"")
        
        # Show session progress
        if len(self.recent_activities) > 0:
            total_time = sum((a.duration for a in self.recent_activities if a.duration), timedelta())
            if total_time.total_seconds() > 0:
                focus_time = sum((a.duration for a in self.recent_activities 
                                if a.classification == 'DIRECT' and a.duration), timedelta())
                focus_percentage = (focus_time.total_seconds() / total_time.total_seconds()) * 100
                print(f"📊 Session Focus: {focus_percentage:.1f}% | Switches: {self.context_switches}")
    
    def check_focus_alerts(self):
        """Check for focus-related alerts"""
        if not self.current_activity or len(self.recent_activities) < 3:
            return
        
        # Check for topic drift
        recent_classifications = [a.classification for a in list(self.recent_activities)[-3:]]
        if 'DISTRACTION' in recent_classifications:
            if recent_classifications.count('DISTRACTION') >= 2:
                print(f"{Colors.FAIL}⚠️  FOCUS ALERT: Multiple distractions detected{Colors.ENDC}")
        
        # Check for prolonged low relevance
        recent_scores = [a.relevance_score for a in list(self.recent_activities)[-5:]]
        if len(recent_scores) >= 5 and sum(recent_scores) / len(recent_scores) < 0.4:
            print(f"{Colors.WARNING}🤔 DRIFT DETECTED: Low relevance to goal \"{self.current_session.goal}\"{Colors.ENDC}")
        
        # Context switching alert
        if self.context_switches > 0 and self.context_switches % 10 == 0:
            print(f"{Colors.WARNING}🔄 HIGH SWITCHING: {self.context_switches} context switches{Colors.ENDC}")
    
    def display_session_summary(self):
        """Display comprehensive session summary"""
        if not self.current_session:
            return
        
        total_duration = self.current_session.duration
        
        print(f"\n{Colors.HEADER}🧠 FOCUS SESSION SUMMARY{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"🎯 Goal: {self.current_session.goal}")
        print(f"⏱️  Duration: {self.format_duration(total_duration)}")
        print(f"🔄 Context Switches: {self.context_switches}")
        
        print(f"\n📊 RELEVANCE BREAKDOWN:")
        print("┌─────────────────────────────────────────────┐")
        
        for classification, duration in self.session_stats.items():
            if total_duration.total_seconds() > 0:
                percentage = (duration.total_seconds() / total_duration.total_seconds()) * 100
                emoji = {'DIRECT': '🟢', 'PERIPHERAL': '🟡', 'INDIRECT': '🟠', 'DISTRACTION': '🔴'}[classification]
                
                print(f"│ {emoji} {classification:12}: {self.format_duration(duration):>8} | {percentage:>5.1f}% │")
        
        print("└─────────────────────────────────────────────┘")
        
        # Focus score calculation
        if total_duration.total_seconds() > 0:
            direct_time = self.session_stats['DIRECT'].total_seconds()
            peripheral_time = self.session_stats['PERIPHERAL'].total_seconds()
            total_seconds = total_duration.total_seconds()
            
            focus_score = ((direct_time * 1.0) + (peripheral_time * 0.7)) / total_seconds * 10
            focus_score = min(focus_score, 10.0)
            
            print(f"\n🎯 FOCUS SCORE: {focus_score:.1f}/10")
            
            if focus_score >= 8.0:
                print(f"{Colors.OKGREEN}✅ EXCELLENT focus session!{Colors.ENDC}")
            elif focus_score >= 6.0:
                print(f"{Colors.WARNING}👍 GOOD focus session{Colors.ENDC}")
            elif focus_score >= 4.0:
                print(f"{Colors.WARNING}⚠️  FAIR - room for improvement{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}❌ LOW focus - consider strategies to reduce distractions{Colors.ENDC}")
    
    def format_duration(self, duration: timedelta) -> str:
        """Format duration as readable string"""
        total_seconds = int(duration.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        if hours > 0:
            return f"{hours}h {minutes:02d}m"
        else:
            return f"{minutes}m {seconds:02d}s"
    
    def start_monitoring(self):
        """Start the enhanced window monitoring loop"""
        print(f"{Colors.HEADER}🪟 Enhanced Focus Monitor Started{Colors.ENDC}")
        
        while self.running:
            try:
                window_info = self.get_active_window()
                
                if window_info and window_info != self.last_window_info:
                    self.last_window_info = window_info
                    self.process_window_change(window_info)
                
                time.sleep(2)  # Check every 2 seconds
                
            except KeyboardInterrupt:
                if self.current_session:
                    self.end_session()
                break
            except Exception as e:
                print(f"{Colors.FAIL}Window monitoring error: {e}{Colors.ENDC}")
                time.sleep(5)

class EnhancedActivityTracker:
    """Enhanced activity tracker with focus session management"""
    
    def __init__(self):
        self.database = FocusDatabase()
        self.content_analyzer = ContentAnalyzer()
        self.window_monitor = EnhancedWindowMonitor(self.content_analyzer, self.database)
        self.running = True
    
    def interactive_session_start(self):
        """Interactive session start with goal input"""
        print(f"\n{Colors.BOLD}🎯 Focus Session Setup{Colors.ENDC}")
        print("Enter your study goal (e.g., 'Deep Learning', 'Quantum Physics'):")
        
        goal = input(f"{Colors.OKCYAN}Goal: {Colors.ENDC}").strip()
        
        if not goal:
            goal = "General Study"
        
        self.window_monitor.start_session(goal)
        return goal
    
    def show_commands(self):
        """Show available commands"""
        print(f"\n{Colors.HEADER}📋 Available Commands:{Colors.ENDC}")
        print(f"  {Colors.OKCYAN}start{Colors.ENDC}  - Start a new focus session")
        print(f"  {Colors.OKCYAN}stop{Colors.ENDC}   - End current session")
        print(f"  {Colors.OKCYAN}status{Colors.ENDC} - Show current session status")
        print(f"  {Colors.OKCYAN}stats{Colors.ENDC}  - Show session statistics")
        print(f"  {Colors.OKCYAN}help{Colors.ENDC}   - Show this help")
        print(f"  {Colors.OKCYAN}quit{Colors.ENDC}   - Exit the tracker")
    
    def run_interactive(self):
        """Run the tracker in interactive mode"""
        print(f"{Colors.BOLD}🚀 Enhanced Focus Tracker{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*50}{Colors.ENDC}")
        
        self.show_commands()
        
        # Start window monitoring in background
        monitor_thread = threading.Thread(target=self.window_monitor.start_monitoring, daemon=True)
        monitor_thread.start()
        
        while self.running:
            try:
                command = input(f"\n{Colors.BOLD}>{Colors.ENDC} ").strip().lower()
                
                if command == 'start':
                    self.interactive_session_start()
                
                elif command == 'stop':
                    if self.window_monitor.current_session:
                        self.window_monitor.end_session()
                        print(f"{Colors.OKGREEN}✅ Session ended{Colors.ENDC}")
                    else:
                        print(f"{Colors.WARNING}No active session to end{Colors.ENDC}")
                
                elif command == 'status':
                    if self.window_monitor.current_session:
                        session = self.window_monitor.current_session
                        duration = session.duration
                        print(f"\n🎯 Active Session: {session.goal}")
                        print(f"⏱️  Duration: {self.window_monitor.format_duration(duration)}")
                        print(f"🔄 Context Switches: {self.window_monitor.context_switches}")
                    else:
                        print(f"{Colors.WARNING}No active session{Colors.ENDC}")
                
                elif command == 'stats':
                    if self.window_monitor.current_session:
                        total = self.window_monitor.current_session.duration
                        print(f"\n📊 Current Session Stats:")
                        for classification, duration in self.window_monitor.session_stats.items():
                            if total.total_seconds() > 0:
                                pct = (duration.total_seconds() / total.total_seconds()) * 100
                                emoji = {'DIRECT': '🟢', 'PERIPHERAL': '🟡', 'INDIRECT': '🟠', 'DISTRACTION': '🔴'}[classification]
                                print(f"  {emoji} {classification}: {self.window_monitor.format_duration(duration)} ({pct:.1f}%)")
                
                elif command == 'help':
                    self.show_commands()
                
                elif command in ['quit', 'exit']:
                    if self.window_monitor.current_session:
                        self.window_monitor.end_session()
                    self.running = False
                    self.window_monitor.running = False
                    print(f"{Colors.OKGREEN}👋 Goodbye!{Colors.ENDC}")
                
                else:
                    print(f"{Colors.WARNING}Unknown command. Type 'help' for available commands.{Colors.ENDC}")
                    
            except KeyboardInterrupt:
                if self.window_monitor.current_session:
                    self.window_monitor.end_session()
                self.running = False
                self.window_monitor.running = False
                break
            except EOFError:
                break

def main():
    """Main function"""
    print(f"{Colors.BOLD}Enhanced Focus Tracker - Study Session Monitor{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    
    # Check dependencies
    missing_deps = []
    
    try:
        import psutil
    except ImportError:
        missing_deps.append('psutil')
    
    if missing_deps:
        print(f"{Colors.FAIL}Missing dependencies: {', '.join(missing_deps)}{Colors.ENDC}")
        print(f"Install with: pip install {' '.join(missing_deps)}")
        return
    
    tracker = EnhancedActivityTracker()
    tracker.run_interactive()

if __name__ == "__main__":
    main()