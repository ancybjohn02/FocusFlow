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
import requests

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    from scapy.all import sniff, IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIRECT = '\033[92m'
    PERIPHERAL = '\033[93m'
    INDIRECT = '\033[94m'
    DISTRACTION = '\033[91m'

@dataclass
class FocusSession:
    goal: str
    description: str
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
    def __init__(self):
        self.educational_domains = {
            'youtube.com': 0.7,
            'coursera.org': 0.95,
            'edx.org': 0.95,
            'khanacademy.org': 0.95,
            'arxiv.org': 0.90,
            'wikipedia.org': 0.80,
            'stackoverflow.com': 0.85,
            'github.com': 0.80,
            'medium.com': 0.60,
            'towardsdatascience.com': 0.85,
            'papers.withcode.com': 0.90,
            'scholar.google.com': 0.90,
            'researchgate.net': 0.85,
            'code': 0.85,
            'focusflow': 0.90,
            'daip': 0.90,
        }
        
        self.distraction_domains = {
            'facebook.com': 0.05,
            'twitter.com': 0.10,
            'instagram.com': 0.05,
            'tiktok.com': 0.05,
            'reddit.com': 0.20,
            'netflix.com': 0.05,
            'twitch.tv': 0.10,
            'gaming': 0.15,
        }
        
        self.api_key = os.getenv('XAI_API_KEY')
        self.use_ai = bool(self.api_key)
        self.keyword_cache = {}
        self.classification_cache = {}
        self.ambiguous_domains = ['youtube.com', 'code', 'focusflow', 'daip', 'medium.com']
    
    def extract_domain(self, title: str, process: str) -> str:
        title_lower = title.lower()
        process_lower = process.lower()
        
        if 'code' in process_lower or 'visual studio code' in title_lower:
            if 'focusflow' in title_lower or 'daip' in title_lower:
                return 'focusflow'
            return 'code'
        
        browser_patterns = [
            r'- ([^-]+\.com)',
            r'([^|\s]+\.[a-z]{2,4})',
            r'YouTube', 'Wikipedia', 'GitHub', 'Stack Overflow'
        ]
        
        for pattern in browser_patterns:
            match = re.search(pattern, title, re.IGNORECASE)
            if match:
                return match.group(1).lower() if pattern not in ['YouTube', 'Wikipedia', 'GitHub', 'Stack Overflow'] else pattern.lower()
        
        if 'youtube' in title_lower:
            return 'youtube.com'
        elif 'wikipedia' in title_lower:
            return 'wikipedia.org'
        elif 'stack overflow' in title_lower:
            return 'stackoverflow.com'
        elif 'github' in title_lower:
            return 'github.com'
        
        return process_lower
    
    def _ai_generate_keywords(self, goal: str, description: str) -> List[str]:
        cache_key = hashlib.md5(f"{goal}_{description}".encode()).hexdigest()
        if cache_key in self.keyword_cache:
            return self.keyword_cache[cache_key]
        
        prompt = f"""Generate a comprehensive list of relevant keywords for the following study goal and description.
Goal: {goal}
Description: {description}

Include keywords related to the core topic, its applications, related fields, interdisciplinary connections, and project-specific terms (e.g., 'focusflow', 'daip', 'v3.py' for productivity-related goals). For computer vision goals, include specific algorithms (e.g., 'alexnet', 'resnet', 'efficientnet', 'cnn', 'convolutional neural network', 'image processing'). Return only a JSON array of keywords (at least 20, max 50).
"""
        
        url = "https://api.x.ai/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        data = {
            "model": "grok-beta",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant that generates relevant keywords."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 500
        }
        
        try:
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            content = response.json()['choices'][0]['message']['content']
            match = re.search(r'\[.*\]', content, re.DOTALL)
            if match:
                keywords = json.loads(match.group(0))
                if len(keywords) < 20:
                    keywords.extend(goal.lower().split() + description.lower().split())
                self.keyword_cache[cache_key] = keywords[:50]
                return self.keyword_cache[cache_key]
            else:
                raise ValueError("No valid JSON array in AI response")
        except Exception as e:
            print(f"{Colors.FAIL}AI keyword generation failed: {e}. Using description words as fallback.{Colors.ENDC}")
            words = re.findall(r'\w+', goal.lower() + ' ' + description.lower())
            return list(set(words))[:50]
    
    def _ai_classify(self, title: str, goal: str, description: str, domain: str) -> Tuple[float, str]:
        cache_key = hashlib.md5(f"{title}_{goal}_{description}_{domain}".encode()).hexdigest()
        if cache_key in self.classification_cache:
            return self.classification_cache[cache_key]
        
        keywords = self._ai_generate_keywords(goal, description)
        
        prompt = f"""Analyze the relevance of the following window title to the study goal and description.
Window Title: {title}
Study Goal: {goal}
Description: {description}
Domain/URL: {domain}
Relevant Keywords: {', '.join(keywords)}

Determine how relevant this content is to the goal and description. Consider core concepts, applications, related fields, and project-specific activities (e.g., coding in 'focusflow' or 'daip' for productivity goals). Treat terms like 'lecture', 'tutorial', 'course', and specific algorithms (e.g., 'alexnet', 'resnet', 'cnn') as highly relevant for computer vision goals. Output only JSON:
{{"relevance_score": float between 0.0 and 1.0,
"classification": "DIRECT" | "PERIPHERAL" | "INDIRECT" | "DISTRACTION",
"reason": short explanation}}
"""
        
        url = "https://api.x.ai/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        data = {
            "model": "grok-beta",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant that classifies content relevance."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 200
        }
        
        try:
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            content = response.json()['choices'][0]['message']['content']
            match = re.search(r'\{.*\}', content, re.DOTALL)
            if match:
                result = json.loads(match.group(0))
                score = result['relevance_score']
                classification = result['classification']
                self.classification_cache[cache_key] = (score, classification)
                return score, classification
            else:
                raise ValueError("No valid JSON in AI response")
        except Exception as e:
            print(f"{Colors.FAIL}AI classification failed: {e}. Falling back to rule-based.{Colors.ENDC}")
            return self._rule_based_classify(title, goal, description, domain, keywords)
    
    def _rule_based_classify(self, title: str, goal: str, description: str, domain: str, keywords: List[str]) -> Tuple[float, str]:
        title_lower = title.lower()
        goal_lower = goal.lower()
        description_lower = description.lower()
        
        base_score = self.educational_domains.get(domain, 0.5)
        
        project_terms = ['focusflow', 'daip', 'v3.py', 'activity_tracker']
        if domain == 'focusflow' or any(term in title_lower for term in project_terms):
            base_score = max(base_score, 0.9)
        
        if domain in self.distraction_domains:
            base_score = min(base_score, self.distraction_domains[domain])
        
        content_score = 0.0
        for keyword in keywords:
            if keyword.lower() in title_lower:
                content_score += 0.2
        if any(word in title_lower for word in description_lower.split()):
            content_score += 0.3
        
        educational_terms = ['lecture', 'tutorial', 'course', 'crash course', 'educational', 'introduction', 'neural', 'cnn', 'convolutional']
        if domain == 'youtube.com' and any(term in title_lower for term in educational_terms):
            content_score += 0.4
        
        final_score = min((base_score + content_score) / 2, 1.0)
        
        if final_score >= 0.8:
            classification = "DIRECT"
        elif final_score >= 0.6:
            classification = "PERIPHERAL"
        elif final_score >= 0.3:
            classification = "INDIRECT"
        else:
            classification = "DISTRACTION"
        
        return final_score, classification
    
    def calculate_relevance_score(self, title: str, goal: str, description: str, domain: str) -> Tuple[float, str]:
        if self.use_ai and domain in self.ambiguous_domains:
            return self._ai_classify(title, goal, description, domain)
        keywords = self._ai_generate_keywords(goal, description) if self.use_ai else re.findall(r'\w+', goal.lower() + ' ' + description.lower())
        return self._rule_based_classify(title, goal, description, domain, list(set(keywords))[:50])

class FocusDatabase:
    def __init__(self, db_path: str = "focus_tracker.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                goal TEXT NOT NULL,
                description TEXT,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                total_duration INTEGER,
                focus_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
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
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO sessions (goal, description, start_time, end_time, total_duration)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            session.goal,
            session.description,
            session.start_time,
            session.end_time,
            int(session.duration.total_seconds()) if session.end_time else None
        ))
        
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return session_id
    
    def save_activity(self, session_id: int, activity: Activity):
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
    def __init__(self, content_analyzer: ContentAnalyzer, database: FocusDatabase):
        self.content_analyzer = content_analyzer
        self.database = database
        self.current_session: Optional[FocusSession] = None
        self.current_activity: Optional[Activity] = None
        self.last_window_info = None
        self.activity_start_time = None
        self.running = True
        
        self.session_stats = {
            'DIRECT': timedelta(),
            'PERIPHERAL': timedelta(),
            'INDIRECT': timedelta(),
            'DISTRACTION': timedelta()
        }
        
        self.recent_activities = deque(maxlen=50)
        self.context_switches = 0
        self.last_classification = None
    
    def start_session(self, goal: str, description: str):
        if self.current_session:
            self.end_session()
        
        self.current_session = FocusSession(
            goal=goal,
            description=description,
            start_time=datetime.now()
        )
        
        self.session_stats = {k: timedelta() for k in self.session_stats}
        self.context_switches = 0
        self.recent_activities.clear()
        
        print(f"\n{Colors.HEADER}🎯 FOCUS SESSION STARTED{Colors.ENDC}")
        print(f"Goal: {Colors.BOLD}{goal}{Colors.ENDC}")
        print(f"Description: {description}")
        print(f"Started: {self.current_session.start_time.strftime('%H:%M:%S')}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    
    def end_session(self):
        if not self.current_session:
            return
        
        if self.current_activity and self.activity_start_time:
            duration = datetime.now() - self.activity_start_time
            self.current_activity.duration = duration
            self.session_stats[self.current_activity.classification] += duration
        
        self.current_session.end_time = datetime.now()
        
        session_id = self.database.save_session(self.current_session)
        for activity in self.current_session.activities:
            self.database.save_activity(session_id, activity)
        
        self.display_session_summary()
        
        self.current_session = None
    
    def get_active_window(self):
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
        if not self.current_session:
            return
        
        now = datetime.now()
        
        if self.current_activity and self.activity_start_time:
            duration = now - self.activity_start_time
            self.current_activity.duration = duration
            self.session_stats[self.current_activity.classification] += duration
            self.current_session.activities.append(self.current_activity)
            self.recent_activities.append(self.current_activity)
        
        domain = self.content_analyzer.extract_domain(window_info['title'], window_info['process'])
        relevance_score, classification = self.content_analyzer.calculate_relevance_score(
            window_info['title'], 
            self.current_session.goal,
            self.current_session.description,
            domain
        )
        
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
        
        if (self.last_classification and 
            self.last_classification != classification and
            classification == 'DISTRACTION'):
            self.context_switches += 1
        self.last_classification = classification
        
        self.display_current_activity()
        self.check_focus_alerts()
    
    def display_current_activity(self):
        if not self.current_activity:
            return
        
        timestamp = self.current_activity.timestamp.strftime("%H:%M:%S")
        classification = self.current_activity.classification
        score = self.current_activity.relevance_score
        title = self.current_activity.title[:60] + "..." if len(self.current_activity.title) > 60 else self.current_activity.title
        
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
        
        if len(self.recent_activities) > 0:
            total_time = sum((a.duration for a in self.recent_activities if a.duration), timedelta())
            if total_time.total_seconds() > 0:
                focus_time = sum((a.duration for a in self.recent_activities 
                                if a.classification == 'DIRECT' and a.duration), timedelta())
                focus_percentage = (focus_time.total_seconds() / total_time.total_seconds()) * 100
                print(f"📊 Session Focus: {focus_percentage:.1f}% | Switches: {self.context_switches}")
    
    def check_focus_alerts(self):
        if not self.current_activity or len(self.recent_activities) < 5:
            return
        
        recent_classifications = [a.classification for a in list(self.recent_activities)[-5:]]
        if recent_classifications.count('DISTRACTION') >= 3:
            print(f"{Colors.FAIL}⚠️  FOCUS ALERT: Multiple distractions detected{Colors.ENDC}")
        
        recent_scores = [a.relevance_score for a in list(self.recent_activities)[-7:]]
        if len(recent_scores) >= 7 and sum(recent_scores) / len(recent_scores) < 0.5:
            print(f"{Colors.WARNING}🤔 DRIFT DETECTED: Low relevance to goal \"{self.current_session.goal}\"{Colors.ENDC}")
        
        if self.context_switches > 0 and self.context_switches % 15 == 0:
            print(f"{Colors.WARNING}🔄 HIGH SWITCHING: {self.context_switches} context switches{Colors.ENDC}")
    
    def display_session_summary(self):
        if not self.current_session:
            return
        
        total_duration = self.current_session.duration
        
        print(f"\n{Colors.HEADER}🧠 FOCUS SESSION SUMMARY{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"🎯 Goal: {self.current_session.goal}")
        print(f"📝 Description: {self.current_session.description}")
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
        total_seconds = int(duration.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        if hours > 0:
            return f"{hours}h {minutes:02d}m"
        else:
            return f"{minutes}m {seconds:02d}s"
    
    def start_monitoring(self):
        print(f"{Colors.HEADER}🪟 Enhanced Focus Monitor Started{Colors.ENDC}")
        while self.running:
            try:
                window_info = self.get_active_window()
                if window_info and window_info != self.last_window_info:
                    self.last_window_info = window_info
                    self.process_window_change(window_info)
                time.sleep(2)
            except KeyboardInterrupt:
                if self.current_session:
                    self.end_session()
                break
            except Exception as e:
                print(f"{Colors.FAIL}Window monitoring error: {e}{Colors.ENDC}")
                time.sleep(5)

class EnhancedActivityTracker:
    def __init__(self):
        self.database = FocusDatabase()
        self.content_analyzer = ContentAnalyzer()
        self.window_monitor = EnhancedWindowMonitor(self.content_analyzer, self.database)
        self.running = True
    
    def interactive_session_start(self):
        print(f"\n{Colors.BOLD}🎯 Focus Session Setup{Colors.ENDC}")
        print("Enter your study goal (e.g., 'Deep Learning', 'Focus Analysis'):")
        goal = input(f"{Colors.OKCYAN}Goal: {Colors.ENDC}").strip()
        
        if not goal:
            goal = "General Study"
        
        print("Enter a detailed description of what you'll be working on (press Enter twice to finish):")
        lines = []
        while True:
            line = input(f"{Colors.OKCYAN}Description: {Colors.ENDC}")
            if line == "":
                break
            lines.append(line)
        description = " ".join(lines).strip() or "No detailed description provided."
        
        self.window_monitor.start_session(goal, description)
        return goal, description
    
    def show_commands(self):
        print(f"\n{Colors.HEADER}📋 Available Commands:{Colors.ENDC}")
        print(f"  {Colors.OKCYAN}start{Colors.ENDC}  - Start a new focus session")
        print(f"  {Colors.OKCYAN}stop{Colors.ENDC}   - End current session")
        print(f"  {Colors.OKCYAN}status{Colors.ENDC} - Show current session status")
        print(f"  {Colors.OKCYAN}stats{Colors.ENDC}  - Show session statistics")
        print(f"  {Colors.OKCYAN}help{Colors.ENDC}   - Show this help")
        print(f"  {Colors.OKCYAN}quit{Colors.ENDC}   - Exit the tracker")
    
    def run_interactive(self):
        print(f"{Colors.BOLD}🚀 Enhanced Focus Tracker{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*50}{Colors.ENDC}")
        
        self.show_commands()
        
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
                        print(f"📝 Description: {session.description}")
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
    print(f"{Colors.BOLD}Enhanced Focus Tracker - Study Session Monitor{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
    
    missing_deps = []
    
    try:
        import psutil
    except ImportError:
        missing_deps.append('psutil')
    
    try:
        import requests
    except ImportError:
        missing_deps.append('requests')
    
    if missing_deps:
        print(f"{Colors.FAIL}Missing dependencies: {', '.join(missing_deps)}{Colors.ENDC}")
        print(f"Install with: pip install {' '.join(missing_deps)}")
        return
    
    if not os.getenv('XAI_API_KEY'):
        print(f"{Colors.WARNING}Note: Set XAI_API_KEY environment variable to enable AI-powered classification. Visit https://x.ai/api for details.{Colors.ENDC}")
    
    tracker = EnhancedActivityTracker()
    tracker.run_interactive()

if __name__ == "__main__":
    main()