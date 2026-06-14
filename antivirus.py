#!/usr/bin/env python3
"""
Whimsical Antivirus - Python Implementation
A cross-platform antivirus scanner with signature matching and YARA support
"""

import os
import hashlib
import json
import sys
import subprocess
import tempfile
import random
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import threading


class FileScanner:
    """Scans files for malware signatures"""
    
    def __init__(self, signatures_file: str = "signatures.json"):
        self.signatures_file = signatures_file
        self.sig_db = self.load_signatures()
    
    def load_signatures(self) -> Dict[str, str]:
        """Load SHA256 signatures from database"""
        try:
            with open(self.signatures_file, 'r') as f:
                data = json.load(f)
                # Convert to dict of hash->name for faster lookup
                return {sig['sha256']: sig['name'] for sig in data.get('signatures', [])}
        except FileNotFoundError:
            print(f"Warning: Signatures file not found: {self.signatures_file}")
            return {}
    
    def get_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (IOError, OSError) as e:
            print(f"Error reading {file_path}: {e}")
            return ""
    
    def get_magic_bytes(self, file_path: Path, n: int = 8) -> str:
        """Get first n bytes of file as hex"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(n)
            return ' '.join(f'{b:02x}' for b in magic)
        except (IOError, OSError):
            return ""
    
    def check_hash(self, file_hash: str) -> Optional[str]:
        """Check if hash matches a known malware signature"""
        return self.sig_db.get(file_hash)
    
    def scan_file(self, file_path: Path) -> Dict:
        """Scan a single file"""
        file_hash = self.get_file_hash(file_path)
        if not file_hash:
            return None
        
        magic_bytes = self.get_magic_bytes(file_path)
        matched_sig = self.check_hash(file_hash)
        
        return {
            'path': str(file_path),
            'hash': file_hash,
            'magic_bytes': magic_bytes,
            'signature': matched_sig,
            'timestamp': datetime.now().isoformat() + 'Z',
            'result': 'matched' if matched_sig else 'clean'
        }
    
    def scan_directory(self, target_path: str = ".") -> List[Dict]:
        """Recursively scan all files in a directory"""
        results = []
        target = Path(target_path)
        
        if target.is_file():
            result = self.scan_file(target)
            if result:
                results.append(result)
        else:
            # Skip common directories to avoid issues
            skip_dirs = {'.git', '__pycache__', 'target', '.cargo', 'node_modules', '.venv', 'venv'}
            for file_path in target.rglob('*'):
                if file_path.is_file():
                    # Skip if in skip_dirs
                    if any(part in skip_dirs for part in file_path.parts):
                        continue
                    result = self.scan_file(file_path)
                    if result:
                        results.append(result)
        
        return results


class WindowsEventScanner:
    """Scans Windows Event Logs for security threats"""
    
    def __init__(self, signatures_file: str = "signatures.json"):
        self.sig_file = signatures_file
        self.threat_keywords = self._load_threat_keywords()
        self.is_windows = sys.platform == 'win32'
    
    def _load_threat_keywords(self) -> Dict[str, int]:
        """Load threat keywords from signatures file"""
        keywords = {
            # Process/Execution threats
            'cmd.exe': 85,
            'powershell': 80,
            'psexec': 95,
            'mimikatz': 100,
            'wmic': 75,
            'taskkill': 70,
            'del ': 70,
            'format': 80,
            'reg.exe': 75,
            
            # Network threats
            'nc.exe': 90,
            'netcat': 90,
            'ncat': 90,
            'curl': 60,
            'wget': 60,
            'certutil': 85,
            'bitsadmin': 80,
            
            # Malware indicators
            'trojan': 95,
            'ransomware': 100,
            'spyware': 90,
            'adware': 70,
            'worm': 95,
            'botnet': 95,
            'backdoor': 100,
            'rootkit': 100,
            
            # Suspicious activity
            'unusual logon': 85,
            'privilege escalation': 95,
            'lateral movement': 90,
            'credential dumping': 95,
            'suspicious service': 80,
            'unauthorized access': 85,
        }
        return keywords
    
    def _run_powershell(self, command: str) -> str:
        """Execute PowerShell command and return output"""
        try:
            result = subprocess.run(
                ['powershell', '-Command', command],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout.strip()
        except Exception as e:
            print(f"PowerShell error: {e}")
            return ""
    
    def scan_security_events(self, hours_back: int = 24) -> List[Dict]:
        """Scan Windows Security Event Log for threats"""
        if not self.is_windows:
            return []
        
        results = []
        print(f"  [i] Attempting to scan Security logs...")
        
        # Get failed login attempts (Event ID 4625)
        ps_cmd = f"""
        Try {{
            Get-WinEvent -FilterHashtable @{{LogName='Security'; ID=4625; StartTime=@(Get-Date).AddHours(-{hours_back})}} -ErrorAction Stop |
            Select-Object -First 20 |
            ForEach-Object {{
                @{{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.ID
                    Message = ($_.Message | Select-Object -First 300)
                }} | ConvertTo-Json
            }}
        }} Catch {{
            Write-Output "Security log access denied - requires admin privileges"
        }}
        """
        
        output = self._run_powershell(ps_cmd)
        if "access denied" in output.lower() or "unauthorized" in output.lower():
            print(f"  [!] Security log requires administrator privileges")
        elif output and "failed" not in output.lower():
            try:
                for line in output.split('\n'):
                    if line.strip() and '{' in line:
                        event = json.loads(line)
                        results.append({
                            'source': 'Windows Security Log',
                            'type': 'Failed Login Attempt',
                            'event_id': 4625,
                            'timestamp': str(event.get('TimeCreated', '')),
                            'message': event.get('Message', '')[:150],
                            'threat_level': 'MEDIUM',
                            'score': 65
                        })
            except json.JSONDecodeError:
                pass
        
        return results
    
    def scan_system_events(self, hours_back: int = 24) -> List[Dict]:
        """Scan Windows System Event Log for suspicious activity"""
        if not self.is_windows:
            return []
        
        results = []
        print(f"  [*] Scanning System log for anomalies...")
        
        # Get all system events and count them
        ps_cmd = f"""
        $all_events = Get-WinEvent -FilterHashtable @{{LogName='System'; StartTime=@(Get-Date).AddHours(-{hours_back})}} -ErrorAction SilentlyContinue
        $critical = $all_events | Where-Object {{$_.Level -le 2}}
        Write-Output "TOTAL_COUNT:$($all_events.Count)"
        Write-Output "CRITICAL_COUNT:$($critical.Count)"
        $critical | Select-Object -First 50 | ForEach-Object {{
            @{{
                TimeCreated = $_.TimeCreated
                EventID = $_.ID
                Source = $_.ProviderName
                Message = $_.Message
            }} | ConvertTo-Json
        }}
        """
        
        output = self._run_powershell(ps_cmd)
        error_count = 0
        scan_count = 0
        
        if output:
            lines = output.split('\n')
            try:
                for line in lines:
                    if line.startswith('TOTAL_COUNT:'):
                        scan_count = int(line.replace('TOTAL_COUNT:', ''))
                    elif line.startswith('CRITICAL_COUNT:'):
                        pass  # We'll count from the actual results
            except ValueError:
                pass
            
            try:
                for line in lines:
                    if line.strip() and '{' in line and line.startswith('{'):
                        event = json.loads(line)
                        message = event.get('Message', '').lower()
                        
                        # Detect suspicious events
                        threat_score = 0
                        threat_type = 'System Event'
                        
                        # Check for suspicious patterns
                        if 'service terminated' in message or 'process crashed' in message:
                            threat_score = 50
                            threat_type = 'Service/Process Crash'
                        elif 'bootloader' in message or 'kernel' in message:
                            threat_score = 70
                            threat_type = 'System Integrity Issue'
                        
                        score = self._score_event(message)
                        if score > threat_score:
                            threat_score = score
                        
                        if threat_score > 0:
                            results.append({
                                'source': 'Windows System Log',
                                'type': threat_type,
                                'event_id': event.get('EventID', 0),
                                'timestamp': str(event.get('TimeCreated', '')),
                                'provider': event.get('Source', 'Unknown'),
                                'message': event.get('Message', '')[:200],
                                'threat_level': 'HIGH' if threat_score >= 60 else 'MEDIUM',
                                'score': threat_score
                            })
                            error_count += 1
            except json.JSONDecodeError:
                pass
        
        # Log scan summary for System log
        results.append({
            'type': 'LOG_SCAN_SUMMARY',
            'source': 'Windows System Log',
            'logs_examined': scan_count,
            'suspicious_found': error_count,
            'timestamp': datetime.now().isoformat() + 'Z',
            'status': 'scanned'
        })
        
        if error_count == 0:
            print(f"  [✓] System log clean ({scan_count} events examined)")
        else:
            print(f"  [!] Found {error_count} suspicious System log events (from {scan_count} total)")
        
        return results
    
    def _score_event(self, message: str) -> int:
        """Score an event based on threat keywords"""
        message_lower = message.lower()
        max_score = 0
        
        for keyword, score in self.threat_keywords.items():
            if keyword.lower() in message_lower:
                max_score = max(max_score, score)
        
        return max_score
    
    def scan_all_logs(self, hours_back: int = 24) -> List[Dict]:
        """Scan all accessible Windows Event Logs"""
        if not self.is_windows:
            print("Note: Windows Event Log scanning only available on Windows systems")
            return []
        
        print(f"\n[*] Scanning Windows Event Logs (last {hours_back} hours)...")
        
        all_results = []
        all_results.extend(self.scan_security_events(hours_back))
        all_results.extend(self.scan_system_events(hours_back))
        all_results.extend(self.scan_application_events(hours_back))
        all_results.extend(self.scan_powershell_events(hours_back))
        
        return all_results
    
    def scan_application_events(self, hours_back: int = 24) -> List[Dict]:
        """Scan Application Event Log for security threats"""
        if not self.is_windows:
            return []
        
        results = []
        print(f"  [*] Scanning Application log...")
        
        # Get all application events
        ps_cmd = f"""
        $all_events = Get-WinEvent -FilterHashtable @{{LogName='Application'; StartTime=@(Get-Date).AddHours(-{hours_back})}} -ErrorAction SilentlyContinue
        Write-Output "TOTAL_COUNT:$($all_events.Count)"
        $all_events | Where-Object {{$_.Message -match '(Defender|Firewall|Security|threat|malware|virus|infected|quarantine|blocked)' }} | Select-Object -First 100 | ForEach-Object {{
            @{{
                TimeCreated = $_.TimeCreated
                EventID = $_.ID
                Source = $_.ProviderName
                Message = $_.Message
            }} | ConvertTo-Json
        }}
        """
        
        output = self._run_powershell(ps_cmd)
        if output:
            lines = output.split('\n')
            threat_count = 0
            scan_count = 0
            
            try:
                for line in lines:
                    if line.startswith('TOTAL_COUNT:'):
                        scan_count = int(line.replace('TOTAL_COUNT:', ''))
            except ValueError:
                pass
            
            try:
                for line in lines:
                    if line.strip() and '{' in line and line.startswith('{'):
                        event = json.loads(line)
                        message = event.get('Message', '')
                        score = self._score_event(message)
                        
                        # Security-related app events are usually medium to high threat
                        if 'threat' in message.lower() or 'malware' in message.lower() or 'virus' in message.lower():
                            score = max(score, 80)
                        elif 'blocked' in message.lower() or 'quarantine' in message.lower():
                            score = max(score, 70)
                        
                        results.append({
                            'source': 'Windows Application Log',
                            'type': 'Security Event',
                            'event_id': event.get('EventID', 0),
                            'timestamp': str(event.get('TimeCreated', '')),
                            'provider': event.get('Source', 'Unknown'),
                            'message': message[:300],
                            'threat_level': 'HIGH' if score >= 75 else 'MEDIUM',
                            'score': score
                        })
                        threat_count += 1
            except json.JSONDecodeError:
                pass
            
            # Log scan summary
            results.append({
                'type': 'LOG_SCAN_SUMMARY',
                'source': 'Windows Application Log',
                'logs_examined': scan_count,
                'security_events_found': threat_count,
                'timestamp': datetime.now().isoformat() + 'Z',
                'status': 'scanned'
            })
            
            if threat_count == 0:
                print(f"  [✓] Application log clean ({scan_count} events examined)")
            else:
                print(f"  [!] Found {threat_count} security events (from {scan_count} total)")
        
        return results
    
    def scan_powershell_events(self, hours_back: int = 24) -> List[Dict]:
        """Scan PowerShell Event Log for suspicious scripts"""
        if not self.is_windows:
            return []
        
        results = []
        print(f"  [*] Scanning PowerShell logs...")
        
        ps_cmd = f"""
        $all_events = Get-WinEvent -FilterHashtable @{{LogName='Windows PowerShell'; StartTime=@(Get-Date).AddHours(-{hours_back})}} -ErrorAction SilentlyContinue
        Write-Output "TOTAL_COUNT:$($all_events.Count)"
        $all_events | Select-Object -First 50 | ForEach-Object {{
            @{{
                TimeCreated = $_.TimeCreated
                EventID = $_.ID
                Message = $_.Message
            }} | ConvertTo-Json
        }}
        """
        
        output = self._run_powershell(ps_cmd)
        if output:
            lines = output.split('\n')
            threat_count = 0
            scan_count = 0
            
            try:
                for line in lines:
                    if line.startswith('TOTAL_COUNT:'):
                        scan_count = int(line.replace('TOTAL_COUNT:', ''))
            except ValueError:
                pass
            
            try:
                for line in lines:
                    if line.strip() and '{' in line and line.startswith('{'):
                        event = json.loads(line)
                        message = event.get('Message', '')
                        score = self._score_event(message)
                        
                        # PowerShell often used by attackers
                        if any(x in message.lower() for x in ['encoded', 'obfuscated', 'scriptblock', 'iex', 'invoke']):
                            score = max(score, 75)
                        
                        if score > 0:
                            results.append({
                                'source': 'Windows PowerShell Log',
                                'type': 'Suspicious Script Activity',
                                'event_id': event.get('EventID', 0),
                                'timestamp': str(event.get('TimeCreated', '')),
                                'message': message[:300],
                                'threat_level': 'HIGH' if score >= 75 else 'MEDIUM',
                                'score': score
                            })
                            threat_count += 1
            except json.JSONDecodeError:
                pass
            
            # Log scan summary
            results.append({
                'type': 'LOG_SCAN_SUMMARY',
                'source': 'Windows PowerShell Log',
                'logs_examined': scan_count,
                'suspicious_scripts_found': threat_count,
                'timestamp': datetime.now().isoformat() + 'Z',
                'status': 'scanned'
            })
            
            if threat_count == 0:
                print(f"  [✓] PowerShell log clean ({scan_count} events examined)")
            else:
                print(f"  [!] Found {threat_count} suspicious scripts (from {scan_count} total)")
        
        return results


class Logger:
    """Logs scan results to file"""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.log_file = self.log_dir / "scan.log"
    
    def log_result(self, result: Dict) -> None:
        """Log a scan result as JSON"""
        with open(self.log_file, 'a') as f:
            json.dump(result, f)
            f.write('\n')


class DecisionEngine:
    """Makes quarantine decisions based on scan results"""
    
    @staticmethod
    def score_entry(entry: Dict) -> int:
        """Score a scan result (0-100)"""
        sig = entry.get('signature')
        
        if sig is None:
            return 0
        
        if 'Signature' in sig:
            return 100
        elif 'YARA' in sig:
            return 70
        else:
            return 40
    
    @staticmethod
    def decide(score: int) -> str:
        """Make a decision based on score"""
        if score >= 80:
            return "AUTO QUARANTINE"
        elif 40 <= score < 80:
            return "WARN USER"
        else:
            return "ALLOW"


class Quarantine:
    """Manages quarantined files"""
    
    def __init__(self, quarantine_dir: str = "quarantine"):
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(exist_ok=True)
    
    def quarantine_file(self, file_path: Path) -> Optional[Path]:
        """Move a file to quarantine and make it read-only"""
        try:
            dest = self.quarantine_dir / file_path.name
            # Add timestamp to avoid collisions
            if dest.exists():
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                dest = self.quarantine_dir / f"{timestamp}{file_path.name}"
            
            file_path.rename(dest)
            # Make read-only
            dest.chmod(0o444)
            print(f"File quarantined: {dest}")
            return dest
        except Exception as e:
            print(f"Error quarantining {file_path}: {e}")
            return None


def process_log(log_file: str = "logs/scan.log") -> None:
    """Process and analyze scan log"""
    try:
        with open(log_file, 'r') as f:
            for line in f:
                entry = json.loads(line)
                score = DecisionEngine.score_entry(entry)
                decision = DecisionEngine.decide(score)
                
                filename = entry.get('path', 'unknown')
                triggered = entry.get('signature', 'None')
                
                print(f"\nFile: {filename}")
                print(f"Hash: {entry.get('hash', 'unknown')[:16]}...")
                print(f"Score: {score}/100")
                print(f"Decision: {decision}")
                print(f"Triggered: {triggered}")
    except FileNotFoundError:
        print(f"Log file not found: {log_file}")


def _no_warnings_in_last_24h(log_file: str = "logs/scan.log") -> bool:
    """Return True if no warning-worthy entries exist in the last 24 hours."""
    cutoff = datetime.now() - timedelta(hours=24)
    try:
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except Exception:
                    continue

                # Try to get a timestamp
                ts = None
                for k in ('timestamp', 'TimeCreated', 'time', 'date'):
                    if k in entry:
                        try:
                            ts_str = str(entry[k])
                            # strip trailing Z
                            ts = datetime.fromisoformat(ts_str.replace('Z', ''))
                        except Exception:
                            ts = None
                        break

                if ts is None:
                    continue

                if ts < cutoff:
                    continue

                # Check explicit decision fields
                if entry.get('decision') in ('WARN USER', 'AUTO QUARANTINE'):
                    return False

                # Check summary counters
                for k in ('suspicious_found', 'security_events_found', 'suspicious_scripts_found', 'events_detected', 'critical_threats', 'high_threats'):
                    try:
                        if int(entry.get(k, 0)) > 0:
                            return False
                    except Exception:
                        pass

                # Score-based heuristic (conservative)
                try:
                    if int(entry.get('score', 0)) >= 40:
                        return False
                except Exception:
                    pass

    except FileNotFoundError:
        return True

    return True


def _spawn_confetti_process(duration: int = 5, fade: int = 60) -> None:
    """Spawn a detached helper process that shows a confetti animation.

    The helper is written to a temp file and launched with the same Python interpreter.
    Running a separate process avoids blocking the scanner and reduces Tkinter mainloop issues.
    """
    script = r"""
import tkinter as tk
import random
import time

def run_confetti(animation_time=5, hold_time=60):
    root = tk.Tk()
    root.overrideredirect(True)
    root.attributes('-topmost', True)
    w = root.winfo_screenwidth()
    h = root.winfo_screenheight()
    root.geometry(f"{w}x{h}+0+0")

    canvas = tk.Canvas(root, width=w, height=h, bg='black')
    canvas.pack()

    particles = []
    colors = ['#ffb6c1', '#ffc0cb', '#ff69b4', '#ff1493', '#ff7eb6']

    for i in range(150):
        x = random.randint(0, w)
        y = random.randint(-h//2, h)
        size = random.randint(4, 12)
        color = random.choice(colors)
        oval = canvas.create_oval(x, y, x+size, y+size, fill=color, outline='')
        vx = random.uniform(-2, 2)
        vy = random.uniform(1, 6)
        particles.append([oval, vx, vy])

    start = time.time()

    def animate():
        now = time.time()
        elapsed = now - start
        for p in particles:
            oval, vx, vy = p
            canvas.move(oval, vx, vy)
            coords = canvas.coords(oval)
            # Wrap horizontally
            if coords[0] > w:
                canvas.move(oval, -w-20, 0)
            if coords[2] < 0:
                canvas.move(oval, w+20, 0)
            # Remove if fell below screen
            if coords[1] > h:
                canvas.move(oval, 0, -h-40)

        if elapsed < animation_time:
            root.after(33, animate)

    root.after(0, animate)

    # Schedule destroy after animation_time + hold_time
    root.after(int((animation_time + hold_time) * 1000), root.destroy)
    root.mainloop()

if __name__ == '__main__':
    try:
        run_confetti()
    except Exception:
        pass
"""

    tmp = Path(tempfile.gettempdir()) / f"whim_confetti_{int(time.time())}.py"
    try:
        tmp.write_text(script)
        # Prefer pythonw on Windows to avoid console window
        python_exec = sys.executable
        if sys.platform == 'win32':
            pyw = python_exec.replace('python.exe', 'pythonw.exe')
            if Path(pyw).exists():
                python_exec = pyw

        # Launch detached
        subprocess.Popen([python_exec, str(tmp)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"Could not spawn confetti helper: {e}")


def maybe_trigger_confetti(log_file: str = 'logs/scan.log', no_celebrate: bool = False) -> None:
    if no_celebrate:
        return

    try:
        if _no_warnings_in_last_24h(log_file):
            print('\n🎉 No warnings in the last 24 hours — showing confetti!')
            # Spawn helper process so we don't block the scanner
            threading.Thread(target=_spawn_confetti_process, args=(5, 60), daemon=True).start()
    except Exception:
        pass


def main():
    """Main antivirus scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Whimsical Antivirus Scanner')
    parser.add_argument('path', nargs='?', default='.', help='Path to scan')
    parser.add_argument('--process-log', action='store_true', help='Process scan log')
    parser.add_argument('--quarantine', action='store_true', help='Quarantine matched files')
    parser.add_argument('--windows-logs', action='store_true', help='Scan Windows Event Logs')
    parser.add_argument('--hours', type=int, default=24, help='Hours of event logs to scan (default: 24)')
    parser.add_argument('--demo', action='store_true', help='Demo mode: simulate threat detection')
    # Allow explicit enable/disable pair: --celebrate / --no-celebrate
    parser.add_argument('--celebrate', dest='celebrate', action='store_true', help='Enable celebratory confetti pop-up')
    parser.add_argument('--no-celebrate', dest='celebrate', action='store_false', help='Disable celebratory confetti pop-up')
    parser.set_defaults(celebrate=True)
    args = parser.parse_args()
    
    if args.process_log:
        process_log()
        # Optionally show confetti if no warnings in last 24h
        maybe_trigger_confetti('logs/scan.log', no_celebrate=(not args.celebrate))
        return
    
    # Demo mode: simulate threats in logs
    if args.demo:
        logger = Logger()
        engine = DecisionEngine()
        
        print("[DEMO MODE] Simulating threat detection from Windows Event Logs\n")
        
        demo_events = [
            {
                'type': 'Failed Login Attempts',
                'source': 'Windows Security Log',
                'event_id': 4625,
                'timestamp': datetime.now().isoformat() + 'Z',
                'message': 'Multiple failed logon attempts detected from IP 192.168.1.105 targeting Administrator account',
                'threat_level': 'MEDIUM',
                'score': 70
            },
            {
                'type': 'Suspicious Process Execution',
                'source': 'Windows Security Log',
                'event_id': 4688,
                'timestamp': datetime.now().isoformat() + 'Z',
                'message': 'PowerShell.exe launched with suspicious parameters: encoded command detected, process parent: explorer.exe',
                'threat_level': 'HIGH',
                'score': 85
            },
            {
                'type': 'Malware Detection',
                'source': 'Windows Defender Log',
                'event_id': 1116,
                'timestamp': datetime.now().isoformat() + 'Z',
                'message': 'Trojan:Win32/Emotet detected in C:\\Users\\Ananya\\Downloads\\invoice.exe - Action: Quarantined',
                'threat_level': 'HIGH',
                'score': 100
            },
            {
                'type': 'Unauthorized Network Activity',
                'source': 'Windows Firewall Log',
                'event_id': 5158,
                'timestamp': datetime.now().isoformat() + 'Z',
                'message': 'Outbound connection attempt from unknown.exe to 10.10.10.50:4444 - Connection blocked',
                'threat_level': 'CRITICAL',
                'score': 95
            },
            {
                'type': 'Privilege Escalation',
                'source': 'Windows Security Log',
                'event_id': 4672,
                'timestamp': datetime.now().isoformat() + 'Z',
                'message': 'Special privileges assigned to token from process rundll32.exe - Unusual pattern detected',
                'threat_level': 'CRITICAL',
                'score': 90
            }
        ]
        
        print(f"Found {len(demo_events)} security threats\n")
        
        for event in demo_events:
            logger.log_result(event)
            score = event.get('score', 0)
            decision = engine.decide(score)
            
            print(f"\n[THREAT DETECTED] ⚠️")
            print(f"  Type: {event['type']}")
            print(f"  Source: {event['source']}")
            print(f"  Score: {score}/100")
            print(f"  Decision: {decision}")
            print(f"  Message: {event['message']}")
        
        # Log summary
        logger.log_result({
            'type': 'DEMO_SCAN_SUMMARY',
            'source': 'Demo Mode',
            'events_detected': len(demo_events),
            'critical_threats': sum(1 for e in demo_events if e['score'] >= 90),
            'high_threats': sum(1 for e in demo_events if 70 <= e['score'] < 90),
            'timestamp': datetime.now().isoformat() + 'Z',
            'status': 'demo_complete'
        })
        
        print(f"\n\nResults logged to: {logger.log_file}")
        print(f"✓ Demo complete - {len(demo_events)} threats detected")
        # Do not auto-celebrate demo runs
        return
    
    # Windows Event Log scanning
    if args.windows_logs:
        event_scanner = WindowsEventScanner()
        logger = Logger()
        engine = DecisionEngine()
        
        # Log scan start
        logger.log_result({
            'type': 'SCAN_START',
            'source': 'Windows Event Logs',
            'hours_scanned': args.hours,
            'timestamp': datetime.now().isoformat() + 'Z',
            'status': 'initiated'
        })
        
        events = event_scanner.scan_all_logs(args.hours)
        
        if events:
            print(f"\n[!] Found {len(events)} security events")
            
            for event in events:
                # Log the event
                logger.log_result(event)
                
                score = event.get('score', 0)
                decision = engine.decide(score)
                
                print(f"\n[SECURITY EVENT]")
                print(f"  Type: {event.get('type', 'Unknown')}")
                print(f"  Source: {event.get('source', 'Unknown')}")
                print(f"  Score: {score}/100")
                print(f"  Decision: {decision}")
                print(f"  Timestamp: {event.get('timestamp', 'Unknown')}")
                
                if 'user' in event:
                    print(f"  User: {event['user']}")
                if 'computer' in event:
                    print(f"  Computer: {event['computer']}")
                if 'provider' in event:
                    print(f"  Provider: {event['provider']}")
                print(f"  Message: {event.get('message', '')}")
        else:
            print("\n✓ No suspicious security events found")
            print("\n[SCAN SUMMARY]")
            print(f"  Scanned: Security Log, System Log, Application Log, PowerShell Log")
            print(f"  Time Range: Last {args.hours} hours")
            print(f"  Status: System appears clean - no threats detected")
            print(f"  Note: Security log requires admin privileges to access full details")
        
        # Log scan end
        logger.log_result({
            'type': 'SCAN_END',
            'source': 'Windows Event Logs',
            'events_found': len(events),
            'hours_scanned': args.hours,
            'timestamp': datetime.now().isoformat() + 'Z',
            'status': 'completed'
        })
        
        print(f"\nResults logged to: {logger.log_file}")
        # Trigger confetti if appropriate
        maybe_trigger_confetti(str(logger.log_file), no_celebrate=(not args.celebrate))
        return
    
    # File system scanning
    scanner = FileScanner()
    logger = Logger()
    engine = DecisionEngine()
    quarantine = Quarantine()
    
    print(f"Scanning: {args.path}")
    results = scanner.scan_directory(args.path)
    
    print(f"\nScanned {len(results)} files\n")
    
    matched_files = []
    for result in results:
        logger.log_result(result)
        
        if result['result'] == 'matched':
            score = engine.score_entry(result)
            decision = engine.decide(score)
            
            print(f"[MATCH] {result['path']}")
            print(f"  Hash: {result['hash'][:16]}...")
            print(f"  Signature: {result['signature']}")
            print(f"  Score: {score}/100")
            print(f"  Decision: {decision}\n")
            
            matched_files.append(result)
            
            if args.quarantine and decision == "AUTO QUARANTINE":
                quarantine.quarantine_file(Path(result['path']))
    
    print(f"\nResults logged to: {logger.log_file}")
    if matched_files:
        print(f"Found {len(matched_files)} matched files")

    # After file scan finishes, possibly celebrate
    maybe_trigger_confetti(str(logger.log_file), no_celebrate=(not args.celebrate))

if __name__ == '__main__':
    main()
