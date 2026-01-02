import subprocess
import json
import os
import sys
import argparse
import re
import threading
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Set, Optional, Any


DOUBLE_EXT_REGEX = re.compile(
    r'\.(pdf|docx?|xlsx?|jpg|jpeg|png|txt|zip|rar|7z|rtf|csv)'
    r'(\.exe|\.com|\.scr|\.cpl|\.bat|\.cmd|\.ps1|\.vbs|\.js|\.jse|\.wsf|\.msi|\.pif|\.gadget)$',
    re.IGNORECASE
)
PATH_TOKEN_REGEX = re.compile(r'[C-Z]:\\[^\"\s]+|\\[^\"\s]+', re.IGNORECASE)
COM_ABUSE_REGEX = re.compile(r'new-object\s+-comobject|createobject\(', re.IGNORECASE)
BASE64_OBFUSC_REGEX = re.compile(r'-enc\s+|-encodedcommand\s+|iex\s+|invoke-expression|downloadstring', re.IGNORECASE)

LOLBIN_PATTERNS = {
    'regsvr32': [re.compile(r'/i:.*http', re.IGNORECASE), re.compile(r'scrobj\.dll', re.IGNORECASE)],
    'rundll32': [re.compile(r'javascript:', re.IGNORECASE), re.compile(r'pcwutl\.dll', re.IGNORECASE), re.compile(r'dfshim\.dll', re.IGNORECASE)],
    'mshta': [re.compile(r'http', re.IGNORECASE), re.compile(r'\.sct', re.IGNORECASE)],
    'wmic': [re.compile(r'process call create.*cmd', re.IGNORECASE), re.compile(r'process call create.*powershell', re.IGNORECASE)],
    'certutil': [re.compile(r'-urlcache', re.IGNORECASE), re.compile(r'-decode .*\.exe', re.IGNORECASE), re.compile(r'-decode .*\.dll', re.IGNORECASE)],
    'bitsadmin': [re.compile(r'/transfer.*http', re.IGNORECASE)],
}

DISCOVERY_KEYWORDS = {
    'dir', 'ls', 'tree', 'type', 'get-content', 'cat', 'findstr', 'attrib', 'icacls', 'robocopy', 'copy', 'move', 'del', 'rd',
    'whoami', 'net user', 'net localgroup', 'net group', 'query user', 'get-localuser', 'get-aduser', 'get-localgroupmember', 'wmic useraccount', 'dsquery user', 'lusrmgr.msc',
    'systeminfo', 'tasklist', 'wmic', 'get-service', 'sc config', 'sc query', 'services.msc', 'msinfo32',
    'ipconfig', 'netstat', 'arp', 'route', 'netsh', 'ping', 'tracert', 'nslookup',
    'get-wmiobject -namespace "root\\securitycenter2"', 'get-mpcomputerstatus', 'defender', 'taskmgr.exe'
}

COLLECTION_TRIGGERS = {
    'archive': ['compress-archive', '7z.exe', '7za.exe', 'winrar.exe', 'tar.exe', 'zip.exe'],
    'file_search': ['get-childitem', 'gci', 'dir /s', 'ls -r', 'findstr', 'grep'],
    'file_copy_move': ['copy', 'xcopy', 'robocopy', 'move', 'cp'],
    'credential_access': ['mimikatz', 'procdump', 'sekurlsa::logonpasswords', 'lsass', 'cmdkey /list', 'vaultcmd /listcreds', 'dpapi::'],
    'exfiltration': ['curl.exe', 'certutil -urlcache', 'wget.exe', 'bitsadmin /transfer', 'invoke-webrequest', 'iwr ', 'ftp -s:', 'scp ', 'sftp ']
}

EXFIL_DOMAINS = {'dropbox.com', 'mega.nz', 'github.com', 'api.telegram.org', 'discord.com', 'amazonaws.com'}
SYSTEM_LOGON_IDS = {'0x3e7', '0x3e4', '0x3e5'}
LEGIT_TECH_KEYWORDS = {'vscode', 'editor-services', 'onedrive', 'ngciso', 'ms-vscode', 'code.exe', 'powershell-ise'}
DISCOVERY_CAPABLE_IMAGES = {'cmd.exe', 'powershell.exe', 'wmic.exe', 'net.exe', 'whoami.exe', 'tasklist.exe', 'systeminfo.exe', 'ipconfig.exe', 'sc.exe'}
OFFICE_APPS = {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'mspub.exe', 'visio.exe'}

g_user = None

def is_private_ip(ip):
    if not ip or ip in ['-', '::1', '127.0.0.1', '0.0.0.0']:
        return True
    try:
        from ipaddress import ip_address
        return ip_address(ip).is_private
    except Exception:
        return False

def load_known_ip_prefixes(file_path=None):
    built_in = {
        '149.154.161.', '149.154.167.', '149.154.171.', '185.76.151.',
        '13.107.', '13.89.', '13.104.', '20.189.', '20.42.', '51.104.',
        '52.112.', '52.113.', '52.120.', '52.168.', '52.109.', '150.171.',
        '172.217.', '142.250.', '172.250.', '8.8.',
        '1.1.', '104.16.', '104.17.', '104.18.', '172.64.', '172.65.',
        '31.13.', '69.171.', '157.240.',
        '17.0.', '17.2.',
    }
    if not file_path:
        return built_in
    if not os.path.isfile(file_path):
        return built_in
    prefixes = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if any(c.isdigit() for c in line):
                        if not line.endswith('.'):
                            line += '.'
                        prefixes.add(line)
        return prefixes
    except:
        return built_in

def is_known_good_ip(ip, known_prefixes):
    return any(ip.startswith(prefix) for prefix in known_prefixes)

def is_suspicious_double_ext(filepath):
    if not filepath:
        return False
    name = os.path.basename(filepath)
    return bool(DOUBLE_EXT_REGEX.search(name))

def is_removable_drive_path(filepath):
    if not filepath or len(filepath) < 3 or filepath[1:3] != ':\\':
        return False
    drive_letter = filepath[0].upper()
    if drive_letter == 'C':
        return False
    if 'D' <= drive_letter <= 'Z':
        lower_path = filepath.lower()
        system_indicators = [
            '\\windows\\', '\\program files', '\\programdata',
            '\\users\\', '\\perflogs\\', '\\recovery\\'
        ]
        if any(ind in lower_path for ind in system_indicators):
            return False
        return True
    return False

def is_trusted_path(filepath: str, user: str = None) -> bool:
    if not filepath:
        return False
    fp = filepath.lower().replace('\\', '/')
    trusted_roots = [
        'c:/windows/system32/',
        'c:/windows/syswow64/',
        'c:/program files/',
        'c:/program files (x86)/',
    ]
    if user:
        trusted_roots.extend([
            f'c:/users/{user.lower()}/appdata/local/programs/',
            f'c:/users/{user.lower()}/appdata/local/microsoft/',
            f'c:/users/{user.lower()}/appdata/roaming/microsoft/',
        ])
    for root in trusted_roots:
        if fp.startswith(root):
            return True
    return False

def load_sensitive_paths(file_path: Optional[str] = None) -> Dict[str, List[str]]:
    default = {
        'blackmail': [
            r'\\AppData\\Roaming\\Signal\\',
            r'\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History',
            r'\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies',
            r'\\AppData\\Roaming\\Telegram Desktop\\',
            r'\\Pictures\\',
            r'\\Desktop\\.*\.(docx?|xlsx?|pdf|txt|jpg|png|jpeg)$'
        ],
        'financial': [
            r'\\AppData\\Roaming\\Bitcoin\\wallet\.dat',
            r'\\AppData\\Roaming\\Ethereum\\',
            r'\\AppData\\Roaming\\Exodus\\',
            r'\\AppData\\Roaming\\MetaMask\\',
            r'\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies'
        ],
        'corporate': [
            r'\\.ssh\\',
            r'\\AppData\\Roaming\\gcloud\\',
            r'\\AppData\\Roaming\\aws\\',
            r'\\AppData\\Roaming\\azure\\',
        ]
    }
    if not file_path:
        return default
    if not os.path.isfile(file_path):
        return default
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return default

def is_sensitive_path(filepath: str, sensitive_patterns: Dict[str, List[str]]) -> Optional[str]:
    if not filepath:
        return None
    fp = filepath.lower().replace('\\', '\\\\')
    for category, patterns in sensitive_patterns.items():
        for pattern in patterns:
            full_pattern = pattern if pattern.startswith(r'\\') else r'.*' + pattern
            try:
                if re.search(full_pattern, fp, re.IGNORECASE):
                    return category
            except re.error:
                continue
    return None

def extract_path_tokens(cmd: str):
    return PATH_TOKEN_REGEX.findall(cmd)

class SessionRiskScorer:
    def __init__(self):
        self.sessions = defaultdict(lambda: {
            'score': 0,
            'events': [],
            'user': None,
            'source_ip': None,
            'first_seen': None,
            'last_seen': None
        })
        self.rules = [
            {'type': 'external_rdp', 'score': 10},
            {'type': 'brute_force', 'score': 15},
            {'type': 'obfuscated_ps', 'score': 12},
            {'type': 'lolbin', 'score': 10},
            {'type': 'sensitive_access', 'score': 5},
            {'type': 'persistence', 'score': 8},
            {'type': 'collection', 'score': 10},
            {'type': 'exfil', 'score': 15},
            {'type': 'com_abuse', 'score': 12},
        ]

    def add_event(self, logon_id: str, event_type: str, event: Dict[str, Any], user: str = None, source_ip: str = None):
        if logon_id not in self.sessions:
            self.sessions[logon_id]['first_seen'] = datetime.fromisoformat(event['time'].replace('Z', '+00:00'))
        self.sessions[logon_id]['last_seen'] = datetime.fromisoformat(event['time'].replace('Z', '+00:00'))
        self.sessions[logon_id]['events'].append({**event, 'type': event_type})
        if user:
            self.sessions[logon_id]['user'] = user
        if source_ip:
            self.sessions[logon_id]['source_ip'] = source_ip
        for rule in self.rules:
            if rule['type'] == event_type:
                self.sessions[logon_id]['score'] += rule['score']
                break

    def get_high_risk_sessions(self, threshold: int = 25):
        high_risk = []
        for logon_id, data in self.sessions.items():
            if data['score'] >= threshold:
                duration = (data['last_seen'] - data['first_seen']).total_seconds()
                high_risk.append({
                    'logon_id': logon_id,
                    'user': data['user'],
                    'source_ip': data['source_ip'],
                    'score': data['score'],
                    'duration_seconds': int(duration),
                    'event_count': len(data['events']),
                    'events': data['events']
                })
        return high_risk

def is_suspicious_process_tree(pid, pid_to_event, process_events):
    if pid not in pid_to_event:
        return False
    item = pid_to_event[pid]
    img_basename = item['img_basename']
    
    if img_basename in OFFICE_APPS:
        children = [e for e in process_events if e['ppid'] == pid]
        for child in children:
            if child['img_basename'] in {'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe'}:
                return True
    return False

def run_powershell_script(full_command: List[str]) -> Optional[str]:
    result = subprocess.run(full_command, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    for line in result.stdout.split('\n'):
        if line.startswith("OUTPUT_FILE:"):
            return line[len("OUTPUT_FILE:"):].strip()
    return None

def load_jsonl(path):
    if not path or not os.path.exists(path):
        return []
    data = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    data.append(json.loads(line))
                except:
                    pass
    return data

def main():
    global g_user
    parser = argparse.ArgumentParser(description="Advanced Threat Detection")
    parser.add_argument("-s", "--security", help="Path to Security .evtx log file")
    parser.add_argument("-j", "--journal", help="Path to Sysmon .evtx log file")
    parser.add_argument("-t", "--hours", type=int, default=24, help="Time window in hours")
    parser.add_argument("-k", "--known-ips", help="Path to known good IP prefixes")
    parser.add_argument("--sensitive-paths", help="Path to JSON with sensitive path patterns")
    parser.add_argument("-o", "--output", help="Export alerts to JSON")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--only-id", help="Comma-separated list of MITRE IDs to include")
    parser.add_argument("--exclude-id", help="Comma-separated list of MITRE IDs to exclude")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--session-report", action="store_true")
    args = parser.parse_args()

    if args.hours <= 0:
        print("[!] Error: --hours must be positive.")
        sys.exit(1)

    only_ids = set(args.only_id.split(',')) if args.only_id else None
    exclude_ids = set(args.exclude_id.split(',')) if args.exclude_id else set()

    known_ip_prefixes = load_known_ip_prefixes(args.known_ips)
    sensitive_patterns = load_sensitive_paths(args.sensitive_paths)

    print(f"[*] Analyzing events from the last {args.hours} hour(s)...")
    print(f"    Security source: {'LIVE' if not args.security else os.path.abspath(args.security)}")
    print(f"    Sysmon source:   {'LIVE' if not args.journal else os.path.abspath(args.journal)}")

    #ЗАПУСК СБОРЩИКОВ
    ps_sec = ["powershell", "-ExecutionPolicy", "Bypass", "-File", "collect_security.ps1", "-HoursBack", str(args.hours)]
    if args.security:
        ps_sec.extend(["-LogPath", os.path.abspath(args.security)])

    ps_sys = ["powershell", "-ExecutionPolicy", "Bypass", "-File", "collect_sysmon.ps1", "-HoursBack", str(args.hours)]
    if args.journal:
        ps_sys.extend(["-LogPath", os.path.abspath(args.journal)])

    sec_file = [None]
    sys_file = [None]
    sec_thread = threading.Thread(target=lambda: sec_file.__setitem__(0, run_powershell_script(ps_sec)))
    sys_thread = threading.Thread(target=lambda: sys_file.__setitem__(0, run_powershell_script(ps_sys)))
    sec_thread.start()
    sys_thread.start()
    sec_thread.join()
    sys_thread.join()

    try:
        security_events = load_jsonl(sec_file[0])
        sysmon_events = load_jsonl(sys_file[0])
    finally:
        for f in [sec_file[0], sys_file[0]]:
            if f and os.path.exists(f):
                try:
                    os.remove(f)
                except:
                    pass

    if args.stats:
        from collections import Counter
        sysmon_ids = Counter(e.get('Id') for e in sysmon_events)
        sec_ids = Counter(e.get('Id') for e in security_events)
        print(f"\n[=] Sysmon: {dict(sysmon_ids)} | Security: {dict(sec_ids)}")
        top_procs = Counter(e.get('Image', '').lower() for e in sysmon_events if e.get('Id') == 1)
        print(f"Top processes: {top_procs.most_common(10)}")
        return

    for e in security_events:
        if e.get('Id') == 4624 and e.get('TargetUser'):
            g_user = e['TargetUser']
            break

    process_events = []
    file_create_events = []
    registry_events = []
    network_events = []

    for e in sysmon_events:
        eid = e.get('Id')
        if eid == 1:
            img = e.get('Image') or ''
            cmd = e.get('CommandLine') or ''
            parent_img = e.get('ParentImage') or ''
            logon_id = e.get('LogonId')
            pid = e.get('ProcessId')
            ppid = e.get('ParentProcessId')

            img_lower = img.lower()
            cmd_lower = cmd.lower()
            parent_img_lower = parent_img.lower()

            img_basename = os.path.basename(img_lower)
            parent_basename = os.path.basename(parent_img_lower)

            is_obfuscated_ps = 'powershell.exe' in img_lower and bool(BASE64_OBFUSC_REGEX.search(cmd_lower))
            com_abuse = 'powershell.exe' in img_lower and bool(COM_ABUSE_REGEX.search(cmd_lower))

            lolbin_alert = None
            for tool, patterns in LOLBIN_PATTERNS.items():
                if tool in img_lower:
                    if any(pat.search(cmd_lower) for pat in patterns):
                        lolbin_alert = f"T1218: LOLBin Abuse ({tool})"
                        break

            is_discovery = any(kw in cmd_lower for kw in DISCOVERY_KEYWORDS)

            process_events.append({
                'event': e,
                'img': img,
                'img_lower': img_lower,
                'img_basename': img_basename,
                'cmd': cmd,
                'cmd_lower': cmd_lower,
                'parent_img': parent_img,
                'parent_img_lower': parent_img_lower,
                'parent_basename': parent_basename,
                'logon_id': logon_id,
                'pid': pid,
                'ppid': ppid,
                'is_obfuscated_ps': is_obfuscated_ps,
                'com_abuse': com_abuse,
                'lolbin_alert': lolbin_alert,
                'is_discovery': is_discovery,
            })
        elif eid == 11:
            file_create_events.append(e)
        elif eid == 13:
            registry_events.append(e)
        elif eid == 3:
            network_events.append(e)

    print(f"[+] Loaded {len(security_events)} Security events, {len(sysmon_events)} Sysmon events.")

    pid_to_event = {item['pid']: item for item in process_events if item['pid']}
    alerts = []
    scorer = SessionRiskScorer()

    brute_attempts = defaultdict(int)
    rdp_logons = []
    for e in security_events:
        if e.get('Id') == 4625:
            ip = e.get('SourceIp')
            if ip and not is_private_ip(ip):
                brute_attempts[ip] += 1
        elif e.get('Id') == 4624 and e.get('LogonType') == 10:
            ip = e.get('SourceIp')
            if ip and not is_private_ip(ip):
                rdp_logons.append(e)
                alerts.append({
                    "reason": "T1078.004: External RDP Login",
                    "time": e.get('Time'),
                    "details": f"User: {e.get('TargetUser')}, IP: {ip}",
                    "logon_id": e.get('LogonId'),
                    "id": "4624-rdp",
                    "confidence": "high"
                })

    rdp_logon_ids = {e.get('LogonId') for e in rdp_logons if e.get('LogonId')}
    for ip, count in brute_attempts.items():
        if count >= 10:
            alerts.append({"reason": "T1110.003: RDP Brute Force Detected", "details": f"{count} failed logins from {ip}", "id": "4625-brute", "confidence": "high"})

    for item in process_events:
        img = item['img']
        img_lower = item['img_lower']
        img_basename = item['img_basename']
        cmd = item['cmd']
        cmd_lower = item['cmd_lower']
        parent_img = item['parent_img']
        parent_img_lower = item['parent_img_lower']
        parent_basename = item['parent_basename']
        logon_id = item['logon_id']
        pid = item['pid']
        is_obfuscated_ps = item['is_obfuscated_ps']
        com_abuse = item['com_abuse']
        lolbin_alert = item['lolbin_alert']
        is_discovery = item['is_discovery']

        if (is_removable_drive_path(img) or 
            is_suspicious_double_ext(img) or 
            '\\temp\\' in img_lower or 
            '\\users\\public\\' in img_lower):

            reason = "T1566/T1204: Suspicious Execution"
            if is_removable_drive_path(img):
                reason = "T1566.003: Initial Access via Removable Media"
                if is_suspicious_double_ext(img):
                    reason += " (Double Extension)"
            elif is_suspicious_double_ext(img):
                reason = "T1566.001: Suspicious Double Extension Binary"
            elif '\\temp\\' in img_lower:
                reason = "T1204/T1566: Process from TEMP"
            if logon_id in rdp_logon_ids:
                reason += " after RDP login"
            alert = {
                "reason": reason,
                "time": item['event'].get('Time'),
                "image": img,
                "command_line": cmd,
                "id": "initial-access",
                "confidence": "high"
            }
            alerts.append(alert)
            if logon_id:
                scorer.add_event(logon_id, 'initial_access', {'time': alert['time']})

        if lolbin_alert:
            alert = {
                "reason": lolbin_alert,
                "time": item['event'].get('Time'),
                "image": img,
                "command_line": cmd,
                "id": "lolbin",
                "confidence": "high"
            }
            alerts.append(alert)
            if logon_id:
                scorer.add_event(logon_id, 'lolbin', {'time': alert['time']})

        if com_abuse:
            alert = {
                "reason": "T1176: Browser or COM Object Abuse",
                "time": item['event'].get('Time'),
                "image": img,
                "command_line": cmd,
                "id": "com-abuse",
                "confidence": "high"
            }
            alerts.append(alert)
            if logon_id:
                scorer.add_event(logon_id, 'com_abuse', {'time': alert['time']})

        if is_obfuscated_ps:
            reason = "T1059.001: Obfuscated PowerShell"
            if logon_id in rdp_logon_ids:
                reason += " after RDP login"
            alert = {
                "reason": reason,
                "time": item['event'].get('Time'),
                "image": img,
                "command_line": cmd,
                "id": "ps-obf",
                "confidence": "high"
            }
            alerts.append(alert)
            if logon_id:
                scorer.add_event(logon_id, 'obfuscated_ps', {'time': alert['time']})

        sensitive_category = is_sensitive_path(img, sensitive_patterns)
        cmd_has_sensitive = False
        for token in extract_path_tokens(cmd):
            cat = is_sensitive_path(token, sensitive_patterns)
            if cat:
                cmd_has_sensitive = True
                if not sensitive_category:
                    sensitive_category = cat
                break
        if sensitive_category and pid:
            if logon_id:
                scorer.add_event(logon_id, 'sensitive_access', {'time': item['event'].get('Time'), 'category': sensitive_category})

        is_trusted = is_trusted_path(img, g_user)
        is_system_session = logon_id in SYSTEM_LOGON_IDS
        is_legit_tech = len(cmd) > 300 and any(kw in cmd_lower for kw in LEGIT_TECH_KEYWORDS)
        has_real_target = sensitive_category or cmd_has_sensitive

        collection_triggers = []
        for key, cmds in COLLECTION_TRIGGERS.items():
            if any(kw in cmd_lower for kw in cmds):
                collection_triggers.append(key.replace('_', ' ').title())

        if collection_triggers and has_real_target and not (is_legit_tech or (is_system_session and not any(kw in cmd_lower for kw in ['mimikatz', 'lsass']))):
            reason = f"T1560/T1555/T1105: Suspicious Collection ({', '.join(collection_triggers)})"
            if logon_id in rdp_logon_ids:
                reason += " after RDP login"
            alert = {
                "reason": reason,
                "time": item['event'].get('Time'),
                "image": img,
                "command_line": cmd,
                "parent_image": parent_img,
                "id": "collection-cmd",
                "confidence": "high"
            }
            alerts.append(alert)
            if logon_id:
                scorer.add_event(logon_id, 'collection', {'time': alert['time']})

        if 'lsass.dmp' in cmd_lower or ('procdump' in cmd_lower and 'lsass' in cmd_lower):
            alert = {
                "reason": "T1003.001: LSASS Memory Dumping",
                "time": item['event'].get('Time'),
                "image": img,
                "command_line": cmd,
                "parent_image": parent_img,
                "id": "lsass-dump",
                "confidence": "high"
            }
            alerts.append(alert)
            if logon_id:
                scorer.add_event(logon_id, 'collection', {'time': alert['time']})

        if img_basename in DISCOVERY_CAPABLE_IMAGES and is_discovery:
            parent_is_legit_editor = parent_basename in {'code.exe', 'devenv.exe', 'pycharm64.exe'}
            if (logon_id in rdp_logon_ids or is_removable_drive_path(parent_img) or is_suspicious_double_ext(parent_img)) and not parent_is_legit_editor:
                reason = "T1087/T1016: Suspicious Discovery"
                if logon_id in rdp_logon_ids:
                    reason += " after RDP login"
                alert = {
                    "reason": reason,
                    "time": item['event'].get('Time'),
                    "image": img,
                    "command_line": cmd,
                    "parent_image": parent_img,
                    "id": "discovery",
                    "confidence": "medium"
                }
                alerts.append(alert)
                if logon_id:
                    scorer.add_event(logon_id, 'discovery', {'time': alert['time']})

        if is_suspicious_process_tree(pid, pid_to_event, process_events):
            alert = {
                "reason": "T1566.001/T1204: Suspicious Process Tree (e.g., Office → PowerShell)",
                "time": item['event'].get('Time'),
                "image": img,
                "pid": pid,
                "id": "process-tree",
                "confidence": "high"
            }
            alerts.append(alert)
            if logon_id:
                scorer.add_event(logon_id, 'initial_access', {'time': alert['time']})

    session_timeline = defaultdict(list)
    for alert in alerts:
        if 'category' in alert and 'time' in alert and alert.get('logon_id'):
            try:
                event_time = datetime.fromisoformat(alert['time'].replace('Z', '+00:00'))
                session_timeline[alert['logon_id']].append({
                    'category': alert['category'],
                    'time': event_time,
                    'event': alert
                })
            except:
                pass

    for logon_id, events in session_timeline.items():
        if len(events) >= 5:
            categories = {e['category'] for e in events}
            if len(categories) >= 2:
                times = [e['time'] for e in events]
                if max(times) - min(times) <= timedelta(seconds=120):
                    first_evt = events[0]['event']
                    alert = {
                        "reason": "T1555/T1005: Data Stealer Behavior",
                        "time": first_evt.get('Time'),
                        "image": first_evt.get('Image'),
                        "categories_accessed": sorted(categories),
                        "files_accessed": len(events),
                        "duration_seconds": int((max(times) - min(times)).total_seconds()),
                        "id": "data-stealer",
                        "confidence": "high"
                    }
                    alerts.append(alert)
                    scorer.add_event(logon_id, 'collection', {'time': alert['time']})

    startup_patterns = [
        r'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\',
        r'\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\'
    ]
    for e in file_create_events:
        target = e.get('TargetFilename', '')
        if not target:
            continue
        name_lower = os.path.basename(target).lower()
        if any(w in name_lower for w in ['stolen', 'data', 'backup', 'archive', 'grab', 'dump']) and target.endswith(('.zip', '.rar', '.7z')):
            alerts.append({
                "reason": "T1560.001: Suspicious Archive Created",
                "time": e.get('Time'),
                "target_filename": target,
                "creating_process": e.get('Image'),
                "id": "archive-create",
                "confidence": "medium"
            })
        if is_sensitive_path(target, sensitive_patterns):
            alerts.append({
                "reason": f"T1555: Sensitive File Modified",
                "time": e.get('Time'),
                "target_filename": target,
                "creating_process": e.get('Image'),
                "id": "sensitive-file-create",
                "confidence": "medium"
            })
        if any(pattern in target for pattern in startup_patterns):
            alerts.append({
                "reason": "T1547.001: Startup Folder Persistence",
                "time": e.get('Time'),
                "target_filename": target,
                "creating_process": e.get('Image'),
                "id": "startup-persistence",
                "confidence": "high"
            })

    RUN_KEYS = [
        r'\registry\machine\software\microsoft\windows\currentversion\run',
        r'\registry\user\.*\software\microsoft\windows\currentversion\run'
    ]
    for e in registry_events:
        target = (e.get('TargetObject') or '').lower()
        if any(key in target for key in RUN_KEYS):
            alerts.append({
                "reason": "T1547.001: Run Key Persistence",
                "time": e.get('Time'),
                "target_object": e.get('TargetObject'),
                "details": e.get('Details'),
                "image": e.get('Image'),
                "id": "runkey-persistence",
                "confidence": "high"
            })

    for e in network_events:
        ip = e.get('DestinationIp')
        port = e.get('DestinationPort')
        host = e.get('DestinationHostname', '')
        if not ip or not port or is_private_ip(ip):
            continue
        if is_known_good_ip(ip, known_ip_prefixes):
            continue
        if host:
            domain = host.lower().split('/')[0].split(':')[0]
            if any(exfil in domain for exfil in EXFIL_DOMAINS):
                alerts.append({
                    "reason": "T1567: Data Exfiltration to Cloud/Messenger",
                    "time": e.get('Time'),
                    "destination": f"{ip}:{port}",
                    "hostname": host,
                    "id": "exfil-cloud",
                    "confidence": "high"
                })

    for e in security_events:
        eid = e.get('Id')
        alert = None
        if eid == 4720:
            alert = {
                "reason": "T1136: Account Created (Potential Backdoor)",
                "time": e.get('Time'),
                "details": f"User: {e.get('TargetUserName')}, Creator: {e.get('SubjectUserName')}, IP: {e.get('IpAddress')}",
                "id": "user-create",
                "confidence": "medium"
            }
        elif eid == 4732:
            group = e.get('TargetUserName', '')
            if 'administrators' in group.lower() or 'remote desktop' in group.lower():
                alert = {
                    "reason": "T1098: Privileged Group Membership Added",
                    "time": e.get('Time'),
                    "details": f"User: {e.get('MemberName')}, Group: {group}, By: {e.get('SubjectUserName')}",
                    "id": "group-add",
                    "confidence": "high"
                }
        elif eid == 4724:
            alert = {
                "reason": "T1078: Password Reset (Potential Account Takeover)",
                "time": e.get('Time'),
                "details": f"User: {e.get('TargetUserName')}, By: {e.get('SubjectUserName')}, IP: {e.get('IpAddress')}",
                "id": "pwd-reset",
                "confidence": "high"
            }
        elif eid == 4697:
            alert = {
                "reason": "T1543.003: Service Created (Security Log)",
                "time": e.get('Time'),
                "details": f"Service: {e.get('ServiceName')}, Binary: {e.get('ImagePath')}, By: {e.get('SubjectUserName')}",
                "id": "service-security",
                "confidence": "high"
            }
        elif eid == 4698:
            alert = {
                "reason": "T1053.005: Scheduled Task Created (Security Log)",
                "time": e.get('Time'),
                "details": f"Task: {e.get('TaskName')}, By: {e.get('SubjectUserName')}",
                "id": "task-security",
                "confidence": "high"
            }

        if alert:
            alerts.append(alert)

    final_alerts = []
    for a in alerts:
        if exclude_ids and a.get("id") in exclude_ids:
            continue
        if only_ids and not any(tid in a.get("reason", "") for tid in only_ids):
            continue
        final_alerts.append(a)

    if args.session_report:
        high_risk = scorer.get_high_risk_sessions(threshold=25)
        if high_risk:
            print(f"\n[!] Detected {len(high_risk)} high-risk sessions:")
            for sess in high_risk:
                print(f"\n→ Session LogonId: {sess['logon_id']} | User: {sess['user']} | IP: {sess['source_ip']} | Score: {sess['score']}")
                print(f"  Duration: {sess['duration_seconds']} sec | Events: {sess['event_count']}")
                unique_types = set(e['type'] for e in sess['events'])
                for t in unique_types:
                    print(f"    - {t}")
        else:
            print("[+] No high-risk sessions detected.")
    else:
        filtered_alerts = [a for a in final_alerts if a.get("confidence") != "low" or args.verbose]
        if filtered_alerts:
            print(f"\n[!] Detected {len(filtered_alerts)} threat indicators:")
            seen = set()
            for alert in filtered_alerts:
                key = (alert.get("reason"), alert.get("time", ""), alert.get("image", alert.get("target_filename", alert.get("destination", alert.get("details", "")))))
                if key in seen:
                    continue
                seen.add(key)
                print(f"\n→ {alert['reason']}")
                for k, v in alert.items():
                    if k not in ('reason', 'id', 'confidence', 'logon_id', 'category'):
                        if k == 'recommendations':
                            print(f"  Recommendations:")
                            for rec in v:
                                print(f"    - {rec}")
                        else:
                            print(f"  {k.replace('_', ' ').title()}: {v}")
        else:
            print("[+] No threats detected.")

    if args.output:
        export_data = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "hours_back": args.hours,
                "user_detected": g_user,
                "alerts_found": len(final_alerts),
                "total_sysmon_events": len(sysmon_events),
                "total_security_events": len(security_events)
            },
            "alerts": final_alerts
        }
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            print(f"\n[+] Results exported to: {args.output}")
        except Exception as e:
            print(f"[!] Export failed: {e}")

if __name__ == "__main__":
    main()
