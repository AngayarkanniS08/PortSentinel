import dpkt
import datetime
import socket
import time
from collections import defaultdict, deque
from .threat_intelligence import ThreatIntel
# --- PUTHU CHANGE: Namma AI Predictor-ah import panrom ---
from ml_module.predictor import predictor

# Intha class, packets ah oru kuripitta nerathuku save panni vechik yardımcı pannum.
class SlidingWindow:
    """Manages event data within a moving time window."""
    def __init__(self, window_seconds):
        self.window = window_seconds
        self.events = defaultdict(deque)  # src -> deque of (timestamp, info)

    def add(self, src, info):
        self.events[src].append((time.time(), info))

    def prune(self):
        """Removes events that are older than the window."""
        cutoff = time.time() - self.window
        to_del = []
        for src, dq in self.events.items():
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                to_del.append(src)
        for s in to_del:
            del self.events[s]

    def get_events_for_src(self, src):
        return self.events.get(src, [])


class DetectionEngine:
    """
    Analyzes packets using stateful logic to detect multiple Nmap scan types.
    False positives are minimized by correlating multiple factors.
    """
    def __init__(self, db_handler, firewall_manager, socketio, thresholds):
        print(f"Detection Engine upgrading with advanced logic...")
        self.db = db_handler
        self.firewall = firewall_manager
        self.socketio = socketio
        self.thresholds = thresholds # Puthu thresholds use panrom
        
        # --- PUTHU CHANGE: Namma AI model-ah inga ready panrom ---
        self.predictor = predictor
        
        # Data structures for tracking packets
        self.win = SlidingWindow(self.thresholds.get('max_time_window', 30))
        self.tcp = defaultdict(lambda: defaultdict(list))
        self.udp = defaultdict(lambda: defaultdict(list))
        self.icmp = defaultdict(list)
        
        self.start_ts = time.time()
        self.report_times = {}  # To avoid spamming alerts
        self.alert_count = 0
        self.ml_anomaly_count = 0
        self.detected_ips = set()
        self.threat_intel_enabled = False
        ABUSEIPDB_API_KEY = "c8aba3b6eb35cdbc110bbde4ee84e3dac9cbed1d93c5ce9f4cad596fe618fc975abd88306c988a99" # <-- UNGA API KEY-AH INGA PODUNGA
        self.threat_intel = ThreatIntel(ABUSEIPDB_API_KEY)
        
        print(f"Detection Engine initialized with advanced thresholds: {self.thresholds}")

    def process_packet(self, raw_packet, sno):
            """
            Processes a single raw packet. It now handles both IP and non-IP packets
            to ensure the UI always shows all traffic.
            """
            try:
                eth = dpkt.ethernet.Ethernet(raw_packet)

                # MAC Address-ah readable format-ku maathura oru chinna function
                def mac_to_str(address):
                    return ':'.join(f'{b:02x}' for b in address)

                if not isinstance(eth.data, dpkt.ip.IP):
                    return {
                        'sno': sno,
                        'time': datetime.datetime.now().strftime('%H:%M:%S'),
                        'proto': eth.data.__class__.__name__,
                        'source_ip': mac_to_str(eth.src), # type: ignore
                        'dest_ip': mac_to_str(eth.dst), # type: ignore
                        'status': 'Ignored'
                    }

                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src) # type: ignore
                dst_ip = socket.inet_ntoa(ip.dst) # type: ignore
                
                # --- PUTHU CHANGE: AI kitta theerpu kekurom ---
                if self.predictor.is_anomaly(raw_packet):
                    # AI "ithu anomaly" nu sonna, udane alert anupurom
                    self.trigger_alert(src_ip, 'ML Anomaly', 'Medium', [])
                    # Inga packet info return panrathunala, UI la "Scan" nu kaatum
                    return {
                        'sno': sno,
                        'time': datetime.datetime.now().strftime('%H:%M:%S'),
                        'proto': ip.data.__class__.__name__,
                        'source_ip': src_ip,
                        'dest_ip': dst_ip,
                        'status': 'Scan' # AI kandupudichathala "Scan" status kudukrom
                    }

                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    if udp.dport == 53 or udp.sport == 53: # type: ignore
                        return {
                            'sno': sno, 'time': datetime.datetime.now().strftime('%H:%M:%S'),
                            'proto': 'DNS (UDP)', 'source_ip': src_ip, 'dest_ip': dst_ip,
                            'status': 'Ignored (DNS)'
                        }

                if src_ip in self.thresholds.get("whitelist", set()):
                    return None
                
                self.win.add(src_ip, {'proto': ip.p}) # type: ignore
                
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    flags = {
                        'SYN': bool(tcp.flags & dpkt.tcp.TH_SYN), 'ACK': bool(tcp.flags & dpkt.tcp.TH_ACK),# type: ignore
                        'RST': bool(tcp.flags & dpkt.tcp.TH_RST), 'FIN': bool(tcp.flags & dpkt.tcp.TH_FIN),# type: ignore
                        'PSH': bool(tcp.flags & dpkt.tcp.TH_PUSH), 'URG': bool(tcp.flags & dpkt.tcp.TH_URG),# type: ignore
                    }
                    self.tcp[src_ip][dst_ip].append({'ts': time.time(), 'dport': tcp.dport, 'flags': flags}) # type: ignore
                
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    self.udp[src_ip][dst_ip].append({'ts': time.time(), 'dport': udp.dport}) # type: ignore
                
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    icmp = ip.data 
                    self.icmp[src_ip].append({'ts': time.time(), 'dst': dst_ip, 'type': icmp.type, 'code': icmp.code}) # type: ignore
                
                packet_info = {
                    'sno': sno, 'time': datetime.datetime.now().strftime('%H:%M:%S'),
                    'proto': ip.data.__class__.__name__, 'source_ip': src_ip,
                    'dest_ip': dst_ip, 'status': 'Allowed'
                }
                return packet_info

            except Exception:
                return {
                    'sno': sno, 'time': datetime.datetime.now().strftime('%H:%M:%S'),
                    'proto': 'Unknown', 'source_ip': 'N/A',
                    'dest_ip': 'N/A', 'status': 'Parse Error'
                }

    def analyze_and_alert(self):
        """
        This is the new core logic. It runs periodically to analyze the collected packets.
        """
        cutoff = time.time() - self.thresholds.get('max_time_window', 30)
        
        # 1. Prune old records
        self.win.prune()
        for s in list(self.tcp.keys()):
            for d in list(self.tcp[s].keys()):
                self.tcp[s][d] = [r for r in self.tcp[s][d] if r['ts'] >= cutoff]
                if not self.tcp[s][d]: del self.tcp[s][d]
            if not self.tcp[s]: del self.tcp[s]
        
        # 2. Analyze TCP patterns (Rule-based)
        for src, dst_map in self.tcp.items():
            total_pkts = sum(len(lst) for lst in dst_map.values())
            win_events = self.win.get_events_for_src(src)
            pkt_rate = len(win_events) / max(1.0, self.thresholds.get('max_time_window', 30))
            distinct_ports = set(r['dport'] for recs in dst_map.values() for r in recs)

            if len(distinct_ports) < self.thresholds.get('min_ports', 10): continue
            if pkt_rate < self.thresholds.get('min_rate', 5.0): continue

            syn_count = sum(1 for recs in dst_map.values() for r in recs if r['flags']['SYN'] and not r['flags']['ACK'])
            syn_ratio = (syn_count / total_pkts) if total_pkts > 0 else 0
            
            if syn_ratio >= self.thresholds.get('min_syn_ratio', 0.6):
                self.trigger_alert(src, 'SYN Scan', 'High', list(distinct_ports))

        # 3. Analyze UDP patterns (Rule-based)
        for src, dst_map in self.udp.items():
            distinct_udp_ports = set(r['dport'] for recs in dst_map.values() for r in recs)
            if len(distinct_udp_ports) < self.thresholds.get('min_ports', 10): continue
            icmp_unreach = sum(1 for ic_src in self.icmp for r in self.icmp[ic_src] if r['type'] == 3 and r['code'] == 3 and r['dst'] == src)
            if icmp_unreach >= self.thresholds.get('min_icmp_unreach', 3):
                self.trigger_alert(src, 'UDP Scan', 'High', list(distinct_udp_ports))
                
        # 4. Analyze ICMP Ping Sweep (Rule-based)
        for src, recs in self.icmp.items():
            dsts = set(r['dst'] for r in recs if r['type'] == 8)
            if len(dsts) >= self.thresholds.get('min_icmp_targets', 6):
                self.trigger_alert(src, 'Ping Sweep', 'Medium', list(dsts))


    def trigger_alert(self, src_ip, scan_type, severity, ports):
            """
            Helper function to create and send alerts with threat intel.
            (ML and Rule based alerts-ku thani thani cool-down vechi, alert-ah anupum).
            """
            # --- PUTHU UPGRADE: ML vs RULE ALERT-ku Thani Thani Cool-down ---
            
            # 1. Alert ML model-la irundhu vandha, count-ah adhigamaakki, 5 nimisham cool-down vekkanum
            if scan_type == 'ML Anomaly':
                key = (src_ip, scan_type)
                # Ore IP-la irundhu adutha 5 nimishathuku ML alert vandha, ignore pannu
                if time.time() - self.report_times.get(key, 0) < 300: # 300 seconds = 5 minutes
                    return
                self.ml_anomaly_count += 1 # AI kandupudicha count-ah ethrom
            
            # 2. Illana, ithu rule-based alert. Pazhaya maathiri 1 nimisham cool-down pothum
            else:
                key = (src_ip, scan_type)
                # Ore IP-la irundhu adutha 1 nimishathuku rule alert vandha, ignore pannu
                if time.time() - self.report_times.get(key, 0) < 60: # 60 seconds = 1 minute
                    return

            # --- Matha logic-lam apdiye thaan irukum ---
            
            intel_data = None
            if self.threat_intel_enabled:
                print(f"Threat Intel is ON. Checking IP: {src_ip}")
                intel_data = self.threat_intel.check_ip(src_ip)
            else:
                print(f"Threat Intel is OFF. Skipping IP check for: {src_ip}")

            if intel_data and intel_data['score'] > 80:
                severity = "Critical"

            self.report_times[key] = time.time() # Alert anupuna neratha save pannikom
            self.alert_count += 1
            self.detected_ips.add(src_ip)
            
            is_blocked_now = False
            if severity.lower() in ['high', 'critical']:
                if self.firewall:
                    self.firewall.block_ip(src_ip)
                    is_blocked_now = True

            alert_data = {
                'ip_address': src_ip,
                'scan_type': scan_type,
                'severity': severity,
                'is_blocked': is_blocked_now,
                'intel': intel_data
            }
            
            print(f"ALERT TRIGGERED: {scan_type} from {src_ip}. Severity: {severity}. Blocked: {is_blocked_now}")
            
            # SocketIO மூலமா UI-ku alert-ah anupurom
            self.socketio.emit('new_alert', alert_data)
            
            # Database-la antha detection-ah save panrom
            self.db.add_detection(src_ip, scan_type, severity)