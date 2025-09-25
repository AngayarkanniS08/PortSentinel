# =================================================================
#            NEW AND UPGRADED engine.py FILE
# =================================================================
import dpkt
import datetime
import socket
import time
from collections import defaultdict, deque

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
        
        # Data structures for tracking packets
        self.win = SlidingWindow(self.thresholds.get('max_time_window', 30))
        self.tcp = defaultdict(lambda: defaultdict(list))
        self.udp = defaultdict(lambda: defaultdict(list))
        self.icmp = defaultdict(list)
        
        self.start_ts = time.time()
        self.report_times = {}  # To avoid spamming alerts
        self.alert_count = 0
        self.detected_ips = set()
        
        print(f"Detection Engine initialized with advanced thresholds: {self.thresholds}")

    def process_packet(self, raw_packet, sno):
        """
        Processes a single raw packet and stores it for future analysis.
        (Inga analysis nadakathu, verum data mattum store pannum)
        """
        try:
            eth = dpkt.ethernet.Ethernet(raw_packet)
            if not isinstance(eth.data, dpkt.ip.IP): return None

            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)  # type: ignore
            dst_ip = socket.inet_to_a(ip.dst)  # type: ignore

            # Whitelist la irundha ignore pannidalam
            if src_ip in self.thresholds.get("whitelist", set()): return None
            
            # --- Packet information ah collect panrom ---
            self.win.add(src_ip, {'proto': ip.p})  # type: ignore
            
            # TCP Packet
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                flags = {
                    'SYN': bool(tcp.flags & dpkt.tcp.TH_SYN), 'ACK': bool(tcp.flags & dpkt.tcp.TH_ACK),  # type: ignore
                    'RST': bool(tcp.flags & dpkt.tcp.TH_RST), 'FIN': bool(tcp.flags & dpkt.tcp.TH_FIN),  # type: ignore
                    'PSH': bool(tcp.flags & dpkt.tcp.TH_PUSH), 'URG': bool(tcp.flags & dpkt.tcp.TH_URG),  # type: ignore
                }
                self.tcp[src_ip][dst_ip].append({'ts': time.time(), 'dport': tcp.dport, 'flags': flags})  # type: ignore
            
            # UDP Packet
            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                self.udp[src_ip][dst_ip].append({'ts': time.time(), 'dport': udp.dport})  # type: ignore
            
            # ICMP Packet
            elif isinstance(ip.data, dpkt.icmp.ICMP):
                icmp = ip.data 
                self.icmp[src_ip].append({'ts': time.time(), 'dst': dst_ip, 'type': icmp.type, 'code': icmp.code})  # type: ignore
            
            # UI ku anupurathuku, basic info create panrom
            packet_info = {
                'sno': sno, 'time': datetime.datetime.now().strftime('%H:%M:%S'),
                'proto': ip.data.__class__.__name__, 'source_ip': src_ip, 'dest_ip': dst_ip, 'status': 'Allowed'
            }
            return packet_info

        except Exception:
            return None

    def analyze_and_alert(self):
        """
        This is the new core logic. It runs periodically to analyze the collected packets.
        (Intha function-ah `main.py`-la irundhu call pannanum)
        """
        cutoff = time.time() - self.thresholds.get('max_time_window', 30)
        
        # 1. Prune old records (Pazhaya data-lam delete pannu)
        self.win.prune()
        for s in list(self.tcp.keys()):
            for d in list(self.tcp[s].keys()):
                self.tcp[s][d] = [r for r in self.tcp[s][d] if r['ts'] >= cutoff]
                if not self.tcp[s][d]: del self.tcp[s][d]
            if not self.tcp[s]: del self.tcp[s]
        # (UDP and ICMP kum ipdiye pannanum)

        # 2. Analyze TCP patterns
        for src, dst_map in self.tcp.items():
            total_pkts = sum(len(lst) for lst in dst_map.values())
            win_events = self.win.get_events_for_src(src)
            pkt_rate = len(win_events) / max(1.0, self.thresholds.get('max_time_window', 30))
            
            distinct_ports = set(r['dport'] for recs in dst_map.values() for r in recs)

            if len(distinct_ports) < self.thresholds.get('min_ports', 10): continue
            if pkt_rate < self.thresholds.get('min_rate', 5.0): continue

            # --- Scan Logic Starts Here ---
            syn_count = sum(1 for recs in dst_map.values() for r in recs if r['flags']['SYN'] and not r['flags']['ACK'])
            syn_ratio = (syn_count / total_pkts) if total_pkts > 0 else 0
            
            # SYN Scan
            if syn_ratio >= self.thresholds.get('min_syn_ratio', 0.6):
                self.trigger_alert(src, 'SYN Scan', 'High', list(distinct_ports))

            # (Inga matha scan types-ku logic add pannanum - FIN, XMAS, etc.)

        # 3. Analyze UDP patterns (with ICMP correlation)
        for src, dst_map in self.udp.items():
            distinct_udp_ports = set(r['dport'] for recs in dst_map.values() for r in recs)
            if len(distinct_udp_ports) < self.thresholds.get('min_ports', 10): continue

            # ICMP Unreachable count pannu
            icmp_unreach = sum(1 for ic_src in self.icmp for r in self.icmp[ic_src] if r['type'] == 3 and r['code'] == 3 and r['dst'] == src)

            if icmp_unreach >= self.thresholds.get('min_icmp_unreach', 3):
                self.trigger_alert(src, 'UDP Scan', 'High', list(distinct_udp_ports))
                
        # 4. Analyze ICMP Ping Sweep
        for src, recs in self.icmp.items():
            dsts = set(r['dst'] for r in recs if r['type'] == 8) # Echo request
            if len(dsts) >= self.thresholds.get('min_icmp_targets', 6):
                self.trigger_alert(src, 'Ping Sweep', 'Medium', list(dsts))


    # engine.py-la intha function-ah maathunga
    def trigger_alert(self, src_ip, scan_type, severity, ports):
        """Helper function to create and send alerts with severity-based blocking logic."""
        key = (src_ip, scan_type)
        if time.time() - self.report_times.get(key, 0) < 60:
            return

        self.report_times[key] = time.time()
        self.alert_count += 1
        self.detected_ips.add(src_ip)
        
        # --- PUTHU CHANGE INGA ---
        is_blocked_now = False
        if severity.lower() in ['high', 'critical']: # High-na auto-block
            if self.firewall:
                self.firewall.block_ip(src_ip)
                is_blocked_now = True
        # --- CHANGE MUDINJATHU ---

        alert_data = {
            'ip_address': src_ip,
            'scan_type': scan_type,
            'severity': severity,
            'is_blocked': is_blocked_now # Status ah UI ku anupurom
        }
        
        print(f"ALERT TRIGGERED: {scan_type} detected from {src_ip}. Severity: {severity}. Blocked: {is_blocked_now}")
        
        self.socketio.emit('new_alert', alert_data)
        self.db.add_detection(src_ip, scan_type, severity)