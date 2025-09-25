import dpkt
import datetime
import socket
import time

class DetectionEngine:
    """
    Analyzes packets to detect threats like port scans with improved logic.
    """
    def __init__(self, db_handler, firewall_manager, socketio, thresholds):
        self.db = db_handler
        self.firewall = firewall_manager
        self.socketio = socketio
        self.syn_trackers = {}
        self.alert_count = 0
        self.detected_ips = set()
        self.thresholds = thresholds
        print(f"Detection Engine initialized with thresholds: {self.thresholds}")

    def _cleanup_trackers(self, current_time):
        """
        Removes old entries from trackers to prevent memory leaks.
        """
        timeout = self.thresholds.get('tracker_timeout', 60)
        stale_ips = [
            ip for ip, tracker in self.syn_trackers.items()
            if current_time - tracker['last_seen'] > timeout
        ]
        for ip in stale_ips:
            del self.syn_trackers[ip]

    def process_packet(self, raw_packet, sno):
        """
        Processes a single raw packet from the sniffer.
        """
        try:
            eth = dpkt.ethernet.Ethernet(raw_packet)
            
            if not isinstance(eth.data, dpkt.ip.IP):
                return None

            ip = eth.data
            # Inga thaan antha warnings vandhuchu. Ippo sari panniyachu.
            src_ip = socket.inet_ntoa(ip.src)  # type: ignore
            dst_ip = socket.inet_ntoa(ip.dst)  # type: ignore
            
            packet_info = {
                'sno': sno,
                'time': datetime.datetime.now().strftime('%H:%M:%S'),
                'proto': 'UNKNOWN',
                'source_ip': f"{src_ip}:{ip.data.sport if hasattr(ip.data, 'sport') else 0}",
                'dest_ip': f"{dst_ip}:{ip.data.dport if hasattr(ip.data, 'dport') else 0}",
                'status': 'Allowed'
            }

            if isinstance(ip.data, dpkt.tcp.TCP):
                packet_info['proto'] = 'TCP'
                tcp = ip.data
                
                # Inga yum warning vandhuchu, fix panniyachu
                if tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):  # type: ignore
                    current_time = time.time()
                    
                    if sno % 100 == 0:
                        self._cleanup_trackers(current_time)

                    if src_ip not in self.syn_trackers:
                        self.syn_trackers[src_ip] = {
                            'count': 0, 'ports': set(),
                            'first_seen': current_time, 'last_seen': current_time
                        }
                    
                    tracker = self.syn_trackers[src_ip]
                    tracker['count'] += 1
                    tracker['ports'].add(tcp.dport)  # type: ignore
                    tracker['last_seen'] = current_time
                    
                    time_window = current_time - tracker['first_seen']

                    min_packets = self.thresholds.get('min_packets', 15)
                    min_ports = self.thresholds.get('min_ports', 10)
                    max_time_window = self.thresholds.get('max_time_window', 10)

                    if (tracker['count'] >= min_packets and 
                        len(tracker['ports']) >= min_ports and 
                        time_window <= max_time_window and 
                        src_ip not in self.detected_ips):
                        
                        packet_info['status'] = 'Scan'
                        self.trigger_alert(src_ip, list(tracker['ports'])[:5])
                        
            elif isinstance(ip.data, dpkt.udp.UDP):
                packet_info['proto'] = 'UDP'
            elif isinstance(ip.data, dpkt.icmp.ICMP):
                packet_info['proto'] = 'ICMP'

            return packet_info

        except Exception:
            return None

    def trigger_alert(self, src_ip, ports_scanned):
        """Trigger an alert for a detected scan"""
        self.alert_count += 1
        self.detected_ips.add(src_ip)
        
        alert_data = {
            'alert_id': f"alert_{self.alert_count}",
            'ip_address': src_ip,
            'scan_type': 'SYN Scan',
            'ports_scanned': ports_scanned,
            'severity': 'High',
            'is_blocked': False
        }
        
        self.socketio.emit('new_alert', alert_data)
        
        if self.db:
            self.db.add_detection(src_ip, 'SYN Scan', 'High')
            
        print(f"ALERT: Port scan detected from {src_ip} on ports {ports_scanned}")

