import dpkt
import socket
import pandas as pd

def pcap_to_features(pcap_file_path):
    """
    Oru .pcap file-la irundhu packet data-va eduthu, atha ML model-ku puriyura
    maathiri numerical features-ah (oru periya table-ah) maathum.
    """
    print(f"'{pcap_file_path}' file-la irundhu features-ah pirichi edukuren...")
    
    features_list = []

    try:
        with open(pcap_file_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            
            for timestamp, buf in pcap:
                try:
                    # Packet-ah parse panrom
                    eth = dpkt.ethernet.Ethernet(buf)
                    
                    # IP packet-ah mattum eduthukalam
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                        
                    ip = eth.data
                    
                    # --- Features-ah Extract Panrom ---
                    
                    # 1. Packet Length
                    packet_len = len(buf)
                    
                    # 2. Protocol Type (TCP=6, UDP=17, ICMP=1)
                    proto = ip.p# type: ignore
                    
                    # 3. Ports and TCP Flags
                    src_port = 0
                    dst_port = 0
                    tcp_fin = 0
                    tcp_syn = 0
                    tcp_rst = 0
                    tcp_psh = 0
                    tcp_ack = 0
                    tcp_urg = 0

                    if proto == 6 and isinstance(ip.data, dpkt.tcp.TCP): # TCP
                        tcp = ip.data
                        src_port = tcp.sport# type: ignore
                        dst_port = tcp.dport# type: ignore
                        tcp_fin = 1 if (tcp.flags & dpkt.tcp.TH_FIN) != 0 else 0# type: ignore
                        tcp_syn = 1 if (tcp.flags & dpkt.tcp.TH_SYN) != 0 else 0# type: ignore
                        tcp_rst = 1 if (tcp.flags & dpkt.tcp.TH_RST) != 0 else 0# type: ignore
                        tcp_psh = 1 if (tcp.flags & dpkt.tcp.TH_PUSH) != 0 else 0# type: ignore
                        tcp_ack = 1 if (tcp.flags & dpkt.tcp.TH_ACK) != 0 else 0# type: ignore
                        tcp_urg = 1 if (tcp.flags & dpkt.tcp.TH_URG) != 0 else 0# type: ignore
                        
                    elif proto == 17 and isinstance(ip.data, dpkt.udp.UDP): # UDP
                        udp = ip.data
                        src_port = udp.sport# type: ignore
                        dst_port = udp.dport# type: ignore

                    features = {
                        'packet_len': packet_len,
                        'proto': proto,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'tcp_fin': tcp_fin,
                        'tcp_syn': tcp_syn,
                        'tcp_rst': tcp_rst,
                        'tcp_psh': tcp_psh,
                        'tcp_ack': tcp_ack,
                        'tcp_urg': tcp_urg,
                    }
                    features_list.append(features)

                except Exception:
                    # Sila packets damage aagirundha, atha ignore pannidalam
                    continue
                    
    except FileNotFoundError:
        print(f"❌ ERROR: '{pcap_file_path}' file-ah kandupudika mudiyala.")
        return None
    except Exception as e:
        print(f"❌ An error occurred: {e}")
        return None

    print(f"✅ {len(features_list)} packets-ah process panni, features extract panniyachu.")
    # List-ah pandas DataFrame (table)-ah maathrom
    return pd.DataFrame(features_list)

if __name__ == '__main__':
    # Intha script-ah thaniya run panni test panna
    # NOTE: Inga unga 'data' folder-la PCAP file irukanum
    features_df = pcap_to_features('data/normal_traffic.pcap')
    
    if features_df is not None:
        print("\n--- Extracted Features (First 5 Rows) ---")
        print(features_df.head())
        print(f"\nTotal Features: {features_df.shape[1]}")