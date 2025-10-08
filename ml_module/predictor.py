import joblib
import pandas as pd
import dpkt
import os

class AnomalyPredictor:
    """
    Train panna ML model-ah load panni, varugira puthu packets anomaliy-ah
    illaya-nu theerpu sollum.
    """
    def __init__(self, model_path='models/sentinel_model.pkl'):
        self.model = None
        # Model file iruka-nu check pannurom
        if not os.path.exists(model_path):
            print(f"🚨 WARNING: Model file '{model_path}' kandupudika mudiyala.")
            print("   AI detection velai seiyathu. Please run 'trainer.py' first.")
        else:
            # Model-ah load panni ready-ah vechikrom
            self.model = joblib.load(model_path)
            print("✅ AI Anomaly Predictor is loaded and ready.")

    def _extract_features_from_packet(self, raw_packet):
        """
        Oru single raw packet-la irundhu features-ah eduthu, atha
        model-ku thevayana format-la (DataFrame) maathum.
        """
        try:
            eth = dpkt.ethernet.Ethernet(raw_packet)
            if not isinstance(eth.data, dpkt.ip.IP):
                return None
            
            ip = eth.data
            proto = ip.p# type: ignore
            
            # Default values
            src_port, dst_port = 0, 0
            tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, tcp_urg = 0, 0, 0, 0, 0, 0

            if proto == 6 and isinstance(ip.data, dpkt.tcp.TCP): # TCP
                tcp = ip.data
                src_port, dst_port = tcp.sport, tcp.dport# type: ignore
                tcp_fin = 1 if (tcp.flags & dpkt.tcp.TH_FIN) else 0# type: ignore
                tcp_syn = 1 if (tcp.flags & dpkt.tcp.TH_SYN) else 0# type: ignore
                tcp_rst = 1 if (tcp.flags & dpkt.tcp.TH_RST) else 0# type: ignore
                tcp_psh = 1 if (tcp.flags & dpkt.tcp.TH_PUSH) else 0# type: ignore
                tcp_ack = 1 if (tcp.flags & dpkt.tcp.TH_ACK) else 0# type: ignore
                tcp_urg = 1 if (tcp.flags & dpkt.tcp.TH_URG) else 0# type: ignore
            elif proto == 17 and isinstance(ip.data, dpkt.udp.UDP): # UDP
                udp = ip.data
                src_port, dst_port = udp.sport, udp.dport# type: ignore
            
            features = {
                'packet_len': [len(raw_packet)], 'proto': [proto],
                'src_port': [src_port], 'dst_port': [dst_port],
                'tcp_fin': [tcp_fin], 'tcp_syn': [tcp_syn], 'tcp_rst': [tcp_rst],
                'tcp_psh': [tcp_psh], 'tcp_ack': [tcp_ack], 'tcp_urg': [tcp_urg]
            }
            return pd.DataFrame(features)
        except Exception:
            return None

    def is_anomaly(self, raw_packet):
        """
        Packet anomaliy-ah illaya-nu theerpu sollum.
        Returns: True (anomaly) or False (normal).
        """
        if self.model is None:
            return False # Model illana, ethuvum anomaly illa

        features_df = self._extract_features_from_packet(raw_packet)
        
        if features_df is None:
            return False

        # Model-kitta theerpu kekurom
        # -1 na anomay (attack), 1 na normal
        prediction = self.model.predict(features_df)
        
        return prediction[0] == -1

# Namma app start aagum bothu, intha object-ah create panni use pannikalam
predictor = AnomalyPredictor()