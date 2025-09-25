# sniffer.py
import pcapy
import time

class PacketSniffer:
    """
    Captures live network traffic and forwards packets for analysis in batches.
    The threading is now managed by the main app.
    """
    def __init__(self, interface, engine, socketio):
        self.interface = interface
        self.engine = engine
        self.socketio = socketio
        self._is_running = False
        self.packet_count = 0

    def _sniff_loop(self):
        """The sniffing loop that collects packets and emits them in batches."""
        self._is_running = True
        self.packet_count = 0
        print("Sniffer background task started.")

        try:
            cap = pcapy.open_live(self.interface, 65536, 1, 100)
            print(f"Sniffer started successfully on interface {self.interface}...")
            
            packet_batch = []
            last_emit_time = time.time()

            while self._is_running:
                (header, packet_data) = cap.next()
                # Use a very small sleep to yield control, preventing 100% CPU usage
                self.socketio.sleep(0.001) 

                if not packet_data:
                    continue
                
                self.packet_count += 1
                processed_packet = self.engine.process_packet(packet_data, self.packet_count)

                if processed_packet:
                    packet_batch.append(processed_packet)

                # Batch updates help reduce frontend lag
                current_time = time.time()
                if current_time - last_emit_time > 1.0 and packet_batch:
                    self.socketio.emit('packet_update_batch', packet_batch)
                    packet_batch = []
                    last_emit_time = current_time

        except pcapy.PcapError as e:
            print(f"CRITICAL SNIFFER ERROR: {e}. Are you running with sudo?")
        except Exception as e:
            print(f"An unexpected error occurred in the sniff loop: {e}")
        
        self._is_running = False
        print("Sniffer background task stopped.")
        self.socketio.emit('monitor_status_update', {'is_running': False})

    def stop(self):
        """Signals the sniffing loop to stop."""
        print("Stop signal received by sniffer.")
        self._is_running = False

    def is_running(self):
        return self._is_running

    # NEW: Getter function to safely access packet count from other modules
    # (Packet count edukka intha function use aagum)
    def get_packet_count(self):
        return self.packet_count
