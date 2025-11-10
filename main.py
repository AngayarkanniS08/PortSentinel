import threading
import time
from app import create_app, socketio
from core.sniffer import PacketSniffer
from core.engine import DetectionEngine
from app.database import DatabaseHandler
from core.firewall import FirewallManager
from core.utils import SystemMonitor, find_active_interface
from config import Config # <-- PUDHUSA IMPORT PANROM

def main():
    """
    Initializes all components and starts the application.
    """
    print("🚀 Initializing Port Sentinel components...")

    # PALA PASAM 'sentinel.db' NU IRUNDHUCHU
    # PUTHUSA 'Config.DATABASE_URI' VAZIYA CORRECT PATH-AH EDKKROM
    db_handler = DatabaseHandler(Config.DATABASE_URI)
    
    firewall_manager = FirewallManager()
    system_monitor = SystemMonitor()
    
    # --- UPGRADED AND ADVANCED THRESHOLDS ---
    # Inga namma scan logic ku thevayana ella numbers-ayum define panrom.
    # False positive-ah thavirkka, intha values romba mukkiyam.
    scan_thresholds = {
        # General Settings
        "max_time_window": 30,       # 30 seconds-kulla nadakura activity-ah analyze pannum
        "min_ports": 8,              # Minimum 8 ports-ku request varanum
        "min_rate": 5.0,             # Oru second-ku 5 packets-ku mela varanum
        "whitelist": {"127.0.0.1"},  # Intha IP-la irundhu varra scan-ah ignore pannidum

        # TCP Scan Specific
        "min_syn_ratio": 0.60,       # 60%-ku mela SYN packets irundha SYN scan
        
        # UDP Scan Specific
        "min_icmp_unreach": 3,       # Minimum 3 "Port Unreachable" message...ing Sweep Specific
        "min_icmp_targets": 6,       # 6 different IP-ku mela ping panna, adhu Ping Sweep
    }

    # Puthu advanced engine-ah intha thresholds vechi start panrom
    detection_engine = DetectionEngine(db_handler, firewall_manager, socketio, thresholds=scan_thresholds)
    
    interface = find_active_interface()
    if not interface:
        print("\n❌ CRITICAL: No active network interface found. Exiting.")
        return

    packet_sniffer = PacketSniffer(interface, detection_engine, socketio)


    app = create_app(
        sniffer=packet_sniffer,
        firewall=firewall_manager,
        db=db_handler,
        sys_monitor=system_monitor,
        interface_name=interface
    )
    
    print(f"\n✅ Port Sentinel web server is starting on http://127.0.0.1:5000")
    print("🔒 NOTE: Run this script with 'sudo' for full packet sniffing and firewall capabilities.")
    
    try:
        # allow_unsafe_werkzeug=True is needed for newer Flask versions when running this way
        socketio.run(app, 
                    host='0.0.0.0', 
                    port=5000, 
                    debug=False, # Debug mode off panniralam for stability
                    use_reloader=False, 
                    allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down Port Sentinel...")
        if packet_sniffer.is_running():
            packet_sniffer.stop()
    finally:
        print("Cleanup complete. Goodbye!")

if __name__ == '__main__':
    main()