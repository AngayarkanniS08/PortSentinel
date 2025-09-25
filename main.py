import threading
from app import create_app, socketio
from core.sniffer import PacketSniffer
from core.engine import DetectionEngine
from app.database import DatabaseHandler
from core.firewall import FirewallManager
from core.utils import SystemMonitor, find_active_interface
from config import Config

def main():
    """
    Initializes all components and starts the application.
    """
    print("Initializing Port Sentinel components...")

    db_handler = DatabaseHandler(Config.DATABASE_URI)
    firewall_manager = FirewallManager()
    system_monitor = SystemMonitor()
    
    # --- PUTHU CHANGE INGA THAAN ---
    # Inga namma scan logic ku thevayana numbers ah define panrom
    # Nee vena intha numbers ah unaku etha maari maathikalam
    scan_thresholds = {
        "min_packets": 15,       # Minimum 15 packets vandha thaan scan nu eduthukom
        "min_ports": 10,         # Minimum 10 vera vera ports ku request varanum
        "max_time_window": 10,   # Idhellam 10 seconds kulla nadakanum
        "tracker_timeout": 120   # 2 nimisham oru IP la irundhu activity illana, antha IP ah list la irundhu thookiduvom
    }

    # Antha numbers ah DetectionEngine kulla anupurom
    detection_engine = DetectionEngine(db_handler, firewall_manager, socketio, thresholds=scan_thresholds)
    
    interface = find_active_interface()
    if not interface:
        print("\nCRITICAL: No active network interface found.")
        return

    packet_sniffer = PacketSniffer(interface, detection_engine, socketio)

    app = create_app(
        sniffer=packet_sniffer,
        firewall=firewall_manager,
        db=db_handler,
        sys_monitor=system_monitor,
        interface_name=interface
    )
    
    print(f"Starting Port Sentinel web server on http://127.0.0.1:5000")
    print("NOTE: Run this script with 'sudo' for packet sniffing capabilities.")
    
    try:
        socketio.run(app, 
                    host='0.0.0.0', 
                    port=5000, 
                    debug=True, 
                    use_reloader=False, 
                    allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\nShutting down Port Sentinel...")
        if packet_sniffer.is_running():
            packet_sniffer.stop()

if __name__ == '__main__':
    main()
