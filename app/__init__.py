from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_login import LoginManager, login_required, current_user

# --- PUDHU CHANGE: Namma auth_routes file-ah import panrom ---
from .auth_routes import init_auth_routes
from .database import User

socketio = SocketIO(async_mode='eventlet')
login_manager = LoginManager()

def create_app(sniffer=None, firewall=None, db=None, sys_monitor=None, interface_name=None):
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret-key-for-port-sentinel'
    
    login_manager.init_app(app)
    login_manager.login_view = 'login' # type: ignore
    socketio.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.find_user_by_id(int(user_id))  # type: ignore
        
    # --- PUDHU CHANGE: Authentication routes-ah inga register panrom ---
    # Ithu antha auth_routes.py file-la irukura ella routes-ayum activate pannidum
    init_auth_routes(app, db)

    # --- Routes (Dashboard mattum thaan inga irukkum) ---
    @app.route('/')
    @login_required 
    def index():
        return render_template('dashboard.html', username=current_user.username)

    @app.route('/traffic')
    @login_required
    def traffic_monitor():
        return render_template('traffic_monitor.html', username=current_user.username) 

    # --- Background Task Functions ---

    def analysis_loop(engine, sniffer_instance):
        """Periodically tells the DetectionEngine to analyze packets."""
        print("✅ Analysis loop thread started (managed by SocketIO).")
        while sniffer_instance and sniffer_instance.is_running():
            socketio.sleep(5)
            # Loop-kulla check panrathu innum better
            if sniffer_instance.is_running():
                print("▶️ Running periodic analysis of collected packets...")
                engine.analyze_and_alert()
        print("⏹️ Analysis loop thread stopped.")


    def send_stats_updates(sniffer, sys_monitor, interface_name):
        print("✅ Stats update thread started.")
        last_packet_count = 0
        
        while sniffer and sniffer.is_running():
            socketio.sleep(1)
            # Loop-kulla check panrathu innum better
            if not sniffer.is_running():
                break

            current_packets = sniffer.get_packet_count()
            packets_per_second = current_packets - last_packet_count
            last_packet_count = current_packets
            max_pps_for_load = 1000.0 
            traffic_load = min(100, int((packets_per_second / max_pps_for_load) * 100))
            alerts = sniffer.engine.alert_count if sniffer.engine else 0
            ips = len(sniffer.engine.detected_ips) if sniffer.engine else 0
            alerts_bar_percent = min(100, int((alerts / 50.0) * 100))
            ips_bar_percent = min(100, int((ips / 10.0) * 100))
            
            current_stats = {
                'packets_processed': current_packets,
                'alerts_triggered': alerts,
                'detected_ips_count': ips,
                'current_traffic_pps': packets_per_second,
                'uptime': sys_monitor.get_uptime() if sys_monitor else '0m 0s',
                'traffic_load_percent': traffic_load,
                'interface': interface_name if interface_name else 'N/A',
                'detection_accuracy': 98.7, # Placeholder value
                'packets_bar_percent': traffic_load,
                'alerts_bar_percent': alerts_bar_percent,
                'ips_bar_percent': ips_bar_percent,
                'traffic_bar_percent': traffic_load,
            }
            socketio.emit('stats_update', current_stats)

        print("⏹️ Stats update thread stopped.")

    # --- SocketIO Events ---

    @socketio.on('connect')
    def handle_connect():
        print('Client connected')
        if sniffer:
            # Monitor status anupurom
            socketio.emit('monitor_status_update', {'is_running': sniffer.is_running()})
            # PUDHU CHANGE: Threat Intel status-ayum anupurom
            if hasattr(sniffer.engine, 'threat_intel_enabled'):
                socketio.emit('threat_intel_status_update', {'is_enabled': sniffer.engine.threat_intel_enabled})

    @socketio.on('disconnect')
    def handle_disconnect():
        print('Client disconnected')

    @socketio.on('control_monitoring')
    def handle_control_monitoring(data):
        action = data.get('action')
        print(f"Received '{action}' monitoring command from client.")

        if not sniffer: return

        if action == 'start' and not sniffer.is_running():
            if sys_monitor: sys_monitor.start_timer()
            # Ella background tasks-ayum inga start panrom
            socketio.start_background_task(target=sniffer._sniff_loop)
            socketio.start_background_task(target=send_stats_updates, sniffer=sniffer, sys_monitor=sys_monitor, interface_name=interface_name)
            socketio.start_background_task(target=analysis_loop, engine=sniffer.engine, sniffer_instance=sniffer)
            # PUDHU CHANGE: Status-ah udane anupurom
            socketio.emit('monitor_status_update', {'is_running': True})

        elif action == 'stop' and sniffer.is_running():
            sniffer.stop()
            socketio.emit('monitor_status_update', {'is_running': False})

    @socketio.on('toggle_threat_intel')
    def handle_toggle_threat_intel(data):
        is_enabled = data.get('enabled', False)
        if sniffer and hasattr(sniffer.engine, 'threat_intel_enabled'):
            sniffer.engine.threat_intel_enabled = is_enabled
            status = "enabled" if is_enabled else "disabled"
            print(f"Threat Intelligence has been {status} by user.")

    @socketio.on('block_ip_request')
    def handle_block_ip(data):
        ip_to_block = data.get('ip')
        print(f"Received request to block IP: {ip_to_block}")
        
        if firewall and ip_to_block:
            success = firewall.block_ip(ip_to_block)
            # UI ku response anupurom
            socketio.emit('ip_action_status', {'success': success, 'ip': ip_to_block, 'action': 'block'})
            if success:
                print(f"Successfully blocked {ip_to_block} via user request.")
            else:
                print(f"Failed to block {ip_to_block} via user request.")

    @socketio.on('unblock_ip_request')
    def handle_unblock_ip(data):
        ip_to_unblock = data.get('ip')
        print(f"Received request to unblock IP: {ip_to_unblock}")
        
        if firewall and ip_to_unblock:
            success = firewall.unblock_ip(ip_to_unblock)
            # UI ku response anupurom
            socketio.emit('ip_action_status', {'success': success, 'ip': ip_to_unblock, 'action': 'unblock'})
            if success:
                print(f"Successfully unblocked {ip_to_unblock} via user request.")
            else:
                print(f"Failed to unblock {ip_to_unblock} via user request.")
        
    return app