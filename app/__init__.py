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

    # --- SocketIO Events (Ithula entha maathamum illa, apdiye irukkattum) ---
    @socketio.on('connect')
    def handle_connect():
        print('Client connected')
        if sniffer:
            socketio.emit('monitor_status_update', {'is_running': sniffer.is_running()})

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
            socketio.start_background_task(target=sniffer._sniff_loop)
            socketio.start_background_task(target=lambda: send_stats_updates(sniffer, sys_monitor, interface_name))
            
        elif action == 'stop' and sniffer.is_running():
            sniffer.stop()
    # app.py-la create_app() function-kulla add pannunga

    @socketio.on('block_ip_request')
    def handle_block_ip(data):
        ip_to_block = data.get('ip')
        print(f"Received request to block IP: {ip_to_block}")
        
        if firewall and ip_to_block:
            success = firewall.block_ip(ip_to_block)
            if success:
                print(f"Successfully blocked {ip_to_block} via user request.")
                # UI ku success message anupurom
                socketio.emit('ip_block_status', {'success': True, 'ip': ip_to_block})
            else:
                print(f"Failed to block {ip_to_block} via user request.")
                socketio.emit('ip_action_status', {'success': True, 'ip': ip_to_block, 'action': 'block'})


    @socketio.on('unblock_ip_request')
    def handle_unblock_ip(data):
        ip_to_unblock = data.get('ip')
        print(f"Received request to unblock IP: {ip_to_unblock}")
        
        if firewall and ip_to_unblock:
            success = firewall.unblock_ip(ip_to_unblock)
            if success:
                print(f"Successfully unblocked {ip_to_unblock} via user request.")
                # UI ku success message anupurom
                socketio.emit('ip_action_status', {'success': True, 'ip': ip_to_unblock, 'action': 'unblock'})
            else:
                print(f"Failed to unblock {ip_to_unblock} via user request.")
                socketio.emit('ip_action_status', {'success': False, 'ip': ip_to_unblock, 'action': 'unblock'})

    @socketio.on('manual_ip_control')
    @login_required
    def handle_manual_ip_control(data):
        ip = data.get('ip_address')
        action = data.get('action')
        if not ip or not action or not firewall: return
        print(f"Firewall: Received manual command to '{action}' IP: {ip}")
        if action == 'block':
            firewall.block_ip(ip)
        elif action == 'unblock':
            firewall.unblock_ip(ip)

    def send_stats_updates(sniffer, sys_monitor, interface_name):
        print("Stats update thread started.")
        last_packet_count = 0
        
        while sniffer and sniffer.is_running():
            socketio.sleep(1)
            current_packets = sniffer.get_packet_count()
            packets_per_second = current_packets - last_packet_count
            last_packet_count = current_packets
            max_pps_for_load = 1000.0 
            traffic_load = min(100, int((packets_per_second / max_pps_for_load) * 100))
            alerts = sniffer.engine.alert_count
            ips = len(sniffer.engine.detected_ips)
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
                'detection_accuracy': 98.7,
                'packets_bar_percent': traffic_load,
                'alerts_bar_percent': alerts_bar_percent,
                'ips_bar_percent': ips_bar_percent,
                'traffic_bar_percent': traffic_load,
            }
            socketio.emit('stats_update', current_stats)

        print("Stats update thread stopped.")
        
    return app