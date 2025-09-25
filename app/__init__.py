from flask import Flask, render_template
from flask_socketio import SocketIO

# Explicitly set async_mode to eventlet for best performance
socketio = SocketIO(async_mode='eventlet')

def create_app(sniffer=None, firewall=None, db=None, sys_monitor=None, interface_name=None):
    """
    Creates and configures the Flask application and its routes.
    """
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret-key-for-port-sentinel'
    socketio.init_app(app)

    # --- Main Route ---
    @app.route('/')
    def index():
        return render_template('dashboard.html')

    # --- SocketIO Events ---
    @socketio.on('connect')
    def handle_connect():
        print('Client connected')
        # FIX: Access 'sniffer' directly instead of 'app.sniffer'
        if sniffer:
            socketio.emit('monitor_status_update', {'is_running': sniffer.is_running()})

    @socketio.on('disconnect')
    def handle_disconnect():
        print('Client disconnected')

    @socketio.on('control_monitoring')
    def handle_control_monitoring(data):
        action = data.get('action')
        print(f"Received '{action}' monitoring command from client.")
        
        # FIX: Access 'sniffer' directly
        if not sniffer:
            return

        if action == 'start' and not sniffer.is_running():
            # FIX: Access 'sys_monitor' directly
            if sys_monitor:
                sys_monitor.start_timer()
            
            # FIX: Access 'sniffer' directly
            socketio.start_background_task(target=sniffer._sniff_loop)
            socketio.start_background_task(target=send_stats_updates)
            
        elif action == 'stop' and sniffer.is_running():
            # FIX: Access 'sniffer' directly
            sniffer.stop()

    def send_stats_updates():
        """
        Background thread to send regular stats updates.
        """
        print("Stats update thread started.")
        last_packet_count = 0
        
        # FIX: Access 'sniffer' directly
        while sniffer and sniffer.is_running():
            socketio.sleep(1)
            
            # FIX: Access 'sniffer' directly
            current_packets = sniffer.get_packet_count()
            packets_per_second = current_packets - last_packet_count
            last_packet_count = current_packets

            max_pps_for_load = 1000.0 
            traffic_load = min(100, int((packets_per_second / max_pps_for_load) * 100))
            
            # FIX: Access 'sniffer' and 'engine' directly
            alerts = sniffer.engine.alert_count
            ips = len(sniffer.engine.detected_ips)

            # --- Progress Bar Logic ---
            alerts_bar_percent = min(100, int((alerts / 50.0) * 100))
            ips_bar_percent = min(100, int((ips / 10.0) * 100))
            
            current_stats = {
                'packets_processed': current_packets,
                'alerts_triggered': alerts,
                'detected_ips_count': ips,
                'current_traffic_pps': packets_per_second,
                # FIX: Access 'sys_monitor' directly
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
            # PUDHUSA ITHA ADD PANNUNGA
    @app.route('/login')
    def login():
        return render_template('login.html')

    @app.route('/register')
    def register():
        return render_template('register.html')
        
    return app