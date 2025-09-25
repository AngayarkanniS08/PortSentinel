from flask import Flask, render_template, request, redirect, url_for, flash
from flask_socketio import SocketIO
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import bcrypt

# --- Project-oda மத்த files-ah import panrom ---
from .database import User

socketio = SocketIO(async_mode='eventlet')
login_manager = LoginManager()

def create_app(sniffer=None, firewall=None, db=None, sys_monitor=None, interface_name=None):
    """
    Creates and configures the Flask application and its routes.
    """
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret-key-for-port-sentinel'
    
    login_manager.init_app(app)
    login_manager.login_view = 'login' # type: ignore
    socketio.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.find_user_by_id(int(user_id))  # type: ignore

    # --- Routes ---

    # --- FIX: Inga Decorator Order-ah Sari Panniyachu ---
    @app.route('/')
    @login_required 
    def index():
        return render_template('dashboard.html', username=current_user.username)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            
            if not email or not password:
                flash('Email and password renduமே aavasiyam.')
                return redirect(url_for('login'))

            user = db.find_user_by_email(email)  # type: ignore

            if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash('Email or password thappu. Sariya pottu paarunga.')
                return redirect(url_for('login'))

        return render_template('login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            first_name = request.form.get('firstName')
            last_name = request.form.get('lastName')
            email = request.form.get('email')
            password = request.form.get('password')

            if not all([first_name, last_name, email, password]):
                flash('Ella fields-um fill pannanum.')
                return redirect(url_for('register'))

            username = f"{first_name} {last_name}"
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) # type: ignore
            
            if db.find_user_by_email(email): # type: ignore
                flash('Intha email already register aayirukku. Vera email use pannunga.')
                return redirect(url_for('register'))

            db.add_user(username, email, hashed_password)  # type: ignore
            flash('Account create aayiduchu! Ippo login pannunga.')
            return redirect(url_for('login'))

        return render_template('register.html')

    # --- FIX: Inga Decorator Order-ah Sari Panniyachu ---
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))
        
    # --- SocketIO Events (Ithula entha maathamum illa) ---
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