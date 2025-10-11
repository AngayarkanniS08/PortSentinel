from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user  # Added current_user
import bcrypt
from .database import User # User model-ah import panrom
from .oauth_handler import GoogleOAuthHandler  # Relative import

# Intha function thaan namma authentication routes-ah create pannum
# __init__.py file-la irunthu 'app' and 'db' object-ah inga vaangurom
def init_auth_routes(app, db):

    oauth_handler = GoogleOAuthHandler(app)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        # Already logged in user-ah check panrom
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            
            if not email or not password:
                flash('Email and password required')
                return redirect(url_for('login'))

            user = db.find_user_by_email(email)

            # PUDHUSAA ADD PANROM: Google user-ah check panrom
            if user and user.auth_provider == 'google':
                flash('Intha email Google login use pannirukku. Google login use pannunga.')
                return redirect(url_for('login'))
                
            # Regular password check
            if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
                login_user(user)
                return redirect(url_for('index')) # 'index' function-ku (dashboard) anuppum
            else:
                flash('Email or password thappu. Sariya pottu paarunga.')
                return redirect(url_for('login'))

        return render_template('login.html')

    # PUDHUSAA ADD PANROM: Google login routes
    @app.route('/login/google')
    def login_google():
        """Google OAuth flow-ah start panrom"""
        return oauth_handler.start_google_login()

    @app.route('/login/google/callback')
    def google_callback():
        """Handle Google OAuth callback"""
        session = None  # Track the database session
        try:
            print("🔍 Google callback started")
            
            user_info = oauth_handler.handle_google_callback()
            print(f"🔍 User info received: {user_info}")
            
            if not user_info:
                flash('Google login failed. Please try again.')
                return redirect(url_for('login'))
            
            print(f"🔍 Looking for user with Google ID: {user_info['google_id']}")
            
            # Get user AND session
            user= db.find_user_by_google_id(user_info['google_id'])
            print(f"🔍 User found: {user}")
            
            if not user:
                print(f"🔍 Creating new user for: {user_info['email']}")
                # Check if email exists
                existing_user = db.find_user_by_email(user_info['email'])
    
                if existing_user:
                    flash('This email is already registered with local login.')
                    
                    return redirect(url_for('login'))
                
                # Create new user - returns user AND session
                user = db.add_google_user(
                    google_id=user_info['google_id'],
                    email=user_info['email'],
                    username=user_info['username'],
                    picture=user_info['picture']
                )
                
                flash('Account created successfully with Google!')
            
            # Log the user in (user is still attached to session)
            login_user(user)
            print("✅ User logged in successfully")

                
            return redirect(url_for('index'))
            
        except Exception as e:
            print(f"🔥 GOOGLE CALLBACK CRASHED: {e}")
            import traceback
            traceback.print_exc()
            # Clean up session on error
            if session:
                session.close()
            flash('Internal server error during Google login')
            return redirect(url_for('login'))

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
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())  # type: ignore
            
            # PUDHUSAA ADD PANROM: Google user already exist aana check panrom
            existing_user = db.find_user_by_email(email)
            if existing_user:
                if existing_user.auth_provider == 'google':
                    flash('Intha email already Google login use pannirukku. Google login use pannunga.')
                else:
                    flash('Intha email already register aayirukku. Vera email use pannunga.')
                return redirect(url_for('register'))

            db.add_user(username, email, hashed_password)
            flash('Account create aayiduchu! Ippo login pannunga.')
            return redirect(url_for('login'))

        return render_template('register.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))