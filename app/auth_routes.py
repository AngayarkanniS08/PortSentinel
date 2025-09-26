from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required
import bcrypt
from .database import User # User model-ah import panrom

# Intha function thaan namma authentication routes-ah create pannum
# __init__.py file-la irunthu 'app' and 'db' object-ah inga vaangurom
def init_auth_routes(app, db):

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            
            if not email or not password:
                flash('Email and password')
                return redirect(url_for('login'))

            user = db.find_user_by_email(email)

            if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
                login_user(user)
                return redirect(url_for('index')) # 'index' function-ku (dashboard) anuppum
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
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())  # type: ignore
            
            if db.find_user_by_email(email):
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