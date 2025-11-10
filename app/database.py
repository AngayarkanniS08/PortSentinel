
import datetime
import os # <-- PUDHUSA IMPORT PANROM
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin 

Base = declarative_base()

class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(120), nullable=True) # Google user kaga nullable=True
    google_id = Column(String(100), unique=True, nullable=True)
    picture = Column(String(200), nullable=True)
    auth_provider = Column(String(20), default='local')

    def __repr__(self):
        return f'<User {self.username}>'

class Detection(Base):
    __tablename__ = 'detections'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String)
    scan_type = Column(String)
    severity = Column(String)

class DatabaseHandler:
    """
    Manages all database operations for the application.
    """
    def __init__(self, db_file):
        
        # --- PUDHU FIX INGA START AAGUTHU ---
        # Namma 'init_db.py' la panra maariye, ingayum directory ah check panrom
        
        if db_file.startswith('sqlite:///'):
            db_uri = db_file
            db_path = db_uri.replace('sqlite:///', '')
        else:
            db_uri = f'sqlite:///{db_file}'
            db_path = db_file
        
        # Database file oda directory ah create panrom (illana)
        # Idhu thaan antha 'sudo' path problem ah solve pannum
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            print(f"DatabaseHandler: Creating directory: {db_dir}")
            os.makedirs(db_dir)
        # --- FIX MUDINJIRUCHU ---

        self.engine = create_engine(db_uri)
        Base.metadata.create_all(self.engine) # Ippo idhu fail aagadhu
        self.Session = sessionmaker(bind=self.engine)

    def add_detection(self, ip, scan_type, severity):
        session = self.Session()
        new_detection = Detection(
            ip_address=ip,
            scan_type=scan_type,
            severity=severity
        )
        session.add(new_detection)
        session.commit()
        session.close()
        print(f"New detection logged for IP: {ip}")

    # --- USER MANAGEMENT FUNCTIONS ---

    def add_user(self, username, email, hashed_password):
        """Pudhu user-ah database-la add pannum."""
        session = self.Session()
        new_user = User(username=username, email=email, password_hash=hashed_password, auth_provider='local')
        session.add(new_user)
        session.commit()
        session.close()
        print(f"New user '{username}' created.")

    def find_user_by_email(self, email):
        """Email vachi user-ah thedum."""
        session = self.Session()
        user = session.query(User).filter_by(email=email).first()
        session.close()
        return user

    def find_user_by_id(self, user_id):
        """User ID vachi user-ah thedum (Login manager use pannum)."""
        session = self.Session()
        user = session.query(User).get(user_id)
        session.close()
        return user
    
    def find_user_by_google_id(self, google_id):
        """Find user by Google ID"""
        session = self.Session()
        user = session.query(User).filter_by(google_id=google_id).first()
        session.close()
        return user
    
    def add_google_user(self, google_id, email, username, picture=None):
        """Add new user who signed up via Google"""
        print(f"🔍 [DEBUG] Creating Google user: {email}")
        session = self.Session()
        new_user = User(
            google_id=google_id,
            email=email,
            username=username,
            picture=picture,
            auth_provider='google',
            password_hash=None
        )
        session.add(new_user)
        session.commit()
        
        # Commit pannathukku appuram user ah return pannurom
        created_user = session.query(User).filter_by(google_id=google_id).first()
        session.close()
        return created_user