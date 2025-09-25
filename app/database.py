import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin # PUDHUSA IMPORT PANROM

# 'declarative_base' thaan namma table models create panna uthavum
Base = declarative_base()

# PUDHUSA USER TABLE MODEL-AH ADD PANROM
# UserMixin, Flask-Login kooda sernthu user session-ah manage pannum
class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(120), nullable=False) # Password-ah eppovume hash panni thaan save pannanum

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
        self.engine = create_engine(f'sqlite:///{db_file}')
        # Intha line users table and detections table, rendu table-aiyum create pannidum
        Base.metadata.create_all(self.engine)
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

    # --- USER MANAGEMENT FUNCTIONS (PUDHUSA ADD PANROM) ---

    def add_user(self, username, email, hashed_password):
        """Pudhu user-ah database-la add pannum."""
        session = self.Session()
        new_user = User(username=username, email=email, password_hash=hashed_password)
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
        # .get() function primary key vachi thedradhuku use aagum, romba fast
        user = session.query(User).get(user_id)
        session.close()
        return user