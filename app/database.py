import sqlite3
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

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

    # Add more methods for querying, deleting, etc.
