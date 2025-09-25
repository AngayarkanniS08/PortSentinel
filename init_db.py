# Intha script-ah namma ore oru thadava run panna pothum.
# Ithu namma database and tables-ah create pannidum.

from sqlalchemy import create_engine
from app.database import Base, User, Detection
from config import Config
import os

print("Database setup script running...")

# Database file enga irukku-nu paakrom
db_path = Config.DATABASE_URI.replace('sqlite:///', '')
db_dir = os.path.dirname(db_path)

# 'instance' folder illana, atha create panrom
if not os.path.exists(db_dir):
    print(f"Creating directory: {db_dir}")
    os.makedirs(db_dir)

# Database engine-ah create panrom
engine = create_engine(Config.DATABASE_URI)

# 'users' and 'detections' table-ah create panrom
print("Creating database tables...")
Base.metadata.create_all(engine)

print("✅ Database and tables created successfully!")
print(f"Database file is at: {db_path}")