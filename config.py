# In PORT_SENTINEL/config.py

import os

# Get the absolute path of the project's root directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = 'your-secret-key'
    # Create the full path for the database file
    db_path = os.path.join(BASE_DIR, 'instance', 'sentinel.db')
    # Create the full SQLAlchemy database URI with the correct prefix
    DATABASE_URI = f'sqlite:///{db_path}'