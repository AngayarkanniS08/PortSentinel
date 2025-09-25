# In PORT_SENTINEL/config.py

import os

# Get the absolute path of the project's root directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = 'your-secret-key'
    # Create the full path for the database inside the 'instance' folder
    DATABASE_URI = os.path.join(BASE_DIR, 'instance', 'sentinel.db')