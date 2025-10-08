import os

# Google OAuth Configuration
GOOGLE_CLIENT_ID = "954161723751-4l2bp0k5htt8dko7plrhg7k89e7ivgsn.apps.googleusercontent.com"  # Your actual Client ID
GOOGLE_CLIENT_SECRET = "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"   # Your Client Secret

# OAuth Settings
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
REDIRECT_URI = "http://lvh.me:5000/login/google/callback"

# For development - in production, use environment variables
class OAuthConfig:
    CLIENT_ID = GOOGLE_CLIENT_ID
    CLIENT_SECRET = GOOGLE_CLIENT_SECRET
    REDIRECT_URI = REDIRECT_URI
    DISCOVERY_URL = GOOGLE_DISCOVERY_URL