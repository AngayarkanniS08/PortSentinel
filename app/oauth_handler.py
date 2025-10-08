from authlib.integrations.flask_client import OAuth
from flask import redirect, url_for, session
import requests             
from .oauth_config import OAuthConfig
        
class GoogleOAuthHandler:
    def __init__(self, app=None):
        self.oauth = OAuth()        
        if app:
            self.setup_oauth(app)
    
    def setup_oauth(self, app):
        """Google OAuth-ah configure panrom"""
        self.oauth.init_app(app) 
        self.oauth.register(
            name='google',
            client_id=OAuthConfig.CLIENT_ID,
            client_secret=OAuthConfig.CLIENT_SECRET,
            server_metadata_url=OAuthConfig.DISCOVERY_URL,
            client_kwargs={
                'scope': 'openid email profile'
            }
        )
        
    
    def start_google_login(self):
        """Google OAuth-ku redirect panrom"""
        try:
            redirect_uri = OAuthConfig.REDIRECT_URI
            # FIX: Clear any existing session state

            return self.oauth.google.authorize_redirect(redirect_uri)
        except Exception as e:
            print(f"Google OAuth start error: {e}")
            return redirect(url_for('login'))
    
    def handle_google_callback(self):
        """Google callback-ah process panrom"""
        try:
            token = self.oauth.google.authorize_access_token()
                        


            user_info = token.get('userinfo')
            
            if user_info:
                return {
                    'google_id': user_info['sub'],
                    'email': user_info['email'],
                    'username': user_info['name'],
                    'picture': user_info.get('picture')
                }
        except Exception as e:
            print(f"Google OAuth callback error: {e}")
            return None
        
        return None