import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'soc-dashboard-super-secure-key-987654321'
    
    # Check if running on Vercel serverless environment
    if os.environ.get('VERCEL') or os.environ.get('VERCEL_ENV'):
        SQLALCHEMY_DATABASE_URI = 'sqlite:////tmp/soc_dashboard.db'
        UPLOAD_FOLDER = '/tmp/uploads'
        REPORT_FOLDER = '/tmp/reports'
    else:
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f"sqlite:///{os.path.join(BASE_DIR, 'soc_dashboard.db')}"
        UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
        REPORT_FOLDER = os.path.join(BASE_DIR, 'reports')
    ALLOWED_EXTENSIONS = {'txt', 'log', 'csv'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size

    # AI Configuration
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
    OPENAI_MODEL = os.environ.get('OPENAI_MODEL', 'gpt-4o-mini')
    OLLAMA_HOST = os.environ.get('OLLAMA_HOST', 'http://localhost:11434')
    USE_OLLAMA = os.environ.get('USE_OLLAMA', 'false').lower() == 'true'

    # HTTPS / SSL Configuration
    USE_HTTPS = os.environ.get('USE_HTTPS', 'false').lower() == 'true'
    SSL_CERT = os.environ.get('SSL_CERT', os.path.join(BASE_DIR, 'certs', 'cert.pem'))
    SSL_KEY = os.environ.get('SSL_KEY', os.path.join(BASE_DIR, 'certs', 'key.pem'))

    # Security & Session Settings
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_NAME = 'soc_dashboard_session'
    PERMANENT_SESSION_LIFETIME = 2592000  # 30 days in seconds
    REMEMBER_COOKIE_DURATION = 2592000
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
