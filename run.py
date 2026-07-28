import os
from dotenv import load_dotenv

load_dotenv()

from app import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5500))
    use_https = os.environ.get('USE_HTTPS', 'false').lower() == 'true'
    
    ssl_context = None
    if use_https:
        cert_path = app.config.get('SSL_CERT', '')
        key_path = app.config.get('SSL_KEY', '')
        
        if cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path):
            ssl_context = (cert_path, key_path)
            print(f"🔒 HTTPS SSL/TLS enabled using cert: {cert_path}")
        else:
            ssl_context = 'adhoc'
            print("🔒 HTTPS SSL/TLS enabled using adhoc certificate")
        print(f"🚀 AI-SOC Dashboard running at https://127.0.0.1:{port}")
    else:
        print("🌐 Server running in standard HTTP mode")
        print(f"🚀 AI-SOC Dashboard running at http://127.0.0.1:{port}")

    app.run(host='0.0.0.0', port=port, debug=True, ssl_context=ssl_context)

