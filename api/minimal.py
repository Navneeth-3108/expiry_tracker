# Minimal working version to identify the issue
import os
from flask import Flask

# Basic Flask app
app = Flask(__name__)
app.secret_key = "test-secret-key"

@app.route('/')
def home():
    return "Basic Flask app working!"

@app.route('/health')
def health():
    return {"status": "ok", "step": "1-basic-flask"}

@app.route('/test-imports')
def test_imports():
    try:
        import bcrypt
        import pymongo
        import twilio
        from flask_mail import Mail
        import schedule
        import pytz
        from dotenv import load_dotenv
        return {"status": "ok", "step": "2-all-imports-work"}
    except Exception as e:
        return {"status": "error", "step": "2-import-failed", "error": str(e)}

@app.route('/test-env')
def test_env():
    try:
        from dotenv import load_dotenv
        load_dotenv()
        return {
            "status": "ok", 
            "step": "3-env-loaded",
            "has_mongo": bool(os.getenv('MONGO_URI')),
            "has_mail": bool(os.getenv('MAIL_USERNAME'))
        }
    except Exception as e:
        return {"status": "error", "step": "3-env-failed", "error": str(e)}

if __name__ == '__main__':
    app.run(debug=True)