# Simple test version to isolate the issue
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello from Vercel!"

@app.route('/health')
def health():
    return {"status": "ok", "message": "Simple Flask app is working"}

if __name__ == '__main__':
    app.run(debug=True)