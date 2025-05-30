import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Any

from bson import ObjectId
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Flask, jsonify, request, send_file
from flask.wrappers import Response
from gridfs import GridFS
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pymongo import MongoClient
from pymongo.database import Database
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Initialize Flask
app = Flask(__name__)

# =========================================================
# CONFIGURATION
# =========================================================
class Config:
    # MongoDB Configuration (using your connection string)
    MONGO_URI = "mongodb+srv://fileuser:TW7G2ctoOYWxBn5t@cluster0.ewob3cm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    DB_NAME = "Cluster0"
    
    # Security
    SECRET_KEY = secrets.token_hex(32)  # 64-character hex
    
    # File Uploads
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}
    
    # Email (configure with your actual SMTP details)
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_USERNAME = "your_email@gmail.com"
    SMTP_PASSWORD = "your_app_password"
    EMAIL_FROM = "your_email@gmail.com"

# Create upload folder if it doesn't exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

# Apply configuration
app.config.from_object(Config)

# =========================================================
# DATABASE CONNECTION
# =========================================================
try:
    client = MongoClient(
        Config.MONGO_URI,
        connectTimeoutMS=5000,
        socketTimeoutMS=5000,
        serverSelectionTimeoutMS=5000
    )
    
    # Verify connection
    client.admin.command('ping')
    print("✅ Successfully connected to MongoDB Atlas!")
    
    db = client[Config.DB_NAME]
    fs = GridFS(db)
    
except Exception as e:
    print(f"❌ MongoDB Connection Error: {str(e)}")
    exit(1)

# Collections
ops_users = db.ops_users
client_users = db.client_users
uploaded_files = db.uploaded_files
tokens = db.tokens

# Security
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
ops_sessions = {}
client_sessions = {}

# =========================================================
# HELPER FUNCTIONS
# =========================================================
def allowed_file(filename: str) -> bool:
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def generate_session_token() -> str:
    return secrets.token_urlsafe(32)

def generate_download_token(file_id: str, user_id: str) -> str:
    return serializer.dumps({
        'file_id': file_id,
        'user_id': user_id,
        'exp': (datetime.utcnow() + timedelta(minutes=30)).timestamp()
    }, salt='secure-download')

def send_email(to: str, subject: str, body: str) -> bool:
    try:
        msg = MIMEMultipart()
        msg['From'] = Config.EMAIL_FROM
        msg['To'] = to
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            server.starttls()
            server.login(Config.SMTP_USERNAME, Config.SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"✉️ Email error: {str(e)}")
        return False

# =========================================================
# AUTH DECORATORS
# =========================================================
def ops_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or token not in ops_sessions:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, ops_user_id=ops_sessions[token], **kwargs)
    return decorated

def client_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or token not in client_sessions:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, client_user_id=client_sessions[token], **kwargs)
    return decorated

# =========================================================
# ROUTES
# =========================================================
@app.route('/')
def home():
    return jsonify({
        "message": "File Sharing API",
        "endpoints": {
            "ops_login": "POST /ops/login",
            "client_signup": "POST /client/signup",
            "client_login": "POST /client/login",
            "upload_file": "POST /ops/upload (ops token required)",
            "list_files": "GET /client/files (client token required)"
        }
    })

@app.route('/ops/login', methods=['POST'])
def ops_login() -> Response:
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    
    user = ops_users.find_one({"username": username})
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    token = generate_session_token()
    ops_sessions[token] = str(user['_id'])
    
    return jsonify({"token": token}), 200

# [Include all your other routes from the previous implementation]

if __name__ == '__main__':
    print(f"🔑 Using SECRET_KEY: {app.config['SECRET_KEY']}")
    print(f"📁 Upload folder: {Config.UPLOAD_FOLDER}")
    app.run(host='0.0.0.0', port=5000, debug=True)