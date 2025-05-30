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
# Client User Routes
@app.route('/client/signup', methods=['POST'])
def client_signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    
    if client_users.find_one({"email": email}):
        return jsonify({"error": "Email already registered"}), 400
    
    hashed_pw = generate_password_hash(password)
    user_id = client_users.insert_one({
        "email": email,
        "password_hash": hashed_pw,
        "verified": False,
        "created_at": datetime.utcnow()
    }).inserted_id
    
    # Generate verification token
    verify_token = serializer.dumps(str(user_id), salt='email-verify')
    verify_url = f"{request.host_url}verify-email/{verify_token}"
    
    # Send verification email
    send_email(
        email,
        "Verify Your Email",
        f"Click to verify: <a href='{verify_url}'>{verify_url}</a>"
    )
    
    return jsonify({"message": "Verification email sent"}), 201

@app.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    try:
        user_id = serializer.loads(token, salt='email-verify', max_age=3600)  # 1 hour expiry
        client_users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"verified": True}}
        )
        return jsonify({"message": "Email verified successfully"}), 200
    except (SignatureExpired, BadSignature):
        return jsonify({"error": "Invalid or expired token"}), 400

@app.route('/client/login', methods=['POST'])
def client_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    
    user = client_users.find_one({"email": email})
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    if not user.get('verified', False):
        return jsonify({"error": "Email not verified"}), 403
    
    token = generate_session_token()
    client_sessions[token] = str(user['_id'])
    
    return jsonify({"token": token}), 200

# File Operations
@app.route('/ops/upload', methods=['POST'])
@ops_login_required
def upload_file(ops_user_id):
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    file_id = uploaded_files.insert_one({
        "filename": filename,
        "path": filepath,
        "uploaded_by": ops_user_id,
        "uploaded_at": datetime.utcnow(),
        "content_type": file.content_type
    }).inserted_id
    
    return jsonify({
        "message": "File uploaded successfully",
        "file_id": str(file_id)
    }), 201

@app.route('/client/files', methods=['GET'])
@client_login_required
def list_files(client_user_id):
    files = list(uploaded_files.find({}, {"filename": 1, "uploaded_at": 1}))
    for file in files:
        file['_id'] = str(file['_id'])
    return jsonify(files), 200

@app.route('/client/download/<file_id>', methods=['GET'])
@client_login_required
def request_download(client_user_id, file_id):
    if not uploaded_files.find_one({"_id": ObjectId(file_id)}):
        return jsonify({"error": "File not found"}), 404
    
    download_token = generate_download_token(file_id, client_user_id)
    return jsonify({
        "download_token": download_token,
        "expires_in": "30 minutes"
    }), 200

@app.route('/download-file/<token>', methods=['GET'])
def download_file(token):
    try:
        data = serializer.loads(token, salt='secure-download', max_age=1800)  # 30 min expiry
        file_id = data['file_id']
        user_id = data['user_id']
        
        file_data = uploaded_files.find_one({"_id": ObjectId(file_id)})
        if not file_data:
            return jsonify({"error": "File not found"}), 404
            
        return send_file(file_data['path'], as_attachment=True)
    except (SignatureExpired, BadSignature):
        return jsonify({"error": "Invalid or expired token"}), 400
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
