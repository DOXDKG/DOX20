from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import requests, os, re, secrets, hashlib, json, sqlite3
from datetime import datetime, timedelta
from typing import Optional, List
import threading
import time

load_dotenv()

# Secure configuration
API_TOKEN = "7597217793:s1Kq29Mq"
API_URL = os.getenv("API_URL", "https://leakosintapi.com/")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
LANG = "en"

# Database configuration for persistent storage
DATABASE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phone_lookup.db")

# If no password hash is set, create one for default password
if not ADMIN_PASSWORD_HASH:
    ADMIN_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()

app = Flask(__name__)
CORS(app)

# Database initialization
def init_database():
    """Initialize SQLite database for persistent storage"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Create access_keys table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_keys (
            key_hash TEXT PRIMARY KEY,
            key_id TEXT NOT NULL,
            key_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            usage_limit INTEGER,
            used_count INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Create admin_sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_sessions (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Create api_config table for storing API configuration
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_config (
            config_key TEXT PRIMARY KEY,
            config_value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    ''')
    
    # Insert default API token if not exists
    cursor.execute('''
        INSERT OR IGNORE INTO api_config (config_key, config_value, updated_at)
        VALUES (?, ?, ?)
    ''', ('api_token', API_TOKEN, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    print("Database initialized successfully")

# Initialize database on startup
init_database()

# Global counter for key IDs
def get_next_key_id():
    """Get the next available key ID"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT MAX(CAST(key_id AS INTEGER)) FROM access_keys')
    result = cursor.fetchone()
    conn.close()
    return str((result[0] or 0) + 1)

def hash_token(token: str) -> str:
    """Hash a token for secure storage"""
    return hashlib.sha256(token.encode()).hexdigest()

def cleanup_expired_data():
    """Clean up expired access keys and admin sessions"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    current_time = datetime.now().isoformat()
    
    # Clean expired access keys
    cursor.execute('DELETE FROM access_keys WHERE expires_at < ? OR is_active = 0', (current_time,))
    
    # Clean expired admin sessions
    cursor.execute('DELETE FROM admin_sessions WHERE expires_at < ? OR is_active = 0', (current_time,))
    
    conn.commit()
    conn.close()

def verify_admin_session(token: str) -> bool:
    """Verify admin session token"""
    cleanup_expired_data()
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    token_hash = hash_token(token)
    current_time = datetime.now().isoformat()
    
    cursor.execute('''
        SELECT username FROM admin_sessions 
        WHERE token_hash = ? AND expires_at > ? AND is_active = 1
    ''', (token_hash, current_time))
    
    result = cursor.fetchone()
    conn.close()
    return result is not None

def verify_access_key(key: str) -> bool:
    """Verify access key and handle usage tracking"""
    cleanup_expired_data()
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    key_hash = hash_token(key)
    current_time = datetime.now().isoformat()
    
    # Get key data
    cursor.execute('''
        SELECT key_id, key_type, usage_limit, used_count 
        FROM access_keys 
        WHERE key_hash = ? AND expires_at > ? AND is_active = 1
    ''', (key_hash, current_time))
    
    result = cursor.fetchone()
    if not result:
        conn.close()
        return False
    
    key_id, key_type, usage_limit, used_count = result
    
    # Check usage limit for non-permanent keys
    if usage_limit is not None:
        if used_count >= usage_limit:
            # Deactivate the key
            cursor.execute('UPDATE access_keys SET is_active = 0 WHERE key_hash = ?', (key_hash,))
            conn.commit()
            conn.close()
            return False
        
        # Increment usage count
        cursor.execute('UPDATE access_keys SET used_count = used_count + 1 WHERE key_hash = ?', (key_hash,))
    
    conn.commit()
    conn.close()
    return True

def get_api_token():
    """Get current API token from database"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT config_value FROM api_config WHERE config_key = ?', ('api_token',))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else API_TOKEN

def update_api_token(new_token: str):
    """Update API token in database"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO api_config (config_key, config_value, updated_at)
        VALUES (?, ?, ?)
    ''', ('api_token', new_token, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# Background cleanup task
def background_cleanup():
    """Background task to clean up expired data periodically"""
    while True:
        time.sleep(3600)  # Run every hour
        try:
            cleanup_expired_data()
            print("Background cleanup completed")
        except Exception as e:
            print(f"Background cleanup error: {e}")

# Start background cleanup thread
cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
cleanup_thread.start()

@app.route("/admin/login", methods=["POST"])
def admin_login():
    """Admin login endpoint"""
    data = request.get_json()
    password_hash = hashlib.sha256(data["password"].encode()).hexdigest()
    
    if data["username"] != ADMIN_USERNAME or password_hash != ADMIN_PASSWORD_HASH:
        return jsonify({"detail": "Invalid credentials"}), 401
    
    # Generate session token with extended expiration (30 days for sustainability)
    session_token = secrets.token_hex(32)
    token_hash = hash_token(session_token)
    expires_at = (datetime.now() + timedelta(days=30)).isoformat()
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO admin_sessions (token_hash, username, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    ''', (token_hash, data["username"], datetime.now().isoformat(), expires_at))
    conn.commit()
    conn.close()
    
    return jsonify({"token": session_token, "message": "Login successful"})

@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    """Admin logout endpoint"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    token = auth_header.split(" ")[1]
    token_hash = hash_token(token)
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE admin_sessions SET is_active = 0 WHERE token_hash = ?', (token_hash,))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Logged out successfully"})

@app.route("/admin/generate-key", methods=["POST"])
def generate_access_key():
    """Generate new access key"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    token = auth_header.split(" ")[1]
    if not verify_admin_session(token):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    data = request.get_json()
    
    # Generate new access key
    new_key = secrets.token_hex(16)
    key_hash = hash_token(new_key)
    key_id = get_next_key_id()
    
    # Set expiration - permanent keys get much longer expiration (10 years)
    expires_at = (datetime.now() + timedelta(days=3650 if data["key_type"] == "permanent" else 1)).isoformat()
    
    # For permanent keys, don't set usage_limit
    usage_limit = None if data["key_type"] == "permanent" else data.get("usage_limit")
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO access_keys (key_hash, key_id, key_type, created_at, expires_at, usage_limit, used_count)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (key_hash, key_id, data["key_type"], datetime.now().isoformat(), expires_at, usage_limit, 0))
    conn.commit()
    conn.close()
    
    return jsonify({
        "key": new_key,
        "type": data["key_type"],
        "expires": expires_at,
        "message": "Access key generated successfully"
    })

@app.route("/admin/keys", methods=["GET"])
def get_active_keys():
    """Get all active access keys"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    token = auth_header.split(" ")[1]
    if not verify_admin_session(token):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    cleanup_expired_data()
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    current_time = datetime.now().isoformat()
    
    cursor.execute('''
        SELECT key_id, key_type, created_at, expires_at, usage_limit, used_count
        FROM access_keys 
        WHERE expires_at > ? AND is_active = 1
        ORDER BY created_at DESC
    ''', (current_time,))
    
    results = cursor.fetchall()
    conn.close()
    
    active_keys = []
    for row in results:
        key_id, key_type, created_at, expires_at, usage_limit, used_count = row
        active_keys.append({
            "id": key_id,
            "key_preview": f"****{key_id}****",  # Show key ID instead of actual key
            "type": key_type,
            "created": created_at,
            "expires": expires_at,
            "usage_limit": usage_limit,
            "used_count": used_count
        })
    
    return jsonify({"keys": active_keys})

@app.route("/admin/change-password", methods=["POST"])
def change_password():
    """Change admin password"""
    global ADMIN_PASSWORD_HASH
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    token = auth_header.split(" ")[1]
    if not verify_admin_session(token):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    data = request.get_json()
    # Update the password hash
    ADMIN_PASSWORD_HASH = hashlib.sha256(data["new_password"].encode()).hexdigest()
    
    return jsonify({"message": "Password changed successfully"})

@app.route("/admin/change-api-key", methods=["POST"])
def change_api_key():
    """Change API key"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    token = auth_header.split(" ")[1]
    if not verify_admin_session(token):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    data = request.get_json()
    new_api_key = data.get("new_api_key", "").strip()
    
    if not new_api_key:
        return jsonify({"detail": "API key cannot be empty"}), 400
    
    update_api_token(new_api_key)
    return jsonify({"message": "API key changed successfully"})

@app.route("/admin/get-api-key", methods=["GET"])
def get_api_key():
    """Get current API key (masked for security)"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    token = auth_header.split(" ")[1]
    if not verify_admin_session(token):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    current_api_token = get_api_token()
    
    # Mask the API key for security (show first 8 and last 4 characters)
    if len(current_api_token) > 12:
        masked_key = current_api_token[:8] + "..." + current_api_token[-4:]
    else:
        masked_key = current_api_token[:4] + "..." + current_api_token[-2:]
    
    return jsonify({"api_key": masked_key})

@app.route("/admin/keys/<key_id>", methods=["DELETE"])
def delete_access_key(key_id):
    """Delete an access key by ID"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    token = auth_header.split(" ")[1]
    if not verify_admin_session(token):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE access_keys SET is_active = 0 WHERE key_id = ?', (key_id,))
    
    if cursor.rowcount > 0:
        conn.commit()
        conn.close()
        return jsonify({"message": "Access key deleted successfully"})
    else:
        conn.close()
        return jsonify({"detail": "Access key not found"}), 404

@app.route("/admin/database-status", methods=["GET"])
def database_status():
    """Get database status and statistics"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    token = auth_header.split(" ")[1]
    if not verify_admin_session(token):
        return jsonify({"detail": "Invalid admin session"}), 401
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Get active keys count
    cursor.execute('SELECT COUNT(*) FROM access_keys WHERE is_active = 1')
    active_keys = cursor.fetchone()[0]
    
    # Get total keys count
    cursor.execute('SELECT COUNT(*) FROM access_keys')
    total_keys = cursor.fetchone()[0]
    
    # Get active sessions count
    cursor.execute('SELECT COUNT(*) FROM admin_sessions WHERE is_active = 1')
    active_sessions = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        "database_file": os.path.basename(DATABASE_FILE),
        "database_exists": os.path.exists(DATABASE_FILE),
        "active_keys": active_keys,
        "total_keys": total_keys,
        "active_sessions": active_sessions,
        "status": "healthy"
    })

@app.route("/lookup", methods=["POST"])
def lookup_phone():
    """Phone lookup endpoint with access key protection"""
    data = request.get_json()
    phone = data["phone"].strip()
    if not re.fullmatch(r"\+91\d{10}", phone):
        return jsonify({"error": "Invalid phone number format. Use +91XXXXXXXXXX"})

    if not data.get("access_key"):
        return jsonify({"detail": "Access key is required"}), 401
    if not verify_access_key(data["access_key"]):
        return jsonify({"detail": "Invalid or expired access key"}), 401

    # Get current API token from database
    current_api_token = get_api_token()
    
    payload = {
        "token": current_api_token,
        "request": phone,
        "lang": LANG
    }

    try:
        response = requests.post(API_URL, json=payload, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        result = response.json()
        entries = result.get("List", {}).get("HiTeckGroop.in", {}).get("Data", [])
        if not entries:
            return jsonify({"error": "No data found for this number."})
        return jsonify({"records": entries})
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out. Please retry again."})
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Could not connect to the API. Please check your internet connection or try again later."})
    except requests.exceptions.HTTPError as e:
        return jsonify({"error": f"API error: {e.response.status_code} - {e.response.text}"})
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred. Please try again."})

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": "connected" if os.path.exists(DATABASE_FILE) else "not_found"
    })

@app.route("/", methods=["GET"])
def backend_status():
    """Backend status page with logo"""
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Phone Lookup Backend</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                color: white;
            }
            .container {
                text-align: center;
                background: rgba(255, 255, 255, 0.1);
                padding: 40px;
                border-radius: 20px;
                backdrop-filter: blur(10px);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            }
            .logo {
                width: 120px;
                height: 120px;
                margin: 0 auto 20px;
                background: linear-gradient(45deg, #4CAF50, #45a049);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 48px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            }
            h1 {
                margin: 20px 0;
                font-size: 2.5em;
                text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
            }
            .status {
                background: rgba(76, 175, 80, 0.8);
                padding: 10px 20px;
                border-radius: 25px;
                display: inline-block;
                margin: 20px 0;
                font-weight: bold;
            }
            .info {
                margin: 20px 0;
                opacity: 0.9;
            }
            .timestamp {
                font-size: 0.9em;
                opacity: 0.7;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">🚀</div>
            <h1>Phone Lookup Backend</h1>
            <div class="status">✅ Backend is Running</div>
            <div class="info">
                <p>API endpoints are active and ready to serve requests</p>
                <p>Database: Connected</p>
            </div>
            <div class="timestamp">
                Server Time: ''' + datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC") + '''
            </div>
        </div>
    </body>
    </html>
    '''


