from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import sqlite3
import os
import logging

from datetime import datetime, timedelta
import bcrypt
from dotenv import load_dotenv
from functools import wraps

# .env yükle
load_dotenv()

app = Flask(__name__)

# Static dosyalar (production)
if os.environ.get('FLASK_ENV') == 'production':
    try:
        from whitenoise import WhiteNoise
        app.wsgi_app = WhiteNoise(app.wsgi_app, root='static/')
        app.wsgi_app.add_files('static/', prefix='static/')
    except ImportError:
        pass

# Secret key (sadece .env’den)
app.secret_key = os.environ["SECRET_KEY"]

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Cache
cache = Cache(app, config={
    'CACHE_TYPE': 'simple',
    'CACHE_DEFAULT_TIMEOUT': 300
})

# Logging
app.logger.setLevel(logging.INFO)

# Debug kapalı
app.config['DEBUG'] = False

# Email config
app.config['MAIL_SERVER'] = os.environ['MAIL_SERVER']
app.config['MAIL_PORT'] = int(os.environ['MAIL_PORT'])
app.config['MAIL_USE_TLS'] = os.environ['MAIL_USE_TLS'].lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ['MAIL_USERNAME']
app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASSWORD']
app.config['MAIL_DEFAULT_SENDER'] = os.environ['MAIL_DEFAULT_SENDER']

EMAIL_ENABLED = os.environ['EMAIL_ENABLED'].lower() == 'true'
mail = Mail(app)

# DB path
DATABASE = os.environ['DATABASE_PATH']

# Session timeout
app.permanent_session_lifetime = timedelta(hours=2)

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# DB bağlantısı
def get_db_connection():
    conn = sqlite3.connect(DATABASE, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

# Şifre hash
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

# Şifre doğrulama
def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Veritabanı init
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Books tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author_name TEXT NOT NULL,
            order_quantity INTEGER NOT NULL,
            size TEXT NOT NULL,
            status TEXT DEFAULT 'Hazırlanıyor',
            track_code TEXT UNIQUE NOT NULL,
            customer_email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Users tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            is_active BOOLEAN DEFAULT 1,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Contact tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contact_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Admin user (env’den)
    admin_username = os.environ["ADMIN_USERNAME"]
    admin_password = os.environ["ADMIN_PASSWORD"]

    # Önce varsa sil
    cursor.execute("DELETE FROM users WHERE username = ?", (admin_username,))
    # Yeni ekle
    hashed = hash_password(admin_password)
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (admin_username, hashed))

    conn.commit()
    conn.close()
    app.logger.info(f"✅ Admin oluşturuldu: {admin_username}")

# İlk açılışta DB init
init_db()

# Login kontrol decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash("⚠️ Lütfen giriş yapın", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE username=?",(username,))
        user = cursor.fetchone()
        conn.close()

        if user and verify_password(password, user['password']):
            session.permanent = True
            session['admin_logged_in'] = True
            session['admin_username'] = username
            flash("✅ Başarıyla giriş yapıldı.","success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("❌ Kullanıcı adı veya şifre hatalı","error")

    return render_template('login.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("👋 Çıkış yapıldı","success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
