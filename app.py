# app.py
# -*- coding: utf-8 -*-
"""
Matbaa Takip - Tek dosyalık Flask uygulaması
- .env'den ayarları okur
- SQLite veritabanı kullanır
- Admin hesabını .env'den oluşturur/günceller
- Basit oturum açma/kapama ve örnek iş (job) CRUD içerir
- E-posta bildirimi (opsiyonel) için Flask-Mail kullanır
"""

import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, session,
    flash, abort, render_template_string, jsonify
)
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from dotenv import load_dotenv

# ---------------------------------------------------------------------
# .env yükle
# ---------------------------------------------------------------------
load_dotenv()

# Ortam değişkenleri
SECRET_KEY = os.getenv("SECRET_KEY", "change_this_dev_key")
DATABASE_PATH = os.getenv("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "matbaa_takip.db"))

EMAIL_ENABLED = str(os.getenv("EMAIL_ENABLED", "false")).strip().lower() == "true"
MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_USE_TLS = str(os.getenv("MAIL_USE_TLS", "true")).strip().lower() == "true"
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", MAIL_USERNAME or "no-reply@example.com")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
FLASK_ENV = os.getenv("FLASK_ENV", "production")

# ---------------------------------------------------------------------
# Flask uygulaması
# ---------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# Bcrypt
bcrypt = Bcrypt(app)

# Mail
app.config.update(
    MAIL_SERVER=MAIL_SERVER,
    MAIL_PORT=MAIL_PORT,
    MAIL_USE_TLS=MAIL_USE_TLS,
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=MAIL_PASSWORD,
    MAIL_DEFAULT_SENDER=MAIL_DEFAULT_SENDER,
)
mail = Mail(app)

# ---------------------------------------------------------------------
# DB yardımcıları
# ---------------------------------------------------------------------
def get_db():
    # UTF-8 ve unicode kullanıcı adları için text_factory
    conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.text_factory = lambda x: x.decode("utf-8", errors="ignore") if isinstance(x, (bytes, bytearray)) else x
    return conn

def init_db():
    """Tabloları oluştur ve admin hesabını .env'den set et."""
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = get_db()
    cur = conn.cursor()

    # users tablosu
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        email TEXT
    )
    """)

    # jobs tablosu (örnek iş kayıtları)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL
    )
    """)

    # Admin kullanıcıyı .env'e göre garanti altına al
    # 1) Aynı kullanıcı adı varsa sil (eski/plain kayıt kalmasın)
    cur.execute("DELETE FROM users WHERE username = ?", (ADMIN_USERNAME,))
    # 2) Hash oluştur ve ekle
    admin_hash = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode("utf-8")
    cur.execute(
        "INSERT INTO users (username, password_hash, is_admin, email) VALUES (?, ?, ?, ?)",
        (ADMIN_USERNAME, admin_hash, 1, None)
    )

    conn.commit()
    conn.close()

# Uygulama start-up'ta DB init
init_db()

# ---------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id") or not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapped

def send_email_notification(subject, recipients, body):
    """E-posta gönder. EMAIL_ENABLED false ise hiçbir şey yapma."""
    if not EMAIL_ENABLED:
        app.logger.info("EMAIL_ENABLED false, e-posta gönderimi atlandı.")
        return False
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        app.logger.warning("Mail kullanıcı adı/şifre yok, e-posta gönderilemedi.")
        return False
    try:
        msg = Message(subject=subject, recipients=recipients, body=body)
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.exception(f"E-posta gönderim hatası: {e}")
        return False

# ---------------------------------------------------------------------
# HTML Şablonları (tek dosya için inline)
# ---------------------------------------------------------------------
BASE_HTML = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>Matbaa Takip</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu, Cantarell, 'Helvetica Neue', Arial, 'Noto Sans', 'Apple Color Emoji','Segoe UI Emoji'; 
       margin:0;padding:0;background:#0d1117;color:#e6edf3}
  header{background:#161b22;padding:16px 20px;display:flex;align-items:center;justify-content:space-between}
  a{color:#7aa2f7;text-decoration:none}
  .container{max-width:980px;margin:24px auto;padding:0 16px}
  .card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:16px;margin-bottom:16px}
  input,textarea,select{width:100%;padding:10px;border-radius:8px;border:1px solid #30363d;background:#0d1117;color:#e6edf3}
  button{padding:10px 14px;border:1px solid #30363d;background:#21262d;color:#e6edf3;border-radius:8px;cursor:pointer}
  button:hover{background:#30363d}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  table{width:100%;border-collapse:collapse}
  th,td{border-bottom:1px solid #30363d;padding:10px;text-align:left}
  .tag{display:inline-block;padding:4px 8px;border:1px solid #30363d;border-radius:999px;font-size:12px}
  .muted{opacity:.8}
  .right{float:right}
  .danger{color:#f7768e}
  .success{color:#9ece6a}
  .center{text-align:center}
  </style>
</head>
<body>
<header>
  <div><a href="{{ url_for('index') }}"><strong>🖨️ Matbaa Takip</strong></a></div>
  <nav>
    {% if session.get('user_id') %}
      <span class="muted">Kullanıcı: <strong>{{ session.get('username') }}</strong>{% if session.get('is_admin') %} (admin){% endif %}</span>
      &nbsp;|&nbsp;
      <a href="{{ url_for('logout') }}">Çıkış</a>
    {% else %}
      <a href="{{ url_for('login') }}">Giriş</a>
    {% endif %}
  </nav>
</header>
<div class="container">
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="card">
        {% for m in messages %}<div>• {{ m }}</div>{% endfor %}
      </div>
    {% endif %}
  {% endwith %}
  {% block content %}{% endblock %}
</div>
</body>
</html>
"""

INDEX_HTML = """
{% extends 'base.html' %}
{% block content %}
  <div class="card">
    <h2>İş Listesi</h2>
    <p class="muted">Toplam: {{ jobs|length }} kayıt</p>
    {% if session.get('user_id') %}
      <a href="{{ url_for('new_job') }}"><button>+ Yeni İş</button></a>
      {% if session.get('is_admin') %}
        <a class="right" href="{{ url_for('admin') }}"><button>⚙️ Admin Panel</button></a>
      {% endif %}
    {% else %}
      <a href="{{ url_for('login') }}"><button>Giriş yap</button></a>
    {% endif %}
  </div>

  <div class="card">
    <table>
      <thead>
        <tr><th>ID</th><th>Başlık</th><th>Durum</th><th>Oluşturma</th><th></th></tr>
      </thead>
      <tbody>
        {% for j in jobs %}
        <tr>
          <td>#{{ j.id }}</td>
          <td>{{ j.title }}</td>
          <td><span class="tag">{{ j.status }}</span></td>
          <td class="muted">{{ j.created_at }}</td>
          <td>
            <a href="{{ url_for('job_detail', job_id=j.id) }}">Görüntüle</a>
            {% if session.get('user_id') %} • <a href="{{ url_for('edit_job', job_id=j.id) }}">Düzenle</a>{% endif %}
            {% if session.get('is_admin') %} • <a class="danger" href="{{ url_for('delete_job', job_id=j.id) }}" onclick="return confirm('Silinsin mi?')">Sil</a>{% endif %}
          </td>
        </tr>
        {% else %}
        <tr><td colspan="5" class="center muted">Kayıt yok</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
{% endblock %}
"""

LOGIN_HTML = """
{% extends 'base.html' %}
{% block content %}
  <div class="card" style="max-width:480px;margin:0 auto;">
    <h2>Giriş</h2>
    <form method="post" autocomplete="off">
      <label>Kullanıcı Adı</label>
      <input name="username" required autofocus placeholder="örn. {{ sample_username }}">
      <label>Şifre</label>
      <input name="password" type="password" required placeholder="●●●●●●●●">
      <div style="margin-top:12px">
        <button type="submit">Giriş yap</button>
      </div>
      <p class="muted" style="margin-top:12px">Not: Kullanıcı adı <strong>büyük/küçük harf duyarlı</strong>dır.</p>
    </form>
  </div>
{% endblock %}
"""

ADMIN_HTML = """
{% extends 'base.html' %}
{% block content %}
  <div class="card">
    <h2>Admin Panel</h2>
    <p class="muted">.env'deki admin bilgileri: <code>{{ admin_username }}</code></p>
    <form method="post" action="{{ url_for('admin_reset') }}" onsubmit="return confirm('Admin hesabı .env\'e göre sıfırlansın mı?');">
      <button type="submit">Admin hesabını .env\'e göre SIFIRLA</button>
    </form>
  </div>

  <div class="card">
    <h3>Kullanıcılar</h3>
    <table>
      <thead><tr><th>ID</th><th>Kullanıcı</th><th>Admin</th><th>E-posta</th></tr></thead>
      <tbody>
        {% for u in users %}
          <tr><td>{{ u.id }}</td><td>{{ u.username }}</td><td>{{ '✔' if u.is_admin else '—' }}</td><td>{{ u.email or '—' }}</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
{% endblock %}
"""

JOB_FORM_HTML = """
{% extends 'base.html' %}
{% block content %}
  <div class="card" style="max-width:720px;margin:0 auto;">
    <h2>{{ 'İşi Düzenle' if job else 'Yeni İş' }}</h2>
    <form method="post">
      <label>Başlık</label>
      <input name="title" required value="{{ job.title if job else '' }}">
      <label>Açıklama</label>
      <textarea name="description" rows="5">{{ job.description if job else '' }}</textarea>
      <label>Durum</label>
      <select name="status">
        {% for st in ['pending','in_progress','done','cancelled'] %}
          <option value="{{ st }}" {% if job and job.status==st %}selected{% endif %}>{{ st }}</option>
        {% endfor %}
      </select>
      <div style="margin-top:12px">
        <button type="submit">Kaydet</button>
        <a href="{{ url_for('index') }}"><button type="button">İptal</button></a>
      </div>
    </form>
  </div>
{% endblock %}
"""

JOB_DETAIL_HTML = """
{% extends 'base.html' %}
{% block content %}
  <div class="card">
    <h2>#{{ job.id }} - {{ job.title }}</h2>
    <p><span class="tag">{{ job.status }}</span></p>
    <p class="muted">Oluşturma: {{ job.created_at }}</p>
    <p style="white-space:pre-wrap">{{ job.description or '—' }}</p>
    <div style="margin-top:12px">
      {% if session.get('user_id') %}
        <a href="{{ url_for('edit_job', job_id=job.id) }}"><button>Düzenle</button></a>
      {% endif %}
      {% if session.get('is_admin') %}
        <a href="{{ url_for('delete_job', job_id=job.id) }}" class="danger" onclick="return confirm('Silinsin mi?')"><button>Sil</button></a>
      {% endif %}
      <a href="{{ url_for('index') }}"><button>Geri</button></a>
    </div>
  </div>
{% endblock %}
"""

# ---------------------------------------------------------------------
# Template register (render_template_string ile extends için env'e base'i ekleyelim)
# ---------------------------------------------------------------------
from jinja2 import DictLoader
app.jinja_loader = DictLoader({
    "base.html": BASE_HTML,
    "index.html": INDEX_HTML,
    "login.html": LOGIN_HTML,
    "admin.html": ADMIN_HTML,
    "job_form.html": JOB_FORM_HTML,
    "job_detail.html": JOB_DETAIL_HTML,
})

# ---------------------------------------------------------------------
# Rotalar
# ---------------------------------------------------------------------
@app.route("/")
def index():
    conn = get_db()
    jobs = conn.execute("SELECT id, title, description, status, created_at FROM jobs ORDER BY id DESC").fetchall()
    conn.close()
    return render_template_string(INDEX_HTML, jobs=jobs)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            flash("Giriş başarılı.")
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        else:
            flash("Kullanıcı adı veya şifre hatalı.")
            return redirect(url_for("login"))
    return render_template_string(LOGIN_HTML, sample_username=ADMIN_USERNAME)

@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı.")
    return redirect(url_for("index"))

@app.route("/admin")
@admin_required
def admin():
    conn = get_db()
    users = conn.execute("SELECT id, username, is_admin, email FROM users ORDER BY id ASC").fetchall()
    conn.close()
    return render_template_string(ADMIN_HTML, users=users, admin_username=ADMIN_USERNAME)

@app.route("/admin/reset", methods=["POST"])
@admin_required
def admin_reset():
    """Admin hesabını .env'e göre sil-yarat."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (ADMIN_USERNAME,))
    new_hash = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode("utf-8")
    cur.execute(
        "INSERT INTO users (username, password_hash, is_admin, email) VALUES (?, ?, ?, ?)",
        (ADMIN_USERNAME, new_hash, 1, None)
    )
    conn.commit()
    conn.close()
    flash("Admin hesabı .env'e göre sıfırlandı.")
    return redirect(url_for("admin"))

# --- İş CRUD ---
@app.route("/jobs/new", methods=["GET", "POST"])
@login_required
def new_job():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        status = request.form.get("status", "pending").strip() or "pending"
        if not title:
            flash("Başlık zorunludur.")
            return redirect(url_for("new_job"))

        conn = get_db()
        conn.execute(
            "INSERT INTO jobs (title, description, status, created_at) VALUES (?, ?, ?, ?)",
            (title, description, status, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()

        # Örnek e-posta bildirimi (aktif ise)
        send_email_notification(
            subject=f"Yeni iş oluşturuldu: {title}",
            recipients=[MAIL_DEFAULT_SENDER],
            body=f"Başlık: {title}\nDurum: {status}\nAçıklama:\n{description}"
        )

        flash("İş eklendi.")
        return redirect(url_for("index"))

    return render_template_string(JOB_FORM_HTML, job=None)

@app.route("/jobs/<int:job_id>")
def job_detail(job_id):
    conn = get_db()
    job = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    conn.close()
    if not job:
        abort(404)
    return render_template_string(JOB_DETAIL_HTML, job=job)

@app.route("/jobs/<int:job_id>/edit", methods=["GET", "POST"])
@login_required
def edit_job(job_id):
    conn = get_db()
    job = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not job:
        conn.close()
        abort(404)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        status = request.form.get("status", "pending").strip() or "pending"
        if not title:
            flash("Başlık zorunludur.")
            conn.close()
            return redirect(url_for("edit_job", job_id=job_id))

        conn.execute("UPDATE jobs SET title=?, description=?, status=? WHERE id=?",
                     (title, description, status, job_id))
        conn.commit()
        conn.close()

        # Örnek e-posta bildirimi (aktif ise)
        send_email_notification(
            subject=f"İş güncellendi: {title}",
            recipients=[MAIL_DEFAULT_SENDER],
            body=f"ID: {job_id}\nBaşlık: {title}\nYeni durum: {status}\nAçıklama:\n{description}"
        )

        flash("İş güncellendi.")
        return redirect(url_for("job_detail", job_id=job_id))

    conn.close()
    return render_template_string(JOB_FORM_HTML, job=job)

@app.route("/jobs/<int:job_id>/delete")
@admin_required
def delete_job(job_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    if deleted:
        flash("İş silindi.")
    else:
        flash("İş bulunamadı.")
    return redirect(url_for("index"))

# Basit API örneği
@app.route("/api/jobs")
def api_jobs():
    conn = get_db()
    jobs = conn.execute("SELECT id, title, status, created_at FROM jobs ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify([dict(j) for j in jobs])

# Sağlık kontrolü
@app.route("/healthz")
def healthz():
    return {"status": "ok", "env": FLASK_ENV}, 200

# ---------------------------------------------------------------------
# Çalıştırma
# ---------------------------------------------------------------------
if __name__ == "__main__":
    # Geliştirme için debug isteğe bağlı: FLASK_ENV=development ise debug True yap
    debug = FLASK_ENV.strip().lower() == "development"
    app.run(host="0.0.0.0", port=5000, debug=debug)
