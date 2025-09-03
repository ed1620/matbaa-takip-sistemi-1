# 📚 Mavi Nefes Matbaa Takip Sistemi

Modern ve güvenli matbaa takip sistemi. Kitap siparişlerini takip etmek, müşteri iletişimini yönetmek ve raporlama yapmak için geliştirilmiş profesyonel bir Flask web uygulaması.

## ✨ Özellikler

### 🔐 Güvenlik
- **Bcrypt** ile güvenli şifre hash'leme
- **Rate limiting** ile brute force koruması
- **CSRF protection** aktif
- **Session timeout** yönetimi
- **Audit logging** tüm işlemler için
- **Input validation** ve sanitization

### 📊 Admin Paneli
- **Dashboard** ile genel durum görünümü
- **Kitap yönetimi** (ekleme, düzenleme, silme)
- **Toplu işlemler** (bulk update/delete)
- **Gelişmiş arama** ve filtreleme
- **Sayfalama** desteği
- **İstatistikler** ve grafikler

### 📧 E-posta Sistemi
- **HTML e-posta şablonları**
- **Otomatik bildirimler** (sipariş, durum değişikliği)
- **Logo ekleme** desteği
- **Gmail SMTP** entegrasyonu

### 📈 Raporlama
- **PDF raporları** (ReportLab)
- **Excel raporları** (OpenPyXL)
- **Filtreleme** seçenekleri
- **Otomatik formatlamalı** tablolar

### 🚀 Performans
- **Redis cache** desteği
- **Database indexing** optimizasyonu
- **Connection pooling**
- **Sayfalama** ile büyük veri desteği

### 🔄 Real-time
- **SocketIO** ile anlık bildirimler
- **Durum güncellemeleri** gerçek zamanlı
- **Admin bildirimleri**

### 🗄️ Veritabanı
- **SQLite** (development)
- **PostgreSQL** (production desteği)
- **Otomatik migration**
- **Backup sistemi**

## 🛠️ Kurulum

### Gereksinimler
- Python 3.8+
- Redis (opsiyonel, cache için)
- PostgreSQL (opsiyonel, production için)

### 1. Bağımlılıkları Yükle
```bash
pip install -r requirements.txt
```

### 2. Environment Variables
`.env` dosyası oluşturun:
```env
# Güvenlik (ZORUNLU!)
SECRET_KEY=your_super_secret_key_change_this
FLASK_ENV=development

# Admin Kullanıcı (ZORUNLU!)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_admin_password

# Email (Opsiyonel)
EMAIL_ENABLED=false
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password

# Database
DATABASE_PATH=matbaa_takip.db
REDIS_URL=redis://localhost:6379/0
```

**⚠️ GÜVENLİK UYARISI:** `.env` dosyasını asla GitHub'a yüklemeyin!

### 3. Uygulamayı Çalıştır
```bash
python app.py
```

Uygulama http://localhost:8080 adresinde çalışacaktır.

## 🐳 Docker ile Çalıştırma

```bash
# Docker Compose ile
docker-compose up -d

# Sadece uygulama
docker build -t matbaa-takip .
docker run -p 8080:8080 matbaa-takip
```

## 📱 Kullanım

### Müşteri Tarafı
1. **Ana sayfa** üzerinden iletişim kurabilir
2. **Takip sayfası** ile sipariş durumunu kontrol edebilir
3. **E-posta bildirimleri** otomatik alır

### Admin Tarafı
1. **Login**: `/login` (Kullanıcı: ADMIN_USERNAME, Şifre: ADMIN_PASSWORD)
2. **Dashboard**: Genel durum ve istatistikler
3. **Kitap Yönetimi**: Ekleme, düzenleme, silme
4. **Raporlama**: PDF/Excel export
5. **İletişim**: Müşteri mesajlarını yönetme

## 🔧 API Endpoints

### Genel
- `GET /` - Ana sayfa
- `GET /track` - Takip sayfası
- `POST /contact` - İletişim formu
- `GET /health` - Sistem durumu

### Admin (Authentication Required)
- `GET /admin/dashboard` - Admin paneli
- `POST /admin/add` - Kitap ekleme
- `PUT /admin/update/<id>` - Kitap güncelleme
- `DELETE /admin/delete/<id>` - Kitap silme
- `POST /admin/books/bulk-update` - Toplu güncelleme
- `DELETE /admin/books/bulk-delete` - Toplu silme
- `GET /admin/backup` - Veritabanı yedekleme
- `GET /admin/stats` - İstatistikler

## 📊 Veritabanı Şeması

### Books Tablosu
```sql
CREATE TABLE books (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    author_name TEXT NOT NULL,
    order_quantity INTEGER NOT NULL,
    size TEXT NOT NULL,
    status TEXT DEFAULT 'Hazırlanıyor',
    track_code TEXT UNIQUE NOT NULL,
    customer_email TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Users Tablosu
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    is_active BOOLEAN DEFAULT 1,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Status History Tablosu
```sql
CREATE TABLE status_history (
    id INTEGER PRIMARY KEY,
    book_id INTEGER NOT NULL,
    old_status TEXT,
    new_status TEXT NOT NULL,
    changed_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (book_id) REFERENCES books (id)
);
```

## 🔒 Güvenlik Özellikleri

- **Bcrypt** şifre hash'leme
- **Rate limiting** (5 login/dakika, 3 contact/dakika)
- **CSRF protection** aktif
- **Session timeout** (2 saat)
- **Input sanitization** ve validation
- **Audit logging** tüm işlemler için
- **SQL injection** koruması

## 📈 Performans Optimizasyonları

- **Database indexing** (track_code, status, created_at)
- **Connection timeout** (10 saniye)
- **Cache sistemi** (5 dakika TTL)
- **Sayfalama** (maksimum 100 kayıt/sayfa)
- **Bulk operations** toplu işlemler için

## 🚀 Production Deployment

### Environment Variables
```env
FLASK_ENV=production
SECRET_KEY=very_long_random_secret_key
DATABASE_URL=postgresql://user:pass@localhost/dbname
EMAIL_ENABLED=true
MAIL_USERNAME=your_production_email
MAIL_PASSWORD=your_app_password
REDIS_URL=redis://localhost:6379/0
PORT=8080
```

### Heroku Deployment
```bash
# Heroku CLI kurulumu
curl https://cli-assets.heroku.com/install.sh | sh

# Proje klasöründe
heroku create mavinefes-matbaa
git init
git add .
git commit -m "Initial commit"
git push heroku main

# Environment variables
heroku config:set FLASK_ENV=production
heroku config:set SECRET_KEY=your_secret_key_here
heroku config:set DATABASE_URL=postgresql://...
heroku config:set MAIL_USERNAME=your_email@gmail.com
heroku config:set MAIL_PASSWORD=your_app_password
```

### Docker Production
```bash
# Production build
docker build -t matbaa-takip:prod .

# Production run
docker run -d \
  -p 8080:8080 \
  -e FLASK_ENV=production \
  -e SECRET_KEY=your_production_secret \
  -e DATABASE_URL=postgresql://... \
  -e REDIS_URL=redis://... \
  --name matbaa-takip-prod \
  matbaa-takip:prod
```

### Nginx Configuration
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 📝 Changelog

### v2.0.0 (2025-01-09)
- ✅ Bcrypt şifre güvenliği
- ✅ Rate limiting eklendi
- ✅ Logging sistemi
- ✅ Cache desteği
- ✅ Audit logging
- ✅ Error handling
- ✅ Docker desteği
- ✅ Bulk operations
- ✅ Input validation
- ✅ Health checks
- ✅ Backup sistemi

## 📞 Destek

Sorularınız için: siparis@mavinefes.com.tr

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. 