# 📚 Mavi Nefes Matbaa Takip Sistemi

Modern ve güvenli matbaa takip sistemi. Kitap siparişlerini takip etmek, müşteri iletişimini yönetmek ve raporlama yapmak için geliştirilmiş profesyonel bir Flask web uygulaması.

## ✨ Özellikler

- **Kitap Sipariş Yönetimi** - Sipariş ekleme, düzenleme, silme
- **Takip Sistemi** - Benzersiz takip kodları ile sipariş takibi
- **Admin Paneli** - Kapsamlı yönetim arayüzü
- **E-posta Bildirimleri** - Otomatik e-posta gönderimi
- **Excel Raporları** - Detaylı raporlama sistemi
- **İletişim Formu** - Müşteri iletişim yönetimi
- **Güvenlik** - Bcrypt şifreleme, rate limiting

## 🚀 Hızlı Başlangıç

### Gereksinimler
- Python 3.8+
- Gmail hesabı (e-posta için)

### Kurulum
```bash
# Bağımlılıkları yükle
pip install -r requirements.txt

# Uygulamayı çalıştır
python app.py
```

### Environment Variables
```env
SECRET_KEY=your_secret_key
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
```

## 🔑 Admin Giriş

- **Kullanıcı Adı:** NARSİST
- **Şifre:** Mavinefes25

## 📧 E-posta Ayarları

Gmail App Password kullanın:
1. Gmail hesabınızda 2-Factor Authentication aktif edin
2. Google Account → Security → App passwords
3. "Mail" seçin ve yeni app password oluşturun

## 🌐 Deployment

### Render.com
1. GitHub repository'yi bağlayın
2. Environment variables ekleyin
3. Deploy edin

### Environment Variables (Render)
```
SECRET_KEY=matbaa_takip_2025_production_secret_key
FLASK_ENV=production
EMAIL_ENABLED=true
MAIL_USERNAME=eren1121623@gmail.com
MAIL_PASSWORD=tozf oanq eoko bvse
ADMIN_USERNAME=NARSİST
ADMIN_PASSWORD=Mavinefes25
DATABASE_PATH=matbaa_takip.db
```

## 📞 İletişim

- **E-posta:** siparis@mavinefes.com.tr
- **Telefon:** +90 258 266 55 44
- **Adres:** Mavi Nefes Yayınları, Zümrüt, Vatan Cd No:240, 20160 Denizli Merkez/Denizli

## 👨‍💻 Geliştirici

**Eren Doğan** - [LinkedIn](https://www.linkedin.com/in/erendogan20/)

---

© 2025 Mavi Nefes Matbaa. Tüm hakları saklıdır.
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