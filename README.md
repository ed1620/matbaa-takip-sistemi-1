# Mavi Nefes Matbaa Takip Sistemi

Modern ve güvenli matbaa takip sistemi. Kitap siparişlerini takip etmek, müşteri iletişimini yönetmek ve raporlama yapmak için geliştirilmiş profesyonel bir Flask web uygulaması.

---

## Özellikler

- Kitap Sipariş Yönetimi (ekleme, düzenleme, silme)
- Sipariş Takip Sistemi (benzersiz takip kodları ile)
- Admin Paneli (yönetim arayüzü)
- E-posta Bildirimleri
- Excel Raporları
- İletişim Formu
- Gelişmiş Güvenlik (bcrypt şifreleme, rate limiting)

---

## Hızlı Başlangıç

### Gereksinimler
- Python 3.8+
- Gmail hesabı (e-posta bildirimleri için)

### Kurulum
```bash
# Projeyi klonlayın
git clone https://github.com/kullaniciadi/projeadi.git

# Klasöre girin
cd projeadi

# Bağımlılıkları yükleyin
pip install -r requirements.txt

# Uygulamayı çalıştırın
python app.py
````

Uygulama [http://localhost:8080](http://localhost:8080) adresinde çalışacaktır.

---

## Ortam Değişkenleri

Aşağıdaki environment değişkenlerini `.env` dosyanıza ekleyin:

```env
SECRET_KEY=your_secret_key
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
ADMIN_USERNAME=your_admin_username
ADMIN_PASSWORD=your_admin_password
```

> Not: Buradaki değerleri kendi güvenli bilgilerinizle doldurun. Public repo’da asla paylaşmayın.

---

## Kullanım

### Müşteri Tarafı

* Ana sayfa üzerinden iletişim kurabilir
* Takip sayfası ile sipariş durumunu kontrol edebilir
* Otomatik e-posta bildirimleri alır

### Admin Tarafı

* Login: `/login`
* Dashboard: Genel durum ve istatistikler
* Kitap Yönetimi: ekleme, düzenleme, silme
* Raporlama: PDF/Excel export
* Müşteri mesajlarını yönetme

---

## API Endpoints

### Genel

* `GET /` → Ana sayfa
* `GET /track` → Takip sayfası
* `POST /contact` → İletişim formu
* `GET /health` → Sistem durumu

### Admin (Authentication Required)

* `GET /admin/dashboard` → Admin paneli
* `POST /admin/add` → Kitap ekleme
* `PUT /admin/update/<id>` → Kitap güncelleme
* `DELETE /admin/delete/<id>` → Kitap silme
* `GET /admin/stats` → İstatistikler

---

## Veritabanı Şeması

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

---

## İletişim

* E-posta: [siparis@mavinefes.com.tr]
* Telefon: +90 258 266 55 44
* Adres: Mavi Nefes Yayınları, Zümrüt, Vatan Cd No:240, 20160 Denizli Merkez/Denizli

---

## Geliştirici

**Eren Doğan** - [LinkedIn](https://www.linkedin.com/in/erendogan20/)

---

© 2025 Mavi Nefes Matbaa. Tüm hakları saklıdır.
