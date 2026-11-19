# كتالوج التسطيب والتشغيل المؤسسي — نظام ان سايت (InSight)

دليل تنفيذي متكامل لإدارة تقنية المعلومات وأمن المعلومات لنشر وتشغيل نظام **ان سايت (InSight)** لإدارة حضور وانصراف الموظفين بأعلى معايير التشفير وحماية الأطراف (Cloudflare Free WAF & Turnstile) وتوزيع شاشات الاستقبال وصلاحيات قاعدة البيانات.

---

## 1. المتطلبات الأساسية للخادم والبيئة (System Prerequisites)

- **نظام التشغيل**: Linux (Ubuntu 22.04 / 24.04 LTS أو Debian 12 أو بيئة Docker / Cloud Run).
- **بيئة التشغيل**: **Node.js v22 LTS** (يدعم TypeScript Type-Stripping أصلياً عبر `--experimental-strip-types`).
- **الموارد الدنيا المقترحة**:
  - للمؤسسات حتى 500 موظف: 2 vCPU · 2 GB RAM · 20 GB SSD.
  - للمؤسسات أكبر من 500 موظف: 4 vCPU · 4 GB RAM + Redis موزع للـ Rate Limiting.
- **الشبكة وبروتوكول النقل**: HTTPS إجباري عبر Reverse Proxy (مثل Nginx / Caddy) أو منصة سحابية خلف Cloudflare Proxied DNS.

---

## 2. تهيئة متغيرات البيئة وإدارة المفاتيح (KMS & Secrets)

أنشئ ملف `.env` على الخادم الإنتاجي (أو اضبط المتغيرات داخل منصة النشر Cloud Run / Kubernetes Secrets). **يُمنع منعاً باتاً حفظ الأسرار في المستودع أو داخل الكود المصدري.**

```ini
NODE_ENV=production
PORT=3000

# تفعيل إجراءات الإنتاج الصارمة والمصادقة الثنائية الإلزامية للإدارة
STRICT_PROD_SECRETS=true
REQUIRE_ADMIN_MFA=true

# مفتاح تشفير قاعدة البيانات (64 خانة Hex = 32 بايت من KMS)
DATA_ENCRYPTION_KEY=<64_HEX_CHARS_FROM_OPENSSL_RAND_HEX_32>

# تهيئة Bootstrap للإدارة الأولى (تُستخدم عند أول تشغيل فقط ثم يُحذف/يُغيّر)
INIT_ADMIN_EMAIL=admin@your-org.com
INIT_ADMIN_PASSWORD=<STRONG_INITIAL_ADMIN_PASSWORD>

# النطاقات المعتمدة لسياسة CORS و CSP Frame Ancestors
ALLOWED_ORIGINS=https://attendance.your-org.com
ALLOWED_FRAME_ANCESTORS='none'

# عدد طبقات البروكسي الموثوقة (1 لـ Nginx أو Cloudflare)
TRUST_PROXY=1

# حماية Cloudflare Turnstile المجانية (اختياري عبر لوحة الأمان)
TURNSTILE_SECRET_KEY=<CLOUDFLARE_TURNSTILE_SECRET_KEY>

# مخزن Rate Limiting موزع عبر Redis (موصى به في العناقيد متعددة النسخ)
UPSTASH_REDIS_REST_URL=https://<your-redis>.upstash.io
UPSTASH_REDIS_REST_TOKEN=<UPSTASH_TOKEN>

# تنبيهات SIEM / Webhook الفورية (HTTPS فقط)
ALERT_WEBHOOK_URL=https://siem.your-org.com/webhooks/insight
```

لتوليد مفتاح `DATA_ENCRYPTION_KEY` عشوائي قوي:

```bash
openssl rand -hex 32
```

---

## 3. خطوات البناء والتشغيل (Build & Systemd Service)

### أ. البناء القياسي على الخادم

```bash
npm ci
npx tsc --noEmit
npm run build
npm test
```

### ب. التشغيل عبر Systemd (Linux Server)

أنشئ ملف `/etc/systemd/system/insight-attendance.service`:

```ini
[Unit]
Description=InSight Enterprise Attendance Server
After=network.target

[Service]
Type=simple
User=insight
WorkingDirectory=/opt/insight
EnvironmentFile=/opt/insight/.env
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/insight/data

[Install]
WantedBy=multi-user.target
```

ثم فعّل الخدمة:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now insight-attendance
sudo systemctl status insight-attendance
```

### ج. إعداد Nginx Reverse Proxy أمام التطبيق

```nginx
server {
    listen 443 ssl http2;
    server_name attendance.your-org.com;

    ssl_certificate     /etc/ssl/cloudflare/origin.pem;
    ssl_certificate_key /etc/ssl/cloudflare/origin.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
        proxy_set_header CF-IPCountry $http_cf_ipcountry;
        proxy_set_header CF-Threat-Score $http_cf_threat_score;
        proxy_set_header CF-Ray $http_cf_ray;
    }
}
```

---

## 4. تفعيل الحماية العالمية عبر Cloudflare Free Plan + Turnstile

يوفر **ان سايت** تكاملاً مباشراً مع ميزات خطة **Cloudflare المجانية** لحماية بوابة الإدارة وشاشات الاستقبال من الهجمات والروبوتات:

1. **إعداد DNS و SSL/TLS**:
   - أضف سجل `A` أو `CNAME` لنطاق النظام (مثل `attendance.your-org.com`) مع تفعيل **السحابة البرتقالية (Proxied)**.
   - من **SSL/TLS → Overview**: اختر الوضع **Full (Strict)** وركّب شهادة **Cloudflare Origin Certificate** على Nginx.
   - من **SSL/TLS → Edge Certificates**: فعّل **Always Use HTTPS** و **Minimum TLS Version: 1.2**.
2. **قواعد WAF المجانية (Security → WAF → Custom Rules)**:
   - أنشئ قاعدة لحظر الطلبات المشبوهة إلى `/api/hr/*` من خارج الدول المصرح بها أو ذات Threat Score المرتفع.
   - فعّل **Bot Fight Mode** من قسم **Security → Bots**.
3. **خدمة التحقق البشري المجانية (Cloudflare Turnstile)**:
   - من لوحة Cloudflare انتقل إلى **Turnstile → Add Widget**.
   - انسخ **Site Key** وأدخله من داخل لوحة الموارد البشرية (تبويب **الأمان والتدقيق → سياسة Cloudflare و WAF**).
   - انسخ **Secret Key** وضعه في متغير البيئة `TURNSTILE_SECRET_KEY` على الخادم وأعد تشغيل الخدمة.
4. **الربط من داخل لوحة تحكم ان سايت**:
   - انتقل إلى تبويب **الأمان والتدقيق**.
   - فعّل:
     - `حماية Cloudflare Edge` (`cloudflare_enabled`)
     - `اعتماد ترويسات Cloudflare الموثقة` (`trust_cf_headers`)
     - تحديد الدول المسموحة بصيغة ISO-2 (مثل `SA, AE, EG`)
     - ضبط عتبة حظر التهديدات (`CF-Threat-Score` مثلاً `35`)
     - تفعيل حظر `X-HTTP-Method-Override` وإلزام `application/json`.

---

## 5. تهيئة عدة أجهزة استقبال (Multi-Device Kiosks) وجدولة إخفاء رمز QR

### أ. اعتماد أجهزة الاستقبال لكل بوابة أو فرع
1. افتح **لوحة الموارد البشرية → الفروع والدوام**.
2. في قسم **أجهزة شاشة الاستقبال (Kiosk)**، اضغط **اعتماد جهاز استقبال جديد**.
3. أدخل:
   - **اسم الجهاز**: (مثال: `بوابة الاستقبال الرئيسية — الدور الأرضي`)
   - **الفرع**: (مثال: `المقر الرئيسي — الرياض`)
   - **بريد الحساب المستقل للجهاز**: (مثال: `kiosk-gate2@your-org.com`)
   - **كلمة مرور قوية** + **سر اعتماد الجهاز (`device_secret`)** يُحفظ لدى فني البوابة ويُدخل في ذاكرة المتصفح فقط عند التشغيل.
4. يمكن تعطيل أي شاشة، تدوير سرّها، أو إبطال جلساتها فوراً دون التأثير على باقي الشاشات.
5. لتشغيل الشاشة في وضع Kiosk تلقائياً عند إقلاع الجهاز اللوحي/الشاشة:
   ```bash
   google-chrome --kiosk --app=https://attendance.your-org.com/kiosk
   ```

### ب. جدولة إخفاء رمز QR وعودة ظهوره تلقائياً
- من قسم **جدولة أوقات التقاط وإخفاء رمز QR**:
  - فعّل الجدول وحدد:
    - **بداية نافذة الحضور (`qr_window_start`)**: مثلاً `07:30`
    - **آخر وقت لالتقاط الرمز وإخفائه (`qr_cutoff_time`)**: مثلاً `11:00` (بعدها يختفي الـ QR وتظهر رسالة التوقف المؤقت تلقائياً ويرفض الخادم أي تسجيل).
    - **وقت رجوع ظهور الرمز للانصراف (`qr_reappear_time`)**: مثلاً `15:30` (يعود الرمز للظهور تلقائياً على جميع الشاشات دون إعادة تحميل الصفحة).
    - **نهاية نافذة اليوم (`qr_window_end`)**: مثلاً `19:00`

---

## 6. إدارة الصلاحيات والتحكم عبر قاعدة البيانات (RBAC & TOTP MFA)

يربط النظام صلاحيات المشرفين بجدولي `public.rbac_roles` و `public.user_permissions` (وفي الخادم المشفر بقاعدة البيانات مباشرة) مع 4 أدوار قياسية قابلة للتخصيص من تبويب **الصلاحيات والتحكم**:

- `super_admin`: صلاحيات كاملة على جميع أقسام النظام وتعديل مصفوفة الصلاحيات.
- `hr_manager`: إدارة الموظفين، السجلات، الأعذار، التقارير، والأجهزة وإعدادات الفروع.
- `attendance_supervisor`: متابعة النظرة العامة، السجلات، والأعذار فقط دون الوصول لإعدادات الأمان أو الحذف الحساس.
- `security_auditor`: مراجعة سجلات التدقيق الأمني والجلسات النشطة وإعدادات الحماية فقط.

> **قاعدة أمان حرجة**: يُمنع النظام ذاتياً من إزالة صلاحية `manage_permissions` عن آخر مشرف نشط (`super_admin`) لضمان عدم فقدان السيطرة الإدارية، وتُفرض المصادقة الثنائية `TOTP MFA (AAL2)` في وضع الإنتاج قبل فتح لوحة الإدارة.

---

## 7. النسخ الاحتياطي المشفر والتعافي من الكوارث (DR)

1. من تبويب **الأمان والتدقيق → نسخة احتياطية مشفّرة ومعزولة**: أدخل عبارة مرور لا تقل عن 12 حرفاً لتنزيل نسخة مشفرة باستخدام `PBKDF2-SHA256 (210,000 iteration)` + `AES-256-GCM` معزولة عن مفتاح الخادم `.master.key`.
2. احتفظ بالنسخ الاحتياطية في مخزن خارجي مشفر (WORM / Object Lock).
3. في حال استخدام PostgreSQL / Supabase: نفّذ جميع ملفات الترحيل بالترتيب من `202611170001` حتى `202611190007` وتأكد من تفعيل `RLS` و `AAL2` عبر تشغيل اختبار الأمان:
   ```bash
   npm test
   ```
