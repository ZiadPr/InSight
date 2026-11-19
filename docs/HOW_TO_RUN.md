# دليل طريقة التشغيل — نظام ان سايت (InSight)

يشرح هذا الدليل خطوات تشغيل النظام من الصفر في **وضع التطوير المحلي** وفي **بيئة الإنتاج المؤسسية**.

---

## أولاً: التشغيل السريع في بيئة التطوير (Local Development)

### 1. استنساخ المستودع وتثبيت الاعتماديات
```bash
git clone https://github.com/<your-org>/insight-attendance.git
cd insight-attendance
npm ci
```

### 2. إعداد ملف متغيرات البيئة (اختياري للتطوير)
```bash
cp .env.example .env
```
> في بيئة التطوير (`NODE_ENV` غير مضبوط على `production`)، يعمل النظام تلقائياً بقاعدة بيانات مشفرة محلية تحت `data/attendance-db.enc` مع بيانات تجريبية للمعاينة فقط تظهر في وضع `DEV` وتُزال تلقائياً عند البناء الإنتاجي.

### 3. تشغيل الخادم والواجهة معاً
```bash
npm run dev
```
سيعمل التطبيق على الرابط:
- البوابة الموحدة: `http://localhost:3000/login`
- بوابة الموظف: `http://localhost:3000/employee`
- لوحة الموارد البشرية: `http://localhost:3000/hr`
- شاشة الاستقبال (Kiosk): `http://localhost:3000/kiosk`

### 4. تشغيل الفحوصات والاختبارات الأمنية
```bash
# فحص الأنواع (TypeScript)
npm run lint

# تشغيل اختبارات الأمان والوحدة (22+ اختباراً)
npm test

# فحص صيغة الخادم على Node 22
node --check server.ts
```

---

## ثانياً: التشغيل في بيئة الإنتاج (Production Deployment)

### 1. توليد مفتاح التشفير وتجهيز المتغيرات
ولّد مفتاح تشفير 256-bit (64 خانة Hex):
```bash
openssl rand -hex 32
```

اضبط متغيرات البيئة في الخادم أو Secret Manager (راجع `.env.example`):
```ini
NODE_ENV=production
PORT=3000
DATA_ENCRYPTION_KEY=<64_HEX_FROM_OPENSSL>
ADMIN_BOOTSTRAP_EMAIL=hr-admin@your-company.com
ADMIN_BOOTSTRAP_PASSWORD=<STRONG_PASSWORD_MIN_12_CHARS>
KIOSK_BOOTSTRAP_SECRET=<HIGH_ENTROPY_KIOSK_SECRET>
REQUIRE_ADMIN_MFA=true
REQUIRE_HTTPS=true
TRUST_PROXY=1
ALLOWED_ORIGINS=https://attendance.your-company.com
```

### 2. البناء الإنتاجي والتشغيل
```bash
npm ci
npm run lint
npm run build
npm test
NODE_ENV=production npm start
```

### 3. الخطوات الإلزامية بعد أول تشغيل للإنتاج
1. سجّل الدخول بحساب المدير الأولي إلى `/hr`.
2. سيتم توجيهك لإتمام ربط المصادقة الثنائية **TOTP MFA** عبر مسح رمز QR من تطبيق Google Authenticator أو Microsoft Authenticator.
3. من تبويب **الفروع والدوام**:
   - اضبط إحداثيات مقر الشركة ونطاق السماح (Geofence) وأوقات الدوام.
   - فعّل **جدول التقاط وإخفاء رمز QR** (إن رغبت بإخفائه بعد وقت الحضور وإعادته وقت الانصراف).
   - اعتمد أجهزة شاشات الاستقبال الإضافية لكل بوابة.
4. من تبويب **الأمان والتدقيق**:
   - فعّل إعدادات **Cloudflare Free WAF** و **Turnstile** (في حال التشغيل خلف Cloudflare).
   - احتفظ بنسخة احتياطية مشفرة ومعزولة (PBKDF2 + AES-256-GCM) بعبارة مرور خارجية آمنة.
5. من تبويب **الصلاحيات والتحكم**:
   - خصص مصفوفة الصلاحيات للأدوار الأربعة وعيّن المشرفين حسب نطاق عملهم.

---

## ثالثاً: المرجع الأرشيفي لـ Supabase (غير متصل بالواجهة — أرشيفي فقط)

بموجب القرار المعماري [`ADR-001`](DECISIONS.md)، تم اعتماد خادم Express (`server.ts`) كمسار وحيد رسمي. ترحيلات PostgreSQL/Supabase السابقة محفوظة كمرجع تصميمي فقط داخل `examples/optional-supabase-mode/` ولا تتصل بالواجهة الأمامية.

للدليل المؤسسي المفصّل شامل إعداد Nginx و Systemd و Cloudflare، راجع:
- [`docs/ENTERPRISE_SETUP_CATALOG.md`](ENTERPRISE_SETUP_CATALOG.md)
- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md)
- [`docs/DECISIONS.md`](DECISIONS.md)
