# ان سايت (InSight) — نظام حضور وانصراف الموظفين الآمن عبر QR + GPS

[![CI Verification](https://img.shields.io/badge/CI-Node_22_&_TypeScript-0f172a?style=flat-square)](.github/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-0284c7?style=flat-square)](LICENSE)
[![Security: AES-256-GCM & MFA](https://img.shields.io/badge/Security-AES--256--GCM_%7C_TOTP_AAL2-047857?style=flat-square)](docs/SECURITY.md)

نظام مؤسسي مفتوح المصدر لإدارة حضور وانصراف الموظفين يعتمد **رسمياً وبشكل موحّد على خادم Express ذاتي الاستضافة (`server.ts`)** مع قناة تشفير تطبيقية (**ECDH P-256 + ECDSA P-256 + AES-256-GCM**)، ويجمع بين رمز **QR المتغير أحادي الاستخدام**، و**الرمز اليدوي البديل** عند تعذر الكاميرا، و**التحقق الجغرافي (GPS Geofencing)**، مع حماية **Cloudflare المجانية (WAF + Turnstile)** ونظام **صلاحيات متصل بقاعدة البيانات (DB RBAC)**.

> **ملاحظة معمارية (ADR-001):** مسار **Express ذاتي الاستضافة (`server.ts`)** هو المسار الرسمي الوحيد المتصل بالواجهة الأمامية لضمان تكافؤ جميع ضوابط التشفير والأمان. أما ترحيلات Supabase القديمة فقد نُقلت إلى [`examples/optional-supabase-mode/`](examples/optional-supabase-mode/README.md) كمرجع أرشيفي تجريبي غير مكافئ أمنياً.

---

## المزايا الرئيسية

- **شاشات استقبال متعددة (Multi-Device Kiosks)**: اعتماد وإدارة عدة أجهزة عرض للبوابات والفروع، لكل جهاز حسابه وسرّه وجلساته المستقلة مع إمكانية الإبطال والتدوير الفوري.
- **جدولة إخفاء وعودة ظهور الـ QR تلقائياً**: تحديد وقت بدء الالتقاط، وآخر وقت قبل إخفاء الرمز تلقائياً، ووقت عودة الظهور للانصراف (يُفرض على الخادم وعلى شاشات الاستقبال بدون إعادة تحميل).
- **بوابة الموظف والماسح المرن**: مسح عبر الكاميرا أو إدخال رمز يدوي من 8 خانات، مع التحقق من حداثة ودقة الـ GPS ومؤقت حي للوردية وملخص الالتزام الشهري.
- **تشفير وحماية إدارية فائقة**:
  - تخزين مشفّر بـ **AES-256-GCM** وتجزئة كلمات المرور عبر **Scrypt**.
  - قناة نقل تطبيقية موقّعة (**ECDH P-256 + ECDSA P-256 + AES-256-GCM**) فوق HTTPS/TLS.
  - بوابة **Step-Up + المصادقة الثنائية TOTP MFA (AAL2)** وإغلاق تلقائي للوحة عند الخمول.
  - جدار حماية ضد SQLi/XSS و Parameter Pollution و HTTP Method-Override و CSRF/CORS الصارم.
- **حماية Cloudflare المجانية و Turnstile**: تصفية الدول (`CF-IPCountry`)، حظر التهديدات (`CF-Threat-Score`)، واعتماد `CF-Connecting-IP` فقط عند التحقق، مع تحقق البوتات المجاني على تسجيل الدخول.
- **التحكم والصلاحيات عبر قاعدة البيانات (RBAC)**: إدارة مصفوفة الصلاحيات والأدوار (`super_admin`, `hr_manager`, `attendance_supervisor`, `security_auditor`) وتعيين المشرفين مباشرة من لوحة التحكم.
- **كتالوج تسطيب مؤسسي مدمج**: دليل تسطيب وتشغيل جاهز للطباعة والتحميل من داخل لوحة التحكم وفي [`docs/ENTERPRISE_SETUP_CATALOG.md`](docs/ENTERPRISE_SETUP_CATALOG.md).

---

## المتطلبات الأساسية (باختصار)

- **Node.js v22.0.0+** و **npm v10+**
- متصفح حديث مع تفعيل HTTPS في الإنتاج لتشغيل الكاميرا والموقع الجغرافي و WebCrypto
- *(اختياري)* حساب Cloudflare مجاني، Upstash Redis للـ Rate Limiting الموزع

للقائمة الكاملة للمتطلبات والعتاد ومتغيرات البيئة راجع: **[`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md)**

---

## طريقة التشغيل السريعة

### 1. التشغيل محلياً للتطوير والاختبار
```bash
git clone https://github.com/<your-org>/insight-attendance.git
cd insight-attendance
npm ci
npm run dev
```
ثم افتح المتصفح على `http://localhost:3000`.

### 2. التحقق والبناء والاختبار
```bash
npm run lint
npm run build
npm test
```

### 3. التشغيل في الإنتاج
```bash
cp .env.example .env
# اضبط DATA_ENCRYPTION_KEY و بيانات Bootstrap الأولية و ALLOWED_ORIGINS
NODE_ENV=production npm start
```

لخطوات التشغيل المفصلة وإعداد Nginx و Systemd راجع: **[`docs/HOW_TO_RUN.md`](docs/HOW_TO_RUN.md)**

---

## المسارات الأساسية في التطبيق

| المسار | الوصف |
| ------ | ----- |
| `/login` | تسجيل الدخول الموحد (مع دعم Cloudflare Turnstile والحد من محاولات التخمين) |
| `/employee` | بوابة الموظف (حالة اليوم، مؤقت الوردية، الإحصائيات الشهرية، سجل الحضور) |
| `/employee/scan` | ماسح رمز QR بالكاميرا + الإدخال اليدوي البديل + التحقق من GPS |
| `/kiosk` | شاشة الاستقبال (QR ديناميكي، الرمز اليدوي، وحالة التوقف المجدول التلقائية) |
| `/hr` | لوحة الموارد البشرية (Step-Up + TOTP MFA، السجلات، الموظفون، الأجهزة، الأمان، الصلاحيات، الكتالوج) |

---

## الوثائق والملفات المرجعية

- [`docs/DECISIONS.md`](docs/DECISIONS.md) — سجل القرارات المعمارية (ADR-001 واعتماد Express كمسار وحيد)
- [`docs/HOW_TO_RUN.md`](docs/HOW_TO_RUN.md) — طريقة التشغيل خطوة بخطوة (تطوير + إنتاج)
- [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) — متطلبات النظام، الحزم، ومتغيرات البيئة
- [`docs/ENTERPRISE_SETUP_CATALOG.md`](docs/ENTERPRISE_SETUP_CATALOG.md) — كتالوج التسطيب داخل المؤسسات وإعداد Cloudflare WAF
- [`docs/SECURITY.md`](docs/SECURITY.md) — البنية الأمنية والتشفير وسياسات الجلسات
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — قائمة التحقق للنشر والنسخ الاحتياطي المشفر (DR)
- [`docs/DATABASE.md`](docs/DATABASE.md) — هيكل التخزين الرسمي والمرجع الأرشيفي لترحيلات SQL
- [`CHANGELOG.md`](CHANGELOG.md) — سجل التغييرات
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — إرشادات المساهمة البرمجية
- [`SECURITY.md`](SECURITY.md) — سياسة الإبلاغ المسؤول عن الثغرات الأمنية

---

## الترخيص (License)

هذا المشروع مرخص بموجب رخصة **MIT License** — راجع ملف [`LICENSE`](LICENSE) للتفاصيل.
