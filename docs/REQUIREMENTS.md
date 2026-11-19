# متطلبات التشغيل والنظام — ان سايت (InSight)

يوضح هذا المستند جميع المتطلبات البرمجية والمادية والبيئية اللازمة لتشغيل نظام **ان سايت (InSight)** سواء في بيئة التطوير المحلية أو داخل المؤسسات في بيئة الإنتاج.

---

## 1. المتطلبات البرمجية الأساسية (Software Requirements)

| المكون | الإصدار المطلوب | الملاحظات |
| ------ | --------------- | --------- |
| **Node.js** | `v22.0.0` أو أحدث (LTS) | مطلوب لدعم TypeScript Type-Stripping الأصلي عند تشغيل `node server.ts` في الإنتاج |
| **npm** | `v10.0.0` أو أحدث | لإدارة وتثبيت الحزم (`npm ci`) |
| **نظام التشغيل** | Linux (Ubuntu 22.04/24.04 / Debian 12) أو macOS أو Windows 10/11 | يفضّل Linux في خوادم الإنتاج أو حاويات Docker |
| **Git** | `2.35+` | لاستنساخ المستودع وإدارة التحديثات |

---

## 2. مواصفات العتاد وحدود القياس (Hardware Sizing & Scaling Boundary)

> **تنبيه معماري مهم — حد العقدة الواحدة (Single-Node Only — Instance واحد فقط):**
> يعتمد الوضع الرسمي (`server.ts` + SQLite WAL `data/attendance.db` وفق [`ADR-001`](DECISIONS.md) و[`ADR-002`](DECISIONS.md)) على قاعدة بيانات SQLite محلية على القرص مع قنوات التشفير المؤقتة (`ECDH`) في الذاكرة. لذلك يدعم وضع Express الذاتي **تشغيل نسخة خادم واحدة فقط (Single Node / 1 Instance)** ولا يجوز تشغيل عدة حاويات/خوادم متوازية تكتب على قرص محلي منفصل لتفادي تضارب البيانات (Split-Brain).
> إذا احتاجت المؤسسة إلى **تعدد الخوادم (Horizontal Multi-Instance Scaling)** خلف موازن أحمال، يجب الاعتماد على قاعدة بيانات علائقية مركزية مشتركة (PostgreSQL — راجع المرجع المؤرشف تحت `examples/optional-supabase-mode/` وفق [`ADR-001`](DECISIONS.md)) مع مخزن Redis موزع (`REDIS_REST_URL`) للـ Rate Limiting والجلسات.

| حجم المؤسسة | المعالج (CPU) | الذاكرة (RAM) | مساحة القرص | بنية التشغيل المعتمدة |
| ----------- | ------------- | ------------- | ----------- | ---------------------- |
| **بيئة تطوير / حتى 150 موظفاً** | 1–2 vCPU | 1–2 GB | 10 GB SSD | **Single-Node (Instance واحد)**: Express + SQLite WAL (`attendance.db`) |
| **مؤسسة متوسطة وكبيرة ضمن مقر/عقدة (150–2,000+ موظف)** | 2–4 vCPU | 2–4 GB | 20–40 GB SSD | **Single-Node (Instance واحد)**: Express + SQLite WAL مفهرس + نسخ احتياطية مشفرة |
| **توسع أفقي متعدد الخوادم (Multi-Server HA)** | 4+ vCPU × N | 4–8 GB | قاعدة مركزية مُدارة | يتطلب **PostgreSQL مشترك** + Upstash Redis (غير مدعوم على SQLite المحلي) |

---

## 3. متطلبات المتصفح والأجهزة الطرفية (Client & Kiosk Browsers)

- **متصفح حديث**: Chrome 110+، Edge 110+، Safari 16.4+، أو Firefox 115+.
- **بروتوكول HTTPS إلزامي في الإنتاج**: الكاميرا (`getUserMedia`) والموقع الجغرافي (`navigator.geolocation`) و WebCrypto (`crypto.subtle`) لا تعمل على النطاقات غير الآمنة HTTP (باستثناء `localhost`).
- **شاشة الاستقبال (Reception Kiosk)**: جهاز لوحي أو شاشة عرض بنظام تشغيل مقفل مع متصفح بوضع ملء الشاشة (`--kiosk`) واتصال شبكي مستقر.

---

## 4. الحزم والمكتبات الأساسية المستخدمة (Dependencies)

- **الواجهة الأمامية**: React 19، React Router DOM 7، Tailwind CSS 4، Lucide React، `qrcode`، `jsqr`.
- **الخادم والأمان**: Express 4، Helmet 8 (CSP/HSTS/Frameguard)، `hpp`، `express-rate-limit`، `zod` 4 (Strict Schema Validation)، `dotenv`.
- **التشفير الأصلي (Node Crypto & WebCrypto)**: `AES-256-GCM`، `ECDH P-256`، `ECDSA P-256`، `HKDF-SHA256`، `Scrypt`، `PBKDF2-SHA256`، `TOTP RFC 6238`.

---

## 5. الخدمات الاختيارية للتكامل المؤسسي (Optional Services)

- **Cloudflare Free Plan + Turnstile**: لحماية Edge WAF وتصفية الدول ودرجة التهديد ومنع البوتات مجاناً.
- **Upstash Redis / Redis REST API**: لمشاركة حدود المحاولات (`Rate Limiting`) بين عدة نسخ من خادم Express.
- *(مرجع أرشيفي فقط)*: ملفات SQL الخاصة بـ Supabase محفوظة تحت `examples/optional-supabase-mode/` وفق [`ADR-001`](DECISIONS.md).

---

## 6. متغيرات البيئة المطلوبة (Environment Variables)

| المتغير | البيئة | مطلوب؟ | الوصف |
| ------- | ------ | ------ | ----- |
| `PORT` | التطوير والإنتاج | لا (افتراضي `3000`) | منفذ تشغيل خادم Express |
| `NODE_ENV` | التطوير والإنتاج | نعم في الإنتاج (`production`) | يفعّل قواعد الأمان الصارمة ووضع البناء |
| `DATA_ENCRYPTION_KEY` | الإنتاج | **إلزامي في الإنتاج** | مفتاح AES-256-GCM بطول 64 خانة Hex (من KMS) |
| `ADMIN_BOOTSTRAP_EMAIL` | الإنتاج (أول تشغيل) | موصى به | بريد المشرف الأعلى عند إنشاء القاعدة لأول مرة |
| `ADMIN_BOOTSTRAP_PASSWORD` | الإنتاج (أول تشغيل) | موصى به | كلمة مرور أول مشرف (12+ خانة قوية) |
| `KIOSK_BOOTSTRAP_SECRET` | الإنتاج (أول تشغيل) | موصى به | سر جهاز الاستقبال الأول (16+ خانة) |
| `REQUIRE_ADMIN_MFA` | الإنتاج | افتراضي `true` | يفرض تفعيل TOTP MFA (AAL2) على الإدارة |
| `ALLOWED_ORIGINS` | الإنتاج | موصى به | النطاقات المسموحة في CORS و Frame Ancestors |
| `TRUST_PROXY` | الإنتاج | حسب البنية | عدد طبقات البروكسي أو CIDR (مثال `1` أو `loopback`) |
| `TURNSTILE_SECRET_KEY` | الإنتاج/التطوير | عند تفعيل Turnstile | المفتاح السري لخدمة Cloudflare Turnstile |
| `REDIS_REST_URL` / `REDIS_REST_TOKEN` | الإنتاج متعدد النسخ | اختياري | مخزن Redis الموزع لـ Rate Limiting |
| `ALERT_WEBHOOK_URL` | الإنتاج | اختياري | رابط HTTPS لإرسال تنبيهات SIEM الأمنية الفورية |
