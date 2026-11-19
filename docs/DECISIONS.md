# Architecture Decision Records (ADR) — InSight (ان سايت)

## ADR-001: اعتماد خادم Express الموحد كمسار خلفي وحيد رسمي (حسم ازدواجية الباك-إند)

- **الحالة (Status):** مقبول ومُنفّذ (Accepted & Implemented)
- **التاريخ:** 2026-11-19
- **المهمة المرجعية:** `01-fix-dual-backend-architecture`

### 1. السياق (Context)
احتوى المشروع سابقاً على مسارين خلفيين منفصلين بالتوازي عبر شرط `isSupabaseConfigured` في الواجهة الأمامية:
1. **خادم Express ذاتي الاستضافة (`server.ts`)**: يدعم قناة نقل تطبيقية مشفّرة وموقّعة (`ECDH P-256 + ECDSA P-256 + AES-256-GCM`)، المصادقة الثنائية (`TOTP MFA AAL2`)، بوابة `Step-Up` الإدارية، صلاحيات `RBAC` المرتبطة بلوحة التحكم، جدولة إخفاء وعودة ظهور QR، إدارة تعدد أجهزة الاستقبال، وإعدادات Cloudflare WAF + Turnstile.
2. **مسار Supabase (Postgres + Edge Functions تحت `supabase/`)**: مسار بديل يعاني من انحراف في المخطط والتسمية (`student_id`, `campus_settings`, `study_calendar` بدلاً من `employee_id` وبيانات الموظفين)، ولا يطبّق قناة التشفير التطبيقي (`ECDH + ECDSA`) أو جدار الحماية والجدولة والصلاحيات بنفس التكافؤ الأمني.

### 2. الخيارات المدروسة (Options Considered)
- **القرار أ (المُختار): اعتماد Express (`server.ts`) كمسار وحيد رسمي** للنظام المفتوح المصدر الموجّه للتشغيل المؤسسي والداخلي (On-Prem / Self-Hosted)، وإزالة كل شروط `isSupabaseConfigured` والكود الميت من الواجهة الأمامية، مع نقل مجلد `supabase/` إلى `examples/optional-supabase-mode/` كمرجع أرشيفي غير مكافئ أمنياً.
- **القرار ب:** اعتماد Supabase كمسار وحيد وحذف `server.ts`. تم استبعاده لأن كافة الميزات المؤسسية والأمنية المتقدمة (E2EE التطبيقي، Step-Up، التوقيع الإلكتروني، جدولة QR، Cloudflare Turnstile/WAF، وتعدد أجهزة الاستقبال) مبنية ومختبرة بالكامل داخل `server.ts`.

### 3. القرار (Decision)
اعتماد **القرار أ**:
1. إزالة `src/lib/supabase.ts` وكافة التفرعات الشرطية `isSupabaseConfigured` من `src/hooks/useAuth.tsx`، `src/services/attendanceService.ts`، `src/services/kioskService.ts`، و`src/pages/AttendanceScannerPage.tsx`.
2. توجيه جميع الطلبات الحساسة حصرياً عبر `secureFetchJson` وقناة التشفير التطبيقي الموقّعة (`ECDH P-256 + ECDSA + AES-256-GCM`) إلى خادم `server.ts`.
3. نقل ملفات `supabase/` واختبارات `supabase-live.test.ts` إلى `examples/optional-supabase-mode/` مع توثيق صريح بعدم تكافئها الأمني أو الوظيفي مع المسار الرسمي.

### 4. الأثر والخطوات اللاحقة (Consequences & Follow-up)
- **إيجابي:** توحيد المسار الأمني 100%؛ كل طلب مصادقة وحضور واستقبال وإدارة يمر حتمياً عبر طبقة E2EE وفحوصات WAF وRBAC دون أي مسار التفاف صامت.
- **متابعة مطلوبة (المهمة 02):** ترحيل التخزين الداخلي في `server.ts` من ملف JSON مشفّر (`attendance-db.enc`) إلى قاعدة بيانات علائقية حقيقية ذاتية الاستضافة (SQLite / PostgreSQL) لضمان القابلية للتوسع وتعدد العمال.
- **متابعة مطلوبة (المهمة 06):** تنظيف وتوحيد ما تبقى من مسميات `student_*` و`campus_*` في النماذج والأمثلة الأرشيفية.

---

## ADR-002: ترحيل تخزين خادم Express من ملف JSON المشفّر إلى SQLite WAL مع تشفير الأعمدة الحساسة

- **الحالة (Status):** مقبول ومُنفّذ (Accepted & Implemented)
- **التاريخ:** 2026-11-19
- **المهمة المرجعية:** `02-migrate-selfhosted-storage`

### 1. السياق (Context)
كان خادم `server.ts` يحمّل كامل حالة قاعدة البيانات في الذاكرة (`DatabaseState`) ويعيد تسلسلها وتشفيرها وكتابتها بالكامل في ملف واحد (`data/attendance-db.enc`) عند كل تسجيل حضور أو تحديث جلسة، ما يسبب تدهوراً خطياً مع نمو السجلات وغياب الفهارس العلائقية.

### 2. القرار (Decision)
1. اعتماد **`better-sqlite3`** في وضع **WAL (`PRAGMA journal_mode = WAL`, `synchronous = NORMAL`, `foreign_keys = ON`)** عبر ملف قاعدة بيانات محلي واحد (`data/attendance.db` بصلاحيات `0o600`).
2. تطبيق **تشفير AES-256-GCM على مستوى الأعمدة الحساسة فقط**: أسرار التشغيل (`auth_secret`, `kiosk_salt`, `ip_salt`, `signing_private_pem`) في `system_secrets`، وأسرار المصادقة الثنائية `users.mfa_secret_enc`، وبيانات المسافة الجغرافية `attendance_records.gps_meta_enc` (مع بقاء العمود النصي `distance_m` بقيمة `NULL`).
3. إضافة فهارس مخصصة (`idx_attendance_emp_date`, `idx_attendance_date`, `idx_attendance_emp_idempotency`) وإلغاء إعادة الكتابة الكاملة للقرص؛ كل عملية حضور (`/api/attendance/scan`) تنفّذ معاملة ذرية محدودة بالصفوف المتأثرة فقط.
4. توفير أداة هجرة آمنة (`scripts/migrate-json-db-to-sqlite.ts` / `npm run migrate:sqlite`) مع نسخ احتياطي تلقائي قبل الهجرة، مع ترحيل تلقائي عند أول إقلاع.
5. تحديد نطاق القياس صراحة في `docs/REQUIREMENTS.md` و`docs/DEPLOYMENT.md`: وضع Express + SQLite هو **Instance واحد فقط (Single-Node)**.

### 3. الأثر (Consequences)
- إزالة اختناق I/O الناتج عن إعادة كتابة كامل الملف؛ حقق اختبار `10,000` عملية كتابة حضور زمناً كلياً `~1.0s` دون تدهور خطي مع الحجم وبزمن استعلام مفهرس `< 1 ms`.
- الحفاظ على سهولة التشغيل الذاتي بدون خادم قاعدة بيانات خارجي (Zero external DB dependency).
