# سجل التغييرات — Changelog (InSight / ان سايت)

جميع التغييرات الجوهرية في البنية والأمان والميزات تُوثّق في هذا الملف.

## [1.1.0-dev] - 2026-11-19

### الأمان والبنية المعمارية (Task 01 — ADR-001)
- **حسم ازدواجية الباك-إند**: اعتماد خادم Express (`server.ts`) وقناة التشفير التطبيقي (`ECDH P-256 + ECDSA P-256 + AES-256-GCM`) كمسار وحيد رسمي للنظام.
- **إزالة الكود الميت للوضع السحابي المزدوج**: حذف `src/lib/supabase.ts` وإزالة جميع فروع `isSupabaseConfigured` من `useAuth.tsx`، `attendanceService.ts`، `kioskService.ts`، و`AttendanceScannerPage.tsx`.
- **أرشفة ملفات Supabase الاختيارية**: نقل مجلد `supabase/` واختبارات `supabase-live.test.ts` إلى `examples/optional-supabase-mode/` مع توثيق الفروقات الأمنية والوظيفية الصريحة.
- **توثيق القرارات الأمنية والمعمارية**: إنشاء `docs/DECISIONS.md` وإضافة جدول مطابقة الميزات الأمنية في `docs/SECURITY.md`.
- **إصلاحات النقل والأوزان**: دعم ترويسات `X-Forwarded-Host` و`APP_URL` ضمن فحص CORS الصارم خلف الوكلاء العكسيين، وإكمال تعريفات أوزان خط `Tajarib Taweel` (`100`–`900`).

### التخزين وقابلية التوسع (Task 02 — ADR-002)
- **استبدال التخزين الكامل للذاكرة بـ SQLite WAL**: إنشاء طبقة `server/sqliteStore.ts` باستخدام `better-sqlite3` (`PRAGMA journal_mode = WAL`) مع تشفير **AES-256-GCM على مستوى الأعمدة الحساسة** (`system_secrets`، `mfa_secret_enc`، `gps_meta_enc`).
- **معاملات ذرية مفهرسة دون إعادة كتابة كاملة**: إزالة `writeEncryptedDb()` و`persistDatabase()` من `server.ts` واستبدالهما بمعاملات صفوف مستهدفة مع فهارس `(employee_id, attendance_date)` و`(attendance_date)`.
- **أداة الهجرة والنسخ الاحتياطي التلقائي**: إضافة `scripts/migrate-json-db-to-sqlite.ts` (`npm run migrate:sqlite`) + الهجرة التلقائية عند الإقلاع مع إنشاء نسخة احتياطية `.bak-*` من `attendance-db.enc`.
- **اختبارات الأداء وحدود القياس**: إضافة `tests/storage/sqlite-storage.test.ts` (اختبار هجرة + اختبار أداء `10,000` سجل) وتوثيق النتائج في `docs/DATABASE.md` وتوثيق حد التشغيل على **Instance واحد فقط (Single-Node)** في `docs/REQUIREMENTS.md` و`docs/DEPLOYMENT.md`.

### تقوية خط التكامل المستمر والأمان الآلي (Task 03 — DevSecOps)
- **فحص الثغرات والتراخيص تلقائياً**: اعتماد `package-lock.json` وتحديث `esbuild` (`^0.28.0`) لتوافق Vite 8، وإضافة بوابة `npm audit --audit-level=high` الملزمة + فحص التراخيص (`scripts/check-licenses.ts`) + فحص تسرب الأسرار من حزم الإنتاج (`scripts/check-bundle-secrets.ts`) في `.github/workflows/ci.yml`.
- **فحص الأسرار والتحليل الثابت SAST**: إضافة وظيفة `secret-scan` عبر `gitleaks` مع `.gitleaks.toml` (تستثني `.env.example` فقط) ووظيفة `codeql-sast` عبر `.github/codeql/codeql-config.yml` لفحص `server.ts` والملفات الحساسة.
- **توليد SBOM والتحديثات التلقائية**: توليد CycloneDX SBOM (`sbom.cdx.json`) ورفعه كـ Artifact على `main`، وإضافة `.github/dependabot.yml` أسبوعياً لحزم npm و GitHub Actions، ومواءمة `docs/DEPLOYMENT.md` مع التشغيل الآلي في CI.
