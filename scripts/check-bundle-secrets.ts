import fs from "node:fs";
import path from "node:path";

const FORBIDDEN_BUNDLE_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: "VITE_ secret env prefix", regex: /\bVITE_[A-Z0-9_]*(SECRET|KEY|PASSWORD|TOKEN|SALT)[A-Z0-9_]*\b/ },
  { label: "Assigned server secret DATA_ENCRYPTION_KEY", regex: /DATA_ENCRYPTION_KEY\s*[:=]\s*["'][0-9a-fA-F]{16,}/ },
  { label: "Assigned server secret TURNSTILE_SECRET_KEY", regex: /TURNSTILE_SECRET_KEY\s*[:=]\s*["']0x[A-Za-z0-9_-]{8,}/ },
  { label: "SUPABASE_SERVICE_ROLE_KEY", regex: /\bSUPABASE_SERVICE_ROLE_KEY\b/ },
  { label: "service_role", regex: /\bservice_role\b/ },
  { label: "KIOSK_DEVICE_SECRET_SALT", regex: /\bKIOSK_DEVICE_SECRET_SALT\b/ },
  { label: "IP_HASH_SALT", regex: /\bIP_HASH_SALT\b/ },
  { label: "PEM private key material", regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { label: "Demo password Admin@2026", regex: /Admin@2026/ },
  { label: "Demo password Emp@2026", regex: /Emp@2026/ },
  { label: "Demo password Kiosk@2026", regex: /Kiosk@2026/ },
  { label: "Demo Kiosk Secret KIOSK-HQ-2026", regex: /KIOSK-HQ-2026/ },
];

function collectDistFiles(dir: string, out: string[] = []): string[] {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectDistFiles(full, out);
    } else if (entry.isFile() && /\.(js|mjs|css|html)$/i.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

function main(): void {
  const distDir = path.resolve(process.cwd(), "dist");
  const files = collectDistFiles(distDir);
  if (files.length === 0) {
    throw new Error("dist/ build artifacts not found; run npm run build first.");
  }

  const findings: Array<{ file: string; issue: string }> = [];
  for (const file of files) {
    const content = fs.readFileSync(file, "utf8");
    for (const pat of FORBIDDEN_BUNDLE_PATTERNS) {
      if (pat.regex.test(content)) {
        findings.push({ file: path.relative(process.cwd(), file), issue: pat.label });
      }
    }
  }

  console.log(
    JSON.stringify(
      {
        ok: findings.length === 0,
        scanned_files: files.length,
        findings,
      },
      null,
      2,
    ),
  );

  if (findings.length > 0) {
    process.exit(1);
  }
}

main();
