import fs from "node:fs";
import path from "node:path";

const DISALLOWED_LICENSE_PATTERNS = [
  /\bAGPL\b/i,
  /\bGPL\b/i,
  /\bSSPL\b/i,
  /\bBUSL\b/i,
  /\bWTFPL\b/i,
  /\bUNLICENSED\b/i,
];

function collectPackageJsonPaths(rootDir: string, out: string[] = []): string[] {
  if (!fs.existsSync(rootDir)) return out;
  for (const entry of fs.readdirSync(rootDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    if (entry.name === ".bin") continue;
    const fullDir = path.join(rootDir, entry.name);
    if (entry.name.startsWith("@")) {
      collectPackageJsonPaths(fullDir, out);
      continue;
    }
    const pkgPath = path.join(fullDir, "package.json");
    if (fs.existsSync(pkgPath)) {
      out.push(pkgPath);
    }
    const nestedNodeModules = path.join(fullDir, "node_modules");
    if (fs.existsSync(nestedNodeModules)) {
      collectPackageJsonPaths(nestedNodeModules, out);
    }
  }
  return out;
}

function extractLicense(pkg: Record<string, unknown>): string {
  if (typeof pkg.license === "string" && pkg.license.trim().length > 0) {
    return pkg.license.trim();
  }
  if (pkg.license && typeof pkg.license === "object" && "type" in pkg.license) {
    return String((pkg.license as { type?: unknown }).type ?? "").trim();
  }
  if (Array.isArray(pkg.licenses)) {
    return pkg.licenses
      .map((l) => (typeof l === "string" ? l : String((l as { type?: unknown })?.type ?? "")))
      .filter(Boolean)
      .join(" OR ");
  }
  return "UNKNOWN";
}

function main(): void {
  const nodeModulesDir = path.resolve(process.cwd(), "node_modules");
  const pkgPaths = collectPackageJsonPaths(nodeModulesDir);
  if (pkgPaths.length === 0) {
    throw new Error("node_modules not found; run npm ci before checking licenses.");
  }

  const violations: Array<{ name: string; version: string; license: string }> = [];
  const summary: Record<string, number> = {};

  for (const pkgPath of pkgPaths) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as Record<string, unknown>;
    const name = String(pkg.name ?? path.basename(path.dirname(pkgPath)));
    const version = String(pkg.version ?? "0.0.0");
    const license = extractLicense(pkg);
    summary[license] = (summary[license] ?? 0) + 1;

    if (DISALLOWED_LICENSE_PATTERNS.some((pat) => pat.test(license))) {
      violations.push({ name, version, license });
    }
  }

  console.log(
    JSON.stringify(
      {
        ok: violations.length === 0,
        scanned_packages: pkgPaths.length,
        licenses: summary,
        violations,
      },
      null,
      2,
    ),
  );

  if (violations.length > 0) {
    process.exit(1);
  }
}

main();
