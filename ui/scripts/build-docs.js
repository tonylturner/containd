const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const repoRoot = path.join(__dirname, "..", "..");
const uiRoot = path.join(__dirname, "..");
const docsDir = path.join(repoRoot, "docs", "mkdocs");
const docsOutDir = path.join(uiRoot, "public", "docs");
const hashFile = path.join(docsOutDir, ".build-hash");

function collectFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  let out = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name); // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal -- entry.name comes from readdirSync on the current docs tree, not user-controlled input.
    if (entry.isDirectory()) {
      out = out.concat(collectFiles(full));
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

function buildHash() {
  const hasher = crypto.createHash("sha256");
  const inputs = [
    path.join(repoRoot, "docs", "mkdocs.yml"),
    path.join(repoRoot, "docs", "requirements-mkdocs.txt"),
    path.join(repoRoot, "linear-dashboard-cursor-rule.md"),
    ...collectFiles(docsDir),
  ].sort();
  for (const file of inputs) {
    if (!fs.existsSync(file)) continue;
    hasher.update(file);
    hasher.update("\0");
    hasher.update(fs.readFileSync(file));
    hasher.update("\0");
  }
  return hasher.digest("hex");
}

function readStoredHash() {
  if (!fs.existsSync(hashFile)) return "";
  try {
    return fs.readFileSync(hashFile, "utf8").trim();
  } catch {
    return "";
  }
}

function writeStoredHash(value) {
  fs.mkdirSync(docsOutDir, { recursive: true });
  fs.writeFileSync(hashFile, `${value}\n`, "utf8");
}

function runMkdocs() {
  const check = spawnSync("mkdocs", ["--version"], {
    cwd: uiRoot,
    stdio: "ignore",
  });
  if (check.status !== 0) {
    return null;
  }
  const result = spawnSync(
    "mkdocs",
    ["build", "-f", "../docs/mkdocs.yml", "-d", "./public/docs"],
    {
      cwd: uiRoot,
      stdio: "inherit",
    },
  );
  return result.status === 0;
}

if (process.env.CONTAIND_SKIP_DOCS === "1") {
  process.exit(0);
}

const currentHash = buildHash();
const previousHash = readStoredHash();
if (currentHash && currentHash === previousHash) {
  process.exit(0);
}

const ran = runMkdocs();
if (ran === true) {
  writeStoredHash(currentHash);
  process.exit(0);
}

const indexPath = path.join(docsOutDir, "index.html");
if (ran === null && fs.existsSync(indexPath)) {
  writeStoredHash(currentHash);
  process.exit(0);
}

if (ran === false) {
  console.error(
    "Docs build failed. Install MkDocs deps via `pip install -r docs/requirements-mkdocs.txt`.",
  );
  process.exit(1);
}
