const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { test } = require("node:test");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "containd-docs-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const scripts = path.join(root, "ui", "scripts");
  const output = path.join(root, "ui", "public", "docs");
  const bin = path.join(root, "bin");
  fs.mkdirSync(scripts, { recursive: true });
  fs.mkdirSync(output, { recursive: true });
  fs.mkdirSync(bin);
  const script = path.join(scripts, "build-docs.js");
  fs.copyFileSync(path.join(__dirname, "build-docs.js"), script);
  return {
    hash: path.join(output, ".build-hash"),
    index: path.join(output, "index.html"),
    run(skip = false) {
      return spawnSync(process.execPath, [script], {
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: bin,
          CONTAIND_SKIP_DOCS: skip ? "1" : "",
        },
      });
    },
    mkdocs(body) {
      fs.writeFileSync(
        path.join(bin, "mkdocs"),
        `#!${process.execPath}\n${body}\n`,
        { mode: 0o755 },
      );
    },
  };
}

test("missing MkDocs fails without stamping a stale index", (t) => {
  const f = fixture(t);
  fs.writeFileSync(f.index, "stale");
  fs.writeFileSync(f.hash, "old-hash\n");
  const result = f.run();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /MkDocs must be on PATH/);
  assert.equal(fs.readFileSync(f.hash, "utf8"), "old-hash\n");
  assert.equal(fs.readFileSync(f.index, "utf8"), "stale");
});

test("missing MkDocs fails when no index exists", (t) => {
  const f = fixture(t);
  assert.equal(f.run().status, 1);
  assert.equal(fs.existsSync(f.hash), false);
});

test("skip neither creates nor updates the hash", (t) => {
  const f = fixture(t);
  assert.equal(f.run(true).status, 0);
  assert.equal(fs.existsSync(f.hash), false);
  fs.writeFileSync(f.hash, "existing\n");
  assert.equal(f.run(true).status, 0);
  assert.equal(fs.readFileSync(f.hash, "utf8"), "existing\n");
});

test("successful generation stamps the hash and default always builds", (t) => {
  const f = fixture(t);
  f.mkdocs(`
const fs = require("node:fs");
const path = require("node:path");
const out = process.argv[process.argv.indexOf("-d") + 1];
fs.writeFileSync(path.join(out, "index.html"), "generated");
`);
  assert.equal(f.run().status, 0);
  assert.match(fs.readFileSync(f.hash, "utf8"), /^[a-f0-9]{64}\n$/);
  assert.equal(fs.readFileSync(f.index, "utf8"), "generated");
  // A matching stamp must not hide a missing generator.
  f.mkdocs("process.exit(1);");
  assert.equal(f.run().status, 1);
});

test("failed generation never stamps existing output", (t) => {
  const f = fixture(t);
  fs.writeFileSync(f.index, "stale");
  f.mkdocs("process.exit(1);");
  assert.equal(f.run().status, 1);
  assert.equal(fs.existsSync(f.hash), false);
});

test("successful command without an index is not a docs build", (t) => {
  const f = fixture(t);
  f.mkdocs("process.exit(0);");
  assert.equal(f.run().status, 1);
  assert.equal(fs.existsSync(f.hash), false);
});
