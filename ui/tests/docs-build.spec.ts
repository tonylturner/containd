import { expect, test } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";

test("docs build writes into the UI export and regenerates on every build", () => {
  const repo = test.info().outputPath("repo");
  const ui = path.join(repo, "ui");
  const bin = path.join(repo, "bin");
  mkdirSync(path.join(ui, "scripts"), { recursive: true });
  mkdirSync(path.join(repo, "docs", "mkdocs"), { recursive: true });
  mkdirSync(bin);
  copyFileSync(path.join(__dirname, "../scripts/build-docs.js"), path.join(ui, "scripts/build-docs.js"));
  writeFileSync(path.join(repo, "docs", "mkdocs.yml"), "site_name: Test\n");
  const calls = path.join(repo, "build-calls");
  // MkDocs resolves a relative site_dir against its configuration directory,
  // not the child process cwd. Model that behavior without installing Python.
  writeFileSync(path.join(bin, "mkdocs"), `#!${process.execPath}
const fs = require("fs");
const path = require("path");
const args = process.argv.slice(2);
if (args[0] === "--version") process.exit(0);
const config = path.resolve(args[args.indexOf("-f") + 1]);
const output = path.resolve(path.dirname(config), args[args.indexOf("-d") + 1]);
fs.mkdirSync(output, { recursive: true });
fs.writeFileSync(path.join(output, "index.html"), "<h1>Test docs</h1>");
fs.appendFileSync(${JSON.stringify(calls)}, "built\\n");
`, { mode: 0o755 });

  const build = () => {
    const result = spawnSync(process.execPath, [path.join(ui, "scripts/build-docs.js")], {
      cwd: ui,
      env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`, CONTAIND_SKIP_DOCS: "0" },
      encoding: "utf8",
    });
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
  };
  const site = path.join(ui, "public", "docs", "index.html");
  build();
  expect(existsSync(site)).toBe(true);
  expect(existsSync(path.join(repo, "docs", "public"))).toBe(false);
  expect(readFileSync(calls, "utf8")).toBe("built\n");
  // Existing output never short-circuits generation.
  build();
  expect(readFileSync(calls, "utf8")).toBe("built\nbuilt\n");
  unlinkSync(site);
  build();
  expect(existsSync(site)).toBe(true);
  expect(readFileSync(calls, "utf8")).toBe("built\nbuilt\nbuilt\n");
});
