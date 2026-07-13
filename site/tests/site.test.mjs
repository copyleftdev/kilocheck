import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const html = await readFile(new URL("index.html", root), "utf8");
const css = await readFile(new URL("styles.css", root), "utf8");
const js = await readFile(new URL("app.js", root), "utf8");

test("page exposes one primary heading and core landmarks", () => {
  assert.equal((html.match(/<h1\b/g) || []).length, 1);
  for (const landmark of ["<header", "<main", "<nav", "<footer"]) assert.ok(html.includes(landmark));
  assert.ok(html.includes('href="#main"'));
  assert.ok(html.includes('aria-live="polite"'));
});

test("all local site references resolve", async () => {
  const refs = [...html.matchAll(/(?:src|href)="(?!https?:|#)([^"?]+)"/g)].map((match) => match[1]);
  for (const ref of refs) {
    const info = await stat(new URL(ref, root));
    assert.ok(info.isFile(), `${ref} must be a file`);
  }
});

test("hero image reserves dimensions and ships responsive WebP", () => {
  assert.match(html, /<img[^>]+width="1254"[^>]+height="1254"/);
  assert.ok(html.includes("kilocheck-bbs-640.webp"));
  assert.ok(html.includes("kilocheck-bbs.webp"));
});

test("animation uses a fixed arena and lifecycle gates", () => {
  assert.match(js, /static CAPACITY = 48/);
  assert.match(js, /new Float32Array/);
  assert.match(js, /new Uint8Array/);
  assert.match(js, /requestAnimationFrame/);
  assert.match(js, /cancelAnimationFrame/);
  assert.match(js, /visibilitychange/);
  assert.match(js, /IntersectionObserver/);
  assert.match(js, /prefers-reduced-motion/);
  assert.doesNotMatch(js, /setInterval\s*\(/);
});

test("motion and paint stay composited and bounded", () => {
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(css, /contain: layout paint/);
  assert.doesNotMatch(css, /background-clip:\s*text/);
  assert.doesNotMatch(css, /border-(?:left|right):\s*[2-9]/);
});

test("site shows the dogfoodable release and actual output shape", () => {
  assert.ok(html.includes("KiloCheck v0.2.0"));
  assert.ok(html.includes("Observed from the v0.2.0 engine"));
  assert.ok(html.includes('"observations"'));
  assert.ok(html.includes("zero network syscalls"));
  assert.ok(!html.includes("Illustrative future snapshot output"));
});
