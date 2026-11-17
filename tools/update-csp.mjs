// Re-pins the Content-Security-Policy in index.html to the exact inline scripts on the page.
// Run this after editing any inline script block (the links JSON block does NOT need it):
//   node tools/update-csp.mjs
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const file = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'index.html');
let html = fs.readFileSync(file, 'utf8');
const hashes = [];
const code = html.replace(/<!--[\s\S]*?-->/g, c => ' '.repeat(c.length)); // ignore commented-out text
for (const m of code.matchAll(/<script(\s[^>]*)?>([\s\S]*?)<\/script>/g)) {
  const attrs = m[1] || '';
  if (/\ssrc\s*=/.test(attrs)) continue;
  const type = (attrs.match(/type\s*=\s*"([^"]+)"/) || [])[1];
  if (type && !['module', 'importmap', 'text/javascript'].includes(type)) continue; // JSON data blocks never execute
  const body = m[2].replace(/\r\n?/g, '\n'); // browsers hash the newline-normalised text
  hashes.push(`'sha256-${crypto.createHash('sha256').update(body, 'utf8').digest('base64')}'`);
}
const before = html;
html = html.replace(/script-src 'self' https:\/\/cdn\.jsdelivr\.net[^;]*;/, `script-src 'self' https://cdn.jsdelivr.net ${hashes.join(' ')};`);
if (html === before && !before.includes(hashes.join(' '))) throw new Error('CSP meta tag not found');
fs.writeFileSync(file, html);
console.log(`CSP pinned to ${hashes.length} inline script(s).`);
