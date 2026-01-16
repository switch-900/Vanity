import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { minify } from 'html-minifier-terser';

function buildCspForHtml(html) {
  // Hash all inline module scripts so we can avoid `unsafe-inline`.
  const hashes = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html))) {
    const attrs = m[1] || '';
    const body = m[2] || '';
    if (/\bsrc\s*=\s*"/i.test(attrs)) continue;
    if (!/\btype\s*=\s*"module"/i.test(attrs)) continue;

    // CSP hashes are over the exact script text content.
    const hash = crypto.createHash('sha256').update(body, 'utf8').digest('base64');
    hashes.push(`'sha256-${hash}'`);
  }

  // Keep this conservative: only allow what we need.
  // Note: opening the file as `file://` has inconsistent CSP handling across browsers.
  // When served over http(s), this provides meaningful protection.
  const scriptSrc = [`'self'`, ...hashes].join(' ');

  return [
    `default-src 'self'`,
    `base-uri 'none'`,
    `object-src 'none'`,
    `frame-ancestors 'none'`,
    `form-action 'none'`,
    `img-src 'self' data:`,
    // CSS is inline in our single-file build.
    `style-src 'self' 'unsafe-inline'`,
    // The app uses Blob-based module workers.
    `worker-src blob:`,
    // Wordlist fetch (optional): same-origin or ordinals.com
    `connect-src 'self' https://ordinals.com`,
    `script-src ${scriptSrc}`,
  ].join('; ');
}

function injectCspMetaIntoHead(html, csp) {
  if (!csp) return html;

  // If a CSP already exists, replace it.
  const existingRe = /<meta\s+http-equiv="Content-Security-Policy"\s+content="[\s\S]*?"\s*\/?>(\s*)/i;
  if (existingRe.test(html)) {
    return html.replace(existingRe, `<meta http-equiv="Content-Security-Policy" content="${csp}">$1`);
  }

  // Otherwise, inject right after <head>.
  return html.replace(/<head>/i, `<head><meta http-equiv="Content-Security-Policy" content="${csp}">`);
}

async function main() {
  const distDir = path.resolve('dist');
  const htmlPath = path.join(distDir, 'index.html');
  let html = await fs.readFile(htmlPath, 'utf8');

  // Remove any dev-only external scripts (e.g. CDN fallbacks).
  // The final dist HTML should remain fully self-contained and compatible with strict CSP.
  html = html.replace(/\s*<script\b[^>]*\bdata-dev-only\s*=\s*"true"[^>]*>(?:<\/script>)?/gi, '');
  html = html.replace(/\s*<script\b[^>]*\bsrc\s*=\s*"https:\/\/cdn\.jsdelivr\.net\/npm\/qr-creator\/dist\/qr-creator\.min\.js"[^>]*><\/script>/gi, '');

  // Remove any Vite-generated preload hints that would reference external files.
  // After inlining, we want *one* standalone HTML file with no external assets.
  html = html.replace(/\s*<link\s+rel="modulepreload"[^>]*>/g, '');
  html = html.replace(/\s*<link\s+rel="stylesheet"[^>]*href="\/?assets\/[^">]+"[^>]*>/g, '');

  // Inline all Vite-generated module scripts (if any). Some builds may already be fully inlined.
  const scriptRe = /<script\s+type="module"([^>]*?)\s+src="([^"]+)"([^>]*)><\/script>/g;
  html = await replaceAsync(html, scriptRe, async (_full, _pre, src, _post) => {
    const srcPath = path.join(distDir, src.replace(/^\//, ''));
    const js = await fs.readFile(srcPath, 'utf8');
    return `<script type="module">\n${js}\n</script>`;
  });

  // Safety: ensure there are no remaining asset references in HTML tags.
  html = html.replace(/\s*<script[^>]*src="\/?assets\/[^">]+"[^>]*><\/script>/g, '');
  html = html.replace(/\s*<link[^>]*href="\/?assets\/[^">]+"[^>]*>/g, '');

  const hasAssetsRef = /\b(?:src|href)="\/?assets\//.test(html);
  if (hasAssetsRef) {
    throw new Error('Build still contains /assets references after inlining.');
  }

  // Minify the final single-file HTML (also minifies inline JS/CSS).
  html = await minify(html, {
    collapseWhitespace: true,
    conservativeCollapse: false,
    removeComments: true,
    removeRedundantAttributes: true,
    removeEmptyAttributes: true,
    sortAttributes: true,
    sortClassName: true,
    minifyCSS: true,
    minifyJS: {
      module: true,
      compress: {
        drop_console: true,
        drop_debugger: true,
      },
      format: {
        comments: false,
      },
    },
    // IMPORTANT: keep type="module" (otherwise it becomes a classic script).
    removeScriptTypeAttributes: false,
  });

  // Add a strict CSP only in the final dist HTML (so Vite dev/HMR isn't impacted).
  const csp = buildCspForHtml(html);
  html = injectCspMetaIntoHead(html, csp);

  await fs.writeFile(htmlPath, html, 'utf8');

  // Remove assets folder (best-effort).
  const assetsDir = path.join(distDir, 'assets');
  await fs.rm(assetsDir, { recursive: true, force: true });
}

async function replaceAsync(str, re, asyncFn) {
  const matches = Array.from(str.matchAll(re));
  if (!matches.length) return str;

  let out = '';
  let lastIndex = 0;
  for (const m of matches) {
    out += str.slice(lastIndex, m.index);
    out += await asyncFn(...m);
    lastIndex = m.index + m[0].length;
  }
  out += str.slice(lastIndex);
  return out;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
