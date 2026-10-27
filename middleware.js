import { next } from '@vercel/functions';

// Gate for Antone's Digest. The passcode lives in the DIGEST_PIN environment
// variable (Vercel project settings); it is never written into this repo.
// If DIGEST_PIN is missing the site stays closed.

export const config = { matcher: ['/:path*'] };

const COOKIE = 'hd_gate';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function same(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function readCookie(request, name) {
  const raw = request.headers.get('cookie') || '';
  const parts = raw.split(';');
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i].trim();
    if (p.indexOf(name + '=') === 0) return p.slice(name.length + 1);
  }
  return '';
}

const HEAD = {
  'content-type': 'text/html; charset=utf-8',
  'cache-control': 'no-store',
  'x-robots-tag': 'noindex, nofollow',
  'referrer-policy': 'no-referrer',
};

function page(message, status) {
  const note = message ? '<p class="err" role="alert">' + message + '</p>' : '';
  const html = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="robots" content="noindex,nofollow"><title>Antone’s Digest</title><style>' +
    ':root{--paper:#F4ECD8;--card:#FBF6E8;--ink:#241F17;--muted:#665D4B;--hair:#D6CAAE;--alert:#A8281F;color-scheme:light dark}' +
    '@media (prefers-color-scheme:dark){:root{--paper:#12100C;--card:#1C1913;--ink:#EFE7D4;--muted:#A89F8A;--hair:#353025;--alert:#FF8F85}}' +
    '*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--paper);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif}' +
    'main{width:min(380px,100%);background:var(--card);border:1px solid var(--hair);border-top:4px solid var(--ink);padding:22px 20px}' +
    'h1{margin:0 0 4px;font-size:26px;letter-spacing:-.02em}p{margin:0 0 14px;color:var(--muted);font-size:14px}' +
    'label{display:block;font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:4px}' +
    'input{width:100%;font:inherit;min-height:44px;padding:8px 10px;color:var(--ink);background:var(--paper);border:1px solid var(--hair);border-radius:4px}' +
    'button{margin-top:12px;width:100%;min-height:44px;font:inherit;font-weight:650;border-radius:4px;border:1px solid var(--ink);background:var(--ink);color:var(--paper);cursor:pointer}' +
    ':focus-visible{outline:3px solid #6C86E0;outline-offset:1px}.err{color:var(--alert);font-weight:650;margin:10px 0 0}' +
    '</style></head><body><main><h1>Antone’s Digest</h1><p>Private page. Enter your passcode.</p>' +
    '<form method="post" action="/" autocomplete="on"><label for="pin">Passcode</label>' +
    '<input id="pin" name="pin" type="password" autocomplete="current-password" autofocus required>' +
    '<button type="submit">Open</button>' + note + '</form></main></body></html>';
  return new Response(html, { status: status || 401, headers: HEAD });
}

export default async function middleware(request) {
  const pin = process.env.DIGEST_PIN;
  if (!pin) {
    return new Response('This page is not configured yet.', { status: 503, headers: HEAD });
  }
  const token = await sha256Hex('hd-gate|' + pin);

  if (same(readCookie(request, COOKIE), token)) return next();

  if (request.method === 'POST') {
    let given = '';
    try { given = String((await request.formData()).get('pin') || ''); } catch (e) { given = ''; }
    const ok = same(await sha256Hex('hd-gate|' + given), token);
    if (ok) {
      return new Response(null, {
        status: 303,
        headers: {
          location: '/',
          'cache-control': 'no-store',
          'set-cookie': COOKIE + '=' + token + '; Path=/; Max-Age=' + MAX_AGE + '; HttpOnly; Secure; SameSite=Strict',
        },
      });
    }
    await new Promise((r) => setTimeout(r, 1500));
    return page('That passcode did not match.', 401);
  }

  return page('', 401);
}
