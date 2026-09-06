/**
 * Реле: GitHub Pages → Cloudflare Worker → твій Telegram.
 *
 * Змінні оточення воркера (Settings → Variables, обидві як Secret):
 *   BOT_TOKEN — токен від @BotFather
 *   MY_CHAT   — твій chat_id (напиши @userinfobot, щоб дізнатись)
 *
 * Деплой без консолі:
 *   dash.cloudflare.com → Workers & Pages → Create → Worker
 *   → Deploy → Edit code → встав цей файл → Deploy
 */

const ORIGIN = 'https://love-vibes.github.io';   // ← твій Pages-домен

const cors = {
  'Access-Control-Allow-Origin': ORIGIN,
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type'
};

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    if (req.method !== 'POST')    return new Response('nope', { status: 405, headers: cors });

    let body;
    try { body = await req.json(); }
    catch { return new Response('bad json', { status: 400, headers: cors }); }

    const text = String(body.text || '').slice(0, 3500);
    if (!text) return new Response('empty', { status: 400, headers: cors });

    // приймаємо план лише від справжньої Telegram-сесії (будь-якої)
    const v = await verify(body.initData, env.BOT_TOKEN);
    if (!v.ok || !v.user) {
      return new Response('unauthorized', { status: 401, headers: cors });
    }

    const who = `\n\n👤 ${v.user.first_name || ''} ${v.user.last_name || ''}`.trimEnd()
        + (v.user.username ? ` (@${v.user.username})` : '');

    const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: env.MY_CHAT, text: text + who })
    });

    return new Response(r.ok ? 'ok' : 'tg failed',
                        { status: r.ok ? 200 : 502, headers: cors });
  }
};

/** Перевірка підпису initData (HMAC-SHA256, схема Telegram) */
async function verify(initData, token) {
  if (!initData) return { ok: false };
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    params.delete('hash');

    const check = [...params.entries()]
      .sort(([a], [b]) => a < b ? -1 : 1)
      .map(([k, val]) => `${k}=${val}`)
      .join('\n');

    const enc = new TextEncoder();
    const secretKey = await crypto.subtle.importKey(
      'raw', enc.encode('WebAppData'),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const secret = await crypto.subtle.sign('HMAC', secretKey, enc.encode(token));

    const dataKey = await crypto.subtle.importKey(
      'raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', dataKey, enc.encode(check));

    const hex = [...new Uint8Array(sig)]
      .map(b => b.toString(16).padStart(2, '0')).join('');

    if (hex !== hash) return { ok: false };

    // не приймаємо старі initData (захист від повторного відтворення)
    const age = Date.now() / 1000 - Number(params.get('auth_date') || 0);
    if (age > 86400) return { ok: false };

    return { ok: true, user: JSON.parse(params.get('user') || 'null') };
  } catch {
    return { ok: false };
  }
}
