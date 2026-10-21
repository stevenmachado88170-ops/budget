'use strict';
// Serveur du budget : aucun paquet npm requis (Node 18+).
// Profils : node server.js adduser <identifiant> [Nom affiché]
const http = require('http'), fs = require('fs'), path = require('path');
const crypto = require('crypto'), readline = require('readline'), net = require('net'), tls = require('tls');
const EMAIL = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;
const PORT = +process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = path.join(__dirname, 'public');
const F = { data: path.join(DIR, 'budget.json'), users: path.join(DIR, 'users.json'), resets: path.join(DIR, 'resets.json'), key: path.join(DIR, 'secret.key') };
fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });

const readJSON = (p, d) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return d; } };
const writeJSON = (p, o) => { const t = p + '.tmp'; fs.writeFileSync(t, JSON.stringify(o), { mode: 0o600 }); fs.renameSync(t, p); };
const users = () => { const u = readJSON(F.users, null); return u && u.users ? u : { order: [], users: {} }; };
const hashPw = (pw, salt) => crypto.scryptSync(String(pw), salt, 32).toString('hex');

const cmd = process.argv[2];
if (cmd === 'adduser' || cmd === 'passwd' || cmd === 'setemail') cli(); else main();

function cli() {
  const id = (process.argv[3] || '').toLowerCase(), name = process.argv[4];
  if (!/^[a-z0-9_-]{1,20}$/.test(id)) { console.error('Usage : node server.js adduser <identifiant> [Nom affiché] [e-mail]'); process.exit(1); }
  if (cmd === 'setemail') {
    const U = users(), e = process.argv[4] || '';
    if (!U.users[id] || !EMAIL.test(e)) { console.error('Usage : node server.js setemail <identifiant existant> <adresse e-mail>'); process.exit(1); }
    U.users[id].email = e.toLowerCase(); writeJSON(F.users, U);
    console.log('Adresse enregistrée pour « ' + id + ' ».'); process.exit(0);
  }
  const ask = q => new Promise(res => {
    if (process.env.BUDGET_PASSWORD) return res(process.env.BUDGET_PASSWORD);
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl.question(q, a => { rl.close(); process.stdout.write('\n'); res(a); });
    rl._writeToOutput = s => rl.output.write(s.includes('\n') ? s : '*');
  });
  (async () => {
    const p1 = await ask('Mot de passe (8 caractères min.) : ');
    if (p1.length < 8) { console.error('Trop court.'); process.exit(1); }
    const p2 = process.env.BUDGET_PASSWORD ? p1 : await ask('Confirmer : ');
    if (p1 !== p2) { console.error('Les deux saisies sont différentes.'); process.exit(1); }
    const U = users(), salt = crypto.randomBytes(16).toString('hex'), old = U.users[id];
    const em = process.argv[5];
    U.users[id] = { name: name || (old && old.name) || id, salt, hash: hashPw(p1, salt), email: EMAIL.test(em || '') ? em.toLowerCase() : (old && old.email) };
    if (!U.order.includes(id)) U.order.push(id);
    writeJSON(F.users, U);
    console.log('Profil « ' + id + ' » enregistré' + (U.order[0] === id ? ' (propriétaire des données existantes).' : '.'));
    process.exit(0);
  })();
}

// Envoi d'e-mail (SMTP) sans dépendance : TLS implicite (465) ou STARTTLS (587).
function smtp(to, subject, text) {
  return new Promise((resolve, reject) => {
    const host = process.env.SMTP_HOST, port = +process.env.SMTP_PORT || 587;
    const user = process.env.SMTP_USER, pass = process.env.SMTP_PASS, from = process.env.SMTP_FROM || user;
    const secure = port === 465 || process.env.SMTP_SECURE === '1';
    if (!host || !from) return reject(new Error('SMTP non configuré'));
    if (!EMAIL.test(to)) return reject(new Error('adresse invalide'));
    const addr = (/<([^>]+)>/.exec(from) || [])[1] || from;
    const mime = ['From: ' + String(from).replace(/[\r\n]+/g, ' '), 'To: ' + to,
      'Subject: =?UTF-8?B?' + Buffer.from(subject).toString('base64') + '?=',
      'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '',
      Buffer.from(text).toString('base64').replace(/.{1,76}/g, '$&\r\n')].join('\r\n');
    let sock, buf = '', step = 'greet', finished = false;
    const end = e => { if (finished) return; finished = true; try { sock.destroy(); } catch (x) {} e ? reject(e) : resolve(); };
    const send = l => sock.write(l + '\r\n');
    const afterHello = () => {
      if (user) { step = 'auth'; send('AUTH PLAIN ' + Buffer.from('\0' + user + '\0' + pass).toString('base64')); }
      else { step = 'from'; send('MAIL FROM:<' + addr + '>'); }
    };
    const handle = (code, line) => {
      const want = { greet: 220, ehlo: 250, starttls: 220, ehlo2: 250, auth: 235, from: 250, rcpt: 250, data: 354, body: 250 }[step];
      if (code !== want) return end(new Error('SMTP ' + step + ' : ' + line));
      if (step === 'greet') { step = 'ehlo'; send('EHLO budget.local'); }
      else if (step === 'ehlo') { if (secure) afterHello(); else { step = 'starttls'; send('STARTTLS'); } }
      else if (step === 'starttls') {
        const raw = sock; raw.removeAllListeners('data'); buf = '';
        sock = tls.connect({ socket: raw, servername: host }, () => { step = 'ehlo2'; send('EHLO budget.local'); });
        attach();
      }
      else if (step === 'ehlo2') afterHello();
      else if (step === 'auth') { step = 'from'; send('MAIL FROM:<' + addr + '>'); }
      else if (step === 'from') { step = 'rcpt'; send('RCPT TO:<' + to + '>'); }
      else if (step === 'rcpt') { step = 'data'; send('DATA'); }
      else if (step === 'data') { step = 'body'; sock.write(mime + '\r\n.\r\n'); }
      else if (step === 'body') { send('QUIT'); end(); }
    };
    const attach = () => {
      sock.setTimeout(20000, () => end(new Error('délai dépassé')));
      sock.on('error', end);
      sock.on('data', d => {
        buf += d.toString('utf8'); let i;
        while ((i = buf.indexOf('\r\n')) >= 0) {
          const line = buf.slice(0, i); buf = buf.slice(i + 2);
          if (/^\d{3}( |$)/.test(line)) handle(+line.slice(0, 3), line);
        }
      });
    };
    sock = secure ? tls.connect({ host, port, servername: host }) : net.connect({ host, port });
    attach();
  });
}

function main() {
  const BASE = (process.env.BASE_URL || '').replace(/\/+$/, '');
  const lim = (max, ms) => { const m = new Map(); return k => { const a = (m.get(k) || []).filter(t => Date.now() - t < ms); a.push(Date.now()); m.set(k, a); return a.length > max; }; };
  const forgotLim = lim(5, 36e5), resetLim = lim(10, 6e5);
  let secret;
  try { secret = fs.readFileSync(F.key, 'utf8'); }
  catch (e) { secret = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(F.key, secret, { mode: 0o600 }); }

  let db = readJSON(F.data, { v: 2, rev: 0, shared: null, personal: {} });
  const persist = () => writeJSON(F.data, db);
  const strip = s => { const o = Object.assign({}, s); delete o.ca; delete o.cd; return o; };
  // Ancien format (une seule personne) -> données du premier profil créé.
  const migrate = () => {
    if (db.v) return;
    if (db.state) {
      const U = users(); if (!U.order.length) return;
      const s = db.state;
      db = { v: 2, rev: db.rev || 1, shared: { ca: s.ca || [], cd: s.cd || [] }, personal: { [U.order[0]]: strip(s) } };
    } else db = { v: 2, rev: 0, shared: null, personal: {} };
    persist();
  };

  const send = (res, code, body, type = 'application/json') => {
    res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' });
    res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
  };
  const sign = (id, exp, u) => crypto.createHmac('sha256', secret).update(id + '.' + exp + '.' + u.hash.slice(0, 16)).digest('hex');
  const cookie = (id, u, secure) => {
    const exp = Date.now() + 90 * 864e5;
    return 'sid=' + id + '.' + exp + '.' + sign(id, exp, u) + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + 90 * 86400 + (secure ? '; Secure' : '');
  };
  const auth = req => {
    const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || ''); if (!m) return null;
    const [id, exp, sig] = m[1].split('.'), u = users().users[id];
    if (!u || !sig || +exp < Date.now()) return null;
    const ok = sign(id, exp, u);
    if (sig.length !== ok.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(ok))) return null;
    return { id, name: u.name };
  };
  const fails = new Map();
  const ip = req => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const blocked = k => { const a = (fails.get(k) || []).filter(t => Date.now() - t < 6e5); fails.set(k, a); return a.length >= 8; };
  const body = (req, cb) => {
    let b = ''; req.on('data', c => { b += c; if (b.length > 1e6) req.destroy(); });
    req.on('end', () => { try { cb(JSON.parse(b)); } catch (e) { cb(null); } });
  };

  http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    const secure = req.headers['x-forwarded-proto'] === 'https';

    if (p === '/api/login' && req.method === 'POST') return body(req, b => {
      const k = ip(req);
      if (blocked(k)) return send(res, 429, { error: 'Trop d’essais, réessaie dans quelques minutes.' });
      const id = String(b && b.id || '').toLowerCase(), u = users().users[id];
      let ok = false;
      if (u && b && typeof b.password === 'string') {
        const h = Buffer.from(hashPw(b.password, u.salt), 'hex'), g = Buffer.from(u.hash, 'hex');
        ok = h.length === g.length && crypto.timingSafeEqual(h, g);
      }
      if (!ok) { fails.set(k, (fails.get(k) || []).concat(Date.now())); return send(res, 401, { error: 'Identifiant ou mot de passe incorrect.' }); }
      res.setHeader('Set-Cookie', cookie(id, u, secure));
      send(res, 200, { ok: true });
    });
    if (p === '/api/forgot' && req.method === 'POST') return body(req, b => {
      send(res, 200, { ok: true });               // même réponse dans tous les cas
      if (forgotLim(ip(req)) || !BASE) { if (!BASE) console.error('BASE_URL non défini : aucun lien envoyé.'); return; }
      const q = String(b && b.id || '').trim().toLowerCase(), U = users();
      const id = U.users[q] ? q : Object.keys(U.users).find(k => U.users[k].email === q);
      const u = id && U.users[id]; if (!u || !u.email) return;
      const R = readJSON(F.resets, {}), now = Date.now();
      const sent = ((R[id] || {}).sent || []).filter(t => now - t < 36e5);
      if (sent.length >= 3) return;
      const sec = crypto.randomBytes(32).toString('base64url');
      R[id] = { h: crypto.createHash('sha256').update(sec).digest('hex'), exp: now + 18e5, sent: sent.concat(now) };
      writeJSON(F.resets, R);
      const link = BASE + '/reset.html#' + id + '.' + sec;
      const text = 'Bonjour ' + u.name + ',\n\nTu as demandé à changer ton mot de passe du budget. Ouvre ce lien (valable 30 minutes, utilisable une seule fois) :\n\n' + link + '\n\nSi ce n’est pas toi, ignore ce message : ton mot de passe reste inchangé.\n';
      if (!process.env.SMTP_HOST) return console.log('SMTP non configuré. Lien pour ' + id + ' : ' + link);
      smtp(u.email, 'Budget : réinitialisation de ton mot de passe', text).catch(e => console.error('Envoi e-mail impossible :', e.message));
    });
    if (p === '/api/reset' && req.method === 'POST') return body(req, b => {
      if (resetLim(ip(req))) return send(res, 429, { error: 'Trop d’essais, réessaie plus tard.' });
      const t = String(b && b.token || ''), pw = String(b && b.password || ''), i = t.indexOf('.');
      const id = t.slice(0, i), sec = t.slice(i + 1), R = readJSON(F.resets, {}), r = R[id];
      const bad = () => send(res, 400, { error: 'Lien invalide ou expiré. Refais une demande.' });
      if (i < 1 || !r || !r.h || r.exp < Date.now()) return bad();
      const a = Buffer.from(crypto.createHash('sha256').update(sec).digest('hex')), c = Buffer.from(r.h);
      if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) return bad();
      if (pw.length < 8) return send(res, 400, { error: '8 caractères minimum.' });
      const U = users(), u = U.users[id]; if (!u) return bad();
      u.salt = crypto.randomBytes(16).toString('hex'); u.hash = hashPw(pw, u.salt); writeJSON(F.users, U);
      R[id] = { h: '', exp: 0, sent: r.sent || [] }; writeJSON(F.resets, R);   // lien à usage unique
      send(res, 200, { ok: true });
      if (u.email && process.env.SMTP_HOST) smtp(u.email, 'Budget : mot de passe modifié', 'Bonjour ' + u.name + ',\n\nTon mot de passe du budget vient d’être modifié. Si ce n’est pas toi, préviens l’administrateur.\n').catch(() => {});
    });
    if (p === '/api/logout' && req.method === 'POST') {
      res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
      return send(res, 200, { ok: true });
    }
    if (p.startsWith('/api/')) {
      const me = auth(req); if (!me) return send(res, 401, { error: 'auth' });
      migrate();
      if (p === '/api/state') {
        const owner = users().order[0] === me.id;
        if (req.method === 'GET') {
          const pe = db.personal[me.id], sh = db.shared;
          return send(res, 200, {
            rev: db.rev, me: { id: me.id, name: me.name, owner }, shared: sh,
            state: pe ? Object.assign({}, pe, { ca: sh ? sh.ca : [], cd: sh ? sh.cd : [] }) : null
          });
        }
        if (req.method === 'PUT') return body(req, s => {
          if (!s || !Array.isArray(s.fixes) || !Array.isArray(s.ca) || !Array.isArray(s.cd)) return send(res, 400, { error: 'invalid' });
          db.personal[me.id] = strip(s); db.shared = { ca: s.ca, cd: s.cd }; db.rev++;
          persist(); send(res, 200, { rev: db.rev });
        });
      }
      return send(res, 404, { error: 'not found' });
    }
    if (req.method !== 'GET') return send(res, 405, { error: 'method' });
    const file = p === '/' ? 'index.html' : decodeURIComponent(p).replace(/^\/+/, '');
    if (file === 'index.html' && !auth(req)) { res.writeHead(302, { Location: 'login.html' }); return res.end(); }
    const full = path.join(PUB, file);
    if (!full.startsWith(PUB + path.sep)) return send(res, 403, 'forbidden', 'text/plain');
    fs.readFile(full, (e, d) => e
      ? send(res, 404, 'not found', 'text/plain')
      : send(res, 200, d, full.endsWith('.html') ? 'text/html; charset=utf-8' : 'application/octet-stream'));
  }).listen(PORT, HOST, () => console.log('Budget sur http://' + HOST + ':' + PORT));
}
