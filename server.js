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
const F = { data: path.join(DIR, 'budget.json'), users: path.join(DIR, 'users.json'), resets: path.join(DIR, 'resets.json'), settings: path.join(DIR, 'settings.json'), key: path.join(DIR, 'secret.key') };
fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });

let secret;
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

const skey = () => crypto.createHash('sha256').update('smtp:' + secret).digest();
const encPw = t => {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', skey(), iv);
  const ct = Buffer.concat([c.update(t, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), ct].map(x => x.toString('base64')).join('.');
};
const decPw = t => {
  const [iv, tag, ct] = t.split('.').map(x => Buffer.from(x, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', skey(), iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
};
// Réglages e-mail : fichier settings.json d'abord, variables d'environnement en secours.
function smtpConf() {
  const s = readJSON(F.settings, {}), m = s.smtp || {};
  let pass = process.env.SMTP_PASS;
  if (m.pass) { try { pass = decPw(m.pass); } catch (e) { pass = undefined; } }
  const port = +(m.port || process.env.SMTP_PORT) || 587;
  const user = m.host ? m.user : process.env.SMTP_USER;
  return {
    host: m.host || process.env.SMTP_HOST, port, user, pass,
    secure: m.host ? !!m.secure : process.env.SMTP_SECURE === '1',
    from: m.host ? (m.from || m.user) : (process.env.SMTP_FROM || process.env.SMTP_USER),
    base: String(s.baseUrl || process.env.BASE_URL || '').replace(/\/+$/, '')
  };
}

// Envoi d'e-mail (SMTP) sans dépendance : TLS implicite (465) ou STARTTLS (587).
function smtp(to, subject, text) {
  return new Promise((resolve, reject) => {
    const c = smtpConf(), host = c.host, port = c.port, user = c.user, pass = c.pass, from = c.from;
    const secure = port === 465 || c.secure;
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
  const forgotLim = lim(5, 36e5), resetLim = lim(10, 6e5), pwLim = lim(15, 6e5), testLim = lim(5, 6e5);
  const pub = (id, u) => ({ id, name: u.name, avatar: u.avatar || '', theme: u.theme || 'auto', accent: u.accent || '' });
  const pwOk = (u, pw) => {
    if (!u || typeof pw !== 'string') return false;
    const h = Buffer.from(hashPw(pw, u.salt), 'hex'), g = Buffer.from(u.hash, 'hex');
    return h.length === g.length && crypto.timingSafeEqual(h, g);
  };
  // Crée un lien de réinitialisation et l'envoie par e-mail. Renvoie un statut.
  const issueReset = async (id, u) => {
    const C = smtpConf();
    if (!u.email) return 'no-email';
    if (!C.base) { console.error('Adresse publique non définie : aucun lien envoyé.'); return 'no-base'; }
    const R = readJSON(F.resets, {}), now = Date.now();
    const sent = ((R[id] || {}).sent || []).filter(t => now - t < 36e5);
    if (sent.length >= 3) return 'limited';
    const sec = crypto.randomBytes(32).toString('base64url');
    R[id] = { h: crypto.createHash('sha256').update(sec).digest('hex'), exp: now + 18e5, sent: sent.concat(now) };
    writeJSON(F.resets, R);
    const link = C.base + '/reset.html#' + id + '.' + sec;
    const text = 'Bonjour ' + u.name + ',\n\nTu as demandé à changer ton mot de passe du budget. Ouvre ce lien (valable 30 minutes, utilisable une seule fois) :\n\n' + link + '\n\nSi ce n’est pas toi, ignore ce message : ton mot de passe reste inchangé.\n';
    if (!C.host) { console.log('SMTP non configuré. Lien pour ' + id + ' : ' + link); return 'logged'; }
    try { await smtp(u.email, 'Budget : réinitialisation de ton mot de passe', text); }
    catch (e) { console.error('Envoi e-mail impossible :', e.message); return 'error: ' + e.message; }
    return 'sent';
  };
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
      if (forgotLim(ip(req))) return;
      const q = String(b && b.id || '').trim().toLowerCase(), U = users();
      const id = U.users[q] ? q : Object.keys(U.users).find(k => U.users[k].email === q);
      if (id) issueReset(id, U.users[id]);
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
      if (u.email && smtpConf().host) smtp(u.email, 'Budget : mot de passe modifié', 'Bonjour ' + u.name + ',\n\nTon mot de passe du budget vient d’être modifié. Si ce n’est pas toi, préviens l’administrateur.\n').catch(() => {});
    });
    if (p === '/api/logout' && req.method === 'POST') {
      res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
      return send(res, 200, { ok: true });
    }
    if (p.startsWith('/api/')) {
      const me = auth(req); if (!me) return send(res, 401, { error: 'auth' });
      migrate();
      if (p === '/api/settings' && req.method === 'GET') {
        const U = users(), admin = U.order[0] === me.id, S = readJSON(F.settings, {}), C = smtpConf();
        return send(res, 200, {
          me: Object.assign(pub(me.id, U.users[me.id]), { email: U.users[me.id].email || '', admin }),
          users: U.order.map(i => Object.assign(pub(i, U.users[i]), { admin: i === U.order[0], email: admin ? (U.users[i].email || '') : '' })),
          smtp: admin ? { host: C.host || '', port: C.port, secure: !!C.secure, user: C.user || '', from: C.from || '', hasPass: !!C.pass, base: C.base, fromEnv: !((S.smtp || {}).host) && !!process.env.SMTP_HOST } : null
        });
      }
      if (p === '/api/profile' && req.method === 'PUT') return body(req, b => {
        b = b || {}; const U = users(), u = U.users[me.id];
        const name = String(b.name || '').trim().slice(0, 30); if (name) u.name = name;
        if (['auto', 'light', 'dark'].includes(b.theme)) u.theme = b.theme;
        if (b.accent === '') delete u.accent; else if (/^#[0-9a-f]{6}$/i.test(b.accent || '')) u.accent = b.accent;
        if (typeof b.avatar === 'string') {
          if (b.avatar === '') delete u.avatar;
          else if (/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+\/=]+$/.test(b.avatar) && b.avatar.length < 100000) u.avatar = b.avatar;
          else return send(res, 400, { error: 'Image invalide ou trop lourde.' });
        }
        if (typeof b.email === 'string') {
          const e = b.email.trim().toLowerCase();
          if (e !== (u.email || '')) {
            if (e && !EMAIL.test(e)) return send(res, 400, { error: 'Adresse e-mail invalide.' });
            if (pwLim(me.id) || !pwOk(u, b.password)) return send(res, 403, { error: 'Mot de passe actuel requis pour changer l’adresse e-mail.' });
            if (e) u.email = e; else delete u.email;
          }
        }
        writeJSON(F.users, U); send(res, 200, { ok: true });
      });
      if (p === '/api/password' && req.method === 'POST') return body(req, b => {
        b = b || {}; const U = users(), u = U.users[me.id], pw = String(b.password || '');
        if (pwLim(me.id) || !pwOk(u, b.current)) return send(res, 403, { error: 'Mot de passe actuel incorrect.' });
        if (pw.length < 8) return send(res, 400, { error: '8 caractères minimum.' });
        u.salt = crypto.randomBytes(16).toString('hex'); u.hash = hashPw(pw, u.salt); writeJSON(F.users, U);
        res.setHeader('Set-Cookie', cookie(me.id, u, secure));   // les autres sessions sont déconnectées
        send(res, 200, { ok: true });
      });
      if (p.startsWith('/api/admin/')) {
        const U = users();
        if (U.order[0] !== me.id) return send(res, 403, { error: 'Réservé à l’administrateur.' });
        if (req.method !== 'POST') return send(res, 405, { error: 'method' });
        return body(req, b => {
          b = b || {};
          if (p === '/api/admin/smtp/test') {
            if (testLim(me.id)) return send(res, 429, { error: 'Trop d’essais.' });
            const u = U.users[me.id];
            if (!u.email) return send(res, 200, { ok: false, error: 'Ajoute d’abord ton adresse e-mail dans ton profil.' });
            return smtp(u.email, 'Budget : e-mail de test', 'Si tu lis ce message, l’envoi d’e-mails fonctionne.\n')
              .then(() => send(res, 200, { ok: true })).catch(e => send(res, 200, { ok: false, error: e.message }));
          }
          if (pwLim(me.id) || !pwOk(U.users[me.id], b.confirm)) return send(res, 403, { error: 'Mot de passe administrateur incorrect.' });
          if (p === '/api/admin/user') {
            const id = String(b.id || '').toLowerCase(), pw = String(b.password || '');
            const name = String(b.name || '').trim().slice(0, 30) || id, em = String(b.email || '').trim().toLowerCase();
            if (!/^[a-z0-9_-]{1,20}$/.test(id)) return send(res, 400, { error: 'Identifiant : minuscules, chiffres, - ou _ (20 maximum).' });
            if (U.users[id]) return send(res, 400, { error: 'Cet identifiant existe déjà.' });
            if (pw.length < 8) return send(res, 400, { error: 'Mot de passe : 8 caractères minimum.' });
            if (em && !EMAIL.test(em)) return send(res, 400, { error: 'Adresse e-mail invalide.' });
            const salt = crypto.randomBytes(16).toString('hex');
            U.users[id] = { name, salt, hash: hashPw(pw, salt) }; if (em) U.users[id].email = em;
            U.order.push(id); writeJSON(F.users, U); return send(res, 200, { ok: true });
          }
          if (p === '/api/admin/delete') {
            const id = String(b.id || '');
            if (id === me.id || !U.users[id]) return send(res, 400, { error: 'Suppression impossible.' });
            delete U.users[id]; U.order = U.order.filter(x => x !== id); writeJSON(F.users, U);
            delete db.personal[id]; persist();
            const R = readJSON(F.resets, {}); delete R[id]; writeJSON(F.resets, R);
            return send(res, 200, { ok: true });
          }
          if (p === '/api/admin/resetlink') {
            const id = String(b.id || ''), u = U.users[id];
            if (!u) return send(res, 400, { error: 'Profil inconnu.' });
            return issueReset(id, u).then(status => send(res, 200, { status }));
          }
          if (p === '/api/admin/smtp') {
            const S = readJSON(F.settings, {}), m = S.smtp || {}, host = String(b.host || '').trim();
            const port = Math.round(+b.port) || 587, base = String(b.base || '').trim().replace(/\/+$/, '');
            if (base && !/^https?:\/\/[^\s\/]+(\/\S*)?$/.test(base)) return send(res, 400, { error: 'Adresse publique invalide (ex. https://budget.exemple.fr).' });
            if (host && !/^[A-Za-z0-9.-]+$/.test(host)) return send(res, 400, { error: 'Nom de serveur SMTP invalide.' });
            if (port < 1 || port > 65535) return send(res, 400, { error: 'Port invalide.' });
            S.baseUrl = base;
            if (!host) delete S.smtp;
            else {
              const n = { host, port, secure: !!b.secure, user: String(b.user || '').trim(), from: String(b.from || '').trim() };
              if (typeof b.pass === 'string' && b.pass) n.pass = encPw(b.pass); else if (m.pass) n.pass = m.pass;
              S.smtp = n;
            }
            writeJSON(F.settings, S); return send(res, 200, { ok: true });
          }
          send(res, 404, { error: 'not found' });
        });
      }
      if (p === '/api/state') {
        const owner = users().order[0] === me.id;
        if (req.method === 'GET') {
          const pe = db.personal[me.id], sh = db.shared;
          return send(res, 200, {
            rev: db.rev, me: Object.assign(pub(me.id, users().users[me.id]), { owner }), shared: sh,
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
