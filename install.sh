#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
TZ="${TZ:-America/Sao_Paulo}"
APP_DIR="/opt/whatsweb"
LOG_FILE="/var/log/whatsweb.log"
NODE_VERSION="${NODE_VERSION:-v20.20.2}"

log() {
  echo ">>> $*"
}

warn() {
  echo ">>> [AVISO] $*" >&2
}

die() {
  echo ">>> [ERRO] $*" >&2
  exit 1
}

cleanup_old_nodesource() {
  rm -f /etc/apt/sources.list.d/nodesource.list         /etc/apt/sources.list.d/nodesource.sources         /etc/apt/preferences.d/nodejs         /etc/apt/keyrings/nodesource.gpg         /usr/share/keyrings/nodesource.gpg         /usr/share/keyrings/nodesource.gpg.key         /etc/apt/trusted.gpg.d/nodesource.gpg || true
}

apt_repair() {
  dpkg --configure -a || true
  apt-get -f install -y || true
}

apt_update_safe() {
  if ! apt-get -o Acquire::Retries=3 update; then
    warn "apt update falhou na primeira tentativa; tentando reparar dependências e limpando NodeSource antigo..."
    apt_repair
    cleanup_old_nodesource
    apt-get -o Acquire::Retries=3 update
  fi
}

detect_node_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7) echo "armv7l" ;;
    *)
      die "Arquitetura não suportada automaticamente: $(uname -m)"
      ;;
  esac
}

install_node_official() {
  local arch tmpdir node_dir tarball url
  arch="$(detect_node_arch)"
  tmpdir="$(mktemp -d)"
  node_dir="/usr/local/lib/nodejs/node-${NODE_VERSION}-linux-${arch}"
  tarball="node-${NODE_VERSION}-linux-${arch}.tar.xz"
  url="https://nodejs.org/dist/${NODE_VERSION}/${tarball}"

  log "Instalando Node.js oficial ${NODE_VERSION} para arquitetura ${arch}..."
  rm -rf "${tmpdir}"
  mkdir -p "${tmpdir}" /usr/local/lib/nodejs
  curl -fsSL "${url}" -o "${tmpdir}/${tarball}"
  tar -xJf "${tmpdir}/${tarball}" -C "${tmpdir}"
  rm -rf "${node_dir}"
  mv "${tmpdir}/node-${NODE_VERSION}-linux-${arch}" "${node_dir}"

  ln -sfn "${node_dir}/bin/node" /usr/local/bin/node
  ln -sfn "${node_dir}/bin/npm" /usr/local/bin/npm
  ln -sfn "${node_dir}/bin/npx" /usr/local/bin/npx
  [ -x "${node_dir}/bin/corepack" ] && ln -sfn "${node_dir}/bin/corepack" /usr/local/bin/corepack || true

  rm -rf "${tmpdir}"
}

ensure_node() {
  if command -v node >/dev/null 2>&1; then
    local current
    current="$(node -v 2>/dev/null || true)"
    log "Node atual detectado: ${current:-desconhecido}"
  fi

  apt-get purge -y nodejs npm || true
  apt-get autoremove -y || true
  install_node_official

  log "Versões instaladas:"
  node -v
  npm -v

  npm config set fund false --global || true
  npm config set audit false --global || true
}

write_server_js() {
  log "Gravando server.js..."
  cat > "${APP_DIR}/server.js" <<'JS'
/* WhatsWeb — multiusuário + multi-conta + webhook + API token + Gerador de Comandos
 * Correções:
 *  - COOKIE_SECRET fixo via ENV (sessões não caem após reboot)
 *  - Baileys com fallback de versão (QR aparece mesmo sem internet/DNS momentâneo)
 *  - Botão/rota "Excluir Conta" (remove credenciais e mensagens da conta)
 *  - /api/send aceita GET (chat) e POST (opcional)
 */

const express = require("express");
const http = require("http");
const { Server: IOServer } = require("socket.io");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const QRCode = require("qrcode");
const pino = require("pino");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const axios = require("axios");
const { nanoid } = require("nanoid");

// ===== DB (SQLite) =====
const Database = require("better-sqlite3");
const db = new Database(path.join(__dirname, "whatsweb.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  passhash TEXT,
  apitoken TEXT UNIQUE,
  role TEXT DEFAULT 'user',
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  token TEXT UNIQUE,
  expires INTEGER
);
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  label TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  account_id INTEGER,
  numero TEXT,
  direction TEXT CHECK(direction IN ('sent','received')),
  message TEXT,
  wa_id TEXT,
  ts INTEGER DEFAULT (strftime('%s','now')*1000)
);
CREATE INDEX IF NOT EXISTS idx_msg_user_acc ON messages(user_id, account_id, ts);
CREATE INDEX IF NOT EXISTS idx_msg_num ON messages(numero);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_msg_waid ON messages(wa_id) WHERE wa_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS webhooks(
  user_id INTEGER PRIMARY KEY,
  url TEXT,
  secret TEXT
);
`);

// Migração defensiva: coluna role
try {
  const cols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
  if (!cols.includes("role")) {
    db.prepare("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'").run();
  }
} catch {}

// Utils
function now() { return Math.floor(Date.now()/1000); }
function hashPassword(pw){
  const salt = crypto.randomBytes(16).toString("hex");
  const iter = 120000;
  const dk = crypto.pbkdf2Sync(pw, salt, iter, 32, "sha256").toString("hex");
  return `pbkdf2$${iter}$${salt}$${dk}`;
}
function verifyPassword(pw, stored){
  try{
    const [_, iterStr, salt, hash] = stored.split("$");
    const dk = crypto.pbkdf2Sync(pw, salt, parseInt(iterStr), 32, "sha256").toString("hex");
    return crypto.timingSafeEqual(Buffer.from(hash,"hex"), Buffer.from(dk,"hex"));
  }catch{ return false; }
}
function newApiToken(){ return nanoid(40); }

function createUser(email, pw, role="user", tokenOverride=null){
  const passhash = hashPassword(pw);
  const apitoken = tokenOverride || newApiToken();
  try{
    const info = db.prepare("INSERT INTO users (email, passhash, apitoken, role) VALUES (?,?,?,?)")
      .run(email, passhash, apitoken, role);
    return info.lastInsertRowid;
  }catch{
    const u = getUserByEmail(email);
    if(u){ db.prepare("UPDATE users SET role=? WHERE id=?").run(role, u.id); return u.id; }
    return null;
  }
}
function getUserByEmail(email){ return db.prepare("SELECT * FROM users WHERE email = ?").get(email); }
function getUserById(id){ return db.prepare("SELECT * FROM users WHERE id = ?").get(id); }
function getUserByToken(token){ return db.prepare("SELECT * FROM users WHERE apitoken = ?").get(token); }

function newSession(user_id){
  const token = nanoid(48);
  const expires = now() + 60*60*24*7;
  db.prepare("INSERT INTO sessions (user_id, token, expires) VALUES (?,?,?)").run(user_id, token, expires);
  return { token, expires };
}
function sessionFromToken(tok){
  const s = db.prepare("SELECT * FROM sessions WHERE token = ?").get(tok);
  if(!s || s.expires < now()){ return null; }
  return s;
}
function destroySession(tok){ db.prepare("DELETE FROM sessions WHERE token = ?").run(tok); }

// contas
function listAccountsFor(user){
  if (user.role === "master") {
    return db.prepare("SELECT * FROM accounts ORDER BY id DESC").all();
  }
  return db.prepare("SELECT * FROM accounts WHERE user_id = ? ORDER BY id DESC").all(user.id);
}
function createAccount(user_id, label){
  const info = db.prepare("INSERT INTO accounts (user_id, label) VALUES (?,?)").run(user_id, label || "Minha conta");
  return info.lastInsertRowid;
}
function getAccount(accId){ return db.prepare("SELECT * FROM accounts WHERE id = ?").get(accId); }
function canUseAccount(user, acc){ return !!acc && (user.role === "master" || acc.user_id === user.id); }

// webhook
function getWebhook(user_id){ return db.prepare("SELECT * FROM webhooks WHERE user_id = ?").get(user_id) || {user_id, url:null, secret:null}; }
function setWebhook(user_id, url, secret){
  db.prepare("INSERT INTO webhooks (user_id,url,secret) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET url=excluded.url, secret=excluded.secret")
    .run(user_id, url||null, secret||null);
}

// mensagens/threads
function saveMessage({user_id, account_id, numero, direction, message, wa_id, ts}){
  db.prepare("INSERT OR IGNORE INTO messages (user_id,account_id,numero,direction,message,wa_id,ts) VALUES (?,?,?,?,?,?,?)")
    .run(user_id, account_id, numero, direction, message, wa_id||null, ts||Date.now());
}
function hasWaId(wa_id){
  if(!wa_id) return false;
  const row = db.prepare("SELECT 1 FROM messages WHERE wa_id=?").get(wa_id);
  return !!row;
}
function listThreads(user, account_id, limit=200){
  if (user.role === "master") {
    return db.prepare(`
      SELECT numero, MAX(ts) as last_ts
      FROM messages WHERE account_id=?
      GROUP BY numero ORDER BY last_ts DESC LIMIT ?`)
      .all(account_id, limit).map(r=>r.numero);
  }
  return db.prepare(`
    SELECT numero, MAX(ts) as last_ts
    FROM messages WHERE user_id=? AND account_id=?
    GROUP BY numero ORDER BY last_ts DESC LIMIT ?`)
    .all(user.id, account_id, limit).map(r=>r.numero);
}
function getThread(user, account_id, numero, limit=800){
  if (user.role === "master") {
    return db.prepare(`
      SELECT numero, direction, message, ts
      FROM messages WHERE account_id=? AND numero=?
      ORDER BY ts ASC LIMIT ?`).all(account_id, numero, limit);
  }
  return db.prepare(`
    SELECT numero, direction, message, ts
    FROM messages WHERE user_id=? AND account_id=? AND numero=?
    ORDER BY ts ASC LIMIT ?`).all(user.id, account_id, numero, limit);
}

// ===== App base =====
const log = pino({ level: "info" });
const app = express();
const server = http.createServer(app);
const io = new IOServer(server, {
  cors: { origin: "*" },
  transports: ["websocket","polling"]
});
app.use(cors());

// >>> COOKIE_SECRET fixo por ENV (evita logout após reboot)
const COOKIE_SECRET = process.env.COOKIE_SECRET || "dev-secret";
app.use(cookieParser(COOKIE_SECRET));

app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));

// ===== Seed MASTER por ENV =====
(function ensureMaster(){
  const email = process.env.MASTER_EMAIL;
  const password = process.env.MASTER_PASSWORD;
  const token = process.env.MASTER_TOKEN || null;
  if(!email || !password) return;
  const exists = getUserByEmail(email);
  if(exists){
    if(exists.role !== "master"){ db.prepare("UPDATE users SET role='master' WHERE id=?").run(exists.id); }
    log.info({email},"MASTER já existe");
  }else{
    createUser(email, password, "master", token);
    log.info({email},"MASTER criado");
  }
})();

// ===== Auth middleware (web) =====
function requireAuth(req,res,next){
  const sid = req.signedCookies && req.signedCookies.sid;
  if(!sid){ return res.redirect("/login"); }
  const s = sessionFromToken(sid);
  if(!s){ return res.redirect("/login"); }
  req.user = getUserById(s.user_id);
  if(!req.user){ return res.redirect("/login"); }
  req.sessionToken = sid;
  next();
}

// ===== Baileys multi-conta =====
const { default: makeWASocket, useMultiFileAuthState, fetchLatestBaileysVersion } = require("@whiskeysockets/baileys");
const WA = { sockets:new Map(), ready:new Map(), qrs:new Map() };

async function startWAForAccount(account){
  const accId = account.id;
  if(WA.sockets.has(accId)) return;
  const authDir = path.join(__dirname, "auth", "account_"+accId);
  fs.mkdirSync(authDir, {recursive:true});
  const { state, saveCreds } = await useMultiFileAuthState(authDir);

  // >>> Fallback de versão (sem internet/DNS o QR não travará)
  let version = [2, 3000, 0];
  try { ({ version } = await fetchLatestBaileysVersion()); }
  catch (e) { log.warn({err:String(e)}, "Baileys version fetch falhou, usando fallback"); }

  const sock = makeWASocket({ version, auth: state, logger: pino({ level:"fatal" }), printQRInTerminal:false });
  WA.sockets.set(accId, sock);
  WA.ready.set(accId, false);

  sock.ev.on("creds.update", saveCreds);
  sock.ev.on("connection.update", (u)=>{
    const { connection, qr } = u || {};
    if(qr){ WA.qrs.set(accId, qr); WA.ready.set(accId, false); io.to(room(accId)).emit("wa-status", {accId, status:"qr", ready:false}); }
    if(connection === "open"){ WA.ready.set(accId, true); WA.qrs.delete(accId); io.to(room(accId)).emit("wa-status", {accId, status:"ready", ready:true}); log.info({accId},"WA ready"); }
    if(connection === "close"){
      WA.ready.set(accId, false);
      io.to(room(accId)).emit("wa-status", {accId, status:"disconnected", ready:false});
      setTimeout(()=>{ WA.sockets.delete(accId); startWAForAccount(account).catch(()=>{}); }, 1500);
    }
  });

  sock.ev.on("messages.upsert", async (ev)=>{
    try{
      for(const m of (ev.messages||[])){
        if(!m || m.key?.fromMe) continue;
        const jid = m.key?.remoteJid || "";
        if(!jid || jid.endsWith("@g.us") || jid.endsWith("@broadcast")) continue;
        const numero = String(jid.split("@")[0]).replace(/[^0-9]/g,"").replace(/^0+/,"");
        const wa_id  = m.key?.id || null;
        const ts     = Number(m.messageTimestamp) * 1000 || Date.now();
        const msg = m.message || {};
        const texto = msg.conversation
          || msg.extendedTextMessage?.text
          || msg.imageMessage?.caption
          || msg.videoMessage?.caption
          || msg.buttonsResponseMessage?.selectedDisplayText
          || msg.listResponseMessage?.singleSelectReply?.selectedRowId
          || "";

        if(wa_id && hasWaId(wa_id)) continue; // DEDUPE

        const owner = getAccount(accId).user_id;
        saveMessage({ user_id: owner, account_id: accId, numero, direction:"received", message:String(texto||""), wa_id, ts });

        io.to(room(accId)).emit("recv", { accId, numero, message: String(texto||""), ts, source:"baileys" });
        io.to(room(accId)).emit("threads-update", { accId, numero, ts });

        const wh = getWebhook(owner);
        if(wh && wh.url){
          const body = JSON.stringify({event:"message.received", accountId: accId, from: numero, text: String(texto||""), ts});
          let headers = { "Content-Type":"application/json" };
          if(wh.secret){
            const sig = crypto.createHmac("sha256", wh.secret).update(body).digest("hex");
            headers["X-Signature"] = sig;
          }
          axios.post(wh.url, body, {headers}).catch(e=> log.error({err:String(e)}, "webhook post"));
        }
      }
    }catch(e){ log.error({err:e}, "RX handler"); }
  });
}

async function sendWhatsAppFromAccount(accId, numeroRaw, message){
  const numero = String(numeroRaw||"").replace(/[^0-9]/g,"").replace(/^0+/,"");
  if(!numero || !message) throw new Error("numero/mensagem inválidos");
  const acc = getAccount(accId); if(!acc) throw new Error("Conta inexistente");
  await startWAForAccount(acc);
  const sock = WA.sockets.get(accId);
  if(!sock || !WA.ready.get(accId)) throw new Error("WhatsApp não está pronto (abra /auth/"+accId+")");
  await sock.sendMessage(`${numero}@s.whatsapp.net`, { text: String(message) });
  const owner = acc.user_id;
  saveMessage({ user_id: owner, account_id: accId, numero, direction:"sent", message:String(message), wa_id:null, ts:Date.now() });
  io.to(room(accId)).emit("sent", { accId, numero, message: String(message), ts: Date.now() });
  return { ok:true, accId, numero, driver:"baileys" };
}

function room(accId){ return `acc_${accId}`; }

// ===== UI helpers =====
function head(title){
  return `
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
<style>
:root{
  --bg0:#070417; --bg1:#0b0f2b; --bg2:#0f1437;
  --glass:rgba(255,255,255,.06); --line:rgba(255,255,255,.10);
  --text:#e9efff; --muted:#a8b4d6;
  --accent:#7c3aed; --accent2:#22d3ee; --accent3:#fb37b5; --success:#16a34a; --danger:#ef4444;
}
*{box-sizing:border-box} html,body{height:100%}
body{
  margin:0; color:var(--text); font-family:Inter,Segoe UI,Roboto,Ubuntu,system-ui,Arial,sans-serif;
  background:
    radial-gradient(1000px 600px at 120% -10%, rgba(124,58,237,.25) 0%, transparent 60%),
    radial-gradient(900px 500px at -10% 100%, rgba(34,211,238,.22) 0%, transparent 60%),
    linear-gradient(135deg,var(--bg0),var(--bg2));
}
.container{width:min(1200px,100%);margin:24px auto;padding:0 16px)
.card{background:linear-gradient(180deg,rgba(255,255,255,.08),rgba(255,255,255,.03));
      border:1px solid var(--line); border-radius:18px; backdrop-filter:blur(10px); box-shadow:0 20px 80px rgba(0,0,0,.45);
      padding:18px;min-width:0;}
.card>*{min-width:0}
@media(max-width:700px){
  .container{margin:12px auto;padding:0 10px}
  .card{padding:14px;border-radius:14px}
  h1{font-size:22px} h2{font-size:18px}
  a.btn,button,.btn{width:100%;justify-content:center}
  .topbar .wrap{flex-wrap:wrap}
  .table th,.table td{white-space:nowrap}
}
h1,h2{letter-spacing:.2px} h1{font-size:28px;margin:0 0 10px;background:linear-gradient(90deg,var(--accent2),var(--accent),var(--accent3));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
a.btn,button,.btn{
  display:inline-flex;align-items:center;gap:8px; padding:10px 14px; border-radius:12px; border:1px solid var(--line);
  background:linear-gradient(90deg,rgba(34,211,238,.18),rgba(124,58,237,.18)); color:#fff; text-decoration:none; cursor:pointer;
  transition:.2s;
}
a.btn:hover,button:hover,.btn:hover{transform:translateY(-1px);box-shadow:0 10px 30px rgba(0,0,0,.35)}
input,select,textarea{
  width:100%; padding:12px 12px; border-radius:12px; border:1px solid var(--line); background:#0b1130; color:var(--text);
}
hr{border:none;border-top:1px solid var(--line);margin:14px 0}
small, .muted{color:var(--muted)}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;background:rgba(34,211,238,.18);border:1px solid var(--line);font-size:12px}
.scroll{overflow:auto} ::-webkit-scrollbar{height:10px;width:10px} ::-webkit-scrollbar-thumb{background:rgba(255,255,255,.12);border-radius:10px}
.topbar{position:sticky;top:0;z-index:10;background:linear-gradient(180deg,rgba(7,4,23,.9),rgba(7,4,23,.6));backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.topbar .wrap{max-width:1200px;margin:0 auto;padding:10px 16px;display:flex;align-items:center;gap:12px}
.logo{font-weight:800;letter-spacing:.3px}
.logo b{background:linear-gradient(90deg,var(--accent2),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left}
</style>`;
}
function topbar(){
  return `
<div class="topbar"><div class="wrap">
  <div class="logo">DOE UM PIX PARA 41127979000140 PARA AJUDAR  CONTINUAR COM O PROJETO <b>WhatsZvnColombo</b></div>
  <div style="margin-left:auto"><a class="btn" href="/dashboard">Dashboard</a></div>
</div></div>`;
}
function headerNav(){ return `<div style="display:flex;gap:10px;margin-bottom:12px"><a class="btn" href="/dashboard">⬅ Voltar</a></div>`; }

// ===== Páginas =====
app.get("/", (req,res)=> res.redirect("/dashboard"));

app.get("/register", (req,res)=>{
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.end(`<!doctype html><html><head>${head("Registrar — WhatsZvnColombo")}</head><body>
${topbar()}
<div class="container">
  <div class="card" style="max-width:520px;margin:10vh auto">
    <h1>Criar conta</h1>
    <form method="post" action="/register" style="display:grid;gap:10px">
      <input name="email" type="email" placeholder="Email" required/>
      <input name="password" type="password" placeholder="Senha (mín. 6)" minlength="6" required/>
      <input name="password2" type="password" placeholder="Confirmar senha" minlength="6" required/>
      <button>Criar</button>
      <small>Já tem conta? <a href="/login">Entrar</a></small>
    </form>
  </div>
</div></body></html>`);
});

app.get("/login", (req,res)=>{
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.end(`<!doctype html><html><head>${head("Login — WhatsWebZvnColombo")}</head><body>
${topbar()}
<div class="container">
  <div class="card" style="max-width:520px;margin:10vh auto">
    <h1>Entrar</h1>
    <form method="post" action="/login" style="display:grid;gap:10px">
      <input name="email" type="email" placeholder="Email" required/>
      <input name="password" type="password" placeholder="Senha" required/>
      <button>Login</button>
      <small>Novo aqui? <a href="/register">Criar conta</a></small>
    </form>
  </div>
</div></body></html>`);
});

app.post("/register", (req,res)=>{
  const {email, password, password2} = req.body || {};
  if(!email || !password) return res.status(400).send("email/senha obrigatórios");
  if(String(password).length < 6) return res.status(400).send("senha muito curta (mín. 6)");
  if(password !== password2) return res.status(400).send("as senhas não conferem");
  if(getUserByEmail(email)) return res.status(400).send("email já registrado");
  const uid = createUser(email, password, "user");
  const { token } = newSession(uid);
  res.cookie("sid", token, { httpOnly:true, signed:true, sameSite:"lax" });
  res.redirect("/dashboard");
});
app.post("/login", (req,res)=>{
  const {email, password} = req.body || {};
  const u = getUserByEmail(email||"");
  if(!u || !verifyPassword(password||"", u.passhash)) return res.status(401).send("credenciais inválidas");
  const { token } = newSession(u.id);
  res.cookie("sid", token, { httpOnly:true, signed:true, sameSite:"lax" });
  res.redirect("/dashboard");
});
app.post("/logout", requireAuth, (req,res)=>{
  if(req.sessionToken) destroySession(req.sessionToken);
  res.clearCookie("sid");
  res.redirect("/login");
});

// ===== Excluir usuário =====
app.post("/user/delete", requireAuth, (req,res)=>{
  const uid = req.user.id;
  db.prepare("DELETE FROM sessions WHERE user_id=?").run(uid);
  db.prepare("DELETE FROM messages WHERE user_id=?").run(uid);
  db.prepare("DELETE FROM accounts WHERE user_id=?").run(uid);
  db.prepare("DELETE FROM webhooks WHERE user_id=?").run(uid);
  db.prepare("DELETE FROM users WHERE id=?").run(uid);
  res.clearCookie("sid");
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.end(`<!doctype html><html><head>${head("Usuário removido — WhatsWeb")}</head><body>
${topbar()}
<div class="container"><div class="card" style="max-width:640px;margin:10vh auto">
  <h2 style="margin-top:0;color:#ffb4b4">Usuário excluído com sucesso.</h2>
  <p class="muted">Todas as contas, mensagens, sessões e webhook foram removidos.</p>
  <hr/>
  <a class="btn" href="/register">Criar novo usuário</a>
</div></div></body></html>`);
});

// ===== Dashboard / Settings =====
app.get("/dashboard", requireAuth, (req,res)=>{
  const accounts = listAccountsFor(req.user);
  const api = req.user.apitoken;
  const base = `${req.protocol}://${req.get("host")}`;
  const wh = getWebhook(req.user.id);
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.end(`<!doctype html><html><head>${head("Dashboard — WhatsWeb")}
<style>
.grid{display:grid;grid-template-columns:1.2fr .8fr;gap:16px}
@media(max-width:1000px){.grid{grid-template-columns:1fr}}
.kv{display:grid;grid-template-columns:120px 1fr;gap:6px 10px}
.search{display:flex;gap:8px}
</style></head><body>
${topbar()}
<div class="container grid">
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div>
        <h1>Bem-vindo, ${req.user.email}${req.user.role==='master'?' <span class="badge">MASTER</span>':''}</h1>
        <div class="kv"><div class="muted">Token API</div><div><code>${api}</code></div></div>
      </div>
      <div>
        <a class="btn" href="/commands">Gerar Comandos</a>
        <form method="post" action="/logout" style="display:inline"><button>Sair</button></form>
        <form method="post" action="/user/delete" style="display:inline" onsubmit="return confirm('Excluir definitivamente seu usuário e todos os dados?');">
          <button class="btn" style="background:linear-gradient(90deg,rgba(239,68,68,.2),rgba(251,55,181,.18));border-color:#de6">Excluir Usuário</button>
        </form>
      </div>
    </div>
    <hr/>
    <p class="muted">Endpoints:</p>
    <div class="kv">
      <div>Enviar</div><div><code>POST ${base}/api/v1/${api}/send</code></div>
      <div>Threads</div><div><code>GET ${base}/api/v1/${api}/threads?account=ID</code></div>
      <div>Thread</div><div><code>GET ${base}/api/v1/${api}/thread?account=ID&numero=5511...</code></div>
      <div>RB</div><div><code>${base}/api/rb/&lt;RB_TOKEN|TOKEN_USUARIO&gt;/send?account=ID&to=5511...&message=...</code></div>
    </div>
  </div>

  <div class="card">
    <h2>Webhook</h2>
    <form method="post" action="/settings/webhook" style="display:grid;gap:8px">
      <label>URL</label><input name="url" value="${wh.url||""}">
      <label>Segredo</label><input name="secret" value="${wh.secret||""}">
      <button>Salvar</button>
      <small class="muted">Recebe <code>POST application/json</code> {"event":"message.received","accountId":ID,"from":"5511...","text":"...","ts":...} com <code>X-Signature</code> (HMAC SHA256 do corpo).</small>
    </form>
  </div>

  <div class="card" style="grid-column:1 / -1">
    <h2>Contas WhatsApp</h2>
    <form method="post" action="/accounts/new" class="search">
      <input name="label" placeholder="Nome da conta (ex: Suporte)" required>
      <button>Criar conta</button>
    </form>
    <div class="scroll" style="margin-top:10px">
      <table class="table">
        <tr><th>ID</th><th>Nome</th><th>Dono</th><th>Ações</th></tr>
        ${accounts.map(a=>`<tr>
          <td>${a.id}</td><td>${a.label}</td><td>${a.user_id}</td>
          <td style="display:flex;gap:8px;flex-wrap:wrap">
            <a class="btn" href="/auth/${a.id}">Autenticar (QR)</a>
            <a class="btn" href="/chat/${a.id}">Abrir chat</a>
            <form method="post" action="/accounts/${a.id}/delete" onsubmit="return confirm('Apagar conta #${a.id}? Isto remove credenciais e mensagens desta conta.');" style="display:inline">
              <button class="btn" style="background:linear-gradient(90deg,rgba(239,68,68,.2),rgba(251,55,181,.18));border-color:#de6">Excluir Conta</button>
            </form>
          </td>
        </tr>`).join("")}
      </table>
    </div>
  </div>
</div></body></html>`);
});
app.post("/accounts/new", requireAuth, async (req,res)=>{
  const id = createAccount(req.user.id, (req.body && req.body.label) || "Minha conta");
  startWAForAccount({id, user_id:req.user.id}).catch(()=>{});
  res.redirect("/dashboard");
});
app.post("/accounts/:accId/delete", requireAuth, (req,res)=>{
  const accId = Number(req.params.accId);
  const acc = getAccount(accId);
  if(!canUseAccount(req.user, acc)) return res.status(404).send("conta não encontrada");

  try { const s = WA.sockets.get(accId); s?.logout?.(); s?.end?.(); s?.ws?.close?.(); } catch {}
  WA.sockets.delete(accId); WA.ready.delete(accId); WA.qrs.delete(accId);

  db.prepare("DELETE FROM messages WHERE account_id=?").run(accId);
  db.prepare("DELETE FROM accounts WHERE id=?").run(accId);
  const dir = path.join(__dirname, "auth", "account_"+accId);
  try { fs.rmSync(dir, { recursive:true, force:true }); } catch {}

  res.redirect("/dashboard");
});
app.post("/settings/webhook", requireAuth, (req,res)=>{
  setWebhook(req.user.id, req.body.url, req.body.secret);
  res.redirect("/dashboard");
});

// ===== PÁGINA DE AUTENTICAÇÃO — QR LIMPO =====
app.get("/status/:accId", requireAuth, (req,res)=>{
  const accId = Number(req.params.accId);
  const acc = getAccount(accId);
  if(!canUseAccount(req.user, acc)) return res.status(404).json({error:"conta não encontrada"});
  startWAForAccount(acc).catch(()=>{});
  const ready = !!WA.ready.get(accId);
  res.json({accId, status: ready ? "ready" : (WA.qrs.get(accId) ? "qr":"starting"), ready});
});

app.get("/qr.png", requireAuth, async (req,res)=>{
  const accId = Number(req.query.acc||0);
  const acc = getAccount(accId);
  if(!canUseAccount(req.user, acc)) return res.status(404).end();
  const qr = WA.qrs.get(accId);
  if(!qr) return res.status(204).end();
  res.setHeader("Content-Type","image/png");
  await QRCode.toFileStream(res, qr, { margin:1, width:600, errorCorrectionLevel:"H" });
});

app.get("/auth/:accId", requireAuth, (req,res)=>{
  const accId = Number(req.params.accId);
  const acc = getAccount(accId);
  if(!canUseAccount(req.user, acc)) return res.status(404).send("conta não encontrada");
  startWAForAccount(acc).catch(()=>{});
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.end(`<!doctype html><html><head>${head("Autenticação — Conta "+accId)}
<style>
.wrap-auth{display:grid;gap:18px}
.qrwrap{position:relative;display:grid;place-items:center;padding:20px;background:#030816;border-radius:18px;border:1px dashed rgba(34,211,238,.45);box-shadow:0 0 30px rgba(34,211,238,.18);z-index:1}
.qrbox{display:grid;place-items:center;width:100%;max-width:620px;aspect-ratio:1/1;background:radial-gradient(200px 200px at 50% 50%,rgba(34,211,238,.08) 0%,transparent 70%);border-radius:14px;position:relative;overflow:hidden}
.qrbox::after{content:"";position:absolute;inset:-6px;border-radius:18px;background:conic-gradient(from 0deg,var(--accent2),var(--accent),var(--accent3),var(--accent2));filter:blur(14px);opacity:.32;animation:spin 9s linear infinite;pointer-events:none}
@keyframes spin{to{transform:rotate(360deg)}}
#qr{width:600px;height:600px;image-rendering:pixelated;border-radius:10px;display:none;user-select:none;pointer-events:none}
#empty{user-select:none}
.actions{display:flex;gap:10px;flex-wrap:wrap}
</style></head><body>
${topbar()}
<div class="container card">
  ${headerNav()}
  <h1>Autenticação — Conta #${accId} (${acc.label})</h1>
  <div class="wrap-auth">
    <div class="qrwrap">
      <div class="qrbox">
        <img id="qr" alt="QR Code para autenticação"/>
        <div id="empty" class="muted">QR indisponível (já autenticado ou iniciando)</div>
      </div>
    </div>

    <div class="actions">
      <a class="btn" onclick="refresh(true)">Atualizar</a>
      <a class="btn" href="/chat/${accId}">Ir para o chat</a>
    </div>
    <div class="muted">Status: <span id="st">starting</span> • Atualizado: <span id="ts">—</span></div>
  </div>
</div>
<script>
async function refresh(force){
  try{
    const s=await fetch("/status/${accId}"+(force?"?x="+Date.now():"")); const v=await s.json();
    document.getElementById("st").textContent=v.status;
    document.getElementById("ts").textContent=new Date().toLocaleString();
    const img=document.getElementById("qr"), empty=document.getElementById("empty");
    if(v.status==="qr"){ img.src="/qr.png?acc=${accId}&ts="+Date.now(); img.style.display="block"; empty.style.display="none"; }
    else{ img.style.display="none"; empty.style.display="block"; }
  }catch{ document.getElementById("st").textContent="erro"; }
}
refresh(true); setInterval(refresh, 2200);
</script>
</body></html>`);
});

// ===== Chat (com botão EXCLUIR CONVERSA) =====
app.get("/chat/:accId", requireAuth, (req,res)=>{
  const accId = Number(req.params.accId);
  const acc = getAccount(accId);
  if(!canUseAccount(req.user, acc)) return res.status(404).send("conta não encontrada");
  startWAForAccount(acc).catch(()=>{});
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.end(`<!doctype html><html><head>${head("Chat — Conta "+accId)}
<style>
.chat{display:grid;grid-template-columns:340px 1fr;gap:16px}
@media(max-width:1100px){.chat{grid-template-columns:1fr}}
.sidebar,.pane{background:linear-gradient(180deg,rgba(255,255,255,.07),rgba(255,255,255,.03));border:1px solid var(--line);border-radius:18px;backdrop-filter:blur(10px)}
.sidebar{display:flex;flex-direction:column;min-height:78vh}
.pane{min-height:78vh;display:grid;grid-template-rows:auto 1fr auto}
.header{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--line)}
.searchBox{padding:10px;border-bottom:1px solid var(--line)}
.list{flex:1;overflow:auto;padding:10px;display:flex;flex-direction:column;gap:8px}
.item{padding:10px;border-radius:12px;border:1px solid transparent;background:rgba(0,0,0,.15);cursor:pointer;display:flex;justify-content:space-between;align-items:center}
.item:hover{background:#0e1444;border-color:#28346b}
.item .num{font-weight:700}
.badge-green{background:rgba(22,163,74,.18);border:1px solid var(--line)}
.msgs{flex:1;overflow-y:auto;padding:18px;display:flex;flex-direction:column;gap:8px;max-height:65vh;min-height:0}
.bub{max-width:72%;padding:12px 14px;border-radius:16px;box-shadow:0 12px 24px rgba(0,0,0,.28);position:relative}
.bub.in{align-self:flex-start;background:linear-gradient(180deg,#0c1442,#0e1a55)}
.bub.out{align-self:flex-end;background:linear-gradient(180deg,#123f3a,#0f362f)}
.bub small{display:block;margin-top:6px;color:var(--muted);opacity:.85}
.input{display:flex;gap:10px;padding:12px;border-top:1px solid var(--line)}
.input input{flex:1}
.input button{min-width:120px}
</style></head><body>
${topbar()}
<div class="container">
  ${headerNav()}
  <div class="chat">
    <div class="sidebar">
      <div class="header" style="padding:12px 14px"><div class="badge">Conta #${accId}</div><a class="btn" href="/auth/${accId}">Autenticar</a></div>
      <div class="searchBox"><input id="numero" placeholder="Novo número (ex: 5511999999999)"></div>
      <div class="list" id="list"></div>
      <div style="padding:10px"><a class="btn" style="width:100%" onclick="startChat()">Abrir conversa</a></div>
    </div>

    <div class="pane">
      <div class="header">
        <div id="title" class="muted">Selecione um contato</div>
        <div style="display:flex;gap:8px">
          <button class="btn" id="delBtn" disabled>Excluir conversa</button>
          <span id="badge" class="badge">•</span>
        </div>
      </div>
      <div id="msgs" class="msgs"></div>
      <form class="input" onsubmit="sendMsg(event)">
        <input id="texto" placeholder="Digite sua mensagem...">
        <button>Enviar</button>
      </form>
    </div>
  </div>
</div>

<script src="/socket.io/socket.io.js"></script>
<script>
const sock = io({ transports:["websocket"] });
const ACC = ${accId};
sock.emit("join", { accId: ACC });

function norm(n){return String(n||"").replace(/[^0-9]/g,"").replace(/^0+/,"");}
let current=null;
const msgs=document.getElementById("msgs");
const list=document.getElementById("list");
const delBtn=document.getElementById("delBtn");

function formatTime(ts){try{return new Date(ts||Date.now()).toLocaleTimeString()}catch{return ""}}
function add(dir,txt,ts){
  const b=document.createElement("div");
  b.className="bub "+(dir==="out"?"out":"in");
  b.innerHTML = "<div>"+(txt||"")+"</div><small>"+formatTime(ts)+"</small>";
  msgs.appendChild(b); msgs.scrollTop=msgs.scrollHeight;
}
async function loadThreads(){
  const arr=await fetch("/api/threads?account="+ACC, {credentials:"same-origin"}).then(r=>r.json()).catch(()=>[]);
  list.innerHTML="";
  arr.forEach(num=>{
    const d=document.createElement("div");
    d.className="item"; d.innerHTML="<div class=\'num\'>"+num+"</div><span class=\'badge badge-green\'>chat</span>";
    d.onclick=()=>openChat(num);
    list.appendChild(d);
  });
}
async function openChat(n){
  current=norm(n);
  delBtn.disabled=false;
  document.getElementById("title").textContent="Conversando com "+current;
  const t=await fetch("/api/thread?account="+ACC+"&numero="+current, {credentials:"same-origin"}).then(r=>r.json()).catch(()=>[]);
  msgs.innerHTML="";
  t.forEach(m=>add(m.direction==="sent"?"out":"in", m.message, m.ts));
}
function startChat(){ const n=norm(document.getElementById("numero").value); if(!n) return; openChat(n); }

function sendMsg(e){
  e.preventDefault(); if(!current) return;
  const t=document.getElementById("texto"); const m=t.value.trim(); if(!m) return;
  fetch("/api/send?account="+ACC+"&numero="+current+"&message="+encodeURIComponent(m), {credentials:"same-origin"});
  t.value="";
}

delBtn.addEventListener("click", ()=>{
  if(!current) return;
  if(!confirm("Excluir TODA a conversa com "+current+"?")) return;
  fetch("/api/delete-thread?account="+ACC+"&numero="+current, {method:"POST", credentials:"same-origin"})
    .then(()=>{ msgs.innerHTML=""; current=null; delBtn.disabled=true; document.getElementById("title").textContent="Selecione um contato"; loadThreads(); })
    .catch(()=>alert("Falha ao excluir."));
});

sock.on("recv", d=>{
  if(d.accId!==ACC) return;
  const n=norm(d.numero);
  if(!current) openChat(n);
  if(current===n) add("in", d.message, d.ts);
});
sock.on("threads-update", d=>{ if(d.accId===ACC) loadThreads(); });
sock.on("sent", d=>{
  if(d.accId!==ACC) return;
  const n=norm(d.numero);
  if(current===n) add("out", d.message, d.ts);
});
loadThreads();
</script>
</body></html>`);
});

// ===== PÁGINA: GERADOR DE COMANDOS =====
app.get("/commands", requireAuth, (req, res) => {
  const accounts = listAccountsFor(req.user);
  const baseApi = `${req.protocol}://${req.get("host")}/api/v1/`;
  const token = req.user.apitoken;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`<!doctype html><html><head>${head("Gerar Comandos — WhatsZvnColombo")}
<style>
  .grid{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,.95fr);gap:16px;align-items:start}
  .formgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
  .actions-row{display:flex;gap:8px;margin-top:10px;align-items:center;flex-wrap:wrap}
  .code{position:relative;background:#0a142b;border:1px solid var(--line);border-radius:12px;min-width:0;overflow:hidden}
  .code header{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:8px 10px;border-bottom:1px solid var(--line)}
  .code h3{margin:0;font-size:13px;color:#cde6ff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  pre{margin:0;padding:12px;white-space:pre-wrap;word-break:break-word;overflow:auto;font-family:ui-monospace, Menlo, Consolas, monospace;font-size:12.5px;line-height:1.45;color:#d9f1ff;max-height:260px}
  .btn.small{padding:7px 10px;font-weight:600;width:auto;min-width:92px;justify-content:center}
  textarea{resize:vertical;min-height:110px}
  @media(max-width:980px){.grid{grid-template-columns:1fr}.formgrid{grid-template-columns:1fr}}
  @media(max-width:620px){
    .code header{flex-direction:column;align-items:stretch}
    .btn.small{width:100%}
    pre{font-size:11.5px;max-height:220px}
    .actions-row button{width:100%}
  }
</style>
</head><body>
${topbar()}
<div class="container">
  <div class="card" style="margin-bottom:16px">
    <div style="display:flex;align-items:center;gap:10px">
      <a class="btn" href="/dashboard">⬅ Voltar</a>
      <h1 style="margin:0">Gerar Comandos</h1>
    </div>
    <p class="muted" style="margin:10px 0 0">Seu token: <code>${token}</code></p>
  </div>

  <div class="grid">
    <div class="card">
      <h2 style="margin-top:0">Parâmetros</h2>
      <div class="formgrid">
        <div>
          <label>Endpoint base (sem token)</label>
          <input id="baseUrl" value="${baseApi}">
        </div>
        <div>
          <label>Rota</label>
          <input id="route" value="send">
        </div>
      </div>

      <div class="formgrid">
        <div>
          <label>Conta (account)</label>
          <select id="account">
            ${accounts.map(a => `<option value="${a.id}">#${a.id} — ${a.label||"Conta"}</option>`).join("")}
          </select>
        </div>
        <div>
          <label>Telefone (to) — ex: 5516999999999</label>
          <input id="to" value="">
        </div>
      </div>

      <label>Mensagem</label>
      <textarea id="message" rows="4">Olá! Mensagem de teste.</textarea>

      <div class="actions-row">
        <button class="btn" id="btnBuild" type="button">Gerar comandos</button>
        <span class="muted" id="status"></span>
      </div>
    </div>

    <div class="card">
      <h2 style="margin-top:0">Comandos Gerados</h2>

      <div class="code" style="margin-bottom:12px">
        <header>
          <h3>Linux (curl)</h3>
          <a class="btn small" data-copy="#outLinux">Copiar</a>
        </header>
        <pre id="outLinux">— clique em “Gerar comandos” —</pre>
      </div>

      <div class="code" style="margin-bottom:12px">
        <header>
          <h3>Windows (PowerShell)</h3>
          <a class="btn small" data-copy="#outWin">Copiar</a>
        </header>
        <pre id="outWin">— clique em “Gerar comandos” —</pre>
      </div>

      <div class="code">
        <header>
          <h3>MikroTik (/tool fetch)</h3>
          <a class="btn small" data-copy="#outRB">Copiar</a>
        </header>
        <pre id="outRB">— clique em “Gerar comandos” —</pre>
      </div>
    </div>
  </div>
</div>

<script>
const USER_TOKEN = ${JSON.stringify(token)};
function normBase(u){ if(!u) return ""; u=u.trim(); return u.endsWith("/")? u.slice(0,-1): u; }
function buildUrl(base, token, route){ if(!base||!token||!route) return ""; return \`\${normBase(base)}/\${encodeURIComponent(token)}/\${route}\`; }
function payload(){ return {
  account: Number(document.getElementById("account").value||"0")||0,
  to: String(document.getElementById("to").value||"").trim(),
  message: String(document.getElementById("message").value||"")
};}
function escROS(s){return s.replace(/\\\\/g,"\\\\\\\\").replace(/"/g,'\\\\\\"');}
function codeLinux(url, body){
  const j = JSON.stringify(body).replace(/'/g,"'\\\\''");
  return \`curl -X POST "\${url}" \\\n  -H "Content-Type: application/json" \\\n  -d '\${j}'\`;
}
function codeWindows(url, body){
  return \`$body = @{\n  account = \${body.account}\n  to      = "\${body.to}"\n  message = "\${body.message.replace(/"/g,'\`"')}"\n} | ConvertTo-Json\n\nInvoke-RestMethod -Uri "\${url}" -Method Post -Body $body -ContentType "application/json"\`;
}
function codeRouterOS(url, body){
  const jEsc = escROS(JSON.stringify(body));
  return \`/tool fetch url="\${url}" \\\n    http-method=post \\\n    http-data="\${jEsc}" \\\n    http-header-field="Content-Type: application/json" \\\n    keep-result=no\`;
}
function setText(sel, t){ document.querySelector(sel).textContent = t; }
function setStatus(msg, ms=1400){
  const s=document.getElementById('status');
  if(!s) return;
  s.textContent=msg;
  if(ms) setTimeout(()=>{ if(s.textContent===msg) s.textContent=''; }, ms);
}
async function copyText(t, btn){
  const text = String(t || '').trim();
  if(!text || text.startsWith('—')){ setStatus('Gere o comando primeiro.'); return; }
  try{
    if(navigator.clipboard && window.isSecureContext){
      await navigator.clipboard.writeText(text);
    }else{
      const ta=document.createElement('textarea');
      ta.value=text;
      ta.setAttribute('readonly','');
      ta.style.position='fixed';
      ta.style.top='-1000px';
      ta.style.left='-1000px';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok=document.execCommand('copy');
      document.body.removeChild(ta);
      if(!ok) throw new Error('execCommand copy falhou');
    }
    const old = btn ? btn.textContent : '';
    if(btn){ btn.textContent='Copiado ✓'; setTimeout(()=>btn.textContent=old, 1200); }
    setStatus('Copiado!');
  }catch(e){
    setStatus('Não consegui copiar automaticamente. Selecione o texto e copie manualmente.', 3500);
  }
}
document.querySelectorAll('[data-copy]').forEach(b=>{
  b.setAttribute('role','button');
  b.setAttribute('tabindex','0');
  const run=()=>{
    const sel = b.getAttribute('data-copy');
    const el = document.querySelector(sel);
    copyText(el ? el.textContent : '', b);
  };
  b.addEventListener('click', (ev)=>{ ev.preventDefault(); run(); });
  b.addEventListener('keydown', (ev)=>{ if(ev.key==='Enter' || ev.key===' '){ ev.preventDefault(); run(); } });
});
document.getElementById("btnBuild").addEventListener("click", ()=>{
  const base = document.getElementById("baseUrl").value || ${JSON.stringify("http://localhost:3000/api/v1/")};
  const route = document.getElementById("route").value || "send";
  const url = buildUrl(base, USER_TOKEN, route);
  const body = payload();
  if(!url || !body.account || !body.to || !body.message){ setStatus('Preencha account/to/message.', 2500); return; }
  setText("#outLinux", codeLinux(url, body));
  setText("#outWin",   codeWindows(url, body));
  setText("#outRB",    codeRouterOS(url, body));
  setStatus('Comandos gerados.');
});
</script>
</body></html>`);
});

// ===== APIs WEB =====
app.get("/api/threads", requireAuth, (req,res)=>{
  const account_id = Number(req.query.account||0);
  const acc = getAccount(account_id);
  if(!canUseAccount(req.user, acc)) return res.status(404).json([]);
  res.json(listThreads(req.user, account_id));
});
app.get("/api/thread", requireAuth, (req,res)=>{
  const account_id = Number(req.query.account||0);
  const acc = getAccount(account_id);
  if(!canUseAccount(req.user, acc)) return res.status(404).json([]);
  const numero = String(req.query.numero||"").replace(/[^0-9]/g,"").replace(/^0+/,"");
  res.json(getThread(req.user, account_id, numero));
});
// GET (usado pelo chat)
app.get("/api/send", requireAuth, async (req,res)=>{
  try{
    const account_id = Number(req.query.account||0);
    const acc = getAccount(account_id);
    if(!canUseAccount(req.user, acc)) return res.status(404).json({ok:false, error:"conta não encontrada"});
    const out = await sendWhatsAppFromAccount(account_id, req.query.numero||req.query.to, req.query.message||req.query.mensagem);
    res.json(out);
  }catch(e){ res.status(500).json({ok:false, error:String(e)}); }
});
// POST (opcional)
app.post("/api/send", requireAuth, async (req,res)=>{
  try{
    const account_id = Number(req.body.account||0);
    const acc = getAccount(account_id);
    if(!canUseAccount(req.user, acc)) return res.status(404).json({ok:false, error:"conta não encontrada"});
    const out = await sendWhatsAppFromAccount(account_id, req.body.numero||req.body.to, req.body.message||req.body.mensagem);
    res.json(out);
  }catch(e){ res.status(500).json({ok:false, error:String(e)}); }
});

// >>> Excluir conversa
app.post("/api/delete-thread", requireAuth, (req,res)=>{
  const account_id = Number(req.query.account||0);
  const acc = getAccount(account_id);
  if(!canUseAccount(req.user, acc)) return res.status(404).json({ok:false});
  const numero = String(req.query.numero||"").replace(/[^0-9]/g,"").replace(/^0+/,"");
  if(!numero) return res.status(400).json({ok:false});
  if(req.user.role === "master"){
    db.prepare("DELETE FROM messages WHERE account_id=? AND numero=?").run(account_id, numero);
  }else{
    db.prepare("DELETE FROM messages WHERE user_id=? AND account_id=? AND numero=?").run(req.user.id, account_id, numero);
  }
  io.to(room(account_id)).emit("threads-update", { accId: account_id, numero, ts: Date.now() });
  res.json({ok:true});
});

// ===== Helpers p/ RB =====
function readLooseBody(req){
  return new Promise((resolve)=>{
    try{
      const ctype=(req.headers["content-type"]||"").toLowerCase();
      let buf=""; req.on("data",ch=>buf+=ch);
      req.on("end",()=>{
        const q=new URL(req.url, "http://local").searchParams;
        const fromQuery = { account:q.get("account"), to:q.get("to")||q.get("numero"), message:q.get("message")||q.get("mensagem") };
        if(fromQuery.account||fromQuery.to||fromQuery.message) return resolve(fromQuery);

        if(req.body && (req.body.account||req.body.to||req.body.numero||req.body.message||req.body.mensagem)){
          return resolve({ account:req.body.account, to:req.body.to||req.body.numero, message:req.body.message||req.body.mensagem });
        }

        if(ctype.includes("application/x-www-form-urlencoded")){
          const o={};
          buf.split("&").forEach(kv=>{
            const [k,v]=kv.split("="); if(k) o[decodeURIComponent(k)]=decodeURIComponent((v||"").replace(/\+/g," "));
          });
          return resolve({account:o.account,to:o.to||o.numero,message:o.message||o.mensagem});
        }

        try{
          const j=JSON.parse(buf||"null");
          if(j){ return resolve({account:j.account,to:j.to||j.numero,message:j.message||j.mensagem}); }
        }catch{}

        const o={};
        buf.split(/[&\n\r;,]+/).forEach(kv=>{
          kv=kv.trim(); if(!kv) return;
          const p=kv.indexOf("="); if(p>0){ o[kv.slice(0,p).trim()]=kv.slice(p+1).trim(); }
        });
        return resolve({account:o.account,to:o.to||o.numero,message:o.message||o.mensagem});
      });
    }catch{ resolve({}); }
  });
}

// ===== API RB =====
app.all("/api/rb/:token/send", async (req,res)=>{
  try{
    const tok=(req.params.token||"").trim();
    const rbTok=(process.env.RB_TOKEN||"").trim();
    let user=null;
    if(rbTok && tok===rbTok){
      user = db.prepare("SELECT * FROM users WHERE role='master' ORDER BY id ASC LIMIT 1").get();
    }
    if(!user){ user = getUserByToken(tok); }
    if(!user){ res.status(401).type("text/plain").end("ERROR token"); return; }

    const b = await readLooseBody(req);
    const account_id = Number(b.account||0);
    const acc = getAccount(account_id);
    if(!acc){ res.status(404).type("text/plain").end("ERROR conta"); return; }
    if(!(user.role==="master" || acc.user_id===user.id)){
      res.status(403).type("text/plain").end("ERROR perm"); return;
    }

    const numero = String(b.to||"");
    const message = String(b.message||"");
    if(!numero || !message){ res.status(400).type("text/plain").end("ERROR params"); return; }

    const out = await sendWhatsAppFromAccount(account_id, numero, message);
    res.status(200).type("text/plain").end(`OK ${out.accId} ${out.numero}`);
  }catch(e){
    res.status(500).type("text/plain").end("ERROR "+String(e));
  }
});

// ===== API REST por token =====
app.post("/api/v1/:token/send", async (req,res)=>{
  try{
    const u = getUserByToken(req.params.token||""); if(!u) return res.status(401).json({error:"token inválido"});
    const account_id = Number(req.body.account||0);
    const acc = getAccount(account_id);
    if(!acc || (u.role!=="master" && acc.user_id !== u.id)) return res.status(404).json({error:"conta não encontrada"});
    const to = req.body.to || req.body.numero;
    const msg = req.body.message || req.body.mensagem;
    const out = await sendWhatsAppFromAccount(account_id, to, msg);
    res.json(out);
  }catch(e){ res.status(500).json({error:String(e)}); }
});
app.get("/api/v1/:token/threads", (req,res)=>{
  const u = getUserByToken(req.params.token||""); if(!u) return res.status(401).json([]);
  const account_id = Number(req.query.account||0);
  const acc = getAccount(account_id);
  if(!acc || (u.role!=="master" && acc.user_id !== u.id)) return res.status(404).json([]);
  res.json(listThreads(u, account_id));
});
app.get("/api/v1/:token/thread", (req,res)=>{
  const u = getUserByToken(req.params.token||""); if(!u) return res.status(401).json([]);
  const account_id = Number(req.query.account||0);
  const acc = getAccount(account_id);
  if(!acc || (u.role!=="master" && acc.user_id !== u.id)) return res.status(404).json([]);
  const numero = String(req.query.numero||"").replace(/[^0-9]/g,"").replace(/^0+/,"");
  res.json(getThread(u, account_id, numero));
});

// ===== Socket.IO =====
io.on("connection", (socket)=>{
  socket.on("join", ({accId})=>{
    if(!accId) return;
    socket.join(room(accId));
    socket.emit("joined", {accId});
  });
  socket.on("disconnect", ()=>{});
});

// ===== Start HTTP =====
const PORT = 3000;
server.listen(PORT, ()=> log.info({PORT}, "HTTP on"));
JS
  sed -i 's/\r$//' "${APP_DIR}/server.js"
}

random_alnum() {
  python3 - "$1" <<'PY'
import secrets, string, sys
n = int(sys.argv[1])
alphabet = string.ascii_letters + string.digits
print(''.join(secrets.choice(alphabet) for _ in range(n)))
PY
}

random_hex() {
  python3 - "$1" <<'PY'
import secrets, sys
n = int(sys.argv[1])
print(secrets.token_hex(n))
PY
}

write_systemd_unit() {
  local rb_token cookie_secret
  rb_token="$(random_alnum 28)"
  cookie_secret="$(random_hex 32)"

  mkdir -p "$(dirname "${LOG_FILE}")"
  touch "${LOG_FILE}"

  log "Criando serviço systemd..."
  cat > /etc/systemd/system/whatsweb.service <<EOF
[Unit]
Description=WhatsWeb (Baileys + SQLite + Multiusuarios + Webhook + API + MASTER + RB)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
Environment=NODE_ENV=production
Environment=MASTER_EMAIL=provedor@provedor
Environment=MASTER_PASSWORD=provedor
Environment=RB_TOKEN=${rb_token}
Environment=COOKIE_SECRET=${cookie_secret}
ExecStart=/usr/bin/bash -lc 'exec /usr/local/bin/node --trace-uncaught ${APP_DIR}/server.js >> ${LOG_FILE} 2>&1'
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now whatsweb

  export RB_TOKEN_GENERATED="${rb_token}"
}

install_app_deps() {
  log "Instalando dependências do sistema..."
  apt-get install -y --no-install-recommends     ca-certificates curl gnupg xz-utils build-essential python3 make g++     chrony ufw libsqlite3-dev pkg-config git

  log "Ajustando fuso horário e NTP..."
  timedatectl set-timezone "${TZ}" || true
  systemctl enable --now chrony || true
  chronyc tracking || true

  mkdir -p "${APP_DIR}"
  cd "${APP_DIR}"
  [ -f package.json ] || npm init -y >/dev/null

  log "Limpando instalação anterior do npm..."
  rm -rf node_modules package-lock.json
  npm cache clean --force >/dev/null 2>&1 || true

  log "Instalando pacotes Node..."
  npm install     @whiskeysockets/baileys     socket.io     express     qrcode     better-sqlite3     pino     cors     cookie-parser     nanoid@3     axios     --omit=dev     --no-audit     --no-fund

  log "Rebuild opcional do better-sqlite3..."
  npm rebuild better-sqlite3 --unsafe-perm || true
}

show_summary() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [ -z "${ip}" ] && ip="SEU_IP_DO_SERVIDOR"

  echo "======================================================="
  echo "✅ WhatsWeb instalado/corrigido"
  echo "   Register:  http://${ip}:3000/register"
  echo "   Dashboard: http://${ip}:3000/dashboard"
  echo "   RB_TOKEN:  ${RB_TOKEN_GENERATED:-não disponível}"
  echo "-------------------------------------------------------"
  systemctl --no-pager --full status whatsweb | sed -n '1,80p' || true
  echo "---------------- Últimas 80 linhas de log ----------------"
  tail -n 80 "${LOG_FILE}" || true
  echo "======================================================="
}

main() {
  log "Parando serviço antigo e liberando porta 3000..."
  systemctl stop whatsweb 2>/dev/null || true
  fuser -k 3000/tcp 2>/dev/null || true

  log "Removendo repositório antigo da NodeSource, se existir..."
  cleanup_old_nodesource

  log "Atualizando índices do APT..."
  apt_update_safe

  ensure_node
  install_app_deps
  write_server_js
  write_systemd_unit

  log "Liberando porta 3000 no firewall..."
  ufw allow 3000/tcp || true

  show_summary
}

main "$@"
