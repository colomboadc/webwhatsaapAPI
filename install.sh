#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
TZ="${TZ:-America/Sao_Paulo}"
APP_DIR="/opt/whatsweb"
LOG_FILE="/var/log/whatsweb.log"
NODE_VERSION="${NODE_VERSION:-v20.20.2}"

log(){ echo ">>> $*"; }
warn(){ echo ">>> [AVISO] $*" >&2; }
die(){ echo ">>> [ERRO] $*" >&2; exit 1; }

cleanup_old_nodesource(){
  rm -f /etc/apt/sources.list.d/nodesource.list \
        /etc/apt/sources.list.d/nodesource.sources \
        /etc/apt/preferences.d/nodejs \
        /etc/apt/keyrings/nodesource.gpg \
        /usr/share/keyrings/nodesource.gpg \
        /usr/share/keyrings/nodesource.gpg.key \
        /etc/apt/trusted.gpg.d/nodesource.gpg || true
}

apt_repair(){ dpkg --configure -a || true; apt-get -f install -y || true; }
apt_update_safe(){
  if ! apt-get -o Acquire::Retries=3 update; then
    warn "apt update falhou; reparando e limpando NodeSource antigo..."
    apt_repair
    cleanup_old_nodesource
    apt-get -o Acquire::Retries=3 update
  fi
}

detect_node_arch(){
  case "$(uname -m)" in
    x86_64|amd64) echo "x64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7) echo "armv7l" ;;
    *) die "Arquitetura não suportada automaticamente: $(uname -m)" ;;
  esac
}

install_node_official(){
  local arch tmpdir node_dir tarball url
  arch="$(detect_node_arch)"
  tmpdir="$(mktemp -d)"
  node_dir="/usr/local/lib/nodejs/node-${NODE_VERSION}-linux-${arch}"
  tarball="node-${NODE_VERSION}-linux-${arch}.tar.xz"
  url="https://nodejs.org/dist/${NODE_VERSION}/${tarball}"
  log "Instalando Node.js oficial ${NODE_VERSION} (${arch})..."
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

ensure_node(){
  if command -v node >/dev/null 2>&1; then log "Node atual: $(node -v 2>/dev/null || true)"; fi
  apt-get purge -y nodejs npm || true
  apt-get autoremove -y || true
  install_node_official
  node -v
  npm -v
  npm config set fund false --global || true
  npm config set audit false --global || true
}

backup_existing(){
  mkdir -p "${APP_DIR}" /root/whatsweb_backups
  if [ -f "${APP_DIR}/server.js" ]; then cp "${APP_DIR}/server.js" "/root/whatsweb_backups/server.js.$(date +%F_%H%M%S).bak" || true; fi
  if [ -f "${APP_DIR}/whatsweb.db" ]; then cp "${APP_DIR}/whatsweb.db" "/root/whatsweb_backups/whatsweb.db.$(date +%F_%H%M%S).bak" || true; fi
  if [ -f /etc/systemd/system/whatsweb.service ]; then cp /etc/systemd/system/whatsweb.service "/root/whatsweb_backups/whatsweb.service.$(date +%F_%H%M%S).bak" || true; fi
}

write_server_js(){
  log "Gravando server.js corrigido e funcional..."
  mkdir -p "${APP_DIR}"
  cat > "${APP_DIR}/server.js" <<'JS'
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
const Database = require("better-sqlite3");
const { default: makeWASocket, useMultiFileAuthState, fetchLatestBaileysVersion, DisconnectReason } = require("@whiskeysockets/baileys");

const log = pino({ level: process.env.LOG_LEVEL || "info" });
const app = express();
const server = http.createServer(app);
const io = new IOServer(server, { cors:{origin:"*"}, transports:["websocket","polling"] });
const db = new Database(path.join(__dirname, "whatsweb.db"));
db.pragma("journal_mode = WAL");
db.pragma("busy_timeout = 5000");

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
  wa_jid TEXT,
  push_name TEXT,
  ts INTEGER DEFAULT (strftime('%s','now')*1000)
);
CREATE INDEX IF NOT EXISTS idx_msg_user_acc ON messages(user_id, account_id, ts);
CREATE INDEX IF NOT EXISTS idx_msg_num ON messages(account_id, numero, ts);
CREATE INDEX IF NOT EXISTS idx_msg_wajid ON messages(account_id, wa_jid, ts);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_msg_waid_acc ON messages(account_id, wa_id) WHERE wa_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS webhooks(
  user_id INTEGER PRIMARY KEY,
  url TEXT,
  secret TEXT
);
CREATE TABLE IF NOT EXISTS lid_links(
  account_id INTEGER,
  lid_numero TEXT,
  real_numero TEXT,
  updated_at INTEGER,
  PRIMARY KEY(account_id, lid_numero)
);
`);

function ensureColumns(){
  const cols = db.prepare("PRAGMA table_info(messages)").all().map(c=>c.name);
  if(!cols.includes("wa_jid")) db.prepare("ALTER TABLE messages ADD COLUMN wa_jid TEXT").run();
  if(!cols.includes("push_name")) db.prepare("ALTER TABLE messages ADD COLUMN push_name TEXT").run();
  const ucols = db.prepare("PRAGMA table_info(users)").all().map(c=>c.name);
  if(!ucols.includes("role")) db.prepare("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'").run();
}
try{ ensureColumns(); }catch(e){ console.error("Erro migração:", e); }

function now(){ return Math.floor(Date.now()/1000); }
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
    const info = db.prepare("INSERT INTO users (email, passhash, apitoken, role) VALUES (?,?,?,?)").run(email, passhash, apitoken, role);
    return info.lastInsertRowid;
  }catch{
    const u = getUserByEmail(email);
    if(u){ db.prepare("UPDATE users SET role=? WHERE id=?").run(role, u.id); return u.id; }
    return null;
  }
}
function getUserByEmail(email){ return db.prepare("SELECT * FROM users WHERE email=?").get(email); }
function getUserById(id){ return db.prepare("SELECT * FROM users WHERE id=?").get(id); }
function getUserByToken(token){ return db.prepare("SELECT * FROM users WHERE apitoken=?").get(token); }
function listAllUsers(){ return db.prepare("SELECT id,email,role,created_at FROM users ORDER BY id ASC").all(); }
function emailExistsForOtherUser(email, id){ return !!db.prepare("SELECT 1 FROM users WHERE email=? AND id<>?").get(email, id); }
function updateUserEmail(id, email){ return db.prepare("UPDATE users SET email=? WHERE id=?").run(email, id); }
function updateUserPassword(id, password){ return db.prepare("UPDATE users SET passhash=? WHERE id=?").run(hashPassword(password), id); }
function updateUserRole(id, role){ return db.prepare("UPDATE users SET role=? WHERE id=?").run(role === "master" ? "master" : "user", id); }
function deleteUserFull(uid){
  const accounts = db.prepare("SELECT id FROM accounts WHERE user_id=?").all(uid);
  db.prepare("DELETE FROM sessions WHERE user_id=?").run(uid);
  db.prepare("DELETE FROM messages WHERE user_id=?").run(uid);
  db.prepare("DELETE FROM webhooks WHERE user_id=?").run(uid);
  db.prepare("DELETE FROM accounts WHERE user_id=?").run(uid);
  db.prepare("DELETE FROM users WHERE id=?").run(uid);
  for(const a of accounts){
    try{ WA.sockets.get(a.id)?.logout?.(); }catch{}
    try{ WA.sockets.delete(a.id); WA.ready.delete(a.id); WA.qrs.delete(a.id); }catch{}
    try{ fs.rmSync(path.join(__dirname,"auth","account_"+a.id),{recursive:true,force:true}); }catch{}
  }
}
function newSession(user_id){
  const token = nanoid(48), expires = now() + 60*60*24*7;
  db.prepare("INSERT INTO sessions (user_id, token, expires) VALUES (?,?,?)").run(user_id, token, expires);
  return {token, expires};
}
function sessionFromToken(tok){ const s=db.prepare("SELECT * FROM sessions WHERE token=?").get(tok); return (!s || s.expires < now()) ? null : s; }
function destroySession(tok){ db.prepare("DELETE FROM sessions WHERE token=?").run(tok); }

(function ensureMaster(){
  const email = process.env.MASTER_EMAIL || "provedor@provedor";
  const password = process.env.MASTER_PASSWORD || "provedor";
  const token = process.env.MASTER_TOKEN || null;
  const exists = getUserByEmail(email);
  if(exists){ if(exists.role !== "master") db.prepare("UPDATE users SET role='master' WHERE id=?").run(exists.id); }
  else createUser(email, password, "master", token);
})();

function listAccountsFor(user){
  if(user.role === "master") return db.prepare("SELECT * FROM accounts ORDER BY id DESC").all();
  return db.prepare("SELECT * FROM accounts WHERE user_id=? ORDER BY id DESC").all(user.id);
}
function createAccount(user_id, label){ return db.prepare("INSERT INTO accounts (user_id,label) VALUES (?,?)").run(user_id, label||"Minha conta").lastInsertRowid; }
function getAccount(accId){ return db.prepare("SELECT * FROM accounts WHERE id=?").get(accId); }
function canUseAccount(user, acc){ return !!acc && (user.role === "master" || acc.user_id === user.id); }
function getWebhook(user_id){ return db.prepare("SELECT * FROM webhooks WHERE user_id=?").get(user_id) || {user_id, url:null, secret:null}; }
function setWebhook(user_id, url, secret){
  db.prepare("INSERT INTO webhooks (user_id,url,secret) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET url=excluded.url, secret=excluded.secret")
    .run(user_id, url||null, secret||null);
}

function jidUser(jid){ return String(jid||"").split("@")[0].replace(/[^0-9]/g,"").replace(/^0+/,""); }
function isIgnoredJid(jid){ jid=String(jid||""); return !jid || jid.endsWith("@g.us") || jid.endsWith("@broadcast") || jid.endsWith("@newsletter") || jid === "status@broadcast"; }
function normalizeNumeroFromJid(jid, pushName=""){
  const raw = jidUser(jid);
  if(String(jid).endsWith("@lid")) return raw ? `lid_${raw}` : `contato_${safeName(pushName)}`;
  return raw || `contato_${safeName(pushName)}`;
}
function isPhoneJid(jid){ return String(jid || "").endsWith("@s.whatsapp.net"); }
function isLidJid(jid){ return String(jid || "").endsWith("@lid"); }
function extractBestIdentity(account_id, m){
  const k = m.key || {};
  const pushName = m.pushName || "";

  // O Baileys/WhatsApp pode entregar o contato como @lid.
  // Quando existir campo alternativo com telefone real, ele deve ganhar prioridade.
  const candidates = [
    k.remoteJidAlt,
    k.participantAlt,
    k.senderPn,
    k.participantPn,
    k.remoteJid,
    k.participant,
    k.senderLid,
    k.participantLid
  ].filter(Boolean).map(String);

  const phoneJid = candidates.find(isPhoneJid) || "";
  const lidJid = candidates.find(isLidJid) || "";

  let replyJid = String(k.remoteJid || phoneJid || lidJid || "");
  if(isIgnoredJid(replyJid)) replyJid = phoneJid || lidJid || "";

  let numero = "";
  if(phoneJid){
    numero = jidUser(phoneJid);
  }else if(lidJid){
    numero = resolveLinkedNumero(account_id, normalizeNumeroFromJid(lidJid, pushName));
  }else{
    numero = normalizeNumeroFromJid(replyJid, pushName);
  }

  // Se a mesma mensagem trouxer LID e telefone, já grava o vínculo e renomeia histórico.
  if(lidJid && phoneJid){
    saveLidLink(account_id, normalizeNumeroFromJid(lidJid, pushName), jidUser(phoneJid));
    numero = jidUser(phoneJid);
  }

  return { numero, replyJid, phoneJid, lidJid, pushName };
}
function safeName(name){ return String(name||"sem_nome").replace(/[^a-zA-Z0-9À-ÿ._ -]/g,"").trim().replace(/\s+/g,"_").slice(0,40) || "sem_nome"; }
function cleanPhone(v){ return String(v||"").replace(/[^0-9]/g,"").replace(/^0+/,""); }
function cleanThreadId(v){
  v = String(v||"").trim();
  if(v.startsWith("lid_") || v.startsWith("contato_")) return v;
  return cleanPhone(v);
}
function resolveLinkedNumero(account_id, numero){
  numero = String(numero||"").trim();
  if(!numero.startsWith("lid_")) return numero;
  try{
    const row = db.prepare("SELECT real_numero FROM lid_links WHERE account_id=? AND lid_numero=? LIMIT 1").get(account_id, numero);
    if(row && row.real_numero) return row.real_numero;
  }catch(e){}
  return numero;
}
function saveLidLink(account_id, lid_numero, real_numero){
  lid_numero = String(lid_numero||"").trim();
  real_numero = cleanPhone(real_numero);
  if(!account_id || !lid_numero.startsWith("lid_") || !real_numero) return false;
  db.prepare(`INSERT INTO lid_links(account_id,lid_numero,real_numero,updated_at)
    VALUES(?,?,?,?)
    ON CONFLICT(account_id,lid_numero) DO UPDATE SET
      real_numero=excluded.real_numero,
      updated_at=excluded.updated_at`).run(account_id, lid_numero, real_numero, Date.now());
  db.prepare("UPDATE messages SET numero=? WHERE account_id=? AND numero=?").run(real_numero, account_id, lid_numero);
  return true;
}
function normalizeMessageObject(msg){
  let m = msg || {};
  for(let i=0;i<8;i++){
    if(m.ephemeralMessage?.message){ m=m.ephemeralMessage.message; continue; }
    if(m.viewOnceMessage?.message){ m=m.viewOnceMessage.message; continue; }
    if(m.viewOnceMessageV2?.message){ m=m.viewOnceMessageV2.message; continue; }
    if(m.documentWithCaptionMessage?.message){ m=m.documentWithCaptionMessage.message; continue; }
    break;
  }
  return m;
}
function extractTextMessage(message){
  const msg = normalizeMessageObject(message || {});
  const text = msg.conversation || msg.extendedTextMessage?.text || msg.imageMessage?.caption || msg.videoMessage?.caption || msg.documentMessage?.caption || msg.buttonsResponseMessage?.selectedDisplayText || msg.listResponseMessage?.title || msg.listResponseMessage?.singleSelectReply?.selectedRowId || msg.templateButtonReplyMessage?.selectedDisplayText || msg.reactionMessage?.text || "";
  if(String(text||"").trim()) return String(text).trim();
  if(msg.imageMessage) return "[imagem]";
  if(msg.audioMessage) return "[áudio]";
  if(msg.videoMessage) return "[vídeo]";
  if(msg.stickerMessage) return "[figurinha]";
  if(msg.documentMessage) return "[documento" + (msg.documentMessage.fileName ? ": " + msg.documentMessage.fileName : "") + "]";
  if(msg.contactMessage) return "[contato]";
  if(msg.contactsArrayMessage) return "[contatos]";
  if(msg.locationMessage) return "[localização]";
  if(msg.liveLocationMessage) return "[localização ao vivo]";
  return "";
}
function saveMessage({user_id, account_id, numero, direction, message, wa_id=null, ts=null, wa_jid=null, push_name=null}){
  const cleanMsg = String(message||"").trim();
  if(!cleanMsg) return false;
  let cleanNumero = cleanThreadId(numero);
  if(!cleanNumero) return false;
  cleanNumero = resolveLinkedNumero(account_id, cleanNumero);
  try{
    const info = db.prepare("INSERT OR IGNORE INTO messages (user_id,account_id,numero,direction,message,wa_id,ts,wa_jid,push_name) VALUES (?,?,?,?,?,?,?,?,?)")
      .run(user_id, account_id, cleanNumero, direction, cleanMsg, wa_id||null, ts||Date.now(), wa_jid||null, push_name||null);
    return info.changes > 0;
  }catch(e){ log.error({err:String(e)}, "saveMessage erro"); return false; }
}
function hasWaId(account_id, wa_id){ if(!wa_id) return false; return !!db.prepare("SELECT 1 FROM messages WHERE account_id=? AND wa_id=?").get(account_id, wa_id); }
function lookupReplyJid(account_id, numero){
  let n = cleanThreadId(numero);
  n = resolveLinkedNumero(account_id, n);
  if(!n) return "";
  let row = db.prepare("SELECT wa_jid FROM messages WHERE account_id=? AND numero=? AND wa_jid IS NOT NULL AND TRIM(wa_jid) != '' ORDER BY ts DESC LIMIT 1").get(account_id, n);
  if(row?.wa_jid) return row.wa_jid;
  const digits = n.replace(/^lid_/,"").replace(/[^0-9]/g,"").replace(/^0+/,"");
  if(digits){
    row = db.prepare("SELECT wa_jid FROM messages WHERE account_id=? AND numero=? AND wa_jid IS NOT NULL AND TRIM(wa_jid) != '' ORDER BY ts DESC LIMIT 1").get(account_id, digits);
    if(row?.wa_jid) return row.wa_jid;
  }
  return "";
}
function listThreads(user, account_id, limit=200){
  if(user.role === "master") return db.prepare("SELECT numero, MAX(ts) last_ts FROM messages WHERE account_id=? AND message IS NOT NULL AND TRIM(message) != '' GROUP BY numero ORDER BY last_ts DESC LIMIT ?").all(account_id, limit).map(r=>r.numero);
  return db.prepare("SELECT numero, MAX(ts) last_ts FROM messages WHERE user_id=? AND account_id=? AND message IS NOT NULL AND TRIM(message) != '' GROUP BY numero ORDER BY last_ts DESC LIMIT ?").all(user.id, account_id, limit).map(r=>r.numero);
}
function getThread(user, account_id, numero, limit=800){
  const n = String(numero||"").trim();
  if(user.role === "master") return db.prepare("SELECT numero,direction,message,ts,wa_jid,push_name FROM messages WHERE account_id=? AND numero=? AND message IS NOT NULL AND TRIM(message) != '' ORDER BY ts ASC LIMIT ?").all(account_id, n, limit);
  return db.prepare("SELECT numero,direction,message,ts,wa_jid,push_name FROM messages WHERE user_id=? AND account_id=? AND numero=? AND message IS NOT NULL AND TRIM(message) != '' ORDER BY ts ASC LIMIT ?").all(user.id, account_id, n, limit);
}

app.use(cors());
app.use(cookieParser(process.env.COOKIE_SECRET || "dev-secret"));
app.use(express.json({limit:"2mb"}));
app.use(express.urlencoded({extended:true}));
function requireAuth(req,res,next){
  const sid = req.signedCookies && req.signedCookies.sid;
  if(!sid) return res.redirect("/login");
  const s = sessionFromToken(sid);
  if(!s) return res.redirect("/login");
  req.user = getUserById(s.user_id);
  if(!req.user) return res.redirect("/login");
  req.sessionToken = sid; next();
}

const WA = { sockets:new Map(), ready:new Map(), qrs:new Map() };
function room(accId){ return `acc_${accId}`; }
async function startWAForAccount(account){
  const accId = account.id;
  if(WA.sockets.has(accId)) return;
  const authDir = path.join(__dirname, "auth", "account_"+accId);
  fs.mkdirSync(authDir, {recursive:true});
  const { state, saveCreds } = await useMultiFileAuthState(authDir);
  let version = [2,3000,0];
  try{ const latest = await fetchLatestBaileysVersion(); if(latest?.version) version = latest.version; }catch(e){ log.warn({err:String(e)}, "Baileys version fallback"); }
  const sock = makeWASocket({ version, auth:state, logger:pino({level:"silent"}), printQRInTerminal:false, browser:["WhatsWeb ZVN Colombo","Chrome","1.0"], syncFullHistory:false, markOnlineOnConnect:false });
  WA.sockets.set(accId, sock); WA.ready.set(accId, false);
  sock.ev.on("creds.update", saveCreds);
  sock.ev.on("connection.update", (u)=>{
    const {connection, qr, lastDisconnect} = u || {};
    if(qr){ WA.qrs.set(accId, qr); WA.ready.set(accId,false); io.to(room(accId)).emit("wa-status",{accId,status:"qr",ready:false}); }
    if(connection === "open"){ WA.ready.set(accId,true); WA.qrs.delete(accId); io.to(room(accId)).emit("wa-status",{accId,status:"ready",ready:true}); log.info({accId}, "WhatsApp conectado"); }
    if(connection === "close"){
      WA.ready.set(accId,false); io.to(room(accId)).emit("wa-status",{accId,status:"disconnected",ready:false});
      WA.sockets.delete(accId);
      log.warn({accId,lastDisconnect}, "WhatsApp desconectado; reconectando");
      setTimeout(()=>startWAForAccount(account).catch(e=>log.error({err:String(e),accId},"reconnect erro")), 2500);
    }
  });
  sock.ev.on("messages.upsert", async (ev)=>{
    try{
      const arr = ev.messages || [];
      log.info({accId,type:ev.type,count:arr.length}, "messages.upsert recebido");
      for(const m of arr){
        if(!m || !m.key) continue;
        const acc = getAccount(accId); if(!acc) continue;
        const ident = extractBestIdentity(accId, m);
        const jid = ident.replyJid;
        if(isIgnoredJid(jid)) continue;
        const texto = extractTextMessage(m.message || {});
        if(!String(texto||"").trim()) continue;
        const wa_id = m.key.id || null;
        if(wa_id && hasWaId(accId, wa_id)) continue;
        const numero = ident.numero;
        const direction = m.key.fromMe ? "sent" : "received";
        const ts = Number(m.messageTimestamp) ? Number(m.messageTimestamp)*1000 : Date.now();
        const inserted = saveMessage({user_id:acc.user_id, account_id:accId, numero, direction, message:String(texto), wa_id, ts, wa_jid:jid, push_name:ident.pushName||""});
        if(inserted){
          const payload = {accId, numero, message:String(texto), ts, source:"baileys"};
          io.to(room(accId)).emit(direction === "sent" ? "sent" : "recv", payload);
          io.to(room(accId)).emit("threads-update", {accId, numero, ts});
          log.info({accId,numero,jid,direction,texto:String(texto).slice(0,80)}, "mensagem salva");
          if(direction === "received"){
            const wh = getWebhook(acc.user_id);
            if(wh?.url){
              const body = JSON.stringify({event:"message.received", accountId:accId, from:numero, text:String(texto), ts});
              const headers = {"Content-Type":"application/json"};
              if(wh.secret) headers["X-Signature"] = crypto.createHmac("sha256", wh.secret).update(body).digest("hex");
              axios.post(wh.url, body, {headers}).catch(e=>log.error({err:String(e)}, "webhook post"));
            }
          }
        }
      }
    }catch(e){ log.error({err:String(e), stack:e?.stack}, "messages.upsert erro"); }
  });
}
async function sendWhatsAppFromAccount(accId, numeroRaw, message){
  const raw = String(numeroRaw||"").trim();
  const msg = String(message||"").trim();
  if(!raw || !msg) throw new Error("numero/mensagem inválidos");
  const acc = getAccount(accId); if(!acc) throw new Error("Conta inexistente");
  await startWAForAccount(acc);
  const sock = WA.sockets.get(accId);
  if(!sock || !WA.ready.get(accId)) throw new Error("WhatsApp não está pronto (abra /auth/"+accId+")");
  let destinoJid = raw.includes("@") ? raw : (lookupReplyJid(accId, raw) || "");
  if(!destinoJid){
    const digits = raw.replace(/[^0-9]/g,"").replace(/^0+/,"");
    if(digits) destinoJid = `${digits}@s.whatsapp.net`;
  }
  if(!destinoJid) throw new Error("Não encontrei o destino da conversa");
  const sent = await sock.sendMessage(destinoJid, {text:msg});
  const wa_id = sent?.key?.id || null;
  const numero = raw.includes("@") ? normalizeNumeroFromJid(raw) : raw;
  saveMessage({user_id:acc.user_id, account_id:accId, numero, direction:"sent", message:msg, wa_id, ts:Date.now(), wa_jid:destinoJid});
  io.to(room(accId)).emit("sent", {accId, numero, message:msg, ts:Date.now()});
  io.to(room(accId)).emit("threads-update", {accId, numero, ts:Date.now()});
  return {ok:true, accId, numero, jid:destinoJid, driver:"baileys"};
}
function startAllExistingAccounts(){
  try{ const accounts = db.prepare("SELECT * FROM accounts ORDER BY id ASC").all(); accounts.forEach(acc=>startWAForAccount(acc).catch(e=>log.error({err:String(e),accId:acc.id},"start conta erro"))); log.info({count:accounts.length}, "contas WhatsApp iniciadas"); }
  catch(e){ log.error({err:String(e)}, "startAllExistingAccounts erro"); }
}

function head(title){ return `
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
<style>
:root{
  --bg:#050713;
  --bg2:#07112d;
  --card:rgba(255,255,255,.075);
  --card2:rgba(255,255,255,.045);
  --line:rgba(255,255,255,.14);
  --line2:rgba(64,221,255,.22);
  --text:#eef6ff;
  --muted:#a9b7d8;
  --cyan:#23d5ff;
  --blue:#3b82f6;
  --violet:#7c3aed;
  --pink:#ff2fb3;
  --green:#22c55e;
  --red:#ef4444;
  --shadow:0 24px 90px rgba(0,0,0,.48);
  --radius:24px;
}
*{box-sizing:border-box}
html,body{min-height:100%}
body{
  margin:0;
  color:var(--text);
  font-family:Inter,Segoe UI,Roboto,Ubuntu,system-ui,Arial,sans-serif;
  background:
    radial-gradient(circle at 12% 8%, rgba(35,213,255,.24), transparent 30%),
    radial-gradient(circle at 88% 4%, rgba(255,47,179,.22), transparent 32%),
    radial-gradient(circle at 50% 115%, rgba(124,58,237,.30), transparent 38%),
    linear-gradient(135deg,#030615 0%,#08132f 48%,#10051f 100%);
  overflow-x:hidden;
}
body::before{
  content:"";
  position:fixed;
  inset:0;
  z-index:-2;
  opacity:.42;
  background-image:
    linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px);
  background-size:44px 44px;
  mask-image:radial-gradient(circle at center, black 0%, transparent 76%);
}
body::after{
  content:"";
  position:fixed;
  width:540px;
  height:540px;
  right:-180px;
  bottom:-180px;
  z-index:-1;
  border-radius:50%;
  background:conic-gradient(from 180deg, rgba(35,213,255,.34), rgba(124,58,237,.30), rgba(255,47,179,.30), rgba(35,213,255,.34));
  filter:blur(55px);
  animation:floatGlow 11s ease-in-out infinite alternate;
}
@keyframes floatGlow{from{transform:translate3d(0,0,0) scale(1)}to{transform:translate3d(-70px,-35px,0) scale(1.12)}}
.container{width:min(1240px,100%);margin:26px auto;padding:0 18px}
.card{
  position:relative;
  background:linear-gradient(180deg,var(--card),var(--card2));
  border:1px solid var(--line);
  border-radius:var(--radius);
  box-shadow:var(--shadow);
  padding:20px;
  min-width:0;
  overflow:hidden;
  backdrop-filter:blur(18px) saturate(130%);
}
.card::before{
  content:"";
  position:absolute;
  inset:0;
  pointer-events:none;
  background:linear-gradient(135deg, rgba(35,213,255,.13), transparent 28%, transparent 70%, rgba(255,47,179,.11));
}
.card>*{position:relative;min-width:0}
h1,h2,h3{letter-spacing:-.025em}
h1{
  font-size:32px;
  line-height:1.05;
  margin:0 0 12px;
  background:linear-gradient(90deg,#fff 0%,#b8f4ff 32%,#bda2ff 62%,#ff9adc 100%);
  -webkit-background-clip:text;
  -webkit-text-fill-color:transparent;
}
h2{margin:0 0 14px;font-size:22px;color:#f5fbff}
a{color:#9eefff}
a.btn,button,.btn{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  gap:8px;
  padding:11px 15px;
  border-radius:15px;
  border:1px solid rgba(255,255,255,.16);
  background:linear-gradient(135deg,rgba(35,213,255,.20),rgba(124,58,237,.24) 55%,rgba(255,47,179,.18));
  color:#fff;
  text-decoration:none;
  cursor:pointer;
  font-weight:750;
  letter-spacing:.01em;
  box-shadow:0 12px 34px rgba(0,0,0,.30), inset 0 1px 0 rgba(255,255,255,.12);
  transition:transform .18s ease, box-shadow .18s ease, border-color .18s ease, filter .18s ease;
}
a.btn:hover,button:hover,.btn:hover{transform:translateY(-2px);filter:saturate(1.16);border-color:rgba(35,213,255,.45);box-shadow:0 18px 42px rgba(0,0,0,.38),0 0 34px rgba(35,213,255,.16)}
button:disabled,.btn:disabled{opacity:.55;cursor:not-allowed;transform:none}
input,select,textarea{
  width:100%;
  padding:13px 14px;
  border-radius:16px;
  border:1px solid rgba(255,255,255,.14);
  background:rgba(2,8,24,.72);
  color:var(--text);
  outline:none;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.06);
}
input:focus,select:focus,textarea:focus{border-color:rgba(35,213,255,.62);box-shadow:0 0 0 4px rgba(35,213,255,.10), inset 0 1px 0 rgba(255,255,255,.08)}
label{display:block;margin:12px 0 7px;color:#cbd7f6;font-size:13px;font-weight:750}
code{background:rgba(35,213,255,.10);border:1px solid rgba(35,213,255,.20);padding:2px 6px;border-radius:8px;color:#d9fbff;word-break:break-all}
hr{border:none;border-top:1px solid var(--line);margin:16px 0}
small,.muted{color:var(--muted)}
.badge{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:999px;background:rgba(35,213,255,.12);border:1px solid rgba(35,213,255,.22);font-size:12px;color:#d9fbff}
.badge::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 12px var(--green)}
.scroll{overflow:auto}.scroll::-webkit-scrollbar,::-webkit-scrollbar{height:10px;width:10px}.scroll::-webkit-scrollbar-thumb,::-webkit-scrollbar-thumb{background:rgba(255,255,255,.16);border-radius:999px}
.topbar{
  position:sticky;
  top:0;
  z-index:20;
  background:rgba(4,7,20,.72);
  backdrop-filter:blur(20px) saturate(160%);
  border-bottom:1px solid rgba(255,255,255,.10);
  box-shadow:0 18px 50px rgba(0,0,0,.28);
}
.topbar .wrap{max-width:1240px;margin:0 auto;padding:12px 18px;display:flex;align-items:center;gap:14px}
.logo{display:flex;align-items:center;gap:12px;font-weight:900;letter-spacing:.2px}
.logo .mark{width:42px;height:42px;border-radius:15px;display:grid;place-items:center;background:linear-gradient(135deg,var(--cyan),var(--violet),var(--pink));box-shadow:0 12px 35px rgba(124,58,237,.36);color:#fff;font-weight:950}
.logo .brand{display:flex;flex-direction:column;line-height:1.05}.logo .brand b{font-size:15px}.logo .brand span{font-size:11px;color:var(--muted);font-weight:700;letter-spacing:.12em;text-transform:uppercase}
.table{width:100%;border-collapse:separate;border-spacing:0 8px}.table th{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);padding:6px 10px;text-align:left}.table td{padding:12px 10px;background:rgba(255,255,255,.045);border-top:1px solid rgba(255,255,255,.08);border-bottom:1px solid rgba(255,255,255,.08)}.table tr td:first-child{border-left:1px solid rgba(255,255,255,.08);border-radius:14px 0 0 14px}.table tr td:last-child{border-right:1px solid rgba(255,255,255,.08);border-radius:0 14px 14px 0}
@media(max-width:760px){
  .container{margin:14px auto;padding:0 10px}.card{padding:15px;border-radius:20px}h1{font-size:24px}h2{font-size:19px}.topbar .wrap{flex-wrap:wrap}.topbar .wrap>div:last-child{margin-left:0!important;width:100%;display:grid;grid-template-columns:1fr}.logo .brand span{font-size:10px}a.btn,button,.btn{width:100%}.table th,.table td{white-space:nowrap}.card [style*="display:flex"]{flex-wrap:wrap}
}
</style>`; }
function topbar(){ return `<div class="topbar"><div class="wrap"><div class="logo"><div class="mark">Z</div><div class="brand"><b>ZVN COLOMBO</b><span>WhatsWeb • Central Tecnológica</span></div></div><div style="margin-left:auto;display:flex;gap:8px;align-items:center"><a class="btn" href="/dashboard">Painel</a><a class="btn" href="/commands">Comandos</a><a class="btn" href="/profile">Minha conta</a></div></div></div>`; }
function headerNav(){ return `<div style="display:flex;gap:10px;margin-bottom:14px;align-items:center;flex-wrap:wrap"><a class="btn" href="/dashboard">← Voltar ao painel</a></div>`; }

app.get("/", (req,res)=>res.redirect("/dashboard"));
app.get("/register", (req,res)=>res.type("html").send(`<!doctype html><html><head>${head("Registrar")}</head><body>${topbar()}<div class="container"><div class="card" style="max-width:520px;margin:10vh auto"><h1>Criar conta</h1><form method="post" action="/register" style="display:grid;gap:10px"><input name="email" type="email" placeholder="Email" required><input name="password" type="password" placeholder="Senha" minlength="6" required><input name="password2" type="password" placeholder="Confirmar senha" minlength="6" required><button>Criar</button><small>Já tem conta? <a href="/login">Entrar</a></small></form></div></div></body></html>`));
app.post("/register", (req,res)=>{ const {email,password,password2}=req.body||{}; if(!email||!password) return res.status(400).send("email/senha obrigatórios"); if(password!==password2) return res.status(400).send("as senhas não conferem"); if(getUserByEmail(email)) return res.status(400).send("email já registrado"); const uid=createUser(email,password,"user"); const {token}=newSession(uid); res.cookie("sid",token,{httpOnly:true,signed:true,sameSite:"lax"}); res.redirect("/dashboard"); });
app.get("/login", (req,res)=>res.type("html").send(`<!doctype html><html><head>${head("Login")}</head><body>${topbar()}<div class="container"><div class="card" style="max-width:520px;margin:10vh auto"><h1>Entrar</h1><form method="post" action="/login" style="display:grid;gap:10px"><input name="email" type="email" placeholder="Email" required><input name="password" type="password" placeholder="Senha" required><button>Login</button><small>Novo aqui? <a href="/register">Criar conta</a></small></form></div></div></body></html>`));
app.post("/login", (req,res)=>{ const {email,password}=req.body||{}; const u=getUserByEmail(email||""); if(!u || !verifyPassword(password||"",u.passhash)) return res.status(401).send("credenciais inválidas"); const {token}=newSession(u.id); res.cookie("sid",token,{httpOnly:true,signed:true,sameSite:"lax"}); res.redirect("/dashboard"); });
app.post("/logout", requireAuth, (req,res)=>{ if(req.sessionToken) destroySession(req.sessionToken); res.clearCookie("sid"); res.redirect("/login"); });
app.post("/user/delete", requireAuth, (req,res)=>{
  const uid=req.user.id;
  deleteUserFull(uid);
  res.clearCookie("sid");
  res.type("html").send(`<!doctype html><html><head>${head("Conta excluída")}</head><body>${topbar()}<div class="container"><div class="card" style="max-width:680px;margin:10vh auto"><h1>Conta excluída</h1><p class="muted">Seu usuário, sessões, contas WhatsApp e dados vinculados foram removidos.</p><a class="btn" href="/register">Criar nova conta</a></div></div></body></html>`);
});

app.get("/profile", requireAuth, (req,res)=>{
  res.type("html").send(`<!doctype html><html><head>${head("Minha conta")}<style>.profile-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.danger{background:linear-gradient(135deg,rgba(239,68,68,.22),rgba(255,47,179,.16))!important;border-color:rgba(239,68,68,.35)!important}@media(max-width:900px){.profile-grid{grid-template-columns:1fr}}</style></head><body>${topbar()}<div class="container">${headerNav()}<div class="card" style="margin-bottom:16px"><h1>Minha conta</h1><p class="muted">Gerencie o e-mail de acesso, senha e dados do usuário do painel.</p><span class="badge">ID ${req.user.id}</span> <span class="badge">${req.user.role}</span></div><div class="profile-grid"><div class="card"><h2>Editar usuário</h2><form method="post" action="/profile/email" style="display:grid;gap:8px"><label>E-mail de acesso</label><input name="email" type="email" value="${req.user.email}" required><button>Salvar e-mail</button></form><hr><h2>Alterar senha</h2><form method="post" action="/profile/password" style="display:grid;gap:8px"><label>Senha atual</label><input name="current" type="password" required><label>Nova senha</label><input name="password" type="password" minlength="6" required><label>Confirmar nova senha</label><input name="password2" type="password" minlength="6" required><button>Alterar senha</button></form></div><div class="card"><h2>Zona de segurança</h2><p class="muted">A exclusão remove usuário, sessões, contas WhatsApp cadastradas por este usuário, mensagens e webhooks.</p><form method="post" action="/user/delete" onsubmit="return confirm('Excluir definitivamente este usuário e todos os dados vinculados?');"><button class="danger">Excluir meu usuário</button></form>${req.user.role==='master'?'<hr><h2>Administração</h2><p class="muted">Como MASTER, você pode gerenciar usuários criados no painel.</p><a class="btn" href="/admin/users">Gerenciar usuários</a>':''}</div></div></div></body></html>`);
});

app.post("/profile/email", requireAuth, (req,res)=>{
  const email=String(req.body.email||"").trim().toLowerCase();
  if(!email || !email.includes("@")) return res.status(400).send("E-mail inválido");
  if(emailExistsForOtherUser(email, req.user.id)) return res.status(400).send("Este e-mail já está em uso");
  updateUserEmail(req.user.id, email);
  res.redirect("/profile");
});

app.post("/profile/password", requireAuth, (req,res)=>{
  const {current,password,password2}=req.body||{};
  const fresh=getUserById(req.user.id);
  if(!fresh || !verifyPassword(current||"", fresh.passhash)) return res.status(401).send("Senha atual incorreta");
  if(!password || String(password).length<6) return res.status(400).send("A nova senha precisa ter no mínimo 6 caracteres");
  if(password!==password2) return res.status(400).send("As senhas não conferem");
  updateUserPassword(req.user.id, password);
  db.prepare("DELETE FROM sessions WHERE user_id=? AND token<>?").run(req.user.id, req.sessionToken||"");
  res.redirect("/profile");
});

app.get("/admin/users", requireAuth, (req,res)=>{
  if(req.user.role!=="master") return res.status(403).send("Acesso negado");
  const users=listAllUsers();
  res.type("html").send(`<!doctype html><html><head>${head("Usuários")}<style>.users-grid{display:grid;gap:14px}.user-card{display:grid;grid-template-columns:80px minmax(180px,1fr) 150px 1.4fr;gap:10px;align-items:end;padding:14px;border:1px solid rgba(255,255,255,.12);border-radius:18px;background:rgba(255,255,255,.05)}.danger{background:linear-gradient(135deg,rgba(239,68,68,.24),rgba(255,47,179,.15))!important;border-color:rgba(239,68,68,.40)!important}@media(max-width:1000px){.user-card{grid-template-columns:1fr}}</style></head><body>${topbar()}<div class="container">${headerNav()}<div class="card" style="margin-bottom:16px"><h1>Gerenciar usuários</h1><p class="muted">Edite e-mail, senha, perfil e exclua usuários do painel. O usuário MASTER não deve ser removido se for o único administrador.</p></div><div class="users-grid">${users.map(u=>`<div class="user-card"><div><label>ID</label><code>${u.id}</code></div><form method="post" action="/admin/users/${u.id}/update" style="display:contents"><div><label>E-mail</label><input name="email" type="email" value="${u.email}" required></div><div><label>Perfil</label><select name="role"><option value="user" ${u.role==='user'?'selected':''}>user</option><option value="master" ${u.role==='master'?'selected':''}>master</option></select></div><div><label>Nova senha opcional</label><input name="password" type="password" minlength="6" placeholder="Deixe vazio para manter"><div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap"><button>Salvar</button></form><form method="post" action="/admin/users/${u.id}/delete" onsubmit="return confirm('Excluir usuário ${u.email} e todos os dados vinculados?');"><button class="danger" ${u.id===req.user.id?'disabled title="Não exclua seu próprio usuário por aqui"':''}>Excluir</button></form></div></div></div>`).join("")}</div></div></body></html>`);
});

app.post("/admin/users/:id/update", requireAuth, (req,res)=>{
  if(req.user.role!=="master") return res.status(403).send("Acesso negado");
  const id=Number(req.params.id||0);
  const target=getUserById(id); if(!target) return res.status(404).send("Usuário não encontrado");
  const email=String(req.body.email||"").trim().toLowerCase();
  if(!email || !email.includes("@")) return res.status(400).send("E-mail inválido");
  if(emailExistsForOtherUser(email, id)) return res.status(400).send("Este e-mail já está em uso");
  updateUserEmail(id,email);
  updateUserRole(id, req.body.role);
  const pw=String(req.body.password||"");
  if(pw){ if(pw.length<6) return res.status(400).send("Senha mínima: 6 caracteres"); updateUserPassword(id,pw); db.prepare("DELETE FROM sessions WHERE user_id=?").run(id); }
  res.redirect("/admin/users");
});

app.post("/admin/users/:id/delete", requireAuth, (req,res)=>{
  if(req.user.role!=="master") return res.status(403).send("Acesso negado");
  const id=Number(req.params.id||0);
  if(id===req.user.id) return res.status(400).send("Não exclua seu próprio usuário por aqui. Use Minha conta.");
  const target=getUserById(id); if(!target) return res.status(404).send("Usuário não encontrado");
  const masters=db.prepare("SELECT COUNT(*) c FROM users WHERE role='master'").get().c;
  if(target.role==='master' && masters<=1) return res.status(400).send("Não é possível excluir o único usuário MASTER.");
  deleteUserFull(id);
  res.redirect("/admin/users");
});

app.get("/dashboard", requireAuth, (req,res)=>{
  const accounts=listAccountsFor(req.user), api=req.user.apitoken, base=`${req.protocol}://${req.get("host")}`, wh=getWebhook(req.user.id);
  res.type("html").send(`<!doctype html><html><head>${head("Dashboard")}<style>.grid{display:grid;grid-template-columns:1.2fr .8fr;gap:16px}@media(max-width:1000px){.grid{grid-template-columns:1fr}}.kv{display:grid;grid-template-columns:120px 1fr;gap:6px 10px}.search{display:flex;gap:8px}</style></head><body>${topbar()}<div class="container grid"><div class="card"><div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap"><div><h1>Bem-vindo ao painel, ${req.user.email}${req.user.role==='master'?' <span class="badge">MASTER</span>':''}</h1><div class="kv"><div class="muted">Token API</div><div><code>${api}</code></div></div></div><div style="display:flex;gap:8px;flex-wrap:wrap"><a class="btn" href="/commands">Gerar Comandos</a><a class="btn" href="/profile">Minha conta</a>${req.user.role==='master'?'<a class="btn" href="/admin/users">Usuários</a>':''}<form method="post" action="/logout" style="display:inline"><button>Sair</button></form></div></div><hr><p class="muted">Endpoints:</p><div class="kv"><div>Enviar</div><div><code>POST ${base}/api/v1/${api}/send</code></div><div>Threads</div><div><code>GET ${base}/api/v1/${api}/threads?account=ID</code></div><div>RB</div><div><code>${base}/api/rb/&lt;TOKEN&gt;/send?account=ID&to=5511...&message=...</code></div></div></div><div class="card"><h2>Webhook</h2><form method="post" action="/settings/webhook" style="display:grid;gap:8px"><label>URL</label><input name="url" value="${wh.url||""}"><label>Segredo</label><input name="secret" value="${wh.secret||""}"><button>Salvar</button></form></div><div class="card" style="grid-column:1/-1"><h2>Contas WhatsApp conectadas</h2><form method="post" action="/accounts/new" class="search"><input name="label" placeholder="Nome da conta / setor" required><button>Criar conta</button></form><div class="scroll" style="margin-top:10px"><table class="table"><tr><th>ID</th><th>Nome</th><th>Dono</th><th>Ações</th></tr>${accounts.map(a=>`<tr><td>${a.id}</td><td>${a.label}</td><td>${a.user_id}</td><td style="display:flex;gap:8px;flex-wrap:wrap"><a class="btn" href="/auth/${a.id}">Autenticar (QR)</a><a class="btn" href="/chat/${a.id}">Abrir chat</a><form method="post" action="/accounts/${a.id}/delete" onsubmit="return confirm('Apagar conta #${a.id}? Isto remove credenciais e mensagens desta conta.');"><button>Excluir Conta</button></form></td></tr>`).join("")}</table></div></div></div></body></html>`);
});
app.post("/accounts/new", requireAuth, (req,res)=>{ const id=createAccount(req.user.id, req.body?.label || "Minha conta"); startWAForAccount({id,user_id:req.user.id}).catch(()=>{}); res.redirect("/dashboard"); });
app.post("/accounts/:accId/delete", requireAuth, (req,res)=>{ const accId=Number(req.params.accId), acc=getAccount(accId); if(!canUseAccount(req.user,acc)) return res.status(404).send("conta não encontrada"); try{ WA.sockets.get(accId)?.logout?.(); }catch{} WA.sockets.delete(accId); WA.ready.delete(accId); WA.qrs.delete(accId); db.prepare("DELETE FROM messages WHERE account_id=?").run(accId); db.prepare("DELETE FROM accounts WHERE id=?").run(accId); try{ fs.rmSync(path.join(__dirname,"auth","account_"+accId),{recursive:true,force:true}); }catch{} res.redirect("/dashboard"); });
app.post("/settings/webhook", requireAuth, (req,res)=>{ setWebhook(req.user.id, req.body.url, req.body.secret); res.redirect("/dashboard"); });

app.get("/status/:accId", requireAuth, (req,res)=>{ const accId=Number(req.params.accId), acc=getAccount(accId); if(!canUseAccount(req.user,acc)) return res.status(404).json({error:"conta não encontrada"}); startWAForAccount(acc).catch(()=>{}); const ready=!!WA.ready.get(accId); res.json({accId,status:ready?"ready":(WA.qrs.get(accId)?"qr":"starting"),ready}); });
app.get("/qr.png", requireAuth, async (req,res)=>{ const accId=Number(req.query.acc||0), acc=getAccount(accId); if(!canUseAccount(req.user,acc)) return res.status(404).end(); const qr=WA.qrs.get(accId); if(!qr) return res.status(204).end(); res.setHeader("Content-Type","image/png"); await QRCode.toFileStream(res, qr, {margin:1,width:600,errorCorrectionLevel:"H"}); });
app.get("/auth/:accId", requireAuth, (req,res)=>{ const accId=Number(req.params.accId), acc=getAccount(accId); if(!canUseAccount(req.user,acc)) return res.status(404).send("conta não encontrada"); startWAForAccount(acc).catch(()=>{}); res.type("html").send(`<!doctype html><html><head>${head("Autenticação")}<style>.qrwrap{display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 50% 50%,rgba(35,213,255,.13),rgba(3,8,22,.90));border-radius:24px;border:1px dashed rgba(35,213,255,.48);box-shadow:0 0 60px rgba(35,213,255,.10)}#qr{width:min(600px,100%);height:auto;display:none}.actions{display:flex;gap:10px;flex-wrap:wrap}</style></head><body>${topbar()}<div class="container card">${headerNav()}<h1>Autenticação — Conta #${accId} (${acc.label})</h1><div class="qrwrap"><img id="qr"><div id="empty" class="muted">QR indisponível (já autenticado ou iniciando)</div></div><div class="actions" style="margin-top:12px"><a class="btn" onclick="refresh(true)">Atualizar</a><a class="btn" href="/chat/${accId}">Ir para o chat</a></div><div class="muted">Status: <span id="st">starting</span> • Atualizado: <span id="ts">—</span></div></div><script>async function refresh(force){try{const s=await fetch('/status/${accId}'+(force?'?x='+Date.now():''));const v=await s.json();st.textContent=v.status;ts.textContent=new Date().toLocaleString();if(v.status==='qr'){qr.src='/qr.png?acc=${accId}&ts='+Date.now();qr.style.display='block';empty.style.display='none'}else{qr.style.display='none';empty.style.display='block'}}catch{st.textContent='erro'}}refresh(true);setInterval(refresh,2200);</script></body></html>`); });

app.get("/chat/:accId", requireAuth, (req,res)=>{
  const accId=Number(req.params.accId), acc=getAccount(accId); if(!canUseAccount(req.user,acc)) return res.status(404).send("conta não encontrada"); startWAForAccount(acc).catch(()=>{});
  res.type("html").send(`<!doctype html><html><head>${head("Chat")}<style>.chat{display:grid;grid-template-columns:360px minmax(0,1fr);gap:18px}@media(max-width:1100px){.chat{grid-template-columns:1fr}}.sidebar,.pane{background:linear-gradient(180deg,rgba(255,255,255,.085),rgba(255,255,255,.035));border:1px solid rgba(255,255,255,.14);border-radius:24px;box-shadow:var(--shadow);backdrop-filter:blur(18px)}.sidebar{display:flex;flex-direction:column;min-height:78vh}.pane{min-height:78vh;display:grid;grid-template-rows:auto 1fr auto}.header{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:14px 16px;border-bottom:1px solid var(--line)}.searchBox{padding:10px;border-bottom:1px solid var(--line)}.list{flex:1;overflow:auto;padding:10px;display:flex;flex-direction:column;gap:8px}.item{padding:12px;border-radius:16px;background:rgba(255,255,255,.055);border:1px solid rgba(255,255,255,.08);cursor:pointer;display:flex;justify-content:space-between;gap:10px;transition:.18s}.item:hover{background:rgba(35,213,255,.11);border-color:rgba(35,213,255,.32);transform:translateY(-1px)}.msgs{overflow-y:auto;padding:18px;display:flex;flex-direction:column;gap:8px;max-height:65vh;min-height:0}.bub{max-width:72%;padding:12px 14px;border-radius:16px;box-shadow:0 12px 24px rgba(0,0,0,.28)}.bub.in{align-self:flex-start;background:linear-gradient(180deg,rgba(31,45,104,.95),rgba(13,26,72,.95));border:1px solid rgba(35,213,255,.16)}.bub.out{align-self:flex-end;background:linear-gradient(135deg,rgba(13,148,136,.95),rgba(21,128,61,.92));border:1px solid rgba(74,222,128,.18)}.bub small{display:block;margin-top:6px;color:var(--muted)}.input{display:flex;gap:10px;padding:12px;border-top:1px solid var(--line)}.input input{flex:1}</style></head><body>${topbar()}<div class="container">${headerNav()}<div class="chat"><div class="sidebar"><div class="header"><div class="badge">Conta #${accId}</div><a class="btn" href="/auth/${accId}">Autenticar</a></div><div class="searchBox"><input id="numero" placeholder="Novo número"></div><div class="list" id="list"></div><div style="padding:10px"><a class="btn" style="width:100%" onclick="startChat()">Abrir conversa</a></div></div><div class="pane"><div class="header"><div id="title" class="muted">Selecione um contato</div><div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn" id="linkBtn" disabled>Vincular ID</button><button class="btn" id="delBtn" disabled>Excluir conversa</button></div></div><div id="msgs" class="msgs"></div><form class="input" onsubmit="sendMsg(event)"><input id="texto" placeholder="Digite sua mensagem..."><button>Enviar</button></form></div></div></div><script src="/socket.io/socket.io.js"></script><script>
const sock=io({transports:['websocket','polling']});const ACC=${accId};sock.emit('join',{accId:ACC});let current=null;const msgs=document.getElementById('msgs'),list=document.getElementById('list'),delBtn=document.getElementById('delBtn'),linkBtn=document.getElementById('linkBtn');
function norm(n){n=String(n||'').trim();if(n.startsWith('lid_')||n.startsWith('contato_'))return n;return n.replace(/[^0-9]/g,'').replace(/^0+/,'')}
function escapeHtml(v){return String(v||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function formatTime(ts){try{return new Date(ts||Date.now()).toLocaleTimeString()}catch{return''}}
function add(dir,txt,ts){if(!String(txt||'').trim())return;const b=document.createElement('div');b.className='bub '+(dir==='out'?'out':'in');b.innerHTML='<div>'+escapeHtml(txt)+'</div><small>'+formatTime(ts)+'</small>';msgs.appendChild(b);msgs.scrollTop=msgs.scrollHeight}
async function loadThreads(){const arr=await fetch('/api/threads?account='+ACC,{credentials:'same-origin'}).then(r=>r.json()).catch(()=>null);if(!Array.isArray(arr))return;list.innerHTML='';arr.forEach(num=>{const d=document.createElement('div');d.className='item';d.innerHTML='<div class="num">'+escapeHtml(num)+'</div><span class="badge">chat</span>';d.onclick=()=>openChat(num);list.appendChild(d)})}
async function openChat(n){const nn=norm(n);const t=await fetch('/api/thread?account='+ACC+'&numero='+encodeURIComponent(nn),{credentials:'same-origin'}).then(r=>r.json()).catch(()=>null);if(!Array.isArray(t))return;current=nn;delBtn.disabled=false;if(linkBtn)linkBtn.disabled=!String(nn).startsWith('lid_');title.textContent='Conversando com '+nn;msgs.innerHTML='';t.forEach(m=>add(m.direction==='sent'?'out':'in',m.message,m.ts))}
function startChat(){const n=norm(numero.value);if(!n)return;openChat(n)}
async function sendMsg(e){e.preventDefault();if(!current)return;const m=texto.value.trim();if(!m)return;texto.value='';try{const r=await fetch('/api/send?account='+ACC+'&numero='+encodeURIComponent(current)+'&message='+encodeURIComponent(m),{credentials:'same-origin'});const j=await r.json().catch(()=>({}));if(!r.ok||j.ok===false)alert('Falha ao enviar: '+(j.error||r.status));}catch(err){alert('Falha ao enviar: '+err)}setTimeout(()=>openChat(current),500);loadThreads()}
if(linkBtn){linkBtn.onclick=async()=>{if(!current||!String(current).startsWith('lid_'))return;const real=prompt('Digite o número real com DDI. Exemplo: 5516992870156');if(!real)return;const numero=String(real).replace(/[^0-9]/g,'').replace(/^0+/,'');if(!numero){alert('Número inválido.');return}try{const r=await fetch('/api/link-lid',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({account:ACC,lid:current,numero})});const j=await r.json();if(!j.ok)throw new Error(j.error||'erro');current=numero;await loadThreads();await openChat(numero);alert('ID vinculado ao número '+numero)}catch(e){alert('Falha ao vincular: '+e.message)}}}
delBtn.onclick=()=>{if(!current)return;if(!confirm('Excluir TODA a conversa com '+current+'?'))return;fetch('/api/delete-thread?account='+ACC+'&numero='+encodeURIComponent(current),{method:'POST',credentials:'same-origin'}).then(()=>{msgs.innerHTML='';current=null;delBtn.disabled=true;title.textContent='Selecione um contato';loadThreads()})};
sock.on('recv',d=>{if(d.accId!==ACC)return;const n=norm(d.numero);if(!current)openChat(n);else if(current===n)add('in',d.message,d.ts);loadThreads()});sock.on('sent',d=>{if(d.accId!==ACC)return;const n=norm(d.numero);if(current===n)add('out',d.message,d.ts);loadThreads()});sock.on('threads-update',d=>{if(d.accId===ACC)loadThreads()});loadThreads();setInterval(()=>{loadThreads();if(current)openChat(current)},5000);
</script></body></html>`);
});

app.get("/commands", requireAuth, (req,res)=>{
  const accounts = listAccountsFor(req.user);
  const baseApi = `${req.protocol}://${req.get("host")}/api/v1/`;
  const token = req.user.apitoken;

  res.type("html").send(`<!doctype html>
<html>
<head>
${head("Gerar Comandos")}
<style>
.cmd-grid{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,.95fr);gap:16px;align-items:start}
.cmd-formgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-bottom:10px}
.cmd-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px}
.cmd-code{background:#0a142b;border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-bottom:12px;min-width:0}
.cmd-code header{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:8px 10px;border-bottom:1px solid var(--line)}
.cmd-code h3{margin:0;font-size:14px;color:#d9f1ff}
.cmd-code pre{margin:0;padding:12px;white-space:pre-wrap;word-break:break-word;overflow:auto;max-height:270px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;line-height:1.45;color:#e5f7ff}
.copy-btn{width:auto;min-width:92px;justify-content:center}
@media(max-width:980px){.cmd-grid,.cmd-formgrid{grid-template-columns:1fr}}
@media(max-width:620px){.cmd-code header{flex-direction:column;align-items:stretch}.copy-btn{width:100%}.cmd-actions button{width:100%}}
</style>
</head>
<body>
${topbar()}
<div class="container">
  <div class="card" style="margin-bottom:16px">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <a class="btn" href="/dashboard">⬅ Voltar</a>
      <h1 style="margin:0">Gerar Comandos</h1>
    </div>
    <p class="muted" style="margin:10px 0 0">Seu token: <code>${token}</code></p>
  </div>

  <div class="cmd-grid">
    <div class="card">
      <h2 style="margin-top:0">Parâmetros</h2>

      <div class="cmd-formgrid">
        <div>
          <label>Endpoint base</label>
          <input id="baseUrl" value="${baseApi}">
        </div>
        <div>
          <label>Rota</label>
          <input id="route" value="send">
        </div>
      </div>

      <div class="cmd-formgrid">
        <div>
          <label>Conta</label>
          <select id="account">
            ${accounts.map(a=>`<option value="${a.id}">#${a.id} — ${a.label || "Conta"}</option>`).join("")}
          </select>
        </div>
        <div>
          <label>Telefone / destino</label>
          <input id="to" placeholder="Ex: 5516992870156">
        </div>
      </div>

      <label>Mensagem</label>
      <textarea id="message" rows="5" style="resize:vertical;min-height:110px">Olá! Mensagem de teste.</textarea>

      <div class="cmd-actions">
        <button id="btnBuild" type="button">Gerar comandos</button>
        <button id="btnClear" type="button">Limpar</button>
        <span class="muted" id="status"></span>
      </div>
    </div>

    <div class="card">
      <h2 style="margin-top:0">Comandos Gerados</h2>

      <div class="cmd-code">
        <header><h3>Linux / curl</h3><button class="copy-btn" type="button" data-copy="outLinux">Copiar</button></header>
        <pre id="outLinux">— clique em Gerar comandos —</pre>
      </div>

      <div class="cmd-code">
        <header><h3>Windows / PowerShell</h3><button class="copy-btn" type="button" data-copy="outWin">Copiar</button></header>
        <pre id="outWin">— clique em Gerar comandos —</pre>
      </div>

      <div class="cmd-code">
        <header><h3>MikroTik RouterOS</h3><button class="copy-btn" type="button" data-copy="outRB">Copiar</button></header>
        <pre id="outRB">— clique em Gerar comandos —</pre>
      </div>

      <div class="cmd-code">
        <header><h3>URL GET simples</h3><button class="copy-btn" type="button" data-copy="outGET">Copiar</button></header>
        <pre id="outGET">— clique em Gerar comandos —</pre>
      </div>
    </div>
  </div>
</div>

<script>
(function(){
  const USER_TOKEN = ${JSON.stringify(token)};

  const el = (id) => document.getElementById(id);
  const baseUrl = el("baseUrl");
  const route = el("route");
  const account = el("account");
  const to = el("to");
  const message = el("message");
  const status = el("status");

  function setStatus(msg, ms){
    status.textContent = msg || "";
    if(ms){
      setTimeout(function(){
        if(status.textContent === msg) status.textContent = "";
      }, ms);
    }
  }

  function normBase(u){
    u = String(u || "").trim();
    while(u.endsWith("/")) u = u.slice(0, -1);
    return u;
  }

  function buildUrl(){
    const b = normBase(baseUrl.value);
    const r = String(route.value || "send").trim().replace(/^\\/+/, "");
    if(!b || !USER_TOKEN || !r) return "";
    return b + "/" + encodeURIComponent(USER_TOKEN) + "/" + r;
  }

  function getPayload(){
    return {
      account: Number(account.value || 0),
      to: String(to.value || "").trim(),
      message: String(message.value || "")
    };
  }

  function jsonForShell(obj){
    return JSON.stringify(obj).replace(/'/g, "'\\\\''");
  }

  function escapePowerShellDouble(v){
    const bt = String.fromCharCode(96);
    return String(v || "").replace(new RegExp(bt, "g"), bt + bt).replace(/"/g, bt + '"').replace(/\\r?\\n/g, bt + "n");
  }

  function escapeRouterOS(v){
    return String(v || "")
      .replace(/\\\\/g, "\\\\\\\\")
      .replace(/"/g, "\\\\\\"")
      .replace(/\\r?\\n/g, "\\\\n");
  }

  function setText(id, text){
    el(id).textContent = text;
  }

  function buildCommands(){
    const url = buildUrl();
    const body = getPayload();

    if(!url){
      setStatus("Endpoint/token/rota inválidos.", 3000);
      return;
    }
    if(!body.account || !body.to || !body.message.trim()){
      setStatus("Preencha Conta, Telefone e Mensagem.", 3000);
      return;
    }

    const bodyJson = JSON.stringify(body);
    const getUrl = url + "?account=" + encodeURIComponent(body.account)
      + "&to=" + encodeURIComponent(body.to)
      + "&message=" + encodeURIComponent(body.message);

    const linux =
      "curl -X POST '" + url + "' \\\\\\n" +
      "  -H 'Content-Type: application/json' \\\\\\n" +
      "  -d '" + jsonForShell(body) + "'";

    const win =
      "$body = @{\\n" +
      "  account = " + body.account + "\\n" +
      "  to      = \\"" + escapePowerShellDouble(body.to) + "\\"\\n" +
      "  message = \\"" + escapePowerShellDouble(body.message) + "\\"\\n" +
      "} | ConvertTo-Json\\n\\n" +
      "Invoke-RestMethod -Uri \\"" + url + "\\" -Method Post -Body $body -ContentType \\"application/json\\"";

    const rb =
      "/tool fetch url=\\"" + url + "\\" \\\\\\n" +
      "    http-method=post \\\\\\n" +
      "    http-header-field=\\"Content-Type: application/json\\" \\\\\\n" +
      "    http-data=\\"" + escapeRouterOS(bodyJson) + "\\" \\\\\\n" +
      "    keep-result=no";

    setText("outLinux", linux);
    setText("outWin", win);
    setText("outRB", rb);
    setText("outGET", getUrl);
    setStatus("Comandos gerados.", 1800);
  }

  async function copyFrom(id, btn){
    const text = String(el(id).textContent || "").trim();
    if(!text || text.startsWith("—")){
      setStatus("Gere o comando primeiro.", 2500);
      return;
    }

    try{
      if(navigator.clipboard && window.isSecureContext){
        await navigator.clipboard.writeText(text);
      }else{
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.top = "-1000px";
        ta.style.left = "-1000px";
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(ta);
        if(!ok) throw new Error("copy bloqueado");
      }
      const old = btn.textContent;
      btn.textContent = "Copiado ✓";
      setTimeout(function(){ btn.textContent = old; }, 1200);
      setStatus("Copiado!", 1500);
    }catch(e){
      setStatus("Não consegui copiar automático. Selecione o texto e copie manualmente.", 4500);
    }
  }

  el("btnBuild").addEventListener("click", buildCommands);
  el("btnClear").addEventListener("click", function(){
    to.value = "";
    message.value = "";
    setText("outLinux", "— clique em Gerar comandos —");
    setText("outWin", "— clique em Gerar comandos —");
    setText("outRB", "— clique em Gerar comandos —");
    setText("outGET", "— clique em Gerar comandos —");
    setStatus("Limpo.", 1200);
  });

  document.querySelectorAll("[data-copy]").forEach(function(btn){
    btn.addEventListener("click", function(){
      copyFrom(btn.getAttribute("data-copy"), btn);
    });
  });
})();
</script>
</body>
</html>`);
});

app.get("/api/threads", requireAuth, (req,res)=>{ const account_id=Number(req.query.account||0), acc=getAccount(account_id); if(!canUseAccount(req.user,acc)) return res.status(404).json([]); res.json(listThreads(req.user, account_id)); });
app.get("/api/thread", requireAuth, (req,res)=>{ const account_id=Number(req.query.account||0), acc=getAccount(account_id); if(!canUseAccount(req.user,acc)) return res.status(404).json([]); const raw=String(req.query.numero||"").trim(); const numero=resolveLinkedNumero(account_id, cleanThreadId(raw)); res.json(getThread(req.user, account_id, numero)); });
app.get("/api/send", requireAuth, async (req,res)=>{ try{ const account_id=Number(req.query.account||0), acc=getAccount(account_id); if(!canUseAccount(req.user,acc)) return res.status(404).json({ok:false,error:"conta não encontrada"}); res.json(await sendWhatsAppFromAccount(account_id, req.query.numero||req.query.to, req.query.message||req.query.mensagem)); }catch(e){ res.status(500).json({ok:false,error:String(e)}); } });
app.post("/api/send", requireAuth, async (req,res)=>{ try{ const account_id=Number(req.body.account||0), acc=getAccount(account_id); if(!canUseAccount(req.user,acc)) return res.status(404).json({ok:false,error:"conta não encontrada"}); res.json(await sendWhatsAppFromAccount(account_id, req.body.numero||req.body.to, req.body.message||req.body.mensagem)); }catch(e){ res.status(500).json({ok:false,error:String(e)}); } });
app.post("/api/link-lid", requireAuth, (req,res)=>{
  try{
    const account_id = Number(req.body.account || req.query.account || 0);
    const acc = getAccount(account_id);
    if(!canUseAccount(req.user,acc)) return res.status(404).json({ok:false,error:"conta não encontrada"});
    const lid = String(req.body.lid || req.query.lid || "").trim();
    const numero = cleanPhone(req.body.numero || req.query.numero || "");
    if(!lid.startsWith("lid_") || !numero) return res.status(400).json({ok:false,error:"Informe o ID lid_ e o número real"});
    saveLidLink(account_id, lid, numero);
    io.to(room(account_id)).emit("threads-update",{accId:account_id,numero,ts:Date.now()});
    res.json({ok:true,lid,numero});
  }catch(e){ res.status(500).json({ok:false,error:String(e)}); }
});
app.post("/api/delete-thread", requireAuth, (req,res)=>{ const account_id=Number(req.query.account||0), acc=getAccount(account_id); if(!canUseAccount(req.user,acc)) return res.status(404).json({ok:false}); const raw=String(req.query.numero||"").trim(); const numero=resolveLinkedNumero(account_id, cleanThreadId(raw)); if(!numero) return res.status(400).json({ok:false}); if(req.user.role==='master') db.prepare("DELETE FROM messages WHERE account_id=? AND numero=?").run(account_id,numero); else db.prepare("DELETE FROM messages WHERE user_id=? AND account_id=? AND numero=?").run(req.user.id,account_id,numero); io.to(room(account_id)).emit("threads-update",{accId:account_id,numero,ts:Date.now()}); res.json({ok:true}); });

function readLooseBody(req){ return new Promise(resolve=>{ let buf=""; req.on("data",ch=>buf+=ch); req.on("end",()=>{ const q=new URL(req.url,"http://local").searchParams; if(q.get("account")||q.get("to")||q.get("message")) return resolve({account:q.get("account"),to:q.get("to")||q.get("numero"),message:q.get("message")||q.get("mensagem")}); try{ const j=JSON.parse(buf||"null"); if(j) return resolve({account:j.account,to:j.to||j.numero,message:j.message||j.mensagem}); }catch{} const o={}; buf.split(/[&\n\r;,]+/).forEach(kv=>{const p=kv.indexOf('='); if(p>0)o[kv.slice(0,p).trim()]=decodeURIComponent(kv.slice(p+1).trim().replace(/\+/g," "))}); resolve({account:o.account,to:o.to||o.numero,message:o.message||o.mensagem}); }); }); }
app.all("/api/rb/:token/send", async (req,res)=>{ try{ const tok=(req.params.token||"").trim(), rbTok=(process.env.RB_TOKEN||"").trim(); let user=null; if(rbTok&&tok===rbTok) user=db.prepare("SELECT * FROM users WHERE role='master' ORDER BY id ASC LIMIT 1").get(); if(!user) user=getUserByToken(tok); if(!user) return res.status(401).type("text/plain").end("ERROR token"); const b=await readLooseBody(req); const account_id=Number(b.account||0), acc=getAccount(account_id); if(!acc) return res.status(404).type("text/plain").end("ERROR conta"); if(!(user.role==='master'||acc.user_id===user.id)) return res.status(403).type("text/plain").end("ERROR perm"); const out=await sendWhatsAppFromAccount(account_id,b.to,b.message); res.type("text/plain").end(`OK ${out.accId} ${out.numero}`); }catch(e){ res.status(500).type("text/plain").end("ERROR "+String(e)); } });
app.post("/api/v1/:token/send", async (req,res)=>{ try{ const u=getUserByToken(req.params.token||""); if(!u) return res.status(401).json({error:"token inválido"}); const account_id=Number(req.body.account||0), acc=getAccount(account_id); if(!acc||(u.role!=="master"&&acc.user_id!==u.id)) return res.status(404).json({error:"conta não encontrada"}); res.json(await sendWhatsAppFromAccount(account_id, req.body.to||req.body.numero, req.body.message||req.body.mensagem)); }catch(e){ res.status(500).json({error:String(e)}); } });
app.get("/api/v1/:token/threads", (req,res)=>{ const u=getUserByToken(req.params.token||""); if(!u) return res.status(401).json([]); const account_id=Number(req.query.account||0), acc=getAccount(account_id); if(!acc||(u.role!=="master"&&acc.user_id!==u.id)) return res.status(404).json([]); res.json(listThreads(u,account_id)); });
app.get("/api/v1/:token/thread", (req,res)=>{ const u=getUserByToken(req.params.token||""); if(!u) return res.status(401).json([]); const account_id=Number(req.query.account||0), acc=getAccount(account_id); if(!acc||(u.role!=="master"&&acc.user_id!==u.id)) return res.status(404).json([]); const raw=String(req.query.numero||"").trim(); const numero=resolveLinkedNumero(account_id, cleanThreadId(raw)); res.json(getThread(u,account_id,numero)); });
io.on("connection", socket=>{ socket.on("join", ({accId})=>{ if(accId){ socket.join(room(accId)); socket.emit("joined",{accId}); } }); });
server.listen(3000, ()=>{ log.info({PORT:3000}, "HTTP on"); startAllExistingAccounts(); });
JS
  sed -i 's/\r$//' "${APP_DIR}/server.js"
}

random_alnum(){ python3 - "$1" <<'PY'
import secrets,string,sys
n=int(sys.argv[1]); print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(n)))
PY
}
random_hex(){ python3 - "$1" <<'PY'
import secrets,sys
print(secrets.token_hex(int(sys.argv[1])))
PY
}
write_systemd_unit(){
  local rb_token cookie_secret
  rb_token="$(grep -E '^Environment=RB_TOKEN=' /etc/systemd/system/whatsweb.service 2>/dev/null | tail -n1 | cut -d= -f3- || true)"
  cookie_secret="$(grep -E '^Environment=COOKIE_SECRET=' /etc/systemd/system/whatsweb.service 2>/dev/null | tail -n1 | cut -d= -f3- || true)"
  [ -n "${rb_token}" ] || rb_token="$(random_alnum 28)"
  [ -n "${cookie_secret}" ] || cookie_secret="$(random_hex 32)"
  mkdir -p "$(dirname "${LOG_FILE}")"; touch "${LOG_FILE}"
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
install_app_deps(){
  apt-get install -y --no-install-recommends ca-certificates curl gnupg xz-utils build-essential python3 make g++ chrony ufw sqlite3 libsqlite3-dev pkg-config git
  timedatectl set-timezone "${TZ}" || true
  systemctl enable --now chrony || true
  mkdir -p "${APP_DIR}"; cd "${APP_DIR}"
  [ -f package.json ] || npm init -y >/dev/null
  rm -rf node_modules package-lock.json
  npm cache clean --force >/dev/null 2>&1 || true
  npm install @whiskeysockets/baileys socket.io express qrcode better-sqlite3 pino cors cookie-parser nanoid@3 axios --omit=dev --no-audit --no-fund
  npm rebuild better-sqlite3 --unsafe-perm || true
}
show_summary(){
  local ip; ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"; [ -z "${ip}" ] && ip="SEU_IP_DO_SERVIDOR"
  echo "======================================================="
  echo "✅ WhatsWeb Pro instalado/corrigido"
  echo "   Register:  http://${ip}:3000/register"
  echo "   Dashboard: http://${ip}:3000/dashboard"
  echo "   Login:     provedor@provedor / provedor"
  echo "   RB_TOKEN:  ${RB_TOKEN_GENERATED:-não disponível}"
  echo "======================================================="
  systemctl --no-pager --full status whatsweb | sed -n '1,80p' || true
  tail -n 80 "${LOG_FILE}" || true
}
main(){
  log "Parando serviço antigo e liberando porta 3000..."; systemctl stop whatsweb 2>/dev/null || true; fuser -k 3000/tcp 2>/dev/null || true
  backup_existing
  cleanup_old_nodesource
  apt_update_safe
  ensure_node
  install_app_deps
  write_server_js
  /usr/local/bin/node -c "${APP_DIR}/server.js"
  sqlite3 "${APP_DIR}/whatsweb.db" "CREATE TABLE IF NOT EXISTS lid_links(account_id INTEGER,lid_numero TEXT,real_numero TEXT,updated_at INTEGER,PRIMARY KEY(account_id,lid_numero));" 2>/dev/null || true
  write_systemd_unit
  ufw allow 3000/tcp || true
  sleep 3
  show_summary
}
main "$@"
