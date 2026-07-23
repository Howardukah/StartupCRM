import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import OpenAI from 'openai';
import path from 'path';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';
import { createClient } from '@supabase/supabase-js';
import { createRequire } from 'module';
import fs from 'fs/promises';
import bcrypt from 'bcryptjs';
import multer from 'multer';

const require = createRequire(import.meta.url);

const app = express();
const httpServer = http.createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// ── Security: HTTP headers via helmet ──────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // disabled to allow inline scripts in our HTML files
}));

// ── Security: CORS ─────────────────────────────────────────────────────
// In production set CORS_ORIGIN to a comma-separated list of allowed origins.
// Left open in local dev since the CRM is loaded from file:// or localhost.
const corsOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map(s => s.trim())
  : (process.env.NODE_ENV === 'production' ? false : true);
app.use(cors({ origin: corsOrigins, exposedHeaders: ['X-Plan-Filename'] }));

// ── Security: Global rate limiter (100 req/min per IP) ─────────────────
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' },
});
app.use('/api/', globalLimiter);

// ── Security: Stricter limiter for auth endpoints (20 req/min) ─────────
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many auth requests, please try again later.' },
});
app.use('/api/auth/', authLimiter);

app.use(express.json({ limit: '30mb' })); // 20MB attachment limit -> ~27MB once base64-encoded, plus headroom

// ── Security: Static file protection ───────────────────────────────────
// Only serve files from the public/ subdirectory. This prevents direct URL
// access to server.js, package.json, .env, and any other server-side files.
const PUBLIC_DIR = path.join(path.resolve('.'), 'public');

// Belt-and-suspenders block for sensitive files in case they somehow end up
// accessible via another route (e.g. during local dev without a public/ dir).
const NEVER_SERVE = new Set([
  'db.json', '.env', '.env.example',
  'package.json', 'package-lock.json',
  'server.js', 'serviceaccountkey.json',
]);
const BLOCKED_PATH_PREFIXES = ['/pdf/', '/plans/', '/node_modules/', '/.git/'];
app.use((req, res, next) => {
  const lower = req.path.toLowerCase();
  if (BLOCKED_PATH_PREFIXES.some(p => lower.startsWith(p))) return res.status(404).end();
  const base = lower.split('/').pop();
  if (NEVER_SERVE.has(base)) return res.status(404).end();
  next();
});

// Subdomain routing: if host starts with "storage.", serve storage.html as default index
app.get('/', (req, res, next) => {
  const host = req.hostname || '';
  if (host.toLowerCase().startsWith('storage.')) {
    return res.sendFile(path.join(PUBLIC_DIR, 'storage.html'));
  }
  return res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.get('/healthz', (req, res) => res.status(200).send('OK'));

// ── Clean URLs: redirect /page.html to /page and serve clean routes ─────
app.get('/:page.html', (req, res, next) => {
  const page = req.params.page;
  if (!page || page.startsWith('api')) return next();
  res.redirect(301, `/${page}`);
});

app.get('/:page', (req, res, next) => {
  const page = req.params.page;
  if (!page || page.includes('.') || page.startsWith('api')) return next();
  const requested = `${page}.html`;
  const lower = requested.toLowerCase();
  if (NEVER_SERVE.has(lower)) return res.status(404).end();

  res.sendFile(path.join(PUBLIC_DIR, requested), (err) => {
    if (err) next(); // no matching .html file → fall through to 404 handler
  });
});

app.use(express.static(PUBLIC_DIR));

const EMPTY_DB = {
  team: [], clients: [], meetings: [], deletedMeetingIds: [],
  projects: [], messages: [], chatGroups: [], notifications: [],
  spreadsheets: [], notes: [],
  leads: [], proposals: [], pricingCatalog: [], mailTemplates: [], autoMails: []
};
// Activity is stored in a dedicated `activity_log` Supabase table — not in the JSONB blob.



// ── Role Permissions Matrix (Master Access List) ─────────────────────────────
const ROLE_PERMISSIONS = {
  'Admin': { canManageTeam: true, canAssignAdmins: true, canViewActivity: true, canManageStorage: true, canEditAllTasks: true, canManageLeads: true, canSendProposals: true, canViewAllPipelines: true, canEditPricing: true, canEditInvoices: true, canViewProjects: true, canViewTools: true, canViewAllContent: true, canManagePayroll: true },
  'HR': { canManageTeamRecords: true, canAddUsers: true, canViewHRMail: true, canManagePayroll: true, canViewTools: true },
  'Engineer': { canEditOwnTasks: true, canUploadAssets: true, canViewProjects: true, canViewTools: true },
  'Task Manager': { canEditAllTasks: true, canAssignTasks: true, canViewProjects: true, canManageLeads: true, canViewTools: true },
  'Marketing/Sales': { canManageLeads: true, canSendProposals: true, canViewUploadPortal: true, canViewTools: true },
  'Marketing/Sales Head': { canManageLeads: true, canSendProposals: true, canViewUploadPortal: true, canEditPricing: true, canViewAllPipelines: true, canEditInvoices: true, canViewTools: true }
};

function hasPermission(role, permission) {
  return ROLE_PERMISSIONS[role] && ROLE_PERMISSIONS[role][permission];
}

// Fixed platform policy: every client asset bucket gets a 10 MB total quota.
// This intentionally ignores asset_buckets.quota_bytes so stale/legacy rows
// (e.g. ones created before this policy, with a 2GB DB column default) can't
// override it.
const CLIENT_QUOTA_BYTES = 10 * 1024 * 1024;

// ── File type safety ─────────────────────────────────────────────────────────
// Blocked dangerous file extensions
const BLOCKED_EXTENSIONS = new Set([
  'exe', 'com', 'bat', 'cmd', 'sh', 'ps1', 'ps2', 'psm1', 'psd1',
  'vbs', 'vbe', 'jse', 'ws', 'wsf', 'wsc', 'wsh',
  'msi', 'msp', 'msc', 'reg', 'inf', 'scr', 'cpl', 'dll', 'sys',
  'jar', 'class', 'py', 'rb', 'pl', 'php', 'asp', 'aspx', 'jsp',
  'elf', 'out', 'bin', 'run', 'apk', 'app', 'ipa',
  'lnk', 'pif', 'hta', 'htc', 'url', 'webloc',
]);

// Magic byte signatures for dangerous file types [offset, bytes_array]
const DANGEROUS_SIGNATURES = [
  [0, [0x4D, 0x5A]],                          // MZ — Windows EXE/DLL
  [0, [0x7F, 0x45, 0x4C, 0x46]],              // ELF — Linux executable
  [0, [0xCA, 0xFE, 0xBA, 0xBE]],              // Java .class
  [0, [0x50, 0x4B, 0x03, 0x04]],              // ZIP (also JAR/APK — blocked by extension)
  [0, [0x23, 0x21]],                           // #! shebang — shell scripts
  [0, [0x3C, 0x3F, 0x70, 0x68, 0x70]],        // <?php
];

/** Returns { safe: boolean, reason: string|null } */
function checkFileSafety(buffer, originalname) {
  const ext = (originalname.split('.').pop() || '').toLowerCase();

  // 1. Block dangerous extensions
  if (BLOCKED_EXTENSIONS.has(ext)) {
    return { safe: false, reason: `File type ".${ext}" is not allowed for security reasons.` };
  }

  // 2. Magic byte check — reject truly dangerous signatures
  const bytes = buffer.slice(0, 16);
  for (const [offset, sig] of DANGEROUS_SIGNATURES) {
    // ZIP sig: only block if extension is also suspicious
    if (sig[0] === 0x50 && sig[1] === 0x4B) {
      if (['jar', 'apk', 'ipa'].includes(ext)) {
        return { safe: false, reason: `File type ".${ext}" is not allowed for security reasons.` };
      }
      continue;
    }
    const match = sig.every((b, i) => bytes[offset + i] === b);
    if (match) {
      return { safe: false, reason: `"${originalname}" was rejected: executable or script content detected.` };
    }
  }

  return { safe: true, reason: null };
}
// ─────────────────────────────────────────────────────────────────────────────

let supabase = null;



// ─── Write-through in-memory cache for the crm JSONB blob ──────────────────
// WebSockets enabled: we push updates to clients instantly.
// Result: Supabase is only read on server start. Cache stays perpetually warm.
let _crmCache = null;   // the cached data object
let _crmCacheTime = 0;      // timestamp of last Supabase read (informational)

async function getCrmData() {
  // Serve from cache if warm — zero Supabase egress
  if (_crmCache) {
    return structuredClone(_crmCache);
  }
  // Cache miss — fetch from Supabase (only happens once on server boot)
  const { data, error } = await supabase.from('crm').select('data').eq('id', 'main').single();
  if (error) throw new Error(error.message);
  _crmCache = data?.data || EMPTY_DB;
  _crmCacheTime = Date.now();
  return structuredClone(_crmCache);
}

// Bcrypt hashes always start with $2a$ / $2b$ / $2y$ — used to detect
// whether a password field is already hashed so we never double-hash.
const BCRYPT_PREFIX = /^\$2[aby]\$/;

/* ── AES-256-GCM encrypt / decrypt for Zoho App Passwords ──────────────
   ENCRYPTION_KEY env var should be a long random secret (any length —
   it is hashed to 32 bytes internally). Falls back to a fixed dev key so
   the server still starts without it, but production must always set it. */
function _encKey() {
  return crypto.createHash('sha256')
    .update(String(process.env.ENCRYPTION_KEY || 'crm_dev_fallback_key_change_in_prod'))
    .digest();
}
function encryptField(plaintext) {
  if (!plaintext) return '';
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', _encKey(), iv);
  let enc = cipher.update(plaintext, 'utf8', 'hex');
  enc += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${enc}:${tag}`;
}
function decryptField(ciphertext) {
  if (!ciphertext) return '';
  try {
    const [ivHex, encHex, tagHex] = ciphertext.split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', _encKey(), Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    let dec = decipher.update(encHex, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
  } catch { return ''; }
}

async function hashPlaintextPasswords(data) {
  if (!data || !Array.isArray(data.team)) return data;
  for (const member of data.team) {
    if (member.password && !BCRYPT_PREFIX.test(member.password)) {
      member.password = await bcrypt.hash(String(member.password), 10);
    }
  }
  return data;
}

async function setCrmData(data) {
  await hashPlaintextPasswords(data);
  const { error } = await supabase.from('crm').upsert({ id: 'main', data });
  if (error) throw new Error(error.message);
  // Write-through: update cache instantly so the next read is always fresh.
  _crmCache = structuredClone(data);
  _crmCacheTime = Date.now();
  // Broadcast ping to all connected WebSockets
  io.emit('db_changed');
}

app.set('trust proxy', true);

function requestIp(req) {
  if (!req) return '127.0.0.1';
  let raw = (
    req.headers['x-forwarded-for'] ||
    req.headers['x-real-ip'] ||
    req.ip ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    ''
  );
  if (Array.isArray(raw)) raw = raw[0];
  let ip = String(raw).split(',')[0].trim();
  if (ip.startsWith('::ffff:')) ip = ip.replace('::ffff:', '');
  if (ip === '::1' || !ip || ip === 'null' || ip === 'undefined') ip = '127.0.0.1';
  return ip;
}

function requestUserAgent(req) {
  return String(req.headers['user-agent'] || '').slice(0, 240);
}

function projectLabel(data, projectId, fallback) {
  const project = (data.projects || []).find(p => String(p.id) === String(projectId));
  return project ? (project.name || project.title || project.id) : (fallback || projectId || 'Project');
}

function memberLabel(data, userId) {
  const member = (data.team || []).find(m => String(m.id) === String(userId));
  return member ? (member.name || member.email || member.id) : (userId || 'Unknown user');
}

function makeActivityEntry(req, fields) {
  return {
    id: crypto.randomUUID(),
    time: new Date().toISOString(),
    actorId: fields.actorId || null,
    actorName: fields.actorName || null,
    actorType: fields.actorType || 'system',
    action: fields.action || 'event',
    targetType: fields.targetType || null,
    targetId: fields.targetId || null,
    targetName: fields.targetName || null,
    text: String(fields.text || fields.action || 'Activity recorded.').slice(0, 500),
    metadata: fields.metadata || {},
    ip: req ? requestIp(req) : '',
    userAgent: req ? requestUserAgent(req) : '',
    source: fields.source || 'server',
  };
}

// Write activity entries directly to the dedicated `activity_log` Supabase table.
// This is fire-and-forget — callers use .catch() so a log failure never breaks a request.
async function appendActivity(entryOrEntries) {
  const entries = (Array.isArray(entryOrEntries) ? entryOrEntries : [entryOrEntries])
    .filter(Boolean)
    .map(e => ({
      created_at: e.time || new Date().toISOString(),
      actor_id: e.actorId ? String(e.actorId).slice(0, 80) : null,
      actor_name: e.actorName ? String(e.actorName).slice(0, 120) : null,
      actor_type: String(e.actorType || 'system').slice(0, 30),
      action: String(e.action || 'event').slice(0, 80),
      target_type: e.targetType ? String(e.targetType).slice(0, 60) : null,
      target_id: e.targetId ? String(e.targetId).slice(0, 80) : null,
      target_name: e.targetName ? String(e.targetName).slice(0, 120) : null,
      text: String(e.text || '').slice(0, 500),
      ip_address: String(e.ip || '').slice(0, 45),
      user_agent: String(e.userAgent || '').slice(0, 240),
      source: String(e.source || 'server').slice(0, 20),
      // Scrub any sensitive keys from metadata before storing
      metadata: sanitizeMetadata(e.metadata || {}),
    }));
  if (!entries.length) return;
  const { error } = await supabase.from('activity_log').insert(entries);
  if (error) {
    console.error('[activity_log] insert error:', error.message);
  } else {
    // Notify connected admins that a new activity occurred
    if (typeof io !== 'undefined') io.emit('activity_logged');
  }
}

// Strip known-sensitive keys from metadata before persisting to the audit log.
function sanitizeMetadata(obj) {
  if (!obj || typeof obj !== 'object') return {};
  const SENSITIVE = new Set(['password', 'token', 'secret', 'key', 'apiKey', 'appPassword', 'authorization']);
  return Object.fromEntries(
    Object.entries(obj).filter(([k]) => !SENSITIVE.has(k))
  );
}

function revokeSessionsForUsers(userIds) {
  const blocked = new Set((userIds || []).filter(Boolean));
  if (!blocked.size) return;
  for (const id of blocked) revokedUserIds.add(id);
  // Auto-purge revocations after 25h (tokens expire in 24h anyway)
  setTimeout(() => { for (const id of blocked) revokedUserIds.delete(id); }, 25 * 60 * 60 * 1000);
}

function sessionUserIdsToRevokeAfterTeamChange(currentTeam, nextTeam) {
  const currentById = new Map((currentTeam || []).map(member => [member.id, member]));
  const nextById = new Map((nextTeam || []).map(member => [member.id, member]));
  const revoke = [];

  for (const [userId, before] of currentById) {
    const after = nextById.get(userId);
    if (!after) {
      revoke.push(userId);
      continue;
    }
    if ((after.status || 'Active') === 'Suspended') {
      revoke.push(userId);
      continue;
    }
    if (before.password !== after.password || before.mustChangePassword !== after.mustChangePassword) {
      revoke.push(userId);
    }
  }

  return revoke;
}

/* ── Per-user isolation for spreadsheets & notes ──────────────────────────
   The client only ever sees the slice of these two collections it's
   allowed to see. Writes are reconciled against the full server-side
   copy so a client can never delete or expose data it was never sent. */
function isSpreadsheetVisible(sheet, userId, userIsAdmin, me) {
  if (!sheet) return false;
  return sheet.ownerId === userId ||
    (Array.isArray(sheet.sharedWith) && sheet.sharedWith.includes(userId)) ||
    (userIsAdmin && sheet.isDefault);
}
function isNoteVisible(note, userId) {
  if (!note) return false;
  return note.ownerId === userId;
}
function isAttendanceVisible(entry, userId, userIsAdmin) {
  if (!entry) return false;
  return userIsAdmin || entry.userId === userId;
}

function filterVisible(list, visibleFn) {
  return (list || []).filter(item => item && visibleFn(item));
}

// Merges a client's submitted slice of an owner-scoped collection back into
// the authoritative server-side list, for a single requesting user.
//  - Items the user can't see are left completely untouched.
//  - Items the user could see but omitted from their submission are treated
//    as deletions (unless canDelete says otherwise, e.g. a default sheet).
//  - New items get their ownerId forced to the requesting user — a client
//    can never create something owned by someone else.
//  - Protected fields (ownership/sharing/default flag) on existing items can
//    only be changed by that item's actual owner.
function reconcileOwnedCollection(serverList, clientList, userId, visibleFn, canDelete, protectedFields) {
  serverList = (serverList || []).filter(Boolean);
  clientList = (clientList || []).filter(Boolean);
  const serverById = new Map(serverList.map(i => [i && i.id, i]).filter(([id]) => id));
  const clientById = new Map(clientList.map(i => [i && i.id, i]).filter(([id]) => id));
  const result = [];

  for (const item of serverList) {
    if (!item || !item.id) continue;
    if (!visibleFn(item)) { result.push(item); continue; } // not this user's business — untouched
    const submitted = clientById.get(item.id);
    if (!submitted) {
      if (canDelete(item)) continue; // user removed it — treat as delete
      result.push(item); // not allowed to delete (e.g. default sheet) — keep server copy
      continue;
    }
    const merged = { ...submitted };
    if (item.ownerId !== userId) {
      // Not the owner: can edit content, but not ownership/sharing/default flags.
      for (const f of protectedFields) merged[f] = item[f];
    }
    result.push(merged);
  }

  for (const item of clientList) {
    if (!item || !item.id) continue;
    if (!serverById.has(item.id)) {
      result.push({ ...item, ownerId: userId }); // new item — force real ownership
    }
  }

  return result;
}

function reconcileUserCollection(serverList, clientList, userId, visibleFn) {
  serverList = (serverList || []).filter(Boolean);
  clientList = (clientList || []).filter(item => item && item.id && (!item.userId || item.userId === userId));
  const clientById = new Map(clientList.map(i => [i.id, i]));
  const result = [];

  for (const item of serverList) {
    if (!item || !item.id) continue;
    if (!visibleFn(item)) { result.push(item); continue; }
    const submitted = clientById.get(item.id);
    result.push(submitted ? { ...submitted, userId: item.userId || userId } : item);
  }

  const serverById = new Map(serverList.map(i => [i.id, i]));
  for (const item of clientList) {
    if (!item || !item.id) continue;
    if (!serverById.has(item.id)) result.push({ ...item, userId });
  }

  return result;
}

/* ── Supabase client ─────────────────────────────────────────────────── */
async function initSupabase() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  if (!url || !key) throw new Error('SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in .env');
  supabase = createClient(url, key, { auth: { persistSession: false } });
  // Probe connection
  const { error } = await supabase.from('crm').select('id').eq('id', 'main').single();
  if (error && error.code !== 'PGRST116') throw new Error(error.message); // PGRST116 = row not found (ok on first run)
  console.log('✅ Successfully connected to Supabase.');
}

/* ── Signed session tokens (survive server restarts) ─────────────────────
   Format: base64url(userId.expiresAt.profileSetupRequired).HMAC-SHA256
   The HMAC is signed with SESSION_SECRET so tokens can't be forged.
   A small in-memory revocation set handles forced logouts (suspended users,
   password changes). Revocations are kept for 25h then auto-purged.
─────────────────────────────────────────────────────────────────────────── */
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomUUID(); // set SESSION_SECRET env var on Render!
const revokedUserIds = new Set(); // revoked by userId (survives for 25h)

function signToken(userId, expiresAt, profileSetupRequired = false) {
  const payload = Buffer.from(JSON.stringify({ userId, expiresAt, profileSetupRequired })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot < 0) return null;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  // Constant-time comparison
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!data.userId || !data.expiresAt) return null;
    if (Date.now() > data.expiresAt) return null;
    return data;
  } catch { return null; }
}

// Keep a small in-memory sessions Map ONLY for real-time revocation lookups
// (so we can still forcibly log out suspended users or password-changed users).
// No longer the source of truth — verifyToken() is.
const sessions = new Map(); // token → { userId } kept only for revokeByToken if needed

// Secure WebSocket connections using the signed token or bucket token
io.use(async (socket, next) => {
  const authType = socket.handshake.auth.type || 'crm';
  const token = socket.handshake.auth.token || socket.handshake.query.token;
  if (!token) return next(new Error('Unauthorized'));

  if (authType === 'bucket') {
    const { data: bucket, error } = await supabase.from('asset_buckets').select('id, revoked').eq('token', token).single();
    if (error || !bucket || bucket.revoked) return next(new Error('Invalid or revoked bucket'));
    socket.data.isBucket = true;
    socket.data.bucketId = bucket.id;
    return next();
  }

  const session = verifyToken(token);
  if (!session) return next(new Error('Session expired'));
  if (revokedUserIds.has(session.userId)) return next(new Error('Session revoked'));
  socket.data.userId = session.userId;
  next();
});

io.on('connection', (socket) => {
  if (socket.data.isBucket) {
    socket.join('asset-bucket:' + socket.data.bucketId);
    // 20-minute strict limit for client connections
    setTimeout(() => {
      socket.disconnect(true);
    }, 20 * 60 * 1000);
  }
});

// Cache TTL for suspended-user checks: re-verify against Supabase at most once per 5 minutes.
const SESSION_VERIFY_INTERVAL_MS = 5 * 60 * 1000;
const sessionLastVerified = new Map(); // userId → timestamp

// Prune stale loginAttempt records every 10 min
setInterval(() => {
  const now = Date.now();
  for (const [key, a] of loginAttempts) {
    if (now - a.first > LOCKOUT_MS * 2) loginAttempts.delete(key);
  }
  // Prune old lastVerified entries
  for (const [uid, ts] of sessionLastVerified) {
    if (now - ts > SESSION_VERIFY_INTERVAL_MS * 3) sessionLastVerified.delete(uid);
  }
}, 10 * 60 * 1000);

async function validateSession(req, res, next) {
  const token = req.headers['x-session-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized.', redirect: true });

  const session = verifyToken(token);
  if (!session) {
    return res.status(401).json({ error: 'Session expired. Please log in again.', redirect: true });
  }

  if (revokedUserIds.has(session.userId)) {
    return res.status(401).json({ error: 'Session revoked. Please log in again.', redirect: true });
  }

  // Only re-verify suspension status once per 5 min per user
  const now = Date.now();
  const lastVerified = sessionLastVerified.get(session.userId) || 0;
  if (now - lastVerified > SESSION_VERIFY_INTERVAL_MS) {
    try {
      const data = await getCrmData();
      const member = (data.team || []).find(m => m.id === session.userId);
      if (!member || member.status === 'Suspended') {
        revokedUserIds.add(session.userId);
        return res.status(403).json({ error: 'Your account is suspended or no longer exists.', redirect: true });
      }
      sessionLastVerified.set(session.userId, now);
    } catch (err) {
      console.error('validateSession error:', err);
    }
  }

  req.userId = session.userId;
  next();
}

/* ── AI / Groq client ────────────────────────────────────────────────── */
if (!process.env.GROQ_API_KEY) {
  console.warn('âš ï¸   GROQ_API_KEY not set. AI sprint planner will not work.');
}
const groqClient = new OpenAI({
  apiKey: process.env.GROQ_API_KEY,
  baseURL: 'https://api.groq.com/openai/v1',
});

/* ── Project plan file storage (local files) ────── */
const MIME_TYPES = {
  '.pdf': 'application/pdf',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.txt': 'text/plain',
  '.md': 'text/markdown',
};
function safeFilename(name) {
  return String(name).replace(/[/\\]/g, '_').replace(/[^a-zA-Z0-9_.\- ]/g, '_').slice(0, 150);
}



/* ────────────────────────────────────────────────────────────────────────────────────────────────────────── 
   AUTH ROUTES
   ──────────────────────────────────────────────────────────────────────────────────────────────────────────  */

// Check if workspace exists — used by login page on load
app.get('/api/auth/check', async (req, res) => {
  try {
    const data = await getCrmData();
    const hasAdmin = Array.isArray(data.team) && data.team.some(m => m && (m.role === 'Admin' || m.role === 'Super Admin'));
    if (!data.team || !data.team.length || !hasAdmin) {
      return res.json({ hasData: false });
    }
    const team = data.team.map(m => ({ id: m.id, name: m.name }));
    res.json({ hasData: true, team });
  } catch (e) {
    console.error('auth check error:', e);
    res.json({ hasData: true });
  }
});

// First-time admin setup — creates workspace
app.post('/api/auth/setup', async (req, res) => {
  try {
    const data = await getCrmData();
    if (data.team && data.team.length > 0) {
      return res.status(400).json({ error: 'Workspace already set up.' });
    }
    const adminMember = req.body.team && req.body.team[0];
    if (adminMember) {
      adminMember.profileSetupRequired = true;
      adminMember.lastLoginIp = requestIp(req);
    }
    await setCrmData(req.body);
    const token = signToken(adminMember.id, Date.now() + 86400000, true);
    res.json({ ok: true, token, userId: adminMember.id, profileSetupRequired: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Login — validates credentials, issues session token
// Simple in-memory brute-force guard: 5 failed attempts per identifier
// locks that identifier out for 15 minutes.
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

app.post('/api/auth/login', async (req, res) => {
  try {
    const { userId, password } = req.body;
    const key = String(userId || '').toLowerCase().trim();
    const attempt = loginAttempts.get(key);
    if (attempt && attempt.count >= MAX_ATTEMPTS && Date.now() - attempt.first < LOCKOUT_MS) {
      return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
    }

    const data = await getCrmData();
    const member = (data.team || []).find(m => m.id === userId || (m.email && m.email.toLowerCase() === String(userId).toLowerCase().trim()));

    const fail = () => {
      const a = loginAttempts.get(key) || { count: 0, first: Date.now() };
      a.count += 1;
      if (a.count === 1) a.first = Date.now();
      loginAttempts.set(key, a);
    };

    if (!member) { fail(); return res.status(401).json({ error: 'Account not found.' }); }
    if (member.status === 'Suspended') {
      return res.status(403).json({ error: 'Credentials restricted. Contact admin.' });
    }
    const isHashed = member.password && BCRYPT_PREFIX.test(member.password);
    const passwordOk = isHashed
      ? await bcrypt.compare(password || '', member.password)
      : (member.password && String(password) === String(member.password));

    if (!passwordOk) {
      fail();
      const currentAttempt = loginAttempts.get(key);
      if (currentAttempt && currentAttempt.count >= MAX_ATTEMPTS) {
        member.suspiciousLoginAttempt = true;
        await setCrmData(data);
      }
      return res.status(401).json({ error: 'Incorrect password.' });
    }

    // Auto-hash plaintext password if needed
    if (!isHashed) {
      member.password = await bcrypt.hash(String(password), 10);
      await setCrmData(data);
    }
    const currentIp = requestIp(req);
    let ipMismatched = false;
    if (member.lastLoginIp && member.lastLoginIp !== currentIp && member.securityQuestion) {
      ipMismatched = true;
    }

    if (ipMismatched) {
      member.suspiciousLoginAttempt = true;
      await setCrmData(data);

      try {
        const mailer = getMailer();
        if (mailer) {
          const toEmail = member.personalEmail || member.email;
          const fromName = process.env.SMTP_FROM_NAME || 'Startup CRM';
          const fromAddr = process.env.SMTP_USER;
          const supportEmail = process.env.SUPPORT_EMAIL || 'support@startupbuild.tech';

          const emailSubject = `⚠️ Security Alert: Login attempt from a new IP/device`;
          const emailHtml = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Security Alert</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f7f7f9; padding: 20px; color: #333;">
<div style="max-width: 600px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); border: 1px solid #e1e8ed;">
  <h2 style="color: #d9534f; margin-top: 0;">⚠️ Suspicious Login Activity Detected</h2>
  <p>Hello <strong>${member.name || member.id}</strong>,</p>
  <p>We detected an attempt to log in to your account from a new location or device that we don't recognize.</p>
  <table style="width: 100%; border-collapse: collapse; margin: 20px 0; background: #f8f9fa; border-radius: 4px;">
    <tr>
      <td style="padding: 10px; font-weight: bold; border-bottom: 1px solid #eee; width: 120px;">IP Address:</td>
      <td style="padding: 10px; border-bottom: 1px solid #eee;">${currentIp}</td>
    </tr>
    <tr>
      <td style="padding: 10px; font-weight: bold; border-bottom: 1px solid #eee;">Date/Time:</td>
      <td style="padding: 10px; border-bottom: 1px solid #eee;">${new Date().toUTCString()}</td>
    </tr>
  </table>
  <p>To ensure it is indeed you, you will be prompted to answer your security question during the login process.</p>
  <p style="color: #666; font-size: 13px; margin-top: 30px;">If this wasn't you, your credentials might be compromised. Please change your password immediately or contact your administrator.</p>
  <hr style="border: 0; border-top: 1px solid #eee; margin: 25px 0;">
  <p style="font-size: 11px; color: #999; text-align: center;">Automated alert from ${fromName}. Need help? Contact <a href="mailto:${supportEmail}" style="color: #2b86a8; text-decoration: none;">${supportEmail}</a></p>
</div>
</body>
</html>`;

          // Non-blocking background send so login is instant
          mailer.sendMail({
            from: `"${fromName}" <${fromAddr}>`,
            to: toEmail,
            subject: emailSubject,
            html: emailHtml,
          }).then(() => console.log(`📧 Suspicious login alert email sent to ${toEmail}`))
            .catch(err => console.error('Failed to send suspicious login email:', err));
        }
      } catch (err) {
        console.error('Security email error:', err);
      }
    }

    if (member.suspiciousLoginAttempt && member.securityQuestion) {
      loginAttempts.delete(key);
      return res.json({ ok: true, securityQuestionRequired: true, userId: member.id });
    }


    // Update IP and clear suspicious flag
    member.lastLoginIp = currentIp;
    member.suspiciousLoginAttempt = false;
    await setCrmData(data);

    loginAttempts.delete(key);
    if (member.mustChangePassword) {
      return res.json({ ok: true, mustChangePassword: true, userId: member.id });
    }
    const isProfileSetupNeeded = !!member.profileSetupRequired;
    const token = signToken(member.id, Date.now() + 86400000, isProfileSetupNeeded);
    await appendActivity(makeActivityEntry(req, {
      actorId: member.id,
      actorName: member.name || member.email || member.id,
      actorType: 'user',
      action: 'auth.login',
      targetType: 'user',
      targetId: member.id,
      targetName: member.name || member.email || member.id,
      text: `${member.name || member.email || member.id} logged in.`,
    }));
    if (isProfileSetupNeeded) {
      return res.json({
        ok: true,
        token,
        userId: member.id,
        profileSetupRequired: true,
        user: { name: member.name || '' }
      });
    }
    res.json({ ok: true, token, userId: member.id, mustChangePassword: false });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/verify-security-question', async (req, res) => {
  try {
    const { userId, securityQuestion, securityAnswer } = req.body || {};
    if (!userId || !securityQuestion || !securityAnswer) {
      return res.status(400).json({ error: 'User ID, security question, and security answer are required.' });
    }

    // Enforce the same lockout as the login endpoint
    const key = String(userId).toLowerCase().trim();
    const attempt = loginAttempts.get(key);
    if (attempt && attempt.count >= MAX_ATTEMPTS && Date.now() - attempt.first < LOCKOUT_MS) {
      return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
    }

    const fail = () => {
      const a = loginAttempts.get(key) || { count: 0, first: Date.now() };
      a.count += 1;
      if (a.count === 1) a.first = Date.now();
      loginAttempts.set(key, a);
    };

    const data = await getCrmData();
    const memberIndex = (data.team || []).findIndex(m => m.id === userId || (m.email && m.email.toLowerCase() === String(userId).toLowerCase().trim()));
    if (memberIndex === -1) {
      fail();
      return res.status(404).json({ error: 'User not found.' });
    }

    const member = data.team[memberIndex];
    if (!member.securityQuestion || !member.securityAnswer) {
      return res.status(400).json({ error: 'Security question not configured for this user.' });
    }

    // Verify the user selected the correct question
    if (securityQuestion !== member.securityQuestion) {
      fail();
      return res.status(401).json({ error: 'Incorrect security question or answer.' });
    }

    const normalized = String(securityAnswer).toLowerCase().trim();
    const answerOk = await bcrypt.compare(normalized, member.securityAnswer);

    if (!answerOk) {
      fail();
      return res.status(401).json({ error: 'Incorrect security question or answer.' });
    }

    member.suspiciousLoginAttempt = false;
    const currentIp = requestIp(req);
    member.lastLoginIp = currentIp;
    await setCrmData(data);

    loginAttempts.delete(key);

    const token = signToken(member.id, Date.now() + 86400000);

    await appendActivity(makeActivityEntry(req, {
      actorId: member.id,
      actorName: member.name || member.email || member.id,
      actorType: 'user',
      action: 'auth.login',
      targetType: 'user',
      targetId: member.id,
      targetName: member.name || member.email || member.id,
      text: `${member.name || member.email || member.id} logged in (passed security question).`,
    }));

    res.json({ ok: true, token, userId: member.id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Force password change — updates password and issues session token.
// Security: requires either a valid session token (user is already logged in)
// OR the request is for a mustChangePassword flow (userId must match a member
// whose mustChangePassword flag is true — no session yet on first login).
app.post('/api/auth/change-password', async (req, res) => {
  try {
    const { userId, newPassword } = req.body;
    if (!userId) {
      return res.status(400).json({ error: 'Session expired. Please refresh the page and log in again.' });
    }
    if (!newPassword || String(newPassword).length < 8) {
      return res.status(400).json({ error: 'Your new password must be at least 8 characters long.' });
    }

    // Allow if caller has a valid session for THIS user, or if it's a
    // first-login forced-change (mustChangePassword=true, no session yet).
    const sessionToken = req.headers['x-session-token'];
    const existingSession = sessionToken ? verifyToken(sessionToken) : null;
    const sessionOwnsUser = existingSession && !revokedUserIds.has(existingSession.userId) && existingSession.userId === userId;

    const data = await getCrmData();
    const memberIndex = (data.team || []).findIndex(m => m.id === userId);
    if (memberIndex === -1) return res.status(404).json({ error: 'User not found.' });

    const member = data.team[memberIndex];
    const isMustChangeFlow = !!member.mustChangePassword;

    if (member.status === 'Suspended') {
      revokeSessionsForUsers([member.id]);
      return res.status(403).json({ error: 'Credentials restricted. Contact admin.' });
    }

    if (!sessionOwnsUser && !isMustChangeFlow) {
      return res.status(401).json({ error: 'Unauthorized.' });
    }

    data.team[memberIndex].password = newPassword; // setCrmData will hash it
    data.team[memberIndex].mustChangePassword = false;
    if (data.team[memberIndex].status === 'Invited') {
      data.team[memberIndex].status = 'Active';
    }
    await setCrmData(data);
    const isProfileSetupNeeded = !!data.team[memberIndex].profileSetupRequired;
    const token = signToken(userId, Date.now() + 86400000, isProfileSetupNeeded);
    appendActivity(makeActivityEntry(req, {
      actorId: userId,
      actorName: member.name || member.email || userId,
      actorType: 'user',
      action: 'auth.password_changed',
      targetType: 'user',
      targetId: userId,
      targetName: member.name || member.email || userId,
      text: (member.name || member.email || userId) + ' changed their password.',
      metadata: { forced: isMustChangeFlow },
    })).catch(e => console.warn('[activity] password_changed:', e.message));
    res.json({
      ok: true,
      token,
      userId,
      profileSetupRequired: isProfileSetupNeeded,
      user: {
        name: member.name || '',
        birthday: member.birthday || '',
        gender: member.sex || '',
        personalEmail: member.personalEmail || '',
        mobileNumber: member.mobileNumber || '',
        photoDataUrl: member.photoDataUrl || ''
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Profile setup — saves new user profile fields and clears the profileSetupRequired flag.
// Called after an invited user changes their default password and fills in their profile.
app.post('/api/profile', validateSession, async (req, res) => {
  try {
    const { name, birthday, sex, personalEmail, mobileNumber, photoDataUrl, securityQuestion, securityAnswer } = req.body || {};
    const data = await getCrmData();
    const idx = (data.team || []).findIndex(m => m.id === req.userId);
    if (idx === -1) return res.status(404).json({ error: 'User not found.' });

    if (name) data.team[idx].name = name;
    if (birthday) data.team[idx].birthday = birthday;
    if (sex) data.team[idx].sex = sex;
    if (personalEmail) data.team[idx].personalEmail = personalEmail;
    if (mobileNumber) data.team[idx].mobileNumber = mobileNumber;
    if (photoDataUrl) data.team[idx].photoDataUrl = photoDataUrl;

    if (securityQuestion) data.team[idx].securityQuestion = securityQuestion;
    if (securityAnswer) {
      const normalized = String(securityAnswer).toLowerCase().trim();
      data.team[idx].securityAnswer = await bcrypt.hash(normalized, 10);
    }

    // Clear the flag so subsequent password resets don't re-prompt for profile setup
    data.team[idx].profileSetupRequired = false;

    await setCrmData(data);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Logout — invalidates session token
app.post('/api/auth/logout', async (req, res) => {
  const token = req.headers['x-session-token'];
  const session = token ? sessions.get(token) : null;
  if (token) sessions.delete(token);
  if (session) {
    getCrmData().then(data => {
      const member = (data.team || []).find(m => m.id === session.userId) || {};
      const name = member.name || member.email || session.userId;
      return appendActivity(makeActivityEntry(req, {
        actorId: session.userId,
        actorName: name,
        actorType: 'user',
        action: 'auth.logout',
        targetType: 'user',
        targetId: session.userId,
        targetName: name,
        text: `${name} logged out.`,
      }));
    }).catch(e => console.warn('activity logout error:', e.message));
  }
  res.json({ ok: true });
});

/* ── DB ROUTES (all require a valid session token) ────────────────────── */

// Read full DB — activity is no longer included; admins fetch it via GET /api/activity.
app.get('/api/db', validateSession, async (req, res) => {
  try {
    const data = await getCrmData();
    const me = (data.team || []).find(m => m.id === req.userId);
    const userIsAdmin = !!me && hasPermission(me.role, 'canViewAllContent');
    const scoped = {
      ...data,
      spreadsheets: filterVisible(data.spreadsheets, s => isSpreadsheetVisible(s, req.userId, userIsAdmin, me)),
      notes: filterVisible(data.notes, n => isNoteVisible(n, req.userId)),
      attendance: filterVisible(data.attendance, a => isAttendanceVisible(a, req.userId, hasPermission(me ? me.role : null, 'canManagePayroll'))),
      leads: [],
      proposals: hasPermission(me ? me.role : null, 'canSendProposals') || userIsAdmin ? (data.proposals || []) : [],
      pricingCatalog: (data.pricingCatalog || []),
      mailTemplates: (data.mailTemplates || []),
      autoMails: (data.autoMails || []),
      // Activity is never served via this endpoint — use GET /api/activity instead.
      activity: [],
    };
    // Never expose per-user mail credentials to any client — accessed via /api/mail/settings only.
    delete scoped.zohoMailSettings;
    res.json(scoped);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Write full DB. Spreadsheets and notes are reconciled per-user rather than
// overwritten wholesale, since the client only ever holds its own visible
// slice of those two collections (see GET /api/db above).
app.post('/api/db', validateSession, async (req, res) => {
  try {
    const current = await getCrmData();
    const me = (current.team || []).find(m => m.id === req.userId);
    const userIsAdmin = !!me && hasPermission(me.role, 'canViewAllContent');
    const incoming = req.body || {};

    const merged = { ...current };

    const SHARED_KEYS = ['clients', 'projects', 'messages', 'chatGroups', 'notifications'];

    for (const key of SHARED_KEYS) {
      if (incoming[key] !== undefined) {
        merged[key] = Array.isArray(incoming[key]) ? incoming[key].filter(Boolean) : incoming[key];
      }
    }
    const deletedMeetingIds = Array.from(new Set([
      ...(current.deletedMeetingIds || []),
      ...(incoming.deletedMeetingIds || [])
    ].filter(Boolean)));
    if (incoming.meetings !== undefined) {
      const deleted = new Set(deletedMeetingIds);
      merged.meetings = (incoming.meetings || []).filter(m => m && m.id && !deleted.has(m.id));
    }
    merged.deletedMeetingIds = deletedMeetingIds;

    // — Team change detection (admin/HR) ——————————————————————————
    if (incoming.team !== undefined && Array.isArray(incoming.team)) {
      const role = me ? me.role : null;
      const canManageTeam = hasPermission(role, 'canManageTeam');
      const canAssignAdmins = hasPermission(role, 'canAssignAdmins');
      const teamList = incoming.team.filter(Boolean);

      if (!canManageTeam) {
        console.warn(`[security] Non-authorized user ${req.userId} tried to write 'team' — ignored.`);
      } else {
        if (!canAssignAdmins) {
          const currentAdmins = (current.team || []).filter(m => m && m.role === 'Admin');
          const adminIds = new Set(currentAdmins.map(m => m.id));
          const safeTeam = [];
          for (const m of teamList) {
            if (m && m.id && adminIds.has(m.id)) {
              const foundAdmin = currentAdmins.find(admin => admin && admin.id === m.id);
              if (foundAdmin) safeTeam.push(foundAdmin);
            } else if (m) {
              if (m.role === 'Admin') m.role = 'Engineer';
              safeTeam.push(m);
            }
          }
          for (const admin of currentAdmins) {
            if (admin && admin.id && !safeTeam.find(m => m && m.id === admin.id)) safeTeam.push(admin);
          }
          incoming.team = safeTeam.filter(Boolean);
        } else {
          incoming.team = teamList;
        }
        revokeSessionsForUsers(sessionUserIdsToRevokeAfterTeamChange(current.team, incoming.team));
        merged.team = incoming.team;
      }
    }

    // Per-user data: reconcile instead of overwrite, so this user's request
    // can't affect data belonging to other users that they never received.
    merged.spreadsheets = reconcileOwnedCollection(
      current.spreadsheets, incoming.spreadsheets, req.userId,
      s => isSpreadsheetVisible(s, req.userId, userIsAdmin),
      s => s.ownerId === req.userId && !s.isDefault,
      ['ownerId', 'isDefault', 'sharedWith']
    );
    merged.notes = reconcileOwnedCollection(
      current.notes, incoming.notes, req.userId,
      n => isNoteVisible(n, req.userId),
      n => n.ownerId === req.userId,
      ['ownerId']
    );
    merged.attendance = reconcileUserCollection(
      current.attendance, incoming.attendance, req.userId,
      a => isAttendanceVisible(a, req.userId, hasPermission(me ? me.role : null, 'canManagePayroll'))
    );
    if (hasPermission(me ? me.role : null, 'canManageLeads') || userIsAdmin) {
      merged.leads = incoming.leads || [];
    } else { merged.leads = current.leads || []; }
    if (hasPermission(me ? me.role : null, 'canSendProposals') || userIsAdmin) {
      merged.proposals = incoming.proposals || [];
      merged.mailTemplates = incoming.mailTemplates || [];
    } else {
      merged.proposals = current.proposals || [];
      merged.mailTemplates = current.mailTemplates || [];
    }
    if (userIsAdmin || (me && me.role === 'Admin')) {
      if (incoming.autoMails !== undefined) merged.autoMails = incoming.autoMails;
    }
    if (hasPermission(me ? me.role : null, 'canEditPricing') || userIsAdmin) {
      merged.pricingCatalog = incoming.pricingCatalog || current.pricingCatalog || [];
    } else {
      merged.pricingCatalog = current.pricingCatalog || [];
    }
    // Activity is NEVER written by the client via save-db. It's written explicitly via logActivity.

    await setCrmData(merged);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Explicit endpoint for the frontend to log CRM actions (like creating projects or clocking in)
app.post('/api/log-activity', validateSession, (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 500);
  const action = String(req.body.action || 'user.action').slice(0, 80);
  if (text) {
    appendActivity(makeActivityEntry(req, {
      action,
      text,
      targetType: 'system'
    }));
  }
  res.json({ ok: true });
});

// Admin-only: paginated activity log fetched directly from the activity_log Supabase table.
// Supports filtering by actor, action category, free-text search, and date range.
// Rate-limited to prevent bulk scraping of the audit trail.
const activityLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many activity log requests. Slow down.' },
});
app.get('/api/activity', activityLimiter, validateSession, async (req, res) => {
  try {
    const crmData = await getCrmData();
    const me = (crmData.team || []).find(m => m.id === req.userId);
    if (!hasPermission(me ? me.role : null, 'canViewActivity')) return res.status(403).json({ error: 'Only Admins can view the activity log.' });

    // — Validate & sanitize query params ————————————————————
    const page = Math.max(1, parseInt(req.query.page || '1', 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '50', 10) || 50));
    const offset = (page - 1) * limit;

    // Allowlist for action filter — must start with a known prefix
    const ACTION_PREFIXES = ['auth', 'storage', 'team', 'workspace'];
    const actionFilter = req.query.action && ACTION_PREFIXES.some(p => String(req.query.action).startsWith(p))
      ? String(req.query.action).slice(0, 80)
      : null;

    // Actor must be a non-empty string (UUID or email-like), no SQL injection risk via RPC
    const actorFilter = req.query.actor ? String(req.query.actor).slice(0, 80) : null;

    // Date range — must parse as valid ISO date
    const parseDate = v => { if (!v) return null; const d = new Date(v); return isNaN(d.getTime()) ? null : d.toISOString(); };
    const fromDate = parseDate(req.query.from);
    const toDate = parseDate(req.query.to);

    // Free-text search — escaped inside ILIKE pattern
    const searchQ = req.query.q ? String(req.query.q).replace(/[%_\\]/g, c => '\\' + c).slice(0, 100) : null;

    // — Build query ————————————————————————————————————————
    let query = supabase
      .from('activity_log')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (actorFilter) query = query.eq('actor_id', actorFilter);
    if (actionFilter) query = query.ilike('action', actionFilter + '%');
    if (fromDate) query = query.gte('created_at', fromDate);
    if (toDate) query = query.lte('created_at', toDate);
    if (searchQ) query = query.or(`text.ilike.%${searchQ}%,actor_name.ilike.%${searchQ}%,target_name.ilike.%${searchQ}%`);

    const { data: rows, error, count } = await query;
    if (error) throw new Error(error.message);

    // — Summary stats ——————————————————————————————————————
    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    const { data: todayStats } = await supabase
      .from('activity_log')
      .select('action')
      .gte('created_at', todayStart.toISOString());

    const loginsToday = (todayStats || []).filter(r => r.action === 'auth.login').length;
    const storageToday = (todayStats || []).filter(r => r.action.startsWith('storage.')).length;
    const teamToday = (todayStats || []).filter(r => r.action.startsWith('team.')).length;

    res.json({
      ok: true,
      activity: (rows || []).map(r => ({ ...r, time: r.created_at, ip: r.ip_address || r.ip || '' })),
      total: count || 0,
      page,
      limit,
      pages: Math.ceil((count || 0) / limit),
      stats: { loginsToday, storageToday, teamToday, totalToday: (todayStats || []).length },
    });
  } catch (e) {
    console.error('[api/activity]', e);
    res.status(500).json({ error: e.message });
  }
});

// Atomic team access toggle. This avoids full-DB save races where a stale
// browser copy can briefly restore the old member status after Suspend/Restore.
app.post('/api/team/:memberId/suspension', validateSession, async (req, res) => {
  try {
    const data = await getCrmData();
    data.team = data.team || [];

    const me = data.team.find(m => m.id === req.userId);
    if (!hasPermission(me ? me.role : null, 'canManageTeam')) {
      return res.status(403).json({ error: 'Only Admins can manage team access.' });
    }

    const memberId = req.params.memberId;
    const member = data.team.find(m => m.id === memberId);
    if (!member) return res.status(404).json({ error: 'User not found.' });
    if (member.id === req.userId) {
      return res.status(400).json({ error: 'You cannot suspend yourself.' });
    }

    const isSuspended = (member.status || 'Active') === 'Suspended';
    const shouldSuspend = typeof req.body?.suspended === 'boolean'
      ? req.body.suspended
      : !isSuspended;

    if (shouldSuspend && member.role === 'Admin') {
      const activeAdmins = data.team.filter(m => m.role === 'Admin' && (m.status || 'Active') !== 'Suspended');
      if (activeAdmins.length <= 1 && !isSuspended) {
        return res.status(400).json({ error: 'Cannot suspend the last active Admin. Promote or restore another Admin first.' });
      }
    }

    if (shouldSuspend) {
      if (!isSuspended) member.statusBeforeSuspend = member.status || 'Active';
      member.status = 'Suspended';
      revokeSessionsForUsers([member.id]);
    } else {
      member.status = member.statusBeforeSuspend || 'Active';
      delete member.statusBeforeSuspend;
    }

    await setCrmData(data);
    res.json({ ok: true, member, team: data.team });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// One-time migration endpoint. Requires MIGRATE_SECRET to be set in .env
// and passed back as a header — disabled entirely otherwise. Remove this
// route (or unset MIGRATE_SECRET) once you're done migrating.
app.post('/api/migrate', async (req, res) => {
  try {
    const secret = process.env.MIGRATE_SECRET;
    if (!secret) return res.status(403).json({ error: 'Migration disabled. Set MIGRATE_SECRET in .env to enable it temporarily.' });
    if (req.headers['x-migrate-secret'] !== secret) return res.status(401).json({ error: 'Invalid migration secret.' });
    const payload = {
      team: req.body.team || [],
      clients: req.body.clients || [],
      meetings: req.body.meetings || [],
      deletedMeetingIds: req.body.deletedMeetingIds || [],
      projects: req.body.projects || [],
      activity: req.body.activity || [],
      messages: req.body.messages || [],
      chatGroups: req.body.chatGroups || [],
      notifications: req.body.notifications || [],
      spreadsheets: req.body.spreadsheets || [],
      notes: req.body.notes || [],
    };
    await hashPlaintextPasswords(payload);
    await setCrmData(payload);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• 
   AI SPRINT PLANNER
   â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â•  */
const SYSTEM_PROMPT = `You are an expert agile delivery lead helping plan a client project's sprints.
Given a project plan, project details, a start date, an end date, and team size, produce a sprint plan.

Return STRICT JSON only: no markdown fences, no commentary, no text outside the JSON. Match this exact schema:
{
  "approach": string (recommended SD process like Scrum/Kanban and short rationale),
  "sprints": [
    {
      "name": string,
      "range": string,
      "tasks": [
        { "title": string, "assignee": string | null, "description": string }
      ]
    }
  ]
}

Rules:
- If REQUESTED SPRINT COUNT is specified, you MUST generate exactly that many sprints. Otherwise, split the timeframe sensibly.
- For each task, "description" MUST contain a detailed explanation of what will be done, the expected output, and how it will be delivered.
- Each sprint MUST have 8-15 specific, granular, actionable tasks derived from the project plan.
- EVERY sprint MUST end with a dedicated "Testing & QA" task.
- The last sprint must include "Final end-to-end testing", "User acceptance testing", "Deployment & release", and "Documentation handoff".
- Sprint 1 MUST include foundational tasks: repo setup, scaffolding, CI/CD, database schema, environment config.
- In the recommended approach rationale, accurately reflect the total project duration between START DATE and END DATE. Do NOT call the project a "2-week project" unless the total project duration is exactly 14 days.
- Do not include any text, explanation, or markdown outside the single JSON object.`;

app.post('/api/plan-sprint', validateSession, async (req, res) => {
  try {
    const { planText, projectDetails, startDate, endDate, teamSize, teamMemberNames, sprintCount, promptInstructions } = req.body || {};
    if (!planText && !projectDetails) return res.status(400).json({ error: 'Provide at least a project plan or project details.' });
    if (!startDate) return res.status(400).json({ error: 'startDate is required.' });
    if (!endDate) return res.status(400).json({ error: 'endDate is required.' });

    let durationText = '';
    if (startDate && endDate) {
      const dStart = new Date(startDate);
      const dEnd = new Date(endDate);
      if (!isNaN(dStart.getTime()) && !isNaN(dEnd.getTime()) && dEnd > dStart) {
        const diffDays = Math.round((dEnd.getTime() - dStart.getTime()) / (1000 * 60 * 60 * 24));
        const diffWeeks = Math.round((diffDays / 7) * 10) / 10;
        durationText = `${diffDays} days (~${diffWeeks} weeks)`;
      }
    }

    const userPrompt = [
      `PROJECT DETAILS:\n${projectDetails || '(none provided)'}`,
      `UPLOADED PROJECT PLAN:\n${planText || '(none provided)'}`,
      `START DATE: ${startDate || '(not specified, assume today)'}`,
      `END DATE: ${endDate}`,
      durationText ? `CALCULATED TOTAL PROJECT DURATION: ${durationText}` : '',
      `TEAM SIZE: ${teamSize || '(not specified)'}`,
      `TEAM MEMBER NAMES: ${(teamMemberNames && teamMemberNames.length) ? teamMemberNames.join(', ') : '(not provided)'}`,
      `REQUESTED SPRINT COUNT: ${sprintCount || 'Determine automatically based on dates'}`,
      `ADDITIONAL INSTRUCTIONS:\n${promptInstructions || 'Follow the rules.'}`
    ].filter(Boolean).join('\n\n');
    const completion = await groqClient.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [{ role: 'system', content: SYSTEM_PROMPT }, { role: 'user', content: userPrompt }],
      temperature: 0.4,
      response_format: { type: 'json_object' },
    });
    const raw = (completion.choices[0].message.content || '').trim();
    const jsonText = raw.replace(/^```json\s*/i, '').replace(/^```\s*/, '').replace(/```\s*$/, '');
    let parsed;
    try { parsed = JSON.parse(jsonText); } catch (e) {
      return res.status(502).json({ error: 'The AI did not return valid JSON. Try again.' });
    }
    if (!parsed.sprints || !Array.isArray(parsed.sprints)) {
      return res.status(502).json({ error: 'AI response missing "sprints" array.' });
    }
    res.json(parsed);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Server error contacting Groq.' });
  }
});

/* â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• 
   PLAN FILE ROUTES
   â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â•  */
app.post('/api/save-plan', validateSession, async (req, res) => {
  try {
    const { projectId, filename, fileBase64 } = req.body || {};
    if (!projectId || !filename || !fileBase64) return res.status(400).json({ error: 'projectId, filename, and fileBase64 are required.' });

    if (!b2Client) {
      throw new Error('Backblaze B2 is not configured on this server.');
    }

    const clean = safeFilename(filename);
    const buffer = Buffer.from(fileBase64, 'base64');
    const ext = path.extname(clean).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    const storagePath = `project-plans/${projectId}/${clean}`;
    await uploadToB2(storagePath, buffer, contentType);
    console.log(`☁️ Project plan uploaded to Backblaze B2: ${storagePath}`);

    res.json({ ok: true, filename: clean });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Could not save the plan file.' });
  }
});

app.get('/api/has-plan/:projectId', validateSession, async (req, res) => {
  try {
    const projectId = req.params.projectId;
    const data = await getCrmData();
    const project = (data.projects || []).find(p => p.id === projectId);
    if (project && project.planFileName) {
      return res.json({ exists: true, filename: project.planFileName });
    }
    res.json({ exists: false });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/get-plan/:projectId', validateSession, async (req, res) => {
  try {
    const projectId = req.params.projectId;

    if (!b2Client) {
      throw new Error('Backblaze B2 is not configured on this server.');
    }

    const data = await getCrmData();
    const project = (data.projects || []).find(p => p.id === projectId);
    const filename = project?.planFileName;

    if (!filename) {
      return res.status(404).json({ error: 'No plan file saved for this project.' });
    }

    const clean = safeFilename(filename);
    const ext = path.extname(clean).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    const storagePath = `project-plans/${projectId}/${clean}`;
    const response = await b2Client.send(new GetObjectCommand({
      Bucket: B2_BUCKET,
      Key: storagePath,
    }));

    const stream = response.Body;
    const buffer = await new Promise((resolve, reject) => {
      const chunks = [];
      stream.on('data', (chunk) => chunks.push(chunk));
      stream.on('error', reject);
      stream.on('end', () => resolve(Buffer.concat(chunks)));
    });
    console.log(`☁️ Serving project plan from B2: ${storagePath}`);

    res.setHeader('Content-Type', contentType);
    res.setHeader('X-Plan-Filename', encodeURIComponent(filename));
    res.send(buffer);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• 
   SEND INVITE EMAIL
   â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â•  */

// Lazily-created transporter so we don't crash if SMTP vars are missing
let _mailer = null;
function getMailer() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) return null;
  const port = parseInt(SMTP_PORT || '465', 10);
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port,
    secure: port === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
    tls: { rejectUnauthorized: false }
  });
}


// ── Auto Mail (System Email Template Renderer & Automation Engine) ───────────
function renderAutoMailHtml(template, vars) {
  const brandName = vars.fromName || process.env.SMTP_FROM_NAME || 'Startup CRM';
  const supportEmail = vars.supportEmail || process.env.SUPPORT_EMAIL || 'support@startupbuild.tech';
  const appUrl = process.env.APP_URL || 'https://crm.startupbuild.tech';
  const loginUrl = vars.loginUrl || (appUrl.replace(/\/$/, '') + '/');

  const allVars = {
    brandName,
    supportEmail,
    appUrl,
    loginUrl,
    dashboardUrl: loginUrl,
    ...vars
  };

  let subject = template.subject || '(No Subject)';
  let bodyHtml = template.bodyHtml || '';
  const bgColor = template.bgColor || '#F7F7F5';
  const cardBgColor = template.cardBgColor || '#FFFFFF';
  const textColor = template.textColor || '#111111';

  // Sanitize any legacy localhost links in custom stored templates
  subject = subject.replace(/http:\/\/localhost(:\d+)?/gi, appUrl).replace(/http:\/\/127\.0\.0\.1(:\d+)?/gi, appUrl);
  bodyHtml = bodyHtml.replace(/http:\/\/localhost(:\d+)?/gi, appUrl).replace(/http:\/\/127\.0\.0\.1(:\d+)?/gi, appUrl);

  for (const [k, v] of Object.entries(allVars)) {
    const reg = new RegExp('{{\\s*' + k + '\\s*}}', 'g');
    const val = v !== undefined && v !== null ? String(v) : '';
    subject = subject.replace(reg, val);
    bodyHtml = bodyHtml.replace(reg, val);
  }

  let bgStyle = 'background: ' + bgColor + ';';
  if (bgColor.startsWith('http://') || bgColor.startsWith('https://')) {
    bgStyle = "background-image: url('" + bgColor + "'); background-size: cover; background-position: center;";
  }

  const fullHtml = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${subject}</title>
<style>
  body { margin: 0; padding: 24px 12px; ${bgStyle} font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; }
  .email-container { max-width: 640px; margin: 0 auto; background: ${cardBgColor}; border-radius: 8px; border: 1px solid rgba(0,0,0,0.08); overflow: hidden; box-shadow: 0 8px 30px rgba(0,0,0,0.12); }
  .email-header { padding: 24px 32px; border-bottom: 1px solid rgba(0,0,0,0.06); font-size: 18px; font-weight: 800; color: #04013E; }
  .email-header span { color: #12A3B4; }
  .email-body { padding: 36px 32px; color: ${textColor}; line-height: 1.65; font-size: 14px; }
  .email-footer { padding: 20px 32px; background: rgba(0,0,0,0.02); border-top: 1px solid rgba(0,0,0,0.05); font-size: 11px; color: #888888; text-align: center; }
  a { color: #12A3B4; }
</style>
</head>
<body style="${bgStyle}">
  <div class="email-container">
    <div class="email-header">Start<span>up.</span></div>
    <div class="email-body">
      ${bodyHtml}
    </div>
    <div class="email-footer">
      Automated email sent by ${brandName}. Need support? Contact <a href="mailto:${supportEmail}">${supportEmail}</a>
    </div>
  </div>
</body>
</html>`;

  return { subject, html: fullHtml };
}

async function checkBirthdayAutoMails() {
  try {
    const mailer = getMailer();
    if (!mailer) return;

    const data = await getCrmData();
    const now = new Date();
    const currentMonth = String(now.getMonth() + 1).padStart(2, '0');
    const currentDate = String(now.getDate()).padStart(2, '0');
    const currentYear = now.getFullYear();

    const appUrl = process.env.APP_URL || 'https://crm.startupbuild.tech';
    const brandName = process.env.SMTP_FROM_NAME || 'Startup CRM';
    const supportEmail = process.env.SUPPORT_EMAIL || 'support@startupbuild.tech';
    const loginUrl = appUrl.replace(/\/$/, '') + '/';

    // Built-in birthday email template — always active, no admin setup required.
    // Customize the HTML below to change the birthday email design.
    const birthdayTemplate = {
      subject: '🎉 Happy Birthday, {{toName}}! 🎂',
      bgColor: 'linear-gradient(135deg, #0d1b2a 0%, #1b263b 100%)',
      cardBgColor: '#FFFFFF',
      textColor: '#111111',
      bodyHtml: `
<div style="text-align:center; padding:10px 0;">
  <div style="font-size:52px; margin-bottom:12px;">🎂</div>
  <h1 style="color:#12A3B4; margin:0 0 14px 0; font-size:28px; font-weight:800;">Happy Birthday, {{toName}}!</h1>
  <p style="font-size:15px; line-height:1.7; color:#333333; margin:0 0 18px 0;">
    Wishing you a wonderful birthday filled with joy, happiness, and great moments!
  </p>
  <p style="font-size:14px; color:#555555; margin:0 0 24px 0;">
    Thank you for being an amazing part of the team at <strong>{{brandName}}</strong>. We truly appreciate everything you bring to the table.
  </p>
  <a href="{{loginUrl}}" style="display:inline-block; background:#12A3B4; color:#ffffff; text-decoration:none; padding:13px 28px; border-radius:4px; font-weight:800; font-size:14px;">Open Dashboard</a>
</div>`
    };

    const team = data.team || [];
    let updated = false;

    for (const member of team) {
      if (!member.email || (member.status || 'Active') === 'Suspended') continue;
      const bdayStr = member.birthday;
      if (!bdayStr) continue;

      let mMonth = '', mDate = '';
      if (bdayStr.includes('/')) {
        const parts = bdayStr.split('/');
        if (parts.length >= 2) {
          mDate = parts[0].padStart(2, '0');
          mMonth = parts[1].padStart(2, '0');
        }
      } else if (bdayStr.includes('-')) {
        const parts = bdayStr.split('-');
        if (parts.length === 3 && parts[0].length === 4) {
          mMonth = parts[1].padStart(2, '0');
          mDate = parts[2].padStart(2, '0');
        } else if (parts.length >= 2) {
          mDate = parts[0].padStart(2, '0');
          mMonth = parts[1].padStart(2, '0');
        }
      }

      if (mMonth === currentMonth && mDate === currentDate) {
        if (member.lastBirthdayEmailYear === currentYear) continue;

        const rendered = renderAutoMailHtml(birthdayTemplate, {
          toName: member.name || member.email,
          toEmail: member.email,
          userBirthday: bdayStr,
          brandName,
          loginUrl,
          fromName: brandName,
          fromAddr: process.env.SMTP_USER,
          supportEmail
        });

        await mailer.sendMail({
          from: `"${brandName}" <${process.env.SMTP_USER}>`,
          to: `"${member.name || ''}" <${member.email}>`,
          subject: rendered.subject,
          html: rendered.html
        });

        console.log(`🎂 Birthday email sent to ${member.email}`);
        member.lastBirthdayEmailYear = currentYear;
        updated = true;
      }
    }

    if (updated) {
      await setCrmData(data);
    }
  } catch (err) {
    console.warn('[BirthdayMailer] Error:', err.message);
  }
}

setInterval(checkBirthdayAutoMails, 2 * 60 * 60 * 1000);
setTimeout(checkBirthdayAutoMails, 10000);



app.post('/api/send-invite-email', validateSession, async (req, res) => {
  try {
    const { toName, toEmail, password } = req.body || {};
    if (!toName || !toEmail) return res.status(400).json({ error: 'toName and toEmail are required.' });

    const mailer = getMailer();
    if (!mailer) {
      console.warn('âš ï¸   SMTP not configured — skipping invite email.');
      return res.json({ ok: true, skipped: true, reason: 'SMTP not configured.' });
    }

    const appUrl = process.env.APP_URL || 'https://crm.startupbuild.tech';
    const loginUrl = appUrl.replace(/\/$/, '') + '/';
    const fromName = process.env.SMTP_FROM_NAME || 'Startup CRM';
    const fromAddr = process.env.SMTP_USER;
    const supportEmail = process.env.SUPPORT_EMAIL || 'support@startupbuild.tech';

    const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome to Startup. - Your Account Login Details</title>
<style>
  body{margin:0;padding:0;background:#F7F7F5;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;color:#111}
  .email{max-width:640px;margin:0 auto;background:#fff;border:1px solid #EAEAE4;border-radius:8px;overflow:hidden;box-shadow:0 8px 30px rgba(0,0,0,0.08)}
  .brand{padding:28px 32px 24px;border-bottom:1px solid #F0F0EA;font-size:20px;font-weight:800;color:#04013E}
  .brand span{color:#12A3B4}
  .body{padding:42px 32px 36px}
  h1{margin:0 0 24px;font-size:26px;line-height:1.2;font-weight:800;color:#050505}
  p{margin:0 0 18px;line-height:1.65;font-size:14px;color:#333}
  strong{font-weight:700}
  .accent{color:#12A3B4;font-weight:700}
  .key{font-family:Consolas,'Courier New',monospace;color:#084D58;font-weight:700;background:rgba(18,163,180,0.08);padding:3px 8px;border-radius:4px}
  .button{display:inline-block;background:#12A3B4;color:#ffffff !important;text-decoration:none;padding:14px 28px;border-radius:6px;font-weight:700;font-size:14px;margin:12px 0 18px}
  a{color:#12A3B4;font-weight:700}
</style>
</head>
<body>
<div class="email">
  <div class="brand">Start<span>up.</span></div>
  <div class="body">
    <h1>Welcome to Startup.</h1>
    <p>Hi <strong>${toName}</strong>,</p>
    <p>Welcome to the team! We're excited to have you on board at <strong>Startup</strong>.</p>
    <p>Your account has been created and is ready to use. Here are your login details:</p>
    <p style="background:#F9F9F8;padding:16px 20px;border-radius:8px;border:1px solid #EAEAE4;line-height:1.8;">
      <strong>Login Email:</strong> <span class="accent">${toEmail}</span><br>
      <strong>Temporary Password:</strong> <span class="key">${password || '0000'}</span>
    </p>
    <p>For security reasons, please log in and change your password immediately after your first sign-in.</p>
    <p style="margin:24px 0 20px;">
      <a class="button" href="${loginUrl}" target="_blank" style="display:inline-block;background:#12A3B4;color:#ffffff !important;text-decoration:none;padding:14px 28px;border-radius:6px;font-weight:700;font-size:14px;">Open Dashboard &rarr;</a>
    </p>
    <p style="font-size:13px;color:#666;">Login Link: <a href="${loginUrl}" target="_blank" style="color:#12A3B4;word-break:break-all;">${loginUrl}</a></p>
    <p style="margin-top:28px;font-size:13px;color:#666;">If you have any trouble accessing your account, reach out to <a href="mailto:${supportEmail}" style="color:#12A3B4;">${supportEmail}</a>.</p>
    <p style="margin-top:24px;">Best regards,<br><strong>Startup Team</strong></p>
  </div>
</div>
</body>
</html>`;

    const crmDataForMail = await getCrmData();
    const autoMails = crmDataForMail.autoMails || [];
    const customInviteRule = autoMails.find(m => m.triggerCondition === 'member_invited' && m.status === 'Active');

    let sendSubject = `Welcome to Startup. - Your Account Login Details`;
    let sendHtml = html;

    if (customInviteRule) {
      const rendered = renderAutoMailHtml(customInviteRule, {
        toName, toEmail, password: password || '0000', loginUrl, fromName, fromAddr, supportEmail
      });
      sendSubject = rendered.subject;
      sendHtml = rendered.html;
    }

    // Ensure no localhost URLs slip through custom rules
    sendHtml = sendHtml.replace(/http:\/\/localhost(:\d+)?/gi, appUrl).replace(/http:\/\/127\.0\.0\.1(:\d+)?/gi, appUrl);

    await mailer.sendMail({
      from: `"${fromName}" <${fromAddr}>`,
      to: `"${toName}" <${toEmail}>`,
      subject: sendSubject,
      html: sendHtml,
    });

    console.log(`📧 Invite email sent to ${toEmail}`);
    res.json({ ok: true });
  } catch (err) {
    console.error('Email send error:', err);
    res.status(500).json({ error: err.message || 'Failed to send invite email.' });
  }
});

/* â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• 
   ZOHO MAIL API
   Credentials are stored per-user inside zohoMailSettings[userId] in
   Supabase (inside the crm jsonb blob), AES-256-GCM encrypted. They are NEVER returned via /api/db.
   â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â•  */

/** Resolve the correct Zoho IMAP/SMTP host based on the user's email TLD. */
function getZohoHosts(email) {
  const lc = (email || '').toLowerCase();
  if (lc.endsWith('.eu') || lc.includes('@zoho.eu')) return { imap: 'imap.zoho.eu', smtp: 'smtp.zoho.eu' };
  if (lc.endsWith('.in') || lc.includes('@zoho.in') || lc.includes('.in>')) return { imap: 'imap.zoho.in', smtp: 'smtp.zoho.in' };

  // Default fallback matching the main organization's Zoho SMTP host
  const mainHost = (process.env.SMTP_HOST || 'smtp.zoho.com').toLowerCase();
  if (mainHost.endsWith('.in')) {
    return { imap: 'imap.zoho.in', smtp: 'smtp.zoho.in' };
  }
  if (mainHost.endsWith('.eu')) {
    return { imap: 'imap.zoho.eu', smtp: 'smtp.zoho.eu' };
  }
  return { imap: 'imap.zoho.com', smtp: 'smtp.zoho.com' };
}

/** Build an authenticated ImapFlow client from decrypted credentials. */
function makeImapClient(email, password) {
  const { imap } = getZohoHosts(email);
  return new ImapFlow({
    host: imap,
    port: 993,
    secure: true,
    auth: { user: email, pass: password },
    logger: false,
  });
}

// GET  /api/mail/settings  — return saved settings (password is masked/omitted)
app.get('/api/mail/settings', validateSession, async (req, res) => {
  try {
    const data = await getCrmData();
    const raw = ((data.zohoMailSettings || {})[req.userId]) || null;
    if (!raw) return res.json({ configured: false, email: '', name: '', replyto: '' });
    res.json({
      configured: true,
      email: raw.email || '',
      name: raw.name || '',
      replyto: raw.replyto || '',
      // password intentionally omitted — client shows a placeholder
    });
  } catch (e) {
    console.error('GET /api/mail/settings error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/mail/settings  — save / update Zoho credentials (password encrypted)
app.post('/api/mail/settings', validateSession, async (req, res) => {
  try {
    const { email, password, name, replyto } = req.body || {};
    if (!email) return res.status(400).json({ error: 'email is required.' });

    const data = await getCrmData();
    if (!data.zohoMailSettings) data.zohoMailSettings = {};

    const existing = data.zohoMailSettings[req.userId] || {};
    // If password is the sentinel placeholder or empty, keep the old encrypted one
    const encryptedPass = (password && password !== '__KEEP__')
      ? encryptField(password)
      : (existing.encryptedPassword || '');

    data.zohoMailSettings[req.userId] = {
      email,
      name: name || '',
      replyto: replyto || '',
      encryptedPassword: encryptedPass,
    };
    await setCrmData(data);
    console.log(`📧 Mail settings saved for user ${req.userId}`);
    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/mail/settings error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/mail/test-connection  — verify IMAP credentials live
app.post('/api/mail/test-connection', validateSession, async (req, res) => {
  try {
    const data = await getCrmData();
    const saved = ((data.zohoMailSettings || {})[req.userId]) || null;
    if (!saved || !saved.encryptedPassword) {
      return res.status(400).json({ error: 'No credentials saved. Please save your settings first.' });
    }
    const password = decryptField(saved.encryptedPassword);
    const client = makeImapClient(saved.email, password);
    await client.connect();
    await client.logout();
    res.json({ ok: true });
  } catch (e) {
    console.error('Test-connection error:', e.message);
    res.status(502).json({ error: e.message || 'IMAP connection failed.' });
  }
});

// GET  /api/mail/sync?folder=inbox|sent|drafts  — fetch live emails via IMAP
app.get('/api/mail/sync', validateSession, async (req, res) => {
  try {
    const folder = (req.query.folder || 'inbox').toLowerCase();
    const data = await getCrmData();
    const saved = ((data.zohoMailSettings || {})[req.userId]) || null;
    if (!saved || !saved.encryptedPassword) {
      return res.status(400).json({ error: 'Mail account not configured.' });
    }
    const password = decryptField(saved.encryptedPassword);
    const client = makeImapClient(saved.email, password);
    await client.connect();

    // Map friendly folder names to IMAP mailbox names
    const FOLDER_MAP = { inbox: 'INBOX', sent: 'Sent', drafts: 'Drafts' };
    const imapFolder = FOLDER_MAP[folder] || 'INBOX';

    const emails = [];
    try {
      const lock = await client.getMailboxLock(imapFolder);
      try {
        const total = client.mailbox.exists || 0;
        if (total > 0) {
          const start = Math.max(1, total - 49); // up to 50 most-recent
          for await (const msg of client.fetch(`${start}:${total}`, { uid: true, flags: true, envelope: true, source: true })) {
            try {
              const parsed = await simpleParser(msg.source);
              const fromAddr = parsed.from?.value?.[0] || {};
              emails.push({
                id: String(msg.uid),
                folder,
                fromName: fromAddr.name || fromAddr.address || 'Unknown',
                fromEmail: fromAddr.address || '',
                to: parsed.to?.text || '',
                cc: parsed.cc?.text || '',
                subject: parsed.subject || '(No Subject)',
                date: parsed.date ? parsed.date.toISOString() : new Date().toISOString(),
                body: parsed.text || (parsed.html ? parsed.html.replace(/<[^>]+>/g, ' ') : ''),
                unread: !msg.flags.has('\\Seen'),
                // Metadata only here — actual bytes are fetched on demand via /api/mail/attachment
                // to avoid re-downloading every attachment just to render the inbox list.
                attachments: (parsed.attachments || [])
                  .filter(a => a.contentDisposition !== 'inline' || !a.cid) // skip inline signature/logo images
                  .map((a, i) => ({
                    index: i,
                    filename: a.filename || `attachment-${i + 1}`,
                    size: a.size || (a.content ? a.content.length : 0),
                    contentType: a.contentType || 'application/octet-stream',
                  })),
              });
            } catch { /* skip unparseable messages */ }
          }
        }
      } finally {
        lock.release();
      }
    } finally {
      await client.logout();
    }

    emails.reverse(); // newest first
    res.json({ ok: true, emails });
  } catch (e) {
    console.error('Mail sync error:', e.message);
    res.status(502).json({ error: e.message || 'Failed to sync emails.' });
  }
});

// POST /api/mail/mark-read  { folder, uid }  — add \Seen flag on IMAP server
app.post('/api/mail/mark-read', validateSession, async (req, res) => {
  const { folder = 'inbox', uid } = req.body || {};
  if (!uid) return res.status(400).json({ error: 'uid is required.' });
  try {
    const data = await getCrmData();
    const saved = ((data.zohoMailSettings || {})[req.userId]) || null;
    if (!saved || !saved.encryptedPassword) {
      return res.status(400).json({ error: 'Mail account not configured.' });
    }
    const password = decryptField(saved.encryptedPassword);
    const client = makeImapClient(saved.email, password);
    await client.connect();
    const FOLDER_MAP = { inbox: 'INBOX', sent: 'Sent', drafts: 'Drafts' };
    const imapFolder = FOLDER_MAP[folder.toLowerCase()] || 'INBOX';
    try {
      const lock = await client.getMailboxLock(imapFolder);
      try {
        await client.messageFlagsAdd([parseInt(uid, 10)], ['\\Seen'], { uid: true });
      } finally { lock.release(); }
    } finally { await client.logout(); }
    res.json({ ok: true });
  } catch (e) {
    console.error('Mail mark-read error:', e.message);
    res.status(502).json({ error: e.message || 'Failed to mark as read.' });
  }
});

// GET  /api/mail/attachment?folder=inbox&uid=123&index=0  — download a single attachment's bytes
app.get('/api/mail/attachment', validateSession, async (req, res) => {
  const folder = (req.query.folder || 'inbox').toLowerCase();
  const uid = parseInt(req.query.uid, 10);
  const index = parseInt(req.query.index, 10);
  if (!uid || Number.isNaN(index)) {
    return res.status(400).json({ error: 'folder, uid, and index are required.' });
  }

  try {
    const data = await getCrmData();
    const saved = ((data.zohoMailSettings || {})[req.userId]) || null;
    if (!saved || !saved.encryptedPassword) {
      return res.status(400).json({ error: 'Mail account not configured.' });
    }
    const password = decryptField(saved.encryptedPassword);
    const client = makeImapClient(saved.email, password);
    await client.connect();

    const FOLDER_MAP = { inbox: 'INBOX', sent: 'Sent', drafts: 'Drafts' };
    const imapFolder = FOLDER_MAP[folder] || 'INBOX';

    let attachment = null;
    try {
      const lock = await client.getMailboxLock(imapFolder);
      try {
        const msg = await client.fetchOne(String(uid), { source: true }, { uid: true });
        if (msg && msg.source) {
          const parsed = await simpleParser(msg.source);
          attachment = (parsed.attachments || [])[index] || null;
        }
      } finally {
        lock.release();
      }
    } finally {
      await client.logout();
    }

    if (!attachment) return res.status(404).json({ error: 'Attachment not found.' });

    res.setHeader('Content-Type', attachment.contentType || 'application/octet-stream');
    const safeAttachName = encodeURIComponent(attachment.filename || 'attachment');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${safeAttachName}`);
    res.send(attachment.content);
  } catch (e) {
    console.error('Mail attachment fetch error:', e.message);
    res.status(502).json({ error: e.message || 'Failed to fetch attachment.' });
  }
});

const MAIL_MAX_ATTACH_BYTES = 20 * 1024 * 1024; // ~20MB total, matches typical Zoho send limits

// POST /api/mail/send  — send an email via Zoho SMTP using the user's own credentials
app.post('/api/mail/send', validateSession, async (req, res) => {
  try {
    const { to, cc, subject, body, attachments } = req.body || {};
    if (!to) return res.status(400).json({ error: 'Recipient (to) is required.' });

    // Validate attachments: each is { filename, contentType, content (base64) }
    let mailAttachments = [];
    if (Array.isArray(attachments) && attachments.length) {
      let totalBytes = 0;
      for (const att of attachments) {
        if (!att || typeof att.content !== 'string' || !att.filename) {
          return res.status(400).json({ error: 'Each attachment needs a filename and base64 content.' });
        }
        const buffer = Buffer.from(att.content, 'base64');
        totalBytes += buffer.length;
        if (totalBytes > MAIL_MAX_ATTACH_BYTES) {
          return res.status(400).json({ error: `Attachments exceed the ${(MAIL_MAX_ATTACH_BYTES / (1024 * 1024)).toFixed(0)}MB limit.` });
        }
        mailAttachments.push({
          filename: att.filename,
          content: buffer,
          contentType: att.contentType || 'application/octet-stream',
        });
      }
    }

    const data = await getCrmData();
    const saved = ((data.zohoMailSettings || {})[req.userId]) || null;
    if (!saved || !saved.encryptedPassword) {
      return res.status(400).json({ error: 'Mail account not configured. Go to Mail Settings first.' });
    }
    const password = decryptField(saved.encryptedPassword);
    const { smtp } = getZohoHosts(saved.email);

    const transporter = nodemailer.createTransport({
      host: smtp,
      port: 465,
      secure: true,
      auth: { user: saved.email, pass: password },
    });

    const fromLabel = saved.name
      ? `"${saved.name}" <${saved.email}>`
      : saved.email;

    await transporter.sendMail({
      from: fromLabel,
      to,
      ...(cc ? { cc } : {}),
      replyTo: saved.replyto || saved.email,
      subject: subject || '(No Subject)',
      text: body || '',
      ...(mailAttachments.length ? { attachments: mailAttachments } : {}),
    });

    console.log(`📤 Email sent by ${req.userId} to ${to}${mailAttachments.length ? ` with ${mailAttachments.length} attachment(s)` : ''}`);
    res.json({ ok: true });
  } catch (e) {
    console.error('Mail send error:', e.message);
    res.status(502).json({ error: e.message || 'Failed to send email.' });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

/* â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• 
   BACKBLAZE B2 STORAGE — Asset bucket for client file uploads (S3-compatible)
   â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â• â•  */

import { S3Client, PutObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { GetObjectCommand } from '@aws-sdk/client-s3';

let b2Client = null;
const B2_BUCKET = process.env.B2_BUCKET_NAME || '';

async function initB2() {
  const keyId = process.env.B2_KEY_ID;
  const appKey = process.env.B2_APP_KEY;
  const endpoint = process.env.B2_ENDPOINT; // e.g. https://s3.us-west-004.backblazeb2.com
  if (!keyId || !appKey || !endpoint || !B2_BUCKET) {
    throw new Error('Backblaze B2 env vars missing: B2_KEY_ID, B2_APP_KEY, B2_ENDPOINT, B2_BUCKET_NAME');
  }
  // Derive region from endpoint (e.g. https://s3.us-east-005.backblazeb2.com → us-east-005)
  const regionMatch = endpoint.match(/s3\.([^.]+)\.backblazeb2\.com/);
  const region = regionMatch ? regionMatch[1] : 'us-west-004';
  b2Client = new S3Client({
    endpoint,
    region,
    credentials: { accessKeyId: keyId, secretAccessKey: appKey },
  });
  console.log(`✅ Backblaze B2 Storage connected → ${B2_BUCKET}`);
}

// multer: store uploads in memory, then stream to B2 (nothing touches disk)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 }, // 500 MB per file hard cap
});

/* ── Helpers ─────────────────────────────────────────────────────────── */

/** Upload a buffer to Backblaze B2. */
async function uploadToB2(storagePath, buffer, contentType) {
  await b2Client.send(new PutObjectCommand({
    Bucket: B2_BUCKET,
    Key: storagePath,
    Body: buffer,
    ContentType: contentType,
  }));
}

/** Generate a Backblaze B2 signed URL valid for 60 minutes. */
async function signedDownloadUrl(storagePath) {
  const cmd = new GetObjectCommand({ Bucket: B2_BUCKET, Key: storagePath });
  return await getSignedUrl(b2Client, cmd, { expiresIn: 3600 });
}

/** Delete a file from Backblaze B2 (non-throwing — logs on error). */
async function deleteFromB2(storagePath) {
  try {
    await b2Client.send(new DeleteObjectCommand({ Bucket: B2_BUCKET, Key: storagePath }));
  } catch (e) {
    console.warn(`âš ï¸   Could not delete B2 file ${storagePath}:`, e.message);
  }
}

/** Check whether the requesting user is a member of the given project (from CRM data). */
function userCanAccessProject(crmData, userId, projectId) {
  const me = (crmData.team || []).find(m => m.id === userId);
  if (!me) return false;
  if (hasPermission(me.role, 'canAssignAdmins')) return true;
  const project = (crmData.projects || []).find(p => p.id === projectId);
  if (!project) return false;
  // Support both array-of-ids and array-of-objects member formats
  const members = project.members || project.team || [];
  return members.some(m => (typeof m === 'string' ? m : m.id) === userId);
}

/* ────────────────────────────────────────────────────────────────────────
   BACKBLAZE B2 STORAGE ROUTES
   ──────────────────────────────────────────────────────────────────────── */

// GET /asset-bucket/:token — Serve the client upload page (asset-bucket.html)
// This route must come BEFORE express.static so it takes priority.
app.get('/asset-bucket/:token', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'upload.html'));
});

// GET /api/storage/validate/:token — validate a bucket token and return quota/usage info
app.get('/api/storage/validate/:token', async (req, res) => {
  try {
    const { data: bucket, error } = await supabase
      .from('asset_buckets')
      .select('id, project_id, project_name, revoked')
      .eq('token', req.params.token)
      .single();

    if (error || !bucket) return res.json({ valid: false, reason: 'Link not found. Please contact the admin.' });
    if (bucket.revoked) return res.json({ valid: false, reason: 'This upload link has been restricted by the admin.' });

    // Sum used bytes for this bucket
    const { data: usage } = await supabase
      .from('assets')
      .select('size_bytes')
      .eq('bucket_id', bucket.id);
    const usedBytes = (usage || []).reduce((s, a) => s + parseInt(a.size_bytes || 0), 0);
    let quotaBytes = CLIENT_QUOTA_BYTES;

    // Retrieve client name from CRM data projects
    let clientName = 'Client';
    try {
      const crmData = await getCrmData();
      const proj = (crmData.projects || []).find(p => String(p.id) === String(bucket.project_id));
      if (proj) {
        if (proj.assetBucketConfig?.customQuotaBytes) {
          quotaBytes = parseInt(proj.assetBucketConfig.customQuotaBytes);
        }
        // Projects reference their client via clientId; the actual name lives on
        // the client record in crmData.clients (see dashboard.html db.clients.push
        // -> { id, name, company, ... } and getClient(p.clientId) usage).
        let found = '';
        if (proj.clientId) {
          const clientRecord = (crmData.clients || []).find(c => String(c.id) === String(proj.clientId));
          if (clientRecord) {
            found = String(clientRecord.name || clientRecord.company || '').trim();
          }
        }

        // Fallback: a direct string field on the project itself, in case older
        // records stored the name inline instead of via clientId.
        if (!found) {
          found = String(
            proj.clientName ||
            proj.client_name ||
            proj.contactName ||
            proj.contact_name ||
            ''
          ).trim();
        }

        clientName = found || 'Client';
      }
    } catch (e) {
      console.warn('Could not read clientName from CRM data:', e.message);
    }

    res.json({
      valid: true,
      bucketId: bucket.id,
      projectId: bucket.project_id,
      projectName: bucket.project_name,
      clientName,
      quotaBytes,
      usedBytes,
      remainingBytes: Math.max(0, quotaBytes - usedBytes),
    });
    appendActivity(makeActivityEntry(req, {
      actorType: 'client',
      actorName: clientName,
      action: 'storage.client_portal_open',
      targetType: 'asset_bucket',
      targetId: bucket.id,
      targetName: bucket.project_name,
      text: `${clientName} opened the upload portal for ${bucket.project_name}.`,
      metadata: { projectId: bucket.project_id, usedBytes, quotaBytes },
    })).catch(e => console.warn('activity portal open error:', e.message));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/storage/bucket/:token/files — Public: list files already uploaded to this bucket
app.get('/api/storage/bucket/:token/files', async (req, res) => {
  try {
    const { data: bucket, error: bErr } = await supabase
      .from('asset_buckets')
      .select('id, project_id, project_name, revoked')
      .eq('token', req.params.token)
      .single();
    if (bErr || !bucket) return res.status(404).json({ error: 'Bucket not found.' });
    if (bucket.revoked) return res.status(403).json({ error: 'This link has been restricted.' });

    const { data: files, error } = await supabase
      .from('assets')
      .select('id, filename, size_bytes, content_type, uploaded_at, client_name')
      .eq('bucket_id', bucket.id)
      .order('uploaded_at', { ascending: false });
    if (error) throw new Error(error.message);

    const usedBytes = (files || []).reduce((s, a) => s + parseInt(a.size_bytes || 0), 0);
    let quotaBytes = CLIENT_QUOTA_BYTES;
    try {
      const crmData = await getCrmData();
      const proj = (crmData.projects || []).find(p => String(p.id) === String(bucket.project_id));
      if (proj && proj.assetBucketConfig?.customQuotaBytes) {
        quotaBytes = parseInt(proj.assetBucketConfig.customQuotaBytes);
      }
    } catch (e) { }

    res.json({ ok: true, files: files || [], usedBytes, quotaBytes });
    appendActivity(makeActivityEntry(req, {
      actorType: 'client',
      actorName: 'Client upload link',
      action: 'storage.client_files_view',
      targetType: 'asset_bucket',
      targetId: bucket.id,
      targetName: bucket.project_name,
      text: `A client viewed files in ${bucket.project_name}.`,
      metadata: { fileCount: (files || []).length, usedBytes, quotaBytes },
    })).catch(e => console.warn('activity bucket files error:', e.message));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// ── PROMISE CACHES to prevent Thundering Herd on Database ──
const bucketTokenCache = new Map();
const bucketTokenPromises = new Map();

async function getBucketByToken(token) {
  if (bucketTokenCache.has(token)) {
    const cached = bucketTokenCache.get(token);
    if (Date.now() < cached.expiresAt) return cached.bucket;
  }
  if (bucketTokenPromises.has(token)) {
    return bucketTokenPromises.get(token);
  }

  const promise = (async () => {
    const { data: bucket, error } = await supabase
      .from('asset_buckets')
      .select('*')
      .eq('token', token)
      .single();

    if (!error && bucket) {
      bucketTokenCache.set(token, {
        bucket,
        expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
      });
    }
    bucketTokenPromises.delete(token);
    return bucket || null;
  })();

  bucketTokenPromises.set(token, promise);
  return promise;
}

const assetCache = new Map();
const assetPromiseCache = new Map();

async function getAssetById(assetId) {
  if (assetCache.has(assetId)) {
    const cached = assetCache.get(assetId);
    if (Date.now() < cached.expiresAt) return cached.asset;
  }
  if (assetPromiseCache.has(assetId)) {
    return assetPromiseCache.get(assetId);
  }

  const promise = (async () => {
    const { data: asset, error } = await supabase
      .from('assets')
      .select('id, bucket_id, storage_path, content_type, project_id, filename')
      .eq('id', assetId)
      .single();

    if (!error && asset) {
      assetCache.set(assetId, {
        asset,
        expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
      });
    }
    assetPromiseCache.delete(assetId);
    return asset || null;
  })();

  assetPromiseCache.set(assetId, promise);
  return promise;
}

const previewUrlCache = new Map();

// GET /api/storage/bucket/:token/files/:assetId/preview — Public: signed thumbnail URL for one
// asset in this bucket. Scoped to the bucket token so a link can only preview its own files.
app.get('/api/storage/bucket/:token/files/:assetId/preview', async (req, res) => {
  try {
    const cacheKey = `${req.params.token}_${req.params.assetId}`;
    const cached = previewUrlCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return res.json({ ok: true, url: cached.url, contentType: cached.contentType });
    }

    const bucket = await getBucketByToken(req.params.token);
    const bErr = !bucket;
    if (bErr || !bucket) {
      return res.status(404).json({ error: 'Bucket not found.' });
    }
    if (bucket.revoked) return res.status(403).json({ error: 'This link has been restricted.' });

    const asset = await getAssetById(req.params.assetId);
    const aErr = !asset;
    if (aErr || !asset) {
      return res.status(404).json({ error: 'File not found.' });
    }
    if (String(asset.bucket_id) !== String(bucket.id)) {
      return res.status(404).json({ error: 'File not found.' });
    }
    if (!(asset.content_type || '').startsWith('image/')) {
      return res.status(400).json({ error: 'Preview is only available for images.' });
    }

    const url = await signedDownloadUrl(asset.storage_path);

    // Cache for 50 minutes (since B2 signed URL is valid for 60 mins)
    previewUrlCache.set(cacheKey, {
      url,
      contentType: asset.content_type,
      expiresAt: Date.now() + 50 * 60 * 1000
    });

    res.json({ ok: true, url, contentType: asset.content_type });
    // Activity log removed to drastically save egress and db writes
  } catch (e) {
    console.error('preview endpoint error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/storage/upload/:token — Upload files to a project bucket (quota-enforced)
const storageUploadLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, message: { error: 'Upload rate limit exceeded.' } });
app.post('/api/storage/upload/:token', storageUploadLimiter, upload.array('files', 100), async (req, res) => {
  try {
    const files = req.files || [];
    if (!files.length) return res.status(400).json({ error: 'No files received.' });

    const bucket = await getBucketByToken(req.params.token);
    const bErr = !bucket;

    if (bErr || !bucket) return res.status(404).json({ error: 'Asset bucket not found.' });
    if (bucket.revoked) return res.status(403).json({ error: 'This upload link has been restricted.' });

    // ── Quota check ──────────────────────────────────────────────────────
    const crmData = await getCrmData();
    const project = (crmData.projects || []).find(p => p.id === bucket.project_id);
    const customQuota = project?.assetBucketConfig?.customQuotaBytes;
    const quotaBytes = customQuota ? parseInt(customQuota) : CLIENT_QUOTA_BYTES;

    const oversized = files.find(file => file.size > quotaBytes);
    if (oversized) {
      return res.status(413).json({
        error: `File upload limit reached — "${oversized.originalname}" exceeds the ${fmtBytesServer(quotaBytes)} limit. Please contact your admin.`,
      });
    }

    const { data: existing } = await supabase.from('assets').select('size_bytes').eq('bucket_id', bucket.id);
    const usedBytes = (existing || []).reduce((s, a) => s + parseInt(a.size_bytes || 0), 0);
    const incomingBytes = files.reduce((s, f) => s + f.size, 0);
    if (usedBytes + incomingBytes > quotaBytes) {
      return res.status(413).json({
        error: `Storage quota exceeded. Used: ${fmtBytesServer(usedBytes)}, Quota: ${fmtBytesServer(quotaBytes)}, Incoming: ${fmtBytesServer(incomingBytes)}.`,
        quotaExceeded: true,
        usedBytes, quotaBytes, incomingBytes,
      });
    }
    // ─────────────────────────────────────────────────────────────────────

    const clientName = String(req.body?.clientName || '').slice(0, 100);
    const savedAssets = [];

    for (const file of files) {
      const assetId = crypto.randomUUID();
      const safeFilename = file.originalname.replace(/[\/\\]/g, '_');
      const storagePath = `asset-buckets/${bucket.project_id}/${assetId}/${safeFilename}`;

      await uploadToB2(storagePath, file.buffer, file.mimetype);

      const { data: assetRow, error: aErr } = await supabase.from('assets').insert({
        id: assetId,
        project_id: bucket.project_id,
        bucket_id: bucket.id,
        filename: safeFilename,
        size_bytes: file.size,
        content_type: file.mimetype,
        storage_path: storagePath,
        client_name: clientName || null,
        uploaded_at: new Date().toISOString(),
      }).select().single();
      if (aErr) throw new Error(aErr.message);
      savedAssets.push({ id: assetId, filename: safeFilename, size: file.size, content_type: file.mimetype, uploaded_at: new Date().toISOString() });
    }

    const newUsedBytes = usedBytes + incomingBytes;
    console.log(`📦 ${files.length} file(s) uploaded to bucket ${bucket.id} (used: ${fmtBytesServer(newUsedBytes)} / ${fmtBytesServer(quotaBytes)})`);
    io.emit('db_changed');
    res.json({ ok: true, uploaded: savedAssets, usedBytes: newUsedBytes, quotaBytes });
    appendActivity(makeActivityEntry(req, {
      actorType: 'client',
      actorName: clientName || 'Client upload link',
      action: 'storage.client_upload',
      targetType: 'asset_bucket',
      targetId: bucket.id,
      targetName: bucket.project_name,
      text: `${clientName || 'A client'} uploaded ${files.length} file(s) to ${bucket.project_name}.`,
      metadata: {
        projectId: bucket.project_id,
        fileCount: files.length,
        bytes: incomingBytes,
        filenames: savedAssets.map(a => a.filename),
        usedBytes: newUsedBytes,
        quotaBytes,
      },
    })).catch(e => console.warn('activity upload error:', e.message));
  } catch (e) {
    console.error('storage upload error:', e);
    res.status(500).json({ error: e.message || 'Upload failed.' });
  }
});

function fmtBytesServer(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

// GET /api/storage/projects — List projects accessible to the current user (for storage.html sidebar)
app.get('/api/storage/projects', validateSession, async (req, res) => {
  try {
    const crmData = await getCrmData();
    const me = (crmData.team || []).find(m => m.id === req.userId);
    if (!me) return res.status(403).json({ error: 'Access denied.' });

    let projects = crmData.projects || [];
    if (!hasPermission(me.role, 'canViewAllContent')) {
      projects = projects.filter(p => userCanAccessProject(crmData, req.userId, p.id));
    }

    // For each project, count assets
    const projectIds = projects.map(p => p.id);
    let assetCounts = {};
    if (projectIds.length) {
      const { data: counts } = await supabase
        .from('assets')
        .select('project_id')
        .in('project_id', projectIds);
      (counts || []).forEach(a => {
        assetCounts[a.project_id] = (assetCounts[a.project_id] || 0) + 1;
      });
    }

    const result = projects.map(p => ({
      id: p.id,
      name: p.name || p.title || p.id,
      assetCount: assetCounts[p.id] || 0,
    }));

    res.json({ ok: true, projects: result });
    appendActivity(makeActivityEntry(req, {
      actorId: req.userId,
      actorName: memberLabel(crmData, req.userId),
      actorType: 'user',
      action: 'storage.projects_view',
      targetType: 'storage',
      targetName: 'Storage portal',
      text: `${memberLabel(crmData, req.userId)} opened the storage project list.`,
      metadata: { projectCount: result.length },
    })).catch(e => console.warn('activity storage projects error:', e.message));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/storage/projects/:projectId/assets — List all assets in a project (for storage.html)
app.get('/api/storage/projects/:projectId/assets', validateSession, async (req, res) => {
  try {
    const crmData = await getCrmData();
    const me = (crmData.team || []).find(m => m.id === req.userId);
    if (!me) return res.status(403).json({ error: 'Access denied.' });
    if (!hasPermission(me.role, 'canViewAllContent') && !userCanAccessProject(crmData, req.userId, req.params.projectId)) {
      return res.status(403).json({ error: 'Access denied to this project.' });
    }

    const { data, error } = await supabase
      .from('assets')
      .select('id, filename, size_bytes, content_type, uploaded_at, client_name, storage_path')
      .eq('project_id', req.params.projectId)
      .order('uploaded_at', { ascending: false });
    const project = (crmData.projects || []).find(p => p.id === req.params.projectId);
    res.json({ ok: true, projectName: project ? project.name : 'Project Assets', assets: data || [] });
    appendActivity(makeActivityEntry(req, {
      actorId: req.userId,
      actorName: memberLabel(crmData, req.userId),
      actorType: 'user',
      action: 'storage.project_assets_view',
      targetType: 'project',
      targetId: req.params.projectId,
      targetName: projectLabel(crmData, req.params.projectId),
      text: `${memberLabel(crmData, req.userId)} viewed storage for ${projectLabel(crmData, req.params.projectId)}.`,
      metadata: { assetCount: (data || []).length },
    })).catch(e => console.warn('activity project assets error:', e.message));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const authDownloadCache = new Map();

// GET /api/storage/assets/:assetId/download — Get signed download URL for an asset
app.get('/api/storage/assets/:assetId/download', validateSession, async (req, res) => {
  try {
    let asset, url;
    const cached = authDownloadCache.get(req.params.assetId);

    if (cached && Date.now() < cached.expiresAt) {
      asset = cached.asset;
      url = cached.url;
    } else {
      const { data, error } = await supabase
        .from('assets')
        .select('project_id, storage_path, filename')
        .eq('id', req.params.assetId)
        .single();
      if (error || !data) return res.status(404).json({ error: 'Asset not found.' });

      asset = data;
      url = await signedDownloadUrl(asset.storage_path);

      authDownloadCache.set(req.params.assetId, {
        asset,
        url,
        expiresAt: Date.now() + 50 * 60 * 1000 // 50 mins
      });
    }

    const crmData = await getCrmData();
    const me = (crmData.team || []).find(m => m.id === req.userId);
    if (!me) return res.status(403).json({ error: 'Access denied.' });
    if (!hasPermission(me.role, 'canViewAllContent') && !userCanAccessProject(crmData, req.userId, asset.project_id)) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    res.json({ ok: true, url, filename: asset.filename });
    // Activity log removed to save extreme database egress during thumbnail loads
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/storage/assets/:assetId — Admin: delete an asset from B2 + Supabase
app.delete('/api/storage/assets/:assetId', validateSession, async (req, res) => {
  try {
    const crmData = await getCrmData();
    const me = (crmData.team || []).find(m => m.id === req.userId);
    if (!hasPermission(me ? me.role : null, 'canManageStorage')) return res.status(403).json({ error: 'Only Admins can delete assets.' });

    const { data: asset, error } = await supabase
      .from('assets')
      .select('project_id, storage_path, filename')
      .eq('id', req.params.assetId)
      .single();
    if (error || !asset) return res.status(404).json({ error: 'Asset not found.' });

    await deleteFromB2(asset.storage_path);
    await supabase.from('assets').delete().eq('id', req.params.assetId);
    if (typeof io !== 'undefined') io.emit('db_changed');
    res.json({ ok: true });
    appendActivity(makeActivityEntry(req, {
      actorId: req.userId,
      actorName: memberLabel(crmData, req.userId),
      actorType: 'user',
      action: 'storage.asset_delete',
      targetType: 'asset',
      targetId: req.params.assetId,
      targetName: asset.filename,
      text: `${memberLabel(crmData, req.userId)} deleted ${asset.filename || 'an asset'} from ${projectLabel(crmData, asset.project_id)} storage.`,
      metadata: { projectId: asset.project_id, storagePath: asset.storage_path },
    })).catch(e => console.warn('activity asset delete error:', e.message));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────
// PROJECT ASSET BUCKET — Per-project asset bucket link & management
// ─────────────────────────────────────────────────────────────────────

// POST /api/projects/create-asset-bucket — Admin creates asset bucket for a project
// Generates a unique upload link, stores it in the project, and emails the client.
const UNASSIGNED_ASSET_BUCKET_GRACE_MS = 60 * 1000;
const pendingAssetBucketInvites = new Map();

async function removeUnassignedAssetBucket(bucketId) {
  const crmData = await getCrmData();
  const { data: bucket, error: bucketError } = await supabase
    .from('asset_buckets')
    .select('id, project_id')
    .eq('id', bucketId)
    .single();

  // Preserve buckets whose projects were saved while the timer was running.
  if (bucketError || !bucket || (crmData.projects || []).some(project => String(project.id) === String(bucket.project_id))) return false;

  const { data: assets, error: assetsError } = await supabase
    .from('assets')
    .select('storage_path')
    .eq('bucket_id', bucket.id);
  if (assetsError) throw new Error(assetsError.message);

  await Promise.all((assets || []).map(asset => deleteFromB2(asset.storage_path)));

  const { error: deleteAssetsError } = await supabase.from('assets').delete().eq('bucket_id', bucket.id);
  if (deleteAssetsError) throw new Error(deleteAssetsError.message);

  const { error: deleteBucketError } = await supabase.from('asset_buckets').delete().eq('id', bucket.id);
  if (deleteBucketError) throw new Error(deleteBucketError.message);

  pendingAssetBucketInvites.delete(bucket.id);
  console.log(`Removed unassigned asset bucket ${bucket.id} after ${UNASSIGNED_ASSET_BUCKET_GRACE_MS / 1000}s.`);
  return true;
}

function scheduleUnassignedAssetBucketCleanup(bucketId) {
  const timer = setTimeout(() => {
    removeUnassignedAssetBucket(bucketId).catch(error => {
      console.error(`Could not remove unassigned asset bucket ${bucketId}:`, error.message);
    });
  }, UNASSIGNED_ASSET_BUCKET_GRACE_MS);
  // Do not keep the server process alive solely for an unassigned-bucket timer.
  if (typeof timer.unref === 'function') timer.unref();
}

app.post('/api/projects/create-asset-bucket', validateSession, async (req, res) => {
  try {
    const { projectId, projectName: reqProjectName, clientId, clientName: clientNameReq } = req.body || {};
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });
    if (!String(reqProjectName || '').trim()) return res.status(400).json({ error: 'A project name is required.' });
    if (!clientId) return res.status(400).json({ error: 'A client is required.' });

    const crmData = await getCrmData();
    const me = (crmData.team || []).find(m => m.id === req.userId);
    if (!hasPermission(me ? me.role : null, 'canManageStorage')) {
      return res.status(403).json({ error: 'Only Admins can create asset buckets.' });
    }

    const project = (crmData.projects || []).find(p => p.id === projectId);
    const client = (crmData.clients || []).find(c => c.id === clientId);
    if (!client) return res.status(400).json({ error: 'Select a valid client before creating an asset bucket.' });

    const toEmail = String(client.email || '').trim();
    if (!/^\S+@\S+\.\S+$/.test(toEmail)) {
      return res.status(400).json({ error: 'The selected client must have a valid email address.' });
    }

    // Generate a unique token for this project's asset bucket (non-expiring)
    const bucketToken = crypto.randomBytes(32).toString('hex');

    // Generate+hash a secret key
    // Exclude ambiguous characters: 0, O, 1, I, L
    const KEY_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
    const secretKeyPlain = Array.from(crypto.randomBytes(5))
      .map(b => KEY_CHARS[b % KEY_CHARS.length])
      .join('');
    const secretKeyHash = await bcrypt.hash(secretKeyPlain, 10);

    // Create asset bucket record in Supabase
    const insertPayload = {
      token: bucketToken,
      project_id: projectId,
      created_by: req.userId,
      created_at: new Date().toISOString(),
      secret_key: secretKeyHash,
    };
    const { data: bucket, error: bErr } = await supabase.from('asset_buckets').insert(insertPayload).select().single();
    if (bErr) {
      console.error('create-asset-bucket Supabase error:', JSON.stringify(bErr));
      throw new Error(bErr.message);
    }

    // New-project buckets are created before the project itself is saved. If
    // that project is not saved within one minute, remove the orphan bucket.
    if (!project) scheduleUnassignedAssetBucketCleanup(bucket.id);

    // Build the asset bucket URL (client upload portal)
    const bucketUrl = `${req.protocol}://${req.get('host')}/asset-bucket/${bucketToken}`;

    if (!project) {
      pendingAssetBucketInvites.set(bucket.id, {
        projectId,
        bucketUrl,
        secretKey: secretKeyPlain,
        expiresAt: Date.now() + UNASSIGNED_ASSET_BUCKET_GRACE_MS,
      });
    }

    if (project) {
      // Store the bucket URL in the project's hyperlink assets field
      if (!project.hyperlinkAssets) project.hyperlinkAssets = [];
      project.hyperlinkAssets.push({
        id: bucket.id,
        url: bucketUrl,
        token: bucketToken,
        createdAt: new Date().toISOString(),
        createdBy: req.userId,
      });

      // Update CRM data with the modified project
      await setCrmData(crmData);
    }

    // Send email to client with upload link + secret key (if email provided)
    let emailSent = false;
    let emailSkipped = false;
    const clientFromProject = project && (
      project.clientName ||
      client.name
    );

    // Resolve name or use empty string if unknown
    let toName = clientNameReq || clientFromProject || (project && project.name ? project.name + ' Team' : null);
    if (!toName || toName.trim() === '' || toName === 'there') {
      toName = '';
    }

    const projectDisplayName = project ? (project.name || project.title) : (reqProjectName || projectId);

    if (toEmail && project) {
      try {
        const mailer = getMailer();
        if (!mailer) {
          console.warn('SMTP not configured -- skipping asset bucket email.');
          emailSkipped = true;
        } else {
          const fromName = process.env.SMTP_FROM_NAME || 'Startup Build';
          const fromAddr = process.env.SMTP_USER;
          const supportEmail = process.env.SUPPORT_EMAIL || 'support@startupbuild.tech';

          const greetingH1 = toName ? `Welcome aboard, ${toName}!` : 'Welcome aboard!';
          const greetingP = toName ? `Hi <strong>${toName}</strong>, your dedicated file upload portal has been set up so you can share project files securely with our team. Click below to open it:` : `Your dedicated file upload portal has been set up so you can share project files securely with our team. Click below to open it:`;
          const emailSubject = toName ? `Welcome aboard, ${toName} -- your upload portal is ready` : `Welcome aboard -- your upload portal is ready`;

          const emailHtml = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome Aboard -- ${fromName}</title>
<style>
  body{margin:0;padding:0;background:#F7F7F5;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;color:#111}
  .email{max-width:620px;margin:0 auto;background:#fff;border:1px solid #EAEAE4;border-radius:4px}
  .brand{padding:28px 32px 24px;border-bottom:1px solid #F0F0EA;font-size:18px;font-weight:800;color:#04013E}
  .brand span{color:#12A3B4}
  .body{padding:42px 32px 36px}
  h1{margin:0 0 6px;font-size:28px;line-height:1.2;font-weight:800;color:#050505}
  .subtitle{margin:0 0 28px;font-size:14px;color:#999}
  p{margin:0 0 18px;line-height:1.65;font-size:14px;color:#333}
  strong{font-weight:800}
  .button{display:inline-block;background:#12A3B4;color:#fff !important;text-decoration:none;padding:14px 28px;border-radius:6px;font-weight:800;font-size:14px;margin:4px 0 24px}
  .key-box{display:block;background:#F0F9FA;border:2px solid #12A3B4;border-radius:10px;padding:22px 32px;text-align:center;font-family:Consolas,'Courier New',monospace;font-size:34px;font-weight:900;letter-spacing:0.5em;color:#084D58;margin:8px 0 8px}
  .key-label{text-align:center;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#aaa;margin-bottom:16px}
  .footer{padding:20px 32px;border-top:1px solid #F0F0EA;font-size:11px;color:#bbb}
  a{color:#12A3B4}
</style>
</head>
<body>
<div class="email">
  <div class="brand">Start<span>up.</span></div>
  <div class="body">
    <h1>${greetingH1}</h1>
    <p class="subtitle">Your secure upload portal for <strong>${projectDisplayName}</strong> is ready.</p>
    <p>${greetingP}</p>
    <p style="text-align:center"><a class="button" href="${bucketUrl}">Open My Upload Portal</a></p>
    <p>When the portal opens, you will be asked for your personal 5-character access key. Your unique key is shown below:</p>
    <p class="key-label">Your Access Key</p>
    <div class="key-box">${secretKeyPlain}</div>
    <p><strong>Never share this key with anyone.</strong> If you lose it or believe it has been compromised, contact your project manager and we will revoke and replace it.</p>
    <p style="font-size:12px;color:#aaa">Direct link: <a href="${bucketUrl}" style="color:#aaa">${bucketUrl}</a></p>
    <p>Questions? Email us at <a href="mailto:${supportEmail}">${supportEmail}</a>.</p>
    <p>Looking forward to working with you,<br><strong>${fromName}</strong></p>
  </div>
  <div class="footer">Sent to ${toEmail} because an upload portal was created for you. Keep your access key private.</div>
</div>
</body>
</html>`;

          const crmDataForBucketMail = await getCrmData();
          const bucketAutoMails = crmDataForBucketMail.autoMails || [];
          const customPortalRule = bucketAutoMails.find(m => m.triggerCondition === 'portal_created' && m.status === 'Active');

          let portalSubject = emailSubject;
          let portalHtml = emailHtml;

          if (customPortalRule) {
            const rendered = renderAutoMailHtml(customPortalRule, {
              toName: toName || toEmail,
              toEmail,
              projectDisplayName,
              secretKey: secretKeyPlain,
              bucketUrl,
              fromName,
              fromAddr,
              supportEmail
            });
            portalSubject = rendered.subject;
            portalHtml = rendered.html;
          }

          await mailer.sendMail({
            from: `"${fromName}" <${fromAddr}>`,
            to: toName ? `"${toName}" <${toEmail}>` : toEmail,
            subject: portalSubject,
            html: portalHtml,
          });
          emailSent = true;
          console.log(`Email sent to ${toEmail} for project ${projectDisplayName}`);
        }
      } catch (emailErr) {
        console.warn('Could not send asset bucket email:', emailErr.message);
      }
    }
    res.json({
      ok: true,
      bucketId: bucket.id,
      bucketToken,
      bucketUrl,
      projectId,
      emailSent,
      emailSkipped,
      emailTo: toEmail || null,
    });
    appendActivity(makeActivityEntry(req, {
      actorId: req.userId,
      actorName: memberLabel(crmData, req.userId),
      actorType: 'user',
      action: 'storage.bucket_create',
      targetType: 'asset_bucket',
      targetId: bucket.id,
      targetName: projectDisplayName,
      text: `${memberLabel(crmData, req.userId)} created a client upload link for ${projectDisplayName}.`,
      metadata: { projectId, emailSent, emailSkipped, emailTo: toEmail || null },
    })).catch(e => console.warn('activity bucket create error:', e.message));
  } catch (e) {
    console.error('create-asset-bucket error:', e);
    res.status(500).json({ error: e.message });
  }
});


// GET /api/projects/:projectId/asset-buckets — List all asset buckets for a project
app.post('/api/projects/:projectId/asset-buckets/:bucketId/send-invite', validateSession, async (req, res) => {
  try {
    const crmData = await getCrmData();
    const me = (crmData.team || []).find(member => member.id === req.userId);
    if (!hasPermission(me ? me.role : null, 'canManageStorage')) return res.status(403).json({ error: 'Only Admins can send asset bucket invitations.' });

    const project = (crmData.projects || []).find(item => String(item.id) === String(req.params.projectId));
    const invite = pendingAssetBucketInvites.get(req.params.bucketId);
    if (!project || !invite || invite.projectId !== req.params.projectId || invite.expiresAt <= Date.now()) {
      return res.status(409).json({ error: 'This asset bucket invitation is no longer available.' });
    }

    const { data: bucket, error: bucketError } = await supabase
      .from('asset_buckets')
      .select('id, project_id')
      .eq('id', req.params.bucketId)
      .single();
    if (bucketError || !bucket || String(bucket.project_id) !== String(project.id)) {
      return res.status(404).json({ error: 'Asset bucket not found.' });
    }

    const client = (crmData.clients || []).find(item => item.id === project.clientId);
    const toEmail = String(project.contactEmail || client?.email || '').trim();
    if (!/^\S+@\S+\.\S+$/.test(toEmail)) return res.status(400).json({ error: 'A valid client email is required.' });

    const mailer = getMailer();
    if (!mailer) return res.json({ ok: true, skipped: true });

    const fromName = process.env.SMTP_FROM_NAME || 'Startup Build';
    const fromAddr = process.env.SMTP_USER;
    const supportEmail = process.env.SUPPORT_EMAIL || 'support@startupbuild.tech';
    const toName = client?.name || '';
    const projectDisplayName = project.name || project.title || 'your project';
    const greetingH1 = toName ? `Welcome aboard, ${toName}!` : 'Welcome aboard!';
    const greetingP = toName
      ? `Hi <strong>${toName}</strong>, your dedicated file upload portal has been set up so you can share project files securely with our team. Click below to open it:`
      : 'Your dedicated file upload portal has been set up so you can share project files securely with our team. Click below to open it:';
    const emailSubject = toName ? `Welcome aboard, ${toName} -- your upload portal is ready` : 'Welcome aboard -- your upload portal is ready';
    const emailHtml = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome Aboard -- ${fromName}</title>
<style>body{margin:0;padding:0;background:#F7F7F5;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;color:#111}.email{max-width:620px;margin:0 auto;background:#fff;border:1px solid #EAEAE4;border-radius:4px}.brand{padding:28px 32px 24px;border-bottom:1px solid #F0F0EA;font-size:18px;font-weight:800;color:#04013E}.brand span{color:#12A3B4}.body{padding:42px 32px 36px}h1{margin:0 0 6px;font-size:28px;line-height:1.2;font-weight:800;color:#050505}.subtitle{margin:0 0 28px;font-size:14px;color:#999}p{margin:0 0 18px;line-height:1.65;font-size:14px;color:#333}strong{font-weight:800}.button{display:inline-block;background:#12A3B4;color:#fff!important;text-decoration:none;padding:14px 28px;border-radius:6px;font-weight:800;font-size:14px;margin:4px 0 24px}.key-box{display:block;background:#F0F9FA;border:2px solid #12A3B4;border-radius:10px;padding:22px 32px;text-align:center;font-family:Consolas,'Courier New',monospace;font-size:34px;font-weight:900;letter-spacing:.5em;color:#084D58;margin:8px 0 8px}.key-label{text-align:center;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#aaa;margin-bottom:16px}.footer{padding:20px 32px;border-top:1px solid #F0F0EA;font-size:11px;color:#bbb}a{color:#12A3B4}</style></head>
<body><div class="email"><div class="brand">Start<span>up.</span></div><div class="body"><h1>${greetingH1}</h1><p class="subtitle">Your secure upload portal for <strong>${projectDisplayName}</strong> is ready.</p><p>${greetingP}</p><p style="text-align:center"><a class="button" href="${invite.bucketUrl}">Open My Upload Portal</a></p><p>When the portal opens, you will be asked for your personal 5-character access key. Your unique key is shown below:</p><p class="key-label">Your Access Key</p><div class="key-box">${invite.secretKey}</div><p><strong>Never share this key with anyone.</strong> If you lose it or believe it has been compromised, contact your project manager and we will revoke and replace it.</p><p style="font-size:12px;color:#aaa">Direct link: <a href="${invite.bucketUrl}" style="color:#aaa">${invite.bucketUrl}</a></p><p>Questions? Email us at <a href="mailto:${supportEmail}">${supportEmail}</a>.</p><p>Looking forward to working with you,<br><strong>${fromName}</strong></p></div><div class="footer">Sent to ${toEmail} because an upload portal was created for you. Keep your access key private.</div></div></body></html>`;

    const customPortalRule = (crmData.autoMails || []).find(rule => rule.triggerCondition === 'portal_created' && rule.status === 'Active');
    const rendered = customPortalRule && renderAutoMailHtml(customPortalRule, {
      toName: toName || toEmail, toEmail, projectDisplayName, secretKey: invite.secretKey,
      bucketUrl: invite.bucketUrl, fromName, fromAddr, supportEmail,
    });
    await mailer.sendMail({
      from: `"${fromName}" <${fromAddr}>`,
      to: toName ? `"${toName}" <${toEmail}>` : toEmail,
      subject: rendered ? rendered.subject : emailSubject,
      html: rendered ? rendered.html : emailHtml,
    });
    pendingAssetBucketInvites.delete(bucket.id);
    res.json({ ok: true, emailSent: true, emailTo: toEmail });
  } catch (error) {
    console.error('send asset bucket invitation error:', error);
    res.status(500).json({ error: error.message });
  }
});

function restrictActiveAssetBucketSessions(bucketId, message = 'This upload link has been restricted. Please contact your project manager.') {
  const room = 'asset-bucket:' + bucketId;
  io.to(room).emit('bucket_restricted', { message });
  // Give connected clients a moment to show the restricted screen, then close
  // their bucket session so it cannot be used again.
  setTimeout(() => io.in(room).disconnectSockets(true), 100);
}

app.get('/api/projects/:projectId/asset-buckets', validateSession, async (req, res) => {
  try {
    const crmData = await getCrmData();
    const me = (crmData.team || []).find(m => m.id === req.userId);
    if (!hasPermission(me ? me.role : null, 'canManageStorage')) {
      return res.status(403).json({ error: 'Only Admins can view asset buckets.' });
    }

    const { data: buckets, error } = await supabase
      .from('asset_buckets')
      .select('id, token, project_name, created_by, created_at')
      .eq('project_id', req.params.projectId)
      .order('created_at', { ascending: false });
    if (error) throw new Error(error.message);

    res.json({ ok: true, buckets: buckets || [] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/asset-buckets/:bucketId/revoke — Admin: revoke or un-revoke an upload link
app.post('/api/asset-buckets/:bucketId/revoke', validateSession, async (req, res) => {
  try {
    const crmData = await getCrmData();
    const me = (crmData.team || []).find(m => m.id === req.userId);
    if (!hasPermission(me ? me.role : null, 'canManageStorage')) return res.status(403).json({ error: 'Only Admins can revoke links.' });

    const revoked = req.body?.revoked !== false; // default true
    const { data: bucketBefore } = await supabase
      .from('asset_buckets')
      .select('id, project_id, project_name')
      .eq('id', req.params.bucketId)
      .single();
    const { error } = await supabase
      .from('asset_buckets')
      .update({ revoked })
      .eq('id', req.params.bucketId);
    if (error) throw new Error(error.message);
    if (revoked) restrictActiveAssetBucketSessions(req.params.bucketId);

    res.json({ ok: true, revoked });
    appendActivity(makeActivityEntry(req, {
      actorId: req.userId,
      actorName: memberLabel(crmData, req.userId),
      actorType: 'user',
      action: revoked ? 'storage.bucket_revoke' : 'storage.bucket_restore',
      targetType: 'asset_bucket',
      targetId: req.params.bucketId,
      targetName: bucketBefore?.project_name || req.params.bucketId,
      text: `${memberLabel(crmData, req.userId)} ${revoked ? 'revoked' : 'restored'} the client upload link for ${bucketBefore?.project_name || 'a project'}.`,
      metadata: { projectId: bucketBefore?.project_id || null },
    })).catch(e => console.warn('activity bucket revoke error:', e.message));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/asset-buckets/:bucketId/quota — Admin: update custom quota
app.post('/api/asset-buckets/:bucketId/quota', validateSession, async (req, res) => {
  try {
    const crmData = await getCrmData();
    const me = (crmData.team || []).find(m => m.id === req.userId);
    if (!hasPermission(me ? me.role : null, 'canManageStorage')) return res.status(403).json({ error: 'Only Admins can change quota.' });

    const quotaMB = parseInt(req.body?.quotaMB);
    if (isNaN(quotaMB) || quotaMB < 1) return res.status(400).json({ error: 'Invalid quota MB.' });

    const { data: bucket } = await supabase.from('asset_buckets').select('project_id').eq('id', req.params.bucketId).single();
    if (!bucket) return res.status(404).json({ error: 'Bucket not found.' });

    const project = (crmData.projects || []).find(p => p.id === bucket.project_id);
    if (project) {
      if (!project.assetBucketConfig) project.assetBucketConfig = {};
      project.assetBucketConfig.customQuotaBytes = quotaMB * 1024 * 1024;
      await setCrmData(crmData);
    }
    res.json({ ok: true, quotaBytes: quotaMB * 1024 * 1024 });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/asset-buckets/:bucketId/regenerate — Admin: regenerate link & passcode, optionally delete assets, send email
app.post('/api/asset-buckets/:bucketId/regenerate', validateSession, async (req, res) => {
  try {
    const crmData = await getCrmData();
    const me = (crmData.team || []).find(m => m.id === req.userId);
    if (!hasPermission(me ? me.role : null, 'canManageStorage')) return res.status(403).json({ error: 'Only Admins can regenerate links.' });

    const deleteAssets = req.body && req.body.deleteAssets;

    // Fetch the bucket
    const { data: bucket, error: bucketError } = await supabase.from('asset_buckets').select('*').eq('id', req.params.bucketId).single();
    if (bucketError) throw new Error(bucketError.message);

    if (deleteAssets) {
      // 1. Fetch assets
      const { data: assets } = await supabase.from('assets').select('id, storage_path').eq('bucket_id', bucket.id);
      if (assets && assets.length > 0) {
        // 2. Delete from B2
        await Promise.all(assets.map(a => deleteFromB2(a.storage_path)));
        // 3. Delete from Supabase
        await supabase.from('assets').delete().eq('bucket_id', bucket.id);
      }

      // Activity Log
      const project = (crmData.projects || []).find(p => p.id === bucket.project_id);
      logActivity(crmData, {
        id: crypto.randomUUID(),
        date: new Date().toISOString(),
        action: 'storage.bucket_clear',
        memberId: req.userId,
        projectId: bucket.project_id,
        text: `${memberLabel(crmData, req.userId)} permanently deleted all assets from ${projectLabel(crmData, bucket.project_id)} upload portal.`,
      }).catch(e => console.warn('activity clear assets log error:', e.message));
    }

    // Generate new token & secret
    const newToken = crypto.randomBytes(32).toString('hex');
    const KEY_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
    const secretKeyPlain = Array.from(crypto.randomBytes(5)).map(b => KEY_CHARS[b % KEY_CHARS.length]).join('');
    const secretKeyHash = await bcrypt.hash(secretKeyPlain, 10);

    const { error: updateError } = await supabase.from('asset_buckets')
      .update({ token: newToken, secret_key: secretKeyHash, revoked: false })
      .eq('id', bucket.id);
    if (updateError) throw new Error(updateError.message);

    // Update crmData if there's a hyperlinkAssets entry
    const project = (crmData.projects || []).find(p => p.id === bucket.project_id);
    if (project && project.hyperlinkAssets) {
      const hLink = project.hyperlinkAssets.find(h => h.id === bucket.id);
      if (hLink) {
        hLink.token = newToken;
        hLink.url = `${req.protocol}://${req.get('host')}/asset-bucket/${newToken}`;
        await setCrmData(crmData);
      }
    }

    // Send email
    const bucketUrl = `${req.protocol}://${req.get('host')}/asset-bucket/${newToken}`;
    const projectDisplayName = project ? (project.name || project.title) : (bucket.project_name || bucket.project_id);
    let toEmail = null;
    let toName = null;

    if (project) {
      toEmail = project.contactEmail;
      toName = project.clientName || (crmData.clients || []).find(c => c.id === project.clientId)?.name || project.name + ' Team';
    }

    if (toEmail) {
      try {
        const mailer = getMailer();
        if (mailer) {
          const fromName = process.env.SMTP_FROM_NAME || 'Startup Build';
          const fromAddr = process.env.SMTP_USER;
          const supportEmail = process.env.SUPPORT_EMAIL || 'support@startupbuild.tech';

          const greetingH1 = toName ? `Your regenerated upload portal is ready, ${toName}!` : 'Your regenerated upload portal is ready!';

          let intactText = '';
          if (!deleteAssets) {
            intactText = `<p style="margin: 0 0 18px; line-height: 1.65; font-size: 14px; color: #12A3B4; font-weight: 800;">Your assets are fully protected and intact.</p>`;
          }

          const greetingP = toName ? `Hi <strong>${toName}</strong>, your file upload portal has been regenerated. Click below to open it:` : `Your file upload portal has been regenerated. Click below to open it:`;
          const emailSubject = toName ? `Your regenerated upload portal is ready, ${toName}` : `Your regenerated upload portal is ready`;

          const emailHtml = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Upload Portal Ready -- ${fromName}</title>
<style>
  body{margin:0;padding:0;background:#F7F7F5;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;color:#111}
  .email{max-width:620px;margin:0 auto;background:#fff;border:1px solid #EAEAE4;border-radius:4px}
  .brand{padding:28px 32px 24px;border-bottom:1px solid #F0F0EA;font-size:18px;font-weight:800;color:#04013E}
  .brand span{color:#12A3B4}
  .body{padding:42px 32px 36px}
  h1{margin:0 0 6px;font-size:28px;line-height:1.2;font-weight:800;color:#050505}
  .subtitle{margin:0 0 28px;font-size:14px;color:#999}
  p{margin:0 0 18px;line-height:1.65;font-size:14px;color:#333}
  strong{font-weight:800}
  .button{display:inline-block;background:#12A3B4;color:#fff !important;text-decoration:none;padding:14px 28px;border-radius:6px;font-weight:800;font-size:14px;margin:4px 0 24px}
  .key-box{display:block;background:#F0F9FA;border:2px solid #12A3B4;border-radius:10px;padding:22px 32px;text-align:center;font-family:Consolas,'Courier New',monospace;font-size:34px;font-weight:900;letter-spacing:0.5em;color:#084D58;margin:8px 0 8px}
  .key-label{text-align:center;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#aaa;margin-bottom:16px}
  .footer{padding:20px 32px;border-top:1px solid #F0F0EA;font-size:11px;color:#bbb}
  a{color:#12A3B4}
</style>
</head>
<body>
<div class="email">
  <div class="brand">Start<span>up.</span></div>
  <div class="body">
    <h1>${greetingH1}</h1>
    <p class="subtitle">Your secure upload portal for <strong>${projectDisplayName}</strong> is ready.</p>
    <p>${greetingP}</p>
    ${intactText}
    <p style="text-align:center"><a class="button" href="${bucketUrl}">Open My Upload Portal</a></p>
    <p>When the portal opens, you will be asked for your personal 5-character access key. Your unique key is shown below:</p>
    <p class="key-label">Your Access Key</p>
    <div class="key-box">${secretKeyPlain}</div>
    <p><strong>Never share this key with anyone.</strong> If you lose it or believe it has been compromised, contact your project manager and we will restrict and replace it.</p>
    <p style="font-size:12px;color:#aaa">Direct link: <a href="${bucketUrl}" style="color:#aaa">${bucketUrl}</a></p>
    <p>Questions? Email us at <a href="mailto:${supportEmail}">${supportEmail}</a>.</p>
    <p>Looking forward to working with you,<br><strong>${fromName}</strong></p>
  </div>
  <div class="footer">Sent to ${toEmail} because an upload portal was regenerated for you. Keep your access key private.</div>
</div>
</body>
</html>`;

          const crmDataForBucketMail = await getCrmData();
          const bucketAutoMails = crmDataForBucketMail.autoMails || [];
          const customPortalRule = bucketAutoMails.find(m => m.triggerCondition === 'portal_created' && m.status === 'Active');

          let portalSubject = emailSubject;
          let portalHtml = emailHtml;

          if (customPortalRule) {
            const rendered = renderAutoMailHtml(customPortalRule, {
              toName: toName || toEmail,
              toEmail,
              projectDisplayName,
              secretKey: secretKeyPlain,
              bucketUrl,
              fromName,
              fromAddr,
              supportEmail
            });
            portalSubject = rendered.subject;
            portalHtml = rendered.html;
          }

          await mailer.sendMail({
            from: `"${fromName}" <${fromAddr}>`,
            to: toName ? `"${toName}" <${toEmail}>` : toEmail,
            subject: portalSubject,
            html: portalHtml,
          });
        }
      } catch (err) {
        console.warn('Could not send regenerate email:', err.message);
      }
    }

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// GET /api/asset-buckets/all — Admin: fetch all asset buckets + sizes
app.get('/api/asset-buckets/all', validateSession, async (req, res) => {
  try {
    const crmData = await getCrmData();
    const me = (crmData.team || []).find(m => m.id === req.userId);
    if (!hasPermission(me ? me.role : null, 'canManageStorage')) return res.status(403).json({ error: 'Only Admins can view all buckets.' });

    // Fetch all buckets
    const { data: buckets, error } = await supabase.from('asset_buckets').select('id, token, project_id, project_name, revoked, created_at').order('created_at', { ascending: false });
    if (error) throw new Error(error.message);

    // Fetch sizes for all assets
    const { data: assets } = await supabase.from('assets').select('bucket_id, size_bytes');

    const sizeMap = {};
    if (assets) {
      assets.forEach(a => {
        if (a.bucket_id) {
          if (!sizeMap[a.bucket_id]) sizeMap[a.bucket_id] = 0;
          sizeMap[a.bucket_id] += parseInt(a.size_bytes || 0);
        }
      });
    }

    const enhancedBuckets = (buckets || []).map(b => ({
      ...b,
      storageUsed: sizeMap[b.id] || 0
    }));

    res.json({ ok: true, buckets: enhancedBuckets });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/asset-bucket/validate/:token — Public: validate bucket token (no secret key in response)
app.get('/api/asset-bucket/validate/:token', async (req, res) => {
  try {
    const bucket = await getBucketByToken(req.params.token);
    const error = !bucket;

    if (error || !bucket) return res.status(404).json({ valid: false, reason: 'Asset bucket not found.' });
    if (bucket.revoked) return res.status(403).json({ valid: false, reason: 'This upload link has been restricted.' });

    // Look up the project name from CRM data (not stored in DB column)
    const crmData = await getCrmData();
    const project = (crmData.projects || []).find(p => p.id === bucket.project_id);
    const projectName = project ? (project.name || project.title || bucket.project_id) : bucket.project_id;

    const customQuota = project?.assetBucketConfig?.customQuotaBytes;
    const quotaBytes = customQuota ? parseInt(customQuota) : CLIENT_QUOTA_BYTES;

    res.json({
      valid: true,
      bucketId: bucket.id,
      projectId: bucket.project_id,
      projectName,
      requiresKey: !!bucket.secret_key, // tells frontend whether to show auth screen
      quotaBytes,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/asset-bucket/auth/:token — Public: verify secret key for a bucket (rate-limited)
const bucketAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { ok: false, error: 'Too many attempts. Your IP has been restricted and the link revoked.' },
  handler: async (req, res, next, options) => {
    try {
      const token = req.params.token;
      if (token) {
        const { data: bucket } = await supabase.from('asset_buckets').select('id, project_id').eq('token', token).single();
        if (bucket) {
          await supabase.from('asset_buckets').update({ revoked: true }).eq('token', token);
          restrictActiveAssetBucketSessions(bucket.id, 'This upload link was restricted after too many unsuccessful access-key attempts.');
          const crmData = await getCrmData();
          const projectName = projectLabel(crmData, bucket.project_id, 'Project');
          await appendActivity({
            actorType: 'system',
            action: 'security.brute_force_detected',
            targetType: 'asset_bucket',
            targetId: bucket.id,
            targetName: projectName,
            text: `System revoked upload link for ${projectName} due to suspicious failed login attempts from IP ${requestIp(req)}.`,
            ip: requestIp(req),
            userAgent: requestUserAgent(req)
          });
        }
      }
    } catch (e) {
      console.error('Error in auth limiter handler:', e);
    }
    res.status(options.statusCode).json(options.message);
  }
});
app.post('/api/asset-bucket/auth/:token', bucketAuthLimiter, async (req, res) => {
  try {
    const { secretKey } = req.body || {};
    if (!secretKey || typeof secretKey !== 'string') {
      return res.status(400).json({ ok: false, error: 'Access key is required.' });
    }

    const bucket = await getBucketByToken(req.params.token);
    const error = !bucket;

    if (error || !bucket) return res.status(404).json({ ok: false, error: 'Upload link not found.' });
    if (bucket.revoked) return res.status(403).json({ ok: false, error: 'This upload link has been restricted.' });
    if (!bucket.secret_key) return res.status(500).json({ ok: false, error: 'This bucket has no access key configured. Contact your admin.' });

    const cleanKey = secretKey.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    const match = await bcrypt.compare(cleanKey, bucket.secret_key);
    if (!match) {
      return res.status(401).json({ ok: false, error: 'Incorrect access key. Please check and try again.' });
    }

    // Key matched — look up project name and return success
    const crmData = await getCrmData();
    const project = (crmData.projects || []).find(p => p.id === bucket.project_id);
    const projectName = project ? (project.name || project.title || bucket.project_id) : bucket.project_id;

    const customQuota = project?.assetBucketConfig?.customQuotaBytes;
    const quotaBytes = customQuota ? parseInt(customQuota) : CLIENT_QUOTA_BYTES;

    res.json({ ok: true, projectId: bucket.project_id, projectName, quotaBytes });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/asset-bucket/:token/upload — Public: upload files to a project bucket
const bucketUploadLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, message: { error: 'Upload rate limit exceeded.' } });
app.post('/api/asset-bucket/:token/upload', bucketUploadLimiter, upload.array('files', 100), async (req, res) => {
  try {
    const files = req.files || [];
    if (!files.length) return res.status(400).json({ error: 'No files received.' });

    // Validate bucket token
    const bucket = await getBucketByToken(req.params.token);
    const bErr = !bucket;

    if (bErr || !bucket) return res.status(404).json({ error: 'Asset bucket not found.' });
    if (bucket.revoked) return res.status(403).json({ error: 'This upload link has been restricted.' });

    const crmData = await getCrmData();
    const project = (crmData.projects || []).find(p => p.id === bucket.project_id);
    const customQuota = project?.assetBucketConfig?.customQuotaBytes;
    const quotaBytes = customQuota ? parseInt(customQuota) : CLIENT_QUOTA_BYTES;
    const { data: existing } = await supabase.from('assets').select('size_bytes').eq('bucket_id', bucket.id);
    const usedBytes = (existing || []).reduce((s, a) => s + parseInt(a.size_bytes || 0), 0);
    const incomingBytes = files.reduce((s, f) => s + f.size, 0);
    if (usedBytes + incomingBytes > quotaBytes) {
      return res.status(413).json({
        error: `Storage quota exceeded. Used: ${fmtBytesServer(usedBytes)}, Quota: ${fmtBytesServer(quotaBytes)}, Incoming: ${fmtBytesServer(incomingBytes)}.`,
        quotaExceeded: true,
        usedBytes, quotaBytes, incomingBytes,
      });
    }

    const clientName = String(req.body?.clientName || '').slice(0, 100);
    const savedAssets = [];

    // ── Step 1: Safety scan ALL files before uploading any ───────────────────
    for (const file of files) {
      const check = checkFileSafety(file.buffer, file.originalname);
      if (!check.safe) {
        return res.status(422).json({ error: check.reason, filename: file.originalname });
      }
    }

    // ── Step 2: Determine sequential numbering base for this bucket ──────────
    const { data: existingAssets } = await supabase
      .from('assets')
      .select('id')
      .eq('bucket_id', bucket.id);
    const existingCount = (existingAssets || []).length;

    // Get project name for file renaming
    const crmDataForRename = await getCrmData();
    const projectForRename = (crmDataForRename.projects || []).find(p => p.id === bucket.project_id);
    const rawProjectName = projectForRename
      ? (projectForRename.name || projectForRename.title || bucket.project_id)
      : bucket.project_id;
    // Sanitize: keep alphanumeric, spaces, hyphens
    const projectSlug = rawProjectName.replace(/[^a-zA-Z0-9 \-]/g, '').trim().replace(/\s+/g, ' ');

    // ── Step 3: Upload each file with auto-renamed filename ──────────────────
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const assetId = crypto.randomUUID();

      // Preserve original extension
      const dotIdx = file.originalname.lastIndexOf('.');
      const ext = dotIdx !== -1 ? file.originalname.slice(dotIdx) : '';

      // e.g. "Acme Website_3.pdf"
      const fileNumber = existingCount + i + 1;
      const renamedFilename = `${projectSlug}_${fileNumber}${ext}`;

      const storagePath = `asset-buckets/${bucket.project_id}/${assetId}/${renamedFilename}`;

      // Upload to Backblaze B2
      await uploadToB2(storagePath, file.buffer, file.mimetype);

      // Record in Supabase with renamed filename
      const { data: assetRow, error: aErr } = await supabase.from('assets').insert({
        id: assetId,
        project_id: bucket.project_id,
        bucket_id: bucket.id,
        filename: renamedFilename,
        size_bytes: file.size,
        content_type: file.mimetype,
        storage_path: storagePath,
        client_name: clientName || null,
        uploaded_at: new Date().toISOString(),
      }).select().single();
      if (aErr) throw new Error(aErr.message);
      savedAssets.push({ id: assetId, filename: renamedFilename, originalName: file.originalname, size: file.size });
    }

    console.log(`📦 ${files.length} asset(s) uploaded to bucket ${bucket.id} for project ${bucket.project_id} (client: ${clientName || 'anonymous'})`);
    io.emit('db_changed');
    res.json({ ok: true, uploaded: savedAssets, projectId: bucket.project_id });
    appendActivity(makeActivityEntry(req, {
      actorType: 'client',
      actorName: clientName || 'Client upload link',
      action: 'storage.legacy_client_upload',
      targetType: 'asset_bucket',
      targetId: bucket.id,
      targetName: bucket.project_name,
      text: `${clientName || 'A client'} uploaded ${files.length} file(s) through the legacy portal for ${bucket.project_name}.`,
      metadata: {
        projectId: bucket.project_id,
        fileCount: files.length,
        bytes: incomingBytes,
        filenames: savedAssets.map(a => a.filename),
        usedBytes: usedBytes + incomingBytes,
        quotaBytes,
      }
    })).catch(e => console.warn('activity legacy upload error:', e.message));
  } catch (e) {
    console.error('asset-bucket upload error:', e);
    res.status(500).json({ error: e.message || 'Upload failed.' });
  }
});

// GET /api/storage/all-assets — Admin view: list all assets across all projects
app.get('/api/storage/all-assets', validateSession, async (req, res) => {
  try {
    const crmData = await getCrmData();
    const me = (crmData.team || []).find(m => m.id === req.userId);

    // Admins see ALL assets. Others see only assets from projects they're part of.
    let query = supabase.from('assets').select('id, project_id, bucket_id, filename, size_bytes, content_type, uploaded_at, client_name');

    if (me && hasPermission(me.role, 'canManageStorage')) {
      // Admin: get all assets
      const { data, error } = await query.order('uploaded_at', { ascending: false });
      if (error) throw new Error(error.message);
      return res.json({ ok: true, assets: data || [], isAdmin: true });
    }

    // Non-admin: filter by projects they're part of
    const accessibleProjectIds = (crmData.projects || [])
      .filter(p => userCanAccessProject(crmData, req.userId, p.id))
      .map(p => p.id);

    if (!accessibleProjectIds.length) {
      return res.json({ ok: true, assets: [], isAdmin: false });
    }

    const { data, error } = await query
      .in('project_id', accessibleProjectIds)
      .order('uploaded_at', { ascending: false });
    if (error) throw new Error(error.message);

    res.json({ ok: true, assets: data || [], isAdmin: false });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/storage/bucket-assets/:bucketId — List assets in a specific bucket
app.get('/api/storage/bucket-assets/:bucketId', validateSession, async (req, res) => {
  try {
    const crmData = await getCrmData();

    // Get bucket info
    const { data: bucket, error: bErr } = await supabase
      .from('asset_buckets')
      .select('project_id')
      .eq('id', req.params.bucketId)
      .single();
    if (bErr || !bucket) return res.status(404).json({ error: 'Bucket not found.' });

    // Check access
    const me = (crmData.team || []).find(m => m.id === req.userId);
    const isAdmin = me && hasPermission(me.role, 'canManageStorage');
    if (!isAdmin && !userCanAccessProject(crmData, req.userId, bucket.project_id)) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    // Get assets in bucket
    const { data: assets, error } = await supabase
      .from('assets')
      .select('id, filename, size_bytes, content_type, uploaded_at, client_name')
      .eq('bucket_id', req.params.bucketId)
      .order('uploaded_at', { ascending: false });
    if (error) throw new Error(error.message);

    res.json({ ok: true, assets: assets || [] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Catch-all 404 handler
app.use((req, res) => {
  res.status(404).sendFile(path.join(PUBLIC_DIR, '404.html'));
});

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
   SERVER STARTUP
   â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

const PORT = process.env.PORT || 8787;
// Hosting platforms (Render, Railway, etc.) set NODE_ENV=production and
// require binding to 0.0.0.0 to be reachable. Locally this stays on
// 127.0.0.1 so the server isn't exposed to your LAN by accident.
const HOST = process.env.HOST || (process.env.NODE_ENV === 'production' ? '0.0.0.0' : '127.0.0.1');

(async () => {
  try {
    await initSupabase();
  } catch (e) {
    console.error('âŒ Could not connect to Supabase. Server will not start.');
    console.error(e.message);
    process.exit(1);
  }
  try {
    await initB2();
  } catch (e) {
    console.warn('âš ï¸  Backblaze B2 not initialised:', e.message);
    console.warn('   Asset storage routes will not work until B2_KEY_ID, B2_APP_KEY, B2_ENDPOINT, B2_BUCKET_NAME are set.');
  }
  if (process.env.NODE_ENV !== 'test') {
    httpServer.listen(PORT, HOST, () => console.log(`🚀 Startup CRM server running at http://${HOST}:${PORT}`));
  }
})();

export { app, httpServer };
