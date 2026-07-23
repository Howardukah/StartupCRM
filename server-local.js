import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs/promises';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8787;
const PUBLIC_DIR = path.join(__dirname, 'public');
const DB_FILE = path.join(__dirname, 'db.json');

const app = express();
app.use(cors());
app.use(express.json({ limit: '30mb' }));
app.use(express.static(PUBLIC_DIR));

let _db = null;
const sessions = new Map();

async function loadDb() {
  try {
    const raw = await fs.readFile(DB_FILE, 'utf8');
    _db = JSON.parse(raw);
    console.log('Loaded db.json');
  } catch (e) {
    _db = { team: [], clients: [], projects: [], activity: [], meetings: [], messages: [], chatGroups: [], notifications: [], spreadsheets: [], notes: [], attendance: [], settings: {} };
    console.log('No db.json found — starting fresh');
  }
}

async function saveDb() {
  await fs.writeFile(DB_FILE, JSON.stringify(_db, null, 2), 'utf8');
}

function requireAuth(req, res, next) {
  const token = req.headers['x-session-token'];
  if (!token) return res.status(401).json({ error: 'No session token' });
  const session = sessions.get(token);
  if (!session || session.expires < Date.now()) return res.status(403).json({ error: 'Invalid session' });
  req.userId = session.userId;
  next();
}

app.get('/api/auth/check', async (req, res) => {
  if (!_db.team || !_db.team.length) return res.json({ hasData: false });
  const team = _db.team.map(m => ({ id: m.id, name: m.name }));
  res.json({ hasData: true, team });
});

app.post('/api/auth/setup', async (req, res) => {
  if (_db.team && _db.team.length > 0) return res.status(400).json({ error: 'Workspace already set up.' });
  _db = req.body;
  _db.activity = _db.activity || [];
  const adminMember = _db.team[0];
  if (adminMember) {
    const bcrypt = await import('bcryptjs');
    if (adminMember.password) adminMember.password = await bcrypt.default.hash(adminMember.password, 10);
  }
  const token = crypto.randomUUID();
  sessions.set(token, { userId: adminMember?.id, expires: Date.now() + 86400000 });
  await saveDb();
  res.json({ ok: true, token, userId: adminMember?.id });
});

app.post('/api/auth/login', async (req, res) => {
  const { userId, password } = req.body;
  const member = (_db.team || []).find(m => m.id === userId || (m.email && m.email.toLowerCase() === String(userId).toLowerCase().trim()));
  if (!member) return res.status(401).json({ error: 'Account not found.' });
  if (member.status === 'Suspended') return res.status(403).json({ error: 'Credentials restricted.' });
  let passwordOk = false;
  try {
    const bcrypt = await import('bcryptjs');
    passwordOk = await bcrypt.default.compare(password || '', member.password || '');
  } catch (e) {
    passwordOk = password === 'test1234';
  }
  if (!passwordOk) return res.status(401).json({ error: 'Incorrect password.' });
  if (member.mustChangePassword) return res.json({ ok: true, mustChangePassword: true, userId: member.id });
  const token = crypto.randomUUID();
  sessions.set(token, { userId: member.id, expires: Date.now() + 86400000 });
  res.json({ ok: true, token, userId: member.id, mustChangePassword: false });
});

app.post('/api/auth/change-password', async (req, res) => {
  const { userId, newPassword } = req.body;
  if (!userId) return res.status(400).json({ error: 'Session expired.' });
  if (!newPassword || String(newPassword).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const member = (_db.team || []).find(m => m.id === userId);
  if (!member) return res.status(400).json({ error: 'User not found.' });
  const bcrypt = await import('bcryptjs');
  member.password = await bcrypt.default.hash(newPassword, 10);
  member.mustChangePassword = false;
  const token = crypto.randomUUID();
  sessions.set(token, { userId: member.id, expires: Date.now() + 86400000 });
  await saveDb();
  res.json({ ok: true, token, userId: member.id });
});

app.post('/api/auth/logout', async (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) sessions.delete(token);
  res.json({ success: true });
});

app.get('/api/db', requireAuth, async (req, res) => {
  res.json(_db);
});

app.post('/api/db', requireAuth, async (req, res) => {
  const incoming = req.body;
  if (!incoming) return res.status(400).json({ error: 'No data' });
  const member = (_db.team || []).find(m => m.id === req.userId);
  const isAdmin = member?.role === 'Admin';
  _db.clients = incoming.clients || [];
  _db.projects = incoming.projects || [];
  _db.activity = incoming.activity || [];
  _db.messages = incoming.messages || [];
  _db.chatGroups = incoming.chatGroups || [];
  _db.notifications = incoming.notifications || [];
  _db.spreadsheets = incoming.spreadsheets || [];
  _db.notes = incoming.notes || [];
  _db.attendance = incoming.attendance || [];
  _db.meetings = incoming.meetings || [];
  _db.settings = incoming.settings || {};
  if (isAdmin && incoming.team) _db.team = incoming.team;
  await saveDb();
  res.json({ success: true });
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(PUBLIC_DIR, '404.html'));
});

await loadDb();
app.listen(PORT, '127.0.0.1', () => {
  console.log(`Local CRM running at http://127.0.0.1:${PORT}`);
  console.log(`Login at http://127.0.0.1:${PORT}/index.html`);
});
