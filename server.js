const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const pty = require('node-pty');
const Docker = require('dockerode');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const Redis = require('ioredis');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFile } = require('child_process');
const net   = require('net');
const ngrok = require('@ngrok/ngrok');

const PORT           = process.env.PORT           || 3000;
const LOCAL_SHELL    = process.env.SHELL          || '/bin/bash';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-in-production';
const LABEL_USER     = 'webterminal.user';

// ── Database ──────────────────────────────────────────────────────────────────
const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'data', 'users.db');
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });

const db = new Database(DB_FILE);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user'
                  CHECK(role IN ('admin','user')),
    active         INTEGER NOT NULL DEFAULT 1,
    max_containers INTEGER NOT NULL DEFAULT 5,
    max_volumes    INTEGER NOT NULL DEFAULT 5,
    max_networks   INTEGER NOT NULL DEFAULT 5,
    ngrok_token    TEXT,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )
`);

// ── Migrate existing databases ─────────────────────────────────────────────
try { db.exec(`ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN max_containers INTEGER NOT NULL DEFAULT 5`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN max_volumes    INTEGER NOT NULL DEFAULT 5`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN max_networks   INTEGER NOT NULL DEFAULT 5`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN ngrok_token TEXT`); } catch (_) {}

// ── Seed users on first run ───────────────────────────────────────────────────
function seedUser(username, password, role) {
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (!exists) {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
      .run(username, hash, role);
    console.log(`Seeded ${role}: ${username}`);
  }
}

// ADMIN_USER=admin:secret  →  creates admin on first run
const ADMIN_USER = process.env.ADMIN_USER || '';
if (ADMIN_USER) {
  const idx = ADMIN_USER.indexOf(':');
  if (idx > 0) seedUser(ADMIN_USER.slice(0, idx).trim(), ADMIN_USER.slice(idx + 1).trim(), 'admin');
}

// USERS=alice:pass,bob:pass  →  creates regular users on first run
for (const entry of (process.env.USERS || '').split(',').filter(Boolean)) {
  const idx = entry.indexOf(':');
  if (idx < 1) continue;
  seedUser(entry.slice(0, idx).trim(), entry.slice(idx + 1).trim(), 'user');
}

if (db.prepare('SELECT COUNT(*) as n FROM users').get().n === 0) {
  console.warn('[warn] No users in database. Set ADMIN_USER env var, e.g.: ADMIN_USER=admin:secret');
}

// ── DB helpers ────────────────────────────────────────────────────────────────
const stmts = {
  findUser:     db.prepare('SELECT * FROM users WHERE username = ?'),
  listUsers:         db.prepare('SELECT username, role, active, max_containers, max_volumes, max_networks, created_at FROM users ORDER BY created_at ASC'),
  createUser:        db.prepare('INSERT INTO users (username, password_hash, role, active, max_containers, max_volumes, max_networks) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  updatePass:        db.prepare('UPDATE users SET password_hash = ? WHERE username = ?'),
  updateRole:        db.prepare('UPDATE users SET role = ? WHERE username = ?'),
  updateActive:      db.prepare('UPDATE users SET active = ? WHERE username = ?'),
  updateMaxContainers: db.prepare('UPDATE users SET max_containers = ? WHERE username = ?'),
  updateMaxVolumes:    db.prepare('UPDATE users SET max_volumes    = ? WHERE username = ?'),
  updateMaxNetworks:   db.prepare('UPDATE users SET max_networks   = ? WHERE username = ?'),
  updateNgrokToken:    db.prepare('UPDATE users SET ngrok_token    = ? WHERE username = ?'),
  deleteUser:        db.prepare('DELETE FROM users WHERE username = ?'),
};

// ── Docker ────────────────────────────────────────────────────────────────────
let docker = null;
try {
  docker = new Docker({ socketPath: '/var/run/docker.sock' });
} catch (e) {
  console.warn('Docker socket not available:', e.message);
}

// ── Redis ─────────────────────────────────────────────────────────────────────
const redisClient = new Redis({
  // host:     process.env.REDIS_HOST     || '127.0.0.1',
  host:     '127.0.0.1',
  port:     parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD || undefined,
  retryStrategy: times => Math.min(times * 100, 3000),
});
redisClient.on('connect', () => console.log('[redis] connected'));
redisClient.on('error',   err => console.error('[redis] error:', err.message));

// ── Express + session ─────────────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const sessionMiddleware = session({
  store: new RedisStore({ client: redisClient }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' },
});

app.use(express.json());
app.use(sessionMiddleware);

// ── Middleware ────────────────────────────────────────────────────────────────
const requireAuth = (req, res, next) => {
  if (!req.session?.user) return res.redirect('/login');
  const u = stmts.findUser.get(req.session.user.username);
  if (!u || !u.active) { req.session.destroy(() => {}); return res.redirect('/login'); }
  next();
};
const requireAuthAPI = (req, res, next) => {
  if (!req.session?.user) return res.status(401).json({ error: 'Unauthorized' });
  const u = stmts.findUser.get(req.session.user.username);
  if (!u || !u.active) { req.session.destroy(() => {}); return res.status(401).json({ error: 'Unauthorized' }); }
  next();
};
const requireAdmin = (req, res, next) => {
  if (req.session?.user?.role === 'admin') return next();
  res.status(403).json({ error: 'Forbidden' });
};
const requireAdminPage = (req, res, next) => {
  if (req.session?.user?.role === 'admin') return next();
  res.redirect('/');
};

const pub = (file) => path.join(__dirname, 'public', file);

// ── Page routes ───────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  if (req.session?.user) return res.redirect('/');
  res.sendFile(pub('login.html'));
});
app.get('/',              requireAuth,                       (req, res) => res.sendFile(pub('index.html')));
app.get('/terminal.html', requireAuth,                       (req, res) => res.sendFile(pub('terminal.html')));
app.get('/admin',         requireAuth, requireAdminPage,     (req, res) => res.sendFile(pub('admin.html')));

// ── Auth API ──────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = stmts.findUser.get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  if (!user.active) {
    return res.status(403).json({ error: 'Account is disabled' });
  }
  req.session.user = { username: user.username, role: user.role };
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', requireAuthAPI, (req, res) => {
  const u = stmts.findUser.get(req.session.user.username);
  res.json({ username: u.username, role: u.role, max_containers: u.max_containers, max_volumes: u.max_volumes, max_networks: u.max_networks, has_ngrok_token: !!u.ngrok_token });
});

// ── Admin API ─────────────────────────────────────────────────────────────────
app.get('/api/admin/users', requireAuthAPI, requireAdmin, (req, res) => {
  res.json(stmts.listUsers.all());
});

app.post('/api/admin/users', requireAuthAPI, requireAdmin, (req, res) => {
  const { username, password, role = 'user', active = true, max_containers = 5, max_volumes = 5, max_networks = 5 } = req.body;
  if (!username?.trim())  return res.status(400).json({ error: 'Username is required' });
  if (!password?.trim())  return res.status(400).json({ error: 'Password is required' });
  if (!['admin', 'user'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
  const maxC = Math.max(1, Math.min(100, parseInt(max_containers, 10) || 5));
  const maxV = Math.max(1, Math.min(100, parseInt(max_volumes,    10) || 5));
  const maxN = Math.max(1, Math.min(100, parseInt(max_networks,   10) || 5));

  try {
    stmts.createUser.run(username.trim(), bcrypt.hashSync(password, 10), role, active ? 1 : 0, maxC, maxV, maxN);
    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.put('/api/admin/users/:username', requireAuthAPI, requireAdmin, (req, res) => {
  const { username } = req.params;
  const { password, role, active, max_containers, max_volumes, max_networks } = req.body;

  if (!stmts.findUser.get(username)) return res.status(404).json({ error: 'User not found' });

  // Prevent an admin from demoting or disabling their own account
  if (username === req.session.user.username && role === 'user') {
    return res.status(400).json({ error: 'Cannot demote your own account' });
  }
  if (username === req.session.user.username && active === false) {
    return res.status(400).json({ error: 'Cannot disable your own account' });
  }

  if (password?.trim()) stmts.updatePass.run(bcrypt.hashSync(password, 10), username);
  if (role && ['admin', 'user'].includes(role)) stmts.updateRole.run(role, username);
  if (typeof active === 'boolean') stmts.updateActive.run(active ? 1 : 0, username);
  if (max_containers != null) {
    const maxC = Math.max(1, Math.min(100, parseInt(max_containers, 10) || 5));
    stmts.updateMaxContainers.run(maxC, username);
  }
  if (max_volumes != null) {
    const maxV = Math.max(1, Math.min(100, parseInt(max_volumes, 10) || 5));
    stmts.updateMaxVolumes.run(maxV, username);
  }
  if (max_networks != null) {
    const maxN = Math.max(1, Math.min(100, parseInt(max_networks, 10) || 5));
    stmts.updateMaxNetworks.run(maxN, username);
  }

  res.json({ ok: true });
});

app.delete('/api/admin/users/:username', requireAuthAPI, requireAdmin, (req, res) => {
  const { username } = req.params;
  if (username === req.session.user.username) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }
  const info = stmts.deleteUser.run(username);
  if (info.changes === 0) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
});

app.post('/api/me/password', requireAuthAPI, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword) return res.status(400).json({ error: 'Current password is required' });
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });

  const { username } = req.session.user;
  const user = stmts.findUser.get(username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }

  stmts.updatePass.run(bcrypt.hashSync(newPassword, 10), username);
  res.json({ ok: true });
});

// ── ngrok token ───────────────────────────────────────────────────────────────
app.put('/api/me/ngrok-token', requireAuthAPI, (req, res) => {
  const { token } = req.body;
  const { username } = req.session.user;
  stmts.updateNgrokToken.run(token?.trim() || null, username);
  res.json({ ok: true });
});

// ── ngrok tunnels (in-memory) ─────────────────────────────────────────────────
const activeTunnels = new Map(); // key: `${username}:${containerId}:${port}`

async function closeTunnelsForContainer(username, containerId) {
  for (const [key, t] of activeTunnels) {
    if (t.username === username && t.containerId === containerId) {
      try { await t.listener.close(); } catch (_) {}
      activeTunnels.delete(key);
    }
  }
}

async function closeTunnelsForUser(username) {
  for (const [key, t] of activeTunnels) {
    if (t.username === username) {
      try { await t.listener.close(); } catch (_) {}
      activeTunnels.delete(key);
    }
  }
}

// List tunnels for a container
app.get('/api/containers/:id/expose', requireAuthAPI, (req, res) => {
  const { id } = req.params;
  const { username } = req.session.user;
  const result = [];
  for (const t of activeTunnels.values()) {
    if (t.username === username && t.containerId === id) {
      result.push({ port: t.port, url: t.url, addr: t.addr });
    }
  }
  res.json(result);
});

// Start a tunnel for a container port
app.post('/api/containers/:id/expose', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { id } = req.params;
  const { port } = req.body;
  if (!port) return res.status(400).json({ error: 'Port is required' });

  const { username } = req.session.user;
  const dbUser = stmts.findUser.get(username);
  if (!dbUser.ngrok_token)
    return res.status(400).json({ error: 'ngrok token not configured. Set it via the ngrok button in the header.' });

  // Verify ownership
  try {
    const owned = await docker.listContainers({
      all: true,
      filters: { id: [id], label: [`${LABEL_USER}=${username}`] },
    });
    if (owned.length === 0) return res.status(404).json({ error: 'Container not found or not yours' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }

  // Resolve address: prefer published host port, fall back to container IP
  let addr;
  try {
    const info = await docker.getContainer(id).inspect();
    const bindings = info.NetworkSettings.Ports || {};
    const tcpKey   = `${port}/tcp`;
    if (bindings[tcpKey]?.[0]?.HostPort) {
      addr = `http://localhost:${bindings[tcpKey][0].HostPort}`;
    } else {
      const nets = info.NetworkSettings.Networks;
      const ip   = Object.values(nets)[0]?.IPAddress;
      if (!ip) return res.status(400).json({ error: 'Container has no network IP. Make sure it is running.' });
      addr = `http://${ip}:${port}`;
    }
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }

  // Pre-flight: verify the target is actually reachable before starting ngrok
  const addrUrl  = new URL(addr);
  const connTest = await testTcpConnectivity(addrUrl.hostname, addrUrl.port);
  if (!connTest.ok) {
    console.warn(`[${username}] ngrok pre-check failed for ${addr}: ${connTest.error}`);
    return res.status(400).json({
      error: `Cannot reach ${addr} — ${connTest.error}. ` +
        `Make sure the service is running on port ${port} inside the container ` +
        `and that the container is accessible from this server. ` +
        `If running in Docker Compose, try publishing the port with "Publish ports" (e.g. ${port}:${port}) when launching the container.`,
      addr,
    });
  }

  // Close any existing tunnel on the same port
  const tunnelKey = `${username}:${id}:${port}`;
  if (activeTunnels.has(tunnelKey)) {
    try { await activeTunnels.get(tunnelKey).listener.close(); } catch (_) {}
    activeTunnels.delete(tunnelKey);
  }

  try {
    const listener = await ngrok.forward({ addr, authtoken: dbUser.ngrok_token });
    const url = listener.url();
    activeTunnels.set(tunnelKey, { listener, url, addr, port: parseInt(port, 10), containerId: id, username });
    console.log(`[${username}] ngrok tunnel ${url} → ${addr}`);
    res.json({ ok: true, url, addr });
  } catch (err) {
    console.error(`[${username}] ngrok.forward failed for ${addr}:`, err.message);
    res.status(500).json({ error: err.message, addr });
  }
});

// Stop a tunnel
app.delete('/api/containers/:id/expose/:port', requireAuthAPI, async (req, res) => {
  const { id, port } = req.params;
  const { username } = req.session.user;
  const tunnelKey = `${username}:${id}:${port}`;
  const tunnel = activeTunnels.get(tunnelKey);
  if (!tunnel) return res.status(404).json({ error: 'No active tunnel on that port' });
  try {
    await tunnel.listener.close();
    activeTunnels.delete(tunnelKey);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────

// TCP connectivity pre-check (3 s timeout)
function testTcpConnectivity(host, port) {
  return new Promise(resolve => {
    const sock = net.createConnection({ host, port: parseInt(port, 10), timeout: 3000 });
    sock.once('connect', () => { sock.destroy(); resolve({ ok: true }); });
    sock.once('timeout', () => { sock.destroy(); resolve({ ok: false, error: 'connection timed out' }); });
    sock.once('error',   err => { resolve({ ok: false, error: err.message }); });
  });
}

// Parse "8080:80, 443:443" → ['-p','8080:80','-p','443:443']
function parsePortFlags(portsStr) {
  if (!portsStr?.trim()) return [];
  return portsStr.split(',')
    .map(s => s.trim())
    .filter(s => /^\d+:\d+$/.test(s))
    .flatMap(s => ['-p', s]);
}

// ── Docker API (user-scoped) ──────────────────────────────────────────────────
app.get('/api/containers', requireAuthAPI, async (req, res) => {
  if (!docker) return res.json([]);
  const { username } = req.session.user;
  try {
    const list = await docker.listContainers({
      all: true,                                           // include stopped containers
      filters: { label: [`${LABEL_USER}=${username}`] },
    });
    res.json(list.map(c => ({
      id:     c.Id.slice(0, 12),
      name:   c.Names[0].replace('/', ''),
      image:  c.Image,
      status: c.Status,
      state:  c.State,   // 'running' | 'exited' | 'created' | …
    })));
  } catch (err) {
    console.error('Failed to list containers:', err.message);
    res.json([]);
  }
});

// Inspect a single user-owned container
app.get('/api/containers/:id', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { id } = req.params;
  const { username } = req.session.user;
  try {
    const owned = await docker.listContainers({
      all: true,
      filters: { id: [id], label: [`${LABEL_USER}=${username}`] },
    });
    if (owned.length === 0)
      return res.status(404).json({ error: 'Container not found or not yours' });

    const info = await docker.getContainer(id).inspect();

    const networks = Object.entries(info.NetworkSettings.Networks || {}).map(([name, net]) => ({
      name,
      ip:      net.IPAddress  || '—',
      gateway: net.Gateway    || '—',
      mac:     net.MacAddress || '—',
    }));

    const mounts = (info.Mounts || []).map(m => ({
      type:        m.Type,
      name:        m.Name || m.Source || '',
      destination: m.Destination,
      mode:        m.Mode || 'rw',
    }));

    const ports = Object.keys(info.NetworkSettings.Ports || {});

    res.json({
      id:       info.Id.slice(0, 12),
      name:     info.Name.replace('/', ''),
      image:    info.Config.Image,
      status:   info.State.Status,
      user:     info.Config.User || 'root',
      created:  info.Created,
      started:  info.State.StartedAt,
      finished: info.State.FinishedAt,
      cmd:      (info.Config.Cmd || []).join(' '),
      networks,
      mounts,
      ports,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Remove a single user-owned container (force stop + delete)
app.delete('/api/containers/:id', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { id } = req.params;
  const { username } = req.session.user;
  try {
    const owned = await docker.listContainers({
      all: true,
      filters: { id: [id], label: [`${LABEL_USER}=${username}`] },
    });
    if (owned.length === 0)
      return res.status(404).json({ error: 'Container not found or not yours' });
    await closeTunnelsForContainer(username, id);
    await docker.getContainer(id).remove({ force: true });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start a single user-owned container
app.post('/api/containers/:id/start', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { id } = req.params;
  const { username } = req.session.user;
  try {
    const owned = await docker.listContainers({
      all: true,
      filters: { id: [id], label: [`${LABEL_USER}=${username}`] },
    });
    if (owned.length === 0)
      return res.status(404).json({ error: 'Container not found or not yours' });
    await docker.getContainer(id).start();
    res.json({ ok: true });
  } catch (err) {
    if (err.statusCode === 304) return res.json({ ok: true }); // already running
    res.status(500).json({ error: err.message });
  }
});

// Stop a single user-owned container
app.post('/api/containers/:id/stop', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { id } = req.params;
  const { username } = req.session.user;
  try {
    const owned = await docker.listContainers({
      all: true,
      filters: { id: [id], label: [`${LABEL_USER}=${username}`] },
    });
    if (owned.length === 0)
      return res.status(404).json({ error: 'Container not found or not yours' });
    await docker.getContainer(id).stop();
    res.json({ ok: true });
  } catch (err) {
    if (err.statusCode === 304) return res.json({ ok: true }); // already stopped
    res.status(500).json({ error: err.message });
  }
});

// Remove ALL containers belonging to this user
app.delete('/api/containers', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { username } = req.session.user;
  try {
    const list = await docker.listContainers({
      all: true,
      filters: { label: [`${LABEL_USER}=${username}`] },
    });
    await closeTunnelsForUser(username);
    await Promise.all(
      list.map(c => docker.getContainer(c.Id).remove({ force: true }).catch(() => {}))
    );
    res.json({ ok: true, removed: list.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Volume API (user-scoped) ──────────────────────────────────────────────
app.get('/api/volumes', requireAuthAPI, async (req, res) => {
  if (!docker) return res.json([]);
  const { username } = req.session.user;
  try {
    const data = await docker.listVolumes({
      filters: JSON.stringify({ label: [`${LABEL_USER}=${username}`] }),
    });
    res.json((data.Volumes || []).map(v => ({ name: v.Name, created: v.CreatedAt })));
  } catch (err) {
    console.error('Failed to list volumes:', err.message);
    res.json([]);
  }
});

app.post('/api/volumes', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Volume name is required' });
  const { username } = req.session.user;
  try {
    const dbUser  = stmts.findUser.get(username);
    const existing = await docker.listVolumes({ filters: JSON.stringify({ label: [`${LABEL_USER}=${username}`] }) });
    if ((existing.Volumes || []).length >= dbUser.max_volumes)
      return res.status(429).json({ error: `Volume limit reached (${dbUser.max_volumes})` });
  } catch (err) {
    console.warn(`[${username}] could not check volume limit: ${err.message}`);
  }
  try {
    await docker.createVolume({
      Name: name.trim(),
      Labels: { [LABEL_USER]: username, 'webterminal': 'true' },
    });
    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.statusCode === 409) return res.status(409).json({ error: 'Volume already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/volumes/:name', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { name } = req.params;
  const { username } = req.session.user;
  try {
    const vol = await docker.getVolume(name).inspect();
    if (vol.Labels?.[LABEL_USER] !== username)
      return res.status(404).json({ error: 'Volume not found or not yours' });
    await docker.getVolume(name).remove();
    res.json({ ok: true });
  } catch (err) {
    if (err.statusCode === 404) return res.status(404).json({ error: 'Volume not found' });
    if (err.statusCode === 409) return res.status(409).json({ error: 'Volume is in use by a container' });
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/volumes/:name', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { name } = req.params;
  const { username } = req.session.user;
  try {
    const vol = await docker.getVolume(name).inspect();
    if (vol.Labels?.[LABEL_USER] !== username)
      return res.status(404).json({ error: 'Volume not found or not yours' });
    res.json({
      name:       vol.Name,
      driver:     vol.Driver,
      scope:      vol.Scope,
      mountpoint: vol.Mountpoint,
      created:    vol.CreatedAt,
      options:    vol.Options  || {},
      labels:     vol.Labels   || {},
      size:       vol.UsageData?.Size ?? -1,
      refcount:   vol.UsageData?.RefCount ?? -1,
    });
  } catch (err) {
    if (err.statusCode === 404) return res.status(404).json({ error: 'Volume not found' });
    res.status(500).json({ error: err.message });
  }
});

// ── Network API (user-scoped) ─────────────────────────────────────────────
app.get('/api/networks', requireAuthAPI, async (req, res) => {
  if (!docker) return res.json([]);
  const { username } = req.session.user;
  try {
    const list = await docker.listNetworks({
      filters: JSON.stringify({ label: [`${LABEL_USER}=${username}`] }),
    });
    res.json(list.map(n => ({
      id:      n.Id.slice(0, 12),
      name:    n.Name,
      driver:  n.Driver,
      created: n.Created,
    })));
  } catch (err) {
    console.error('Failed to list networks:', err.message);
    res.json([]);
  }
});

app.post('/api/networks', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Network name is required' });
  const { username } = req.session.user;
  try {
    const dbUser   = stmts.findUser.get(username);
    const existing = await docker.listNetworks({ filters: JSON.stringify({ label: [`${LABEL_USER}=${username}`] }) });
    if ((existing || []).length >= dbUser.max_networks)
      return res.status(429).json({ error: `Network limit reached (${dbUser.max_networks})` });
  } catch (err) {
    console.warn(`[${username}] could not check network limit: ${err.message}`);
  }
  try {
    await docker.createNetwork({
      Name: name.trim(),
      Driver: 'bridge',
      Labels: { [LABEL_USER]: username, 'webterminal': 'true' },
    });
    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.statusCode === 409) return res.status(409).json({ error: 'Network already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/networks/:name', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { name } = req.params;
  const { username } = req.session.user;
  try {
    const list = await docker.listNetworks({
      filters: JSON.stringify({ label: [`${LABEL_USER}=${username}`], name: [name] }),
    });
    if (list.length === 0)
      return res.status(404).json({ error: 'Network not found or not yours' });
    await docker.getNetwork(list[0].Id).remove();
    res.json({ ok: true });
  } catch (err) {
    if (err.statusCode === 403) return res.status(403).json({ error: 'Cannot remove predefined network' });
    if (err.statusCode === 409) return res.status(409).json({ error: 'Network has active endpoints' });
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/networks/:name', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { name } = req.params;
  const { username } = req.session.user;
  try {
    const list = await docker.listNetworks({
      filters: JSON.stringify({ label: [`${LABEL_USER}=${username}`], name: [name] }),
    });
    if (list.length === 0)
      return res.status(404).json({ error: 'Network not found or not yours' });
    const info = await docker.getNetwork(list[0].Id).inspect();
    const ipam = (info.IPAM?.Config || []).map(c => ({
      subnet:  c.Subnet  || '—',
      gateway: c.Gateway || '—',
    }));
    const containers = Object.values(info.Containers || {}).map(c => ({
      name: c.Name,
      ipv4: c.IPv4Address || '—',
      mac:  c.MacAddress  || '—',
    }));
    res.json({
      id:         info.Id.slice(0, 12),
      name:       info.Name,
      driver:     info.Driver,
      scope:      info.Scope,
      internal:   info.Internal,
      attachable: info.Attachable,
      created:    info.Created,
      ipam,
      containers,
      options:    info.Options || {},
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/images', requireAuthAPI, async (req, res) => {
  if (!docker) return res.json([]);
  const { username } = req.session.user;
  try {
    const images = await docker.listImages();
    const result = images
      // Show system images (no webterminal.user label) + images owned by this user
      .filter(img => {
        const owner = (img.Labels || {})[LABEL_USER];
        return !owner || owner === username;
      })
      .flatMap(img =>
        (img.RepoTags || [])
          .filter(tag => tag && tag !== '<none>:<none>')
          .map(tag => ({ tag, size: img.Size }))
      )
      .sort((a, b) => a.tag.localeCompare(b.tag));
    res.json(result);
  } catch (err) {
    console.error('Failed to list images:', err.message);
    res.json([]);
  }
});

app.get('/api/images/:tag(*)', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const tag      = req.params.tag;
  const username = req.session.user.username;
  try {
    // Verify the user can see this image
    const images = await docker.listImages({ filters: JSON.stringify({ reference: [tag] }) });
    if (images.length === 0) return res.status(404).json({ error: 'Image not found' });
    const owner = (images[0].Labels || {})[LABEL_USER];
    if (owner && owner !== username) return res.status(404).json({ error: 'Image not found' });

    const image   = docker.getImage(tag);
    const [info, history] = await Promise.all([image.inspect(), image.history()]);

    const cfg = info.Config || {};
    res.json({
      id:           info.Id.replace('sha256:', '').slice(0, 12),
      tags:         info.RepoTags  || [],
      size:         info.Size,
      created:      info.Created,
      architecture: info.Architecture,
      os:           info.Os,
      author:       info.Author   || '—',
      cmd:          cfg.Cmd       || [],
      entrypoint:   cfg.Entrypoint || [],
      env:          cfg.Env       || [],
      expose:       Object.keys(cfg.ExposedPorts || {}),
      workdir:      cfg.WorkingDir || '/',
      user:         cfg.User      || 'root',
      labels:       cfg.Labels    || {},
      history:      history.map(h => ({
        created:    h.Created,
        createdBy:  (h.CreatedBy || '').replace(/^\/bin\/sh -c #\(nop\) /, '').replace(/^\/bin\/sh -c /, 'RUN ').trim(),
        size:       h.Size,
        empty:      h.Size === 0,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/containers/:id/commit', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { id } = req.params;
  const { name, tag = 'latest' } = req.body;
  const { username } = req.session.user;

  if (!name?.trim()) return res.status(400).json({ error: 'Image name is required' });

  try {
    const owned = await docker.listContainers({
      all: true,
      filters: { id: [id], label: [`${LABEL_USER}=${username}`] },
    });
    if (owned.length === 0)
      return res.status(404).json({ error: 'Container not found or not yours' });

    await docker.getContainer(id).commit({
      repo: name.trim(),
      tag:  tag.trim() || 'latest',
      changes: [
        `LABEL ${LABEL_USER}=${username}`,
        'LABEL webterminal=true',
      ],
    });
    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.statusCode === 409) return res.status(409).json({ error: 'Image name/tag already in use' });
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/containers/run', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { username } = req.session.user;
  let { image, volume, network, ports, mem = 512, cpu = 1, shell, cmd, entrypoint, user: userParam } = req.body;

  if (!image?.trim()) return res.status(400).json({ error: 'Image is required' });

  // Container limit check
  try {
    const dbUser   = stmts.findUser.get(username);
    const existing = await docker.listContainers({
      all: true, filters: { label: [`${LABEL_USER}=${username}`] },
    });
    if (existing.length >= dbUser.max_containers)
      return res.status(429).json({ error: `Container limit reached (${dbUser.max_containers})` });
  } catch (err) {
    console.warn(`[${username}] could not check container limit: ${err.message}`);
  }

  // Auto-create default network
  let networkName = network || null;
  if (!networkName) {
    const defaultNet = `netdefault-${username}`;
    try {
      const existing = await docker.listNetworks({ filters: JSON.stringify({ name: [defaultNet] }) });
      if (existing.length === 0) {
        await docker.createNetwork({
          Name: defaultNet, Driver: 'bridge',
          Labels: { [LABEL_USER]: username, 'webterminal': 'true' },
        });
      }
      networkName = defaultNet;
    } catch (err) {
      console.warn(`[${username}] could not ensure default network: ${err.message}`);
    }
  }

  mem = Math.max(64,  Math.min(8192, parseInt(mem,  10) || 512));
  cpu = Math.max(0.1, Math.min(8,    parseFloat(cpu) || 1));

  const portFlags = parsePortFlags(ports);
  const args = ['run', '-d', '-w', '/data',
    `--label=${LABEL_USER}=${username}`,
    '--label=webterminal=true',
    '--memory', `${mem}m`,
    '--cpus',   String(cpu),
    ...portFlags,
    ...(userParam  && userParam !== 'root' ? ['--user',       userParam]  : []),
    ...(entrypoint                         ? ['--entrypoint', entrypoint] : []),
    ...(volume      ? ['-v', `${volume}:/data`]    : []),
    // ...(networkName ? ['--network', networkName]   : []),
    image.trim(),
    ...(shell ? ['sh', '-c', cmd || 'command -v bash >/dev/null 2>&1 && exec bash || exec sh'] : []),
  ];

  console.log(`[${username}] run (bg) → ${image.trim()}`);

  execFile('docker', args, (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message.split('\n')[0] });
    res.status(201).json({ ok: true, id: stdout.trim().slice(0, 12) });
  });
});

app.get('/api/containers/:id/logs', requireAuthAPI, async (req, res) => {
  if (!docker) return res.status(503).json({ error: 'Docker not available' });
  const { id } = req.params;
  const tail = Math.min(500, Math.max(1, parseInt(req.query.tail || '200', 10)));
  const { username } = req.session.user;
  try {
    const owned = await docker.listContainers({
      all: true,
      filters: { id: [id], label: [`${LABEL_USER}=${username}`] },
    });
    if (owned.length === 0)
      return res.status(404).json({ error: 'Container not found or not yours' });

    const buf = await docker.getContainer(id).logs({
      stdout: true, stderr: true, follow: false, tail,
    });
    // Strip ANSI escape codes and Docker multiplexing headers
    const text = buf.toString('utf8')
      .replace(/[\x00-\x08\x0e-\x1a\x1c-\x1f]/g, '')   // control chars (keep \n \r \t)
      .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');            // ANSI CSI sequences
    res.type('text/plain').send(text);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── WebSocket ─────────────────────────────────────────────────────────────────
function parseSession(req) {
  return new Promise(resolve => {
    const fakeRes = { getHeader: () => {}, setHeader: () => {} };
    sessionMiddleware(req, fakeRes, () => resolve(req.session));
  });
}

wss.on('connection', async (ws, req) => {
  const sess = await parseSession(req);
  const user = sess?.user;

  if (!user) {
    ws.send(JSON.stringify({ type: 'output', data: '\r\n\x1b[31mUnauthorized. Please log in.\x1b[0m\r\n' }));
    ws.close();
    return;
  }

  const dbUser = stmts.findUser.get(user.username);
  if (!dbUser || !dbUser.active) {
    ws.send(JSON.stringify({ type: 'output', data: '\r\n\x1b[31mAccount is disabled.\x1b[0m\r\n' }));
    ws.close();
    return;
  }

  const { username } = user;
  const url = new URL(req.url, 'http://localhost');
  const containerId = url.searchParams.get('container');
  const imageName   = url.searchParams.get('image');
  const root        = url.searchParams.get('root') === '1';

  let cmd, args, opts;

  if (containerId) {
    if (docker) {
      try {
        const owned = await docker.listContainers({
          filters: { id: [containerId], label: [`${LABEL_USER}=${username}`] },
        });
        if (owned.length === 0) {
          ws.send(JSON.stringify({ type: 'output', data: '\r\n\x1b[31mAccess denied: container not yours.\x1b[0m\r\n' }));
          ws.close();
          return;
        }
      } catch { /* docker unavailable */ }
    }
    if (root) {
      console.log(`[${username}] exec (root) → ${containerId}`);
      cmd  = 'docker';
      args = ['exec', '-it', '-u', 'root', containerId, 'sh', '-c',
        'command -v bash >/dev/null 2>&1 && exec bash || exec sh'];
    } else {
      console.log(`[${username}] attach → ${containerId}`);
      cmd  = 'docker';
      args = ['attach', containerId];
    }
    opts = { name: 'xterm-color', cols: 80, rows: 24, env: process.env };

  } else if (imageName) {
    // ── Container limit check ────────────────────────────────────────────
    if (docker) {
      try {
        const dbUser   = stmts.findUser.get(username);
        const existing = await docker.listContainers({
          all: true,
          filters: { label: [`${LABEL_USER}=${username}`] },
        });
        if (existing.length >= dbUser.max_containers) {
          ws.send(JSON.stringify({ type: 'output', data:
            `\r\n\x1b[31mContainer limit reached (${dbUser.max_containers}/${dbUser.max_containers}). Remove an existing container first.\x1b[0m\r\n` }));
          ws.close();
          return;
        }
      } catch (err) {
        console.warn(`[${username}] could not check container limit: ${err.message}`);
      }
    }

    const volumeName  = url.searchParams.get('volume');
    let   networkName = url.searchParams.get('network');

    // Auto-create a default bridge network for the user if none was selected
    if (!networkName && docker) {
      const defaultNet = `netdefault-${username}`;
      try {
        const existing = await docker.listNetworks({
          filters: JSON.stringify({ name: [defaultNet] }),
        });
        if (existing.length === 0) {
          await docker.createNetwork({
            Name: defaultNet,
            Driver: 'bridge',
            Labels: { [LABEL_USER]: username, 'webterminal': 'true' },
          });
          console.log(`[${username}] created default network: ${defaultNet}`);
        }
        networkName = defaultNet;
      } catch (err) {
        console.warn(`[${username}] could not ensure default network: ${err.message}`);
      }
    }

    // Resource limits — clamp to sane bounds regardless of user input
    const mem  = Math.max(64,  Math.min(8192, parseInt(url.searchParams.get('mem')  || '512', 10)));
    const cpu  = Math.max(0.1, Math.min(8,    parseFloat(url.searchParams.get('cpu') || '1')));

    const shell           = url.searchParams.get('shell') === '1';
    const cmdParam        = url.searchParams.get('cmd')        || null;
    const entrypointParam = url.searchParams.get('entrypoint') || null;
    const userParam       = url.searchParams.get('user')       || null; // 'root' | 'uid:gid' | null
    const portFlags       = parsePortFlags(url.searchParams.get('ports'));

    console.log(`[${username}] run → ${imageName}${volumeName ? ` +vol:${volumeName}` : ''}${networkName ? ` +net:${networkName}` : ''} mem:${mem}m cpu:${cpu} user:${userParam || 'default'} shell:${shell}`);
    cmd  = 'docker';
    args = ['run', '-it', '-w', '/data',
      `--label=${LABEL_USER}=${username}`,
      '--label=webterminal=true',
      '--memory', `${mem}m`,
      '--cpus',   String(cpu),
      ...portFlags,
      ...(userParam       && userParam !== 'root' ? ['--user',       userParam]       : []),
      ...(entrypointParam                         ? ['--entrypoint', entrypointParam] : []),
      ...(volumeName  ? ['-v', `${volumeName}:/data`]  : []),
      ...(networkName ? ['--network', networkName]      : []),
      imageName,
      ...(shell ? ['sh', '-c', cmdParam || 'command -v bash >/dev/null 2>&1 && exec bash || exec sh'] : [])];
    opts = { name: 'xterm-color', cols: 80, rows: 24, env: process.env };

  } else {
    if (user.role !== 'admin') {
      ws.send(JSON.stringify({ type: 'output', data: '\r\n\x1b[31mAccess denied: local shell is for admins only.\x1b[0m\r\n' }));
      ws.close();
      return;
    }
    console.log(`[${username}] local shell`);
    cmd  = LOCAL_SHELL;
    args = [];
    opts = { name: 'xterm-color', cols: 80, rows: 24, cwd: os.homedir(), env: process.env };
  }

  let ptyProcess;
  try {
    ptyProcess = pty.spawn(cmd, args, opts);
  } catch (err) {
    ws.send(JSON.stringify({ type: 'output', data: `\r\nFailed to start session: ${err.message}\r\n` }));
    ws.close();
    return;
  }

  ptyProcess.onData(data => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'output', data }));
  });

  ptyProcess.onExit(({ exitCode }) => {
    console.log(`[${username}] exited, code: ${exitCode}`);
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'exit', code: exitCode }));
      ws.close();
    }
  });

  ws.on('message', message => {
    try {
      const msg = JSON.parse(message);
      if (msg.type === 'input')  ptyProcess.write(msg.data);
      if (msg.type === 'resize') ptyProcess.resize(msg.cols, msg.rows);
    } catch { }
  });

  ws.on('close', () => { try { ptyProcess.kill(); } catch {} });
  ws.on('error', () => { try { ptyProcess.kill(); } catch {} });
});

server.listen(PORT, () => console.log(`Web terminal running at http://localhost:${PORT}`));
