const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const pty = require('node-pty');
const Docker = require('dockerode');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const os = require('os');

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
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )
`);

// ── Migrate existing databases that lack the active column ────────────────
try {
  db.exec(`ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1`);
} catch (_) { /* column already exists */ }

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
  listUsers:    db.prepare('SELECT username, role, active, created_at FROM users ORDER BY created_at ASC'),
  createUser:   db.prepare('INSERT INTO users (username, password_hash, role, active) VALUES (?, ?, ?, ?)'),
  updatePass:   db.prepare('UPDATE users SET password_hash = ? WHERE username = ?'),
  updateRole:   db.prepare('UPDATE users SET role = ? WHERE username = ?'),
  updateActive: db.prepare('UPDATE users SET active = ? WHERE username = ?'),
  deleteUser:   db.prepare('DELETE FROM users WHERE username = ?'),
};

// ── Docker ────────────────────────────────────────────────────────────────────
let docker = null;
try {
  docker = new Docker({ socketPath: '/var/run/docker.sock' });
} catch (e) {
  console.warn('Docker socket not available:', e.message);
}

// ── Express + session ─────────────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const sessionMiddleware = session({
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
  res.json({ username: req.session.user.username, role: req.session.user.role });
});

// ── Admin API ─────────────────────────────────────────────────────────────────
app.get('/api/admin/users', requireAuthAPI, requireAdmin, (req, res) => {
  res.json(stmts.listUsers.all());
});

app.post('/api/admin/users', requireAuthAPI, requireAdmin, (req, res) => {
  const { username, password, role = 'user', active = true } = req.body;
  if (!username?.trim())  return res.status(400).json({ error: 'Username is required' });
  if (!password?.trim())  return res.status(400).json({ error: 'Password is required' });
  if (!['admin', 'user'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

  try {
    stmts.createUser.run(username.trim(), bcrypt.hashSync(password, 10), role, active ? 1 : 0);
    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.put('/api/admin/users/:username', requireAuthAPI, requireAdmin, (req, res) => {
  const { username } = req.params;
  const { password, role, active } = req.body;

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

app.get('/api/images', requireAuthAPI, async (req, res) => {
  if (!docker) return res.json([]);
  try {
    const images = await docker.listImages();
    const result = images
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
    console.log(`[${username}] exec → ${containerId} root:${root}`);
    cmd  = 'docker';
    args = ['exec', '-it',
      ...(root ? ['-u', 'root'] : []),
      containerId, 'sh', '-c',
      'command -v bash >/dev/null 2>&1 && exec bash || exec sh'];
    opts = { name: 'xterm-color', cols: 80, rows: 24, env: process.env };

  } else if (imageName) {
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

    console.log(`[${username}] run → ${imageName}${volumeName ? ` +vol:${volumeName}` : ''}${networkName ? ` +net:${networkName}` : ''} mem:${mem}m cpu:${cpu} root:${root}`);
    cmd  = 'docker';
    args = ['run', '-it', '-w', '/data',
      `--label=${LABEL_USER}=${username}`,
      '--label=webterminal=true',
      '--memory', `${mem}m`,
      '--cpus',   String(cpu),
      ...(!root ? ['--user', '1000:1000'] : []),
      ...(volumeName  ? ['-v', `${volumeName}:/data`]  : []),
      ...(networkName ? ['--network', networkName]      : []),
      imageName, 'sh', '-c',
      'command -v bash >/dev/null 2>&1 && exec bash || exec sh'];
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
