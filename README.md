# Web Terminal

A self-hosted web-based terminal that runs shell sessions inside Docker containers directly from your browser. Built with [xterm.js](https://xtermjs.org/), Node.js, and the Docker Engine API.

---

## Features

- **Browser terminal** — full xterm.js terminal with colour support, resize, and keyboard shortcuts
- **Docker container sessions** — launch ephemeral containers from any available image
- **Attach to running containers** — connect to an existing container's shell
- **Container management** — start, stop, and remove containers from the dashboard
- **Container details** — inspect IP, networks, mounts, ports, and lifecycle timestamps
- **Persistent volumes** — create named volumes mounted at `/data` inside containers
- **Bridge networks** — create and attach private bridge networks to isolate traffic
- **Resource limits** — configurable memory (MB) and CPU limits per container launch
- **Multi-user auth** — session-based login with bcrypt-hashed passwords (SQLite)
- **Role system** — `admin` and `user` roles with separate capabilities
- **Admin panel** — create, edit, delete users and reset any user's password
- **Change password** — every user can change their own password from the dashboard
- **Local shell** — admins can open a shell directly on the host machine

---

## Architecture

```
Browser  ──HTTP/WS──▶  Express + ws  ──node-pty──▶  docker exec / docker run
                            │
                        SQLite DB  (users, passwords, roles)
                            │
                       Docker socket  /var/run/docker.sock
```

| Component | Role |
|-----------|------|
| `server.js` | Express HTTP server, REST API, WebSocket handler |
| `node-pty` | Spawns a PTY process (`docker exec` / `docker run` / local shell) |
| `xterm.js` | Terminal emulator rendered in the browser |
| `better-sqlite3` | Lightweight embedded database for users |
| `dockerode` | Node.js Docker Engine API client |
| `express-session` | Cookie-based session management |
| `bcryptjs` | Password hashing |

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) ≥ 20.10
- Docker Compose v2 (bundled with Docker Desktop) **or** Node.js ≥ 20 for running locally

---

## Quick Start (Docker Compose)

1. **Clone the repository**

   ```bash
   git clone https://github.com/mario21ic/webterminal.git
   cd webterminal
   ```

2. **Start the service**

   ```bash
   docker compose up -d
   ```

3. **Open your browser**

   ```
   http://localhost:3000
   ```

4. **Log in** with the default admin credentials:

   | Username | Password |
   |----------|----------|
   | `admin`  | `changeme` |

   > **Change the default password immediately** — see [Environment Variables](#environment-variables).

---

## Environment Variables

Set these in `docker-compose.yml` under `environment:` or pass them with `-e` when running the container.

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | HTTP port the server listens on |
| `SESSION_SECRET` | `change-me-in-production` | Secret used to sign session cookies. **Must be changed in production.** |
| `ADMIN_USER` | *(empty)* | Seed an admin account on first run: `username:password` |
| `USERS` | *(empty)* | Seed regular user accounts on first run: `alice:pass,bob:pass` |
| `SHELL` | `/bin/bash` | Shell used for the local shell session (admin only) |
| `DB_PATH` | `./data/users.db` | Path to the SQLite database file |

Example for production use:

```yaml
environment:
  - SESSION_SECRET=a-long-random-string-here
  - ADMIN_USER=admin:strongpassword
  - USERS=alice:alicepass,bob:bobpass
```

> Seed variables only create accounts if they do not already exist. Changing them after first run has no effect on existing accounts.

---

## Running Without Docker Compose

### Using a pre-built image

```bash
docker run -d \
  --name webterminal \
  -p 3000:3000 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v webterminal_data:/app/data \
  -e SESSION_SECRET=change-me \
  -e ADMIN_USER=admin:changeme \
  mario21ic/webterminal:latest
```

### Building the image locally

```bash
docker build -t webterminal .
docker run -d \
  --name webterminal \
  -p 3000:3000 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v webterminal_data:/app/data \
  -e SESSION_SECRET=change-me \
  -e ADMIN_USER=admin:changeme \
  webterminal
```

### Running with Node.js (development)

```bash
npm install
ADMIN_USER=admin:changeme SESSION_SECRET=dev-secret node server.js
```

> Requires Node.js ≥ 20 and `python3 / make / g++` for `node-pty` native compilation.

---

## Data Persistence

The SQLite database is stored at `/app/data/users.db` inside the container. Mount a named volume or a host directory to preserve it across container restarts:

```yaml
volumes:
  - webterminal_data:/app/data
```

---

## User Roles

| Capability | `user` | `admin` |
|------------|:------:|:-------:|
| Launch containers from images | ✓ | ✓ |
| Connect to own running containers | ✓ | ✓ |
| Manage own volumes and networks | ✓ | ✓ |
| Change own password | ✓ | ✓ |
| Open local host shell | — | ✓ |
| Access Admin panel | — | ✓ |
| Create / delete users | — | ✓ |
| Reset any user's password | — | ✓ |
| Change any user's role | — | ✓ |

---

## Dashboard

After login every user sees the **dashboard** (`/`) with the following cards:

| Card | Description |
|------|-------------|
| **Local Shell** | Opens a shell on the host machine. Admin only. |
| **My Containers** | Lists your containers (running / stopped). Connect, start, stop, remove, or inspect each one. |
| **Docker Image** | Pick an image, optional volume and network, set memory and CPU limits, then launch an ephemeral container. |
| **My Networks** | Create and remove personal bridge networks. |
| **My Volumes** | Create and remove persistent volumes (mounted at `/data` in containers). |

### Container resource limits

When launching a container from an image you can set:

- **Memory** — 64 MB to 8192 MB (default 512 MB)
- **CPU** — 0.1 to 8 CPUs (default 1)

Limits are validated server-side and cannot be exceeded regardless of what the browser sends.

---

## Admin Panel

Accessible at `/admin` for users with the `admin` role.

### User table

Each row shows the username, role badge, and creation date with three actions:

| Action | Description |
|--------|-------------|
| **Edit** | Change the user's role (`user` / `admin`) |
| **Reset Pwd** | Set a new password for any user without needing their current one |
| **Delete** | Permanently delete the user (cannot delete your own account) |

### Creating a user

Click **+ New User**, fill in a username, password (min. 6 characters), and role, then submit.

---

## API Reference

All API endpoints require an active session (login first). Admin endpoints additionally require the `admin` role.

### Auth

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/login` | `{ username, password }` → sets session cookie |
| `POST` | `/api/logout` | Destroys session |
| `GET` | `/api/me` | Returns `{ username, role }` |
| `POST` | `/api/me/password` | `{ currentPassword, newPassword }` → change own password |

### Admin — Users

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/users` | List all users |
| `POST` | `/api/admin/users` | `{ username, password, role }` → create user |
| `PUT` | `/api/admin/users/:username` | `{ role }` → update role |
| `DELETE` | `/api/admin/users/:username` | Delete user |
| `PUT` | `/api/admin/users/:username` | `{ password }` → reset password (also accepts role + password together) |

### Containers

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/containers` | List own containers |
| `GET` | `/api/containers/:id` | Inspect container (networks, mounts, ports) |
| `DELETE` | `/api/containers/:id` | Force-remove a container |
| `POST` | `/api/containers/:id/start` | Start a stopped container |
| `POST` | `/api/containers/:id/stop` | Stop a running container |
| `DELETE` | `/api/containers` | Force-remove all own containers |

### Volumes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/volumes` | List own volumes |
| `POST` | `/api/volumes` | `{ name }` → create volume |
| `DELETE` | `/api/volumes/:name` | Remove volume |

### Networks

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/networks` | List own networks |
| `POST` | `/api/networks` | `{ name }` → create bridge network |
| `DELETE` | `/api/networks/:name` | Remove network |

### Images

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/images` | List all images available on the Docker host |

---

## Security Notes

- **Docker socket access** — the container mounts `/var/run/docker.sock`. This grants root-equivalent access to the Docker host. Deploy only on trusted infrastructure.
- **Session secret** — always set a strong, unique `SESSION_SECRET` in production.
- **Default credentials** — change the `ADMIN_USER` password before exposing the service.
- **Container isolation** — each user's containers are labelled with `webterminal.user=<username>` and API calls are scoped to that label, so users cannot access each other's containers.
- **HTTPS** — this service does not terminate TLS. Put it behind a reverse proxy (nginx, Caddy, Traefik) with HTTPS in production.

---

## Project Structure

```
webterminal/
├── server.js          # Express server, REST API, WebSocket / PTY handler
├── public/
│   ├── index.html     # User dashboard
│   ├── terminal.html  # xterm.js terminal view
│   ├── admin.html     # Admin panel
│   └── login.html     # Login page
├── Dockerfile         # Multi-stage build (builder + lean runtime)
├── docker-compose.yml # Compose stack for easy deployment
├── package.json
└── data/              # Runtime — SQLite DB (created automatically)
    └── users.db
```

---

## License

[MIT](LICENSE)
