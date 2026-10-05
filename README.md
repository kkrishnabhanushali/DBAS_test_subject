# 🛡️ SecureTask — Security-Hardened Task Management App

A fully hardened, production-ready task management web application built with **Node.js + Express** backend and **vanilla HTML/CSS/JS** frontend. Every layer is designed to be vulnerability-proof against OWASP Top 10 and beyond.

![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?logo=nodedotjs&logoColor=white)
![Express](https://img.shields.io/badge/Express-4.x-000000?logo=express&logoColor=white)
![Security](https://img.shields.io/badge/Security-Hardened-10b981)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## 📋 Table of Contents

- [Features](#-features)
- [Security Defenses](#-security-defenses)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Environment Variables](#-environment-variables)
- [API Reference](#-api-reference)
- [Security Architecture](#-security-architecture)
- [Deployment & Hosting](#-deployment--hosting)
- [License](#-license)

---

## ✨ Features

- **User Authentication** — Register, login, logout with secure session management
- **Task Management** — Full CRUD (create, read, update, delete) with priority levels and due dates
- **User Profiles** — Edit display name, email, and change password
- **Dashboard** — Real-time stats (total, pending, in-progress, completed tasks)
- **Task Filtering** — Filter by status (all, pending, in progress, completed)
- **Premium UI** — Dark glassmorphism design with Inter font, gradients, and micro-animations
- **Responsive** — Works on desktop, tablet, and mobile
- **Production-Ready** — Graceful shutdown, centralized error handling, safe logging

---

## 🔒 Security Defenses

This application is hardened against **17+ vulnerability types**:

| # | Vulnerability | Defense | Implementation |
|---|---|---|---|
| 1 | **SQL Injection** | Zero SQL surface — uses pure JS JSON data store | No SQL = no SQLi possible |
| 2 | **Credential Stuffing** | Auth-specific rate limiter (5 requests/15 minutes per IP) | `express-rate-limit` on `/api/auth/*` |
| 3 | **Brute Force** | Account lockout after 5 failed attempts (15-minute cooldown) | Login attempt tracking + auto-lock |
| 4 | **XSS (Cross-Site Scripting)** | Content Security Policy headers + input sanitization + `textContent` only (never `innerHTML`) | `helmet` CSP + `express-validator` escape + safe DOM APIs |
| 5 | **CSRF (Cross-Site Request Forgery)** | Double-submit cookie pattern + `SameSite=Strict` cookies | `csrf-csrf` library |
| 6 | **Clickjacking** | `X-Frame-Options: DENY` + `frame-ancestors: 'none'` | `helmet` frameguard |
| 7 | **Session Hijacking** | `httpOnly`, `secure`, `SameSite=Strict` cookies; session regeneration on login | `express-session` with hardened config |
| 8 | **Weak Passwords** | bcrypt hashing (cost factor 12) + password complexity rules | 8+ chars, upper, lower, number, special char required |
| 9 | **Username Enumeration** | Constant-time responses (dummy hash when user doesn't exist) + generic error messages | `"Invalid username or password"` for both cases |
| 10 | **Broken Access Control** | Server-side ownership validation on every data operation | `userId` checked in every query |
| 11 | **Mass Assignment** | Explicit field whitelisting on all create/update endpoints | Only `title`, `description`, `priority`, `status`, `dueDate` accepted |
| 12 | **DoS (Denial of Service)** | Request body size limit (10KB) + global rate limiter (100 req/15min) | `express.json({ limit: '10kb' })` + `express-rate-limit` |
| 13 | **HTTP Parameter Pollution** | HPP middleware | `hpp` package |
| 14 | **Security Misconfiguration** | Helmet security headers, `X-Powered-By` disabled, HSTS enabled | `helmet()` with full config |
| 15 | **Sensitive Data Exposure** | Secrets in `.env`, no sensitive data in logs/errors, HTTPS-ready | `dotenv` + safe `morgan` config |
| 16 | **Information Leakage** | Generic error messages in production (no stack traces, no DB schema) | Centralized error handler |
| 17 | **Open Redirect** | No user-controlled redirects | All redirects are hardcoded paths |

### Security Headers (automatically set on every response)

```
Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none'; ...
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-DNS-Prefetch-Control: off
Referrer-Policy: strict-origin-when-cross-origin
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Runtime** | Node.js 18+ | JavaScript runtime |
| **Framework** | Express 4.x | Web server & routing |
| **Database** | JSON file store | Zero SQL injection surface, portable |
| **Auth** | bcryptjs + express-session | Password hashing & session management |
| **Security Headers** | helmet | CSP, HSTS, X-Frame-Options, etc. |
| **Rate Limiting** | express-rate-limit | Brute force & DoS protection |
| **CSRF** | csrf-csrf | Double-submit cookie protection |
| **Validation** | express-validator | Input sanitization & validation |
| **HPP** | hpp | HTTP parameter pollution protection |
| **Frontend** | Vanilla HTML/CSS/JS | No framework dependencies |
| **Design** | Inter font + Glassmorphism | Premium dark theme |

---

## 📁 Project Structure

```
securetask/
├── server.js                          # Main Express server (14 security middleware layers)
├── package.json                       # Project manifest & scripts
├── .env                               # Environment variables (secrets — never commit!)
├── .env.example                       # Template for environment variables
├── .gitignore                         # Ignores node_modules, .env, *.db
│
├── public/                            # Static frontend files
│   ├── index.html                     # Login & registration page
│   ├── dashboard.html                 # Dashboard (tasks, profile, security views)
│   ├── css/
│   │   └── style.css                  # Complete design system (700+ lines)
│   └── js/
│       └── app.js                     # Frontend logic (XSS-safe, CSRF-aware)
│
└── src/                               # Backend source code
    ├── db/
    │   └── database.js                # Secure JSON data store with atomic writes
    ├── middleware/
    │   ├── rateLimiter.js             # 3-tier rate limiting (global, auth, API)
    │   ├── validator.js               # Input validation schemas for all endpoints
    │   ├── auth.js                    # Session-based authentication guard
    │   └── errorHandler.js            # Safe centralized error handler
    └── routes/
        ├── auth.js                    # POST /register, /login, /logout + GET /me
        ├── tasks.js                   # GET/POST/PUT/DELETE /tasks (ownership enforced)
        └── user.js                    # GET/PUT /profile, PUT /password
```

---

## 🚀 Getting Started

### Prerequisites

- **Node.js** 18 or higher — [Download](https://nodejs.org/)
- **npm** (comes with Node.js)

### Installation

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd testsubject

# 2. Install dependencies (locally in node_modules — no global installs)
npm install

# 3. Set up environment variables
cp .env.example .env
# Edit .env with your own secrets (see Environment Variables section)

# 4. Start the server
npm start
```

### Running in Development

```bash
npm run dev    # Starts with --watch for auto-reload on file changes
```

### Open in Browser

Navigate to **http://localhost:3000** — you'll see the login page.

1. Click **"Create one"** to register a new account
2. Fill in your details (password must have 8+ chars, upper, lower, number, special)
3. You'll be redirected to the dashboard
4. Start creating tasks!

---

## 🔑 Environment Variables

Create a `.env` file in the project root (use `.env.example` as a template):

| Variable | Description | Default | Required |
|---|---|---|---|
| `NODE_ENV` | Environment mode (`development` or `production`) | `production` | Yes |
| `PORT` | Server port | `3000` | No |
| `SESSION_SECRET` | Secret key for signing session cookies (64+ chars) | — | **Yes** |
| `CSRF_SECRET` | Secret key for CSRF token generation (64+ chars) | — | **Yes** |

### Generating Secure Secrets

```bash
# Generate a cryptographically secure random secret
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

> ⚠️ **Never commit `.env` to version control.** It's already in `.gitignore`.

---

## 📡 API Reference

All API responses follow this format:
```json
{
  "success": true|false,
  "error": "message"      // only on failure
}
```

### Authentication

| Method | Endpoint | Description | Auth Required | Rate Limited |
|---|---|---|---|---|
| `POST` | `/api/auth/register` | Create a new account | No | ✅ 5/15min |
| `POST` | `/api/auth/login` | Log in | No | ✅ 5/15min |
| `POST` | `/api/auth/logout` | Log out (destroys session) | Yes | No |
| `GET` | `/api/auth/me` | Get current user info | Yes | No |

### Tasks

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/api/tasks` | Get all tasks + stats | Yes |
| `POST` | `/api/tasks` | Create a task | Yes |
| `GET` | `/api/tasks/:id` | Get a single task | Yes |
| `PUT` | `/api/tasks/:id` | Update a task | Yes |
| `DELETE` | `/api/tasks/:id` | Delete a task | Yes |

### User / Profile

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/api/user/profile` | Get profile | Yes |
| `PUT` | `/api/user/profile` | Update display name / email | Yes |
| `PUT` | `/api/user/password` | Change password | Yes |

### CSRF Token

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/csrf-token` | Get a CSRF token (required before POST/PUT/DELETE) |

> All `POST`, `PUT`, `DELETE` requests require the `x-csrf-token` header.

### Request/Response Examples

<details>
<summary><strong>Register</strong></summary>

```bash
# 1. Get CSRF token
curl -c cookies.txt http://localhost:3000/api/csrf-token
# → {"success":true,"token":"abc123..."}

# 2. Register
curl -b cookies.txt -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: abc123..." \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "MySecurePass1!",
    "displayName": "John Doe"
  }'
# → {"success":true,"message":"Account created successfully","user":{...}}
```
</details>

<details>
<summary><strong>Create Task</strong></summary>

```bash
curl -b cookies.txt -X POST http://localhost:3000/api/tasks \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: abc123..." \
  -d '{
    "title": "Review security audit",
    "description": "Check all OWASP defenses",
    "priority": "high",
    "dueDate": "2026-09-15"
  }'
# → {"success":true,"task":{"id":1,"title":"Review security audit",...}}
```
</details>

---

## 🏗️ Security Architecture

### Middleware Stack (applied in order)

```
Request
  │
  ├─ 1.  Helmet          → Security headers (CSP, HSTS, X-Frame-Options...)
  ├─ 2.  CORS            → Same-origin only
  ├─ 3.  HPP             → HTTP parameter pollution protection
  ├─ 4.  Body Parser     → 10KB request size limit
  ├─ 5.  Cookie Parser   → Signed cookie handling
  ├─ 6.  Session         → Secure session (httpOnly, SameSite=Strict)
  ├─ 7.  CSRF            → Double-submit cookie validation
  ├─ 8.  Rate Limiter    → Global: 100/15min, Auth: 5/15min, API: 60/min
  ├─ 9.  Morgan          → Request logging (no sensitive data)
  ├─ 10. Static Files    → Serve from /public only, dotfiles denied
  ├─ 11. API Routes      → Auth, Tasks, User (with validation & ownership)
  ├─ 12. Catch-all       → 404 for unknown routes
  └─ 13. Error Handler   → Generic errors (no stack traces in production)
```

### Data Security

- **Password Storage**: bcrypt with cost factor 12 (never stored in plaintext)
- **Session Cookies**: `httpOnly` (no JS access), `secure` (HTTPS only in production), `SameSite=Strict` (CSRF prevention), 30-minute expiry
- **Data Isolation**: Every database query includes `userId` — users can never access other users' data
- **Atomic Writes**: Database writes to a temp file first, then renames (prevents corruption on crash)

### Frontend Security

- **No `innerHTML`**: All DOM content is set via `textContent` or `createElement` (XSS impossible)
- **No `eval()` or `Function()`**: No dynamic code execution
- **CSRF tokens**: Automatically fetched and attached to every state-changing API call
- **Auto-redirect on 401**: If session expires, user is redirected to login

---

## 🌐 Deployment & Hosting

### Before Deploying

1. **Generate new secrets** for production:
   ```bash
   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
   ```
   
2. **Update `.env`** with the new secrets and set `NODE_ENV=production`

3. **Set up HTTPS** — required for `secure` cookies to work in production

### Option 1: VPS (DigitalOcean, AWS EC2, Linode)

```bash
# Install Node.js on your server
# Clone your repo
git clone <repo-url> && cd testsubject
npm install --production

# Use PM2 for process management
npm install -g pm2
pm2 start server.js --name securetask
pm2 save
pm2 startup

# Set up nginx as reverse proxy with SSL (Let's Encrypt)
```

<details>
<summary><strong>Example nginx config</strong></summary>

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```
</details>

### Option 2: Platform (Render, Railway, Fly.io)

1. Push your code to GitHub
2. Connect the repo to your platform
3. Set environment variables in the platform dashboard:
   - `NODE_ENV=production`
   - `SESSION_SECRET=<your-secret>`
   - `CSRF_SECRET=<your-secret>`
   - `PORT=3000` (or platform's default)
4. Deploy — the platform will run `npm start` automatically

### Option 3: Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
EXPOSE 3000
USER node
CMD ["node", "server.js"]
```

```bash
docker build -t securetask .
docker run -p 3000:3000 --env-file .env securetask
```

---

## 🧪 Testing Security

You can verify the security defenses yourself:

```bash
# Test SQL Injection (should return generic error)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR 1=1 --","password":"anything"}'

# Test XSS (should escape HTML)
# → <script> becomes &lt;script&gt;

# Test CSRF (missing token → 403)
curl -X POST http://localhost:3000/api/tasks \
  -H "Content-Type: application/json" \
  -d '{"title":"No CSRF"}'

# Check security headers
curl -I http://localhost:3000

# Test rate limiting (6th request in 15 min → 429)
for i in {1..6}; do
  curl -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"wrong"}';
  echo;
done
```

---

## 📄 License

This project is licensed under the MIT License.
