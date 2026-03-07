# OWASP TOP 10 ONLINE SCANNER

🛡️ Security vulnerability scanner powered by [Nuclei](https://github.com/projectdiscovery/nuclei) with OWASP Top 10 categorization.

## Features

- **Login-only access** — No public registration; admin creates all users
- **Admin Panel** — CRUD users, view audit logs, dashboard stats, manage all jobs
- **User Dashboard** — Submit scans, view history, findings grouped by severity & OWASP category
- **Background Scanning** — Scans run server-side via Redis Queue; persist even if browser closes
- **OWASP Mapping** — 200+ CWE-to-OWASP mappings + tag-based heuristics
- **Findings Management** — Mark as False Positive / Needs Review / Confirmed
- **Deep Scan Mode**: Integrated with ProjectDiscovery **Katana** for passive/active crawling to discover endpoints before scanning.
- **Reporting & Export**: Export findings in detailed JSON or CSV formats.
- **Target Validation** — SSRF protection (blocks private IPs, cloud metadata)
- **Rate Limiting** — Per-user and global scan limits
- **Audit Logging** — All actions logged (login, scan, user changes)
- **Responsive UI** — Mobile-first dark theme with glassmorphism design
- **API Documentation** — Swagger/OpenAPI (development mode)

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.10+ / FastAPI |
| Frontend | React 19 / Vite |
| Database | SQLite (default) / PostgreSQL |
| Queue | Redis + RQ |
| Scanner | Nuclei |
| Auth | Session-based (bcrypt, httponly cookies) |

## Quick Start (Local Development)

### Requirements

- Python 3.10+
- Node.js 18+
- Redis Server
- [Nuclei](https://github.com/projectdiscovery/nuclei) (v3.3+)
- [Katana](https://github.com/projectdiscovery/katana) (for Deep Scan feature)for scanning, app works without it)

### 1. Clone & Setup Backend

```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# From project root
cp .env.example .env
# Edit .env with your settings
```

### 3. Initialize Database & Create Admin User

```bash
cd backend
python seed.py
```

Default credentials:
- **Username:** `admin`
- **Password:** `Admin@123`

⚠️ **Change this password immediately after first login!**

### 4. Start Backend

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 5. Start Worker (for background scanning)

```bash
cd backend
python worker.py
```

### 6. Setup & Start Frontend

```bash
cd frontend
npm install
npm run dev
```

### 7. Open Application

Navigate to `http://localhost:5173`

## Environment Variables

See [.env.example](.env.example) for all available configuration options.

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | `development` or `production` |
| `SECRET_KEY` | random | Session signing key |
| `DATABASE_URL` | `sqlite:///./scanner.db` | Database connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `NUCLEI_BIN` | `/usr/local/bin/nuclei` | Path to nuclei binary |
| `NUCLEI_TEMPLATES` | `~/nuclei-templates` | Nuclei templates directory |
| `MAX_CONCURRENT_SCANS_PER_USER` | `5` | Per-user scan limit |
| `MAX_CONCURRENT_SCANS_GLOBAL` | `20` | Global scan limit |
| `RATE_LIMIT_SCAN` | `5` | Scan submissions per minute |

## API Documentation

When `APP_ENV=development`, Swagger UI is available at:
- `http://localhost:8000/api/docs`
- `http://localhost:8000/api/redoc`

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | No | Login |
| POST | `/api/auth/logout` | Yes | Logout |
| GET | `/api/auth/me` | Yes | Current user |
| GET | `/api/dashboard` | Yes | User dashboard stats |
| POST | `/api/scan` | Yes | Submit scan target |
| GET | `/api/scan` | Yes | List user's scans |
| GET | `/api/scan/:id` | Yes | Scan details |
| POST | `/api/scan/:id/stop` | Yes | Stop scan |
| GET | `/api/scan/:id/findings` | Yes | List findings |
| GET | `/api/scan/:id/export` | Yes | Export findings |
| POST | `/api/findings/:id/mark` | Yes | Mark finding status |
| GET | `/api/admin/users` | Admin | List users |
| POST | `/api/admin/users` | Admin | Create user |
| PUT | `/api/admin/users/:id` | Admin | Update user |
| DELETE | `/api/admin/users/:id` | Admin | Delete user |
| GET | `/api/admin/logs` | Admin | Audit logs |
| GET | `/api/admin/jobs` | Admin | All scan jobs |
| GET | `/api/admin/dashboard` | Admin | Admin stats |

## Installing Nuclei

```bash
# Go install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or download binary from:
# https://github.com/projectdiscovery/nuclei/releases

# Update templates
nuclei -update-templates
```

## Security Notes

- All passwords are hashed with bcrypt
- Sessions stored in database with expiry
- Secure cookies (httponly, samesite=strict, secure in production)
- SSRF protection: blocks private IP ranges and cloud metadata
- Rate limiting on scan submissions
- Security headers (X-Content-Type-Options, X-Frame-Options, etc.)
- Audit logging for all critical actions

## Backup

### Database
```bash
# SQLite
cp backend/scanner.db backup/scanner-$(date +%Y%m%d).db

# PostgreSQL
pg_dump scanner_db > backup/scanner-$(date +%Y%m%d).sql
```

### Scan Outputs
```bash
cp -r /tmp/scanner-outputs/ backup/scan-outputs-$(date +%Y%m%d)/
```

## License

MIT
