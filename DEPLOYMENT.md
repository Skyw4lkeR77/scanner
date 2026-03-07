# Deployment Guide — OWASP TOP 10 ONLINE SCANNER

## Option 1: DirectAdmin (VPS)

### Prerequisites
- VPS with DirectAdmin installed
- Python 3.10+ installed
- Node.js 18+ installed
- Redis installed
- Domain pointed to your server

### Step 1: Create Domain in DirectAdmin

1. Login to DirectAdmin → **Domain Setup** → Add your domain (e.g., `scanner.example.com`)
2. Enable SSL via **SSL Certificates** → **Let's Encrypt**

### Step 2: Upload Files

```bash
# SSH into your server
ssh user@your-server

# Navigate to the domain directory
cd /home/user/domains/scanner.example.com/public_html

# Clone or upload project files
# Option A: Git clone
git clone <your-repo-url> .

# Option B: Upload via SCP
scp -r ./sacnner/* user@your-server:/home/user/domains/scanner.example.com/public_html/
```

### Step 3: Setup Backend

```bash
cd /home/user/domains/scanner.example.com/public_html

# Create virtual environment
python3 -m venv backend/venv
source backend/venv/bin/activate

# Install dependencies
cd backend
pip install -r requirements.txt

# Configure environment
cd ..
cp .env.example .env
nano .env  # Edit with production settings
# Set: APP_ENV=production
# Set: SECRET_KEY=<generate-random-key>
# Set: DATABASE_URL=sqlite:///./scanner.db
# Set: ALLOWED_HOSTS=scanner.example.com

# Initialize DB and create admin
cd backend
python seed.py
```

### Step 4: Build Frontend

```bash
cd /home/user/domains/scanner.example.com/public_html/frontend
npm install
npm run build
```

### Step 5: Install Redis

```bash
# Ubuntu/Debian
sudo apt install redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

### Step 6: Install Nuclei

```bash
# Download latest release
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_*_linux_amd64.zip
unzip nuclei_*_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
nuclei -update-templates
```

### Step 7: Create Systemd Services

**Backend API service:**
```bash
sudo nano /etc/systemd/system/scanner-api.service
```

```ini
[Unit]
Description=OWASP Scanner API
After=network.target redis-server.service

[Service]
Type=simple
User=user
WorkingDirectory=/home/user/domains/scanner.example.com/public_html/backend
Environment="PATH=/home/user/domains/scanner.example.com/public_html/backend/venv/bin"
ExecStart=/home/user/domains/scanner.example.com/public_html/backend/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Worker service:**
```bash
sudo nano /etc/systemd/system/scanner-worker.service
```

```ini
[Unit]
Description=OWASP Scanner Worker
After=network.target redis-server.service

[Service]
Type=simple
User=user
WorkingDirectory=/home/user/domains/scanner.example.com/public_html/backend
Environment="PATH=/home/user/domains/scanner.example.com/public_html/backend/venv/bin"
ExecStart=/home/user/domains/scanner.example.com/public_html/backend/venv/bin/python worker.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable scanner-api scanner-worker
sudo systemctl start scanner-api scanner-worker
```

### Step 8: Configure Reverse Proxy (Apache/Nginx)

**For Apache** (DirectAdmin default), add to `.htaccess` or domain config:

```apache
# /home/user/domains/scanner.example.com/public_html/.htaccess
RewriteEngine On

# API proxy
RewriteCond %{REQUEST_URI} ^/api
RewriteRule ^(.*)$ http://127.0.0.1:8000/$1 [P,L]

# Serve frontend
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ /frontend/dist/index.html [L]
```

**For Nginx**, create server block:

```nginx
server {
    listen 443 ssl;
    server_name scanner.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    root /home/user/domains/scanner.example.com/public_html/frontend/dist;

    location /api {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

---

## Option 2: Docker Deployment

### Prerequisites
- Docker & Docker Compose installed

### Deploy

```bash
cd /path/to/project

# Configure
cp .env.example .env
nano .env  # Set production values

# Build and start
docker-compose up -d

# Create admin user
docker-compose exec app python seed.py
```

The app will be available at `http://localhost:8000`

### Useful Docker Commands

```bash
# View logs
docker-compose logs -f

# Restart
docker-compose restart

# Stop
docker-compose down

# Rebuild
docker-compose up -d --build
```

---

## Cron Jobs (Optional)

### Update Nuclei Templates

```bash
# Add to crontab (daily at 2am)
crontab -e
0 2 * * * /usr/local/bin/nuclei -update-templates >> /var/log/nuclei-update.log 2>&1
```

### Database Backup

```bash
# Daily backup at midnight
0 0 * * * cp /path/to/scanner.db /path/to/backups/scanner-$(date +\%Y\%m\%d).db
```

### Clean Old Scan Outputs

```bash
# Weekly cleanup of outputs older than 90 days
0 3 * * 0 find /tmp/scanner-outputs -mtime +90 -delete
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `Nuclei not found` | Install nuclei and set `NUCLEI_BIN` in .env |
| `Redis connection refused` | Start Redis: `sudo systemctl start redis-server` |
| `Permission denied` | Ensure nuclei has execute permission: `chmod +x /usr/local/bin/nuclei` |
| `502 Bad Gateway` | Check if backend is running: `systemctl status scanner-api` |
| `Scan stuck in queued` | Check worker: `systemctl status scanner-worker` |
