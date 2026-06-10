# RiskPilot

RiskPilot is a Django-based SaaS platform designed for risk analysis, management, and mitigation. This repository contains the initial development environment setup using Python 3.13, Celery, PostgreSQL, Redis, ClamAV, and Nginx.

---

## Architecture Overview

The system consists of the following services configured in Docker Compose:

1. **Nginx**: Reverses proxies requests to Django and serves static/media files directly.
2. **Django Web (`web`)**: The core application server running Django 5.1.
3. **Migration Runner (`migration`)**: Runs database migrations automatically at startup and exits.
4. **PostgreSQL (`db`)**: Database backend (v17).
5. **Redis (`redis`)**: Cache backend and Celery message broker (v7).
6. **Celery Worker (`celery_worker`)**: Executes asynchronous background tasks.
7. **Celery Beat (`celery_beat`)**: Schedules periodic cron-like tasks.
8. **ClamAV Daemon (`clamav`)**: Antivirus daemon used for secure file scanning.

---

## Local Development (Outside Docker)

### Prerequisites
- Python 3.13
- PostgreSQL and Redis running locally (optional, if running entirely outside Docker)

### Step 1: Create & Activate Virtual Environment
```bash
# Create the virtual environment (if not already done)
py -3.13 -m venv .venv

# Activate on Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Activate on Unix/macOS
source .venv/bin/activate
```

### Step 2: Install Dependencies
```bash
pip install -r requirements/dev.txt
```

### Step 3: Configure Environment Variables
Copy `.env.example` to `.env` and adjust credentials as necessary:
```bash
copy .env.example .env
```

### Step 4: Run Django Commands
```bash
cd app
python manage.py check
```

---

## Docker Compose Development Environment

### Start the Stack
Build the development image once, then start the stack:
```bash
docker compose up --build -d
```

For normal Python/template/static app changes after that, do **not** rebuild. The app directory is bind-mounted into the containers, so Django and Celery see your local edits:
```bash
docker compose up -d
```

Rebuild only when you change `requirements/`, `docker/Dockerfile.dev`, or OS-level container dependencies:
```bash
docker compose build web
docker compose up -d
```

### Check Container Status & Health
All services contain embedded health checks. To monitor health:
```bash
docker compose ps
```

You can view real-time logs for all services:
```bash
docker compose logs -f
```

### Running Commands in Container
- **Run Migrations manually**: `docker compose run --rm web python manage.py migrate`
- **Create Superuser**: `docker compose run --rm web python manage.py createsuperuser`
- **Shell**: `docker compose run --rm web python manage.py shell`

---

## Production Deployment

A production configuration is defined in `docker-compose.prod.yml`. It runs with Gunicorn, disables host directory mounts (baking the code into the image), runs containers as a non-root system user, and locks down ports.

To build and run in production:
```bash
docker compose -f docker-compose.prod.yml up --build -d
```

---

## Service Health Checks

| Container | Health Check Method | Port (Host / Container) |
|---|---|---|
| **db** | `pg_isready` | `5432:5432` |
| **redis** | `redis-cli ping` | `6379:6379` |
| **clamav** | `clamdscan /dev/null` | `3310:3310` |
| **web** | `curl -f /health/` | `8000:8000` |
| **celery_worker** | `celery inspect ping` | N/A |
| **celery_beat** | Process status (`ps`) | N/A |
| **nginx** | configuration check + request test | `80:80` |
