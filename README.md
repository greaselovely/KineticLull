<!-- README.md -->
# KineticLull

## Overview

KineticLull (http://kineticlull.com) is a web application for managing and deploying External Dynamic Lists (EDLs) used in network security and firewall policy management. It provides a user-friendly interface for creating, managing, and deploying EDLs without requiring direct firewall access. Inspired by Palo Alto Networks' MineMeld, but simpler and self-hosted.

> **Warning**: KineticLull is designed for internal/private network use only. Do not expose it directly to the internet. It uses self-signed certificates and is not hardened for public-facing deployment.

## Key Features

- **EDL Management**: Create, edit, clone, and delete EDLs through a clean web interface.
- **Access Control Lists (ACLs)**: Configurable per-EDL ACLs to restrict which IPs/networks can retrieve list contents.
- **Group-Scoped Security**: EDLs are scoped to user groups. Users only see EDLs belonging to their groups. Superusers see everything.
- **Favorites**: Star EDLs for quick access from the Favorites view.
- **API Integration**: Submit new FQDNs and update/overwrite existing EDLs programmatically via API with Bearer token auth.
- **Activity Logging**: All user and device actions logged to the database with a searchable log viewer for staff/admins.
- **In-App Upgrades**: Superusers can upgrade the application directly from the web UI — pulls latest code, installs dependencies, runs migrations, and reloads the app.
- **API Key Management**: Generate and manage API keys from the user profile.
- **Backup and Export**: Download EDL contents as text files.

## Supported Platforms

- Ubuntu Desktop and Server 20, 22, 24
- Fedora Workstation and Server 39+

## Fresh Install

### Prerequisites

Python 3.12 is required. We provide a helper script:

```bash
bash install_python.sh
```

### Setup

```bash
git clone https://github.com/greaselovely/KineticLull.git
cd KineticLull
bash setup.sh
```

The setup script handles virtual environment creation, dependency installation, database setup, Nginx + Gunicorn configuration, and systemd service creation. It will prompt for the IP or FQDN the application will be accessible at.

**Deployment architecture**: Fresh installs use Nginx for SSL termination, static file serving, security headers, and API rate limiting. Gunicorn runs behind Nginx on `127.0.0.1:8000`.

### Default Credentials

A default superuser account is created during setup:

- **Email**: support@kineticlull.com
- **Password**: Password!

**Change these immediately after first login.**

## Upgrading an Existing Install

### Option 1: Web UI (if already on a version with the Upgrade feature)

Log in as a superuser and click **Admin > Upgrade** in the sidebar.

### Option 2: Command line

```bash
cd /path/to/KineticLull
bash upgrade.sh
```

This will pull the latest code, install/update dependencies, run database migrations, collect static files, and restart the service. If you are running the legacy Gunicorn + direct SSL setup, `upgrade.sh` will offer to migrate to Nginx + Gunicorn (highly recommended).

### Option 2b: Web UI Migration Wizard

Superusers can also initiate the Nginx migration from **Admin > Deployment** in the sidebar. The wizard generates a migration script that you run with `sudo` on the server.

### Option 3: Manual

```bash
cd /path/to/KineticLull
git pull
source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate --noinput
python manage.py collectstatic --noinput
sudo systemctl restart kineticlull
```

## API Usage

All API endpoints require a Bearer token in the Authorization header. Generate an API key from your profile page.

### Submit FQDNs for Review

Creates a new inbox entry for admin review:

```bash
curl -k -X POST https://<kineticlull_url>/api/submit_fqdn/ \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer <your_api_key>" \
    -d '{"fqdn_list": ["example1.com", "example2.net", "example3.org"]}'
```

### Update an Existing EDL

Adds new entries to an existing EDL (duplicates are skipped):

```bash
curl -k -X POST https://<kineticlull_url>/api/update_edl/ \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer <your_api_key>" \
    -d '{"auto_url": "https://<kineticlull_url>/abc123def456.kl", "fqdn_list": ["example1.com", "example2.net"]}'
```

### Overwrite an Existing EDL

Replaces the entire EDL contents:

```bash
curl -k -X POST https://<kineticlull_url>/api/update_edl/ \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer <your_api_key>" \
    -d '{"auto_url": "https://<kineticlull_url>/abc123def456.kl", "command": "overwrite", "fqdn_list": ["example1.com", "example2.net"]}'
```

### API Notes

- Maximum 50 FQDNs per request.
- Protocol prefixes (`http://`, `https://`) are automatically stripped.
- When updating or overwriting, entries are annotated with timestamp and user. Palo Alto Networks firewalls ignore everything after the first space in EDL entries.

## About EDLs

External Dynamic Lists (EDLs) allow dynamic firewall policy updates based on real-time list changes without manual firewall configuration. Firewalls poll the EDL URL on a schedule and apply the entries to security policy.

## Contributing

Contributions are welcome. Submit PRs at https://github.com/greaselovely/KineticLull.

## TL;DR

### Fresh install
```bash
git clone https://github.com/greaselovely/KineticLull.git
cd KineticLull
bash install_python.sh
bash setup.sh
```

### Upgrade existing install
```bash
cd /path/to/KineticLull
bash upgrade.sh
```

## Companion Tools

Check out [GhostHunter](https://github.com/greaselovely/GhostHunter) for Firefox and Chrome — a browser extension for submitting domains to KineticLull.
