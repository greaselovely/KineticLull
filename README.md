<!-- README.md -->
# KineticLull

## Overview

KineticLull (http://kineticlull.com) is a web application for managing and deploying External Dynamic Lists (EDLs) used in network security and firewall policy management. It provides a user-friendly interface for creating, managing, and deploying EDLs without requiring direct firewall access. Inspired by Palo Alto Networks' MineMeld, but simpler and self-hosted.

> **Warning**: KineticLull is designed for internal/private network use only. Do not expose it directly to the internet. It uses self-signed certificates and is not hardened for public-facing deployment.

## Key Features

- **EDL Management**: Create, edit, clone, and delete EDLs through a clean web interface. Per-EDL ACLs restrict which IPs/networks can retrieve list contents.
- **Group-Scoped Security**: EDLs are scoped to user groups. Users only see EDLs belonging to their groups. Superusers see everything.
- **Favorites**: Star EDLs for quick access from the home page.
- **URL Shortener**: Built-in URL shortening with per-user URLs, hit tracking, and notes. Short URLs use branded `.kl` codes and redirect via `/s/<code>/`.
- **One-Time File Sharing**: Secure file sharing with OTP email verification via Resend. Files are automatically deleted after download or expiration. Configurable expiration (1 hour to 7 days), configurable size limit, and brandable download pages with custom colors, logo, and name.
- **Auto-Block (multi-layered)**:
  - **Rate-based burst window** (e.g., 50 hits in 60s) for noisy scanners.
  - **Cumulative window** (e.g., 30 hits in 24h) for paced scanners that pace probes to evade the burst rule.
  - **Pattern-based instant block** for known exploit paths (`.env`, `.git/config`, `wp-admin`, `phpmyadmin`, `/etc/passwd`, ~40 patterns total). One hit on a scanner path blocks the source IP immediately. Operators can extend the list with custom patterns from Settings without a code change; the built-in list is shown in a collapsible reference panel.
  - **IPv4 /24 aggregation** (opt-in): when the configured number of auto-blocked /32 addresses pile up in the same /24, they collapse into a single CIDR block. Skipped automatically when any whitelisted IP lives in that /24.
  - **Failed-login block** with separate threshold + window.
  - **Configurable block duration**: leave bans permanent (default) or set an expiration so old auto-blocks self-purge.
  - All gated by a single master toggle. All honor the whitelist.
- **Whitelisted IPs**: Dedicated nav entry. Whitelist individual IPs or CIDR subnets to exclude them from any auto-block layer. Your current admin IP is detected and one-click whitelistable.
- **Backups (Local + Backblaze B2)**:
  - Daily local snapshots of EDLs, URLs, users, settings, OneTimeFile metadata, and `media/` to `backups/data/` with 30-day retention.
  - Optional offsite mirror to a Backblaze B2 bucket (single-shot for files ≤200MB, large-file API beyond that). Per-bucket application keys; credentials encrypted at rest.
  - Configurable daily backup time in your display timezone.
  - Manual "Backup Now" buttons for both destinations on the Settings page.
  - Restore from local snapshots OR from any version still in B2.
- **API Integration**: Submit new FQDNs and update/overwrite existing EDLs programmatically via API with Bearer token auth. API key access is gated by the `users.use_api_key` group permission.
- **Activity Logging**: All user and device actions logged to the database with a searchable log viewer for staff/admins. Tamper-evident chain hash. Configurable retention.
- **System Health**: Sidebar badge surfaces issues: stale code after a pull, missing sudoers, expiring SSL cert, B2 backup gone stale, nginx log unreadable. One-click fixes for the common ones.
- **Tabbed Settings**: General / Customization / Integrations / Security / Limits / Backups. Per-page sticky save.
- **Configurable robots.txt**: Edit the body served at `/robots.txt` directly from Settings → Customization. Default ships with a base64 easter egg.
- **In-App Upgrades**: Superusers can upgrade the application directly from the web UI: pulls latest code, installs dependencies, runs migrations, patches Nginx config, and restarts services. The page only reports success after polling a lightweight version endpoint and confirming that workers are actually serving the deployed code (end-to-end verification, not a "did the service come back?" guess). Includes a dedicated Restart Services button that fires the same restart helper. Warns if system permissions need updating.
- **User Management**: Create, edit, and delete users. Self-service "My Account" entry for any logged-in user (change password, manage own API key when permitted). Deleting a user reassigns their EDLs and URLs to the next oldest account.
- **Toast Notifications**: Success/error/info messages appear as Bootstrap toasts that don't shift page layout.
- **Timezone Setup**: First-login prompt for superusers to configure display timezone.
- **Backup and Export**: Download EDL contents as text files.

## Supported Platforms

- Ubuntu Desktop and Server 20, 22, 24
- Fedora Workstation and Server 39+

## Fresh Install

### Prerequisites

Python 3.13 is required. `setup.sh` will install it for you (deadsnakes PPA on Debian/Ubuntu, system package manager on RHEL/Fedora) along with the matching `python3.13-venv` package, so you can usually skip ahead to Setup.

### Setup

```bash
git clone https://github.com/greaselovely/KineticLull.git
cd KineticLull
bash setup.sh
```

The setup script handles Python 3.13 install (if missing), virtual environment creation, dependency installation, database setup, Nginx + Gunicorn configuration, and systemd service creation. It will prompt for the IP or FQDN the application will be accessible at.

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

This will pull the latest code, install/update dependencies, run database migrations, collect static files, and restart the service. If the venv is on an older Python interpreter than 3.13, `upgrade.sh` will install Python 3.13, rebuild the venv from `requirements.txt`, and preserve the prior environment at `venv.old` for recovery. If you are running the legacy Gunicorn + direct SSL setup, `upgrade.sh` will offer to migrate to Nginx + Gunicorn (highly recommended).

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

## Security Advisories & Dependency Updates

Dependencies are scanned with [Snyk](https://snyk.io/). When a scan flags a vulnerable
package, the pin is bumped in `requirements.txt` (and the floor in `requirements.in`
where applicable) and the change ships in the next release. The web-UI **Upgrade** and
`upgrade.sh` both run `pip install -r requirements.txt`, so package fixes deploy together
with code - no separate step is required.

### 1.1.3.001 (2026-07-13)

**URL shortener - `mailto:` and `tel:` support** - shortened links can now point at
`mailto:` (and `tel:`) targets, not just web URLs. Django's `URLField`/`URLValidator`
hardcodes `scheme://` and rejects opaque-scheme URIs, so `ShortenedURL.original_url`
moved to a `CharField` with a custom `validate_short_link` validator (migration
`0046`).

- **Scheme allowlist** (`ALLOWED_LINK_SCHEMES`): `http, https, ftp, ftps, mailto, tel`
  - a strict allowlist, since a public redirector must never forward to `javascript:`,
  `data:`, or `file:`. Single source of truth, reused by the validator and the redirect.
- `mailto:` addresses are validated with Django's `EmailValidator` (supports comma-lists
  and `?subject=` params); `tel:` is accepted opaquely.
- `redirect_short_url` now uses a `ShortLinkRedirect` response subclass that widens
  `allowed_schemes` to match - plain `HttpResponseRedirect` raises `DisallowedRedirect`
  on `mailto:`/`tel:`.

### 1.1.3.000 (2026-07-13)

**Dependency security upgrades** - closes all 12 findings from the Snyk scan of
`requirements.txt` (0 vulnerable paths remaining after upgrade):

| Package | From | To | Highest severity | Findings closed (Snyk ID) |
| --- | --- | --- | --- | --- |
| `cryptography` | 46.0.7 | 48.0.1 | **High** | Out-of-bounds Read (17344551) |
| `django` | 5.2.14 | 5.2.16 | **Medium** | Improper Neutralization (17881426), Buffer Access with Incorrect Length (17881427), + 6 Low: case-sensitivity handling (17151726), cleartext transmission (17151727), signature verification (17151728), incomplete comparison (17151772), sensitive cache 17151780 / 17881428 |
| `idna` | 3.13 | 3.15 | Medium | ReDoS (16769942) |
| `urllib3` | 2.6.3 | 2.7.0 | **High** | Sensitive info in sent data (16642024), Decompression Bomb (16642059) |

Notes:
- `django` stays within the `>=5.2.x,<5.3` LTS line - a patch bump, no major-version jump.
- `cryptography` 46→48 is a larger jump but uses stable symmetric (`Fernet`) APIs; no
  application code change was required. Verify with `python manage.py check` and a
  One-Time Secret/File create+burn after upgrading.
- `idna` and `urllib3` are transitive (via `resend` → `requests`); their fixed floors are
  pinned in `requirements.in` so a future `pip-compile` cannot regress them.

**Application security hardening** (same release):
- **Trusted client-IP resolution**: `get_client_ip()` now trusts only the reverse proxy's
  `X-Real-IP` / the rightmost `X-Forwarded-For` token, ignoring spoofable client headers
  (`X-Client-IP`, `True-Client-IP`, `X-Originating-IP`, `X-Azure-*`, `X-Host`, and the
  leftmost XFF token). This closes an IP-spoofing vector used to evade auto-block and poison
  the blocklist (e.g. forging `127.0.0.1`).
- **Blocklist safety guard**: auto-block paths refuse any non-globally-routable address
  (loopback / RFC1918 / link-local / reserved), so loopback or private IPs can never enter
  the firewall drop-EDL.
- **`clean_spoofed_ips` management command**: one-time cleanup that removes previously
  recorded spoofed/non-routable entries from the blocklist, recovers the real attacker IP
  from the audit trail, and re-blocks it. The immutable activity-log chain is never modified.

## API Usage

All API endpoints require a Bearer token in the Authorization header. Generate an API key from **Admin → My Account** (your group must have the `Can use an API key` permission, which superusers always have).

Keys are stored as a SHA-256 hash, so the plaintext is displayed **once**, at generation. Copy it then; there is no way to recover it afterwards. The account page keeps showing the key's prefix, scopes, expiry, and last-used time so you can tell keys apart and spot dead integrations.

### Versioned API (`/api/v1/`)

The current API is served by Django Ninja at `/api/v1/`, with interactive documentation at `/api/v1/docs` (superusers only) and the OpenAPI schema at `/api/v1/openapi.json`.

| Endpoint | Method | Scope | Purpose |
|---|---|---|---|
| `/api/v1/edl/submit` | POST | `edl:write` | Queue FQDNs for review |
| `/api/v1/edl/update` | POST | `edl:write` | Append to or overwrite an EDL |
| `/api/v1/system/boot_version` | GET | none | Version this worker is running |

The `/api/submit_fqdn/` and `/api/update_edl/` paths below are **frozen** for compatibility with shipped GhostHunter builds and existing customer scripts. They run the same code as their `/api/v1/` equivalents and are not going away, but new integrations should target `/api/v1/`.

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
- Errors are always shaped `{"error": "..."}`, on both the legacy paths and `/api/v1/`. Request-validation failures on `/api/v1/` add a `detail` array with the full field-level breakdown.
- An `Authorization` header without the `Bearer ` prefix is accepted, since keys issued before `/api/v1/` were used that way.

## Firewalls

Register your firewalls once under **System → Firewalls**, and reuse them in two places
instead of retyping addresses and keeping credentials somewhere else again:

- **EDL access.** Name a firewall or a group in an EDL's ACL rather than pasting its
  address into every list.
- **User-ID push.** Mappings go to the firewalls you mark as targets, using the
  credentials stored on each one.

Firewalls can be collected into **groups**, so an EDL can be scoped to a whole site at
once and a group can be nominated to receive User-ID mappings.

### Management address vs fetch address

A firewall's management address is used both for the API and, by default, for EDL ACL
matching. Those are not always the same: a service route commonly sends EDL fetches out a
dataplane interface. When they differ, add the fetch addresses under **Additional Source
Addresses** on the firewall. Getting this wrong presents as an EDL problem rather than a
routing one, because the fetch is silently denied.

### EDL access control

An EDL is fetchable if **any** of these matches the requesting address:

| Grant | Notes |
|---|---|
| `*` on its own line in the address list | Allows anything |
| An address or CIDR in the address list | A bare address is one host: `/32` for IPv4, `/128` for IPv6 |
| A firewall named on the EDL | Matches its management address and any additional source addresses |
| A firewall in a group named on the EDL | |

Disabled firewalls satisfy nothing. A malformed ACL denies rather than erroring.

The System Blocklist EDL is auto-managed, but its access can now be scoped like any other
list; only its contents and name stay read-only.

## Palo Alto User-ID

KineticLull can attribute firewall traffic to usernames without standing up RADIUS and without asking end users to log in a second time.

Mappings go to every firewall marked **Receives User-ID mappings**, plus every firewall in the group nominated in Settings. Pushing to a single firewall and letting PAN-OS **Data Redistribution** fan out downstream is Palo Alto's own recommended pattern at scale; pushing to several directly works too. Each firewall is pushed independently, so one failing box never stops the others, and each carries its own last-push status.

A managed browser extension posts the signed-in identity to KineticLull on a heartbeat. **KineticLull records the source address it observes on that connection**, never an address the client claims, and keeps the user-to-IP mapping. A background thread batches mappings and pushes them to the firewall's User-ID XML API.

Configure it under **Settings → Integrations → Palo Alto User-ID**, then watch it under **System → User-ID**, which has Test Connection and Push Now buttons and shows the exact `curl` to reproduce a failed push by hand.

### How the sync behaves

- New and changed mappings ship on the next push pass (default every 30 seconds). Twenty students signing in at once produce **one** firewall request, not twenty, because everything that arrived in the interval goes out in a single `uid-message`.
- Mappings already on the firewall are re-sent every refresh interval (default 15 minutes), comfortably inside the mapping timeout (default 45 minutes), so entries never age out while a device is still online.
- A device that goes quiet past the stale window (default 30 minutes) is dropped rather than refreshed. It generates no traffic to attribute, and holding its entry open would leave a stale name on whatever picks up that address next.
- Check-ins from non-private addresses are rejected by default. A device taken home reports its home NAT address, and attaching a student's name to a public IP is both wrong and a privacy problem.

### Collector endpoints

The extension is a thin client: it fetches its own timing from the server on every check-in, so intervals can change without repackaging and redeploying to every device.

```bash
curl -k -X POST https://<kineticlull_url>/api/v1/userid/checkin \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer <api_key_scoped_userid:write>" \
    -d '{"username": "student@example.org", "device_id": "CB-1", "agent_version": "0.1.0"}'
```

```json
{"status": "ok", "enabled": true, "heartbeat_seconds": 600, "jitter_seconds": 120}
```

`GET /api/v1/userid/config` returns the same configuration block for a collector that has not checked in yet. Both require an API key carrying the `userid:write` scope.

Check-ins are deliberately **not** written to the activity log; only a new mapping or an address changing hands is recorded. Logging every heartbeat would bury the audit log and put a write amplification on the database for no information.

### Security note

The identity in the request body is self-asserted: the API key identifies the integration, not the person. Someone who extracts the key from a force-installed extension could claim a different username, but only ever for **their own** address, because the mapping is bound to the source IP the server observed. That trade is reasonable for attribution. It would not be reasonable if User-ID mappings later drive enforcement policy, at which point the identity should be a signed token verified server-side rather than a string in a request body.

Give the collector's key the `userid:write` scope and nothing else, so a leaked extension cannot touch EDLs.

## About EDLs

External Dynamic Lists (EDLs) allow dynamic firewall policy updates based on real-time list changes without manual firewall configuration. Firewalls poll the EDL URL on a schedule and apply the entries to security policy.

## Contributing

Contributions are welcome. Submit PRs at https://github.com/greaselovely/KineticLull.

## TL;DR

### Fresh install
```bash
git clone https://github.com/greaselovely/KineticLull.git
cd KineticLull
bash setup.sh
```

### Upgrade existing install
```bash
cd /path/to/KineticLull
bash upgrade.sh
```

## Companion Tools

Check out [GhostHunter](https://github.com/greaselovely/GhostHunter) for Firefox and Chrome, a browser extension for submitting domains to KineticLull.
