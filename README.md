# AD Web Console

A self-hosted web-based administration console for **Microsoft Active Directory**, built with Node.js + Express and `ldapjs`. Manage users, groups, and OUs from any browser — no Windows tools required.

---

## Features

- **User management** — create, disable, unlock, reset passwords, move between OUs
- **Group management** — create groups, add/remove members, view membership trees
- **OU browsing** — navigate your directory structure visually
- **Audit logging** — every action is logged via Winston with timestamps and actor identity
- **AD authentication** — login via your existing AD credentials
- **Local fallback admin** — survive AD outages with a local emergency admin account
- **Group-based access control** — restrict console access to specific AD groups
- **Email alerts** — nodemailer-powered notifications on critical events
- **Scheduled tasks** — node-cron jobs for recurring AD hygiene tasks
- **HTTPS support** — optional TLS termination built in
- **Rate limiting + security headers** — `express-rate-limit` + `helmet` out of the box

---

## Prerequisites

| Requirement | Version |
|---|---|
| Node.js | 18 LTS or higher |
| npm | 9+ |
| Active Directory / LDAP | Windows Server 2012 R2+ or Samba 4 |
| Network access | Console server must reach AD on port 389 (LDAP) or 636 (LDAPS) |

A **read/write service account** in AD is required. Minimum permissions needed:

- Read all user/group/OU attributes in the managed scope
- Reset passwords (if using password reset feature)
- Write `member` attribute on groups (if using group management)
- Create/delete objects in target OUs (if using user creation/deletion)

> **Security tip**: create a dedicated service account (`svc-adwebconsole`), put it in a tightly scoped OU, and grant only the permissions above via AD Delegation of Control — not Domain Admin.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/gpavankumar0510/AD-WEB-CONSOLE.git
cd AD-WEB-CONSOLE
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment

```bash
cp .env.example .env
```

Open `.env` and fill in all required values (see [Configuration](#configuration) below).

> **Important**: generate a strong random SESSION_SECRET before starting. Example:
> ```bash
> node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
> ```

### 4. Start the server

**Development:**
```bash
npm run dev
```

**Production:**
```bash
npm start
```

**Windows (PowerShell installer):**
```powershell
.\install.ps1
```

The console will be available at `http://localhost:3000` (or your configured port).

---

## Configuration

All configuration is via the `.env` file. Copy `.env.example` to `.env` and set the following:

### Active Directory connection

| Variable | Required | Description |
|---|---|---|
| `AD_HOST` | ✅ | LDAP URL, e.g. `ldaps://dc01.corp.local` (use `ldaps://` in production) |
| `AD_PORT` | ✅ | `389` for LDAP, `636` for LDAPS |
| `AD_BASE_DN` | ✅ | Base DN to search, e.g. `DC=corp,DC=local` |
| `AD_USERNAME` | ✅ | Service account UPN, e.g. `svc-adwebconsole@corp.local` |
| `AD_PASSWORD` | ✅ | Service account password |
| `AD_DOMAIN` | ✅ | Domain name for user login, e.g. `corp.local` |

### Access control

| Variable | Required | Description |
|---|---|---|
| `ADMIN_AD_GROUPS` | ✅ | Comma-separated AD group names whose members can access the console |

### Local fallback admin

| Variable | Required | Description |
|---|---|---|
| `LOCAL_ADMIN_USERNAME` | ✅ | Local admin username (used when AD is unreachable) |
| `LOCAL_ADMIN_PASSWORD` | ✅ | **Change this immediately.** Use a strong unique password |

### Session & security

| Variable | Required | Description |
|---|---|---|
| `SESSION_SECRET` | ✅ | 64+ character random string. Generate with `crypto.randomBytes(64)` |
| `SESSION_MAX_AGE_HOURS` | ❌ | Session lifetime in hours (default: 8) |

### Application

| Variable | Required | Description |
|---|---|---|
| `PORT` | ❌ | HTTP port (default: 3000) |
| `NODE_ENV` | ❌ | `production` or `development` |
| `HTTPS_ENABLED` | ❌ | `true` to enable built-in TLS |
| `HTTPS_CERT_PATH` | if HTTPS | Path to TLS certificate file |
| `HTTPS_KEY_PATH` | if HTTPS | Path to TLS private key file |

### Email alerts

| Variable | Required | Description |
|---|---|---|
| `SMTP_HOST` | ❌ | SMTP server hostname |
| `SMTP_PORT` | ❌ | SMTP port (default: 587) |
| `SMTP_USER` | ❌ | SMTP username |
| `SMTP_PASS` | ❌ | SMTP password |
| `ALERT_EMAIL_TO` | ❌ | Recipient for alert emails |

---

## Security hardening checklist

Before going to production, verify the following:

- [ ] `AD_HOST` uses `ldaps://` (port 636), not plain `ldap://` (port 389)
- [ ] `SESSION_SECRET` is at least 64 random characters, not the example value
- [ ] `LOCAL_ADMIN_PASSWORD` has been changed from the example value
- [ ] The server is behind a reverse proxy (nginx/IIS) with TLS
- [ ] `.env` is in `.gitignore` and **never committed to git**
- [ ] The AD service account has minimum required permissions (not Domain Admin)
- [ ] `NODE_ENV=production` is set in the environment
- [ ] Firewall restricts access to the console port to authorised source IPs only

---

## Project structure

```
AD-WEB-CONSOLE/
├── server.js              # Express app entry point
├── routes/                # Route handlers (auth, users, groups, OUs)
├── views/                 # EJS templates
├── public/                # Static assets (CSS, JS, images)
├── middleware/            # Auth, CSRF, rate-limit middleware
├── utils/                 # LDAP helpers, email, logging
├── logs/                  # Winston log output (gitignored)
├── .env.example           # Environment template
├── .gitignore
├── package.json
└── install.ps1            # Windows installer script
```

---

## Audit logs

All admin actions (logins, password resets, user creation/deletion, group changes) are written to `logs/audit.log` in JSON format:

```json
{
  "timestamp": "2025-10-15T09:23:11.042Z",
  "level": "info",
  "actor": "john.doe@corp.local",
  "action": "PASSWORD_RESET",
  "target": "jane.smith@corp.local",
  "ip": "10.0.1.45"
}
```

Log rotation is handled automatically. Do not delete the `logs/` directory.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add: my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

Please run `npm audit` and ensure no high/critical vulnerabilities before submitting.

---

## License

MIT — see [LICENSE](LICENSE) for details.
