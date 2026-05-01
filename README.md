# RepoRadar

![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Platform](https://img.shields.io/badge/platform-GitHub%20API-black?logo=github)

**GitHub Repository Security Scanner** — scans public repositories for exposed secrets, dangerous CI/CD misconfigurations, and sensitive files.

Built for authorized security assessments and educational research.

---

## Features

| Module | What it detects |
|---|---|
| **Secret Scanning** | 30+ patterns: AWS keys, GitHub tokens, Stripe, Slack, Discord, JWTs, private keys, database URLs, and more |
| **CI/CD Auditing** | GitHub Actions misconfigs: script injection, pull_request_target abuse, unpinned actions, hardcoded credentials |
| **Sensitive Files** | Detects `.env`, private keys, kubeconfigs, Terraform state files, and 25+ other dangerous paths tracked by git |
| **JSON Output** | Machine-readable reports for integration with dashboards or portfolio sites |

---

## Installation

```bash
git clone https://github.com/dmzpurge/reporadar.git
cd reporadar
pip install -r requirements.txt
cp .env.example .env
# Add your GitHub token to .env
```

---

## Usage

```bash
# Scan all public repos for a user
python scanner.py --user dmzpurge

# Scan a specific repository
python scanner.py --repo owner/reponame
python scanner.py --repo https://github.com/owner/repo

# Export findings as JSON
python scanner.py --user dmzpurge --json --output report.json

# Check your API rate limit
python scanner.py --rate-limit
```

---

## Configuration

Copy `.env.example` to `.env` and add your [GitHub Personal Access Token](https://github.com/settings/tokens):

```
GITHUB_TOKEN=your_token_here
```

Required scope: `public_repo` (read-only).

Without a token you get 60 API requests/hour. With a token: 5,000/hour.

---

## Output Example

```
◆ owner/repo  A web application project
 SEV        CATEGORY                  FINDING                                       FILE                LINE
 CRITICAL   Secret Exposure           Potential AWS Access Key detected             src/config.js       12
 HIGH       Sensitive File Exposed    Sensitive file tracked by git                 .env
 HIGH       CI/CD Misconfiguration   Pull request target (pwn-request risk)        .github/workflows/  3
 MEDIUM     CI/CD Misconfiguration   Floating action tag (main/master/latest)      .github/workflows/  14
```

---

## Detection Patterns

### Secrets (30+ patterns)
AWS, GitHub, Stripe, Google, Slack, Discord, SendGrid, Twilio, Mailgun, Heroku, Firebase, Square, PayPal, JWT, private keys (RSA/EC/DSA/SSH/PGP), database URLs (postgres, mysql, mongodb), and generic password/secret patterns.

### CI/CD Misconfigurations
Based on [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) and GitHub Security Lab research:
- Script injection via `github.event` context
- `pull_request_target` without proper conditions (pwn request)
- Floating action tags (`@main`, `@master`, `@latest`)
- `write-all` permissions
- Hardcoded credentials in workflow env blocks
- Self-hosted runners

---

## Limitations

- Scans **public** repositories only (by design)
- File content scanning is sampled (up to 150 files/repo, max 500KB each)
- Secret patterns use static regex — may produce false positives on test fixtures
- For deep binary or obfuscated secret detection, combine with [truffleHog](https://github.com/trufflesecurity/trufflehog)

---

## Legal

This tool is intended for **authorized security research and educational purposes only**.  
Only scan repositories you own or have explicit permission to test.  
The author assumes no liability for misuse.

---

## Author

**Sergio Rodriguez** — [@dmzpurge](https://github.com/dmzpurge)  
Student Developer | IONA '26 | Cisco Networking Academy
