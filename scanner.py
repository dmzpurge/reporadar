#!/usr/bin/env python3
"""
RepoRadar - GitHub Repository Security Scanner
Scans public GitHub repositories for exposed secrets,
dangerous CI/CD patterns, and security misconfigurations.

Usage:
    python scanner.py --user dmzpurge
    python scanner.py --repo owner/reponame
    python scanner.py --repo https://github.com/owner/repo --json
    python scanner.py --user dmzpurge --json --output report.json
"""

import argparse
import base64
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich import box

load_dotenv()

console = Console()

BANNER = """
[bold cyan]
██████╗ ███████╗██████╗  ██████╗ ██████╗  █████╗ ██████╗  █████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗
██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝███████║██║  ██║███████║██████╔╝
██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗
██║  ██║███████╗██║     ╚██████╔╝██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
[/bold cyan][dim]  GitHub Repository Security Scanner  |  For authorized use only[/dim]
"""

# ─── Secret Detection Patterns ───────────────────────────────────────────────

SECRET_PATTERNS: dict[str, str] = {
    "AWS Access Key":               r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":               r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "GitHub Token (Classic)":       r"ghp_[A-Za-z0-9]{36}",
    "GitHub OAuth Token":           r"gho_[A-Za-z0-9]{36}",
    "GitHub Actions Token":         r"ghs_[A-Za-z0-9]{36}",
    "GitHub Fine-Grained PAT":      r"github_pat_[A-Za-z0-9_]{82}",
    "Stripe Secret Key":            r"sk_live_[A-Za-z0-9]{24}",
    "Stripe Publishable Key":       r"pk_live_[A-Za-z0-9]{24}",
    "Google API Key":               r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Client":          r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Slack Token":                  r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
    "Slack Webhook":                r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
    "Discord Token":                r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}",
    "Discord Webhook":              r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+",
    "Private RSA Key":              r"-----BEGIN RSA PRIVATE KEY-----",
    "Private EC Key":               r"-----BEGIN EC PRIVATE KEY-----",
    "Private DSA Key":              r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH Private Key":              r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP Private Key":              r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Heroku API Key":               r"[hH]eroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "SendGrid API Key":             r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
    "Twilio Auth Token":            r"SK[0-9a-fA-F]{32}",
    "Mailgun API Key":              r"key-[0-9a-zA-Z]{32}",
    "Firebase URL":                 r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Square Access Token":          r"sq0atp-[A-Za-z0-9\-_]{22}",
    "Square OAuth Secret":          r"sq0csp-[A-Za-z0-9\-_]{43}",
    "PayPal/Braintree Token":       r"access_token\$production\$[A-Za-z0-9]+\$[A-Za-z0-9]+",
    "JWT Token":                    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "Database URL (postgres)":      r"postgres(?:ql)?://[^:@\s]+:[^@\s]+@[^/\s]+",
    "Database URL (mysql)":         r"mysql://[^:@\s]+:[^@\s]+@[^/\s]+",
    "Database URL (mongodb)":       r"mongodb(?:\+srv)?://[^:@\s]+:[^@\s]+@[^/\s]+",
    "Basic Auth in URL":            r"https?://[A-Za-z0-9%]+:[A-Za-z0-9%]+@",
    "Generic Password":             r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "Generic Secret":               r"(?i)(?:secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
}

# ─── CI/CD Dangerous Patterns ────────────────────────────────────────────────

CICD_PATTERNS: dict[str, tuple[str, str]] = {
    # (pattern, severity)
    "Floating action tag (main/master/latest)":     (r"uses:\s+[^\s@]+@(?:main|master|latest)\b",                                                         "MEDIUM"),
    "Pull request target (pwn-request risk)":       (r"pull_request_target",                                                                               "HIGH"),
    "Script injection via event context":           (r"\$\{\{\s*github\.event\.(?:issue\.body|pull_request\.(?:body|title)|comment\.body)",                "CRITICAL"),
    "Head ref injection":                           (r"\$\{\{\s*github\.head_ref\s*\}\}",                                                                  "HIGH"),
    "Write-all permissions granted":                (r"permissions:\s*write-all",                                                                           "HIGH"),
    "Hardcoded credential in env block":            (r"(?i)(?:TOKEN|SECRET|KEY|PASSWORD|API_KEY)\s*:\s*['\"]?[A-Za-z0-9+/=_\-]{20,}['\"]?",              "CRITICAL"),
    "Self-hosted runner (lateral movement)":        (r"runs-on:\s+self-hosted",                                                                            "MEDIUM"),
    "Arbitrary code from PR body":                  (r"run:.*\$\{\{\s*github\.event\.pull_request",                                                        "CRITICAL"),
}

# ─── Sensitive File Paths ─────────────────────────────────────────────────────

SENSITIVE_FILES: list[str] = [
    ".env", ".env.local", ".env.production", ".env.backup", ".env.dev",
    ".env.staging", ".env.test",
    "config/secrets.yml", "config/database.yml", "config/credentials.yml",
    "config/secrets.json", "secrets.json", "credentials.json",
    ".aws/credentials", ".aws/config",
    "id_rsa", "id_ecdsa", "id_ed25519", ".ssh/id_rsa",
    "private.pem", "server.key", "private.key",
    "wp-config.php", "phpinfo.php", "web.config", ".htpasswd",
    "docker-compose.override.yml", "docker-compose.prod.yml",
    ".npmrc", ".pypirc", ".netrc",
    "terraform.tfvars", "terraform.tfvars.json",
    "*.tfstate", "*.tfstate.backup",
    "kubeconfig", ".kube/config",
    "shadow", "passwd",
]

# File extensions worth scanning for secrets
SCAN_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".php", ".go",
    ".java", ".cs", ".env", ".config", ".cfg", ".ini",
    ".yaml", ".yml", ".json", ".xml", ".sh", ".bash", ".zsh",
    ".tf", ".toml", ".properties", ".gradle", ".plist",
}

MAX_FILE_SIZE = 500_000   # 500 KB — skip binary/huge files
MAX_FILES_PER_REPO = 150  # avoid excessive API usage per repo


# ─── GitHub API Wrapper ───────────────────────────────────────────────────────

class GitHubAPI:
    BASE = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "RepoRadar-Scanner/1.0",
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def get(self, path: str, **kwargs) -> Optional[dict | list]:
        try:
            r = self.session.get(f"{self.BASE}{path}", timeout=15, **kwargs)
            if r.status_code == 404:
                return None
            if r.status_code == 401:
                console.print("[bold red][!] Bad credentials — check your token.[/]")
                sys.exit(1)
            if r.status_code == 403:
                reset = r.headers.get("X-RateLimit-Reset", "unknown")
                console.print(f"[bold yellow][!] Rate limited. Resets at epoch {reset}. Use a token to increase limits.[/]")
                return None
            r.raise_for_status()
            return r.json()
        except requests.Timeout:
            console.print(f"[yellow][!] Timeout on {path}[/]")
            return None
        except requests.RequestException as e:
            console.print(f"[red][-] API error on {path}: {e}[/]")
            return None

    def get_user_repos(self, username: str) -> list[dict]:
        repos = []
        page = 1
        while True:
            data = self.get(
                f"/users/{username}/repos",
                params={"per_page": 100, "page": page, "type": "public", "sort": "updated"},
            )
            if not data or not isinstance(data, list):
                break
            repos.extend(data)
            if len(data) < 100:
                break
            page += 1
        return repos

    def get_repo(self, owner: str, repo: str) -> Optional[dict]:
        return self.get(f"/repos/{owner}/{repo}")  # type: ignore

    def get_tree(self, owner: str, repo: str, branch: str) -> list[dict]:
        data = self.get(
            f"/repos/{owner}/{repo}/git/trees/{branch}",
            params={"recursive": "1"},
        )
        if not data or not isinstance(data, dict):
            return []
        return [item for item in data.get("tree", []) if item.get("type") == "blob"]

    def get_file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        data = self.get(f"/repos/{owner}/{repo}/contents/{path}")
        if not data or not isinstance(data, dict) or "content" not in data:
            return None
        if data.get("size", 0) > MAX_FILE_SIZE:
            return None
        try:
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            return None

    def check_rate_limit(self) -> dict:
        result = self.get("/rate_limit")
        return result if isinstance(result, dict) else {}


# ─── Finding Data Model ───────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    detail: str
    file: str = ""
    line: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ─── Scan Logic ───────────────────────────────────────────────────────────────

def scan_content_for_secrets(content: str, filepath: str) -> list[Finding]:
    findings = []
    lines = content.splitlines()
    for pattern_name, pattern in SECRET_PATTERNS.items():
        try:
            compiled = re.compile(pattern)
        except re.error:
            continue
        for i, line in enumerate(lines, 1):
            if compiled.search(line):
                findings.append(Finding(
                    severity="CRITICAL",
                    category="Secret Exposure",
                    title=f"Potential {pattern_name} detected",
                    detail=line.strip()[:120],
                    file=filepath,
                    line=str(i),
                ))
                break  # one finding per pattern per file to avoid noise
    return findings


def scan_cicd_workflow(content: str, filepath: str) -> list[Finding]:
    findings = []
    lines = content.splitlines()
    for danger_name, (pattern, severity) in CICD_PATTERNS.items():
        try:
            compiled = re.compile(pattern)
        except re.error:
            continue
        for i, line in enumerate(lines, 1):
            if compiled.search(line):
                findings.append(Finding(
                    severity=severity,
                    category="CI/CD Misconfiguration",
                    title=danger_name,
                    detail=line.strip()[:120],
                    file=filepath,
                    line=str(i),
                ))
                break
    return findings


def check_sensitive_files(file_paths: list[str]) -> list[Finding]:
    findings = []
    for sensitive in SENSITIVE_FILES:
        needle = sensitive.lstrip("*")
        matches = [p for p in file_paths if p == sensitive or p.endswith(needle)]
        for match in matches:
            findings.append(Finding(
                severity="HIGH",
                category="Sensitive File Exposed",
                title="Sensitive file tracked by git",
                detail=f"`{match}` is publicly visible in the repository",
                file=match,
            ))
    return findings


def scan_repo(api: GitHubAPI, owner: str, repo_name: str) -> dict:
    result: dict = {
        "repo": f"{owner}/{repo_name}",
        "url": f"https://github.com/{owner}/{repo_name}",
        "description": "",
        "stars": 0,
        "findings": [],
        "scanned_files": 0,
        "error": None,
    }

    repo_data = api.get_repo(owner, repo_name)
    if not repo_data:
        result["error"] = "Could not fetch repository metadata"
        return result

    result["description"] = repo_data.get("description") or ""
    result["stars"] = repo_data.get("stargazers_count", 0)
    default_branch = repo_data.get("default_branch", "main")

    tree = api.get_tree(owner, repo_name, default_branch)
    if not tree:
        result["error"] = "Could not fetch file tree (empty repo or API error)"
        return result

    file_paths = [item["path"] for item in tree]

    # 1 — Sensitive file name detection
    for f in check_sensitive_files(file_paths):
        result["findings"].append(f.to_dict())

    # 2 — CI/CD workflow scanning
    workflow_files = [
        p for p in file_paths
        if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))
    ]
    for wf_path in workflow_files:
        content = api.get_file_content(owner, repo_name, wf_path)
        if content:
            for f in scan_cicd_workflow(content, wf_path):
                result["findings"].append(f.to_dict())
            result["scanned_files"] += 1

    # 3 — Secret scanning in code files (sampled)
    scannable = [
        item for item in tree
        if any(item["path"].endswith(ext) for ext in SCAN_EXTENSIONS)
        and item.get("size", 0) < MAX_FILE_SIZE
    ][:MAX_FILES_PER_REPO]

    for item in scannable:
        content = api.get_file_content(owner, repo_name, item["path"])
        if content:
            for f in scan_content_for_secrets(content, item["path"]):
                result["findings"].append(f.to_dict())
            result["scanned_files"] += 1

    return result


# ─── Output & Reporting ───────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}


def render_report(all_results: list[dict], target: str) -> None:
    total_findings = sum(len(r["findings"]) for r in all_results)
    total_files    = sum(r.get("scanned_files", 0) for r in all_results)
    total_repos    = len(all_results)

    crit_count = sum(
        1 for r in all_results
        for f in r["findings"]
        if f["severity"] == "CRITICAL"
    )
    high_count = sum(
        1 for r in all_results
        for f in r["findings"]
        if f["severity"] == "HIGH"
    )

    summary_color = "bold red" if crit_count else ("red" if high_count else "green")

    console.print(Panel.fit(
        f"[bold]Target:[/]  [white]{target}[/]\n"
        f"[bold]Repos:[/]   [white]{total_repos}[/]  |  "
        f"[bold]Files scanned:[/] [white]{total_files}[/]\n"
        f"[bold]Findings:[/] [{summary_color}]{total_findings} total[/]  "
        f"([bold red]{crit_count} CRITICAL[/]  [red]{high_count} HIGH[/])\n"
        f"[dim]Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]",
        border_style="cyan",
        title="[bold cyan]RepoRadar  Results[/]",
    ))

    if not total_findings:
        console.print("\n[bold green][+] No findings detected. Repositories appear clean.[/]\n")
        return

    for repo_result in all_results:
        findings = repo_result.get("findings", [])
        console.print(
            f"\n[bold cyan]◆ {repo_result['repo']}[/]"
            + (f"  [dim]{repo_result['description']}[/]" if repo_result.get("description") else "")
        )

        if repo_result.get("error"):
            console.print(f"  [red][!] Error: {repo_result['error']}[/]")
            continue

        if not findings:
            console.print("  [green][+] Clean — no findings[/]")
            continue

        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold dim",
            expand=False,
            padding=(0, 1),
        )
        table.add_column("SEV",      width=10)
        table.add_column("CATEGORY", width=26)
        table.add_column("FINDING",  width=44)
        table.add_column("FILE",     width=34)
        table.add_column("LINE",     width=5)

        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))

        for f in sorted_findings:
            color = SEVERITY_COLOR.get(f["severity"], "white")
            file_display = f.get("file", "")
            if len(file_display) > 34:
                file_display = "…" + file_display[-33:]
            table.add_row(
                Text(f["severity"], style=color),
                Text(f["category"]),
                Text(f["title"][:44]),
                Text(file_display, style="dim"),
                Text(f.get("line", ""), style="dim"),
            )

        console.print(table)

        # Print detail snippet for CRITICAL findings
        critical = [f for f in sorted_findings if f["severity"] == "CRITICAL"]
        if critical:
            console.print("  [bold red][!] Critical details:[/]")
            for f in critical[:3]:
                console.print(f"      [dim]{f.get('file', '')}:{f.get('line', '')}[/]")
                console.print(f"      [red]→[/] {f['detail'][:110]}\n")


def build_json_output(all_results: list[dict], target: str) -> dict:
    return {
        "scan_target": target,
        "scan_time": datetime.now().isoformat(),
        "tool": "RepoRadar v1.0",
        "summary": {
            "repos_scanned": len(all_results),
            "total_findings": sum(len(r["findings"]) for r in all_results),
            "total_files_scanned": sum(r.get("scanned_files", 0) for r in all_results),
            "critical": sum(1 for r in all_results for f in r["findings"] if f["severity"] == "CRITICAL"),
            "high":     sum(1 for r in all_results for f in r["findings"] if f["severity"] == "HIGH"),
            "medium":   sum(1 for r in all_results for f in r["findings"] if f["severity"] == "MEDIUM"),
        },
        "results": all_results,
    }


# ─── Target Parsing ───────────────────────────────────────────────────────────

def parse_target(target: str) -> tuple[Optional[str], Optional[str]]:
    """Parse a GitHub URL, owner/repo string, or bare username."""
    if target.startswith("http"):
        parts = urlparse(target).path.strip("/").split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
        if len(parts) == 1:
            return parts[0], None
    if "/" in target:
        parts = target.split("/", 1)
        return parts[0], parts[1]
    return target, None


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="RepoRadar — GitHub Repository Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py --user dmzpurge
  python scanner.py --repo owner/reponame
  python scanner.py --repo https://github.com/owner/repo
  python scanner.py --user dmzpurge --json --output report.json
  python scanner.py --rate-limit
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--user",       "-u", metavar="USERNAME", help="Scan all public repos for a GitHub user")
    group.add_argument("--repo",       "-r", metavar="REPO",     help="Scan a specific repo (owner/repo or full URL)")
    group.add_argument("--rate-limit",        action="store_true",  help="Show current API rate limit status and exit")
    parser.add_argument("--json",      "-j", action="store_true",  help="Print JSON output to stdout")
    parser.add_argument("--output",    "-o", metavar="FILE",      help="Write JSON output to a file")
    parser.add_argument("--token",     "-t", metavar="TOKEN",     help="GitHub PAT (overrides GITHUB_TOKEN in .env)")
    args = parser.parse_args()

    console.print(BANNER)

    token = args.token or os.getenv("GITHUB_TOKEN")
    api = GitHubAPI(token=token)

    # ── Rate limit check ──
    if args.rate_limit:
        data = api.check_rate_limit()
        core = data.get("resources", {}).get("core", {})
        remaining = core.get("remaining", "?")
        limit = core.get("limit", "?")
        reset_ts = core.get("reset", 0)
        reset_str = datetime.fromtimestamp(reset_ts).strftime("%H:%M:%S") if reset_ts else "unknown"
        console.print(f"[cyan]Rate limit:[/] {remaining}/{limit} requests remaining")
        console.print(f"[cyan]Resets at: [/] {reset_str}")
        return

    if not token:
        console.print(
            "[yellow][!] No GitHub token found. Unauthenticated = 60 requests/hour limit.[/]\n"
            "[yellow]    Add GITHUB_TOKEN=your_token to your .env file for 5000 req/hr.[/]\n"
        )

    all_results: list[dict] = []
    target: str = ""

    # ── Scan a user's repos ──
    if args.user:
        target = args.user
        console.print(f"[cyan][*] Fetching public repos for user:[/] [bold]{target}[/]")
        repos = api.get_user_repos(target)
        if not repos:
            console.print("[red][-] No repositories found or user does not exist.[/]")
            sys.exit(1)
        console.print(f"[cyan][*] Found {len(repos)} repositories. Starting scan...[/]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(repos))
            for repo in repos:
                progress.update(task, description=f"[cyan]Scanning[/] {repo['name']}…")
                result = scan_repo(api, target, repo["name"])
                all_results.append(result)
                progress.advance(task)

    # ── Scan a specific repo ──
    elif args.repo:
        owner, repo_name = parse_target(args.repo)
        if not owner or not repo_name:
            console.print("[red][-] Could not parse repo. Use: owner/repo  or  https://github.com/owner/repo[/]")
            sys.exit(1)
        target = f"{owner}/{repo_name}"
        console.print(f"[cyan][*] Scanning repository:[/] [bold]{target}[/]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console,
        ) as progress:
            progress.add_task(f"Scanning {repo_name}…", total=None)
            result = scan_repo(api, owner, repo_name)
            all_results.append(result)

    # ── Output ──
    if args.json or args.output:
        output_data = build_json_output(all_results, target)
        json_str = json.dumps(output_data, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(json_str)
            console.print(f"\n[green][+] JSON report saved to:[/] {args.output}")
        if args.json:
            print(json_str)
    else:
        render_report(all_results, target)


if __name__ == "__main__":
    main()
