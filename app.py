"""
RepoRadar Web — Flask wrapper around the CLI scanner.

Routes:
  GET  /            Landing page with scan form
  POST /scan        Run a scan, render results
  POST /capture     Email capture for full JSON download
  GET  /report      Download captured JSON report
  GET  /health      Health check for Railway
"""

import io
import json
import os
import secrets
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from scanner import GitHubAPI, build_json_output, parse_target, scan_repo

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

FREE_SCAN_LIMIT = 3
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


def get_session_scan_count() -> int:
    return session.get("scan_count", 0)


def increment_scan_count() -> None:
    session["scan_count"] = get_session_scan_count() + 1


def severity_summary(findings: list[dict]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


@app.route("/")
def index():
    return render_template(
        "index.html",
        scans_used=get_session_scan_count(),
        scan_limit=FREE_SCAN_LIMIT,
    )


@app.route("/scan", methods=["POST"])
def scan():
    target_input = (request.form.get("target") or "").strip()

    if not target_input:
        flash("Enter a GitHub repo URL or owner/repo string.", "error")
        return redirect(url_for("index"))

    if get_session_scan_count() >= FREE_SCAN_LIMIT:
        flash(
            f"You've used all {FREE_SCAN_LIMIT} free scans this session. "
            "Sign up for unlimited scans.",
            "limit",
        )
        return redirect(url_for("index"))

    owner, repo_name = parse_target(target_input)
    if not owner or not repo_name:
        flash(
            "Could not parse target. Use format: owner/repo or "
            "https://github.com/owner/repo",
            "error",
        )
        return redirect(url_for("index"))

    api = GitHubAPI(token=GITHUB_TOKEN)
    result = scan_repo(api, owner, repo_name)

    increment_scan_count()

    findings = result.get("findings", [])
    summary = severity_summary(findings)
    target = f"{owner}/{repo_name}"

    json_payload = build_json_output([result], target)
    session["last_report"] = json.dumps(json_payload)

    return render_template(
        "results.html",
        result=result,
        target=target,
        summary=summary,
        total_findings=len(findings),
        scanned_files=result.get("scanned_files", 0),
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        scans_used=get_session_scan_count(),
        scan_limit=FREE_SCAN_LIMIT,
        error=result.get("error"),
    )


@app.route("/capture", methods=["POST"])
def capture():
    """Save email to session for later marketing follow-up.
    In production, persist to a database or mailing list provider."""
    email = (request.form.get("email") or "").strip().lower()
    if "@" not in email or len(email) < 5:
        flash("Please enter a valid email.", "error")
        return redirect(request.referrer or url_for("index"))

    captured = session.get("captured_emails", [])
    if email not in captured:
        captured.append(email)
    session["captured_emails"] = captured

    # Persist to a local file for MVP — replace with Mailchimp/ConvertKit API later
    try:
        with open("captured_emails.txt", "a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now().isoformat()}\t{email}\n")
    except OSError:
        pass

    flash("Thanks! Your full JSON report is ready below.", "success")
    return redirect(url_for("report"))


@app.route("/report")
def report():
    raw = session.get("last_report")
    if not raw:
        flash("No recent report found. Run a scan first.", "error")
        return redirect(url_for("index"))

    if not session.get("captured_emails"):
        return redirect(url_for("index"))

    buf = io.BytesIO(raw.encode("utf-8"))
    return send_file(
        buf,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"reporadar_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
    )


@app.route("/about")
def about():
    return render_template("index.html",
                           scans_used=get_session_scan_count(),
                           scan_limit=FREE_SCAN_LIMIT,
                           show_about=True)


@app.route("/health")
def health():
    return Response("ok", mimetype="text/plain")


@app.errorhandler(404)
def not_found(_):
    return redirect(url_for("index"))


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
