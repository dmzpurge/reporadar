# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

If you discover a security issue in RepoRadar itself (e.g., a pattern that causes
unsafe behavior, a dependency vulnerability, or unintended data exposure), please
**do not open a public GitHub issue**.

Instead, report it privately:

- Email: [your email or GitHub security advisory link]
- Or open a [GitHub Security Advisory](https://github.com/dmzpurge/reporadar/security/advisories/new)

I will acknowledge receipt within 48 hours and aim to resolve confirmed issues
within 14 days.

## Responsible Use

RepoRadar is designed for **authorized security research only**.

- Only scan repositories you own or have explicit written permission to test
- Do not use output from this tool to facilitate unauthorized access
- Comply with GitHub's Terms of Service and applicable laws

## False Positives

Secret detection uses regex patterns and may produce false positives, especially
on test fixtures, documentation, or example files. Always manually verify any
finding before acting on it.
