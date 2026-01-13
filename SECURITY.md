# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in py-cap, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Email the maintainers directly or use [GitHub's private vulnerability reporting](https://github.com/CaptainDriftwood/py-cap/security/advisories/new)
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Within 30 days (depending on complexity)

## Security Best Practices

When using py-cap:

- Always use TLS/SSL when connecting to ICAP servers over untrusted networks
- Validate and sanitize any user-provided input before passing to ICAP methods
- Keep py-cap and its dependencies up to date
- Review ICAP server configurations for security hardening