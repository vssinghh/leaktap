# Security Policy

## Supported Versions

Security fixes ship on the latest `0.4.x` release.

| Version | Supported |
| :--- | :--- |
| `0.4.x` | Yes |
| `< 0.4.0` | No (upgrade to `0.4.1+`) |

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities in `leaktap` itself (for example: command execution via untrusted workspace files during `scan`, file corruption or symlink traversal in `clean`, SSRF in `--inspect-mcp`, or secret exposure in masked outputs).

Report vulnerabilities privately through [GitHub Private Vulnerability Reporting](https://github.com/vssinghh/leaktap/security/advisories/new) with a minimal reproduction.

## Scope Notes

Before reporting a live-wrapping bypass, check [Limitations](README.md#limitations). `leaktap` runs in user space without `sudo`, custom root certificates, or kernel hooks, so hostile binaries that ignore `*_BASE_URL` environment variables or make direct encrypted connections to third-party servers are outside its enforcement boundary and require an OS sandbox (`bubblewrap`, `landlock`, `sandbox-exec`, or a container/VM).

Detection bypasses in `scan`, `--block-secrets`, or `--redact-secrets` for supported formats and cooperative CLIs are welcome either via private advisory or regular issues/PRs.
