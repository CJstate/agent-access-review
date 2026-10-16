# Security policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Report them privately through GitHub: on this repository go to **Security → Report a vulnerability**. I'll acknowledge the report within 5 business days and agree a disclosure date with you once a fix is ready.

Useful things to include: the version or commit, the input file that triggers the problem (with real secrets removed), and what you expected to happen.

## Scope

This tool parses configuration files that may contain secrets and may come from untrusted sources. Especially relevant reports:

- A secret (token, password, connection-string credential) that survives redaction and appears in the Markdown report, CSV, evidence JSON or OSCAL output.
- A crafted MCP config or `agents.yaml` that causes code execution, writes outside the `--out` folder, or hangs the scanner.
- A way to change an evidence file without breaking its SHA-256 hash.

A finding the checks *should* raise but don't (for example, a risky MCP server missing from `catalog.yaml`) is a normal bug: please open an issue.

## Design notes

- Configs are only read, never executed. YAML is loaded with `yaml.safe_load`.
- Secrets are redacted during parsing, before anything is written or hashed.
- The tool makes no network calls.
