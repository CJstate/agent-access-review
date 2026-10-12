# agent-access-review

[![Tests](https://github.com/Mihirajmera/agent-access-review/actions/workflows/tests.yml/badge.svg)](https://github.com/Mihirajmera/agent-access-review/actions/workflows/tests.yml)

**User access reviews for AI agents.** It finds every agent and MCP server an organization runs, works out what each one can read, write, execute and send, tests that access against 12 controls, and produces the packet an auditor expects: a reviewer sign-off sheet, hashed evidence, and OSCAL assessment results mapped to NIST 800-53, SOC 2, NIST AI RMF and the OWASP Top 10 for LLM Applications.

## Problem

Every SOX and SOC 2 program runs quarterly user access reviews: list who has access to what, have an owner confirm it's still needed, revoke the rest, keep the evidence. AI agents now hold the same kind of access (API tokens, database connections, shell access, mailboxes), and almost nobody reviews them:

- **No owner, no approval.** A developer adds an MCP server to their Claude Desktop or Cursor config and the agent instantly has their GitHub token and home directory. No ticket, no approver, and it never appears in an access review.
- **Over-broad by default.** Setup guides tell people to grant the whole home directory, the full-control `repo` scope, or tenant-wide `*.All` Microsoft Graph permissions.
- **Secrets in plain text.** MCP configs routinely hold raw tokens and database passwords.
- **A new attack path.** An agent that can read sensitive data, read content an attacker wrote (a GitHub issue, an email, a web page), and send data out can be prompt-injected into leaking that data. No traditional access control looks at that combination.

Agents are non-human identities. They need the same joiner/mover/leaver and recertification controls as people, plus a few that are specific to AI.

## What it checks

| ID | Control | Severity | Frameworks |
|----|---------|----------|------------|
| AAR-01 | Every agent has an accountable human owner | high | NIST 800-53 AC-2 · SOC 2 CC6.2 · AI RMF GOVERN 2.1 |
| AAR-02 | Access is approved and recertified within 90 days | high / medium | AC-2 · CC6.2, CC6.3 |
| AAR-03 | Privileged actions (write, delete, send) need human approval | high / medium | AC-6 · CC6.3 · AI RMF MAP 3.5 · OWASP LLM06 |
| AAR-04 | Least privilege: no home directories, wildcards, admin or tenant-wide scopes | high | AC-6 · CC6.3 · LLM06 |
| AAR-05 | Code and shell execution is sandboxed | high | CM-7, AC-6 · LLM05, LLM06 |
| AAR-06 | No hardcoded credentials | high | IA-5 · CC6.1 |
| AAR-07 | Credentials rotated within 90 days | medium / low | IA-5 · CC6.1 |
| AAR-08 | Dormant access removed after 90 days | medium / low | AC-2(3) · CC6.2 |
| AAR-09 | **No exfiltration path** (sensitive data + untrusted input + egress, with no human gate) | high | AC-4 · AI RMF MEASURE 2.7 · LLM01, LLM02 |
| AAR-10 | Tool packages pinned to a version or image digest | medium | SR-3 · LLM03 |
| AAR-11 | Remote MCP servers use HTTPS | high | SC-8 · CC6.7 |
| AAR-12 | Every tool's capabilities are inventoried | medium | CM-8 · AI RMF GOVERN 1.6 |

Each control is defined once in [`controls.yaml`](agent_access_review/controls.yaml) and cross-walked to every framework, so one test produces evidence for all of them. The mappings are my own judgment and should be checked against official crosswalks before being relied on in a real audit.

## How it works

```
MCP configs ─┐                                                     ┌─> access-review.md   reviewer packet + sign-off
             ├─> parsers ──> inventory ──> 12 checks ──> findings ─┼─> access-review.csv  UAR decision sheet
agents.yaml ─┘   (redact      (Agent,       (checks.py)            ├─> evidence/*.json    hashed, one per agent
                  secrets)     Grant)                              └─> oscal/assessment-results.json
```

1. **Discover.** Point it at files or folders. It reads two formats:
   - **MCP configs** (Claude Desktop, Cursor, VS Code `.vscode/mcp.json`): local `npx` / `uvx` / `docker` servers and remote HTTP servers. These carry no owner or approval, which is exactly why they're the shadow-AI problem.
   - **Agent manifests** ([`agents.yaml`](examples/agents.yaml)): a governed record for LangChain, CrewAI or custom agents, with owner, approval, tools, scopes, credentials and last-used dates.
2. **Classify.** An MCP config only says which server runs, not what it can do. The [capability catalog](agent_access_review/catalog.yaml) turns a server name into a grant: actions, data classification, whether it ingests untrusted content and whether it can send data out. Unknown servers are flagged (AAR-12), never assumed safe.
3. **Redact, then hash.** Secrets are masked during parsing, before anything is stored, so evidence can be shared with auditors. Each agent's inventory and redacted source record are hashed with SHA-256 over canonical JSON, so any later edit to the evidence is detectable.
4. **Review.** Every tool grant gets a recommended decision (**Keep / Modify / Revoke / Investigate**) and an empty column for the reviewer, the same shape as a user access review spreadsheet.
5. **Export.** OSCAL 1.1.2 assessment results: one observation per agent pointing at its evidence file and hash, and one finding per NIST 800-53 control objective.

## Sample run

The [`examples/`](examples) folder has a developer's Claude Desktop config, a VS Code MCP config and three governed agents:

```
$ python -m agent_access_review scan examples --as-of 2026-10-12
AGENT                        TOOLS  HIGH   MED   LOW
support-copilot                  2     0     0     0
finance-ops-agent                4     4     3     0
devops-agent                     2     6     1     1
claude-desktop-config            6    11     5     1
vscode-mcp                       2     5     1     3
```

Some of what it finds:

- **finance-ops-agent** reads vendor bills in NetSuite (restricted data), reads an inbox vendors can email (untrusted input) and can send email (egress), with no human approval. That's an **AAR-09 exfiltration path**: one crafted invoice email could get the agent to mail out vendor banking details. Its approval is also 216 days old, and its OCR tool hasn't been used in 164 days, so it's marked **Revoke**.
- **claude-desktop-config** gives an agent the whole `/Users/dev` home directory, an unsandboxed terminal, a GitHub token and a database password in plain text, and runs four unpinned packages.
- **support-copilot** passes every check: it writes to tickets, but a human approves before anything is sent.

Every CI run publishes the full packet on the [Actions summary page](https://github.com/Mihirajmera/agent-access-review/actions/workflows/tests.yml) and as a downloadable artifact.

## Run it

Requirements: Python 3.11+. No cloud account or API keys needed.

```bash
git clone https://github.com/Mihirajmera/agent-access-review.git
cd agent-access-review
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m agent_access_review scan examples           # writes review/
python -m agent_access_review scan ~/Library/Application\ Support/Claude/claude_desktop_config.json
pytest -q
```

Options: `--out DIR` (default `review/`), `--as-of YYYY-MM-DD` (date used for recertification, rotation and dormancy), `--fail-on high|medium|low` (exit 1 if a finding is at or above that severity).

### As a CI gate

Keep `agents.yaml` in the repo that deploys your agents, and block merges that introduce high-risk access:

```yaml
- run: pip install pyyaml && git clone --depth 1 https://github.com/Mihirajmera/agent-access-review /tmp/aar
- run: PYTHONPATH=/tmp/aar python -m agent_access_review scan agents.yaml --fail-on high
```

## Design decisions

- **Agents are identities, not apps.** The review is modeled on ITGC user access reviews (owner, approval, recertification, dormancy, credential hygiene) because that's the control framework auditors already test. AI-specific risks are added on top, not instead.
- **AAR-09 looks at combinations, not single permissions.** Each leg of an exfiltration path is harmless alone. The risk only appears when one agent holds all three, which is why traditional permission reviews miss it. A human approval step on the untrusted-input or egress leg breaks the chain.
- **Fail closed on unknown tools.** An unclassified MCP server is a finding, not a pass. The catalog is data, so a GRC team can extend it without touching code.
- **Redact before hashing.** Evidence that contains secrets can't be shared, and redacting afterwards would break the hash. Redaction happens in the parser.
- **Docker tags count as unpinned.** Only an image digest is immutable. `:v1.0` can be re-pushed.

## Limitations

- It reviews **configuration**, not runtime behavior. It sees that an agent *can* send email, not what it actually sent. Usage dates come from the manifest, which in production would be fed from tool-call logs.
- The capability catalog is **approximate**: it describes what a server can do by default, and a token's real scopes (for example, a fine-grained GitHub PAT) can be narrower. The manifest format lets you record exact scopes.
- JSON-with-comments configs are skipped with a warning.

## What I'd do at enterprise scale

- **Discover from endpoints, not files.** Collect MCP configs from managed laptops through MDM or EDR, and agent identities from the IdP (service principals, OAuth apps), so shadow agents surface automatically.
- **Feed usage from logs.** Populate `last_used` from MCP gateway or proxy logs so AAR-08 is evidence-based rather than self-reported.
- **Run the review in the GRC platform.** Push the decision sheet into ServiceNow GRC or SailPoint as a certification campaign with owners, due dates and escalation, and auto-revoke grants that aren't certified.
- **Close the loop.** Turn `not-satisfied` OSCAL findings into POA&M items with owners and due dates.

## License

MIT
