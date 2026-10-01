# Access-Governed RAG Console

An enterprise-style retrieval-augmented generation (RAG) assistant that enforces
role-based access control on the documents a large language model is allowed to
retrieve, and logs every access decision for audit.

It is a working model of the security problem behind internal AI help-desk
tools. The assistant should only surface documents the signed-in user is
authorized to see, prompt-level attempts to talk around those boundaries should
fail, and every decision should be reviewable after the fact.

> **Core principle:** access control is enforced at the **retrieval layer,
> before the language model ever sees a document**. A restricted document is
> removed from the candidate set for an unauthorized user *before scoring runs*,
> so it cannot leak through the model regardless of how a query is phrased.

---

## Table of contents

- [Scenario](#scenario)
- [Architecture at a glance](#architecture-at-a-glance)
- [Security model](#security-model)
- [Screenshots](#screenshots)
- [Authentication: two paths](#authentication-two-paths)
- [Prompt injection defense](#prompt-injection-defense)
- [Audit trail](#audit-trail)
- [Running it locally](#running-it-locally)
- [Testing](#testing)
- [Bugs found and fixed during development](#bugs-found-and-fixed-during-development)
- [Gaps](#gaps-what-a-production-version-would-still-need)
- [Project layout](#project-layout)

---

## Scenario

The project models a corporate IT help-desk assistant. Some documents are
general (Wi-Fi setup, password reset, VPN config); others are restricted
(firewall rules, the privileged-account registry). A Help Desk user should be
able to ask about the general documents, and only an IT Admin should be able to
retrieve the restricted ones. The assistant enforces that difference itself,
on the server, where the client can't bypass it.

---

## Architecture at a glance

```
                    Browser (thin UI -- no secrets, no access logic)
                                     |
                                     v
        +-------------------------------------------------------+
        |                  Flask backend (app.py)                |
        |                                                        |
        |  1. Auth        -> session role from Entra claim OR    |
        |                    demo login (never from client)      |
        |  2. Injection   -> pre-flight scanner (layer 1)        |
        |     scan                                               |
        |  3. Retrieval   -> RBAC filter BEFORE scoring          |
        |                    (restricted docs removed from the   |
        |                     candidate set for non-admins)      |
        |  4. Generation  -> Claude via Anthropic API,           |
        |                    backend-only, grounded in context   |
        |  5. Audit       -> every decision logged with          |
        |                    user, role, auth method, outcome    |
        +-------------------------------------------------------+
                                     |
                    Identity: Microsoft Entra ID (OAuth2)
                    Generation: Claude (claude-sonnet-4-6)
```

Everything security-relevant runs server-side. The browser only renders what
the backend sends it. It holds no corpus data, no access-control logic, and no
API key.

---

## Security model

| Concern | How it's handled |
|---|---|
| Where role comes from | Server-side session, set from an authenticated Entra app-role claim or the demo login, never from client input |
| Where access is enforced | At retrieval, before scoring. Restricted docs are excluded from the candidate set instead of being filtered from the response afterward |
| Where the LLM runs | Backend only; the API key lives in a server environment variable and is never reachable from the browser |
| Where secrets live | Environment variables only; no secret is committed to the repo |
| Injection resistance | Pre-flight pattern scanner (layer 1) + RBAC as the backstop (layer 2); verified by a test battery |
| Auditability | Append-only log capturing every decision, including which auth method was used |

---

## Screenshots

**Sign-in.** Two ways in: Microsoft Entra ID single sign-on, or a zero-setup
demo login. Role is assigned server-side on authentication; there is no role
selector in the browser.

![Login screen](screenshots/01_login_screen.png)

**Help Desk view.** The restricted documents appear in the corpus panel greyed
out and labelled "not retrievable as current role." The backend will not return
their contents to this role.

![Help Desk console view](screenshots/02_console_helpdesk_view.png)

**Help Desk asks for restricted content and is denied.** The restricted document
was never in this user's retrieval candidate set, so nothing leaks. The audit
log records `access-denied`.

![Help Desk access denied](screenshots/03_helpdesk_access_denied.png)

**Out-of-scope query.** When no document in the corpus covers the question, the
assistant says so and points the user to a human instead of fabricating an
answer.

![Help Desk no match](screenshots/04_helpdesk_no_match.png)

**Admin view.** Signed in as an IT Admin, the restricted documents are no longer
greyed out.

![Admin console view](screenshots/05_console_admin_view.png)

**Admin asks the same restricted query.** The query that was denied for Help
Desk is answered for Admin, grounded in the retrieved restricted document. The
backend session alone decides the outcome in both directions.

![Admin restricted query answered](screenshots/06_admin_restricted_query_result.png)

**Audit log.** The same query text produces `DENIED` for Help Desk and
`ANSWERED` for Admin, each with its identity and matched documents.

![Audit log both roles](screenshots/07_audit_log_both_roles.png)

---

## Authentication: two paths

The project supports two sign-in methods, and role always lands in the same
server-side session. RBAC, retrieval, audit and injection scanning behave
identically regardless of how the user signed in.

**Microsoft Entra ID (production-style):** a full OAuth2 authorization-code flow
via MSAL. The user's role comes from an Entra **app-role claim** defined in the
App Registration and assigned to users in the Enterprise Application. The claim
is mapped to the internal RBAC model on the server.

In the screenshot below, an Admin signed in through Microsoft Entra ID asks the
restricted query. The header shows the Entra identity, the answer is grounded
in the restricted document, and the audit log records the Entra account plus
the auth method.

![Entra admin restricted query answered](screenshots/10_entra_admin_restricted_answered.png)

**Demo login (zero-setup):** a small hardcoded user table so the project runs
with no Azure tenant at all. Both roles are available instantly. If the Entra
environment variables are not set, the Microsoft button is hidden and the app
runs in demo-login-only mode, so anyone can clone and run it.

---

## Prompt injection defense

A pre-flight scanner inspects each query *before* it reaches retrieval or the
model, catching known instruction-override, role-escalation, prompt-extraction,
delimiter-injection, and jailbreak patterns. Blocked attempts are logged as
`injection-blocked` with the matched category, and the query never reaches the
model.

The scanner is only the first layer. A query crafted to slip past it is still
stopped by RBAC downstream, because a non-admin session has no restricted
documents in its retrieval candidate set.

![Injection attempts blocked](screenshots/08_injection_blocked.png)

The audit log captures each attempt verbatim with its category, so a SOC
analyst can review what was tried.

![Injection attempts in audit log](screenshots/09_injection_audit_log.png)

A 10-case test battery (`test_injection.py`) fires attack payloads as a
low-privilege user and checks both the scanner decision and whether any
restricted content appeared in the response. Six cases are designed to be
caught by the scanner. The other four are deliberately subtle enough to bypass
it, so the result measures the whole system and not only the scanner.
Result: **10/10 resisted, 0 leaked.**

---

## Audit trail

Every request is logged with:

- timestamp (UTC)
- user and role
- **auth method** (demo vs Entra)
- the query text
- matched document IDs
- the decision: `answered`, `access-denied`, `no-match`, or `injection-blocked`

The log is append-only. Denials and injection attempts are recorded as outcomes
in their own right, so the trail shows what was refused and why alongside what
was answered.

---

## Running it locally

```bash
pip install -r requirements.txt

# Required for real answer generation
export ANTHROPIC_API_KEY=sk-ant-...
# Any long random string; signs the session cookie
export FLASK_SECRET_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")

python3 app.py
```

Open `http://localhost:5000`.

**Demo accounts** (no Azure needed):

| Username | Password | Role | Access |
|---|---|---|---|
| `helpdesk_user` | `helpdesk123` | Help Desk | general documents only |
| `admin_user` | `admin123` | IT Admin | general + restricted documents |

Sign in as each and run the same restricted query to watch the access decision
flip. The backend session decides it; the UI has no say.

### Optional: Microsoft Entra ID sign-in

Set these environment variables (see `.env.example`) and the "Sign in with
Microsoft" button appears automatically:

```bash
export ENTRA_CLIENT_ID=...          # App Registration's Application (client) ID
export ENTRA_TENANT_ID=...          # Directory (tenant) ID
export ENTRA_CLIENT_SECRET=...      # client secret VALUE (not the Secret ID)
```

The Entra App Registration needs two app roles (`Admin`, `Helpdesk`) assigned
to users, and a redirect URI of `http://localhost:5000/auth/callback` for local
use.

---

## Testing

```bash
python3 test_logic.py       # 18 checks: auth, RBAC, retrieval, audit
python3 test_injection.py   # 10-case prompt injection battery (server must be running)
```

`test_logic.py` exercises the Flask app end to end: auth, session handling,
retrieval scoring, RBAC filtering, and audit persistence. It covers
unauthenticated rejection, bad credentials, server-side role assignment,
in-scope answering, the out-of-scope no-match case, the restricted-content
denial (and that no document IDs or content leak on denial), the same
restricted query succeeding for an admin, and the audit log persisting both the
denial and the later success for the identical query string.

---

## Bugs found and fixed during development

Testing surfaced two defects, both now fixed:

1. **Substring false-match in retrieval.** Scoring originally used substring
   containment, so the token `user` matched inside `username`, causing an
   unrelated document to co-match a password-reset query. Fixed with whole-word
   token matching; pinned by a regression check in `test_logic.py`.

2. **Model re-applying access judgment.** When an authorized admin retrieved a
   document labelled "RESTRICTED - IT ADMIN ONLY", the model initially refused
   to relay it, applying its own caution on top of access control the backend
   had already cleared. Fixed by making the system prompt state that anything in
   context has already passed a server-side authorization check.

---

## Gaps (what a production version would still need)

This models the security architecture; it is not a production system.

- Retrieval is **local keyword-overlap scoring**, not an embedding or semantic
  search index, so it will miss paraphrased queries a semantic search would
  catch. The whole-word-matching fix closes one failure mode of this approach,
  not the underlying limitation.
- The document corpus is **a small fixed set** defined in code instead of an
  indexed document store.
- Audit entries go to **an append-only JSON file on local disk**, not a SIEM or
  log-analytics workspace. There is no export, retention policy, or tamper
  protection.
- A production deployment would rely solely on the identity provider. The
  **demo user table** is a stand-in for setups where SSO isn't configured.
- RBAC is the backstop. **The injection scanner is a pattern-based first
  layer** that reduces load and catches obvious attempts, not a complete
  defense.

---

## Project layout

```
rag-console-server/
├── app.py                  # Flask backend: auth, RBAC, retrieval, generation, audit, injection scan
├── templates/
│   └── index.html          # Single-page UI
├── static/
│   ├── app.js              # Thin UI layer -- no access logic, no secrets
│   └── style.css
├── test_logic.py           # 18-check end-to-end test suite
├── test_injection.py       # 10-case prompt injection battery
├── capture_screenshots.py  # Regenerates the screenshot set via Playwright
├── requirements.txt
├── .env.example            # Documents every environment variable
└── screenshots/            # Walkthrough images used in this README
```
