# Access-Governed RAG Console

An enterprise-style retrieval-augmented generation (RAG) assistant that enforces
role-based access control on the documents a large language model is allowed to
retrieve, and logs every access decision for audit.

It is a working model of the security problem behind internal AI help-desk
tools: making sure the assistant only surfaces documents the signed-in user is
actually authorized to see, that prompt-level attempts to talk around those
boundaries fail, and that every decision is reviewable after the fact.

> **Core principle:** access control is enforced at the **retrieval layer,
> before the language model ever sees a document** -- not by asking the model
> nicely to keep secrets. A restricted document is removed from the candidate
> set for an unauthorized user *before scoring runs*, so it cannot leak through
> the model regardless of how a query is phrased.

---

## Table of contents

- [Why this project exists](#why-this-project-exists)
- [Architecture at a glance](#architecture-at-a-glance)
- [Security model](#security-model)
- [Walkthrough with screenshots](#walkthrough-with-screenshots)
- [Authentication: two paths](#authentication-two-paths)
- [Prompt injection defense](#prompt-injection-defense)
- [Audit trail](#audit-trail)
- [Running it locally](#running-it-locally)
- [Testing](#testing)
- [Bugs found and fixed during development](#bugs-found-and-fixed-during-development)
- [Honest gaps](#honest-gaps-what-a-production-version-would-still-need)
- [Project layout](#project-layout)

---

## Why this project exists

Securing an AI application is a distinct problem from using AI as a security
tool. This project focuses on the former: making an LLM's access to internal
data respect the same boundaries a human employee would have, enforcing those
boundaries where they can't be bypassed from the client, defending against
prompt-level attempts to talk around them, and keeping every decision auditable.

The scenario is a corporate IT help-desk assistant. Some documents are general
(Wi-Fi setup, password reset, VPN config); some are restricted (firewall rules,
the privileged-account registry). A Help Desk user should be able to ask about
the general documents. Only an IT Admin should be able to retrieve the
restricted ones. The assistant must enforce that difference itself.

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
the backend decides to send it -- it holds no corpus data, no access-control
logic, and no API key.

---

## Security model

| Concern | How it's handled |
|---|---|
| Where role comes from | Server-side session, set from an authenticated Entra app-role claim or the demo login -- never from client input |
| Where access is enforced | At retrieval, before scoring -- restricted docs are excluded from the candidate set, not filtered from the response afterward |
| Where the LLM runs | Backend only; the API key lives in a server environment variable and is never reachable from the browser |
| Where secrets live | Environment variables only -- no secret is committed to the repo |
| Injection resistance | Pre-flight pattern scanner (layer 1) + RBAC as the backstop (layer 2); verified by a test battery |
| Auditability | Append-only log capturing every decision, including which auth method was used |

---

## Walkthrough with screenshots

### 1. Sign-in

Two ways in: real Microsoft Entra ID single sign-on, or a zero-setup demo
login. Role is assigned server-side on authentication -- it is not a client-side
selector.

![Login screen](screenshots/01_login_screen.png)

### 2. Help Desk view -- restricted documents are visible in the list but marked not retrievable

Signed in as a Help Desk user. The restricted documents appear in the corpus
panel greyed out and labelled "not retrievable as current role." The backend
will not return their contents to this role.

![Help Desk console view](screenshots/02_console_helpdesk_view.png)

### 3. Help Desk asks for restricted content -- access denied

The same restricted query that an admin can answer is denied here. The
restricted document was never in this user's retrieval candidate set, so
nothing leaks. The audit log records `access-denied`.

![Help Desk access denied](screenshots/03_helpdesk_access_denied.png)

### 4. Out-of-scope query -- the assistant declines instead of guessing

When no document in the corpus covers the question, the assistant says so and
points the user to a human, rather than fabricating an answer.

![Help Desk no match](screenshots/04_helpdesk_no_match.png)

### 5. Admin view -- the same documents are now retrievable

Signed in as an IT Admin, the restricted documents are no longer greyed out.

![Admin console view](screenshots/05_console_admin_view.png)

### 6. Admin asks the same restricted query -- answered, grounded in the document

The identical query that was denied for Help Desk is answered for Admin, with
the response grounded in the retrieved restricted document. This is the access
boundary working in both directions, enforced entirely by the backend session.

![Admin restricted query answered](screenshots/06_admin_restricted_query_result.png)

### 7. Audit log -- the same query, opposite outcomes by role

The audit trail shows the same query text producing `DENIED` for Help Desk and
`ANSWERED` for Admin, each with its identity and matched documents.

![Audit log both roles](screenshots/07_audit_log_both_roles.png)

---

## Authentication: two paths

The project supports two sign-in methods, and role always lands in the same
server-side session -- everything downstream (RBAC, retrieval, audit, injection
scanning) is identical regardless of how the user signed in.

**Microsoft Entra ID (production-style):** a full OAuth2 authorization-code flow
via MSAL. The user's role comes from an Entra **app-role claim** defined in the
App Registration and assigned to users in the Enterprise Application. The claim
is mapped to the internal RBAC model on the server.

Below: signed in through real Microsoft Entra ID as an Admin, asking the
restricted query. The header shows the Entra identity, the answer is grounded
in the restricted document, and the audit log records the real Entra account
plus the auth method.

![Entra admin restricted query answered](screenshots/10_entra_admin_restricted_answered.png)

**Demo login (zero-setup):** a small hardcoded user table so the project runs
with no Azure tenant at all. Both roles are available instantly. If the Entra
environment variables are not set, the Microsoft button is hidden automatically
and the app runs demo-login-only -- so anyone can clone and run it.

---

## Prompt injection defense

A pre-flight scanner inspects each query *before* it reaches retrieval or the
model, catching known instruction-override, role-escalation, prompt-extraction,
delimiter-injection, and jailbreak patterns. Blocked attempts are logged as
`injection-blocked` with the matched category -- and the query never reaches the
model.

Crucially, this is only the first layer. Anything crafted to slip past the
scanner is still caught by RBAC downstream, because a non-admin session simply
has no restricted documents in its retrieval candidate set.

![Injection attempts blocked](screenshots/08_injection_blocked.png)

The audit log captures each attempt verbatim, with its category -- useful for a
SOC analyst reviewing what was tried.

![Injection attempts in audit log](screenshots/09_injection_audit_log.png)

A 10-case test battery (`test_injection.py`) fires real attack payloads as a
low-privilege user and checks both the scanner decision and whether any
restricted content appeared in the response. Six cases are designed to be
caught by the scanner; four are deliberately subtle enough to bypass it, so the
result reflects the whole system's resistance rather than just the scanner's.
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

The log is append-only and captures denials and injection attempts as
first-class outcomes, not silent failures -- so the trail shows not just what
was answered, but what was refused and why.

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
flip -- decided entirely by the backend session, not the UI.

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
python3 test_logic.py       # 17 checks: auth, RBAC, retrieval, audit
python3 test_injection.py   # 10-case prompt injection battery (server must be running)
```

`test_logic.py` exercises the real Flask app end to end -- real auth, session
handling, retrieval scoring, RBAC filtering, and audit persistence. It covers
unauthenticated rejection, bad credentials, server-side role assignment,
in-scope answering, the out-of-scope no-match case, the restricted-content
denial (and that no document IDs or content leak on denial), the same
restricted query succeeding for an admin, and the audit log persisting both the
denial and the later success for the identical query string.

---

## Bugs found and fixed during development

Two real defects surfaced through testing and were fixed -- both worth noting
because they show the value of the test harness:

1. **Substring false-match in retrieval.** Scoring originally used substring
   containment, so the token `user` matched inside `username`, causing an
   unrelated document to co-match a password-reset query. Fixed with whole-word
   token matching; pinned by a regression check in `test_logic.py`.

2. **Model re-applying access judgment.** When an authorized admin retrieved a
   document labelled "RESTRICTED - IT ADMIN ONLY", the model initially refused
   to relay it -- applying its own caution on top of access control the backend
   had already cleared. Fixed by making the system prompt state that anything in
   context has already passed a server-side authorization check.

---

## Honest gaps (what a production version would still need)

This is a faithful working model of the security architecture, not a production
system, and it doesn't pretend to be:

- **Retrieval is local keyword-overlap scoring**, not a real embedding /
  semantic search index. It will miss paraphrased queries a semantic search
  would catch. The whole-word-matching fix closes one failure mode of this
  approach, not the underlying limitation.
- **The document corpus is a small fixed set** defined in code, not a real
  indexed document store.
- **The audit log is an append-only JSON file on local disk**, not a real SIEM
  or log-analytics workspace. No export, retention policy, or tamper protection.
- **The demo user table is a stand-in** for scenarios where full SSO isn't
  configured; a production deployment would rely solely on the identity
  provider.
- **The injection scanner is a pattern-based first layer**, not a complete
  defense. RBAC is the actual backstop; the scanner reduces load and catches
  obvious attempts.

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
├── test_logic.py           # 17-check end-to-end test suite
├── test_injection.py       # 10-case prompt injection battery
├── capture_screenshots.py  # Regenerates the screenshot set via Playwright
├── requirements.txt
├── .env.example            # Documents every environment variable
└── screenshots/            # Walkthrough images used in this README
```
