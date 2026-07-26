"""
Access-Governed RAG Console — server-side build.

Closes the biggest gap flagged in the browser-artifact version of this
project: role is now an authenticated server-side session, not a client-side
dropdown, and the LLM call happens from the backend (this process), never
from browser JavaScript. An API key can now live in a server environment
variable instead of being reachable from the client at all.

Authentication supports two paths:
  - Demo login: a hardcoded user table (zero-config, so anyone can clone the
    repo and run it without an Azure tenant). Documented stand-in.
  - Microsoft Entra ID: real OAuth2 authorization-code flow via MSAL, with the
    role taken from an Entra app-role claim. Only active when the ENTRA_*
    environment variables are set; otherwise the button is hidden and the app
    falls back to demo login only.

Either way, role lands in session["role"] and everything downstream (RBAC,
retrieval, audit logging, injection scanning) is identical -- it only reads
the session, not how the session was populated.

Still-honest gaps (see README.md "Honest gaps" section):
  - Audit log is a local JSON file, not a real SIEM / Log Analytics Workspace
  - Retrieval is still local keyword-overlap scoring, not Azure AI Search
"""
import os
import re
import json
import time
import uuid
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import urllib.request
import urllib.error

APP_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_LOG_PATH = os.path.join(APP_DIR, "data", "audit_log.json")
MAX_AUDIT_ENTRIES = 500

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

# ---------------------------------------------------------------------------
# Microsoft Entra ID (OAuth2) configuration.
#
# All three values come from environment variables -- the client secret is
# treated with the same discipline as the Anthropic API key and is never
# hardcoded. If any are missing, OR if the msal library isn't installed,
# Entra sign-in is silently disabled and the app runs demo-login-only. This
# keeps the repo runnable by anyone who clones it without an Azure tenant.
# ---------------------------------------------------------------------------
ENTRA_CLIENT_ID = os.environ.get("ENTRA_CLIENT_ID")
ENTRA_TENANT_ID = os.environ.get("ENTRA_TENANT_ID")
ENTRA_CLIENT_SECRET = os.environ.get("ENTRA_CLIENT_SECRET")
ENTRA_REDIRECT_URI = os.environ.get(
    "ENTRA_REDIRECT_URI", "http://localhost:5000/auth/callback"
)
ENTRA_AUTHORITY = (
    f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}"
    if ENTRA_TENANT_ID else None
)
# We only need the user's identity + app-role claim, so the OIDC scopes suffice.
ENTRA_SCOPES = []  # app roles arrive in the ID token; no Graph scopes needed

try:
    import msal
    _MSAL_AVAILABLE = True
except ImportError:
    _MSAL_AVAILABLE = False

ENTRA_ENABLED = bool(
    _MSAL_AVAILABLE
    and ENTRA_CLIENT_ID
    and ENTRA_TENANT_ID
    and ENTRA_CLIENT_SECRET
)

# Screenshot-only UI flag. When ENTRA_UI_DEMO=1, the frontend shows the
# "Sign in with Microsoft" button EVEN IF real Entra credentials aren't
# configured -- this exists solely so the automated screenshot script can
# capture the complete login UI without embedding real secrets in the repo.
# It does NOT enable the actual OAuth routes (/auth/login still 404s unless
# real credentials are present), so it can never be mistaken for, or provide,
# a working sign-in. It only affects what the login screen renders.
ENTRA_UI_DEMO = os.environ.get("ENTRA_UI_DEMO") == "1"

# Maps the Entra app-role claim value (defined in the App Registration) to the
# internal role string the rest of the app already uses. The left side must
# match the "Value" field of each app role in Azure exactly.
ENTRA_ROLE_MAP = {
    "Admin": "admin",
    "Helpdesk": "helpdesk",
}


def _build_msal_app():
    return msal.ConfidentialClientApplication(
        ENTRA_CLIENT_ID,
        authority=ENTRA_AUTHORITY,
        client_credential=ENTRA_CLIENT_SECRET,
    )

# ---------------------------------------------------------------------------
# Users. In production this table is replaced entirely by Entra ID / SSO —
# the app would never store or check passwords itself. This is a deliberate,
# documented stand-in, same spirit as the README's Azure substitution table.
# ---------------------------------------------------------------------------
USERS = {
    "helpdesk_user": {
        "password_hash": generate_password_hash("helpdesk123"),
        "role": "helpdesk",
        "display_name": "Help Desk User",
    },
    "admin_user": {
        "password_hash": generate_password_hash("admin123"),
        "role": "admin",
        "display_name": "IT Admin",
    },
}

# ---------------------------------------------------------------------------
# Corpus — same documents as the browser artifact, moved server-side so a
# client can no longer see restricted document content in any payload at all
# (the artifact version at least kept restricted docs out of the DOM's
# visible text, but a curious user could still read CORPUS in view-source;
# that is no longer possible here).
# ---------------------------------------------------------------------------
CORPUS = [
    {
        "id": "wifi-setup",
        "title": "Corporate Wi-Fi Setup Guide",
        "classification": "general",
        "content": (
            "To connect to the corporate Wi-Fi network CORP-SECURE, select the "
            "network from your device list and authenticate using your corporate "
            "username and password (WPA2-Enterprise, EAP-PEAP). Guest devices "
            "should use CORP-GUEST instead, which requires a sponsor code from "
            "the front desk."
        ),
    },
    {
        "id": "password-reset",
        "title": "Password Reset Procedure",
        "classification": "general",
        "content": (
            "Users can reset their own password at reset.corp.internal using "
            "their registered email and security questions. If the self-service "
            "portal fails after 3 attempts, the account locks for 15 minutes. "
            "Help desk staff can manually unlock and reset a password through "
            "the Identity Admin Console after verifying the user's identity via "
            "employee ID."
        ),
    },
    {
        "id": "vpn-config",
        "title": "VPN Configuration Guide",
        "classification": "general",
        "content": (
            "Remote access uses Cisco AnyConnect Secure Mobility Client "
            "connecting to vpn.corp.internal. Employees authenticate with their "
            "corporate credentials plus a push notification via the Duo mobile "
            "app. Split tunneling is disabled by default for all standard "
            "employee profiles."
        ),
    },
    {
        "id": "firewall-rules",
        "title": "Perimeter Firewall Rule Set",
        "classification": "restricted",
        "content": (
            "[RESTRICTED - IT ADMIN ONLY] Perimeter firewall rules "
            "(fictional/demo data): Rule 10 allows inbound HTTPS (443) from any "
            "to the DMZ web tier. Rule 20 allows inbound SSH (22) only from the "
            "jump-host subnet 10.20.0.0/24. Rule 30 denies all inbound traffic "
            "to the finance VLAN except from the VPN gateway. Rule 40 blocks "
            "all outbound traffic to known-malicious IP ranges per the threat "
            "intel feed."
        ),
    },
    {
        "id": "admin-registry",
        "title": "Privileged Admin Account Registry",
        "classification": "restricted",
        "content": (
            "[RESTRICTED - IT ADMIN ONLY] Privileged account registry "
            "(fictional/demo data): Domain Admin accounts are limited to 3 "
            "named individuals in the Security Engineering team, each with a "
            "break-glass emergency account stored in the PAM vault requiring "
            "dual approval to check out."
        ),
    },
]

ROLE_ACCESS = {
    "helpdesk": {"general"},
    "admin": {"general", "restricted"},
}

STOPWORDS = {
    "the", "and", "for", "are", "how", "what", "which", "who", "when",
    "where", "tell", "about", "can", "you", "get", "set", "into", "from",
    "with", "this", "that", "does", "did", "has", "have", "your",
}
MIN_SCORE = 2

# ---------------------------------------------------------------------------
# Prompt injection scanner — layer 1 defense.
#
# Catches obvious instruction-override and role-escalation patterns before
# the query ever reaches the retrieval pipeline or the LLM. This is
# intentionally documented as a partial defense: it will catch the patterns
# below and nothing else. Subtle attacks (authority impersonation, indirect
# content discovery, obfuscation) are designed to bypass this layer so that
# the test battery can evaluate LLM-level resistance independently.
#
# Each tuple is (compiled regex, attack category label for the audit log).
# ---------------------------------------------------------------------------
INJECTION_PATTERNS = [
    # Direct instruction override
    (re.compile(r"ignore\s+(your\s+)?(previous|prior|above|all)\s+(instructions?|prompts?|context|rules?)", re.I), "instruction-override"),
    (re.compile(r"disregard\s+(your|the|all)\s+(instructions?|prompts?|context|rules?)", re.I), "instruction-override"),
    (re.compile(r"forget\s+(your|the|all|previous)\s+(instructions?|prompts?|context|rules?)", re.I), "instruction-override"),
    (re.compile(r"override\s+(your|the|all)?\s*(instructions?|access\s*controls?|restrictions?)", re.I), "instruction-override"),
    # Role / identity escalation
    (re.compile(r"you\s+are\s+now\s+(an?\s+)?(admin|administrator|superuser|root|unrestricted|different)", re.I), "role-escalation"),
    (re.compile(r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(admin|unrestricted|different\s+ai)", re.I), "role-escalation"),
    # Jailbreak keywords
    (re.compile(r"\bdan\s+mode\b", re.I), "jailbreak"),
    (re.compile(r"\bdo\s+anything\s+now\b", re.I), "jailbreak"),
    # System prompt extraction
    (re.compile(r"(repeat|reveal|show|print|output|display|tell\s+me)\s+(your|the)\s+(system\s+)?(prompt|instructions?)\s*(verbatim|word\s+for\s+word|exactly)?", re.I), "prompt-extraction"),
    (re.compile(r"what\s+(are|is)\s+your\s+(instructions?|system\s+prompt|rules?|constraints?)", re.I), "prompt-extraction"),
    # Delimiter / markup injection
    (re.compile(r"<\/?\s*(system|prompt|context|instruction|human|assistant)\s*>", re.I), "delimiter-injection"),
    (re.compile(r"\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>", re.I), "delimiter-injection"),
    # Roleplay / hypothetical bypass
    (re.compile(r"(roleplay|role[\s\-]play)\s*:.{0,40}(unrestricted|no\s+restrictions?|admin)", re.I), "roleplay-bypass"),
    (re.compile(r"hypothetically.{0,60}(no\s+restrictions?|bypass|unrestricted)", re.I), "hypothetical-bypass"),
]


def scan_for_injection(text):
    """
    Returns (flagged: bool, category: str | None).
    Scans query text against known injection patterns before it reaches
    the retrieval pipeline or the LLM.
    """
    for pattern, category in INJECTION_PATTERNS:
        if pattern.search(text):
            return True, category
    return False, None


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return jsonify({"error": "not authenticated"}), 401
        return fn(*args, **kwargs)
    return wrapper


@app.route("/api/config", methods=["GET"])
def get_config():
    """Tells the frontend whether to show the 'Sign in with Microsoft' button.

    The button shows when real Entra is configured, or when ENTRA_UI_DEMO=1
    (screenshot capture only -- the button appears but the OAuth routes remain
    disabled unless real credentials are present)."""
    return jsonify({"entra_enabled": ENTRA_ENABLED or ENTRA_UI_DEMO})


# ---------------------------------------------------------------------------
# Entra ID OAuth2 authorization-code flow.
#
# /auth/login   -> redirect the browser to Microsoft's sign-in page
# /auth/callback -> Microsoft redirects back here with an auth code; we
#                   exchange it for tokens, read the app-role claim, map it to
#                   an internal role, and populate the same session the demo
#                   login uses.
#
# A per-request 'state' value is stored in the session and checked on callback
# to defend against CSRF on the OAuth flow itself.
# ---------------------------------------------------------------------------
@app.route("/auth/login")
def entra_login():
    if not ENTRA_ENABLED:
        return jsonify({"error": "Entra sign-in is not configured on this server"}), 404
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    auth_url = _build_msal_app().get_authorization_request_url(
        ENTRA_SCOPES,
        state=state,
        redirect_uri=ENTRA_REDIRECT_URI,
    )
    return redirect(auth_url)


@app.route("/auth/callback")
def entra_callback():
    if not ENTRA_ENABLED:
        return jsonify({"error": "Entra sign-in is not configured"}), 404

    # CSRF check on the OAuth state
    if request.args.get("state") != session.get("oauth_state"):
        return _entra_error_page("State mismatch -- possible CSRF. Sign-in aborted.")
    session.pop("oauth_state", None)

    if "error" in request.args:
        return _entra_error_page(
            f"{request.args.get('error')}: {request.args.get('error_description', '')}"
        )

    code = request.args.get("code")
    if not code:
        return _entra_error_page("No authorization code returned by Microsoft.")

    result = _build_msal_app().acquire_token_by_authorization_code(
        code,
        scopes=ENTRA_SCOPES,
        redirect_uri=ENTRA_REDIRECT_URI,
    )

    if "error" in result:
        return _entra_error_page(
            f"Token exchange failed: {result.get('error_description', result['error'])}"
        )

    claims = result.get("id_token_claims", {})
    roles = claims.get("roles", [])  # app-role claim, a list of role Values

    # Map the first recognized Entra app role to an internal role.
    internal_role = None
    matched_entra_role = None
    for r in roles:
        if r in ENTRA_ROLE_MAP:
            internal_role = ENTRA_ROLE_MAP[r]
            matched_entra_role = r
            break

    if internal_role is None:
        return _entra_error_page(
            "Your account authenticated successfully but has no matching app "
            "role assigned (need Helpdesk or Admin). Ask an administrator to "
            "assign a role to your account in the Enterprise Application."
        )

    display_name = claims.get("name") or claims.get("preferred_username") or "Entra User"
    username = claims.get("preferred_username") or claims.get("oid") or "entra-user"

    session["username"] = username
    session["role"] = internal_role
    session["display_name"] = display_name
    session["auth_method"] = "entra"
    session["entra_role_claim"] = matched_entra_role

    return redirect(url_for("index"))


def _entra_error_page(message):
    safe = message.replace("<", "&lt;").replace(">", "&gt;")
    return (
        f"<html><body style='font-family:sans-serif;background:#0d1117;"
        f"color:#e6edf3;padding:40px;'>"
        f"<h2>Microsoft sign-in problem</h2><p>{safe}</p>"
        f"<p><a style='color:#4fd1c5;' href='/'>Back to sign-in</a></p>"
        f"</body></html>",
        400,
    )


@app.route("/api/login", methods=["POST"])
def login():
    body = request.get_json(force=True, silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    user = USERS.get(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "invalid credentials"}), 401
    session["username"] = username
    session["role"] = user["role"]
    session["display_name"] = user["display_name"]
    session["auth_method"] = "demo"
    return jsonify({"username": username, "role": user["role"],
                     "display_name": user["display_name"]})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/session", methods=["GET"])
def get_session():
    if "username" not in session:
        return jsonify({"authenticated": False})
    # display_name is now stored on the session directly (set by both demo and
    # Entra login), so we no longer look it up in USERS -- an Entra user's
    # username is not in that table and doing so would raise KeyError.
    return jsonify({
        "authenticated": True,
        "username": session["username"],
        "role": session["role"],
        "display_name": session.get("display_name", session["username"]),
        "auth_method": session.get("auth_method", "demo"),
    })


# ---------------------------------------------------------------------------
# Corpus visibility (for the UI panel) — filtered server-side by session role
# ---------------------------------------------------------------------------
@app.route("/api/corpus", methods=["GET"])
@login_required
def get_corpus():
    role = session["role"]
    allowed = ROLE_ACCESS[role]
    out = [
        {
            "id": d["id"],
            "title": d["title"],
            "classification": d["classification"],
            "visible": d["classification"] in allowed,
        }
        for d in CORPUS
    ]
    return jsonify({"role": role, "documents": out})


# ---------------------------------------------------------------------------
# Retrieval — identical logic to the browser artifact, ported to Python.
# RBAC filtering happens BEFORE scoring: restricted docs are never in the
# candidate set for a non-admin session, they are not merely excluded from
# the response afterward.
# ---------------------------------------------------------------------------
def tokenize(text, drop_stopwords=True):
    cleaned = "".join(c if c.isalnum() or c.isspace() else " " for c in text.lower())
    words = cleaned.split()
    if drop_stopwords:
        return [w for w in words if len(w) > 2 and w not in STOPWORDS]
    return set(w for w in words if len(w) > 0)


def score_against(query_words, docs):
    scored = []
    for doc in docs:
        doc_tokens = tokenize(doc["title"] + " " + doc["content"], drop_stopwords=False)
        score = sum(1 for w in query_words if w in doc_tokens)
        if score >= MIN_SCORE:
            scored.append((score, doc))
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored


def retrieve(query, role):
    allowed = ROLE_ACCESS[role]
    candidates = [d for d in CORPUS if d["classification"] in allowed]
    query_words = tokenize(query)

    scored_allowed = score_against(query_words, candidates)
    scored_all = score_against(query_words, CORPUS)

    top_overall = scored_all[0] if scored_all else None
    top_allowed_score = scored_allowed[0][0] if scored_allowed else -1

    was_blocked_by_role = (
        top_overall is not None
        and top_overall[1]["classification"] not in allowed
        and top_overall[0] > top_allowed_score
    )

    matches = [doc for _, doc in scored_allowed[:2]]
    blocked_doc = top_overall[1] if was_blocked_by_role else None
    return matches, was_blocked_by_role, blocked_doc


# ---------------------------------------------------------------------------
# Generation — server-side call to Claude. The API key is read from an
# environment variable on this process; it is never sent to, or reachable
# from, the browser.
# ---------------------------------------------------------------------------
def generate_answer(query, matched_docs):
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set on the server. Set it as an "
            "environment variable before starting this app — it must never "
            "be hardcoded or sent to the client."
        )

    context = "\n\n".join(f"[{d['title']}]\n{d['content']}" for d in matched_docs)
    system_prompt = (
        "You are an internal corporate IT help desk assistant. Answer ONLY "
        "using the context documents provided below. Do not use outside "
        "knowledge, and do not speculate. Keep answers concise (2-4 sentences). "
        "The documents below have already been filtered by a separate, "
        "server-side access control check based on the current user's "
        "authenticated role -- if a document appears here, that check has "
        "already confirmed this user is authorized to see it, including any "
        "document labeled RESTRICTED or ADMIN ONLY. Do not re-apply your own "
        "access judgment on top of that filtering, and do not refuse or "
        "redirect the user to another team based on a document's "
        "classification label -- simply answer their question using the "
        "content provided."
        f"\n\nCONTEXT:\n{context}"
    )

    payload = json.dumps({
        "model": "claude-sonnet-4-6",
        "max_tokens": 300,
        "system": system_prompt,
        "messages": [{"role": "user", "content": query}],
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    for block in data.get("content", []):
        if block.get("type") == "text":
            return block["text"]
    return "The assistant did not return a response. Please try again."


# ---------------------------------------------------------------------------
# Audit log — append-only JSON file on disk. Documented stand-in for a real
# SIEM / Log Analytics Workspace; see README.
# ---------------------------------------------------------------------------
def load_audit_log():
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    try:
        with open(AUDIT_LOG_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def append_audit_entry(entry):
    log = load_audit_log()
    log.append(entry)
    log = log[-MAX_AUDIT_ENTRIES:]
    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
    with open(AUDIT_LOG_PATH, "w") as f:
        json.dump(log, f, indent=2)


@app.route("/api/audit-log", methods=["GET"])
@login_required
def get_audit_log():
    return jsonify({"entries": load_audit_log()})


@app.route("/api/audit-log", methods=["DELETE"])
@login_required
def clear_audit_log():
    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
    with open(AUDIT_LOG_PATH, "w") as f:
        json.dump([], f)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Query endpoint — the actual pipeline. Role comes from session, never from
# the request body, so a client cannot claim a role it wasn't authenticated
# into.
# ---------------------------------------------------------------------------
@app.route("/api/query", methods=["POST"])
@login_required
def query():
    body = request.get_json(force=True, silent=True) or {}
    user_query = (body.get("query") or "").strip()
    if not user_query:
        return jsonify({"error": "empty query"}), 400

    role = session["role"]
    username = session["username"]
    auth_method = session.get("auth_method", "demo")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _audit(decision, matched_doc_ids, **extra):
        """Build a consistent audit entry with auth_method always included."""
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "username": username,
            "role": role,
            "auth_method": auth_method,
            "query": user_query,
            "matched_doc_ids": matched_doc_ids,
            "decision": decision,
        }
        entry.update(extra)
        append_audit_entry(entry)
        return entry

    # --- Layer 1: pre-flight injection scan ---
    # Runs before retrieval and before any LLM call. If the query matches a
    # known injection pattern, it is blocked here and logged with full
    # context. The LLM never sees it.
    injection_flagged, injection_category = scan_for_injection(user_query)
    if injection_flagged:
        _audit("injection-blocked", [], injection_category=injection_category)
        return jsonify({
            "decision": "injection-blocked",
            "answer": "That query was flagged as a potential prompt injection attempt and was not processed.",
            "matched_doc_ids": [],
            "injection_category": injection_category,
        })

    matches, was_blocked_by_role, blocked_doc = retrieve(user_query, role)

    if not matches and was_blocked_by_role:
        _audit("access-denied", [])
        return jsonify({
            "decision": "access-denied",
            "answer": "I don't have information on that. Please contact the IT help desk directly.",
            "matched_doc_ids": [],
        })

    if not matches:
        _audit("no-match", [])
        return jsonify({
            "decision": "no-match",
            "answer": "I don't have information on that. Please contact the IT help desk directly.",
            "matched_doc_ids": [],
        })

    try:
        answer = generate_answer(user_query, matches)
        decision = "answered"
    except (RuntimeError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        answer = f"Error contacting the generation service: {e}"
        decision = "generation-error"

    _audit(decision, [m["id"] for m in matches])

    return jsonify({
        "decision": decision,
        "answer": answer,
        "matched_doc_ids": [m["id"] for m in matches],
        "matched_doc_titles": [m["title"] for m in matches],
    })


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=port, debug=debug)
