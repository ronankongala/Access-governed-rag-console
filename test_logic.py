"""
Exercises the real server logic (auth, session, RBAC-before-scoring,
audit logging) end to end via Flask's test client. Does not call the live
Anthropic API (no network in this sandbox) — patches generate_answer so the
retrieval/RBAC/audit path is still tested for real, not mocked out entirely.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as app_module

app_module.app.config["TESTING"] = True

# Patch only the generation call (the part that needs network); everything
# else — auth, session, retrieval scoring, RBAC filtering, audit persistence
# — runs unmodified.
def fake_generate_answer(query, matched_docs):
    return f"[stub answer grounded in {len(matched_docs)} doc(s)]"

app_module.generate_answer = fake_generate_answer

# Use a throwaway audit log file so this doesn't pollute the real one
app_module.AUDIT_LOG_PATH = "/tmp/test_audit_log.json"
if os.path.exists(app_module.AUDIT_LOG_PATH):
    os.remove(app_module.AUDIT_LOG_PATH)

client = app_module.app.test_client()

def check(label, cond):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {label}")
    if not cond:
        raise SystemExit(1)

# 1. Unauthenticated query is rejected
r = client.post("/api/query", json={"query": "how do I reset a password"})
check("unauthenticated query -> 401", r.status_code == 401)

# 2. Bad login rejected
r = client.post("/api/login", json={"username": "helpdesk_user", "password": "wrong"})
check("bad password -> 401", r.status_code == 401)

# 3. Helpdesk login works
r = client.post("/api/login", json={"username": "helpdesk_user", "password": "helpdesk123"})
check("helpdesk login -> 200", r.status_code == 200)
check("helpdesk role assigned server-side", r.get_json()["role"] == "helpdesk")

# 4. In-scope query as helpdesk -> answered, and does NOT false-match the
# unrelated Wi-Fi doc via the "user" substring inside "username"
r = client.post("/api/query", json={"query": "How do I reset a user's password?"})
data = r.get_json()
check("in-scope query answered", data["decision"] == "answered")
check("matched password-reset doc", "password-reset" in data["matched_doc_ids"])
check("did NOT false-match wifi-setup via 'user' substring in 'username'",
      "wifi-setup" not in data["matched_doc_ids"])

# 5. Out-of-scope query -> no-match
r = client.post("/api/query", json={"query": "Which firewalls are Cisco?"})
data = r.get_json()
check("out-of-scope query -> no-match (Cisco bug fix holds server-side)", data["decision"] == "no-match")

# 6. Restricted query as helpdesk -> access-denied, and content never leaves the server
r = client.post("/api/query", json={"query": "Tell me the firewall rules."})
data = r.get_json()
check("restricted query as helpdesk -> access-denied", data["decision"] == "access-denied")
check("no doc ids leaked on denial", data["matched_doc_ids"] == [])
check("no firewall rule content leaked in answer", "Rule 10" not in data["answer"])

# 7. Corpus panel hides restricted content but shows it's there
r = client.get("/api/corpus")
docs = r.get_json()["documents"]
restricted_doc = next(d for d in docs if d["id"] == "firewall-rules")
check("restricted doc marked not visible for helpdesk", restricted_doc["visible"] is False)

client.post("/api/logout", methods=["POST"]) if False else client.post("/api/logout")

# 8. Same restricted query as admin -> answered
r = client.post("/api/login", json={"username": "admin_user", "password": "admin123"})
check("admin login -> 200", r.status_code == 200)

r = client.post("/api/query", json={"query": "Tell me the firewall rules."})
data = r.get_json()
check("restricted query as admin -> answered", data["decision"] == "answered")
check("matched firewall-rules doc as admin", "firewall-rules" in data["matched_doc_ids"])

# 9. Audit log persisted to disk and captures both denial and success for the same query text
r = client.get("/api/audit-log")
entries = r.get_json()["entries"]
check("audit log has entries", len(entries) >= 4)
denied_entries = [e for e in entries if e["decision"] == "access-denied"]
answered_firewall = [e for e in entries if e["query"] == "Tell me the firewall rules." and e["decision"] == "answered"]
check("audit log recorded the denial", len(denied_entries) == 1)
check("audit log recorded the later admin success for same query", len(answered_firewall) == 1)

print("\nAll checks passed.")
