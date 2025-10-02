# demo_security_suite.py

from flask import Flask, request, redirect, send_file
import sqlite3
import subprocess
import pickle
import tempfile
import requests
import hashlib
import os

app = Flask(__name__)

# -------------------------------
# 1) Hardcoded "secret" (Secret scanning demo)
# -------------------------------
# Contoh credential yang TIDAK BOLEH disimpan di kode nyata.
API_TOKEN = "demo_api_token_1234567890"    # <= secret (demo)
DB_PASSWORD = "DemoPass123!"               # <= secret (demo)


# -------------------------------
# 2) Insecure DB query (SQL Injection demo)
# -------------------------------
def init_db():
    conn = sqlite3.connect("demo_users.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    # sample user (username: alice, password: wonder)
    c.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'alice', 'wonder')")
    conn.commit()
    conn.close()

@app.route("/login", methods=["POST"])
def login():
    # VULNERABLE: building SQL query by string concat -> SQL injection
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect("demo_users.db")
    cursor = conn.cursor()
    # Dangerous: user-controlled input inserted directly into SQL
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return {"matched": len(rows), "query": query}


# -------------------------------
# 3) Unsafe subprocess call (Command injection demo)
# -------------------------------
@app.route("/run", methods=["GET"])
def run_cmd():
    # VULNERABLE: using shell=True with user input
    cmd = request.args.get("cmd", "echo hello")
    # Dangerous: allows command injection if cmd comes from user
    subprocess.call(cmd, shell=True)
    return f"Executed: {cmd}"


# -------------------------------
# 4) Unsafe eval usage (Remote code execution demo)
# -------------------------------
@app.route("/calc", methods=["POST"])
def calc():
    expr = request.form.get("expr", "2+2")
    # VULNERABLE: eval on user input -> remote code execution risk
    result = eval(expr)
    return {"expr": expr, "result": str(result)}


# -------------------------------
# 5) Insecure temporary file handling (race condition / info leak)
# -------------------------------
@app.route("/temp", methods=["GET"])
def temp_demo():
    # VULNERABLE: mktemp is unsafe; predictable filename/race condition
    tmp_path = tempfile.mktemp()
    with open(tmp_path, "w") as f:
        f.write("temporary secret data\n")
    return {"wrote_to": tmp_path}


# -------------------------------
# 6) Unsafe deserialization (pickle) demo
# -------------------------------
@app.route("/upload_pickle", methods=["POST"])
def upload_pickle():
    # VULNERABLE: deserializing data from request without validation
    data = request.data
    try:
        obj = pickle.loads(data)   # unsafe if data from untrusted source
        return {"status": "ok", "type": str(type(obj))}
    except Exception as e:
        return {"status": "error", "err": str(e)}


# -------------------------------
# 7) Insecure TLS usage (verify=False demo)
# -------------------------------
@app.route("/insecure_fetch", methods=["GET"])
def insecure_fetch():
    # VULNERABLE: verify=False disables TLS cert checking (MITM risk)
    r = requests.get("https://example.com", verify=False)
    return {"status_code": r.status_code, "len": len(r.text)}


# -------------------------------
# 8) Weak hashing demo
# -------------------------------
@app.route("/weak_hash", methods=["POST"])
def weak_hash():
    pw = request.form.get("pw", "secret")
    # VULNERABLE: MD5 is weak for password hashing
    digest = hashlib.md5(pw.encode()).hexdigest()
    return {"md5": digest}


# -------------------------------
# 9) Open redirect demo
# -------------------------------
@app.route("/go")
def open_redirect():
    # VULNERABLE: redirect to user-provided URL (open redirect)
    target = request.args.get("url", "https://example.com")
    return redirect(target)


# -------------------------------
# Helper: run app (for local demo only)
# -------------------------------
if __name__ == "__main__":
    # WARNING: debug=True is unsafe in production
    app.run(host="0.0.0.0", port=5000, debug=True)
