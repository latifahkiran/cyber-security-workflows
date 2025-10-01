from flask import Flask, request
import sqlite3

app = Flask(__name__)

# coba alert flask debug
app.config["DEBUG"] = True  

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    # 🚨 Celah 2: SQL Injection
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)  # rawan SQL injection
    result = cursor.fetchall()
    return str(result)

if __name__ == "__main__":
    app.run()
