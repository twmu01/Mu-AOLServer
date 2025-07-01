from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from passlib.hash import bcrypt

app = Flask(__name__)
CORS(app)
DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(force=False):
    conn = get_db_connection()
    c = conn.cursor()
    if force:
        c.execute('DROP TABLE IF EXISTS users')
        print("[INFO] Dropped existing users table.")

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            about_me TEXT DEFAULT ''
        )
    ''')
    conn.commit()
    conn.close()
    print("[INFO] Database initialized.")

@app.route('/initdb', methods=['GET'])
def initdb_route():
    init_db(force=True)
    return jsonify({"success": True, "message": "Database initialized."})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Missing JSON body"}), 400

    account = data.get("Account")
    password = data.get("Password")
    if not account or not password:
        return jsonify({"success": False, "message": "Missing account or password"}), 400

    password_hash = bcrypt.hash(password)
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('INSERT INTO users (account, password_hash) VALUES (?, ?)', (account, password_hash))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Account registered."})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Account already exists."}), 409

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Missing JSON body"}), 400

    account = data.get("Account")
    password = data.get("Password")
    if not account or not password:
        return jsonify({"success": False, "message": "Missing account or password"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT password_hash FROM users WHERE account = ?', (account,))
    row = c.fetchone()
    conn.close()

    if row and bcrypt.verify(password, row['password_hash']):
        return jsonify({"success": True, "message": "Login successful", "account": account})
    else:
        return jsonify({"success": False, "message": "Invalid account or password"}), 401

@app.route('/profile/<account>', methods=['GET'])
def get_profile(account):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT about_me FROM users WHERE account = ?', (account,))
    row = c.fetchone()
    conn.close()

    if row:
        return jsonify({"success": True, "about_me": row['about_me']})
    else:
        return jsonify({"success": False, "message": "User not found"}), 404

@app.route('/profile/<account>', methods=['POST'])
def update_profile(account):
    data = request.get_json()
    about_me = data.get("about_me", "")

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('UPDATE users SET about_me = ? WHERE account = ?', (about_me, account))
    conn.commit()
    changes = conn.total_changes
    conn.close()

    if changes:
        return jsonify({"success": True, "message": "Profile updated."})
    else:
        return jsonify({"success": False, "message": "User not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5367)
