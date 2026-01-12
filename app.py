"""
Module: Cyber Sentry Core (Backend)
Description: Flask-based Controller for Password Management & Authentication.
Developer: Samir Raja (Panther)
"""

from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import socket
import os
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# [SECURITY NOTE]: In a production environment, use Environment Variables for keys.
# Hardcoded here for local demonstration purposes only.
app.secret_key = "SUPER_SECRET_KEY_SHHH" 
DB_NAME = "cyber_sentry.db"

# --- DATABASE INITIALIZATION ---
def init_db():
    """Initializes the SQLite database structure if not exists."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Table: Users (Stores Credentials)
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)''')
    
    # Table: Secrets (Encrypted Vault linked to User ID)
    c.execute('''CREATE TABLE IF NOT EXISTS secrets 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, website TEXT, password TEXT)''')
    
    conn.commit()
    conn.close()

# Initialize DB on startup
init_db()

# --- 1. AUTHENTICATION GATEWAY (Login) ---
@app.route('/', methods=['GET', 'POST'])
def login():
    # Check if session is already active
    if 'user_id' in session:
        return redirect('/dashboard') 
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        
        # Validate Password Hash
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0] # Set Session Token
            session['username'] = user[1]
            return redirect('/dashboard')
        else:
            return "<h1 style='color:red;text-align:center;background:black;font-family:monospace;'>❌ ACCESS DENIED: INVALID CREDENTIALS</h1>"

    return render_template('login.html')

# --- 2. USER REGISTRATION ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Security: Hashing password before storage (SHA-256 via Werkzeug)
        hashed_pw = generate_password_hash(password) 
        
        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            conn.close()
            return redirect('/')
        except sqlite3.IntegrityError:
            return "<h1 style='color:red;'>❌ ERROR: User already exists in database!</h1>"
            
    return render_template('register.html')

# --- 3. SECURITY DASHBOARD ---
@app.route('/dashboard')
def dashboard():
    # Session Validation
    if 'user_id' not in session:
        return redirect('/') 
    return render_template('index.html', user=session['username'])

# --- 4. SESSION TERMINATION ---
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# --- 5. ENCRYPTED VAULT ---
@app.route('/vault', methods=['GET', 'POST'])
def vault():
    if 'user_id' not in session:
        return redirect('/')

    user_id = session['user_id']
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    if request.method == 'POST':
        website = request.form.get('website')
        password = request.form.get('password')
        
        # Storing secret linked to specific UserID
        c.execute("INSERT INTO secrets (user_id, website, password) VALUES (?, ?, ?)", (user_id, website, password))
        conn.commit()
        return redirect('/vault')

    # Fetching only user-specific data
    c.execute("SELECT website, password FROM secrets WHERE user_id=?", (user_id,))
    secrets = c.fetchall()
    conn.close()
    
    return render_template('vault.html', secrets=secrets)

# --- 6. UTILITY TOOLS ---
@app.route('/myip')
def get_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    # Inline HTML used for lightweight response
    return f"<body style='background:black;color:lime;font-family:courier;text-align:center;margin-top:100px;'><h1>🔥 TARGET IDENTIFIED: {ip_address}</h1><br><a href='/dashboard' style='color:white;'>Back</a></body>"

@app.route('/generate')
def generate_pass():
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    strong_pass = "".join(random.choice(chars) for i in range(16))
    return f"<body style='background:black;color:lime;font-family:courier;text-align:center;margin-top:100px;'><h1>🔑 KEY: {strong_pass}</h1><br><a href='/vault' style='color:white;'>Copy & Go to Vault</a></body>"

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    # Running on 0.0.0.0 to expose to local network
    app.run(debug=True, host='0.0.0.0')
