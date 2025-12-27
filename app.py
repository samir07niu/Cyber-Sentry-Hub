from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import socket
import os
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_KEY_SHHH" # Session ke liye zaruri hai
DB_NAME = "cyber_sentry.db"

# --- DATABASE SETUP (Ye automatic Table banayega) ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Users Table
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)''')
    # Secrets Table (Link to User ID)
    c.execute('''CREATE TABLE IF NOT EXISTS secrets 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, website TEXT, password TEXT)''')
    conn.commit()
    conn.close()

# App start hote hi DB check karo
init_db()

# --- 1. LOGIN PAGE (First Screen) ---
@app.route('/', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect('/dashboard') # Agar pehle se login hai to dashboard bhejo
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        
        # Password Check (Hash Match)
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0] # Login Successful
            session['username'] = user[1]
            return redirect('/dashboard')
        else:
            return "<h1 style='color:red;text-align:center;background:black;'>❌ ACCESS DENIED: WRONG PASSWORD</h1>"

    return render_template('login.html')

# --- 2. REGISTER PAGE ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password) # Password ko encrypt karo
        
        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            conn.close()
            return redirect('/')
        except:
            return "<h1 style='color:red;'>❌ ERROR: Username already exists!</h1>"
            
    return render_template('register.html')

# --- 3. MAIN DASHBOARD (Login Required) ---
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/') # Bina login ke no entry
    return render_template('index.html', user=session['username'])

# --- 4. LOGOUT ---
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# --- 5. PASSWORD VAULT (Personalized) ---
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
        # Sirf current user ke liye save karo
        c.execute("INSERT INTO secrets (user_id, website, password) VALUES (?, ?, ?)", (user_id, website, password))
        conn.commit()
        return redirect('/vault')

    # Sirf current user ka data nikalo
    c.execute("SELECT website, password FROM secrets WHERE user_id=?", (user_id,))
    secrets = c.fetchall()
    conn.close()
    
    return render_template('vault.html', secrets=secrets)

# --- 6. OTHER TOOLS ---
@app.route('/myip')
def get_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
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
    app.run(debug=True, host='0.0.0.0')