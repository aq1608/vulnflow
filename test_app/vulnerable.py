# test_app/vulnerable_app.py
from flask import Flask, request, render_template_string, g
import sqlite3

app = Flask(__name__)

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('test.db')
    return g.db

# ==========================================
# SQL INJECTION VULNERABILITIES
# ==========================================

@app.route('/sqli/error-based')
def sqli_error():
    """Error-based SQL injection"""
    user_id = request.args.get('id', '')
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    try:
        result = get_db().execute(query).fetchall()
        return str(result)
    except Exception as e:
        return f"SQL Error: {e}"  # Exposes error messages

@app.route('/sqli/blind-boolean')
def sqli_blind_boolean():
    """Boolean-based blind SQL injection"""
    user_id = request.args.get('id', '')
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    result = get_db().execute(query).fetchone()
    if result:
        return "User exists"
    return "User not found"

@app.route('/sqli/blind-time')
def sqli_blind_time():
    """Time-based blind SQL injection"""
    user_id = request.args.get('id', '')
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    get_db().execute(query)
    return "Query executed"

@app.route('/sqli/secure')
def sqli_secure():
    """Secure implementation - for comparison testing"""
    user_id = request.args.get('id', '')
    query = "SELECT * FROM users WHERE id = ?"
    result = get_db().execute(query, (user_id,)).fetchall()
    return str(result)

# ==========================================
# XSS VULNERABILITIES
# ==========================================

@app.route('/xss/reflected')
def xss_reflected():
    """Reflected XSS"""
    name = request.args.get('name', '')
    # VULNERABLE: Direct rendering without escaping
    return render_template_string(f"<h1>Hello {name}!</h1>")

@app.route('/xss/stored', methods=['GET', 'POST'])
def xss_stored():
    """Stored XSS"""
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        # VULNERABLE: Storing without sanitization
        get_db().execute("INSERT INTO comments (text) VALUES (?)", (comment,))
        get_db().commit()
    
    comments = get_db().execute("SELECT text FROM comments").fetchall()
    html = "<h1>Comments</h1>"
    for comment in comments:
        html += f"<p>{comment[0]}</p>"  # VULNERABLE: No escaping
    return html

@app.route('/xss/dom')
def xss_dom():
    """DOM-based XSS"""
    return '''
    <html>
    <body>
        <div id="output"></div>
        <script>
            // VULNERABLE: Using location.hash without sanitization
            document.getElementById('output').innerHTML = 
                decodeURIComponent(location.hash.substring(1));
        </script>
    </body>
    </html>
    '''

@app.route('/xss/secure')
def xss_secure():
    """Secure implementation"""
    from markupsafe import escape
    name = request.args.get('name', '')
    return f"<h1>Hello {escape(name)}!</h1>"

# ==========================================
# CSRF VULNERABILITIES
# ==========================================

@app.route('/csrf/vulnerable', methods=['GET', 'POST'])
def csrf_vulnerable():
    """No CSRF protection"""
    if request.method == 'POST':
        # VULNERABLE: No CSRF token validation
        new_email = request.form.get('email')
        return f"Email changed to {new_email}"
    return '''
    <form method="POST">
        <input name="email" placeholder="New Email">
        <button type="submit">Change Email</button>
    </form>
    '''

# ==========================================
# SECURITY HEADER ISSUES
# ==========================================

@app.route('/headers/missing')
def headers_missing():
    """Missing security headers"""
    response = app.make_response("No security headers")
    # Missing: X-Frame-Options, CSP, X-Content-Type-Options, etc.
    return response

@app.route('/headers/secure')
def headers_secure():
    """Proper security headers"""
    response = app.make_response("With security headers")
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response

# ==========================================
# OTHER VULNERABILITIES
# ==========================================

@app.route('/lfi')
def lfi_vulnerable():
    """Local File Inclusion"""
    filename = request.args.get('file', 'default.txt')
    # VULNERABLE: No path validation
    try:
        with open(f"templates/{filename}") as f:
            return f.read()
    except:
        return "File not found"

@app.route('/redirect')
def open_redirect():
    """Open Redirect"""
    url = request.args.get('url', '/')
    # VULNERABLE: No URL validation
    from flask import redirect
    return redirect(url)

@app.route('/cmd')
def command_injection():
    """Command Injection"""
    import subprocess
    hostname = request.args.get('host', 'localhost')
    # VULNERABLE: Direct command execution
    result = subprocess.run(f"ping -c 1 {hostname}", 
                          shell=True, capture_output=True)
    return result.stdout.decode()


if __name__ == '__main__':
    # Initialize database
    with app.app_context():
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS users 
                     (id INTEGER PRIMARY KEY, name TEXT, email TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS comments 
                     (id INTEGER PRIMARY KEY, text TEXT)''')
        db.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin@test.com')")
        db.commit()
    
    app.run(debug=True, port=5000)