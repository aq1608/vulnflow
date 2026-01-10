# websec/remediation/engine.py
from typing import Dict, List
from dataclasses import dataclass


@dataclass
class RemediationAdvice:
    vulnerability_type: str
    framework: str
    description: str
    code_example: str
    references: List[str]
    priority: int = 1


class RemediationEngine:
    """Provides contextual remediation advice based on detected tech stack"""
    
    def __init__(self):
        self.knowledge_base = self._load_knowledge_base()
    
    def _load_knowledge_base(self) -> Dict:
        """Load remediation knowledge base"""
        return {
            "SQL Injection": {
                "Django": RemediationAdvice(
                    vulnerability_type="SQL Injection",
                    framework="Django",
                    description="Use Django ORM's parameterized queries instead of raw SQL",
                    code_example='''# VULNERABLE:
User.objects.raw("SELECT * FROM users WHERE id = '%s'" % user_id)

# SECURE - Use ORM:
User.objects.filter(id=user_id)

# SECURE - Parameterized raw query:
User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])''',
                    references=[
                        "https://docs.djangoproject.com/en/4.0/topics/security/#sql-injection-protection",
                        "https://owasp.org/www-community/attacks/SQL_Injection"
                    ],
                    priority=1
                ),
                "Flask": RemediationAdvice(
                    vulnerability_type="SQL Injection",
                    framework="Flask",
                    description="Use SQLAlchemy ORM or parameterized queries",
                    code_example='''# VULNERABLE:
db.execute(f"SELECT * FROM users WHERE id = {user_id}")

# SECURE - SQLAlchemy ORM:
User.query.filter_by(id=user_id).first()

# SECURE - Parameterized query:
db.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})''',
                    references=[
                        "https://flask-sqlalchemy.palletsprojects.com/",
                        "https://docs.sqlalchemy.org/en/14/core/tutorial.html#using-textual-sql"
                    ],
                    priority=1
                ),
                "Express.js": RemediationAdvice(
                    vulnerability_type="SQL Injection",
                    framework="Express.js",
                    description="Use parameterized queries or an ORM like Sequelize",
                    code_example='''// VULNERABLE:
db.query(`SELECT * FROM users WHERE id = '${userId}'`);

// SECURE - Parameterized (mysql2):
db.execute('SELECT * FROM users WHERE id = ?', [userId]);

// SECURE - Sequelize ORM:
User.findByPk(userId);''',
                    references=[
                        "https://sequelize.org/docs/v6/",
                        "https://github.com/sidorares/node-mysql2#using-prepared-statements"
                    ],
                    priority=1
                ),
                "generic": RemediationAdvice(
                    vulnerability_type="SQL Injection",
                    framework="Generic",
                    description="Always use parameterized queries or prepared statements",
                    code_example='''General Principles:
1. Never concatenate user input into SQL queries
2. Use parameterized queries/prepared statements
3. Use ORM frameworks when possible
4. Apply input validation as defense in depth
5. Use least privilege database accounts
6. Never expose SQL error messages to users''',
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/89.html"
                    ],
                    priority=1
                )
            },
            "Cross-Site Scripting": {
                "Django": RemediationAdvice(
                    vulnerability_type="Cross-Site Scripting",
                    framework="Django",
                    description="Django auto-escapes by default. Avoid using |safe filter or mark_safe()",
                    code_example='''# SECURE - Auto-escaped:
{{ user_input }}

# VULNERABLE - Bypass escaping:
{{ user_input|safe }}
{% autoescape off %}{{ user_input }}{% endautoescape %}

# For JSON in templates:
{{ value|json_script:"my-data" }}''',
                    references=[
                        "https://docs.djangoproject.com/en/4.0/topics/security/#cross-site-scripting-xss-protection"
                    ],
                    priority=1
                ),
                "React": RemediationAdvice(
                    vulnerability_type="Cross-Site Scripting",
                    framework="React",
                    description="React escapes by default. Avoid dangerouslySetInnerHTML",
                    code_example='''// SECURE - React auto-escapes:
<div>{userInput}</div>

// VULNERABLE:
<div dangerouslySetInnerHTML={{__html: userInput}} />

// If HTML needed, sanitize first:
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />''',
                    references=[
                        "https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml",
                        "https://github.com/cure53/DOMPurify"
                    ],
                    priority=1
                ),
                "generic": RemediationAdvice(
                    vulnerability_type="Cross-Site Scripting",
                    framework="Generic",
                    description="Encode output based on context (HTML, JavaScript, URL, CSS)",
                    code_example='''General Principles:
1. HTML encode user input: < becomes &lt;
2. JavaScript encode for JS context
3. URL encode for URL parameters
4. Use Content-Security-Policy headers
5. Set HttpOnly flag on cookies
6. Use modern frameworks with auto-escaping''',
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/79.html"
                    ],
                    priority=1
                )
            },
            "Missing Security Header": {
                "generic": RemediationAdvice(
                    vulnerability_type="Missing Security Headers",
                    framework="Generic",
                    description="Add security headers to HTTP responses",
                    code_example='''Recommended Security Headers:

# Prevent clickjacking
X-Frame-Options: DENY

# Prevent MIME sniffing
X-Content-Type-Options: nosniff

# Enable HSTS (HTTPS only)
Strict-Transport-Security: max-age=31536000; includeSubDomains

# Content Security Policy
Content-Security-Policy: default-src 'self'

# Referrer Policy
Referrer-Policy: strict-origin-when-cross-origin

# Permissions Policy
Permissions-Policy: geolocation=(), microphone=()''',
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://securityheaders.com/"
                    ],
                    priority=2
                ),
                "Nginx": RemediationAdvice(
                    vulnerability_type="Missing Security Headers",
                    framework="Nginx",
                    description="Add security headers in Nginx configuration",
                    code_example='''# nginx.conf or site config
server {
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}''',
                    references=[
                        "https://nginx.org/en/docs/http/ngx_http_headers_module.html"
                    ],
                    priority=2
                ),
                "Express.js": RemediationAdvice(
                    vulnerability_type="Missing Security Headers",
                    framework="Express.js",
                    description="Use Helmet.js middleware for security headers",
                    code_example='''const helmet = require('helmet');
const app = express();

// Use helmet with defaults
app.use(helmet());

// Or configure individually
app.use(helmet.frameguard({ action: 'deny' }));
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"]
    }
}));''',
                    references=[
                        "https://helmetjs.github.io/"
                    ],
                    priority=2
                )
            },
            "CSRF": {
                "Django": RemediationAdvice(
                    vulnerability_type="CSRF",
                    framework="Django",
                    description="Use Django's built-in CSRF protection",
                    code_example='''# Ensure middleware is enabled in settings.py
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
    ...
]

# In templates, use csrf_token
<form method="post">
    {% csrf_token %}
    ...
</form>

# For AJAX, include the token in headers''',
                    references=[
                        "https://docs.djangoproject.com/en/4.0/ref/csrf/"
                    ],
                    priority=1
                ),
                "generic": RemediationAdvice(
                    vulnerability_type="CSRF",
                    framework="Generic",
                    description="Implement CSRF tokens for state-changing operations",
                    code_example='''CSRF Prevention:
1. Generate unique token per session
2. Include token in forms as hidden field
3. Validate token on server for POST/PUT/DELETE
4. Use SameSite cookie attribute
5. Verify Origin/Referer headers''',
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                    ],
                    priority=1
                )
            }
        }
    
    def get_remediation(self, vulnerability_type: str, 
                        detected_tech: Dict) -> List[RemediationAdvice]:
        """Get remediation advice based on vulnerability and tech stack"""
        advice_list = []
        
        # Normalize vulnerability type
        vuln_key = None
        for key in self.knowledge_base.keys():
            if key.lower() in vulnerability_type.lower():
                vuln_key = key
                break
        
        if not vuln_key:
            return advice_list
        
        vuln_remediations = self.knowledge_base.get(vuln_key, {})
        
        # Get framework-specific advice
        for tech_name in detected_tech:
            if tech_name in vuln_remediations:
                advice_list.append(vuln_remediations[tech_name])
        
        # Add generic advice if available and no specific match
        if not advice_list and "generic" in vuln_remediations:
            advice_list.append(vuln_remediations["generic"])
        elif "generic" in vuln_remediations:
            # Add generic as additional context
            generic = vuln_remediations["generic"]
            if generic not in advice_list:
                advice_list.append(generic)
        
        return sorted(advice_list, key=lambda x: x.priority)