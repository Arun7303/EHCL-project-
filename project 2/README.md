EduPlus Student Portal
======================

This repository presents two modes of the portal:

- Project 1 (Vulnerable): Intentionally insecure build for security exercises.
- Project 2 (Secure): Hardened build with secure coding practices applied.

Quick start (Project 2 – Secure)
--------------------------------
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app.py
flask run -p 5000
```

Default users (passwords hashed in DB):
- admin: admin / password123
- teacher: t1 / password123
- student: s1 / password123

Initialize database (recreate DB)
---------------------------------
```bash
python init_db.py
```

Project 1 (Vulnerable) – Attacks possible
-----------------------------------------
- SQL Injection in login and search
- Plaintext passwords and weak password policy
- Stored XSS in assignment descriptions and comments
- Unrestricted file upload and unsafe filenames
- Broken access control (admin dashboard, grading IDOR)
- Path traversal on download
- Open redirect on login
- Debug mode enabled and weak secret key
- Sensitive data exposure via unauthenticated API
- DoS and command execution endpoints

Project 2 (Secure) – Measures taken
-----------------------------------
- Parameterized SQL everywhere to prevent SQL injection
- Passwords hashed (Werkzeug PBKDF2) and minimum length policy (>= 8)
- No unsafe `|safe` rendering; user content is escaped by default
- Secure file handling: allowed extensions, `secure_filename`, validated path, size limit
- Proper authorization: admin-only areas; teacher must own assignments to grade; students see only their grades
- Safe downloads restricted to `uploads/`
- Removed open redirect; login redirects to dashboard
- Strong secret key from env (`PORTAL_SECRET`); debug disabled
- Removed sensitive APIs, DoS, and command execution endpoints

Roles and flows
---------------
- Admin: Create users at `/admin/users` (passwords stored hashed).
- Teacher: Create assignments and grade submissions for owned assignments.
- Student: View assignments, submit before deadline, and view only their grades.

Security notes
--------------
- Set `PORTAL_SECRET` in your environment for a persistent secret key.
- Use a production WSGI server and HTTPS in real deployments.


