EduPlus Student Portal (Intentionally Vulnerable)
=================================================

This is a deliberately vulnerable Flask + SQLite student portal for academic security exercises.

Quick start
-----------

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app.py
export FLASK_ENV=development
flask run -p 5000
```

Default users (passwords are plaintext in DB):
- admin: admin / password123
- teacher: alice / password123
- student: bob / password123

WARNING: Do NOT deploy to the internet. This app is intentionally insecure.

Deliberate vulnerabilities (10)
-------------------------------
- 1) SQL Injection: String-concatenated queries in `app.py` login and search.
- 2) Plaintext passwords: User passwords stored and compared in plaintext.
- 3) Stored XSS: Assignment descriptions rendered with `|safe` in teacher and student views.
- 4) Unrestricted file upload: No validation of type/size; uploads saved under user folder.
- 5) Unsafe filename handling: Raw `f.filename` used (no `secure_filename`).
- 6) IDOR: Teachers can grade any submission by ID without ownership checks.
- 7) Path traversal: `/download?path=...` serves arbitrary filesystem paths.
- 8) Open redirect: `next` parameter on login is not validated.
- 9) Hardcoded weak secret key: Static `app.secret_key = "secret123"`.
- 10) Debug mode: App runs with `debug=True` in `__main__`.

Basic roles and flows
---------------------
- Admin: Create users at `/admin/users`.
- Teacher: Create assignments and view them at `/teacher/assignments`.
- Student: View assignments, upload at `/student/assignments` and `/student/upload/<id>`.

Initialize database
-------------------
```bash
python init_db.py
```

Notes
-----
- Files are stored in `uploads/<username>/` with original names.
- This app is for demonstration/testing of security tools only.


