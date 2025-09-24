import os
import sqlite3
from datetime import datetime
from flask import (
    Flask, request, redirect, url_for, render_template, session, send_file, flash, abort
)


# Intentionally weak secret key (Vulnerability #9: Hardcoded weak key)
app = Flask(__name__)
app.secret_key = "secret123"  # weak and hardcoded

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "portal.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/", methods=["GET", "POST"])
def login():
    # Vulnerability #1: SQL Injection via string concatenation
    # Vulnerability #8: Open redirect via unvalidated next parameter
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        next_url = request.args.get("next", url_for("dashboard"))
        conn = get_db()
        cur = conn.cursor()
        query = f"SELECT id, username, password, role FROM users WHERE username = '{username}' AND password = '{password}'"
        cur.execute(query)
        user = cur.fetchone()
        conn.close()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            # Open redirect: no validation of next_url
            return redirect(next_url)
        flash("Invalid credentials")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    # Vulnerability #2: weak password policy & plaintext storage
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        role = request.form.get("role", "student")
        if len(password) < 3:  # weak policy, intentionally short
            flash("Password can be as short as 3 characters (intentionally weak)")
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                f"INSERT INTO users(username, password, role) VALUES('{username}', '{password}', '{role}')"
            )
            conn.commit()
            flash("Registered successfully. Please log in.")
            return redirect(url_for("login"))
        except Exception as e:
            flash(str(e))
        finally:
            conn.close()
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login", next=url_for("dashboard")))
    role = session.get("role")
    if role == "admin":
        return redirect(url_for("admin_users"))
    if role == "teacher":
        return redirect(url_for("teacher_assignments"))
    return redirect(url_for("student_assignments"))


# --------------------- Admin: Manage Users ---------------------
@app.route("/admin/users", methods=["GET", "POST"])
def admin_users():
    # Minimal authorization check (easily bypassed elsewhere)
    if session.get("role") != "admin":
        abort(403)
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        # Vulnerability #2: Plaintext passwords stored; #1 raw SQL concatenation
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        role = request.form.get("role", "student")
        try:
            cur.execute(
                f"INSERT INTO users(username, password, role) VALUES('{username}', '{password}', '{role}')"
            )
            conn.commit()
            flash("User created")
        except Exception as e:
            flash(f"Error: {e}")
    cur.execute("SELECT id, username, role FROM users ORDER BY id DESC")
    users = cur.fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)


@app.route("/admin/dashboard")
def admin_dashboard():
    # Vulnerability #3: Broken access control (no role check)
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, password FROM users ORDER BY id")
    users = cur.fetchall()
    conn.close()
    return render_template("admin_dashboard.html", users=users)


# --------------------- Teacher: Assignments ---------------------
@app.route("/teacher/assignments", methods=["GET", "POST"])
def teacher_assignments():
    if session.get("role") != "teacher":
        abort(403)
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        # Vulnerability #3: Stored XSS via HTML in description rendered as safe
        title = request.form.get("title")
        description = request.form.get("description")  # allow HTML
        due_date = request.form.get("due_date")
        teacher_id = session.get("user_id")
        cur.execute(
            f"INSERT INTO assignments(title, description, teacher_id, due_date) VALUES('{title}', '{description}', {teacher_id}, '{due_date}')"
        )
        conn.commit()
        flash("Assignment created")
    cur.execute(
        f"SELECT a.id, a.title, a.description, a.due_date FROM assignments a WHERE a.teacher_id = {session.get('user_id')} ORDER BY a.id DESC"
    )
    assignments = cur.fetchall()
    conn.close()
    return render_template("teacher_assignments.html", assignments=assignments)


@app.route("/teacher/submissions")
def teacher_submissions():
    # List all submissions for assignments created by the logged-in teacher
    if session.get("role") != "teacher":
        abort(403)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT s.id as submission_id,
               a.title as assignment_title,
               u.username as student,
               s.grade as grade,
               s.filename as filename
        FROM submissions s
        JOIN assignments a ON s.assignment_id = a.id
        JOIN users u ON s.student_id = u.id
        WHERE a.teacher_id = {session.get('user_id')}
        ORDER BY s.id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return render_template("teacher_submissions.html", rows=rows)


@app.route("/teacher/grade/<int:submission_id>", methods=["GET", "POST"])
def grade_submission(submission_id: int):
    # Vulnerability #6: IDOR – no check that teacher owns this assignment
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        grade = request.form.get("grade")
        feedback = request.form.get("feedback")
        cur.execute(
            f"UPDATE submissions SET grade = '{grade}', feedback = '{feedback}' WHERE id = {submission_id}"
        )
        conn.commit()
        flash("Submission graded")
    cur.execute(
        f"SELECT s.id, s.filename, s.grade, s.feedback, u.username as student, a.title as assignment_title FROM submissions s JOIN users u ON s.student_id = u.id JOIN assignments a ON s.assignment_id = a.id WHERE s.id = {submission_id}"
    )
    sub = cur.fetchone()
    conn.close()
    if not sub:
        abort(404)
    return render_template("grade.html", sub=sub)


# --------------------- Student: Assignments & Uploads ---------------------
@app.route("/student/assignments")
def student_assignments():
    if session.get("role") != "student":
        abort(403)
    conn = get_db()
    cur = conn.cursor()
    # All assignments visible
    cur.execute("SELECT id, title, description, due_date FROM assignments ORDER BY id DESC")
    assignments = cur.fetchall()
    # Student submissions
    cur.execute(
        f"SELECT s.id, s.assignment_id, s.filename, s.grade FROM submissions s WHERE s.student_id = {session.get('user_id')} ORDER BY s.id DESC"
    )
    submissions = cur.fetchall()
    conn.close()
    return render_template("student_assignments.html", assignments=assignments, submissions=submissions)


@app.route("/student/upload/<int:assignment_id>", methods=["GET", "POST"])
def upload_assignment(assignment_id: int):
    if session.get("role") != "student":
        abort(403)
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        f = request.files.get("file")
        if not f:
            flash("No file")
            return redirect(request.url)
        # Vulnerability #4: Unrestricted file upload (no type/size checks)
        # Vulnerability #5: Unsafe filename handling (no secure_filename)
        student_name = session.get("username")
        user_dir = os.path.join(UPLOAD_DIR, student_name)
        os.makedirs(user_dir, exist_ok=True)
        file_path = os.path.join(user_dir, f.filename)
        f.save(file_path)
        # Vulnerability #4: Missing server-side deadline validation (not checked)
        cur.execute(
            f"INSERT INTO submissions(assignment_id, student_id, filename) VALUES({assignment_id}, {session.get('user_id')}, '{file_path}')"
        )
        conn.commit()
        flash("Uploaded")
        return redirect(url_for("student_assignments"))
    # Minimal page w/ assignment info
    cur.execute(f"SELECT id, title FROM assignments WHERE id = {assignment_id}")
    assignment = cur.fetchone()
    conn.close()
    if not assignment:
        abort(404)
    return render_template("upload.html", assignment=assignment)


@app.route("/download")
def download():
    # Vulnerability #7: Path traversal in download (trusting path param)
    path = request.args.get("path")
    if not path:
        abort(400)
    try:
        return send_file(path, as_attachment=True)
    except Exception:
        abort(404)


@app.route("/search")
def search():
    # Vulnerability #1 again: SQLi in search
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        f"SELECT id, username, role FROM users WHERE username LIKE '%{q}%' ORDER BY id DESC"
    )
    results = cur.fetchall()
    conn.close()
    return render_template("search.html", q=q, results=results)


@app.route("/student/view_grades")
def view_grades():
    # Vulnerability #5: IDOR via student_id param
    if "user_id" not in session:
        return redirect(url_for("login"))
    student_id = request.args.get("student_id", session.get("user_id"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        f"SELECT s.id, s.assignment_id, s.grade FROM submissions s WHERE s.student_id = {student_id} ORDER BY s.id DESC"
    )
    rows = cur.fetchall()
    conn.close()
    return render_template("view_grades.html", rows=rows, student_id=student_id)


@app.route("/student/update_grade", methods=["POST"])
def update_grade():
    # Vulnerability #6: Grade tampering endpoint exposed to students
    if "user_id" not in session:
        return redirect(url_for("login"))
    submission_id = request.form.get("submission_id")
    new_grade = request.form.get("grade")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        f"UPDATE submissions SET grade = '{new_grade}' WHERE id = {submission_id}"
    )
    conn.commit()
    conn.close()
    flash("Grade updated (insecure endpoint)")
    return redirect(url_for("view_grades"))


@app.route("/student/comments/<int:assignment_id>", methods=["GET", "POST"])
def comments(assignment_id: int):
    # Vulnerability #7: Stored XSS in comments (now tied to assignment)
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        content = request.form.get("content", "")
        cur.execute(
            f"INSERT INTO comments(user_id, assignment_id, content, created_at) VALUES({session.get('user_id')}, {assignment_id}, '{content}', '{datetime.utcnow().isoformat()}')"
        )
        conn.commit()
    cur.execute(
        f"SELECT c.id, u.username, c.content, c.created_at FROM comments c JOIN users u ON c.user_id=u.id WHERE c.assignment_id = {assignment_id} ORDER BY c.id DESC"
    )
    items = cur.fetchall()
    cur.execute(f"SELECT id, title FROM assignments WHERE id = {assignment_id}")
    assignment = cur.fetchone()
    conn.close()
    return render_template("comments.html", items=items, assignment=assignment)


@app.route("/api/users")
def api_users():
    # Vulnerability #8 (new): Sensitive Data Exposure
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, password FROM users")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"users": rows}


@app.route("/api/dos")
def api_dos():
    # Vulnerability #9 (new): CPU DoS via heavy loop
    n = int(request.args.get("n", 50000000))
    total = 0
    for i in range(n):
        total += (i * i) % 97
    return {"result": total, "n": n}


@app.route("/execute", methods=["GET", "POST"])
def execute():
    # Vulnerability #10 (new): Command injection for authenticated users
    if "user_id" not in session:
        return redirect(url_for("login"))
    output = ""
    if request.method == "POST":
        cmd = request.form.get("cmd", "")
        # Directly pass to shell (dangerous)
        output = os.popen(cmd).read()
    return render_template("execute.html", output=output)


@app.template_filter("datetime")
def format_datetime(value: str):
    try:
        return datetime.fromisoformat(value).strftime("%b %d, %Y")
    except Exception:
        return value


if __name__ == "__main__":
    # Vulnerability #10: Debug mode enabled in production-like run
    app.run(host="0.0.0.0", port=5000, debug=True)


