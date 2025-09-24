import os
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse
from flask import (
    Flask, request, redirect, url_for, render_template, session, send_file, flash, abort
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


# Secure configuration
app = Flask(__name__)
app.secret_key = os.environ.get("PORTAL_SECRET", os.urandom(32))
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB upload limit

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
    # Secure login with parameterized query and password hashing
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        conn.close()
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    # Secure register with hashing and basic policy
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "student")
        if role not in ("student", "teacher"):
            role = "student"
        if len(password) < 8:
            flash("Password must be at least 8 characters long")
            return render_template("register.html")
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users(username, password, role) VALUES(?,?,?)", (username, generate_password_hash(password), role))
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
    if session.get("role") != "admin":
        abort(403)
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "student")
        if role not in ("student", "teacher", "admin"):
            role = "student"
        if len(password) < 8:
            flash("Password must be at least 8 characters long")
        else:
            try:
                cur.execute("INSERT INTO users(username, password, role) VALUES(?,?,?)", (username, generate_password_hash(password), role))
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
        title = request.form.get("title")
        description = request.form.get("description")
        due_date = request.form.get("due_date")
        teacher_id = session.get("user_id")
        cur.execute(
            "INSERT INTO assignments(title, description, teacher_id, due_date) VALUES(?,?,?,?)",
            (title, description, teacher_id, due_date),
        )
        conn.commit()
        flash("Assignment created")
    cur.execute(
        "SELECT a.id, a.title, a.description, a.due_date FROM assignments a WHERE a.teacher_id = ? ORDER BY a.id DESC",
        (session.get('user_id'),)
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
    if session.get("role") != "teacher":
        abort(403)
    conn = get_db()
    cur = conn.cursor()
    # Verify teacher owns assignment for this submission
    cur.execute(
        """
        SELECT s.id, s.filename, s.grade, s.feedback, u.username as student, a.title as assignment_title, a.teacher_id
        FROM submissions s
        JOIN users u ON s.student_id = u.id
        JOIN assignments a ON s.assignment_id = a.id
        WHERE s.id = ?
        """,
        (submission_id,),
    )
    sub = cur.fetchone()
    if not sub:
        conn.close()
        abort(404)
    if sub["teacher_id"] != session.get("user_id"):
        conn.close()
        abort(403)
    if request.method == "POST":
        grade = request.form.get("grade")
        feedback = request.form.get("feedback")
        cur.execute(
            "UPDATE submissions SET grade = ?, feedback = ? WHERE id = ?",
            (grade, feedback, submission_id),
        )
        conn.commit()
        flash("Submission graded")
    conn.close()
    return render_template("grade.html", sub=sub)


# --------------------- Student: Assignments & Uploads ---------------------
@app.route("/student/assignments")
def student_assignments():
    if session.get("role") != "student":
        abort(403)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, title, description, due_date FROM assignments ORDER BY id DESC")
    assignments = cur.fetchall()
    cur.execute(
        "SELECT s.id, s.assignment_id, s.filename, s.grade FROM submissions s WHERE s.student_id = ? ORDER BY s.id DESC",
        (session.get('user_id'),)
    )
    submissions = cur.fetchall()
    conn.close()
    return render_template("student_assignments.html", assignments=assignments, submissions=submissions)


ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "zip"}

def is_allowed(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/student/upload/<int:assignment_id>", methods=["GET", "POST"])
def upload_assignment(assignment_id: int):
    if session.get("role") != "student":
        abort(403)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, title, due_date FROM assignments WHERE id = ?", (assignment_id,))
    assignment = cur.fetchone()
    if not assignment:
        conn.close()
        abort(404)
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("No file selected")
            return redirect(request.url)
        if not is_allowed(f.filename):
            flash("File type not allowed")
            return redirect(request.url)
        # Enforce deadline
        due = assignment["due_date"]
        if due:
            try:
                due_dt = datetime.fromisoformat(due)
                now = datetime.now(timezone.utc)
                if due_dt.tzinfo is None:
                    # assume local/naive, compare to naive now
                    now = datetime.utcnow()
                if now > due_dt:
                    flash("Deadline has passed; submissions are closed")
                    return redirect(url_for("student_assignments"))
            except Exception:
                pass
        student_name = session.get("username")
        user_dir = os.path.join(UPLOAD_DIR, secure_filename(student_name))
        os.makedirs(user_dir, exist_ok=True)
        safe_name = secure_filename(f.filename)
        file_path = os.path.join(user_dir, safe_name)
        f.save(file_path)
        cur.execute(
            "INSERT INTO submissions(assignment_id, student_id, filename) VALUES(?,?,?)",
            (assignment_id, session.get('user_id'), file_path),
        )
        conn.commit()
        flash("Uploaded")
        conn.close()
        return redirect(url_for("student_assignments"))
    conn.close()
    return render_template("upload.html", assignment=assignment)


@app.route("/download")
def download():
    path = request.args.get("path")
    if not path:
        abort(400)
    real = os.path.realpath(path)
    if not real.startswith(os.path.realpath(UPLOAD_DIR) + os.sep):
        abort(403)
    if not os.path.isfile(real):
        abort(404)
    return send_file(real, as_attachment=True)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role FROM users WHERE username LIKE ? ORDER BY id DESC", (f"%{q}%",))
    results = cur.fetchall()
    conn.close()
    return render_template("search.html", q=q, results=results)


@app.route("/student/view_grades")
def view_grades():
    if "user_id" not in session:
        return redirect(url_for("login"))
    student_id = session.get("user_id")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT s.id, s.assignment_id, s.grade FROM submissions s WHERE s.student_id = ? ORDER BY s.id DESC",
        (student_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return render_template("view_grades.html", rows=rows, student_id=student_id)


# Removed insecure grade tampering endpoint


@app.route("/student/comments/<int:assignment_id>", methods=["GET", "POST"])
def comments(assignment_id: int):
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        content = request.form.get("content", "")
        cur.execute(
            "INSERT INTO comments(user_id, assignment_id, content, created_at) VALUES(?,?,?,?)",
            (session.get('user_id'), assignment_id, content, datetime.utcnow().isoformat()),
        )
        conn.commit()
    cur.execute(
        "SELECT c.id, u.username, c.content, c.created_at FROM comments c JOIN users u ON c.user_id=u.id WHERE c.assignment_id = ? ORDER BY c.id DESC",
        (assignment_id,)
    )
    items = cur.fetchall()
    cur.execute("SELECT id, title FROM assignments WHERE id = ?", (assignment_id,))
    assignment = cur.fetchone()
    conn.close()
    return render_template("comments.html", items=items, assignment=assignment)


# Removed sensitive data exposure endpoint


# Removed DoS endpoint


# Removed command execution endpoint


@app.template_filter("datetime")
def format_datetime(value: str):
    try:
        return datetime.fromisoformat(value).strftime("%b %d, %Y")
    except Exception:
        return value


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)


