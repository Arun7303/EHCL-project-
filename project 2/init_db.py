import sqlite3
import os
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "portal.db")

schema = """
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS assignments;
DROP TABLE IF EXISTS submissions;
DROP TABLE IF EXISTS comments;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  role TEXT
);

CREATE TABLE assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  description TEXT,
  teacher_id INTEGER,
  due_date TEXT
);

CREATE TABLE submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  assignment_id INTEGER,
  student_id INTEGER,
  filename TEXT,
  grade TEXT,
  feedback TEXT
);

CREATE TABLE comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  assignment_id INTEGER,
  content TEXT,
  created_at TEXT
);
"""

seed_plain = [
    ("admin", "password123", "admin"),
    ("t1", "password123", "teacher"),
    ("s1", "password123", "student"),
]

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript(schema)
    seed_hashed = [(u, generate_password_hash(p), r) for (u, p, r) in seed_plain]
    cur.executemany("INSERT INTO users(username, password, role) VALUES(?,?,?)", seed_hashed)
    conn.commit()
    conn.close()
    print("Database initialized at", DB_PATH)

if __name__ == "__main__":
    main()


