
import os
import sqlite3
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-for-local-testing")
DB_PATH = os.environ.get("DB_PATH", "queen.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    db.commit()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)
    return wrapper


@app.route("/")
def index():
    return render_template("index.html", page="home")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(password) < 10:
            flash("Username must be 3+ characters and password 10+ characters.")
            return redirect(url_for("register"))

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return redirect(url_for("register"))

        flash("Account created. Please log in.")
        return redirect(url_for("login"))

    return render_template("index.html", page="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")

    return render_template("index.html", page="login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute(
        "SELECT id, username, balance FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()
    requests_list = db.execute(
        "SELECT * FROM requests WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],)
    ).fetchall()
    return render_template(
        "index.html", page="dashboard",
        user=user, requests_list=requests_list
    )


@app.route("/request", methods=["POST"])
@login_required
def create_request():
    kind = request.form.get("kind", "")
    try:
        amount = float(request.form.get("amount", "0"))
    except ValueError:
        amount = 0

    if kind not in ("Deposit", "Withdrawal") or not (0 < amount <= 100000):
        flash("Invalid request amount or type.")
        return redirect(url_for("dashboard"))

    db = get_db()
    user = db.execute(
        "SELECT balance FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if kind == "Withdrawal" and amount > user["balance"]:
        flash("Insufficient available balance.")
        return redirect(url_for("dashboard"))

    db.execute(
        "INSERT INTO requests (user_id, kind, amount) VALUES (?, ?, ?)",
        (session["user_id"], kind, amount)
    )
    db.commit()
    flash("Request submitted for manual review.")
    return redirect(url_for("dashboard"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")
        expected = os.environ.get("ADMIN_PASSWORD", "")

        if expected and password == expected:
            session.clear()
            session["is_admin"] = True
            return redirect(url_for("admin"))

        flash("Invalid admin password.")

    return render_template("index.html", page="admin_login")


@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    requests_list = db.execute("""
        SELECT requests.*, users.username
        FROM requests JOIN users ON users.id = requests.user_id
        ORDER BY requests.id DESC
    """).fetchall()
    return render_template(
        "index.html", page="admin", requests_list=requests_list
    )


@app.route("/admin/review/<int:request_id>", methods=["POST"])
@admin_required
def review_request(request_id):
    decision = request.form.get("decision")
    if decision not in ("Approve", "Reject"):
        flash("Invalid decision.")
        return redirect(url_for("admin"))

    db = get_db()
    item = db.execute(
        "SELECT * FROM requests WHERE id = ?", (request_id,)
    ).fetchone()

    if not item or item["status"] != "Pending":
        flash("Request not found or already reviewed.")
        return redirect(url_for("admin"))

    if decision == "Approve":
        amount = item["amount"]
        user_id = item["user_id"]

        if item["kind"] == "Deposit":
            db.execute(
                "UPDATE users SET balance = balance + ? WHERE id = ?",
                (amount, user_id)
            )
        else:
            result = db.execute(
                """UPDATE users SET balance = balance - ?
                   WHERE id = ? AND balance >= ?""",
                (amount, user_id, amount)
            )
            if result.rowcount != 1:
                flash("Withdrawal cannot be approved: insufficient balance.")
                return redirect(url_for("admin"))

    db.execute(
        "UPDATE requests SET status = ? WHERE id = ?",
        (decision, request_id)
    )
    db.commit()
    flash("Request reviewed.")
    return redirect(url_for("admin"))


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


with app.app_context():
    init_db()
