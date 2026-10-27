
import os
import secrets
import hashlib
import smtplib
import sqlite3
import time
import ssl

from email.message import EmailMessage
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Load environment variables from .env in this project directory
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "CHANGE-THIS-TO-A-LONG-RANDOM-SECRET",
)
DB_PATH = os.getenv("DATABASE_PATH", "shieldgate.db")

OTP_TTL_SECONDS = 300
MAX_OTP_ATTEMPTS = 5


# -------------------- DATABASE --------------------

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)


# -------------------- OTP FUNCTIONS --------------------

def make_otp():
    return f"{secrets.randbelow(1_000_000):06d}"


def otp_digest(code, salt):
    return hashlib.sha256(
        (salt + code).encode("utf-8")
    ).hexdigest()


def send_otp_email(recipient, otp):
    sender = os.getenv("GMAIL_ADDRESS", "").strip()
    app_password = os.getenv(
        "GMAIL_APP_PASSWORD", ""
    ).replace(" ", "").strip()

    if not sender or not app_password:
        raise RuntimeError(
            "GMAIL_ADDRESS and GMAIL_APP_PASSWORD must be configured in .env."
        )

    message = EmailMessage()
    message["Subject"] = "Your ShieldGate login verification code"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Your ShieldGate verification code is: {otp}\n\n"
        "This code expires in 5 minutes. Do not share it with anyone.\n"
        "If you did not try to sign in, you can ignore this email."
    )

    
    # Gmail SMTP using STARTTLS on port 587
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ssl.create_default_context())
        smtp.ehlo()
        smtp.login(sender, app_password)
        smtp.send_message(message)



# -------------------- LOGIN PROTECTION --------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


# -------------------- HOME --------------------

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    return render_template("index.html")


# -------------------- REGISTRATION --------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or len(password) < 8:
            flash(
                "Enter your name, a valid email, and a password "
                "with at least 8 characters.",
                "danger",
            )
            return render_template("register.html")

        try:
            with db() as conn:
                conn.execute(
                    """
                    INSERT INTO users
                    (name, email, password_hash, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        name,
                        email,
                        generate_password_hash(password),
                        int(time.time()),
                    ),
                )

            flash(
                "Account created. You can now log in with MFA.",
                "success",
            )
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash(
                "An account with that email already exists.",
                "danger",
            )

    return render_template("register.html")


# -------------------- LOGIN / SEND OTP --------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,),
            ).fetchone()

        if not user or not check_password_hash(
            user["password_hash"], password
        ):
            flash("Invalid email or password.", "danger")
            return render_template("login.html")

        code = make_otp()
        salt = secrets.token_hex(16)

        try:
            send_otp_email(user["email"], code)

        except Exception:
            app.logger.exception("Unable to send login OTP")
            flash(
                "Could not send the OTP email. "
                "Check the Gmail settings in .env and the server log.",
                "danger",
            )
            return render_template("login.html")

        session.clear()
        session["pending_user_id"] = user["id"]
        session["otp_hash"] = otp_digest(code, salt)
        session["otp_salt"] = salt
        session["otp_expires"] = int(time.time()) + OTP_TTL_SECONDS
        session["otp_attempts"] = 0

        flash(
            "A 6-digit verification code was sent to your email.",
            "success",
        )
        return redirect(url_for("verify_otp"))

    return render_template("login.html")


# -------------------- VERIFY OTP --------------------

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if not session.get("pending_user_id"):
        return redirect(url_for("login"))

    if request.method == "POST":
        if int(time.time()) > session.get("otp_expires", 0):
            session.clear()
            flash(
                "The OTP expired. Please log in again to request a new code.",
                "warning",
            )
            return redirect(url_for("login"))

        attempts = session.get("otp_attempts", 0)

        if attempts >= MAX_OTP_ATTEMPTS:
            session.clear()
            flash(
                "Too many incorrect attempts. Please log in again.",
                "danger",
            )
            return redirect(url_for("login"))

        code = request.form.get("otp", "").strip()
        expected = session.get("otp_hash", "")
        salt = session.get("otp_salt", "")

        if (
            len(code) == 6
            and code.isdigit()
            and secrets.compare_digest(
                otp_digest(code, salt),
                expected,
            )
        ):
            user_id = session["pending_user_id"]
            session.clear()
            session["user_id"] = user_id

            flash("MFA verification successful.", "success")
            return redirect(url_for("dashboard"))

        session["otp_attempts"] = attempts + 1
        remaining = MAX_OTP_ATTEMPTS - session["otp_attempts"]

        flash(
            f"Incorrect OTP. Attempts remaining: {remaining}.",
            "danger",
        )

    return render_template("verify_otp.html")


# -------------------- DASHBOARD --------------------

@app.route("/dashboard")
@login_required
def dashboard():
    with db() as conn:
        user = conn.execute(
            "SELECT name, email FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=user)


# -------------------- LOGOUT --------------------

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


# -------------------- ERROR HANDLER --------------------

@app.errorhandler(500)
def server_error(_error):
    return render_template("error.html"), 500


# -------------------- START APPLICATION --------------------

init_db()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
    )
