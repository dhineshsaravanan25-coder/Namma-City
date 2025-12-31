from flask import Flask, render_template, request, redirect, session,render_template
import sqlite3, os, random,smtplib,requests
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash, check_password_hash

import requests

from dotenv import load_dotenv

load_dotenv()

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
BREVO_SENDER_EMAIL = os.getenv("BREVO_SENDER_EMAIL")
BREVO_SENDER_NAME = "Namma City"


def send_email(to_email, subject, html_content):
    url = "https://api.brevo.com/v3/smtp/email"

    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }

    payload = {
        "sender": {
            "name": BREVO_SENDER_NAME,
            "email": BREVO_SENDER_EMAIL
        },
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_content
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code not in (200, 201):
        raise Exception("Brevo error: " + response.text)


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_key")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "egovdb.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT,
            created_by INTEGER,
            is_active INTEGER DEFAULT 1
        )
    """)

    db.execute("""
    CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        category TEXT,
        location TEXT,
        latitude TEXT,
        longitude TEXT,
        photo TEXT,
        status TEXT DEFAULT 'Pending',

        citizen_id INTEGER,
        panchayat_id INTEGER,
        inspector_id INTEGER,
        
        rating INTEGER,
        feedback TEXT,

        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
""")


    db.execute("""
        CREATE TABLE IF NOT EXISTS status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id INTEGER,
            old_status TEXT,
            new_status TEXT,
            updated_by TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS otp_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            otp TEXT,
            expires_at DATETIME
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS complaint_upvotes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (complaint_id, user_id)
        )
    """)

    db.commit()
    db.close()

    



def migrate_db():
    db = get_db()
    try:
        db.execute(
            "ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1"
        )
        db.commit()
        print("Migration success: is_active added")
    except sqlite3.OperationalError:
        # Column already exists
        pass
    finally:
        db.close()


init_db()
migrate_db()

def migrate_add_panchayat_and_inspector():
    db = get_db()
    try:
        db.execute("ALTER TABLE complaints ADD COLUMN panchayat_id INTEGER")
    except sqlite3.OperationalError:
        pass

    try:
        db.execute("ALTER TABLE complaints ADD COLUMN inspector_id INTEGER")
    except sqlite3.OperationalError:
        pass

    db.commit()
    db.close()

with app.app_context():
    migrate_add_panchayat_and_inspector()

def migrate_add_feedback():
    db = get_db()
    try:
        db.execute("ALTER TABLE complaints ADD COLUMN rating INTEGER")
    except sqlite3.OperationalError:
        pass

    try:
        db.execute("ALTER TABLE complaints ADD COLUMN feedback TEXT")
    except sqlite3.OperationalError:
        pass

    db.commit()
    db.close()

with app.app_context():
    migrate_add_feedback()


@app.route("/")
def login():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def do_login():
    email = request.form["email"]
    password = request.form["password"]

    db = get_db()
    user = db.execute("""
        SELECT * FROM users
        WHERE email=? AND is_active=1
    """, (email,)).fetchone()
    db.close()

    if user and check_password_hash(user["password"], password):
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        return redirect(f"/{user['role']}")

    return "Invalid login 🤦‍♀️"



from werkzeug.security import generate_password_hash

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            return "Passwords do not match! <a href='/register'>Try Again</a>"

        db = get_db()
        
        # Check if email exists
        existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            db.close()
            return "Email already registered. Try logging in."

        # Create INACTIVE user
        db.execute("""
            INSERT INTO users (name, email, password, role, is_active)
            VALUES (?, ?, ?, 'citizen', 0)
        """, (
            name,
            email,
            generate_password_hash(password)
        ))
        
        # Generate OTP
        otp = str(random.randint(100000, 999999))
        expires_at = datetime.now() + timedelta(minutes=10)

        # Store OTP
        db.execute(
            "INSERT INTO otp_requests (email, otp, expires_at) VALUES (?, ?, ?)",
            (email, otp, expires_at)
        )
        db.commit()
        db.close()

        # Send OTP Email
        try:
            html_content = f"""
                <h3>Welcome to Namma City!</h3>
                <p>Valued citizen,</p>
                <p>Your verification code is:</p>
                <h2>{otp}</h2>
                <p>Please enter this code to activate your account.</p>
            """
            send_email(email, "Verify Your Account", html_content)
        except Exception as e:
            print("Registration Email Failed:", e)
            # If email fails, deleting user so they can try again might be better, 
            # but for now let's just show the error and NOT redirect.
            return f"Error sending email: {e}. <a href='/register'>Try Again</a>"

        # Redirect to verification page with email in query param
        return redirect(f"/verify_registration?email={email}")

    return render_template("register.html")


@app.route("/verify_registration", methods=["GET", "POST"])
def verify_registration():
    if request.method == "POST":
        email = request.form["email"]
        otp = request.form["otp"]

        db = get_db()
        
        # Check Valid OTP
        record = db.execute("""
            SELECT * FROM otp_requests
            WHERE email=? AND otp=? AND expires_at > ?
        """, (email, otp, datetime.now())).fetchone()

        if record:
            # Activate User
            db.execute("UPDATE users SET is_active=1 WHERE email=?", (email,))
            
            # Get User Details for Auto-Login
            user = db.execute("SELECT id, role FROM users WHERE email=?", (email,)).fetchone()
            
            # Cleanup OTP
            db.execute("DELETE FROM otp_requests WHERE email=?", (email,))
            db.commit()
            db.close()
            
            # Auto-Login
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            
            return redirect(f"/{user['role']}")

        db.close()
        return "Invalid or Expired OTP. <a href='/register'>Try Again</a>"

    # GET request: Show form
    email = request.args.get("email", "")
    return render_template("verify_registration.html", email=email)



@app.route("/citizen")
def citizen_dashboard():
    db = get_db()

    complaints = db.execute("""
        SELECT
            c.*,
            COUNT(cu.id) AS upvotes,
            EXISTS(
                SELECT 1
                FROM complaint_upvotes cu2
                WHERE cu2.complaint_id = c.id
                  AND cu2.user_id = ?
            ) AS user_voted
        FROM complaints c
        LEFT JOIN complaint_upvotes cu ON c.id = cu.complaint_id
        GROUP BY c.id
        ORDER BY upvotes DESC, c.created_at DESC
    """, (session["user_id"],)).fetchall()

    db.close()
    return render_template("citizen_dashboard.html", complaints=complaints)


@app.route("/add_complaint", methods=["POST"])
def add_complaint():
    photo_file = request.files.get("photo")
    filename = None

    if photo_file and photo_file.filename:
        filename = datetime.now().strftime("%Y%m%d%H%M%S_") + photo_file.filename
        photo_file.save(os.path.join(UPLOAD_FOLDER, filename))

    location = request.form["location"]
    if not location or not location.strip():
        return "Location is mandatory! Please enable GPS and try again.", 400

    db = get_db()
    # Assign to first available Panchayat (Logic Placeholder)
    panchayat = db.execute("SELECT id FROM users WHERE role='panchayat' AND is_active=1 LIMIT 1").fetchone()
    panchayat_id = panchayat["id"] if panchayat else None

    db.execute("""
        INSERT INTO complaints
        (title, description, category, location, latitude, longitude, photo, citizen_id, panchayat_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        request.form["title"],
        request.form["description"],
        request.form["category"],
        request.form["location"],
        request.form["latitude"],
        request.form["longitude"],
        filename,
        session["user_id"],
        panchayat_id
    ))
    db.commit()
    db.close()
    return redirect("/citizen")


@app.route("/submit_feedback", methods=["POST"])
def submit_feedback():
    if session.get("role") != "citizen":
        return "Unauthorized", 403

    complaint_id = request.form["complaint_id"]
    rating = request.form["rating"]
    feedback = request.form["feedback"]

    db = get_db()
    
    # Verify complaint belongs to user and is resolved
    complaint = db.execute("""
        SELECT id FROM complaints 
        WHERE id=? AND citizen_id=? AND status='Resolved'
    """, (complaint_id, session["user_id"])).fetchone()

    if not complaint:
        db.close()
        return "Invalid Complaint or Status", 400

    db.execute("""
        UPDATE complaints
        SET rating = ?, feedback = ?
        WHERE id = ?
    """, (rating, feedback, complaint_id))
    
    db.commit()
    db.close()
    
    return redirect("/citizen")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/collector")
def collector_dashboard():
    if session.get("role") != "collector":
        return "Unauthorized", 403

    db = get_db()

    total_complaints = db.execute(
        "SELECT COUNT(*) FROM complaints"
    ).fetchone()[0]

    total_panchayats = db.execute(
        "SELECT COUNT(*) FROM users WHERE role='panchayat'"
    ).fetchone()[0]

    total_resolved = db.execute(
        "SELECT COUNT(*) FROM complaints WHERE status='Resolved'"
    ).fetchone()[0]

    db.close()

    return render_template(
        "collector_dashboard.html",
        total_complaints=total_complaints,
        total_panchayats=total_panchayats,
        total_resolved=total_resolved
    )

@app.route("/collector/panchayats")
def collector_panchayats():
    if session.get("role") != "collector":
        return "Unauthorized", 403

    db = get_db()
    panchayats = db.execute("""
        SELECT id, name, email, is_active
        FROM users
        WHERE role='panchayat'
        ORDER BY name
    """).fetchall()
    db.close()

    return render_template(
        "collector_panchayats.html",
        panchayats=panchayats
    )

@app.route("/collector/create_panchayat", methods=["POST"])
def create_panchayat():
    if session.get("role") != "collector":
        return "Unauthorized", 403

    name = request.form["name"].strip()
    email = request.form["email"].strip()
    password = request.form["password"]

    db = get_db()

    # Prevent duplicate email
    existing = db.execute(
        "SELECT id FROM users WHERE email=?",
        (email,)
    ).fetchone()

    if existing:
        db.close()
        return "Email already exists"

    db.execute("""
        INSERT INTO users
        (name, email, password, role, created_by, is_active)
        VALUES (?, ?, ?, 'panchayat', ?, 1)
    """, (
        name,
        email,
        generate_password_hash(password),  # 🔐 HASHED
        session["user_id"]
    ))

    db.commit()
    db.close()

    return redirect("/collector/panchayats")

@app.route("/collector/toggle_panchayat/<int:pid>")
def toggle_panchayat(pid):
    if session.get("role") != "collector":
        return "Unauthorized", 403

    db = get_db()
    db.execute("""
        UPDATE users
        SET is_active = CASE
            WHEN is_active = 1 THEN 0
            ELSE 1
        END
        WHERE id=? AND role='panchayat'
    """, (pid,))
    db.commit()
    db.close()

    return redirect("/collector/panchayats")

@app.route("/collector/complaints")
def collector_complaints():
    if session.get("role") != "collector":
        return "Unauthorized", 403

    db = get_db()

    complaints = db.execute("""
        SELECT
            c.id,
            c.title,
            c.status,
            c.photo,
            c.location,
            cu.name AS citizen_name,
            ins.name AS inspector_name

        FROM complaints c
        JOIN users cu ON c.citizen_id = cu.id
        LEFT JOIN users ins ON c.inspector_id = ins.id
        ORDER BY c.created_at DESC
    """).fetchall()

    db.close()

    return render_template(
        "collector_complaints.html",
        complaints=complaints
    )



@app.route("/panchayat")
def panchayat_dashboard():
    print("PANCHAYAT ROUTE HIT")
    print("SESSION:", dict(session))


    # Safety check (recommended)
    if "user_id" not in session or session.get("role") != "panchayat":
        return redirect("/login")

    db = get_db()

    # 1️⃣ Complaints with upvotes (FIXED)
    complaints = db.execute("""
        SELECT
            c.id,
            c.title,
            u.name AS citizen,
            c.status,
            COUNT(DISTINCT cu.id) AS upvotes,
            ins.name AS inspector_name
        FROM complaints c
        JOIN users u ON u.id = c.citizen_id
        LEFT JOIN complaint_upvotes cu ON cu.complaint_id = c.id
        LEFT JOIN users ins ON ins.id = c.inspector_id
        WHERE c.panchayat_id = ?
        GROUP BY
            c.id,
            c.title,
            u.name,
            c.status,
            ins.name
        ORDER BY upvotes DESC
    """, (session["user_id"],)).fetchall()

    # 2️⃣ Inspectors under this panchayat
    inspectors = db.execute("""
        SELECT id, name
        FROM users
        WHERE role = 'inspector'
          AND created_by = ?
          AND is_active = 1
    """, (session["user_id"],)).fetchall()

    # 3️⃣ Overview counts
    total_complaints = db.execute("""
        SELECT COUNT(*)
        FROM complaints
        WHERE panchayat_id = ?
    """, (session["user_id"],)).fetchone()[0]

    resolved_complaints = db.execute("""
        SELECT COUNT(*)
        FROM complaints
        WHERE panchayat_id = ?
          AND status = 'Resolved'
    """, (session["user_id"],)).fetchone()[0]

    db.close()

    return render_template(
        "panchayat_dashboard.html",
        complaints=complaints,
        inspectors=inspectors,
        total_complaints=total_complaints,
        resolved_complaints=resolved_complaints
    )


@app.route("/panchayat/create_inspector", methods=["POST"])
def create_inspector():
    if session.get("role") != "panchayat":
        return "Unauthorized", 403

    name = request.form["name"].strip()
    email = request.form["email"].strip()
    password = request.form["password"]

    db = get_db()

    # Prevent duplicate email
    existing = db.execute(
        "SELECT id FROM users WHERE email=?",
        (email,)
    ).fetchone()

    if existing:
        db.close()
        return "Email already exists"

    db.execute("""
        INSERT INTO users
        (name, email, password, role, created_by, is_active)
        VALUES (?, ?, ?, 'inspector', ?, 1)
    """, (
        name,
        email,
        generate_password_hash(password),
        session["user_id"]
    ))

    db.commit()
    db.close()

    return redirect("/panchayat")


@app.route("/panchayat/assign_inspector/<int:cid>", methods=["POST"])
def assign_inspector(cid):
    if session.get("role") != "panchayat":
        return "Unauthorized", 403

    inspector_id = request.form["inspector_id"]
    
    db = get_db()
    db.execute("""
        UPDATE complaints
        SET inspector_id = ?
        WHERE id = ? AND panchayat_id = ?
    """, (inspector_id, cid, session["user_id"]))
    db.commit()
    db.close()
    
    return redirect("/panchayat")


@app.route("/panchayat/update_status/<int:cid>", methods=["POST"])
def update_status(cid):
    if session.get("role") != "panchayat":
        return "Unauthorized", 403

    new_status = request.form["status"]
    
    db = get_db()
    
    # Get old status for history (optional but good practice)
    old_status = db.execute("SELECT status FROM complaints WHERE id=?", (cid,)).fetchone()[0]

    db.execute("""
        UPDATE complaints
        SET status = ?
        WHERE id = ? AND panchayat_id = ?
    """, (new_status, cid, session["user_id"]))

    # Log history
    db.execute("""
        INSERT INTO status_history (complaint_id, old_status, new_status, updated_by)
        VALUES (?, ?, ?, 'panchayat')
    """, (cid, old_status, new_status))

    db.commit()
    db.close()
    
    return redirect("/panchayat")


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip()
        otp = str(random.randint(100000, 999999))
        expires_at = datetime.now() + timedelta(minutes=5)

        db = get_db()

        # Check if active user exists
        user = db.execute(
            "SELECT id FROM users WHERE email=? AND is_active=1",
            (email,)
        ).fetchone()

        if user:
            # Remove any old OTPs for this email
            db.execute(
                "DELETE FROM otp_requests WHERE email=?",
                (email,)
            )

            # Store new OTP
            db.execute(
                """
                INSERT INTO otp_requests (email, otp, expires_at)
                VALUES (?, ?, ?)
                """,
                (email, otp, expires_at)
            )
            db.commit()

            # ✅ Send OTP via Brevo
            try:
                html_content = f"""
                    <p>Your OTP for password reset:</p>
                    <h2>{otp}</h2>
                    <p>This OTP is valid for 5 minutes.</p>
                    <p><b>Do not share this OTP.</b></p>
                """
                send_email(email, "Password Reset OTP", html_content)
            except Exception as e:
                print("Brevo email error:", e)
                # Do NOT reveal error to user (security)

        db.close()

        # Always redirect (even if email not found)
        return redirect("/reset_password")

    return render_template("forgot_password.html")

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form["email"]
        otp = request.form["otp"]
        new_password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if new_password != confirm_password:
            return "Passwords do not match! <a href='/reset_password'>Try Again</a>"

        db = get_db()
        record = db.execute("""
            SELECT * FROM otp_requests
            WHERE email=? AND otp=? AND expires_at > ?
        """, (email, otp, datetime.now())).fetchone()

        if record:
            db.execute(
                "UPDATE users SET password=? WHERE email=?",
                (new_password, email)
            )
            db.execute("DELETE FROM otp_requests WHERE email=?", (email,))
            db.commit()
            db.close()
            return redirect("/")

        db.close()
        return "Invalid or expired OTP"

    return render_template("reset_password.html")

@app.route("/upvote/<int:cid>")
def toggle_upvote(cid):
    if session.get("role") != "citizen":
        return "Unauthorized", 403

    user_id = session["user_id"]
    db = get_db()

    existing = db.execute("""
        SELECT id FROM complaint_upvotes
        WHERE complaint_id=? AND user_id=?
    """, (cid, user_id)).fetchone()

    if existing:
        # Remove upvote
        db.execute("""
            DELETE FROM complaint_upvotes
            WHERE complaint_id=? AND user_id=?
        """, (cid, user_id))
    else:
        # Add upvote
        db.execute("""
            INSERT INTO complaint_upvotes (complaint_id, user_id)
            VALUES (?, ?)
        """, (cid, user_id))

    db.commit()
    db.close()

    return redirect("/citizen")


@app.route("/inspector")
def inspector_dashboard():
    if session.get("role") != "inspector":
        return "Unauthorized", 403

    db = get_db()
    complaints = db.execute("""
        SELECT * FROM complaints
        WHERE inspector_id=?
        ORDER BY created_at DESC
    """, (session["user_id"],)).fetchall()
    db.close()

    return render_template("inspector_dashboard.html", complaints=complaints)


@app.route("/inspector/update_status/<int:cid>", methods=["POST"])
def inspector_update_status(cid):
    if session.get("role") != "inspector":
        return "Unauthorized", 403

    new_status = request.form["status"]
    
    # Restrict "Resolved" status for inspectors
    if new_status == "Resolved":
        return "Inspectors cannot resolve complaints directly.", 403

    db = get_db()
    
    # Get old status and panchayat info
    row = db.execute("""
        SELECT c.status, c.panchayat_id, u.email AS panchayat_email
        FROM complaints c
        JOIN users u ON c.panchayat_id = u.id
        WHERE c.id=?
    """, (cid,)).fetchone()
    
    old_status = row["status"]
    panchayat_email = row["panchayat_email"]

    db.execute("""
        UPDATE complaints
        SET status=?
        WHERE id=? AND inspector_id=?
    """, (new_status, cid, session["user_id"]))

    db.execute("""
        INSERT INTO status_history (complaint_id, old_status, new_status, updated_by)
        VALUES (?, ?, ?, 'inspector')
    """, (cid, old_status, new_status))

    # Notify Panchayat if "Work Completed"
    if new_status == "Work Completed" and panchayat_email:
        try:
            subject = f"Work Completed: Complaint #{cid}"
            content = f"""
                <h3>Work Completed Report</h3>
                <p>Inspector has marked complaint <b>#{cid}</b> as "Work Completed".</p>
                <p>Please review and mark as Resolved if appropriate.</p>
            """
            send_email(panchayat_email, subject, content)
        except Exception as e:
            print("Email notification failed:", e)

    db.commit()
    db.close()

    return redirect("/inspector")


if __name__ == "__main__":
    app.run(debug=True)
