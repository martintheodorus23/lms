from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, Response, abort
)
import mysql.connector
import secrets
import smtplib
import time
from datetime import datetime


app = Flask(__name__)
app.secret_key = "super_secure_secret_key_for_session"

# ─────────────── MySQL Config ───────────────
DB_CONFIG = dict(
    host="raidnlci.mysql.pythonanywhere-services.com",
    user="raidnlci",
    password="raiddb@2025",
    database="raidnlci$default"
)

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

# ─────────────── DB Helpers ───────────────
def get_user_by_email(email: str):
    cn = get_db()
    cur = cn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    cn.close()
    return user

def get_user_by_username(username: str):
    cn = get_db()
    cur = cn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    cn.close()
    return user

def insert_user(username: str, email: str, otp: str):
    cn = get_db()
    cur = cn.cursor()
    cur.execute(
        "INSERT INTO users (username, email, otp, verified) VALUES (%s, %s, %s, %s)",
        (username, email, otp, False)
    )
    cn.commit()
    cur.close()
    cn.close()

def update_otp(username: str, otp: str):
    cn = get_db()
    cur = cn.cursor()
    cur.execute("UPDATE users SET otp = %s WHERE username = %s", (otp, username))
    cn.commit()
    cur.close()
    cn.close()

def verify_user(username: str):
    cn = get_db()
    cur = cn.cursor()
    cur.execute("UPDATE users SET verified = TRUE WHERE username = %s", (username,))
    cn.commit()
    cur.close()
    cn.close()

def get_external_by_email(email: str):
    cn = get_db()
    cur = cn.cursor(dictionary=True)
    cur.execute("SELECT * FROM externals WHERE email = %s", (email,))
    external = cur.fetchone()
    cur.close()
    cn.close()
    return external

def get_flp_by_email(email: str):
    cn = get_db()
    cur = cn.cursor(dictionary=True)
    cur.execute("SELECT * FROM flp WHERE Mail_ID = %s", (email,))
    flp_record = cur.fetchone()
    cur.close()
    cn.close()
    return flp_record


# ─────────────── Routes ───────────────

@app.route("/")
def index():
    if not session.get("verified"):
        return redirect(url_for("login"))

    username = session["username"]
    user = get_user_by_username(username)

    if not user:
        # user not found → handle gracefully
        return redirect(url_for("login"))  # or show 404/flash message

    session["type"] = user.get("type")

    return render_template(
        "index.html",
        username=session["username"],
        user_type=session["type"]
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            return render_template("login.html", error="Email is required")

        # Allow nlife emails OR externals table entries
        is_nlife_email = email.endswith("@nlife.in")
        external_user = get_external_by_email(email)
        flp_members = get_flp_by_email(email)

        if not is_nlife_email and not external_user and not flp_members:
            return render_template("login.html", error="❌ Invalid email")

        session["email"] = email

        # Look for main user first
        user = get_user_by_email(email)
        if user:
            session["username"] = user["username"]
            return redirect(url_for("send_otp"))

        # If in externals table, use their username if it exists
        if external_user and "username" in external_user:
            session["username"] = external_user["username"]
            return redirect(url_for("send_otp"))

        # Otherwise continue to username entry step
        return redirect(url_for("enter_username"))

    return render_template("login.html")


import re

@app.route("/enter_username", methods=["GET", "POST"])
def enter_username():
    if "email" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()

        # Empty check
        if not username:
            return render_template("enter_username.html", error="Username is required")

        # Reject uppercase letters or spaces
        if not re.match("^[a-z0-9_]+$", username):
            return render_template("enter_username.html",
                                   error="❌ Use only lowercase letters, numbers, and underscores (no spaces)")

        # Duplicate check
        if get_user_by_username(username):
            return render_template("enter_username.html", error="❌ Username already taken")

        session["username"] = username
        return redirect(url_for("send_otp"))

    return render_template("enter_username.html")

# Step 3: Send OTP and go to verify page
@app.route("/send_otp")
def send_otp():
    if "username" not in session or "email" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    email = session["email"]
    otp = f"{secrets.randbelow(1_000_000):06d}"

    user = get_user_by_username(username)
    if user:
        update_otp(username, otp)
    else:
        insert_user(username, email, otp)

    try:
        sender_email = "martintheodorus4@gmail.com"
        sender_pass = "votv tusw peot fnds"
        msg = f"Subject: Your OTP Code: {otp}\n\nYour OTP is: {otp}\nDo not share this code."

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(sender_email, sender_pass)
            s.sendmail(sender_email, email, msg)

    except Exception as e:
        return render_template("error.html", message=f"Failed to send OTP: {e}")

    return redirect(url_for("verify_otp"))

# Step 4: Verify OTP
@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_input = request.form.get("otp", "").strip()

        # Validate OTP format
        if not otp_input.isdigit() or len(otp_input) != 6:
            return render_template("otp.html", error="Enter a valid 6-digit OTP")

        username = session["username"]
        user = get_user_by_username(username)

        if user and user.get("otp") == otp_input:
            verify_user(username)
            session["verified"] = True
            session["type"] = user.get("type")
            return redirect(url_for("index"))

        # OTP doesn't match
        return render_template("otp.html", error="❌ Invalid OTP")

    # GET request → Show OTP form
    return render_template("otp.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/profile/<username>")
def profile(username):
    # Ensure user exists
    user = get_user_by_username(username)
    if not user:
        abort(404, description="User not found")

    # Only logged-in users can view profiles
    if "username" not in session:
        return redirect(url_for("login"))

    cn = get_db()
    cur = cn.cursor(dictionary=True)

    # Fetch requests made by this user
    cur.execute("""
        SELECT r.id, r.book, r.datetime, r.given
        FROM requests r
        WHERE r.name = %s
        ORDER BY r.datetime DESC
    """, (username,))
    user_requests = cur.fetchall()

    # Fetch books currently borrowed by this user
    cur.execute("""
        SELECT id, book_title, availability
        FROM library_books
        WHERE borrower_name = %s
    """, (username,))
    borrowed_books = cur.fetchall()

    cur.close()
    cn.close()

    return render_template(
        "profile.html",
        user=user,
        user_requests=user_requests,
        borrowed_books=borrowed_books,
        user_status=user.get("type", "Member")  # fallback if type missing
    )

@app.route("/help")
def help_page():
    return render_template("help.html")

# ─────────────────────────── LIBRARY ───────────────────────────
@app.route("/library")
def library():
    if "email" not in session:
        return redirect(url_for("login"))

    cn = get_db()
    cur = cn.cursor(dictionary=True)
    cur.execute("SELECT * FROM library_books")
    books = cur.fetchall()
    genres = sorted({b["genre"] for b in books})
    cur.close()
    cn.close()
    return render_template("library.html", books=books, genres=genres)


@app.route("/library/lms")
def dashboard():
    # allow only users with type='admin' or 'tester'
    if "username" not in session:
        return redirect(url_for("login"))

    user = get_user_by_username(session["username"])
    allowed_types = {"admin", "tester"}
    if not user or (user.get("type") or "").lower() not in allowed_types:
        return "Access Denied: Admins and Testers only", 403

    return render_template("dashboard.html")

@app.route("/library/lms/dashboard/api")
def api_dashboard():
    cn = get_db()
    cur = cn.cursor()

    cur.execute("SELECT COUNT(*) FROM library_books")
    total_books = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM library_books WHERE Availability='Taken'"    )
    taken_books = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM library_books WHERE genre = 'Survey Reports'")
    survey_reports =cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM users where verified=1")
    users =cur.fetchone()[0]

    cur.close()
    cn.close()
    return jsonify(
        total_books=total_books,
        taken_books=taken_books,
        survey_reports=survey_reports,
        users=users
    )

@app.route("/library/lms/dashboard/api/requests")
def api_requests():
    cn  = get_db()
    cur = cn.cursor(dictionary=True)

    cur.execute("SELECT * FROM requests ORDER BY `datetime` DESC LIMIT 50")

    rows = [
        {
            "id"          : row["id"],
            "who"         : row["name"],
            "book"        : row["book"],
            "requested_at": row["datetime"].strftime("%Y-%m-%d %H:%M:%S"),
            "given"       : bool(row["given"]),
        }
        for row in cur.fetchall()
    ]

    cur.close()
    cn.close()
    return jsonify(rows)

@app.route("/library/lms/dashboard/api/taken")
def api_taken_books():
    conn = get_db()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT
            id,
            book_title,
            borrower_name
        FROM library_books
        WHERE availability = 'taken'
    """)

    return jsonify(cur.fetchall())


@app.route("/library/add", methods=["GET"])
def add_book_form():
    if "email" not in session:
        return redirect(url_for("login"))
    return render_template("new_book.html")  # Render your form

@app.route("/library/add", methods=["POST"])
def add_book():
    if "email" not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No JSON data received"}), 400

    fields = {
        "book_title"    : data.get("book_title"),
        "author"        : data.get("author"),
        "publish_year"  : data.get("publish_year"),
        "genre"         : data.get("genre"),
        "series"        : data.get("series"),
        "volume"        : data.get("volume"),
        "library_code"  : data.get("library_code"),
    }

    try:
        cn = get_db()
        cur = cn.cursor()
        cur.execute("""
            INSERT INTO library_books (
                book_title, author, publish_year, genre, series,
                volume, library_code
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, tuple(fields.values()))
        cn.commit()
        cur.close()
        cn.close()
        return jsonify({"status": "success", "message": "Book saved successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to insert book: {str(e)}"}), 500

@app.route("/library/add_survey", methods=["POST"])
def add_survey():
    if "email" not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No JSON data received"}), 400

    fields = {
        "book_title"    : data.get("book_title"),
        "author"        : data.get("author"),
        "publish_year"  : data.get("publish_year"),
        "genre"         : data.get("genre"),
        "series"        : data.get("series"),
        "volume"        : data.get("volume"),
        "library_code"  : data.get("library_code"),
    }

    try:
        cn = get_db()
        cur = cn.cursor()
        cur.execute("""
            INSERT INTO library_books (
                book_title, author, publish_year, genre, series,
                volume, library_code
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, tuple(fields.values()))
        cn.commit()
        cur.close()
        cn.close()
        return jsonify({"status": "success", "message": "Survey saved successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to insert survey: {str(e)}"}), 500

@app.route("/request_book", methods=["POST"])
def request_book():
    data = request.get_json()
    book_id = data.get("book_id")

    # Get logged-in username from session
    username = session.get("username")
    if not username:
        return jsonify({"error": "User not logged in"}), 401

    cn = get_db()
    cur = cn.cursor()

    try:
        # Get book title from library_books
        cur.execute("SELECT book_title FROM library_books WHERE id = %s", (book_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Book not found %s"%book_id}), 404
        book_title = row[0]

        # Insert request into requests table
        cur.execute("""
            INSERT INTO requests (name, book_id, book, datetime, given)
            VALUES (%s, %s, %s, %s, %s)
        """, (username, book_id, book_title, datetime.now(), 0))

        cn.commit()
        return jsonify({"success": True, "requested_by": username, "book": book_title})

    except Exception as e:
        cn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        cur.close()
        cn.close()


@app.route("/library/lms/remove_request", methods=["POST"])
def remove_request():
    data = request.get_json()
    req_id = data.get("id")

    # Ensure user is logged in
    username = session.get("username")
    if not username:
        return jsonify({"error": "User not logged in"}), 401

    cn = get_db()
    cur = cn.cursor()

    try:
        # Check if request exists
        cur.execute("SELECT id, name, book FROM requests WHERE id = %s", (req_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": f"Request {req_id} not found"}), 404

        # Only allow admin OR the person who made the request to delete
        req_owner = row[1]
        if session.get("type") != "admin" and req_owner != username:
            return jsonify({"error": "Not authorized to remove this request"}), 403

        # Delete request
        cur.execute("DELETE FROM requests WHERE id = %s", (req_id,))
        cn.commit()

        return jsonify({"success": True, "removed_request_id": req_id, "book": row[2]})

    except Exception as e:
        cn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        cur.close()
        cn.close()

@app.route("/library/lms/give", methods=["POST"])
def give_book():
    data = request.get_json()
    request_id = data.get("id")

    if not request_id:
        return jsonify({"error": "Missing request ID"}), 400

    cn = get_db()
    cursor = cn.cursor(dictionary=True)

    # Fetch the request record
    cursor.execute("SELECT * FROM requests WHERE id = %s", (request_id,))
    row = cursor.fetchone()

    if not row:
        cursor.close()
        cn.close()
        return jsonify({"error": "Request not found"}), 404

    try:
        # Update book availability using book_id
        cursor.execute(
            "UPDATE library_books SET availability = 'Taken', borrower_name = %s WHERE id = %s",
            (row["name"], row["book_id"])
        )

        # Delete from requests table
        cursor.execute("DELETE FROM requests WHERE id = %s", (request_id,))

        cn.commit()
        return jsonify({"success": True})
    except Exception as e:
        cn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        cn.close()

@app.route("/library/lms/return", methods=["POST"])
def return_book():
    data = request.json
    book_id = data.get("book_id")

    if not book_id:
        return jsonify({"error": "Missing book ID"}), 400

    cn = mysql.connector.connect(**DB_CONFIG)
    cur = cn.cursor()

    cur.execute("""
        UPDATE library_books
        SET availability = 'Available', borrower_name = NULL
        WHERE id = %s
    """, (book_id,))

    if cur.rowcount == 0:
        cn.rollback()
        return jsonify({"error": "Book not found"}), 404

    cn.commit()
    cur.close()
    cn.close()

    return jsonify({"success": True})

# ────────────────────────── ATTENDANCE ─────────────────────────
@app.route("/attendance")
def attendance_page():
    if "email" not in session:
        return redirect(url_for("login"))
    return render_template("attendance.html")


@app.route("/mark_attendance", methods=["POST"])
def mark_attendance():
    if "email" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    name = data.get("name", "").strip()
    t = data.get("time", "").strip()

    if not name or not t:
        return jsonify({"message": "Name and time are required"}), 400

    cn = get_db()
    cur = cn.cursor()
    cur.execute(
        """
        INSERT INTO attendance (name, time, date)
        VALUES (%s, %s, %s)
        """,
        (name, t, datetime.now().strftime("%Y-%m-%d")),
    )
    cn.commit()
    cur.close()
    cn.close()

    return jsonify({"message": f"Attendance marked for {name} at {t}"}), 200


# ────────────────────────────  CHAT  ───────────────────────────
@app.route("/chat")
def home_chat():
    if "email" not in session:
        return redirect(url_for("login"))
    return render_template(
        "chat.html", current_user=session.get("name", "Anonymous")
    )


@app.route("/send", methods=["POST"])
def send():
    if "email" not in session:
        return "", 401

    msg_text = request.form.get("message", "").strip()
    email = session["email"]

    if msg_text:
        cn = get_db()
        cur = cn.cursor()
        cur.execute(
            """
            INSERT INTO messages (user_email, message, time)
            VALUES (%s, %s, %s)
            """,
            (email, msg_text, datetime.now().strftime("%H:%M")),
        )
        cn.commit()
        cur.close()
        cn.close()
    return "", 204

@app.route("/messages")
def messages():
    if "email" not in session:
        return jsonify([])

    cn = get_db()
    cur = cn.cursor(dictionary=True)
    cur.execute("""
        SELECT
            m.user_email,
            u.username AS user_name,
            m.message,
            m.time
        FROM messages m
        LEFT JOIN users u ON u.email = m.user_email
        ORDER BY m.id ASC
    """)
    msgs = cur.fetchall()

    # Convert time to string (e.g., "14:30:00")
    for msg in msgs:
        if isinstance(msg['time'], (datetime, )):
            msg['time'] = msg['time'].strftime("%H:%M:%S")
        else:
            msg['time'] = str(msg['time'])  # fallback

    cur.close()
    cn.close()
    return jsonify(msgs)

# _____________________________  develop ________________________________

def serialize_value(val):
    if isinstance(val, bytearray):
        return val.decode(errors="ignore")  # or `str(val)`
    return val

@app.route("/dev")
def dev():
    return render_template('dev.html')

@app.route("/dev/execute", methods=["POST"])
def execute_query():
    sql = request.json.get("query", "").strip()
    if not sql:
        return Response("Error: Empty query", mimetype="text/plain"), 400

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(sql)

        def serialize_value(val):
            if isinstance(val, bytearray):
                return val.decode(errors="ignore")
            return val

        if cur.description:
            cols = [d[0] for d in cur.description]
            rows = [
                [serialize_value(val) for val in row]
                for row in cur.fetchall()
            ]

            # Create ASCII table
            widths = [max(len(str(col)), max(len(str(row[i])) for row in rows)) for i, col in enumerate(cols)]
            def pad(s, l): return str(s) + ' ' * (l - len(str(s)))
            sep = '+-' + '-+-'.join('-' * w for w in widths) + '-+'
            header = '| ' + ' | '.join(pad(col, widths[i]) for i, col in enumerate(cols)) + ' |'
            body = '\n'.join('| ' + ' | '.join(pad(row[i], widths[i]) for i in range(len(cols))) + ' |' for row in rows)
            table = f"{sep}\n{header}\n{sep}\n{body}\n{sep}"
            result = table
        else:
            conn.commit()
            result = f"OK ({cur.rowcount} rows affected)"
    except Exception as e:
        result = f"Error: {e}"
    finally:
        try: cur.close()
        except: pass
        try: conn.close()
        except: pass

    with open('code_log.txt','a') as file:
        file.write("""Who:\n%s\nTIME:\n%s\nQuery:\n%s\nResult:\n%s\n"""%(time.ctime(),session,sql,result))

    return Response(result, mimetype="text/plain")



# ────────────────────────────  TESTER  ───────────────────────────
if __name__ == "__main__":
    app.run(debug=True)
