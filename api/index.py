from flask import Flask, render_template, send_from_directory, request, jsonify, session, redirect, url_for, flash
from functools import wraps

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper
import os
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import random
import string

def generate_meet_link():
    """Generate a Google Meet style link automatically."""
    def part():
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(3))

    code = f"{part()}-{part()}{part()}-{part()}"
    return f"https://meet.google.com/{code}"


# ==================================
# 📁 PATH SETUP
# ==================================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'documents')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==================================
# 🚀 FLASK SETUP
# ==================================
app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

app.config["SESSION_PERMANENT"] = False


from datetime import timedelta

app.permanent_session_lifetime = timedelta(days=7)




# ==================================
# ⚙️ DATABASE SETUP (Auto-detect SQLite or PostgreSQL)
# ==================================

DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    print("📡 Using PostgreSQL from Render")
    # Render gives URL starting with "postgres://"
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
else:
    print("💾 Using local SQLite database")
    INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
    os.makedirs(INSTANCE_DIR, exist_ok=True)

    DB_PATH = os.path.join(INSTANCE_DIR, "users.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_PATH

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

from flask_migrate import Migrate

migrate = Migrate(app, db)


# Teacher details separated from user
class TeacherProfile(db.Model):
    __tablename__ = "teacher_profiles"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True)
    bio = db.Column(db.Text)
    qualifications = db.Column(db.String(500))
    subjects = db.Column(db.String(300))   # comma separated or JSON later
    experience_years = db.Column(db.Integer, default=0)
    availability = db.Column(db.String(200))  # e.g. "Evenings, Weekends"
    resume_path = db.Column(db.String(500))
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.now())


    user = db.relationship("User", backref=db.backref("teacher_profile", uselist=False))

class Booking(db.Model):
    __tablename__ = "bookings"
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey("teacher_profiles.id"), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    subject = db.Column(db.String(200))
    requested_time = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="pending")  # pending/accepted/rejected/completed
    meet_link = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=db.func.now())

    teacher = db.relationship("TeacherProfile", backref="bookings")
    student = db.relationship("User", foreign_keys=[student_id])

class LiveClass(db.Model):
    __tablename__ = "live_classes"
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey("teacher_profiles.id"), nullable=False)
    subject = db.Column(db.String(200))
    meet_link = db.Column(db.String(500))
    is_live = db.Column(db.Boolean, default=True)
    started_at = db.Column(db.DateTime, default=db.func.now())


class SavedTeacher(db.Model):
    __tablename__ = "saved_teachers"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey("teacher_profiles.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())


# 🧑‍💻 USER MODEL
class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    coins = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), nullable=True)


    def __repr__(self):
        return f"<User {self.username}>"

# 📢 Announcements Table
class Announcement(db.Model):
    __tablename__ = 'announcements'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    def __repr__(self):
        return f"<Announcement {self.id}>"




# ==================================
# 🔑 OpenAI API KEY
# ==================================
from openai import OpenAI
import os

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


# ==================================
# 🌍 PAGE ROUTES
# ==================================
@app.route('/')
def home():
    # Home page should be PUBLIC
    return render_template("index.html")
@app.route("/<page>")
def spa_page(page):
    allowed = ["subjects", "projects", "match", "rewards", "dashboard", "teacher-dashboard"]
    if page in allowed:
        return render_template("index.html", pageFromServer=page)
    return render_template("index.html")


@app.route('/admin', methods=['GET', 'POST'])
def admin_page():
    # 🛑 Block if not logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # 🛑 Block if not admin
    user = User.query.get(session['user_id'])
    if not user or not getattr(user, 'is_admin', False):
        return "<h3 style='color:red;'>❌ Access Denied — Admins Only.</h3>"

    # 📢 Handle announcement submission
    if request.method == 'POST':
        message = request.form.get("announcement")
        if message:
            new_announcement = Announcement(message=message)
            db.session.add(new_announcement)
            db.session.commit()
            print("📢 New announcement added:", message)

    # 📥 Load data for admin dashboard
    users = User.query.all()
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).all()

    return render_template('admin.html', users=users, announcements=announcements)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    admin = User.query.get(session['user_id'])
    if not admin or not getattr(admin, 'is_admin', False):
        return "<h3 style='color:red;'>❌ Access Denied — Admins Only.</h3>"

    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        return jsonify({"error": "User not found"}), 404

    # 1️⃣ Delete Teacher Profile if exists
    teacher_profile = TeacherProfile.query.filter_by(user_id=user_id).first()
    if teacher_profile:
        # Delete bookings linked to this teacher
        Booking.query.filter_by(teacher_id=teacher_profile.id).delete()
        
        # Delete saved teacher references
        SavedTeacher.query.filter_by(teacher_id=teacher_profile.id).delete()

        db.session.delete(teacher_profile)

    # 2️⃣ Delete student bookings
    Booking.query.filter_by(student_id=user_id).delete()

    # 3️⃣ Delete saved teachers for student
    SavedTeacher.query.filter_by(student_id=user_id).delete()

    # 4️⃣ Finally delete the user
    db.session.delete(user_to_delete)
    db.session.commit()

    print(f"🗑️ Deleted user and related data: {user_to_delete.email}")
    return redirect(url_for('admin_page'))


# 📢 Create Announcement
@app.route('/create_announcement', methods=['POST'])
def create_announcement():
    if not session.get("is_admin"):
        return redirect(url_for("login"))

    message = request.form.get("announcement")
    if message:
        new_announcement = Announcement(message=message)
        db.session.add(new_announcement)
        db.session.commit()
    return redirect(url_for("admin_page"))


# 💰 Add Reward Coins
@app.route('/add_coins/<int:user_id>', methods=['POST'])
def add_coins(user_id):
    if not session.get("is_admin"):
        return redirect(url_for("login"))

    coins = request.form.get("coins")
    user = User.query.get(user_id)
    if user and coins.isdigit():
        user.coins += int(coins)
        db.session.commit()
    return redirect(url_for("admin_page"))




@app.route('/dashboard')
@login_required
def dashboard():
    if 'user_id' not in session:
        print("⚠️ No user_id in session — redirecting to login")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        print("⚠️ User not found — session cleared")
        return redirect(url_for('login'))

    # 📰 Fetch announcements (latest first)
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).all()

    user_data = {
        "name": user.username,
        "coins": getattr(user, 'coins', 0),
        "email": user.email,
        "projects": ["AI Chatbot", "Smart Attendance", "Vyatihar Platform"],
        "live_status": "LIVE"
    }

    # Pass announcements to the template
    return render_template('dashboard.html', user=user_data, announcements=announcements)



@app.route('/status')
@login_required
def live_status():
    return render_template('status.html')

@app.route('/static/<path:filename>')
@login_required
def serve_static(filename):
    return send_from_directory(STATIC_DIR, filename)

# ===============================
# 👤 USER AUTH ROUTES (Connected to Forms)
# ===============================

from flask import redirect, url_for

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")   # ✅ fixed variable name
        email = request.form.get("email")
        password = request.form.get("password")

        # Check if email exists
        if User.query.filter_by(email=email).first():
            return "<h3 style='color:red;'>❌ Email already registered. Try <a href='/login'>Login</a>.</h3>"

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

        # ✅ use hashed password for security
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        return "<h3 style='color:green;'>✅ Signup successful! <a href='/login'>Login now</a></h3>"

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        # WRONG CREDENTIALS
        if not user or not bcrypt.check_password_hash(user.password, password):
            return "<h3 style='color:red;'>❌ Invalid credentials. <a href='/login'>Try again</a>.</h3>"

        # SAVE SESSION
        session["user_id"] = user.id
        session["username"] = user.username
        session["email"] = user.email
        session["role"] = user.role 

        # 1️⃣ ADMIN CHECK
        if user.is_admin:
            session["is_admin"] = True
            return redirect("/admin")

        # 2️⃣ NO ROLE SELECTED → ROLE PAGE
        if not user.role:
            return redirect("/choose-role")

        # 3️⃣ STUDENT
        if user.role == "student":
            return redirect("/student-dashboard")

        # 4️⃣ TEACHER
        if user.role == "teacher":
            return redirect("/teacher-dashboard")

        # fallback
        return redirect("/login")

    # GET REQUEST → show login page
    return render_template("login.html")




@app.route('/choose-role', methods=['GET', 'POST'])
@login_required
def choose_role():
    user = User.query.get(session['user_id'])

    # Agar already role set hai → direct dashboard
    if user.role:
        if user.role == "student":
            return redirect("/student-dashboard")
        elif user.role == "teacher":
            return redirect("/teacher-dashboard")

    if request.method == "POST":
        role = request.form.get("role")

        if role not in ["student", "teacher"]:
            return "Invalid role", 400

        user.role = role
        db.session.commit()

        if role == "student":
            return redirect("/student-dashboard")
        else:
            return redirect("/teacher-dashboard")

    return render_template("choose_role.html")





@app.route('/logout')
def logout():
    session.clear()     # remove ALL session data
    return redirect('/')   # go to homepage, not login



# -------------------------
# 🔐 PROTECTED STUDENT PAGES
# -------------------------

@app.route("/subjects")
@login_required
def subjects_page():
    return render_template("index.html", pageFromServer="subjects")


@app.route("/projects")
@login_required
def projects_page():
    return render_template("index.html", pageFromServer="projects")


@app.route("/rewards")
@login_required
def rewards_page():
    return render_template("index.html", pageFromServer="rewards")


@app.route("/match")
@login_required
def match_page():
    return render_template("index.html", pageFromServer="match")


@app.route("/api/check-session")
def check_session():
    return {"logged_in": "user_id" in session}


# ==============================
# 🧭 STUDENT DASHBOARD (Role-Based)
# ==============================
@app.route("/student-dashboard")
@login_required
def student_dashboard():
    user = User.query.get(session["user_id"])

    if user.role != "student":
        return "<h3 style='color:red'>❌ Access Denied — Students Only</h3>"

    announcements = Announcement.query.order_by(Announcement.created_at.desc()).all()

    return render_template("student_dashboard.html", user=user, announcements=announcements)


# ==============================
# 🎓 TEACHER DASHBOARD (Role-Based)
# ==============================
@app.route("/teacher-dashboard")
@login_required
def teacher_dashboard():
    user = User.query.get(session["user_id"])

    if user.role != "teacher":
        return "<h3 style='color:red'>❌ Access Denied — Teachers Only</h3>"

    profile = TeacherProfile.query.filter_by(user_id=user.id).first()

    return render_template("teacher_dashboard.html", user=user, profile=profile)


@app.route("/teachers")
def list_teachers():
    teachers = TeacherProfile.query.all()
    return render_template("teachers.html", teachers=teachers)


@app.route("/teacher/<int:profile_id>")
def teacher_profile_page(profile_id):
    profile = TeacherProfile.query.get(profile_id)
    
    if not profile:
        return "<h3>Teacher not found</h3>", 404

    # Send as teacher
    return render_template("teacher_profile.html", teacher=profile)




@app.route("/teachers/search")
def search_teachers():
    q = request.args.get("q", "")
    q = f"%{q}%"

    teachers = TeacherProfile.query.filter(
        (TeacherProfile.subjects.ilike(q)) |
        (TeacherProfile.qualifications.ilike(q)) |
        (TeacherProfile.bio.ilike(q))
    ).all()

    return render_template("teachers.html", teachers=teachers)


@app.route("/become-teacher", methods=["GET"])
@login_required
def become_teacher_page():
    return render_template("become_teacher.html")


# @app.route('/logout')
# def logout():
#     session.clear()
#     flash("👋 Logged out successfully.")
#     return redirect(url_for('login_page'))

# ==================================
# 🧠 AI STUDY ASSISTANT
# ==================================


@app.route('/ask_ai', methods=['POST'])
def ask_ai():
    try:
        data = request.get_json()
        question = data.get("question", "").strip()

        if not question:
            return jsonify({"error": "No question provided"}), 400

        # 🧠 OpenAI ChatGPT Call
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Fast & cheap model
            messages=[
                {"role": "user", "content": question}
            ]
        )

        answer = response.choices[0].message.content
        return jsonify({"answer": answer})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================================
# 🎥 LIVE CLASS ENDPOINT
# ==================================
@app.route("/live_class", methods=["GET"])
@login_required
def get_live_class():
    data = {
        "subject": "AI & ML",
        "status": "LIVE",
        "meetLink": "https://meet.google.com/xyz",
        "timestamp": "2025-11-11T14:30:00"
    }
    return jsonify(data)

# ==================================
# 📄 NOTES UPLOAD
# ==================================
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt', 'pptx', 'mp4'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_note', methods=['POST'])
@login_required
def upload_note():
    file = request.files.get('note')
    if not file or file.filename == '':
        return "No file uploaded", 400
    if not allowed_file(file.filename):
        return "File type not allowed", 400
    filename = secure_filename(file.filename)
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    return f"<h3>✅ Note uploaded successfully: {filename}</h3><a href='/dashboard'>Go Back</a>"


# ==============================
# 🛠️ AUTO CREATE DB ON STARTUP (FIRST)
# ==============================
with app.app_context():
    try:
        db.create_all()
        print("✅ Database created / exists")
    except Exception as e:
        print("❌ DB creation error:", e)


# ==============================
# 👑 AUTO CREATE ADMIN (SECOND)
# ==============================
with app.app_context():
    existing_admin = User.query.filter_by(email="admin@vyatihar.com").first()

    if not existing_admin:
        admin_pass = bcrypt.generate_password_hash("admin123").decode("utf-8")
        admin = User(
            username="admin",
            email="admin@vyatihar.com",
            password=admin_pass,
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("👑 Auto-created Admin!")
    else:
        print("👑 Admin already exists")


@app.route("/teachers")
@login_required
def teachers_page():

    # Load all teacher profiles
    teachers = TeacherProfile.query.order_by(TeacherProfile.id.desc()).all()

    return render_template("teachers.html", teachers=teachers)




# ---------- TEACHER / BOOKING API (JSON) ----------
from werkzeug.utils import secure_filename
from datetime import datetime

# Config for uploaded resumes (optional)
RESUME_UPLOAD_DIR = os.path.join(BASE_DIR, "resumes")
os.makedirs(RESUME_UPLOAD_DIR, exist_ok=True)
ALLOWED_RESUME_EXT = {'pdf', 'docx', 'doc'}

def allowed_resume(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_RESUME_EXT

# 1) Become Teacher (connect logged-in user -> create TeacherProfile)
@app.route("/api/teacher/become", methods=["POST"])
@login_required
def api_become_teacher():
    if 'user_id' not in session:
        return jsonify({"error":"login_required"}), 401

    user_id = session['user_id']

    # check existing teacher
    if TeacherProfile.query.filter_by(user_id=user_id).first():
        return jsonify({"error":"already_teacher"}), 400

    # GET FORM DATA (HTML form → request.form)
    data = request.form

    bio = data.get("bio", "")
    qualifications = data.get("qualifications", "")
    subjects = data.get("subjects", "")
    experience_years = int(data.get("experience_years") or 0)
    availability = data.get("availability", "")

    resume_path = None

    # FILE upload
    if 'resume' in request.files:
        f = request.files['resume']
        if f and allowed_resume(f.filename):
            fname = secure_filename(f.filename)
            dest = os.path.join(RESUME_UPLOAD_DIR, f"{user_id}_{fname}")
            f.save(dest)
            resume_path = dest

    profile = TeacherProfile(
        user_id=user_id,
        bio=bio,
        qualifications=qualifications,
        subjects=subjects,
        experience_years=experience_years,
        availability=availability,
        resume_path=resume_path,
        verified=False
    )

    db.session.add(profile)
    db.session.commit()

    return redirect("/teacher-dashboard")

# 2) Update teacher profile (teacher must be logged in)
@app.route("/api/teacher/update", methods=["POST"])
@login_required
def api_teacher_update():
    if 'user_id' not in session:
        return jsonify({"error":"login_required"}), 401
    user_id = session['user_id']
    profile = TeacherProfile.query.filter_by(user_id=user_id).first()
    if not profile:
        return jsonify({"error":"not_a_teacher"}), 404
    data = request.form if request.form else request.json or {}
    profile.bio = data.get("bio", profile.bio)
    profile.qualifications = data.get("qualifications", profile.qualifications)
    profile.subjects = data.get("subjects", profile.subjects)
    profile.experience_years = int(data.get("experience_years") or profile.experience_years)
    profile.availability = data.get("availability", profile.availability)

    if 'resume' in request.files:
        f = request.files['resume']
        if f and allowed_resume(f.filename):
            fname = secure_filename(f.filename)
            dest = os.path.join(RESUME_UPLOAD_DIR, f"{user_id}_{int(datetime.utcnow().timestamp())}_{fname}")
            f.save(dest)
            profile.resume_path = dest

    db.session.commit()
    return jsonify({"ok":True})

# 3) Get single teacher profile (public)
@app.route("/api/teacher/<int:profile_id>", methods=["GET"])
def api_get_teacher(profile_id):
    p = TeacherProfile.query.get(profile_id)
    if not p:
        return jsonify({"error":"not_found"}), 404
    u = p.user
    return jsonify({
        "id": p.id,
        "user_id": p.user_id,
        "name": u.username,
        "email": u.email if session.get("is_admin") or session.get("user_id")==p.user_id else None,
        "bio": p.bio,
        "qualifications": p.qualifications,
        "subjects": p.subjects,
        "experience_years": p.experience_years,
        "availability": p.availability,
        "resume": p.resume_path,
        "verified": p.verified
    })

# 4) List teachers (supports optional query ?q=search)
@app.route("/api/teachers", methods=["GET"])
@login_required
def api_list_teachers():
    q = request.args.get("q","").strip()
    subject = request.args.get("subject","").strip()
    query = TeacherProfile.query.join(User, TeacherProfile.user_id==User.id)
    if q:
        qterm = f"%{q}%"
        query = query.filter( (User.username.ilike(qterm)) | (TeacherProfile.bio.ilike(qterm)) | (TeacherProfile.qualifications.ilike(qterm)) )
    if subject:
        st = f"%{subject}%"
        query = query.filter(TeacherProfile.subjects.ilike(st))
    profiles = query.order_by(TeacherProfile.created_at.desc()).limit(200).all()
    out = []
    for p in profiles:
        out.append({
            "id": p.id,
            "name": p.user.username,
            "subjects": p.subjects,
            "qualifications": p.qualifications,
            "experience_years": p.experience_years,
            "bio": (p.bio or "").slice(0,200) if hasattr(p.bio, "slice") else (p.bio or "")[:200],
            "verified": p.verified
        })
    return jsonify(out)

# 5) Save / Unsave teacher (bookmark) (student only)
@app.route("/api/teacher/save", methods=["POST"])
@login_required
def api_save_teacher():
    if 'user_id' not in session:
        return jsonify({"error":"login_required"}), 401
    student_id = session['user_id']
    data = request.json or request.form
    teacher_id = int(data.get("teacher_id"))
    saved = SavedTeacher.query.filter_by(student_id=student_id, teacher_id=teacher_id).first()
    if saved:
        db.session.delete(saved); db.session.commit()
        return jsonify({"ok":True, "saved":False})
    new = SavedTeacher(student_id=student_id, teacher_id=teacher_id)
    db.session.add(new); db.session.commit()
    return jsonify({"ok":True, "saved":True})

# 6) Book teacher (student -> create booking request)
@app.route("/api/teacher/book", methods=["POST"])
@login_required
def api_book_teacher():
    if 'user_id' not in session:
        return jsonify({"error":"login_required"}), 401

    student_id = session['user_id']
    data = request.json or request.form

    # teacher_id coming from frontend = USER ID
    teacher_user_id = int(data.get("teacher_id"))

    # find correct teacher profile ID
    teacher_profile = TeacherProfile.query.filter_by(user_id=teacher_user_id).first()
    if not teacher_profile:
        return jsonify({"error": "teacher_profile_not_found"}), 404

    subject = data.get("subject", "")
    requested_time = data.get("requested_time")

    try:
        rt = datetime.fromisoformat(requested_time) if requested_time else None
    except:
        rt = None

    # FIX: teacher_id must be TeacherProfile.id
    booking = Booking(
        teacher_id=teacher_profile.id,   # ⭐ FIXED
        student_id=student_id,
        subject=subject,
        requested_time=rt,
        status="pending",
        created_at=datetime.utcnow()
    )

    db.session.add(booking)
    db.session.commit()

    return jsonify({"ok": True, "booking_id": booking.id})

# -------------------------
# 7) Teacher view their bookings (teacher must be logged in)
# -------------------------
@app.route("/api/teacher/bookings", methods=["GET"])
@login_required
def api_teacher_bookings():
    if 'user_id' not in session:
        return jsonify({"error":"login_required"}), 401

    profile = TeacherProfile.query.filter_by(user_id=session['user_id']).first()
    if not profile:
        return jsonify({"error":"not_a_teacher"}), 403

    bookings = Booking.query.filter_by(teacher_id=profile.id).order_by(Booking.created_at.desc()).all()
    out = []
    for b in bookings:
        out.append({
            "id": b.id,
            "student_id": b.student.id if getattr(b, "student", None) else None,
            "student_name": b.student.username if getattr(b, "student", None) else "Student",
            "student_email": getattr(b.student, "email", None),
            "subject": b.subject,
            "requested_time": b.requested_time.isoformat() if b.requested_time else None,
            "status": b.status,
            "meet_link": b.meet_link or ""
        })
    return jsonify(out)


# -------------------------
# 8) Accept / Reject / Complete booking (teacher)
# -------------------------
@app.route("/api/teacher/booking/<int:booking_id>/action", methods=["POST"])
@login_required
def api_teacher_action_booking(booking_id):
    if 'user_id' not in session:
        return jsonify({"error":"login_required"}), 401

    profile = TeacherProfile.query.filter_by(user_id=session['user_id']).first()
    if not profile:
        return jsonify({"error":"not_a_teacher"}), 403

    b = Booking.query.get(booking_id)
    if not b or b.teacher_id != profile.id:
        return jsonify({"error":"not_found"}), 404

    # Accept both JSON and form data (FormData from frontend)
    data = request.json or request.form

    action = (data.get("action") or "").lower()

    # If teacher passed a meet_link in the request, save it
    provided_meet = data.get("meet_link")
    if provided_meet:
        provided_meet = provided_meet.strip()
        if provided_meet:
            b.meet_link = provided_meet

    if action == "accept":
        b.status = "accepted"
        # Auto-generate meet link if still empty
        if (not b.meet_link) or (b.meet_link.strip() == ""):
            b.meet_link = generate_meet_link()
    elif action == "reject":
        b.status = "rejected"
    elif action == "complete":
        b.status = "completed"
    else:
        return jsonify({"error":"unknown_action"}), 400

    db.session.commit()

    return jsonify({
        "ok": True,
        "status": b.status,
        "meet_link": b.meet_link or ""
    })

# 9) Student view their saved teachers & bookings
@app.route("/api/student/saved", methods=["GET"])
@login_required
def api_student_saved():
    if 'user_id' not in session:
        return jsonify({"error":"login_required"}), 401
    student_id = session['user_id']
    saved = SavedTeacher.query.filter_by(student_id=student_id).all()
    out = []
    for s in saved:
        p = s.teacher
        out.append({"id": p.id, "name": p.user.username, "subjects": p.subjects, "qualifications": p.qualifications})
    return jsonify(out)

@app.route("/api/student/bookings", methods=["GET"])
@login_required
def api_student_bookings():
    if 'user_id' not in session:
        return jsonify({"error":"login_required"}), 401
    student_id = session['user_id']
    bookings = Booking.query.filter_by(student_id=student_id).order_by(Booking.created_at.desc()).all()
    out = []
    for b in bookings:
        out.append({
            "id": b.id,
            "teacher_name": b.teacher.user.username,
            "subject": b.subject,
            "requested_time": b.requested_time.isoformat() if b.requested_time else None,
            "status": b.status,
            "meet_link": b.meet_link
        })
    return jsonify(out)





@app.route("/api/teacher/me")
@login_required
def api_teacher_me():
    if "user_id" not in session:
        return jsonify({"error": "login_required"}), 401
    
    profile = TeacherProfile.query.filter_by(user_id=session["user_id"]).first()
    if not profile:
        return jsonify({"error": "not_a_teacher"}), 403

    return jsonify({
        "id": profile.id,
        "name": profile.user.username,
        "bio": profile.bio,
        "qualifications": profile.qualifications,
        "subjects": profile.subjects,
        "experience_years": profile.experience_years,
        "availability": profile.availability,
        "verified": profile.verified
    })



@app.route("/reset_password", methods=["POST"])
@login_required
def reset_password():
    email = request.form.get("email")
    new_pass = request.form.get("password")

    if not email or not new_pass:
        return {"error": "Missing fields"}, 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return {"error": "User not found"}, 404

    user.password = bcrypt.generate_password_hash(new_pass).decode("utf-8")
    db.session.commit()

    return {"ok": True, "message": "Password reset successful"}

@app.route("/api/live/start", methods=["POST"])
@login_required
def start_live():
    profile = TeacherProfile.query.filter_by(user_id=session["user_id"]).first()
    if not profile:
        return jsonify({"error": "not_a_teacher"}), 403

    subject = request.form.get("subject", "Live Class")
    meet_link = generate_meet_link()

    live = LiveClass(
        teacher_id=profile.id,
        subject=subject,
        meet_link=meet_link,
        is_live=True
    )

    db.session.add(live)
    db.session.commit()

    return jsonify({
        "ok": True,
        "subject": subject,
        "meet_link": meet_link,
        "live_id": live.id
    })


@app.route("/api/live/end", methods=["POST"])
@login_required
def end_live():
    profile = TeacherProfile.query.filter_by(user_id=session["user_id"]).first()

    live = LiveClass.query.filter_by(teacher_id=profile.id, is_live=True).first()
    if not live:
        return jsonify({"error": "no_live_class"}), 404

    live.is_live = False
    db.session.commit()

    return jsonify({"ok": True})


@app.route("/api/live/current")
def get_current_live():
    live = LiveClass.query.filter_by(is_live=True).order_by(LiveClass.started_at.desc()).first()
    
    if not live:
        return jsonify({"live": False})

    teacher = TeacherProfile.query.get(live.teacher_id)

    return jsonify({
        "live": True,
        "subject": live.subject,
        "meet_link": live.meet_link,
        "teacher_name": teacher.user.username
    })


# ===============================
# 🤖 AI ASSISTANT PAGE ROUTE
# ===============================
@app.route('/assistant')
def assistant_page():
    return render_template('assistant.html')


# ==================================
# 🏁 START SERVER
# ==================================
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))   # <-- 5000 default now
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() in ("1","true","yes")
    app.run(host="0.0.0.0", port=port, debug=debug_mode)


