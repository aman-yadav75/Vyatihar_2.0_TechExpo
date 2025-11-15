from flask import Flask, render_template, send_from_directory, request, jsonify, session, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
import google.generativeai as genai
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

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
# 🔑 GEMINI API KEY
# ==================================
import sys
GENAI_KEY = os.environ.get("GENAI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
if not GENAI_KEY:
    print("⚠️ GENAI_API_KEY not set — AI features will be disabled")
else:
    genai.configure(api_key=GENAI_KEY)


# ==================================
# 🌍 PAGE ROUTES
# ==================================
@app.route('/')
def home():
    return render_template('index.html')

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

    db.session.delete(user_to_delete)
    db.session.commit()

    print(f"🗑️ Deleted user: {user_to_delete.email}")
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
def live_status():
    return render_template('status.html')

@app.route('/static/<path:filename>')
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
        if user and bcrypt.check_password_hash(user.password, password):

            # Save basic session info
            session["user_id"] = user.id
            session["username"] = user.username
            session["email"] = user.email

            # Check admin
            if getattr(user, "is_admin", False):
                session["is_admin"] = True
                return redirect(url_for("admin_page"))
            else:
                session["is_admin"] = False
                return redirect(url_for("dashboard"))

        return "<h3 style='color:red;'>❌ Invalid credentials. <a href='/login'>Try again</a>.</h3>"

    return render_template("login.html")







@app.route('/logout')
def logout():
    # ✅ clear Flask session
    session.clear()
    print("🚪 User logged out successfully")

    # ✅ optional: redirect to login
    return redirect(url_for('login'))



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

        available_models = [m.name for m in genai.list_models() if "generateContent" in m.supported_generation_methods]
        if not available_models:
            return jsonify({"error": "No supported Gemini model found!"}), 500

        model = genai.GenerativeModel(available_models[0])
        response = model.generate_content(question)
        answer = getattr(response, "text", "⚠️ No response text available")
        return jsonify({"answer": answer})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================================
# 🎥 LIVE CLASS ENDPOINT
# ==================================
@app.route("/live_class", methods=["GET"])
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

@app.route('/subjects')
def subjects_page():
    return render_template('index.html')

@app.route('/match')
def match_page():
    return render_template('index.html')


@app.route("/projects")
def projects_page():
    return render_template("index.html")


@app.route('/rewards')
def rewards_page():
    return render_template('index.html')


# ==================================
# 🏁 START SERVER
# ==================================
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() in ("1","true","yes")
    app.run(host="0.0.0.0", port=port, debug=debug_mode)

