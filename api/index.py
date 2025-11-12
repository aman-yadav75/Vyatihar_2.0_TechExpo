from flask import Flask, render_template, send_from_directory, request, jsonify
import os
from werkzeug.utils import secure_filename
import google.generativeai as genai

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

# ==================================
# 🔑 GEMINI API KEY (replace with yours)
# ==================================
genai.configure(api_key="AIzaSyCSVU8XDYfcvr7hzre15llP8mG6C9Bzsec")

# ==================================
# 🌍 PAGE ROUTES
# ==================================
@app.route('/')
def home():
    try:
        return render_template('index.html')
    except Exception as e:
        return f"<h2 style='color:red;'>Template Error:</h2><pre>{e}</pre>"

@app.route('/admin')
def admin_page():
    return render_template('admin.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/status')
def live_status():
    return render_template('status.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(STATIC_DIR, filename)

# ==================================
# 🧠 AI STUDY ASSISTANT (GEMINI)
# ==================================
@app.route('/ask_ai', methods=['POST'])
def ask_ai():
    try:
        data = request.get_json()
        question = data.get("question", "").strip()
        if not question:
            return jsonify({"error": "No question provided"}), 400

        # 🧠 Automatically choose any working Gemini text model
        available_models = [m.name for m in genai.list_models() if "generateContent" in m.supported_generation_methods]
        if not available_models:
            return jsonify({"error": "No supported Gemini model found!"}), 500

        # Pick the first available one (usually gemini-1.5-flash or gemini-pro)
        model_name = available_models[0]
        print(f"✅ Using model: {model_name}")

        model = genai.GenerativeModel(model_name)
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
@app.route('/upload_note', methods=['POST'])
def upload_note():
    file = request.files.get('note')
    if not file:
        return "No file uploaded", 400
    filename = secure_filename(file.filename)
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    return f"<h3>✅ Note uploaded successfully: {filename}</h3><a href='/dashboard'>Go Back</a>"

# ==================================
# 🏁 START SERVER
# ==================================
if __name__ == '__main__':
    print("📂 BASE_DIR:", BASE_DIR)
    print("📂 TEMPLATE_DIR:", TEMPLATE_DIR)
    print("📂 STATIC_DIR:", STATIC_DIR)
    print("🚀 Flask server started: http://127.0.0.1:5001")
    app.run(host="0.0.0.0", port=5001, debug=True)
