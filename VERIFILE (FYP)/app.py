import os
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cybersecurity_secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///verifile.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Konfigurasi Email (Guna Gmail App Password)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com' # TUKAR INI
app.config['MAIL_PASSWORD'] = 'your-app-password'    # TUKAR INI

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    role = db.Column(db.String(20)) # 'admin' atau 'user'

class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    category = db.Column(db.String(50)) # Transcript, Exam, Certificate
    hash_value = db.Column(db.String(64))
    upload_time = db.Column(db.DateTime, default=datetime.now)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def calculate_hash(file):
    sha256 = hashlib.sha256()
    while chunk := file.read(4096):
        sha256.update(chunk)
    file.seek(0)
    return sha256.hexdigest()

# --- MODEL DATABASE BARU ---
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(100))
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.now)

# Fungsi helper untuk rakam log secara automatik
def record_log(action_text):
    new_log = AuditLog(user_email=current_user.email, action=action_text)
    db.session.add(new_log)
    db.session.commit()

# --- ROUTES ---

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    role_requested = request.form.get('role')
    
    user = User.query.filter_by(email=email, password=password, role=role_requested).first()
    
    if user:
        login_user(user)
        # Email Notification
        msg = Message('VERIFILE Login Alert', sender='noreply@verifile.com', recipients=[email])
        msg.body = f"Hello, you have successfully logged in as {user.role} at {datetime.now()}."
        # mail.send(msg) # Un-comment if email config is ready
        
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    
    flash('Invalid credentials!')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        new_user = User(
            email=request.form.get('email'),
            password=request.form.get('password'),
            role=request.form.get('role')
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin': return "Access Denied"
    files = FileRecord.query.all()
    # Ambil 10 log terakhir untuk dipaparkan
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all() 
    return render_template('dashboard_admin.html', user=current_user, files=files, logs=logs)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    files = FileRecord.query.all()
    return render_template('dashboard_user.html', user=current_user, files=files)

@app.route('/upload_admin', methods=['POST'])
@login_required
def upload_admin():
    if current_user.role != 'admin': return "Access Denied"
    
    file = request.files['file']
    category = request.form.get('category')
    
    if file:
        file_hash = calculate_hash(file)
        # Cek jika file sudah ada untuk di-update/replace
        existing = FileRecord.query.filter_by(filename=file.filename, category=category).first()
        if existing:
            existing.hash_value = file_hash
            existing.upload_time = datetime.now()
        else:
            new_file = FileRecord(filename=file.filename, category=category, hash_value=file_hash)
            db.session.add(new_file)
        
        db.session.commit()
        record_log(f"Admin uploaded/updated file: {file.filename}") 
        flash('File Registered/Updated in Library!')
    return redirect(url_for('admin_dashboard'))

@app.route('/compare', methods=['POST'])
@login_required
def compare_file():
    file = request.files['file']
    target_id = request.form.get('file_id')
    
    if file:
        user_hash = calculate_hash(file)
        original = FileRecord.query.get(target_id)
        
        match = (user_hash == original.hash_value)
        return render_template('dashboard_user.html', match=match, files=FileRecord.query.all(), result_msg="Match!" if match else "Tampered!")

@app.route('/update_file/<int:file_id>', methods=['POST'])
@login_required
def update_file(file_id):
    if current_user.role != 'admin':
        return "Unauthorized Access", 403
    
    file = request.files['file']
    if file:
        # 1. Kira hash baru untuk fail yang diupload.pdf]
        new_hash = calculate_hash(file)
        
        # 2. Cari rekod fail dalam database menggunakan ID.pdf]
        file_to_update = FileRecord.query.get_or_404(file_id)
        
        # 3. Update nilai hash dan masa.pdf]
        file_to_update.hash_value = new_hash
        file_to_update.upload_time = datetime.now()
        
        db.session.commit()
        flash(f'File {file_to_update.filename} has been updated with new hash!')
        
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True, port=8080)