import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-prod')

# 配置
MEDIA_DIR = os.environ.get('MEDIA_DIR', os.path.expanduser('~/.openclaw/media'))
UPLOAD_FOLDER = MEDIA_DIR
SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'pdf', 'txt', 'doc', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# 確保目錄存在
os.makedirs(MEDIA_DIR, exist_ok=True)
os.makedirs(os.path.join(MEDIA_DIR, 'shared'), exist_ok=True)

# 初始化擴展
bcrypt = Bcrypt()
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ============== 資料庫模型 ==============

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    filesize = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    folder = db.Column(db.String(255), default='/')
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

# ============== 工具函數 ==============

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_folder_size(path):
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.exists(fp):
                total += os.path.getsize(fp)
    return total

def format_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

# ============== 路由 ==============

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    folder = request.args.get('folder', '/')
    
    folder_path = os.path.join(MEDIA_DIR, folder.lstrip('/'))
    if not os.path.exists(folder_path):
        os.makedirs(folder_path, exist_ok=True)
    
    files = []
    folders = []
    
    for item in os.listdir(folder_path):
        item_path = os.path.join(folder_path, item)
        if os.path.isdir(item_path):
            folders.append({
                'name': item,
                'path': os.path.join(folder, item)
            })
        else:
            stat = os.stat(item_path)
            files.append({
                'name': item,
                'size': format_size(stat.st_size),
                'size_bytes': stat.st_size,
                'date': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
            })
    
    total_size = get_folder_size(MEDIA_DIR)
    
    return render_template('index.html', 
                         files=files, 
                         folders=folders,
                         current_folder=folder,
                         total_size=format_size(total_size))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password_hash=hashed)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    folder = request.args.get('folder', '/')
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if os.path.exists(os.path.join(MEDIA_DIR, folder.lstrip('/'), filename)):
                name, ext = os.path.splitext(filename)
                filename = f"{name}_{datetime.now().strftime('%Y%m%d%H%M%S')}{ext}"
            
            filepath = os.path.join(MEDIA_DIR, folder.lstrip('/'), filename)
            file.save(filepath)
            
            record = FileRecord(
                filename=filename,
                original_name=file.filename,
                filepath=filepath,
                filesize=os.path.getsize(filepath),
                user_id=current_user.id,
                folder=folder
            )
            db.session.add(record)
            db.session.commit()
            
            flash(f'File uploaded: {filename}', 'success')
            return redirect(url_for('index', folder=folder))
        else:
            flash('Invalid file type', 'error')
    
    return render_template('upload.html', folder=folder)

@app.route('/download/<path:filename>')
@login_required
def download(filename):
    return send_from_directory(MEDIA_DIR, filename, as_attachment=True)

@app.route('/view/<path:filename>')
@login_required
def view(filename):
    return send_from_directory(MEDIA_DIR, filename)

@app.route('/delete/<path:filename>', methods=['POST'])
@login_required
def delete(filename):
    filepath = os.path.join(MEDIA_DIR, filename.lstrip('/'))
    if os.path.exists(filepath):
        os.remove(filepath)
        FileRecord.query.filter_by(filepath=filepath).delete()
        db.session.commit()
        flash(f'Deleted: {filename}', 'success')
    else:
        flash('File not found', 'error')
    return redirect(url_for('index', folder=os.path.dirname(filename)))

@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    folder_name = request.form.get('folder_name')
    parent_folder = request.form.get('parent_folder', '/')
    
    if folder_name:
        new_folder_path = os.path.join(MEDIA_DIR, parent_folder.lstrip('/'), secure_filename(folder_name))
        os.makedirs(new_folder_path, exist_ok=True)
        flash(f'Folder created: {folder_name}', 'success')
    
    return redirect(url_for('index', folder=parent_folder))

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    results = []
    
    if query:
        for root, dirs, files in os.walk(MEDIA_DIR):
            for f in files:
                if query.lower() in f.lower():
                    filepath = os.path.join(root, f)
                    rel_path = os.path.relpath(filepath, MEDIA_DIR)
                    results.append({
                        'name': f,
                        'path': rel_path,
                        'size': format_size(os.path.getsize(filepath))
                    })
    
    return render_template('index.html', search_results=results, search_query=query)

@app.route('/api/stats')
@login_required
def stats():
    total_files = sum(1 for _, _, files in os.walk(MEDIA_DIR) for _ in files)
    total_folders = sum(1 for _, dirs, _ in os.walk(MEDIA_DIR) for _ in dirs)
    total_size = get_folder_size(MEDIA_DIR)
    users_count = User.query.count()
    
    return jsonify({
        'total_files': total_files,
        'total_folders': total_folders,
        'total_size': format_size(total_size),
        'total_size_bytes': total_size,
        'users_count': users_count
    })

# ============== 初始化 ==============

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=bcrypt.generate_password_hash('admin123').decode('utf-8'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created: admin / admin123")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
