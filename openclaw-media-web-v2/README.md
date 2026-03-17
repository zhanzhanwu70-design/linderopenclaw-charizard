# OpenClaw Media Manager Web App v2
# Python Flask + SQLite 版本

## 功能清單

| 功能 | 說明 |
|------|------|
| 🔐 用戶認證 | 註冊/登入/登出 |
| 📁 檔案管理 | 上傳/下載/刪除/預覽 |
| 🗂️ 資料夾支援 | 建立資料夾/移動檔案 |
| 🔍 搜尋功能 | 搜尋檔案名稱 |
| 📊 空間統計 | 顯示使用空間 |
| 📱 響應式設計 | 手機/平板都能用 |

## 安裝依賴

```bash
pip install flask flask-login flask-bcrypt flask-sqlalchemy
```

## 專案結構

```
openclaw-media-web/
├── app.py              # 主程式
├── models.py           # 資料庫模型
├── requirements.txt    # 依賴
├── static/            # 靜態資源
│   └── style.css
└── templates/         # HTML 模板
    ├── base.html
    ├── login.html
    ├── register.html
    ├── index.html
    ├── upload.html
    ├── folder.html
    └── admin.html
```

## app.py

```python
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
    
    # 取得資料夾內容
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
    
    # 空間統計
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
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
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
            return redirect(url_for('index'))
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
            # 避免檔名衝突
            if os.path.exists(os.path.join(MEDIA_DIR, folder.lstrip('/'), filename)):
                name, ext = os.path.splitext(filename)
                filename = f"{name}_{datetime.now().strftime('%Y%m%d%H%M%S')}{ext}"
            
            filepath = os.path.join(MEDIA_DIR, folder.lstrip('/'), filename)
            file.save(filepath)
            
            # 記錄到資料庫
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
        # 刪除資料庫記錄
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
    # 建立管理員帳號（如果不存在）
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
```

## templates/base.html

```html
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}OpenClaw Media Manager{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <nav class="navbar">
        <div class="nav-brand">
            <a href="{{ url_for('index') }}">🔥 OpenClaw Media</a>
        </div>
        <div class="nav-links">
            {% if current_user.is_authenticated %}
                <span>👤 {{ current_user.username }}</span>
                <a href="{{ url_for('index') }}">📁 檔案</a>
                <a href="{{ url_for('upload') }}">⬆️ 上傳</a>
                <a href="{{ url_for('logout') }}">🚪 登出</a>
            {% else %}
                <a href="{{ url_for('login') }}">🔐 登入</a>
                <a href="{{ url_for('register') }}">📝 註冊</a>
            {% endif %}
        </div>
    </nav>
    
    <main class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </main>
    
    <footer class="footer">
        <p>Powered by OpenClaw 🦄</p>
    </footer>
</body>
</html>
```

## templates/index.html

```html
{% extends "base.html" %}

{% block content %}
<div class="toolbar">
    <h2>📁 檔案列表 {% if current_folder != '/' %} - {{ current_folder }}{% endif %}</h2>
    <div class="toolbar-actions">
        <a href="{{ url_for('upload', folder=current_folder) }}" class="btn btn-primary">⬆️ 上傳</a>
        <form method="POST" action="{{ url_for('create_folder') }}" class="inline-form">
            <input type="hidden" name="parent_folder" value="{{ current_folder }}">
            <input type="text" name="folder_name" placeholder="新資料夾" required>
            <button type="submit" class="btn btn-secondary">📁 新資料夾</button>
        </form>
    </div>
</div>

<!-- 搜尋 -->
<div class="search-box">
    <form method="GET" action="{{ url_for('search') }}">
        <input type="text" name="q" placeholder="搜尋檔案..." value="{{ search_query or '' }}">
        <button type="submit">🔍 搜尋</button>
    </form>
</div>

<!-- 麵包屑 -->
{% if current_folder != '/' %}
<nav class="breadcrumb">
    <a href="{{ url_for('index', folder='/') }}">🏠</a>
    {% set parts = current_folder.strip('/').split('/') %}
    {% set path = '' %}
    {% for part in parts %}
        {% set path = path + '/' + part %}
        <span>/</span>
        <a href="{{ url_for('index', folder=path) }}">{{ part }}</a>
    {% endfor %}
</nav>
{% endif %}

<!-- 資料夾列表 -->
{% if folders %}
<div class="folder-list">
    {% for folder in folders %}
    <div class="item folder">
        <a href="{{ url_for('index', folder=folder.path) }}">
            <span class="icon">📁</span>
            <span class="name">{{ folder.name }}</span>
        </a>
    </div>
    {% endfor %}
</div>
{% endif %}

<!-- 檔案列表 -->
{% if files or search_results %}
<table class="file-table">
    <thead>
        <tr>
            <th>名稱</th>
            <th>大小</th>
            <th>日期</th>
            <th>操作</th>
        </tr>
    </thead>
    <tbody>
        {% if search_results %}
            {% for file in search_results %}
            <tr>
                <td>📄 {{ file.name }}</td>
                <td>{{ file.size }}</td>
                <td>-</td>
                <td>
                    <a href="{{ url_for('view', filename=file.path) }}" target="_blank" class="btn btn-sm">👁️</a>
                    <a href="{{ url_for('download', filename=file.path) }}" class="btn btn-sm">⬇️</a>
                </td>
            </tr>
            {% endfor %}
        {% else %}
            {% for file in files %}
            <tr>
                <td>📄 {{ file.name }}</td>
                <td>{{ file.size }}</td>
                <td>{{ file.date }}</td>
                <td>
                    <a href="{{ url_for('view', filename=(current_folder + '/' + file.name)|replace('//', '/')) }}" target="_blank" class="btn btn-sm">👁️</a>
                    <a href="{{ url_for('download', filename=(current_folder + '/' + file.name)|replace('//', '/')) }}" class="btn btn-sm">⬇️</a>
                    <form method="POST" action="{{ url_for('delete', filename=(current_folder + '/' + file.name)|replace('//', '/')) }}" style="display:inline" onsubmit="return confirm('確定刪除？');">
                        <button type="submit" class="btn btn-sm btn-danger">🗑️</button>
                    </form>
                </td>
            </tr>
            {% endfor %}
        {% endif %}
    </tbody>
</table>
{% else %}
<p class="empty">尚無檔案</p>
{% endif %}

<!-- 空間統計 -->
<div class="stats">
    <span>💾 總空間使用：{{ total_size }}</span>
</div>
{% endblock %}
```

## static/style.css

```css
:root {
    --primary: #3b82f6;
    --danger: #ef4444;
    --success: #22c55e;
    --bg: #f8fafc;
    --card: #ffffff;
    --text: #1e293b;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

.navbar {
    background: var(--card);
    padding: 1rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.navbar a {
    color: var(--text);
    text-decoration: none;
    margin-left: 1rem;
}

.navbar a:hover { color: var(--primary); }

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
    flex: 1;
    width: 100%;
}

.toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
    gap: 1rem;
}

.toolbar-actions {
    display: flex;
    gap: 0.5rem;
    align-items: center;
}

.btn {
    padding: 0.5rem 1rem;
    border: none;
    border-radius: 0.375rem;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    font-size: 0.875rem;
}

.btn-primary { background: var(--primary); color: white; }
.btn-secondary { background: #64748b; color: white; }
.btn-danger { background: var(--danger); color: white; }
.btn-sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }

.flash {
    padding: 1rem;
    border-radius: 0.5rem;
    margin-bottom: 1rem;
}
.flash.success { background: #dcfce7; color: #166534; }
.flash.error { background: #fee2e2; color: #991b1b; }

.file-table {
    width: 100%;
    background: var(--card);
    border-radius: 0.5rem;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.file-table th, .file-table td {
    padding: 0.75rem 1rem;
    text-align: left;
}

.file-table th { background: #f1f5f9; }
.file-table tr:not(:last-child) td { border-bottom: 1px solid #e2e8f0; }

.search-box {
    margin-bottom: 1rem;
}
.search-box input {
    padding: 0.5rem;
    border: 1px solid #e2e8f0;
    border-radius: 0.375rem;
    width: 300px;
}

.breadcrumb {
    margin-bottom: 1rem;
    font-size: 0.875rem;
}

.stats {
    margin-top: 2rem;
    padding: 1rem;
    background: var(--card);
    border-radius: 0.5rem;
    font-size: 0.875rem;
}

.footer {
    text-align: center;
    padding: 1rem;
    color: #64748b;
    font-size: 0.875rem;
}

.inline-form {
    display: flex;
    gap: 0.5rem;
}

.inline-form input {
    padding: 0.5rem;
    border: 1px solid #e2e8f0;
    border-radius: 0.375rem;
}

@media (max-width: 640px) {
    .toolbar { flex-direction: column; align-items: flex-start; }
    .search-box input { width: 100%; }
    .file-table { font-size: 0.875rem; }
}
```

## requirements.txt

```
flask==3.0.0
flask-login==0.6.3
flask-bcrypt==1.0.1
flask-sqlalchemy==3.1.1
Werkzeug==3.0.1
gunicorn==21.2.0
```

## Zeabur 部署指南

### 1. 推送程式碼到 GitHub

```bash
cd openclaw-media-web-v2
git init
git add .
git commit -m "OpenClaw Media Manager v2"
# 建立 GitHub repo，然後 push
```

### 2. Zeabur 部署

1. 登入 [zeabur.com](https://zeabur.com)
2. New Project → Deploy from GitHub
3. 選擇這個 repo
4. 選擇 Python Flask
5. 設定環境變數：

| 變數 | 值 |
|------|-----|
| `SECRET_KEY` | 隨機字串（用 `openssl rand -hex 32` 生成）|
| `MEDIA_DIR` | `/app/media` |
| `PORT` | `5000` |

6. 點擊 Deploy

### 3. 掛載 Volume（重要！）

Zeabur 免費版無法掛載 Volume，付費版設定：

1. 專案 Settings → Storage
2. Create Storage (建議 1GB)
3. 掛載到 `/app/media`

### 4. 或者使用外部儲存

如果不想用 Volume，可以用 **Cloudflare R2**（免費 1GB/月）：

```python
# 新增 r2_storage.py
import boto3

class R2Storage:
    def __init__(self):
        self.client = boto3.client('s3',
            endpoint_url=os.environ['R2_ENDPOINT'],
            aws_access_key_id=os.environ['R2_ACCESS_KEY'],
            aws_secret_access_key=os.environ['R2_SECRET_KEY'])
        self.bucket = os.environ['R2_BUCKET']
    
    def upload(self, key, file):
        self.client.upload_fileobj(file, self.bucket, key)
    
    def download(self, key):
        return self.client.download_fileobj(self.bucket, key)
```

### 5. 預設帳號

- 帳號：`admin`
- 密碼：`admin123`

**上線後請立即修改密碼！**

---

## 安全檢查清單（由 mrmime 提供）

- [ ] 修改 SECRET_KEY
- [ ] 修改 admin 密碼
- [ ] 啟用 HTTPS
- [ ] 設定登入失敗次數限制
- [ ] 定期備份資料庫
- [ ] 監控異常登入

---

有任何問題嗎？🔥
