# OpenClaw Media Manager Web App
# Python Flask Web Application

## 安裝依賴

```bash
pip install flask flask-login flask-bcrypt
```

## 專案結構

```
openclaw-media-web/
├── app.py              # 主程式
├── requirements.txt    # 依賴
└── templates/         # HTML 模板
    ├── base.html
    ├── login.html
    ├── index.html
    └── upload.html
```

## app.py

```python
import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# 配置
MEDIA_DIR = os.path.expanduser('~/.openclaw/media')
UPLOAD_FOLDER = MEDIA_DIR
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# 確保 media 目錄存在
os.makedirs(MEDIA_DIR, exist_ok=True)

# Flask-Login 配置
bcrypt = Bcrypt()
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 簡單用戶資料 (可改用資料庫)
users = {
    'admin': bcrypt.generate_password_hash('admin123').decode('utf-8')
}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 路由

@app.route('/')
@login_required
def index():
    files = []
    if os.path.exists(MEDIA_DIR):
        for f in os.listdir(MEDIA_DIR):
            filepath = os.path.join(MEDIA_DIR, f)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                files.append({
                    'name': f,
                    'size': stat.st_size,
                    'date': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
                })
    
    # 按日期排序
    files.sort(key=lambda x: x['date'], reverse=True)
    return render_template('index.html', files=files, media_dir=MEDIA_DIR)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users and bcrypt.check_password_hash(users[username], password):
            login_user(User(username))
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
            # 如果檔案已存在，加入時間戳
            if os.path.exists(os.path.join(MEDIA_DIR, filename)):
                name, ext = os.path.splitext(filename)
                filename = f"{name}_{datetime.now().strftime('%Y%m%d%H%M%S')}{ext}"
            
            file.save(os.path.join(MEDIA_DIR, filename))
            flash(f'File uploaded: {filename}', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid file type', 'error')
    
    return render_template('upload.html')

@app.route('/download/<filename>')
@login_required
def download(filename):
    return send_from_directory(MEDIA_DIR, filename, as_attachment=True)

@app.route('/view/<filename>')
@login_required
def view(filename):
    return send_from_directory(MEDIA_DIR, filename)

@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete(filename):
    filepath = os.path.join(MEDIA_DIR, secure_filename(filename))
    if os.path.exists(filepath):
        os.remove(filepath)
        flash(f'Deleted: {filename}', 'success')
    else:
        flash('File not found', 'error')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

## templates/base.html

```html
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenClaw Media Manager</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: #fff; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
        h1 { color: #333; }
        nav a { margin-left: 20px; color: #007bff; text-decoration: none; }
        nav a:hover { text-decoration: underline; }
        .flash { padding: 10px 20px; margin-bottom: 20px; border-radius: 4px; }
        .flash.success { background: #d4edda; color: #155724; }
        .flash.error { background: #f8d7da; color: #721c24; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-primary { background: #007bff; color: #fff; }
        .btn-danger { background: #dc3545; color: #fff; }
        .btn-sm { padding: 4px 8px; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔥 OpenClaw Media Manager</h1>
            {% if current_user.is_authenticated %}
            <nav>
                <a href="{{ url_for('index') }}">📁 檔案列表</a>
                <a href="{{ url_for('upload') }}">⬆️ 上傳</a>
                <a href="{{ url_for('logout') }}">🚪 登出</a>
            </nav>
            {% endif %}
        </header>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
</body>
</html>
```

## templates/login.html

```html
{% extends "base.html" %}

{% block content %}
<div style="max-width: 400px; margin: 50px auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
    <h2 style="margin-bottom: 20px;">🔐 登入</h2>
    <form method="POST">
        <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">帳號</label>
            <input type="text" name="username" required style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px;">
        </div>
        <div style="margin-bottom: 20px;">
            <label style="display: block; margin-bottom: 5px;">密碼</label>
            <input type="password" name="password" required style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px;">
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">登入</button>
    </form>
</div>
{% endblock %}
```

## templates/index.html

```html
{% extends "base.html" %}

{% block content %}
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
    <h2>📁 檔案列表 ({{ files|length }} 個檔案)</h2>
    <a href="{{ url_for('upload') }}" class="btn btn-primary">⬆️ 上傳新檔案</a>
</div>

<div style="background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
    <table style="width: 100%; border-collapse: collapse;">
        <thead>
            <tr style="background: #f8f9fa; border-bottom: 2px solid #dee2e6;">
                <th style="padding: 15px; text-align: left;">預覽</th>
                <th style="padding: 15px; text-align: left;">檔名</th>
                <th style="padding: 15px; text-align: left;">大小</th>
                <th style="padding: 15px; text-align: left;">日期</th>
                <th style="padding: 15px; text-align: right;">操作</th>
            </tr>
        </thead>
        <tbody>
            {% for file in files %}
            <tr style="border-bottom: 1px solid #dee2e6;">
                <td style="padding: 10px;">
                    <img src="{{ url_for('view', filename=file.name) }}" style="width: 60px; height: 60px; object-fit: cover; border-radius: 4px;">
                </td>
                <td style="padding: 10px;">{{ file.name }}</td>
                <td style="padding: 10px;">{{ (file.size / 1024)|round(1) }} KB</td>
                <td style="padding: 10px;">{{ file.date }}</td>
                <td style="padding: 10px; text-align: right;">
                    <a href="{{ url_for('view', filename=file.name) }}" target="_blank" class="btn btn-primary btn-sm">👁️ 檢視</a>
                    <a href="{{ url_for('download', filename=file.name) }}" class="btn btn-primary btn-sm">⬇️ 下載</a>
                    <form method="POST" action="{{ url_for('delete', filename=file.name) }}" style="display: inline;" onsubmit="return confirm('確定要刪除嗎？');">
                        <button type="submit" class="btn btn-danger btn-sm">🗑️ 刪除</button>
                    </form>
                </td>
            </tr>
            {% else %}
            <tr>
                <td colspan="5" style="padding: 30px; text-align: center; color: #666;">尚無檔案</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}
```

## templates/upload.html

```html
{% extends "base.html" %}

{% block content %}
<div style="max-width: 600px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
    <h2 style="margin-bottom: 20px;">⬆️ 上傳圖片</h2>
    <form method="POST" enctype="multipart/form-data">
        <div style="margin-bottom: 20px;">
            <input type="file" name="file" accept="image/*" required style="width: 100%; padding: 10px; border: 2px dashed #ddd; border-radius: 8px;">
        </div>
        <div style="margin-bottom: 20px; color: #666; font-size: 14px;">
            支援格式: PNG, JPG, JPEG, GIF, WEBP, BMP<br>
            最大檔案大小: 16MB
        </div>
        <div style="display: flex; gap: 10px;">
            <button type="submit" class="btn btn-primary">上傳</button>
            <a href="{{ url_for('index') }}" class="btn" style="background: #6c757d; color: #fff;">取消</a>
        </div>
    </form>
</div>
{% endblock %}
```

## requirements.txt

```
flask==3.0.0
flask-login==0.6.3
flask-bcrypt==1.0.1
Werkzeug==3.0.1
```

## 啟動方式

```bash
# 建立虛擬環境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或 venv\Scripts\activate  # Windows

# 安裝依賴
pip install -r requirements.txt

# 啟動伺服器
python app.py
```

## 預設登入帳號

- 帳號: `admin`
- 密碼: `admin123`

**請記得上線前修改密碼！**

## 部署到 Zeabur

1. 推送到 GitHub
2. 在 Zeabur 選擇 Python Flask
3. 設定環境變數 `SECRET_KEY` 和帳號密碼
4. 部署完成！

---

需要我幫你調整什麼嗎？🔥

