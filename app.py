from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from uuid import uuid4
from datetime import datetime
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(256), nullable=False)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    encrypted_path = db.Column(db.String(256), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(256))

# User loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
        hashed_pw = generate_password_hash(password)
        user = User(username=username, password_hash=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('upload'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['file']
        description = request.form.get('description', '')
        if not file:
            flash('No file selected')
            return redirect(request.url)
        filename = secure_filename(file.filename)
        uuid_str = str(uuid4())
        key = get_random_bytes(32)  # 256-bit key
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = file.read()
        # Pad data
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len]) * pad_len
        encrypted = iv + cipher.encrypt(data)
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{uuid_str}.bin')
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted)
        image = Image(user_id=current_user.id, filename=filename, uuid=uuid_str, encrypted_path=encrypted_path, description=description)
        db.session.add(image)
        db.session.commit()
        # Show key as hex for sharing
        key_hex = key.hex()
        return render_template('upload_success.html', key=key_hex, link=url_for('decrypt', uuid=uuid_str, _external=True))
    return render_template('upload.html')

@app.route('/my_uploads')
@login_required
def my_uploads():
    images = Image.query.filter_by(user_id=current_user.id).order_by(Image.uploaded_at.desc()).all()
    return render_template('my_uploads.html', images=images)

@app.route('/delete/<uuid>', methods=['POST'])
@login_required
def delete_upload(uuid):
    image = Image.query.filter_by(uuid=uuid, user_id=current_user.id).first_or_404()
    try:
        os.remove(image.encrypted_path)
    except Exception:
        pass
    db.session.delete(image)
    db.session.commit()
    flash('Upload deleted')
    return redirect(url_for('my_uploads'))

@app.route('/decrypt/<uuid>', methods=['GET', 'POST'])
def decrypt(uuid):
    image = Image.query.filter_by(uuid=uuid).first_or_404()
    if request.method == 'POST':
        key_hex = request.form['key']
        try:
            key = bytes.fromhex(key_hex)
            with open(image.encrypted_path, 'rb') as f:
                encrypted = f.read()
            iv = encrypted[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            data = cipher.decrypt(encrypted[16:])
            pad_len = data[-1]
            if pad_len < 1 or pad_len > 16:
                raise ValueError('Invalid padding')
            data = data[:-pad_len]
            return send_file(BytesIO(data), download_name=image.filename, mimetype='image/jpeg')
        except Exception:
            flash('Invalid key or decryption failed')
    return render_template('decrypt.html', image=image)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 