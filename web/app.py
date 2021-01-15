from flask import session, Flask, request, render_template, make_response, redirect, flash, g, send_file, url_for

from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import asc, desc
from sqlalchemy import or_, and_
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

from bcrypt import hashpw, checkpw, gensalt
from passlib.hash import bcrypt
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
import base64
import hashlib

from dotenv import load_dotenv
from datetime import timedelta, datetime
import uuid
import json
import re
import requests
import os
import time
import io
import regex
import jwt

#------------------------------------------------------------------------------------------------

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1 ,x_proto=1)
load_dotenv()
JWT_SECRET = os.environ.get('JWT_SECRET')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('POSTGRES_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.secret_key = os.environ.get('SECRET_KEY')
csrf = CSRFProtect(app)
app.config['SESSION_TYPE'] = "sqlalchemy"
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_SQLALCHEMY_TABLE'] = "sessions"
app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
ses = Session(app)
app.permanent_session_lifetime = timedelta(minutes=5)

FAILED_AUTH_TIME = 300 #seconds
FAILED_AUTH_MAX_ATTEMPTS = 5

#------------------------------------------------------------------------------------------------

class UserModel(db.Model):
    __tablename__ = 'users'
    login = db.Column(db.String(), primary_key=True)
    password = db.Column(db.String())
    email = db.Column(db.String())
    def __init__(self, data):
        self.login = data.get("login")
        self.password = data.get("password")
        self.email = data.get("email")
    def __repr__(self):
        return f"<User {self.login}"

def user_exists(login):
    return db.session.query(UserModel).filter_by(login=login).first()

def create_user(data):
    data["password"] = bcrypt.using(rounds=5).hash(data["password"])
    db.session.add(UserModel(data))
    db.session.commit()

def verify_user(login, password):
    if not user_exists(login):
        return False
    hpassword = db.session.query(UserModel).filter_by(login=login).first().password
    return bcrypt.verify(password, hpassword)

def update_password(login, password):
    user = db.session.query(UserModel).filter_by(login=login).first()
    password = hashpw(password.encode('utf-8'), gensalt(5)).decode('utf8')
    user.password = password
    db.session.commit()

def is_valid(field, value):
    if field == 'login': return re.compile('[a-z]{3,16}').match(value)
    if field == 'password': return re.compile('.{8,}').match(value.strip()) and \
                                   regex.compile('.*[[:upper:]].*').match(value.strip()) and \
                                   regex.compile('.*[[:lower:]].*').match(value.strip()) and \
                                   re.compile('.*[!@#$&*].*').match(value.strip()) and \
                                   re.compile('.*[0-9].*').match(value.strip())
    if field == 'email': return re.compile('[\w\.-]+@[\w\.-]+(\.[\w]+)+').match(value)
    if field == 'passwordlite': return re.compile('.{8,}').match(value.strip())
    return False

def generate_recovery_email(user):
    user = user_exists(user)
    if user:
        return {
            "login": user.login,
            "email": user.email,
            "link": url_for("pass_reset_get", token = generate_pass_reset_token(user.login), _external=True)
        }
    return {}

def generate_pass_reset_token(user):
    payload = {
        "iss": "notatkaplus",
        "aud": "notatkaplus",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(seconds=900),
        "sub": user
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


#------------------------------------------------------------------------------------------------

class LoginAttemptModel(db.Model):
    __tablename__ = 'login_attempts'
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String())
    time = db.Column(db.Integer())
    is_success = db.Column(db.String())
    ip = db.Column(db.String())
    def __init__(self, data):
        self.user = data.get("user")
        self.time = data.get("time")
        self.is_success = data.get("is_success")
        self.ip = data.get("ip")
    def __repr__(self):
        return f"<LoginAttempt {self.user} {self.time}"
    def as_dict_no_user(self):
        return {
            "ip": self.ip,
            "time": datetime.utcfromtimestamp(self.time).strftime('%Y-%m-%d %H:%M:%S'),
            "is_success": "udana" if self.is_success == "true" else "nieudana"
        }
    

def register_attempt(data):
    db.session.add(LoginAttemptModel(data))
    db.session.commit()

def count_attempts(ip):
    stime = int(time.time()) - FAILED_AUTH_TIME
    c = db.session.query(LoginAttemptModel).filter(
        and_(
            LoginAttemptModel.ip.like(ip),
            LoginAttemptModel.is_success.like("false"),
            LoginAttemptModel.time > stime
        )
    ).count()
    return c 

def get_last_login(user):
    lasttime = db.session.query(LoginAttemptModel).filter(
        and_(
            LoginAttemptModel.user.like(user),
            LoginAttemptModel.is_success.like("true")
        )
    ).order_by(desc(LoginAttemptModel.time))
    try:
        lasttime = lasttime[1]
    except:
        return None
    return datetime.utcfromtimestamp(lasttime.time).strftime('%Y-%m-%d %H:%M:%S') if lasttime else None

def check_suspicious_attempts(user, ip):
    lasttime = db.session.query(LoginAttemptModel).filter(
        and_(
            LoginAttemptModel.user.like(user),
            LoginAttemptModel.ip.like(ip),
            LoginAttemptModel.is_success.like("true")
        )
    ).order_by(desc(LoginAttemptModel.time))
    try:
        lasttime = lasttime[1].time
    except:
        lasttime = 0

    attempts = db.session.query(LoginAttemptModel).filter(
        and_(
            LoginAttemptModel.user.like(user),
            LoginAttemptModel.ip.notlike(ip),
            LoginAttemptModel.time > lasttime
        )
    ).order_by(desc(LoginAttemptModel.time))
    return [attempt.as_dict_no_user() for attempt in attempts]

#------------------------------------------------------------------------------------------------

class NoteModel(db.Model):
    __tablename__ = 'notes'
    id = db.Column(db.String(), primary_key=True)
    owner = db.Column(db.String())
    text = db.Column(db.String())
    is_public = db.Column(db.String())
    password = db.Column(db.String())
    creation_time = db.Column(db.String())
    file = db.Column(db.String())
    def __init__(self, data):
        self.id = data.get("id")
        self.owner = data.get("owner")
        self.text = data.get("text")
        self.is_public = data.get("is_public")
        self.password = data.get("password")
        self.creation_time = data.get("creation_time")
        self.file = data.get("file")
    def __repr__(self):
        return f"<User {self.id}"
    def as_dict(self):
        file = self.file
        if file:
            f = get_file(file, self.owner)
            file = {
                "id": f.id,
                "file_name": f.file_name
            }
        else:
            file = None
        return {
            "id": self.id,
            "owner": self.owner,
            "text": self.text,
            "password": "true" if len(self.password) > 0 else "false",
            "is_public": "publiczna" if self.is_public == "true" else "prywatna",
            "creation_time": self.creation_time,
            "file": file
        }

def create_note(data):
    if (len(data.get('password')) > 0):
        nonce = base64.b64encode(get_random_bytes(8)).decode()
        data["text"] = encrypt_text(data["text"], data["password"] + nonce)
        data["password"] = hashpw(data["password"].encode(), gensalt(5)).decode() + nonce
    if data["file"]:
        file_data = {
            "id": uuid.uuid4().hex,
            "file_name": data["file"].filename,
            "value": data["file"].read()
        }
        db.session.add(FileModel(file_data))
        data["file"] = file_data.get("id")
    else:
        data["file"] = ""
    db.session.add(NoteModel(data))
    db.session.commit()

def get_note(id, user, password):
    note = db.session.query(NoteModel).filter_by(id=id).first()
    if (note.owner == user or note.is_public == "true"):
        if checkpw(password.encode(), note.password[:-12].encode()):
            note_d = note.as_dict()
            note_d["text"] = decrypt_text(note_d["text"], password + note.password[-12:])
            note_d["password"] = "false"
            return note_d
        else:
            return None
    else:
        return None

def get_notes(user):
    notes = db.session.query(NoteModel).filter(
        or_(
            NoteModel.owner.like(user),
            NoteModel.is_public.like("true")
        )
    )
    return [note.as_dict() for note in notes]

def expand_data(data):
    return data + b"\x00"*(16-len(data)%16) 

def encrypt_text(text, password):
    nonce = base64.b64decode(password[-12:].encode())
    counter = Counter.new(64, nonce) 
    key = hashlib.sha256(password[0:-12].encode()).digest()
    aes = AES.new(key, AES.MODE_CTR, counter=counter)
    encrypted = aes.encrypt(expand_data(text.encode()))
    return base64.b64encode(encrypted).decode()

def decrypt_text(text, password):
    nonce = base64.b64decode(password[-12:].encode())
    counter = Counter.new(64, nonce) 
    key = hashlib.sha256(password[0:-12].encode()).digest()
    aes = AES.new(key, AES.MODE_CTR, counter=counter)
    encrypted = base64.b64decode(text.encode())
    return aes.decrypt(encrypted).decode()
#------------------------------------------------------------------------------------------------

class FileModel(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.String(), primary_key=True)
    file_name = db.Column(db.String())
    value = db.Column(db.LargeBinary)
    def __init__(self, data):
        self.id = data.get("id")
        self.file_name = data.get("file_name")
        self.value = data.get("value")
    def __repr__(self):
        return f"<File {self.id}"

def get_file(id, user):
    note = db.session.query(NoteModel).filter_by(file=id).first()
    if (note.is_public or note.owner == user):
        return db.session.query(FileModel).filter_by(id=id).first()
    return ""

#------------------------------------------------------------------------------------------------

def slow_down(start, duration):
    dtime = time.time() - start
    time.sleep(max(duration - dtime,0))

#------------------------------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register', methods=["GET"])
def register_form():
    return render_template("register.html")

@app.route('/register', methods=["POST"])
def register():
    login = request.form.get("login")
    password = request.form.get("password")
    rpassword = request.form.get("rpassword")
    email = request.form.get("email")

    errors = []
    if not is_valid("login", login): errors.append('login')
    if user_exists(login): errors.append('login_taken')
    if not is_valid("password", password): errors.append('password')
    if password != rpassword: errors.append('rpassword')
    if not is_valid("email", email): errors.append('email')
    if len(errors) > 0:
        for error in errors:
            flash(error)
        session['form_data'] = request.form
        return redirect('/register')

    userdata = {
        "login": login,
        "password": password,
        "email": email
    }
    create_user(userdata)
    return redirect('/login')

@app.route('/login', methods=["GET"])
def login_form():
    return render_template("login.html")

@app.route('/login', methods=["POST"])
def login():
    stime = time.time()
    login = request.form.get("login")
    password = request.form.get("password")
    failed_attemps = count_attempts(request.remote_addr)
    if (failed_attemps > FAILED_AUTH_MAX_ATTEMPTS):
        flash('toomanyattempts')
        return redirect('/login')

    if not verify_user(login, password): 
        flash('loginorpassword')
        session['form_data'] = request.form
        register_attempt({
            "user": login,
            "time": int(stime),
            "is_success": "false",
            "ip": request.remote_addr
        })
        slow_down(stime, 2 + failed_attemps)
        return redirect('/login')

    session['user'] = login
    register_attempt({
        "user": login,
        "time": int(stime),
        "is_success": "true",
        "ip": request.remote_addr
    })
    slow_down(stime, 2 + failed_attemps)
    return redirect(url_for("dashboard"))
    
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    login = session['user']
    if 'initial_info' not in session:
        suspicious_attempts = check_suspicious_attempts(login, request.remote_addr)
        last_login = get_last_login(login)
        session['initial_info'] = "done"
    else:
        suspicious_attempts = []
        last_login = None
    notes = get_notes(session['user'])
    unotes = session.get('unlocked_notes')
    if unotes:
        for i in range(0, len(notes)):
            if notes[i].get('id') in unotes:
                notes[i] = unotes.get(notes[i].get('id'))
    return render_template("dashboard.html", attempts = suspicious_attempts, last_login = last_login, notes = notes)

@app.route('/note', methods=["POST"])
def note_create():
    text = request.form.get("text")
    password = request.form.get("password")
    fileu = request.files['file']
    is_public = "true" if request.form.get("is_public") == "on" else "false"
    owner = session['user']

    if (password != ""):
        errors = []
        if not is_valid("passwordlite", password): errors.append('password')
        if len(errors) > 0:
            for error in errors:
                flash(error)
            session['form_data'] = request.form
            return redirect('/dashboard')

    note_data = {
        "id": uuid.uuid4().hex,
        "text": text,
        "is_public": is_public,
        "owner": owner,
        "password": password,
        "creation_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file": fileu
    }
    create_note(note_data)
    return redirect('/dashboard')

#@app.route('/note', methods=["GET"])
#def notes_get():
#    user = session['user']
#    notes = get_notes(user)
#    return json.dumps(notes), 200

@app.route('/note/<id>', methods=["POST"])
def note_get(id):
    if 'user' not in session:
        return redirect('/login')
    stime = time.time()
    password = request.form.get("password")
    user = session.get('user')

    if session.get('unlocked_notes') is None:
        session['unlocked_notes'] = {}
    note = get_note(id, user, password)
    if note:
        session['unlocked_notes'][id] = note
    slow_down(stime, 2)
    return redirect(url_for("dashboard"))

@app.route('/download/<id>')
def download_file(id):
    user = session.get("user")
    if user:
        file = get_file(id, user)
        if file:
            return send_file(
                io.BytesIO(file.value),
                as_attachment = True,
                attachment_filename=file.file_name
            )
    return "Unatuhorized", 403

@app.route('/passreset/<token>', methods=["GET"])
def pass_reset_get(token):
    return render_template("pass-reset.html", token=token)

@app.route('/passreset', methods=["POST"])
def pass_reset_post():
    login = request.form.get("login")
    password = request.form.get("password")
    rpassword = request.form.get("rpassword")
    token = request.form.get("token")

    errors = []
    try:
        tokend = jwt.decode(token, JWT_SECRET, algorithms=['HS256'], audience='notatkaplus')
        if tokend.get("sub") != login:
            errors.append('invalid')
    except Exception as e:
        errors.append('invalid')
    if not is_valid("password", password): errors.append('password')
    if password != rpassword: errors.append('rpassword')
    if len(errors) > 0:
        for error in errors:
            flash(error)
        return redirect('/passreset/' + token)

    update_password(login, password)
    return redirect('/login')

@app.route('/passrecovery', methods=["GET"])
def pass_recovery_get():
    return render_template("pass-recovery.html", info=None, msg=None)

@app.route('/passrecovery', methods=["POST"])
def pass_recovery_post():
    login = request.form.get("login")
    msg = generate_recovery_email(login)
    return render_template("pass-recovery.html", info=True, msg=msg)

#------------------------------------------------------------------------------------------------

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000)