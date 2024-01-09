from src import app
from src.utils import sanitize_note
from io import BytesIO
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import UserMixin, LoginManager, current_user, login_user, login_required, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
import qrcode, pyotp, base64, bcrypt, bleach, markdown, sqlite3

limiter = Limiter(
    get_remote_address,
    storage_uri="redis://redis:6379",
    app = app,
    default_limits=['50 per hour']
)

@app.route('/home')
@limiter.limit('2/second', override_defaults = False)
@login_required
def home():
    username = current_user.id

    with sqlite3.connect(app.config['DB_NAME']) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT id,is_shared,title,salt FROM notes WHERE username == ?", (username, ))
        notes = cursor.fetchall()
        cursor.execute("SELECT id,username,title FROM notes WHERE is_shared == 1")
        shared_notes = cursor.fetchall()

    return render_template('home.html', name=current_user.id, notes= notes, shared_notes = shared_notes) 


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")

@app.route('/create_note', methods=['GET', 'POST'])
@login_required
def create_note():
    if request.method == 'POST':
        title = request.form['title']
        note = request.form.get("content","")

        rendered = markdown.markdown(note)
        clean_rendered = sanitize_note(rendered)

        username = current_user.id

        is_shared = 1 if request.form['option'] == 'shared' else 0
        is_encrypted = 1 if request.form['option'] == 'encrypted' else 0

        password = ''
        hashed_key = ''
        salt = ''
        if is_encrypted == 1:
            key = Fernet.generate_key()
            password = request.form['encryption_passsword'].encode('utf-8')

            cipher = Fernet(key)
            clean_rendered = cipher.encrypt(note.encode())

            salt = bcrypt.gensalt()  
            kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    iterations = 39000,
                    salt = salt,
                    length = 32
                    )
            hashed_passw = base64.urlsafe_b64encode(kdf.derive(password))

            cipher = Fernet(hashed_passw)
            hashed_key = cipher.encrypt(key)

            password = bcrypt.hashpw(hashed_passw, bcrypt.gensalt())
                      

        with sqlite3.connect(app.config['DB_NAME']) as connection:
            cursor = connection.cursor()
            cursor.execute("INSERT INTO notes (title, username, content, is_shared, encrypted_password, encrypted_key, salt) VALUES (?,?,?,?,?,?,?)", 
                                            (title, username, clean_rendered, is_shared, password, hashed_key, salt))
            connection.commit()

        if is_shared == 1:
            return render_template("note.html", rendered=clean_rendered, is_shared=1, title=title)
        return render_template("note.html", rendered=clean_rendered, title=title)

    return render_template('create_note.html')

@app.route("/note/<int:note_id>", methods=['GET', 'POST'])
@login_required
def note(note_id):
    with sqlite3.connect(app.config['DB_NAME']) as connection:
        cursor = connection.execute("SELECT title, username, content, is_shared, encrypted_password, encrypted_key, salt FROM notes WHERE id == ? ", (note_id, ))
        try:
            title, username, content, is_shared, hashed_password, hashed_key, salt = cursor.fetchone()
            if is_shared == 1:
                return render_template("note.html", rendered=content, is_shared=1, title=title)
            if username != current_user.id:
                return "Access to note forbidden", 403
            if salt != '':
                if request.method == 'POST':
                    password = request.form['encryption_passsword'].encode('utf-8')
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        iterations = 39000,
                        salt = salt,
                        length = 32
                    )
                    hashed_passw = base64.urlsafe_b64encode(kdf.derive(password))
                    if bcrypt.checkpw(hashed_passw, hashed_password):
                        cipher = Fernet(hashed_passw)
                        key = cipher.decrypt(hashed_key)
                        cipher = Fernet(key)
                        plaintext_content = cipher.decrypt(content)
                        return render_template("note.html", rendered=plaintext_content.decode('utf-8'), title=title)
                    else:
                        error = 'Wrong password'
                        return render_template("note.html", rendered=content, is_encrypted=1, title=title, error = error, note_id=note_id)
                return render_template("note.html", rendered=content, is_encrypted=1, title=title, note_id = note_id)
            return render_template("note.html", rendered=content, title=title)
        except Exception as e:
            print(e)
            return "Note not found", 404