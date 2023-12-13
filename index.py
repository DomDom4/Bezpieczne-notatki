from flask import Flask, render_template, request, redirect, url_for
from flask_login import UserMixin, LoginManager, current_user, login_user, login_required, logout_user
from passlib.hash import sha256_crypt
import sqlite3
import secrets
import markdown
import bleach

allowed_tags = ['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'a', 'strong', 'em', 'b', 'i', 'img']
allowed_attributes = {'a': ['href', 'title'], 'img':['src', 'alt']}

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = "login"

DATABASE = 'users.db'

class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
   conn = sqlite3.connect(DATABASE)
   curs = conn.cursor()
   curs.execute("SELECT * FROM users WHERE username = ?", (username, ))
   lu = curs.fetchone()
   if lu is None:
      return None
   else:
      user = User()
      user.id = lu[1]
      user.password = lu[2]
      return user
   

@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = user_loader(username)

        if user and sha256_crypt.verify(password, user.password):
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            error = 'Invalid credentials. Please try again.'
            return render_template('login.html', error=error)

    return render_template('login.html', error=None)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = sha256_crypt.hash(password)

        user = user_loader(username)

        if user:
            return render_template('register.html', error = 'Username taken')
        
        with sqlite3.connect(DATABASE) as connection:
            cursor = connection.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            connection.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/home')
@login_required
def home():
    username = current_user.id

    with sqlite3.connect(DATABASE) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT id,is_shared,title FROM notes WHERE username == ?", (username, ))
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
        clean_rendered = bleach.clean(rendered, tags=allowed_tags, attributes=allowed_attributes)
        username = current_user.id
        is_shared = 1 if request.form['option'] == 'shared' else 0
        with sqlite3.connect(DATABASE) as connection:
            cursor = connection.cursor()
            cursor.execute("INSERT INTO notes (title, username, content, is_shared) VALUES (?,?,?,?)", (title, username, clean_rendered, is_shared))
            connection.commit()

        if is_shared == 1:
            return render_template("note.html", rendered=clean_rendered, is_shared=1, title=title)
        return render_template("note.html", rendered=clean_rendered, title=title)

    return render_template('create_note.html')

@app.route("/note/<int:note_id>")
@login_required
def note(note_id):
    with sqlite3.connect(DATABASE) as connection:
        cursor = connection.execute("SELECT title, username, content, is_shared FROM notes WHERE id == ? ", (note_id, ))
        try:
            title, username, content, is_shared = cursor.fetchone()
            if is_shared == 1:
                return render_template("note.html", rendered=content, is_shared=1, title=title)
            if username != current_user.id:
                return "Access to note forbidden", 403
            return render_template("note.html", rendered=content, title=title)
        except:
            return "Note not found", 404


if __name__ == '__main__':
    app.run(debug=True)
