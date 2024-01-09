from src import app
from src.utils import login_attempts_limit, make_qr_image, get_totp_from_encrypted_secret, encrypt_otp_secret
from flask import render_template, request, redirect, url_for, session
from flask_login import UserMixin, LoginManager, current_user, login_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
import pyotp, bcrypt, sqlite3

encryption_password = app.config['TOTP_ENCRYPTION_PASSWORD']
limiter = Limiter(
    get_remote_address,
    storage_uri="redis://redis:6379",
    app = app,
    default_limits=['50 per hour']
)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
   conn = sqlite3.connect(app.config['DB_NAME'])
   curs = conn.cursor()
   curs.execute("SELECT * FROM users WHERE username = ?", (username, ))
   lu = curs.fetchone()
   conn.close()
   if lu is None:
      return None
   else:
      user = User()
      user.id = lu[1]
      user.password = lu[2]
      user.otp_secret = lu[3]
      return user

@app.route('/', methods=['GET', 'POST'])
@limiter.limit('2/second', override_defaults = False)
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        user = user_loader(username)

        if user and bcrypt.checkpw(password, user.password):
            session['user'] = username
            return render_template('fa2.html', login=1)
        else:
            error = 'Invalid credentials. Please try again.'
            return render_template('login.html', error=error)

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        otp_secret = pyotp.random_base32()

        encrypted_otp_secret = encrypt_otp_secret(otp_secret)
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        user = user_loader(username)

        if user:
            return render_template('register.html', error = 'Username taken')
        
        with sqlite3.connect(app.config['DB_NAME']) as connection:
            cursor = connection.cursor()
            cursor.execute('INSERT INTO users (username, password, otp_secret) VALUES (?, ?, ?)', (username, hashed_password, encrypted_otp_secret))
            connection.commit()

        qr_image = make_qr_image(otp_secret, username)
        
        return render_template('fa2.html', register=qr_image)
    
    return render_template('register.html')

@app.route('/fa2', methods=['GET','POST'])
@limiter.limit('2/second', override_defaults = False)
def fa2():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        user = user_loader(session.get('user'))
        otp_code = request.form['otp_code']
        totp = get_totp_from_encrypted_secret(user.otp_secret)
        if totp.verify(otp_code):
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            return render_template('fa2.html', error="Wrong code", login=1)
    return render_template('fa2.html')