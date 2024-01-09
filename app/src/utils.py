from io import BytesIO
from flask import render_template, session
import pyotp, qrcode, base64, bleach
from cryptography.fernet import Fernet
from src import app

allowed_tags = ['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'a', 'strong', 'em', 'b', 'i', 'img']
allowed_attributes = {'a': ['href', 'title'], 'img':['src', 'alt']}

encryption_password = app.config['TOTP_ENCRYPTION_PASSWORD']

def make_qr_image(key, username):
    uri = pyotp.totp.TOTP(key).provisioning_uri(name=username, issuer_name="Bezpieczne notatki")
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered)
    buffered.seek(0)
    return base64.b64encode(buffered.read()).decode('utf-8')

def login_attempts_limit(func):
    def wrapper(*args, **kwargs):
        if 'login_attempts' not in session:
            session['login_attempts'] = 0

        if session['login_attempts'] >= 5:
            return render_template('account_locked.html')

        return func(*args, **kwargs)

    return wrapper

def sanitize_note(note):
    return bleach.clean(note, tags=allowed_tags, attributes=allowed_attributes)

def encrypt_otp_secret(otp_secret):
    cipher = Fernet(encryption_password)
    return cipher.encrypt(otp_secret.encode())

def decrypt_otp_secret(otp_secret):
    cipher = Fernet(encryption_password)
    return cipher.decrypt(otp_secret)

def get_totp_from_encrypted_secret(otp_secret):
    decrypted_secret = decrypt_otp_secret(otp_secret)
    return pyotp.TOTP(decrypted_secret)