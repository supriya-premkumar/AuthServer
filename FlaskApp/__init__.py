from flask import Flask, render_template
import bcrypt, os
from twilio.rest import TwilioRestClient
from datetime import timedelta, datetime
from flask.ext.login import LoginManager, login_user, logout_user, current_user, login_required
from flask import Flask, session, send_file, request, redirect, url_for, render_template
from itsdangerous import URLSafeTimedSerializer
from pymongo import Connection
import pyotp, qrcode
import hashlib
from io import BytesIO


app = Flask(__name__)
app.secret_key = os.environ["APP_SECRET"]
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(seconds=10)
mongo_url = os.environ["MONGO_URL"]
connection = Connection(mongo_url)

login_manager = LoginManager()
login_manager.init_app(app)
ttl=1000

@login_manager.user_loader
def load_user(user_id):
    db = connection.auth.users
    found_user = db.find_one({'uid': user_id})
    if found_user == None:
        return None
    return User(user_id)


class User:
    def __init__(self, user_id):
        self.id = user_id.lower()
        self.db = connection.auth.users
        self.account = self.db.find_one({'uid': self.id})

    def create(self):
        self.db.insert({'uid': self.id})
        self.account = self.db.find_one({'uid': self.id})

    def save(self):
        self.db.save(self.account)

    def password_valid(self, pwd):
        pwd_hash = self.account['password_hash']
        return bcrypt.hashpw(pwd, pwd_hash) == pwd_hash

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def update_expiry(self):
        self.account['expires_at'] = datetime.utcnow() + timedelta(seconds=ttl)
        self.save()

@app.route('/', methods=['GET', 'POST'])
def homepage():
    opts = {}
    if request.method == 'GET':
        opts = {}
        opts['current_context'] = "login"
        return render_template("main.html", opts=opts)
    user = User(request.form['username'])
    if not user.account or not user.password_valid(request.form['password']):
        opts['invalid_username_or_password'] = True
        opts['current_context'] = "login"
        return render_template('main.html', opts=opts), 401
    if user.account['mfa_enabled']:
       session['uid'] = user.get_id()
       return render_template('verify-mfa.html', opts=opts)
    else:
       login_user(user, remember=True)
       user.update_expiry()
       return redirect(url_for('user')), 200

@app.route('/validate-mfa-token', methods=['POST'])
def validate_mfa_token():
    opts = {}
    token = request.form['otp-token']
    db = connection.auth.users
    found_user = db.find_one({'uid': session['uid']})
    u = User(found_user['uid'])

    if found_user is None:
        opts['invalid_user'] = True
        return render_template('verify-mfa.html', opts=opts), 401
    totp = pyotp.TOTP(found_user['otp_base'])
    try:
        token = int(token)
        if totp.verify(token):
            login_user(u, remember=True)
            return redirect(url_for('user'))
        else:
            raise ValueError
    except ValueError as e:
        opts['invalid_totp_token'] = True
        return render_template('verify-mfa.html', opts=opts)

@app.route("/enable-mfa", methods=['GET', 'POST'])
def enable_mfa():
    if 'uid' not in session:
        return redirect(url_for('homepage'))
    return render_template('enable-mfa.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route('/qrcode')
def qr_gen():
    opts = {}
    if 'uid' not in session:
        opts['invalid_session'] = True
        return redirect(url_for('homepage'))

    db = connection.auth.users
    found_user = db.find_one({'uid': session['uid']})

    if found_user is None:
        opts['invalid_user'] = True
        return redirect(url_for('homepage'))

    base = pyotp.random_base32()
    otp_uri = 'otpauth://totp/supriya%27s%20tech%20blog:{0}?secret={1}&issuer=supriya.tech' \
            .format(session['uid'], base)
    # Save the base in the DB.
    current_user = User(found_user['uid'])
    current_user.account['otp_base'] =  base
    current_user.save()

    stream = BytesIO()
    qr = qrcode.make(otp_uri)
    qr.save(stream, 'JPEG', quality=70)
    stream.seek(0)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/jpeg',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}
    return render_template('enable-mfa.html', filename='img_io')

@app.route("/sign-up", methods=['GET', 'POST'])
def sign_up():
    opts = {}
    if request.method == 'GET':
        opts = {}
        opts['current_context'] = "register"
        return render_template('main.html', opts=opts)
    if len(request.form['username']) < 4:
        opts['username_too_short'] = True
        opts['current_context'] = "register"
        return render_template('main.html', opts=opts), 400
    if len(request.form['password']) < 8:
        opts['password_too_short'] = True
        opts['current_context'] = "register"
        return render_template('main.html', opts=opts), 400
    if request.form['password'] != request.form['confirm-password']:
        opts['passwords_dont_match'] = True
        opts['current_context'] = "register"
        return render_template('main.html', opts=opts), 400
    if len(request.form['email']) == "" or "@" not in request.form['email']:
        opts['email invalid'] = True
        opts['current_context'] = "register"
        return render_template('main.html', opts=opts), 400

    user = User(request.form['username'])
    if user.account:
        opts['username_exists'] = True
        opts['current_context'] = "register"
        return render_template('main.html', opts=opts)
    user.create()
    pwd_hash = bcrypt.hashpw(request.form['password'], bcrypt.gensalt())
    user.account['password_hash'] = pwd_hash
    user.account['token'] = generate_token()
    user.account['expires_at'] = datetime.utcnow() + timedelta(seconds=ttl)
    if 'enable-mfa' in request.form:
        if request.form['enable-mfa'] == "on":
            user.account['mfa_enabled'] = True
            session['uid'] = user.account['uid']
            user.save()
            return redirect(url_for('enable_mfa'))
    user.account['mfa_enabled'] = False
    user.save()
    login_user(user, remember=True)
    user.update_expiry()
    return redirect(url_for('user'))

@app.route("/user", methods=['GET', 'POST'])
@login_required
def user():
    opts = {'user': current_user,
            'logged_in': True}
    return render_template('user.html', opts=opts)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main_page'))

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(seconds=ttl)
    session.modified = True

def generate_token():
    return hashlib.sha1(bcrypt.gensalt()).hexdigest()

if __name__ == "__main__":
    app.run(debug=True)
