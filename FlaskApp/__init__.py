from flask import Flask, render_template
import bcrypt, os
from datetime import timedelta, datetime
from flask.ext.login import LoginManager, login_user, logout_user, current_user, login_required
from flask import Flask, session, send_file, request, redirect, url_for, render_template
from itsdangerous import URLSafeTimedSerializer
from pymongo import Connection
import pyotp, qrcode
import hashlib
from io import BytesIO

# Init stuff
app = Flask(__name__)
ttl=30*60
app.secret_key = os.environ["APP_SECRET"]
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(seconds=ttl)
mongo_url = os.environ["MONGO_URL"]
connection = Connection(mongo_url)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    db = connection.auth.users
    found_user = db.find_one({'uid': user_id})
    if found_user == None:
        return None
    return User(user_id)

# User class
class User:
    def __init__(self, user_id):
        self.id = user_id.lower()
        self.db = connection.auth.users
        self.account = self.db.find_one({'uid': self.id})

    # Creates a User
    def create(self):
        self.db.insert({'uid': self.id})
        self.account = self.db.find_one({'uid': self.id})

    # Saves user account details
    def save(self):
        self.db.save(self.account)

    # Checks whether the password hash is valid. Uses bcrypt to validate
    def password_valid(self, pwd):
        pwd_hash = self.account['password_hash']
        return bcrypt.hashpw(pwd, pwd_hash) == pwd_hash

    # Stubbed out as this is not used. This is to satisfy the base class
    def is_authenticated(self):
        return True

    # Stubbed out as this is not used. This is to satisfy the base class
    def is_active(self):
        return True

    # Stubbed out as this is not used. This is to satisfy the base class
    def is_anonymous(self):
        return False

    # Returns the current userid(username)
    def get_id(self):
        return self.id

    # Update expiry. We timeout only on non-active users for better UX
    def update_expiry(self):
        self.account['expires_at'] = datetime.utcnow() + timedelta(seconds=ttl)
        self.save()

@app.route('/', methods=['GET', 'POST'])
def homepage():
    opts = {}
    # On GET Render the main.html
    if request.method == 'GET':
        opts = {}
        opts['current_context'] = "login"
        return render_template("main.html", opts=opts)
    user = User(request.form['username'])

    # On POST, validate that the user exists and the password is correct.
    if not user.account or not user.password_valid(request.form['password']):
        opts['invalid_username_or_password'] = True
        opts['current_context'] = "login"
        return render_template('main.html', opts=opts), 401

    # Check if the user had enabled MFA during sign up
    if user.account['mfa_enabled']:
       # Send off to accept and validate MFA token.
       session['uid'] = user.get_id()
       return render_template('verify-mfa.html', opts=opts)
    else:
       # No MFA. Continue with loggin in.
       login_user(user, remember=True)
       user.update_expiry()
       return redirect(url_for('user')), 200

# Validates the MFA Token passed in via the form
@app.route('/validate-mfa-token', methods=['POST'])
def validate_mfa_token():
    opts = {}
    token = request.form['otp-token']
    db = connection.auth.users
    if 'uid' not in session:
        opts['session_expired'] = True
        opts['current_context'] = "login"
        return render_template('main.html', opts=opts), 401
    found_user = db.find_one({'uid': session['uid']})
    u = User(found_user['uid'])

    if found_user is None:
        opts['invalid_user'] = True
        return render_template('verify-mfa.html', opts=opts), 401

    # Get the user's TOTP Secret to validate the token
    totp = pyotp.TOTP(found_user['otp_base'])
    try:
        token = int(token)
        if totp.verify(token):
            u.update_expiry()
            login_user(u, remember=True)
            return redirect(url_for('user'))
        else:
            raise ValueError
    except ValueError as e:
        # Token Invalid. Communicate the error back to the user.
        opts['invalid_totp_token'] = True
        return render_template('verify-mfa.html', opts=opts)

# Enables MFA during sign-up
@app.route("/enable-mfa", methods=['GET', 'POST'])
def enable_mfa():
    if 'uid' not in session:
        return redirect(url_for('homepage'))
    # Since we will generate and render a QR code specific to the current user.
    # Tell browser to not cache this.
    return render_template('enable-mfa.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

# Generates QR Code based on the standard TOTP URI Format otpauth://totp/LABEL?PARAMETERS
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

    # Generate a secret
    base = pyotp.random_base32()
    otp_uri = 'otpauth://totp/supriya%27s%20tech%20blog:{0}?secret={1}&issuer=supriya.tech' \
            .format(session['uid'], base)
    # Save the base in the DB.
    cur_user = User(found_user['uid'])
    # Save the user's 2FA Secret. We use this to validate 2FA token during login.
    cur_user.account['otp_base'] =  base
    cur_user.save()

    # We need to render the qr-code in the browser window. Stream the image.
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

# Handles user registration
@app.route("/sign-up", methods=['GET', 'POST'])
def sign_up():
    opts = {}
    if request.method == 'GET':
        opts = {}
        opts['current_context'] = "register"
        return render_template('main.html', opts=opts)
    # Form Validation
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
    # Generate an access token. This is used by different REST Services outside flask to validate the session
    user.account['token'] = generate_token()
    user.account['expires_at'] = datetime.utcnow() + timedelta(seconds=ttl)

    # Handle MFA
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

# Protected URL. Allows user to make REST calls outside flask context.
# Currently supporting python and go servers on TLS
@app.route("/user", methods=['GET', 'POST'])
@login_required
def user():
    opts = {'user': current_user,
            'logged_in': True}
    return render_template('user.html', opts=opts)

# Currently unsed.
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main_page'))

# Ensure the session liveness is tracked.
@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(seconds=ttl)
    session.modified = True

# Generate an access token to store in the database for the user.
def generate_token():
    return hashlib.sha1(bcrypt.gensalt()).hexdigest()

if __name__ == "__main__":
    app.run(debug=True)
