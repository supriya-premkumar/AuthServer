### Auth Server
#### Design
1. The backend is written in python using Flask. Data is stored in MongoDB, Front-end
is written in html, css and js. The two backend servers are written in python and go
2. Using apache 2 to serve the website.
3. Using Let's Encrypt as CA.
4. Running on an Ubuntu 16.04 instance on google cloud.
5. Apache server hardened with fail2ban and rthunter.
6. `__init__.py` is the main function. srv.py and srv.go are separate TLS based REST endpoints.
7. All the tests can be found under tests/

#### Demo URL
https://supriya.tech

#### Demo Screencast
Has a 30 second wait to trigger a timeout. Easier for the demo :-)
<img src='https://media.giphy.com/media/NUw6vyzSmNGzy3hCzE/giphy.gif' title='Video Walkthrough' width='' alt='Video Walkthrough' />

#### Dependencies:
1. You will need an OTP app like [Google Authenticator](https://itunes.apple.com/us/app/google-authenticator/id388497605?mt=8) or [Authy](https://itunes.apple.com/us/app/authy/id494168017?mt=8) to use MFA.

#### Features
1. Secure user login and registration. All traffic served over TLS.
2. Support for Multi-Factor Auth.
3. Encrypted user passwords using bcrypt.

#### Test Results
Local tests are run without TLS Verify mode.
```
(venv) supriyap@auth-server:/var/www/FlaskApp/FlaskApp/tests$ python main_test.py
/usr/lib/python2.7/dist-packages/urllib3/connectionpool.py:794: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.org/en/latest/security.html
  InsecureRequestWarning)
...............
----------------------------------------------------------------------
Ran 15 tests in 12.778s

OK
```




#### How to run locally
```
1. Create a virual env
2. Run `pip install -r requirements.txt`
3. Install MongoDB and start mongoDB service.
4. export MONGO_URL=localhost:27017
5. export APP_SECRET="correct horse battery staple"
6. python __init__.py
7. Server will be running at localhost:5000
```
