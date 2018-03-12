#!/usr/bin/python
import sys
import os
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/FlaskApp/")
os.environ["APP_SECRET"]='your secret key. If you share your website, do NOT share it with this key.'
os.environ["MONGO_URL"]="localhost:27017"

from FlaskApp import app as application
application.secret_key = 'your secret key. If you share your website, do NOT share it with this key.'
