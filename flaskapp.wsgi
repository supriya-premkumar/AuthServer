#!/usr/bin/python
import sys
import os
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/FlaskApp/")
os.environ["APP_SECRET"]='correct horse battery staple'
os.environ["MONGO_URL"]="localhost:27017"

from FlaskApp import app as application
application.secret_key = 'correct horse battery staple'
