from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import json, os
from pymongo import Connection
from datetime import datetime
connection = Connection("localhost:27017")
import ssl

class S(BaseHTTPRequestHandler):
    # Allow requests originating only from the flask app
    def _set_headers(self):
        self.send_header('Content-type', 'text/html')
        self.send_header('Access-Control-Allow-Origin', 'https://supriya.tech')
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        self.wfile.write("<html><body><h1>I'm Alive!</h1></body></html>")

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        post_data = json.loads(post_data)
        print(post_data)
        greeting = self.get_greeting(post_data["token"])

    def get_greeting(self, token):
        db = connection.auth.users
        found_user = db.find_one({'token': token})
        if found_user == None:
            self.send_response(404)
            self._set_headers()
            self.wfile.write("Error! User not found. Please register")
        # Session validation
        if found_user['expires_at'] < datetime.utcnow():
            self.send_response(401)
            self._set_headers()
            self.wfile.write("Error! Unauthorized. Please login.")
        self.send_response(200)
        self._set_headers()
        resp = {}
        resp["Message"] = "Hello " + found_user["uid"] + "! Python is pleased to meet you!"
        self.wfile.write(json.dumps(resp))


def run(server_class=HTTPServer, handler_class=S, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.socket = ssl.wrap_socket(httpd.socket, certfile='/etc/letsencrypt/live/supriya.tech/fullchain.pem', keyfile='/etc/letsencrypt/live/supriya.tech/privkey.pem', server_side=True, ssl_version=ssl.PROTOCOL_TLSv1_2)
    print 'Starting httpd...'
    httpd.serve_forever()

if __name__ == "__main__":
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
