from flask import Flask, json
from flask import request
import logging
import os
import threading



api = Flask(__name__)
api.debug = False

keyAuthorization = {}

@api.route('/.well-known/acme-challenge/<token>', methods=['GET'])
def get_acme_challenge(token):
    return keyAuthorization[token]

@api.route('/.well-known/acme-challenge/<token>', methods=['POST'])
def post_acme_challenge(token):
    if not request.json or not 'keyAuthorization' in request.json:
        abort(400)
    keyAuthorization[token] = request.json['keyAuthorization']
    return json.dumps({"success": True}), 201

# def run_server():
#     api.run(port=5002)

if __name__ == '__main__':
    # server = threading.Thread(target=lambda: api.run(port=5002, threaded=True))
    # server.daemon = True
    # server.start()
    api.run(port=5002)
