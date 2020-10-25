from flask import Flask, json
from flask import request
import logging
import os
import threading
import argparse

parser = argparse.ArgumentParser(description='ACME challengeHttpServer')
parser.add_argument('record', help='Challenge Type')

args = parser.parse_args()


api = Flask("challengeHttpServer")
api.logger.disabled = True
log = logging.getLogger('werkzeug')
log.disabled = True

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



if __name__ == '__main__':
    # server = threading.Thread(target=lambda: api.run(port=5002, threaded=True))
    # server.daemon = True
    # server.start()
    port = 5002
    print("challenge server on port: ", port)
    api.run(host=args.record, port=port)
