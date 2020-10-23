import client
import argparse
import challengeHttpServer
import dnsServer
import json
import socket
import time
import crypto


# TODO: remove (requests warning surpression)
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

parser = argparse.ArgumentParser(description='ACME Client')
parser.add_argument('challenge', help='Challenge Type')
parser.add_argument('--dir', dest='dir', default='https://1.1.1.1:14000/dir',help='DIR_URL is the directory URL of the ACME server that should be used.')
parser.add_argument('--record', dest='record', default='1.2.3.4',help='IPv4_ADDRESS is the IPv4 address which must be returned by your DNS server for all A-record queries')
parser.add_argument('--domain', dest='domain',action='append' ,help='DOMAIN  is the domain for  which to request the certificate.')


args = parser.parse_args()

# TODO: remove (warnings surpression)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

if (args.challenge == 'http01'):
    challenge = 'http-01'
elif(args.challenge == 'dns01'):
    challenge = 'dns-01'
else:
    print("wrong challenge")

# start dnsServer using the args.record as ip address
resolver = dnsServer.setup_resolver('1.2.3.4')
udp_server = dnsServer.run_server(resolver)

# start httpServer using args.domain

test_client = client.ACMEClient(args.dir, args.domain)
# test_client.get_rootCert()
test_client.init_directory()
test_client.get_newNonce()

test_client.post_newAccount()

test_client.post_newOrder()

# index indicated for which domain in array ['www.example.com', 'example.com']
index=0
test_client.post_newAuthz(index)

if (challenge=='http-01'):
    challenge_http_url = 'http://localhost:5002/'
    test_client.post_newHttpChallenge(index, challenge_http_url, challenge)
else:
    # dns challenge
    c = test_client.get_challenge(index, challenge)
    resolver.txt = c.dnsAuthorization

test_client.post_ChallengeReady(index, challenge)

time.sleep(3)
# should be valid now
test_client.post_checkStatus(index)

time.sleep(2)
test_client.post_checkOrder()

test_client.post_finalizeOrder()

ret = test_client.post_checkOrder()

if (ret):
    cert = test_client.post_DownloadCert()

test_client.post_revokeCert(cert)

try:
    while udp_server.isAlive():
        time.sleep(1)
except KeyboardInterrupt:
    pass
