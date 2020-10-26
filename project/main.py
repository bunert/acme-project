import client
import argparse
import certificateHttpServer
import shutdownHttpServer
import dnsServer
import time
import subprocess
from cryptography.hazmat.primitives import serialization


# TODO: remove (requests warning surpression)
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

parser = argparse.ArgumentParser(description='ACME Client')
parser.add_argument('challenge', help='Challenge Type')
parser.add_argument('--dir', dest='dir', default='https://1.1.1.1:14000/dir',help='DIR_URL is the directory URL of the ACME server that should be used.')
parser.add_argument('--record', dest='record', default='1.2.3.4',help='IPv4_ADDRESS is the IPv4 address which must be returned by your DNS server for all A-record queries')
parser.add_argument('--domain', dest='domain',action='append' ,help='DOMAIN  is the domain for  which to request the certificate.')
parser.add_argument('--revoke', dest='revoke',action='store_true', help='revoke certificates after they have been issued by the ACME server.')

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
resolver = dnsServer.setup_resolver(args.record, args.domain)
udp_server = dnsServer.run_server(resolver, args.record)


# start shutdownHttpServer
shutdownServer = shutdownHttpServer.start_server(args.record)

# start challengeHttpServer
# challengeServer = challengeHttpServer.start_server()
challengeServer = subprocess.Popen(['python3', 'challengeHttpServer.py', args.record])

time.sleep(1)


test_client = client.ACMEClient(args.dir, args.domain)
# test_client.get_rootCert()
test_client.init_directory()
test_client.get_newNonce()

test_client.post_newAccount()

test_client.post_newOrder()

# index indicated for which domain in array ['www.example.com', 'example.com']
# index=0
for i in range(len(args.domain)):
    test_client.post_newAuthz(i)

# test_client.post_newAuthz(index)

for i in range(len(args.domain)):
    if (challenge=='http-01'):
        # challenge_http_url ='http://localhost:5002/'
        test_client.post_newHttpChallenge(i, args.record, challenge)
    else:
        # dns challenge
        c = test_client.get_challenge(i, challenge)
        # print(test_client.identifiers[i].value)
        resolver.txt[test_client.identifiers[i].value] = c.dnsAuthorization
        # print("added dns entry: ", args.domain[i])
        # print(c.dnsAuthorization)
        # print(resolver.txt)

for i in range(len(args.domain)):
    test_client.post_ChallengeReady(i, challenge)

# time.sleep(5)
# test_client.post_checkStatus(index)
#
# time.sleep(5)
# test_client.post_checkStatus(index)
#
# time.sleep(5)
limit = 0
while (test_client.post_checkOrder() != 'ready' and limit < 10):
    limit += 1
    time.sleep(2)


test_client.post_finalizeOrder()

status = test_client.post_checkOrder()

if (status == 'valid'):
    cert = test_client.post_DownloadCert()
    with open("certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    # start certificateHttpServer
    certServer = certificateHttpServer.start_server(args.record)

if (args.revoke and status == 'valid'):
    print("revoke cert")
    test_client.post_revokeCert(cert)

print("finished")

try:
    while shutdownServer.is_alive():
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    challengeServer.terminate()
