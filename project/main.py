import client
import argparse

# TODO: remove (requests warning surpression)
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

parser = argparse.ArgumentParser(description='ACME Client')
parser.add_argument('challenge', help='Challenge Type')
parser.add_argument('--dir', dest='dir', default='https://1.1.1.1:14000/dir',help='DIR_URL is the directory URL of the ACME server that should be used.')
parser.add_argument('--record', dest='record', default='1.2.3.4',help='IPv4_ADDRESS is the IPv4 address which must be returned by your DNS server for all A-record queries')
parser.add_argument('--domain', dest='domain',help='DOMAIN  is the domain for  which to request the certificate.')


args = parser.parse_args()

# TODO: remove (warnings surpression)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

values = ["www.example.org", "example.org"]
test_client = client.ACMEClient(args.dir, values)
# test_client.get_rootCert()
test_client.init_directory()
test_client.get_newNonce()

test_client.post_newAccount()

test_client.post_newOrder()

test_client.post_newAuthz()
