import requests
import json
import formats
import crypto

class ACMEClient(object):
    """docstring fo Client."""

    def __init__(self, url):
        self.UrlDict = {}
        self.UrlDict["dir"] = url
        self.url = 'https://0.0.0.0:14000/'
        self.nonce = ""

        sk, pk = crypto.ecdsa_key_gen()
        self.ecdsa_sk = sk
        self.ecdsa_pk = pk
        self.jws = formats.JSONWebSignature(self.ecdsa_pk, self.ecdsa_sk)

    def get_rootCert(self):
        resp =  requests.get('https://0.0.0.0:15000/roots/0', verify=False)
        cafile = resp.text
        with open ("private.pem", "w") as prv_file:
            print("{}".format(cafile), file=prv_file)

    def init_directory(self):
        resp = requests.get(self.UrlDict["dir"], verify=False)
        dir = json.loads(resp.text)
        self.UrlDict["newAccount"] = dir["newAccount"]
        self.UrlDict["newNonce"] = dir["newNonce"]
        self.UrlDict["newOrder"] = dir["newOrder"]
        self.UrlDict["revokeCert"] = dir["revokeCert"]


    def get_newNonce(self):
        resp = requests.get(self.UrlDict["newNonce"], verify=False)
        self.nonce = resp.headers['Replay-nonce']
        if resp.status_code not in [requests.codes.no_content,requests.codes.ok]:
            print("get_newNonce: ", resp.status_code)

    def get_newAccount(self):
        data, kid = self.jws.get_newAccountData(self.UrlDict["newAccount"], self.nonce)
        self.kid = kid
        headers = {'content-type': 'application/jose+json'}

        resp = requests.post(self.UrlDict["newAccount"], data=data, headers=headers, verify=False)
        if resp.status_code not in [requests.codes.created]:
            print("get_newAccount: ", resp.status_code)

        self.kid = resp.headers['Location']
        self.nonce = resp.headers['Replay-nonce']

    def get_newOrder(self):
        data = self.jws.get_newOrderData(self.UrlDict["newOrder"], self.nonce, self.kid)
        headers = {'content-type': 'application/jose+json'}

        resp = requests.post(self.UrlDict["newOrder"], data=data, headers=headers, verify=False)
        if resp.status_code not in [requests.codes.created]:
            print("get_newOrder: ", resp.status_code)
        self.nonce = resp.headers['Replay-nonce']
        self.orderID = resp.headers['Location']

        resp_json = json.loads(resp.text)
        expires = resp_json["expires"]
        self.finalize_url = resp_json["finalize"]
        authorizations = resp_json["authorizations"]
        print(expires)

    def get_finalizeOrder(self):
        data = self.jws.get_finalizeOrderData(self.UrlDict["newOrder"], self.nonce, self.kid)
        headers = {'content-type': 'application/jose+json'}

        resp = requests.post(self.UrlDict["newOrder"], data=data, headers=headers, verify=False)
