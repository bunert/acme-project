import requests
import json
import formats
import crypto


class ACMEClient(object):
    """docstring fo Client."""

    def __init__(self, url, values):
        self.UrlDict = {}
        self.UrlDict["dir"] = url
        self.url = 'https://0.0.0.0:14000/'
        self.nonce = ""

        sk, pk = crypto.ecdsa_key_gen()
        self.ecdsa_sk = sk
        self.ecdsa_pk = pk
        self.jws = formats.JSONWebSignature(self.ecdsa_pk, self.ecdsa_sk)
        self.identifiers = [formats.Identifier(value) for value in values]

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
        if resp.status_code not in [requests.codes.no_content,requests.codes.ok]:
            print("get_newNonce: ", resp.status_code)
        else:
            self.nonce = resp.headers['Replay-nonce']

    def post_newAccount(self):
        data, kid = self.jws.get_newAccountData(self.UrlDict["newAccount"], self.nonce)
        self.kid = kid
        headers = {'content-type': 'application/jose+json'}

        resp = requests.post(self.UrlDict["newAccount"], data=data, headers=headers, verify=False)
        if resp.status_code not in [requests.codes.created]:
            print("get_newAccount: ", resp.status_code)
        else:
            self.kid = resp.headers['Location']
            self.nonce = resp.headers['Replay-nonce']

    def post_AccountUpdate(self):
        # required?
        pass
    def post_AccountDeactivation(self):
        # required? 
        pass

    def post_newOrder(self):
        # TODO: values as input???
        data = self.jws.get_newOrderData(self.UrlDict["newOrder"], self.nonce, self.kid, [id.value for id in self.identifiers])
        headers = {'content-type': 'application/jose+json'}

        resp = requests.post(self.UrlDict["newOrder"], data=data, headers=headers, verify=False)
        if resp.status_code not in [requests.codes.created]:
            print("get_newOrder: ", resp.status_code)
        else:
            self.nonce = resp.headers['Replay-nonce']
            self.orderID = resp.headers['Location']
            resp_json = json.loads(resp.text)
            self.expires = resp_json["expires"]
            self.finalize_url = resp_json["finalize"]
            self.authorizations_url = resp_json["authorizations"]

    def post_newAuthz(self):
        data = self.jws.get_newAuthzData(self.authorizations_url[0], self.nonce, self.kid)
        headers = {'content-type': 'application/jose+json'}
        resp = requests.post(self.authorizations_url[0], data=data, headers=headers, verify=False)
        if resp.status_code not in [requests.codes.ok]:
            print("get_newAuthz: ", resp.status_code)
        else:
            self.nonce = resp.headers['Replay-nonce']
            resp_json = json.loads(resp.text)
            self.identifiers[0].set_IdentifierData(resp_json)



    def post_finalizeOrder(self):
        data = self.jws.get_finalizeOrderData(self.UrlDict["newOrder"], self.nonce, self.kid)
        headers = {'content-type': 'application/jose+json'}

        resp = requests.post(self.UrlDict["newOrder"], data=data, headers=headers, verify=False)
