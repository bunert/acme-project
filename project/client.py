import requests
import json
import formats
import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class ACMEClient(object):
    """docstring fo Client."""

    def __init__(self, url, values):
        self.UrlDict = {}
        self.UrlDict["dir"] = url
        self.nonce = ""

        sk, pk = crypto.ecdsa_key_gen()
        self.ecdsa_sk = sk
        self.ecdsa_pk = pk
        self.jws = formats.JSONWebSignature(self.ecdsa_pk, self.ecdsa_sk)
        self.identifiers = {}
        for value in values:
            self.identifiers[value] = formats.Identifier()

    def get_rootCert(self):
        resp =  requests.get('https://localhost:15000/roots/0', verify='pebble.minica.pem')
        cafile = resp.text
        with open ("private.pem", "w") as prv_file:
            print("{}".format(cafile), file=prv_file)

    def get_challenge(self, dom, challenge):
        for c in self.identifiers[dom].challenge_array:
            if (c.type == challenge):
                return c
        print("no such challenge exists")

    def init_directory(self):
        # pebble.minica.pem
        resp = requests.get(self.UrlDict["dir"], verify='pebble.minica.pem')
        if resp.status_code not in [requests.codes.ok]:
            print("init_directory: ", resp.status_code)
        else:
            # handle response
            dir = json.loads(resp.text)
            self.UrlDict["newAccount"] = dir["newAccount"]
            self.UrlDict["newNonce"] = dir["newNonce"]
            self.UrlDict["newOrder"] = dir["newOrder"]
            self.UrlDict["revokeCert"] = dir["revokeCert"]
        # exit(1)


    def get_newNonce(self):
        resp = requests.get(self.UrlDict["newNonce"], verify='pebble.minica.pem')
        if resp.status_code not in [requests.codes.no_content,requests.codes.ok]:
            print("get_newNonce: ", resp.status_code)
        else:
            # handle response
            self.nonce = resp.headers['Replay-nonce']

    def post_newAccount(self):
        data, kid = self.jws.get_newAccountData(self.UrlDict["newAccount"], self.nonce)
        self.kid = kid
        headers = {'content-type': 'application/jose+json'}

        resp = requests.post(self.UrlDict["newAccount"], data=data, headers=headers, verify='pebble.minica.pem')
        if resp.status_code not in [requests.codes.created]:
            print("get_newAccount: ", resp.status_code)
            self.get_newNonce()
            self.post_newAccount()
        else:
            # handle response
            self.kid = resp.headers['Location']
            self.nonce = resp.headers['Replay-nonce']

    def post_AccountUpdate(self):
        # required?
        pass
    def post_AccountDeactivation(self):
        # required?
        pass

    def post_newOrder(self, domains):
        # TODO: values as input???
        data = self.jws.get_newOrderData(self.UrlDict["newOrder"], self.nonce, self.kid, domains)
        headers = {'content-type': 'application/jose+json'}

        resp = requests.post(self.UrlDict["newOrder"], data=data, headers=headers, verify='pebble.minica.pem')
        if resp.status_code not in [requests.codes.created]:
            print("get_newOrder: ", resp.status_code)
            self.get_newNonce()
            self.post_newOrder()
        else:
            # handle response
            self.nonce = resp.headers['Replay-nonce']
            self.UrlDict["order"] = resp.headers['Location']
            resp_json = json.loads(resp.text)
            self.expires = resp_json["expires"]
            self.UrlDict["finalize"] = resp_json["finalize"]
            ids= resp_json["identifiers"]
            urls = resp_json["authorizations"]
            # print(resp.text)
            for i in range(len(ids)):
                # print(ids[i]["value"])
                self.identifiers[ids[i]["value"]].authorizations_url = urls[i]

    def post_newAuthz(self, dom):
        data = self.jws.get_newAuthzData(self.identifiers[dom].authorizations_url, self.nonce, self.kid)
        headers = {'content-type': 'application/jose+json'}
        resp = requests.post(self.identifiers[dom].authorizations_url, data=data, headers=headers, verify='pebble.minica.pem')
        if resp.status_code not in [requests.codes.ok]:
            print("post_newAuthz: ", resp.status_code)
            self.get_newNonce()
            self.post_newAuthz(dom)
        else:
            # handle response
            # print(resp.text)
            self.nonce = resp.headers['Replay-nonce']
            resp_json = json.loads(resp.text)
            true_dom = resp_json["identifier"]["value"]
            wildcard = False
            try:
                wildcard = resp_json["wildcard"]
            except KeyError:
                pass
            if (wildcard):
                true_dom = '*.'+true_dom
            self.identifiers[true_dom].set_IdentifierData(resp_json, self.jws)

    def post_ChallengeReady(self, dom, challenge):
        c = self.get_challenge(dom, challenge)
        url = c.url
        data = self.jws.get_ChallengeReadyData(url, self.nonce, self.kid)
        headers = {'content-type': 'application/jose+json'}

        resp = requests.post(url, data=data, headers=headers, verify='pebble.minica.pem')
        if resp.status_code not in [requests.codes.ok]:
            print("post_ChallengeReady: ", resp.status_code)
            self.get_newNonce()
            self.post_ChallengeReady(dom, challenge)
            # TODO: On receiving such an error, the client SHOULD undo any actions that have been
            # taken to fulfill the challenge, e.g., removing files that have been provisioned to a web server.
        else:
            # handle response
            self.nonce = resp.headers['Replay-nonce']

    def post_checkStatus(self, dom):
        data = self.jws.get_newAuthzData(self.identifiers[dom].authorizations_url, self.nonce, self.kid)
        headers = {'content-type': 'application/jose+json'}
        resp = requests.post(self.identifiers[dom].authorizations_url, data=data, headers=headers, verify='pebble.minica.pem')
        if resp.status_code not in [requests.codes.ok]:
            print("post_checkStatus: ", resp.status_code)
            self.get_newNonce()
            self.post_checkStatus(dom)
        else:
            # handle response
            # print(resp.text)
            self.nonce = resp.headers['Replay-nonce']
            resp_json = json.loads(resp.text)



    def post_finalizeOrder(self, domains):
        data = self.jws.get_finalizeOrderData(self.UrlDict["finalize"], self.nonce, self.kid, domains)
        headers = {'content-type': 'application/jose+json'}

        resp = requests.post(self.UrlDict["finalize"], data=data, headers=headers, verify='pebble.minica.pem')
        # print(resp.text)
        if resp.status_code not in [requests.codes.ok]:
            print("post_finalizeOrder: ", resp.status_code)
        else:
            # handle response
            self.nonce = resp.headers['Replay-nonce']
            resp_json = json.loads(resp.text)

    def post_checkOrder(self):
        data = self.jws.get_checkOrderData(self.UrlDict["order"], self.nonce, self.kid)
        headers = {'content-type': 'application/jose+json'}
        resp = requests.post(self.UrlDict["order"], data=data, headers=headers, verify='pebble.minica.pem')
        if resp.status_code not in [requests.codes.ok]:
            print("post_checkOrder: ", resp.status_code)
            self.get_newNonce()
            return self.post_checkOrder()
        else:
            # handle response
            # print(resp.text)
            self.nonce = resp.headers['Replay-nonce']
            resp_json = json.loads(resp.text)
            if (resp_json["status"] == "valid"):
                self.UrlDict["cert"] = resp_json["certificate"]
            return resp_json["status"]
        return 'false'

    def post_DownloadCert(self):
        data = self.jws.get_DownloadCertData(self.UrlDict["cert"], self.nonce, self.kid)
        headers = {'content-type': 'application/jose+json'}

        resp = requests.post(self.UrlDict["cert"], data=data, headers=headers, verify='pebble.minica.pem')
        if resp.status_code not in [requests.codes.ok]:
            print("post_DownloadCert: ", resp.status_code)
            self.get_newNonce()
            self.post_DownloadCert()
        else:
            self.nonce = resp.headers['Replay-nonce']
            cert = x509.load_pem_x509_certificate(resp.text.encode('utf-8'), default_backend())
            return cert

    def post_revokeCert(self, cert):
        data = self.jws.get_RevokeCertData(self.UrlDict["revokeCert"], self.nonce, self.kid, cert)
        headers = {'content-type': 'application/jose+json'}

        resp = requests.post(self.UrlDict["revokeCert"], data=data, headers=headers, verify='pebble.minica.pem')
        if resp.status_code not in [requests.codes.ok]:
            print("post_revokeCert: ", resp.status_code)
            self.get_newNonce()
            self.post_revokeCert(cert)
        else:
            # handle response
            self.nonce = resp.headers['Replay-nonce']

    def post_newHttpChallenge(self, dom, ip, challenge):
        headers = {'content-type': 'application/jose+json'}
        c = self.get_challenge(dom, challenge)
        url = 'http://'+ip+':5002' +'/.well-known/acme-challenge/'+c.token
        data = json.dumps({"keyAuthorization":c.keyAuthorization})
        resp = requests.post(url, data=data, headers=headers)
        if resp.status_code not in [requests.codes.created]:
            print("post_newHttpChallenge:" , resp.status_code)
