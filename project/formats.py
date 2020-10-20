from Crypto.PublicKey import ECC
import json
import base64
import crypto
import constants

def b64encode(msg):
    if not isinstance(msg, bytes):
        msg = msg.encode('utf-8')
    return base64.urlsafe_b64encode(msg).rstrip(b'=').decode('utf-8')

def b64decode(msg):
    if not isinstance(msg, str):
        msg = msg.decode('utf-8')
    return base64.urlsafe_b64decode(msg).decode('utf-8')

def get_jwsObject(header, payload, sig):
    jws_object = {
        "protected": header,
        "payload": payload,
        "signature": sig,
    }

    return json.dumps(jws_object)


class JSONWebSignature(object):
    """docstring for JWS."""

    def __init__(self, pk_pem, sk):
        self.sk = sk
        self.pk = ECC.import_key(pk_pem)

    def get_jwsSignature(self, header, payload):
        sign_msg = '.'.join([header, payload])
        sign_msg_encoded = sign_msg.encode(encoding="ascii")

        return b64encode(crypto.ecdsa_sign(self.sk, sign_msg_encoded))

    def get_jwkHeader(self, url, nonce):
        self.kid = "1"
        jwk_dict = {}
        jwk_dict["kty"] = "EC"
        jwk_dict["crv"] = str(self.pk.curve[5:])
        jwk_dict["x"] = str(b64encode((self.pk.pointQ.x).to_bytes(constants.EC_COORDINATE_LEN)))
        jwk_dict["y"] = str(b64encode((self.pk.pointQ.y).to_bytes(constants.EC_COORDINATE_LEN)))
        jwk_dict["kid"] = self.kid

        header_dict = {}
        header_dict["alg"] = "ES256"
        header_dict["jwk"] = jwk_dict
        header_dict["nonce"] = nonce
        header_dict["url"] = url
        header_json = json.dumps(header_dict)
        return header_json

    def get_kidHeader(self, kid, nonce, url):
        header_dict = {}
        header_dict["alg"] = "ES256"
        header_dict["kid"] = kid
        header_dict["nonce"] = nonce
        header_dict["url"] = url
        header_json = json.dumps(header_dict)
        return header_json

    def get_newAccountData(self, url, nonce):
        header_json = self.get_jwkHeader(url, nonce)

        payload_dict = {}
        payload_dict["termsOfServiceAgreed"] = True
        payload_json = json.dumps(payload_dict)


        jws_protected_header = b64encode(header_json)

        jws_payload = b64encode(payload_json)

        jws_signature = self.get_jwsSignature(jws_protected_header, jws_payload)

        return get_jwsObject(jws_protected_header, jws_payload, jws_signature), self.kid

    def get_newOrderData(self, url, nonce, kid, values):
        header_json = self.get_kidHeader(kid, nonce, url)
        jws_protected_header = b64encode(header_json)

        payload_dict = {}
        payload_dict["identifiers"] = [{"type": "dns", "value": value} for value in values]
        # payload_dict["notBefore"] = "2020-10-10T00:04:00+04:00"
        # payload_dict["notAfter"] = "2020-10-20T00:04:00+04:00"
        payload_json = json.dumps(payload_dict)

        jws_payload = b64encode(payload_json)

        jws_signature = self.get_jwsSignature(jws_protected_header, jws_payload)

        return get_jwsObject(jws_protected_header, jws_payload, jws_signature)

    def get_newAuthzData(self, url, nonce, kid):
        header_json = self.get_kidHeader(kid, nonce, url)
        jws_protected_header = b64encode(header_json)

        payload = ""

        jws_payload = b64encode(payload)

        jws_signature = self.get_jwsSignature(jws_protected_header, jws_payload)

        return get_jwsObject(jws_protected_header, jws_payload, jws_signature)

    def get_finalizeOrderData(self, url, nonce, kid):
        header_json = self.get_kidHeader(kid, nonce, url)
        jws_protected_header = b64encode(header_json)

        payload_dict = {}
        payload_dict["csr"] = "test"
        payload_json = json.dumps(payload_dict)

        jws_payload = b64encode(payload_json)

        jws_signature = self.get_jwsSignature(jws_protected_header, jws_payload)

        return get_jwsObject(jws_protected_header, jws_payload, jws_signature)

class Identifier(object):
    def __init__(self, value):
        self.value = value

    def set_challenges(self, challenges):
        self.challenge_array = [c for c in challenges]