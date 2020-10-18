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

class JSONWebSignature(object):
    """docstring for JWS."""

    def __init__(self, pk_pem, sk):
        self.sk = sk
        self.pk = ECC.import_key(pk_pem)




    def get_newAccountData(self, url, nonce):
        kid = "1"
        jwk_dict = {}
        jwk_dict["kty"] = "EC"
        jwk_dict["crv"] = str(self.pk.curve[5:])
        jwk_dict["x"] = str(b64encode((self.pk.pointQ.x).to_bytes(constants.EC_COORDINATE_LEN)))
        jwk_dict["y"] = str(b64encode((self.pk.pointQ.y).to_bytes(constants.EC_COORDINATE_LEN)))
        jwk_dict["kid"] = kid

        header_dict = {}
        header_dict["alg"] = "ES256"
        header_dict["jwk"] = jwk_dict
        header_dict["nonce"] = nonce
        header_dict["url"] = url
        header_json = json.dumps(header_dict)

        payload_dict = {}
        payload_dict["termsOfServiceAgreed"] = True
        payload_json = json.dumps(payload_dict)


        jws_protected_header = b64encode(header_json)

        jws_payload = b64encode(payload_json)

        sign_msg = '.'.join([jws_protected_header, jws_payload])
        sign_msg_encoded = sign_msg.encode(encoding="ascii")

        jws_signature = b64encode(crypto.ecdsa_sign(self.sk, sign_msg_encoded))

        jws_object = {
            "protected": jws_protected_header,
            "payload": jws_payload,
            "signature": jws_signature,
        }


        return json.dumps(jws_object), kid

    def get_newOrderData(self, url, nonce, kid):
        header_dict = {}
        header_dict["alg"] = "ES256"
        header_dict["kid"] = kid
        header_dict["nonce"] = nonce
        header_dict["url"] = url
        header_json = json.dumps(header_dict)

        payload_dict = {}
        id_entry1 = {"type": "dns", "value": "www.example.org"}
        id_entry2 = {"type": "dns", "value": "example.org"}
        payload_dict["identifiers"] = [id_entry1, id_entry2]
        # payload_dict["notBefore"] = "2020-10-10T00:04:00+04:00"
        # payload_dict["notAfter"] = "2020-10-20T00:04:00+04:00"
        payload_json = json.dumps(payload_dict)

        jws_protected_header = b64encode(header_json)

        jws_payload = b64encode(payload_json)

        sign_msg = '.'.join([jws_protected_header, jws_payload])
        sign_msg_encoded = sign_msg.encode(encoding="ascii")

        jws_signature = b64encode(crypto.ecdsa_sign(self.sk, sign_msg_encoded))

        jws_object = {
            "protected": jws_protected_header,
            "payload": jws_payload,
            "signature": jws_signature,
        }


        return json.dumps(jws_object)

    def get_finalizeOrderData(self, url, nonce, kid):
        header_dict = {}
        header_dict["alg"] = "ES256"
        header_dict["kid"] = kid
        header_dict["nonce"] = nonce
        header_dict["url"] = url
        header_json = json.dumps(header_dict)

        payload_dict = {}
        payload_dict["csr"] = "test"
        payload_json = json.dumps(payload_dict)

        jws_protected_header = b64encode(header_json)

        jws_payload = b64encode(payload_json)

        sign_msg = '.'.join([jws_protected_header, jws_payload])
        sign_msg_encoded = sign_msg.encode(encoding="ascii")

        jws_signature = b64encode(crypto.ecdsa_sign(self.sk, sign_msg_encoded))

        jws_object = {
            "protected": jws_protected_header,
            "payload": jws_payload,
            "signature": jws_signature,
        }


        return json.dumps(jws_object)
