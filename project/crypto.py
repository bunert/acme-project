from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import constants


def get_nonce():
    return get_random_bytes(constants.NONCE_LEN)

def ecdsa_key_gen():
	sk = ECC.generate(curve='P-256')
	pk = sk.public_key()
	pk_pem = pk.export_key(format='PEM')
	return (sk, pk_pem)

def ecdsa_sign(sk, msg):
	hash = SHA256.new(msg)
	sig = DSS.new(sk, 'fips-186-3')
	signature  = sig.sign(hash)
	return signature

def ecdsa_verify(pk_pem, msg, signature):
	pk = ECC.import_key(pk_pem)
	hash = SHA256.new(msg)
	sig = DSS.new(pk, 'fips-186-3')
	try:
		sig.verify(hash, signature)
		result = True
	except ValueError:
		result = False
	return result
