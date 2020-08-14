# simple script used to generate signatures and keys
import ecies
import base64
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
'''
key = ecies.utils.generate_eth_key()
priv_key = key.to_hex()
print('private key:')
print(priv_key)
pub_key = key.public_key.to_hex()
print('public key:')
print(pub_key)
'''

pub_key = 0x8b7b944c1a7312b0c41f1b3b780d96f9d1edb40aea5bbcd95cd591811363f151222434a1f7cd73765c5df6f94c1afc062bf32c02ca8da44ceeb781ff9d500165
priv_key = 0xa2bc5e616913c367314de49dd93bd76638411a01d2362e5a01c1418a199929fb
to_be_signed = b'\x04\x03L\xd07\xe4?Et\xbc7]U\x18X\xc9\xa7\xfd\xe1=\xe6S\x8bHy \xd2tD9\x8b\x10\xaf&\xaa$\xef\xa15q\x1a\xa9\xd8\x03a\xe0\xa7\x06n\x17\xc9Zy\x7f6n\xae\xb4d\x11>_\xcf\xd1\x93cB\xc4\xd8\x1d\xaew\xe6x@\x90~\x99\xb0\xeeQ\xda\x040\xc7\x84\x8a\xd1\xcb\x0b\x949\xae\xf0h\x8f@s(\xb2oO\x82\x06o\xd0,\xd7\x16?\x91\xbbjWN\xd5\x07\xde\r{\xaf\xb7l\x959\xf3\xf2q\xb8\t\xfeO+'
# encrypted_test = ecies.encrypt(pub_key, bytes(to_be_signed, 'utf-8'))
# decrypted_test = ecies.decrypt(priv_key, encrypted_test)
# generate a signature
# msgHash = hashlib.sha3_256(test_string.encode('utf-8'))
ecies_priv_key = ecies.hex2prv(hex(priv_key))
ecies_priv_key.public_key = ecies.hex2pub(hex(pub_key))
decrypted_result = decrypt(hex(priv_key), to_be_signed)
print('decrypted eth:')
print(decrypted_result.decode('utf-8'))
signature = ecies_priv_key.sign(decrypted_result)
print('signed with private:')
print(signature)
# encoded_signature = base64.b64encode(signature)
encoded_signature = "MEQCIFE620xZO6hRsijz+RCh0cpnYdXW56VYe2ejmgBc8enaAiBtt/ovNyFMOdM6MeS6b4VAoofToEihu7d/2M0AUdlHJg=="
print('enncoded signature: ')
print(encoded_signature)
decoded_signature = base64.b64decode(encoded_signature)
print('decoded signature')
print(decoded_signature)
ecies_pub_key = ecies.hex2pub(hex(pub_key))
result = ecies_pub_key.verify(signature, decrypted_result)
if result:
    print('matched public key verification')
else:
    print('did not match public key verification')

'''
eth_k = generate_eth_key()
sk_hex = eth_k.to_hex()  # hex string
pk_hex = eth_k.public_key.to_hex()  # hex string
data = b'this is a test'
result = decrypt(sk_hex, encrypt(pk_hex, data))
print('decrypted eth:')
print(result.decode('utf-8'))
secp_k = generate_key()
sk_bytes = secp_k.secret  # bytes
pk_bytes = secp_k.public_key.format(True)  # bytes
sec_res = decrypt(sk_bytes, encrypt(pk_bytes, data))
print('decrypted sec:')
print(sec_res.decode('utf-8'))
'''