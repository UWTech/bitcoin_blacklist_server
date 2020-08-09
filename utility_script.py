# simple script used to generate signatures and keys
import ecies
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
to_be_signed = b'\x04B4\xf9\x83\xce\x10\xbaY\xd1\xe1\xab\x86\xc6V\xa4\xd5\x98.6\x15\x7fp+\xd3M\xf8\xe9\x1a\x02\x8e\xa2GK\xf1\xa8\xc5\x8d\x93\xbf\x84\xf7\x967#\x18\xd5\xfe$y=\xe27\xc7\xba\xc8A\xc0\x19O\x94\x9as\x9e\xc4\x84%\x03\xef\\F\x1dJ\x81P3Sz\x0fu\xb6\xc4-\x98\x12\x936\x1d\x92\x0c\xf0o\x86l\xb4\x03\xc8$\x10*\xb0i\x00\xac\xc4\xd0\x87\xbb\xde\xe99\xfe`Vq\rC;!\xd4#\xe6@d\x8f-\x7f\xc3\xd0\x016\xef\xc4'
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