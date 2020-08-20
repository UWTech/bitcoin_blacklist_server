# simple script used to generate signatures and keys
import ecies
import base64
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
to_be_signed = b'\x04\x82\xe5v\xa979s\x1a\xbb\xcdE\x8d\xfb\xb0S\xbf\x96\xd1&0=\x8dU{\x12\xc7\xfdI\x19u\xd1\xa1\x8b\xf8}\xc5\t\xde\xd4\x0fn\x13~H\xd8k\xe34V\xd5/\xbb\xfeI\xc9\xac\x86\xa7\xbfz\xb1\x91Q7C\x17m\x87\x98Y_9\x9fJ\r\xbeB\xb1\x1c>Z\xda\x0c!\x85n\x9c\x1a\x00\xcfL}\xbe\xd9B\xa8DW\xfaF\x94\x10\xb3Ph\x99\xdfR\xe3e\xa2g2\xfb\xec\xf1,\xe8Mb\t\"\xa8\xff\xa7;\x9c\x1b\xbdv\xddA'
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
encoded_signature = base64.b64encode(signature)
# encoded_signature = "MEQCIFE620xZO6hRsijz+RCh0cpnYdXW56VYe2ejmgBc8enaAiBtt/ovNyFMOdM6MeS6b4VAoofToEihu7d/2M0AUdlHJg=="
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