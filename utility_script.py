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
# command to generate the scriptPubKey
# echo -n $PUB_KEY | xxd -r -p | openssl dgst -sha256 -binary | openssl dgst -rmd160
pub_key = 0x8b7b944c1a7312b0c41f1b3b780d96f9d1edb40aea5bbcd95cd591811363f151222434a1f7cd73765c5df6f94c1afc062bf32c02ca8da44ceeb781ff9d500165
priv_key = 0xa2bc5e616913c367314de49dd93bd76638411a01d2362e5a01c1418a199929fb
to_be_signed = b'\\x04\\xfa\\xf1c\\xb1V\\xae\\xd7\\x07B\\x12\\x1e\\xb1\\xc6\\xa8OI\\xb9\\xb9H\\x07b\\xa1U\\x84\\xc8\\xb9o\\x9c\\x152c\\x9a\\xf7:\\x93PvC\\x9e\\xed\\xc0\\xfc\\xbbF\\x84f\\xb8\\x80\\xa0\\xd3d+\\x91Z\\xf2\\xb8g\\xf6gL\\xd3\\xaeZ3\\xdeF\\x08\\x1e\\xedYI-W\\x1d\\x94\\xb5\\xd1\\xdf\\xa7\\xc8\\xe8~z\\xf2?\\xc7{\\xad\\xa6P\\xb9\\x07:\\xfd\\xd1\\xc8x\\xf6\\x7f\\x916_\\xde\\xd7\\xafk\\x9a\\xcf\\xb8\\x9b\\x9e\\x92i\\xd8\\xfbCsfpU^L\\xc7\\xf4 \\xff\\xa7S\\xed\\x9a\\xbf\\x07'
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
b'0D\\x02 bw`\\xcb{`\\x1b\\xc8O\\x92\\xe1\\xbcl\\xeb\\xa7._\\xeadx\\x10\\x80\\xf0\\x1a\\x16\\xbc\\xdd\\xc0I\\xfc\\x97\\xd3\\x02 y*\\x821e\\xa2\\xbd%.\\xfa\\xb3Jo\\xd0B(\\xc5\\x10\\xfe\\x99}`\\xc0\\x10\\xe3\\xdfH\\x98/\\x83\\xce\\x91'
