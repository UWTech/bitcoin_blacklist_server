'''
contains methods and logic for handling initial blacklist requests,
as well as confirming secondary requests, and writing those requests to the
permanent blacklist.
Responsible for evaluating validity of requests, and writing through to temporary
and permanent tables as appropriate
'''

import logging
import global_variables
import ecies
import base64
from ecdsa import VerifyingKey
import uuid

from storage.datastore_client import DatastoreClient
class BlacklistRequestHandler:

    def __init__(self):
        self.datastore_client = DatastoreClient()

    def _write_to_intial_request_table(self, pub_key_string, record_id, unencrypted_nonce):
        '''
        writes the row to the initial request table
        :param pub_key_string: the public key, as a string, that will serve as the primary key for the partition
        :param record_id: the secondary unique identifier to differentiate discrete requests,
        this prevents bad actors from overwriting records with the public key alone
        :param unencrypted_nonce: the nonce generated for the challenge
        :return: true if record is written successfully, false on bad input,
        and the constant 'Conflict' if the record already exists
        '''
        try:
            # insert
            res = self.datastore_client.write_initial_blacklist_request(str(pub_key_string), str(record_id),
                                                                        str(unencrypted_nonce))
            if res:
                return True
            else:
                logging.error('failed to write temp record')
                return False
        except:
            logging.exception('')
            logging.error('failed to write temp record')
            return False

    def check_for_blacklist_entry(self, pub_key_string):
        '''
        checks for the existence of the record in the blacklist table
        :param pub_key_string: the lookup key for the blacklist record
        :return: true if the record has already been blacklisted, false otherwise
        '''
        res = self.datastore_client.get_record_from_blacklisted_table([pub_key_string])
        return res

    def _write_to_permanent_blacklist_table(self):
        return True

    def _encrypt_nonce(self, pub_key, nonce, key_type):
        '''
        method responsible for generating the encrypted nonce
        :param pub_key: the public key used to encrypt the nonce
        :param nonce: the nonce to be encrypted
        :param key_type: the type of key being used for the encryption
        :return: the nonce encrypted with the public key
        '''
        if key_type.upper() == global_variables.SECP256k1_TYPE:
            #key = ecies.utils.generate_eth_key()
            #priv_key = key.to_hex()
            #pub_key = key.public_key.to_hex()
            encrypted_nonce = ecies.encrypt(str(pub_key), bytes(nonce, 'utf-8'))
            return encrypted_nonce
        else:
            # not in supported key types
            raise ValueError('invalid key type specified')

    def _decrypt_nonce(self, pub_edcsa, encrypted_nonce):
        '''
        method responsible for generating the decrypted nonce
        :param pub_ecdsa: the public key used to encrypt the nonce
        :param encrypted_nonce: the nonce to be decrypted
        :return:
        '''
        # decrypt nonce using public key,
        # return
        return True

    def generate_challenge(self, pub_key_string, key_type):
        '''
        method responsible for encrypting a nonce with
        the public key, and storing in the temporary table
        :param pub_key_string: the string representation of the key
        :param key_type: the key type as allowed in the global variables
        :return: return value (true, false, conflict), the nonce that was written to the table encrypted with the public key,
        and the record ID (record ID allows for differentiation of multiple attempts,
        and prevents interference from bad actors)
        '''
        # avoid costly encryption if the record already exists, and return 'conflict'
        exists = self.check_for_blacklist_entry(pub_key_string)
        if exists:
            return global_variables.CONFLICT_STRING, 'Record exists for public key'

        # generate the nonce, use UUID4 to minimize bad actors causing collisions
        challenge_nonce = str(uuid.uuid4())
        # convert the string to a key
        try:
            pub_key = self._key_from_string(pub_key_string, key_type)
        except ValueError:
            logging.exception('')
            logging.error('invalid key type specified')
            return global_variables.BAD_INPUT, "Unsupported of invalid key type specified"

        # encrypt the nonce
        encrypted_nonce = self._encrypt_nonce(pub_key, challenge_nonce, key_type)
        # generate record ID
        record_id = uuid.uuid4()
        # write record to nonce table
        result = self._write_to_intial_request_table(pub_key_string, record_id, challenge_nonce)
        # convert the nonce and record ID to a JSON friendly format for the response
        return result, str(encrypted_nonce), str(record_id)

    def _key_from_string(self, key_string, key_type):
        if key_type.upper() == global_variables.SECP256k1_TYPE:
            ecc_key = key_string
            return ecc_key
        else:
            # not in supported key types
            raise ValueError('invalid key type specified')

    def _verify_key_validity(self, pub_key):
        '''
        confirms that the supplied key is valid
        :param pub_key:
        :return: true if the key is valid, false otherwise
        '''
        try:
            pub_key = VerifyingKey.from_der()
        except:
            logging.exception('')
            logging.error('key invalid')
            return False

    def verify_challenge(self, pub_key, record_id, signed_nonce):
        '''
        method responsible for putting a record permanently in the black list table
        Checks the validity of the encrypted nonce against the record for the
        associated public key
        :return: status code associated with interaction
        '''
        # note DDos protection is to be taken care of by existing Bitcoin
        # check for existence of record keyed by this public key
        # if not present return 404
        result = self.datastore_client.get_record_from_blacklist_request_table(pub_key, record_id)
        if result is False:
            logging.info('failed to find record')
            return False
        # if present
        # decrypt the supplied nonce using the supplied public key
        stored_decrypted_nonce = result.current_rows[0].nonce
        # convert from base64 string to Bytes
        signature_bytes = base64.b64decode(signed_nonce)
        # verify the signature
        match = self._compare_nonce(pub_key, signature_bytes, stored_decrypted_nonce)
        # if they do not match, return a False
        if match is False:
            logging.info('nonce values did not match')
            return False
        else:
            # if they do match, write a permanent blacklist request to the blacklist table
            try:
                # TODO:: hash entry before writing: https://learnmeabitcoin.com/technical/public-key-hash
                # calculate the OP_HASH160 of the address, as this will be the scriptPubKey
                # echo -n $PUB_KEY | xxd -r -p | openssl dgst -sha256 -binary | openssl dgst -rmd160
                OP_HASH160 = subprocess.call('echo -n {} | xxd -r -p | openssl dgst -sha256 -binary | openssl dgst -rmd160'.format(pub_key))
                result = self.datastore_client.write_permanent_blacklist_record([OP_HASH160])
                return result
            except:
                logging.exception('')
                logging.error('failed to write record to permanent table')
                return False

    def _compare_nonce(self, pub_key, signed_nonce, stored_decrypted_nonce):
        '''
        compares the signed nonce with the supplied public key, and verifies
        the value is the same as that stored in the datastore
        :param pub_key: key to use for decrypting the nonce
        :param signed_nonce: the nonce supplied by the user
        :param stored_decrypted_nonce: the value expected
        :return: true if the nonces match, false or exception otherwise
        '''
        # compare and verify signature
        try:
            pub_key = ecies.hex2pub(pub_key)
            result = pub_key.verify(signed_nonce, stored_decrypted_nonce.encode())
            return result
        except:
            logging.exception('')
            logging.error('failed to verify signature')
            return False