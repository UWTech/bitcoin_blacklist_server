'''
contains methods and logic for handling initial blacklist requests,
as well as confirming secondary requests, and writing those requests to the
permanent blacklist.
Responsible for evaluating validity of requests, and writing through to temporary
and permanent tables as appropriate
'''

import logging
import global_variables
import ecdsa
import ecies
from ecies.utils import generate_key
from ecies import encrypt, decrypt
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import uuid
import hashlib

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
        # check if the record already exists in permanent blacklist table
        if self.check_for_blacklist_entry(pub_key_string):
            return global_variables.CONFLICT_STRING
        # if so, return conflict
        # else
        try:
            # insert
            res = self._write_to_intial_request_table(pub_key_string, record_id, unencrypted_nonce)
            if res: # TODO:: check logic
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
        if key_type == global_variables.SECP256k1_TYPE:
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
        exists = self._check_for_blacklist_entry(pub_key_string)
        if exists:
            return global_variables.CONFLICT_STRING, 'Record exists for public key'

        # if not generate nonce
        # encrypt the nonce with the public key
        # write nonce to table, keyed by the public key, and ID
        # return the encrypted Nonce
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
        return result, encrypted_nonce, record_id

    def _key_from_string(self, key_string, key_type):
        if key_type == global_variables.SECP256k1_TYPE:
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

    def verify_challenge(self, pub_ecdsa, encrypted_nonce):
        '''
        method responsible for putting a record permanently in the black list table
        Checks the validity of the encrypted nonce against the record for the
        associated public key
        :return: status code associated with interaction
        '''
        # note DDos protection is to be taken care of by existing Bitcoin
        # DDOS protections. Exponential backoff has based off number of requests for a public key
        # has the potential to allow attacker to make it impossible for legitimate owner to
        # to request blacklist
        # check for existence of record keyed by this public key
        # if not present return 404
        # if present
        # decrypt the supplied nonce using the supplied public key
        # compare with the store decrypted nonce
        # if they do not match, return a 400
        # if they do match, write a permanent blacklist request to the blacklist table
        # return a 201
        return True

