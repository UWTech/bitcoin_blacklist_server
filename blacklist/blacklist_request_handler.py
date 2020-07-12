'''
contains methods and logic for handling initial blacklist requests,
as well as confirming secondary requests, and writing those requests to the
permanent blacklist.
Responsible for evaluating validity of requests, and writing through to temporary
and permanent tables as appropriate
'''

import logging
import ecdsa
from storage.datastore_client import DatastoreClient
class BlacklistRequestHandler:

    def __init__(self):
        self.datastore_client = DatastoreClient()

    def _write_to_intial_request_table(self):
        return True

    def _write_to_permanent_blacklist_table(self):
        return True

    def _encrypt_nonce(self, pub_ecdsa, nonce):
        '''
        method responsible for generating the encrypted nonce
        :param pub_ecdsa: the public key used to encrypt the nonce
        :param nonce: the nonce to be encrypted
        :return:
        '''
        # encrypt nonce using public key,
        # return
        return True

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

    def generate_challenge(self, pub_ecdsa):
        '''
        method responsible for encrypting a nonce with
        the public key, and storing in the temporary table
        :param pub_ecdsa:
        :return: the nonce written to the table, and the record ID
        '''
        # check if key is already black listed
        # if so, return 409 conflict
        # if not generate nonce
        # encrypt the nonce with the public key
        # write nonce to table, keyed by the public key
        # return the Nonce
        return True

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

