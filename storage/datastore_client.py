'''
contains logic for establishing a session with a given database
given credentials and location information injected into environment
'''

import os
import logging
import global_variables
from cassandra.cluster import Cluster
from datetime import datetime
from cassandra.auth import PlainTextAuthProvider


class DatastoreClient:

    def __init__(self):
        self.username = os.environ.get(global_variables.DATASTORE_USERNAME_KEY)
        self.password = os.environ.get(global_variables.DATASTORE_PASSWORD_KEY)
        self.host = os.environ.get(global_variables.DATASTORE_HOST_KEY)
        self.port = os.environ.get(global_variables.DATASTORE_PORT_KEY)
        self.keyspace_name = os.environ.get(global_variables.DATASTORE_KEYSPACE_NAME_KEY)
        try:
            self.datastore_session = self._generate_datastore_session(self.username, self.password, self.host,\
                                                                      self.port, self.keyspace_name)
            # logging.getLogger('cassandra').setLevel(logging.DEBUG)
        except:
            logging.exception('')
            logging.error('failed to establish datastore session')
            raise

    def _generate_datastore_session(self, user, password, host, port, keyspace):
        try:
            self.auth_provider = PlainTextAuthProvider(username=user, password=password)
            self.cluster = Cluster([host], port=port)
            self.session = self.cluster.connect(keyspace=keyspace)
        except:
            logging.exception('')
            logging.error('failed to connect to datastore cluster')
            raise
        return self.session

    def _execute_query(self, query, params_list=None):
        '''
        method that execute the provided query with the supplied optinal params
        :param query: the parametrized query string to be formatted with the optional params
        :param params_list: option params to use in formatting the query string
        :return: the response from the data store
        '''
        try:
            if params_list:
                res = self.session.execute(query, parameters=params_list)
            else:
                res = self.session.execute(query)
        except:
            logging.exception('')
            logging.error('Cassandra query failed: {}'.format(query))
            raise
        return res

    def get_record_from_blacklisted_table(self, pubkey):
        '''
        method responsible for retrieving a record from the permanent blacklist table
        :param pubkey: the hex value (as a number) representing the public key that acts as
        the lookup key for the blacklisted record
        :return:
        '''
        res = self._execute_query(global_variables.DATASTORE_GET_BLACKLISTED_QUERY, pubkey)
        # check for a non-zero number of records for the key
        if len(res.current_rows) > 0:
            return True
        else:
            return False

    def get_record_from_blacklist_request_table(self, pubkey, record_id):
        '''
        retrieves the nonce from the table
        :param pubkey: the public key that acts as the partition key
        :param record_id: the clustering column value for looking up a specific challenge nonce
        :return: the rows associated with the record if the exist
        '''
        query_params = (pubkey, record_id)
        try:
            res = self._execute_query(global_variables.DATASTORE_GET_TEMP_BLACKLISTED_QUERY, params_list=query_params)
            return res
        except:
            logging.exception('')
            logging.error('failed to retrieve record')
            return False

    def write_initial_blacklist_request(self, public_key_hex, record_id, nonce):
        '''
        writes the initial unconfirmed blacklist request to the temporary table with
        the TTL specified in the global variables file
        :param public_key_hex: the hex associated with the public key
        :param record_id: the record ID to be used as the partition key
        :param nonce: the unencrypted nonce to be matched
        :return: true if successful in writing, false or exception otherwise
        '''
        # convert params to list as required by datastore driver
        query_params = (public_key_hex, record_id, nonce)
        try:
            res = self._execute_query(global_variables.DATASTORE_WRITE_TEMP_BLACKLIST_QUERY, query_params)
            return True
        except:
            logging.exception('')
            logging.error('failed to write to table')
            return False

    def write_permanent_blacklist_record(self, public_key_hex):
        '''
        writes the specified record to the permanent table
        :param public_key_hex:
        :return:
        '''
        # convert params to list as required by datastore driver
        try:
            row_timestamp = int(float(datetime.now().strftime("%s.%f"))) * 1000
            res = self._execute_query(global_variables.DATASTORE_WRITE_BLACKLISTED_QUERY, public_key_hex)
                                      #(public_key_hex, str(row_timestamp)))
            return True
        except:
            logging.exception('')
            logging.error('failed to write to table')
            return False

    def close_session(self):
        return True