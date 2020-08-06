'''
contains logic for establishing a session with a given database
given credentials and location information injected into environment
'''

import os
import logging
import global_variables
from ssl import PROTOCOL_TLSv1, CERT_REQUIRED, CERT_OPTIONAL
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
from cassandra.policies import RoundRobinPolicy


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

    def close_session(self):
        return True