'''
contains logic for establishing a session with a given database
given credentials and location information injected into environment
'''

import os
import logging
import global_variables

class DatastoreClient:

    def __init__(self):
        self.username = os.environ.get(global_variables.DATASTORE_USERNAME_KEY)
        self.username = os.environ.get(global_variables.DATASTORE_PASSWORD_KEY)
        self.host = os.environ.get(global_variables.DATASTORE_HOST_KEY)

        try:
            self.datastore_session = self._generate_datastore_session(self.username, self.password, self.host)
        except:
            logging.exception('')
            logging.error('failed to establish datastore session')
            raise

    def _generate_datastore_session(self, user, password, host):
        return True

    def execute_query(self):
        return True

    def close_session(self):
        return True