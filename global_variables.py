'''
contains names of global variables for ease of dependency injection,
and ensuring there are no typos
'''

# runtime constants
SECP256k1_TYPE = 'SECP256K1'
CONFLICT_STRING = 'conflict'
BAD_INPUT = 'bad_input'
SERVER_ERROR = 'server_error'
PUBLIC_KEY = 'public_key'
KEY_TYPE = 'key_type'
# environment variables for data store
DATASTORE_USERNAME_KEY = 'DATASTORE_USERNAME'
DATASTORE_PASSWORD_KEY = 'DATASTORE_PASSWORD'
DATASTORE_HOST_KEY = 'DATASTORE_HOST'
DATASTORE_PORT_KEY = 'DATASTORE_PORT'
DATASTORE_KEYSPACE_NAME_KEY = 'DATASTORE_KEYSPACE_NAME'
DATASTORE_CERT_PATH_KEY = 'DATASTORE_CERT_PATH'
# response params
SIGNED_NONCE = 'signed_nonce'
ENCRYPTED_NONCE = 'encrytped_nonce'
RECORD_ID = 'record_id'
# queries for datastore
# for adding a record that is being considered for inclusion in the permanent table. TTL of 1200 seconds leaves 20 minutes for the requestor to confirm
DATASTORE_WRITE_TEMP_BLACKLIST_QUERY = 'insert into blacklist_request (public_key_hex, record_id, nonce) values (%s,%s,%s) using ttl 1200'
# for retrieving the temporary record to confirm nonce values
DATASTORE_GET_TEMP_BLACKLISTED_QUERY = 'select * from blacklist_request where public_key_hex=%s and record_id=%s'
# for retrieving a record from the permanent blacklisted table
DATASTORE_GET_BLACKLISTED_QUERY = 'select * from blacklisted_keys where public_key_hex=%s'
# for writing a record to the permanent table
DATASTORE_WRITE_BLACKLISTED_QUERY = 'insert into blacklisted_keys (public_key_hex, datetime) values (%s, toTimestamp(now()))'

