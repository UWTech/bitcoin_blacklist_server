'''
contains the top level RESTFul API definitions
'''

import logging
import global_variables
import uvicorn
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.applications import Starlette

app = Starlette()

@app.route("/api/v1/health", methods=["GET"])
async def health(request: Request):
    '''
    API for use in HA to determine health of this specific instance
    of the application
    :param request:
    :return: 200 in a plaintext response if application is healthy, 4xx/5xx otherwise
    '''
    return PlainTextResponse('healthy', status_code=200)

@app.route("/api/v1/request_blacklist", methods=["POST"])
async def post_request_blacklist(request: Request):
    '''
    API for posting initial request to add a public key to the list
    of blacklisted keys
    Requires:
      public_key: the public key to be used in the series of requests
      key_type: one of the enumerated key types supported
      (currently limited to ECDSA)
    :param request:
    :return:
    on success 201 return code and
        record_id: the ID representing the row where the intermediate challenge is stored
        nonce: the ontime cryptographic challenge seed to be encrypted by the private key
    409 if the record already exists in the blacklist for this public key
    400 on malformed request
    5xx on other unspecified error
    '''
    # check if record is already listed for this public key
    # if so, return 409 noting the record already exists in the table of blacklisted public keys
    # generate the nonce
    # generate the record ID
    # add a record to the challenge table with a TTL of 24 hours keyed by the ID containing the
    # public key, and the nonce
    # return a 201, along with the record_id and the nonce
    return JSONResponse('healthy', status_code=200)

@app.route("/api/v1/confirm_blacklist", methods=["POST"])
async def post_confirm_blacklist(request: Request):
    '''
    API for completing the challenge initially posed by the request blacklist API
    Requires:
        record_id: the id in the challenge table associated with the initial request
        encrypted_nonce: the nonce from the initial challenge, encrypted with the private
        key associated with the public key stored in the challenge table
    :param request:
    :return:
    '''
    # attempt to lookup record
    # if not found, return 404
    # found
    # attempt to decrypt the encrypted_nonce param with the public key stored in the
    # challenge table
    # if the decrypted nonce matches the record stored in the challenge table
    # write record in the blacklist table
    # return 201
    # else
    # return 400
    # Note:: assumes we're taking advantage of Bitcoin DDOS properties
    return True

@app.route("/api/v1/blacklist", methods=["GET"])
async def get_blacklist(request: Request):
    '''
    used by Bitcoin nodes to determine if the supplied
    scriptSig's public key is listed in the blacklist table
    :param request:
    :return:
    404 if the supplied public key is not present in the blacklist table
    200 if the key has been blacklisted
    500 in the event of other error
    '''
    # attempt to lookup blacklist based on public key associated with scriptSig
    # if present, return 200
    # if not found return 404
    # other error return 5xx
    return True

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8080)
