'''
contains the top level RESTFul API definitions
'''
import binascii
import logging
import ecdsa

from ecdsa.ecdsa import generator_secp256k1
from ecdsa import VerifyingKey

import global_variables
import os
import ecies
import uvicorn
import requests
from blacklist.blacklist_request_handler import  BlacklistRequestHandler
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.applications import Starlette
from json import JSONDecodeError
# for signature
import hashlib, secrets
app = Starlette()
blacklist_handler = BlacklistRequestHandler()

@app.route("/api/v1/transaction", methods=["POST"])
async def transaction(request: Request):
    '''
    method that takes in the Bitcoin transaction, 
    and checks the scriptPubKey parameter against the 
    blacklist service to determine if the transaction
    should be allowed on the basis of the state of the
    bitcoin key
    :param request: the body containing the Bitcoin transaction JSON
    :return: 201 in event transaction is allowed 400 otherwise
    '''
    # extract any script pub keys (scriptPubKey) from any of the request info
    # note that this can entail multiple keys in teh event on a complex
    # transaction
    # if the scriptPubKey is listed as black listed,
    # return 4xx return code, and do not pass on the request to the Bitcion node
    # if the key is not blacklisted, 
    # pass to Bitcoin CLI via shell communication,
    # and pass response
    try:
        request_payload = await request.json()
    except JSONDecodeError:
        logging.exception('')
        logging.error('failed to decode request')
        return JSONResponse('bad JSON', status_code=400)
    # check each JSON record in the request, as in the event of complex
    # transaction, could multiple scriptPubKey involved
    is_blacklisted = False
    blacklist_server_uri = os.environ.get(global_variables.BLACKLIST_SERVER_URI)
    blacklist_server_uri = blacklist_server_uri + global_variables.CHECK_KEY_STATUS_URI_PATH
    for json_record in request_payload:
        # extract the public key associated with this JSON element involved in transaction
        scriptPubKey = json_record[global_variables.SCRIPT_PUB_KEY]
        # check against blacklisted keys
        resp = requests.post(blacklist_server_uri)
    if is_blacklisted is False:
        # pass transaction to CLI 
        response = 'success'
        return JSONResponse(response, status_code=201)
    else:
        # key has been blacklisted
        return JSONResponse('Key invalid. Listed as blacklisted', 400)

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
      (currently limited to ECC SECP256k1)
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
    # return a 201, along with the record_id (public key is record ID) and the nonce

    try:
        request_payload = await request.json()
    except JSONDecodeError:
        logging.exception('')
        logging.error('failed to decode request')
        return JSONResponse('bad JSON', status_code=400)

    public_key = request_payload[global_variables.PUBLIC_KEY]
    key_type = request_payload[global_variables.KEY_TYPE]

    result, encrypted_nonce, record_id = blacklist_handler.generate_challenge(public_key, key_type)

    if result == global_variables.CONFLICT_STRING:
        return JSONResponse('Conflict', status_code=409)
    if result == global_variables.BAD_INPUT:
        return JSONResponse('Bad Input', status_code=400)
    if result == global_variables.SERVER_ERROR:
        return JSONResponse('Internal Server Error', status_code=500)
    # else
    response = {}
    response[global_variables.ENCRYPTED_NONCE] = encrypted_nonce
    response[global_variables.RECORD_ID] = record_id
    return JSONResponse(response, status_code=201)

@app.route("/api/v1/confirm_blacklist", methods=["POST"])
async def post_confirm_blacklist(request: Request):
    '''
    API for completing the challenge initially posed by the request blacklist API
    Requires:
        record_id: the id in the challenge table associated with the initial request
        key_type: one of the enumerated key types supported
        (currently limited to ECC SEP25k)
        encrypted_nonce: the nonce from the initial challenge, encrypted with the private
        key associated with the public key stored in the challenge table
    :param request:
    :return:
    '''
    # attempt to lookup record
    # if not found, return 404
    # found
    # sha3_256 hash the nonce, verify the signature with the public key stored
    # https://wizardforcel.gitbooks.io/practical-cryptography-for-developers-book/content/digital-signatures/ecdsa-sign-verify-examples.html
    # challenge table
    # if the nonce signature matches the record stored in the challenge table
    # write record in the blacklist table
    # return 201
    # else
    # return 400
    # Note:: assumes we're taking advantage of Bitcoin DDOS properties
    try:
        try:
            request_payload = await request.json()
        except JSONDecodeError:
            logging.exception('')
            logging.error('failed to decode request')
            return JSONResponse('bad JSON', status_code=400)

        public_key = request_payload[global_variables.PUBLIC_KEY]
        record_id = request_payload[global_variables.RECORD_ID]
        signed_nonce = request_payload[global_variables.SIGNED_NONCE]
        result = blacklist_handler.check_for_blacklist_entry(public_key)

        if result is True:
            # don't do expensive decryption if the key pair is
            # already blacklisted
            return JSONResponse('key is blacklisted', status_code=409)

        # attempt to verify the challenge
        result = blacklist_handler.verify_challenge(public_key, record_id, signed_nonce)

        if result is False:
            return JSONResponse('invalid input', status_code=400)
        else:
            return JSONResponse('server error', status_code=201)
    except:
        logging.exception('')
        return JSONResponse('server error', status_code=500)
    return True

@app.route("/api/v1/blacklist", methods=["GET"])
async def get_blacklist(request: Request):
    '''
    used by Bitcoin nodes to determine if the supplied
    scriptSig's public key is listed in the blacklist table
    :param request: the public key, keyed by the value public_keym
    and the key type keyed by the
    :return:
    404 if the supplied public key is not present in the blacklist table
    200 if the key has been blacklisted
    500 in the event of other error
    '''
    try:
        # need to block and wait for asynchronous return
        request_payload = await request.body()
        request_params = request.query_params
        public_key = request_params[global_variables.PUBLIC_KEY]
        key_type = request_params[global_variables.KEY_TYPE]
        result = blacklist_handler.check_for_blacklist_entry(public_key, key_type)

        if result is True:
            return JSONResponse('key is blacklisted', status_code=200)
        elif result is False:
            return JSONResponse('key is valid', status_code=204)
        else:
            return JSONResponse('server error', status_code=500)
    except:
        logging.exception('')
        logging.error('Get Blacklisted key request failed')
        # else
        return JSONResponse('server error', status_code=500)

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8080)
