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


if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8080)
