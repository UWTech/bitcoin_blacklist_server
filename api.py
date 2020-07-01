'''
contains the top level RESTFul API definitions
'''

import logging
import global_variables
from uvicorn.main import run
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.applications import Starlette

app = Starlette()

@app.route("/api/v1/health", methods=["GET"])
async def health(request: Request):
    return PlainTextResponse('healthy', status_code=200)

if __name__ == "__main__":
    run(app)