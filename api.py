'''
contains the top level RESTFul API definitions
'''

import logging
import global_variables
from uvicorn.main import run
from starlette.applications import Starlette

app = Starlette()



if __name__ == "__main__":
    run(app)