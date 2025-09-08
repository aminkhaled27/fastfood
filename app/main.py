from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import models
from .database import engine
from .routers import auth, social_auth
from .response_utils import error_response, validation_error_response


models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Custom exception handler for HTTPException
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Extract the response data if it's already in our format
    if isinstance(exc.detail, dict) and "ret" in exc.detail:
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.detail
        )
    
    # Convert to our standard format
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response(
            ret=exc.status_code,
            msg=str(exc.detail) if exc.detail else "An error occurred",
            status_code=exc.status_code
        )
    )

# Custom exception handler for validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=validation_error_response(
            msg="Validation error",
            data=[{"field": error["loc"][-1], "message": error["msg"]} for error in exc.errors()]
        )
    )

app.include_router(auth.router)
app.include_router(social_auth.router)