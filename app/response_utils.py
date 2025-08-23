from typing import Any, Optional, Union
from fastapi.responses import JSONResponse
from fastapi import status

def create_response(
    ret: int,
    data: Any = None,
    msg: str = "",
    status_code: int = 200
) -> dict:
    """
    Create a standardized API response
    
    Args:
        ret: Response code (200, 404, etc.)
        data: Response data payload
        msg: Response message
        status_code: HTTP status code
    
    Returns:
        Standardized response dictionary
    """
    return {
        "ret": ret,
        "data": data,
        "msg": msg
    }

def success_response(
    data: Any = None,
    msg: str = "Success",
    status_code: int = 200
) -> dict:
    """
    Create a success response
    
    Args:
        data: Response data payload
        msg: Success message
        status_code: HTTP status code
    
    Returns:
        Success response dictionary
    """
    return create_response(
        ret=status_code,
        data=data,
        msg=msg
    )

def error_response(
    ret: int,
    msg: str = "Error occurred",
    data: Any = None,
    status_code: int = 400
) -> dict:
    """
    Create an error response
    
    Args:
        ret: Error code
        msg: Error message
        data: Additional error data (optional)
        status_code: HTTP status code
    
    Returns:
        Error response dictionary
    """
    return create_response(
        ret=ret,
        data=data,
        msg=msg
    )

def not_found_response(msg: str = "Resource not found") -> dict:
    """Create a 404 not found response"""
    return error_response(
        ret=404,
        msg=msg,
        status_code=404
    )

def validation_error_response(msg: str = "Validation error", data: Any = None) -> dict:
    """Create a validation error response"""
    return error_response(
        ret=422,
        msg=msg,
        data=data,
        status_code=422
    )

def unauthorized_response(msg: str = "Unauthorized") -> dict:
    """Create an unauthorized response"""
    return error_response(
        ret=401,
        msg=msg,
        status_code=401
    )

def forbidden_response(msg: str = "Forbidden") -> dict:
    """Create a forbidden response"""
    return error_response(
        ret=403,
        msg=msg,
        status_code=403
    )

def conflict_response(msg: str = "Conflict occurred") -> dict:
    """Create a conflict response"""
    return error_response(
        ret=409,
        msg=msg,
        status_code=409
    )

def internal_error_response(msg: str = "Internal server error") -> dict:
    """Create an internal server error response"""
    return error_response(
        ret=500,
        msg=msg,
        status_code=500
    )
