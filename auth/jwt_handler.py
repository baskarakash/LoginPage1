# auth/jwt_handler.py

import time
import jwt
from decouple import config
from fastapi import HTTPException

MIN_TOKEN_LENGTH = 50

JWT_SECRET = config("secret")
JWT_ALGORITHM = config("algorithm")



def is_valid_token_format(token_value: str) -> bool:
    # Add your custom logic to check the token format
    # For example, check if it contains only alphanumeric characters
    return token_value.isalnum()




def token_response(token: str):
    return {
        "access_token": token
    }

def signJWT(userID: str):
    payload = {
        "userID": userID,
        "expiry": time.time() + 600
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Check if the token length is as expected
    if len(token) < MIN_TOKEN_LENGTH:
        raise HTTPException(status_code=500, detail="Token generation failed")

    return token_response(token)

def decodeJWT(token: str):
    try:
        # Validate token format
        if not token.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid token format")

        token_value = token[len("Bearer "):].strip()

        # Validate token length
        if len(token_value) < MIN_TOKEN_LENGTH:
            raise HTTPException(status_code=401, detail="Invalid token length")

        # Validate the token format
        if not is_valid_token_format(token_value):
            raise HTTPException(status_code=401, detail="Invalid token format")

        # Decode and verify the token
        decode_token = jwt.decode(token_value, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        # Validate additional claims as needed
        user_id = decode_token.get('userID')
        expiry = decode_token.get('expiry')

        if not user_id or not expiry or expiry < time.time():
            raise HTTPException(status_code=401, detail="Invalid token")

        return decode_token
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired. Please log in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token. Please provide a valid access token.")
    except Exception as e:
        print(f"Error decoding token: {e}")
        raise HTTPException(status_code=401, detail=f"Error decoding token: {e}. Please try again.")
