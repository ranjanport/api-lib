import sys, os, json
sys.path.append("..")

from fastapi import APIRouter, Request, status, Response
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from models.common import *
from utils.utils import create_jwt, verify_password, do_password_hash, decode_jwt_token
from utils.db import *

load_dotenv()


authRouter = APIRouter(tags=["Auth"], prefix="/api/auth")

@authRouter.post("/login")
async def login(user_data: User, request: Request, db = Depends(get_db)):
    if user_data.username != "" and user_data.password != "":
        headers = dict(request.headers)
        if 'content-length' in headers:
            headers.pop('content-length')
        conn = db
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL(f"""SELECT * FROM {SCHEMA}.users WHERE email=%s or username=%s"""),
                [user_data.email, user_data.username]
            )
            USER_ = cur.fetchone()
        if not USER_:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Username Not Exists", headers=headers)
        if USER_['isactive'] == False:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User Not Active : Plese Verify Your Account!", headers=headers)
        if not verify_password(user_data.password, USER_['password'].encode('utf-8')):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Credentials", headers=headers)

        content = {
            "status": "OK",
            "status_code" : status.HTTP_200_OK,
            "message": "Login successful",
            "token": create_jwt(dict(user_data), "Auth"),
            "ip" : request.client.host
        }

        conn.close()
        # background_tasks.add_task(sendMail, user_data.username, "Accounts : New Device Login", f"Your Account has been access from \n\n: {ip} at {datetime.utcnow()} near {location} using {browser}")
        return JSONResponse(content=content, status_code=status.HTTP_200_OK, headers=headers)
    else:
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and Password must not be empty")


@authRouter.post("/token/check")
async def login(request: Request, db = Depends(get_db)):
    if not request.headers['token']:
        return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token Not Exists")
    if request.headers['token']:
        message = decode_jwt_token(request.headers['token'])
    if message == {"error": "Invalid token"} or message == {"error": "Token has expired"}:
        content = {
                    "status": "ERROR",
                    "status_code" : status.HTTP_403_FORBIDDEN,
                    "isValid": False,
                    "ip" : request.client.host
                }
        headers = dict(request.headers)
        if 'content-length' in headers:
            headers.pop('content-length')
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token is either Expired or Invalid")
        
    elif message:
        content = {
            "status": "OK",
            "status_code" : status.HTTP_200_OK,
            "isValid": True,
            "ip" : request.client.host
        }
        headers = dict(request.headers)
        if 'content-length' in headers:
            headers.pop('content-length')
        return JSONResponse(content=content, status_code=status.HTTP_200_OK, headers=headers)