import sys, os, json, copy
sys.path.append("..")

from fastapi import APIRouter, Request, status, BackgroundTasks
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from models.common import *
from utils.utils import create_jwt, verify_password, do_password_hash, decode_jwt_token, generate_verification_link, send_verification_email, send_reset_link_email
from utils.db import *

load_dotenv()


authRouter = APIRouter(tags=["Auth"], prefix="/api/auth")

@authRouter.post("/login")
async def login(user_data: User, request: Request,  db = Depends(get_db)):
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
async def check_token(request: Request, db = Depends(get_db)):
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

@authRouter.post("/start")
async def sign_up(user_data : UserCreate, request: Request, background_tasks: BackgroundTasks, db = Depends(get_db)):
    headers = dict(request.headers)
    if 'content-length' in headers:
        headers.pop('content-length')
    if not all([user_data.username, user_data.password, user_data.rePassword, user_data.name]):
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT, detail="Required Content Not Passed.", headers=headers)
    if user_data.password != user_data.rePassword:
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT, detail="Password Not Matched", headers=headers)
    
    conn = db
    with conn.cursor() as cur:
        cur.execute(
            sql.SQL(f"""SELECT * FROM {SCHEMA}.users WHERE email=%s or username=%s"""),
            [user_data.email, user_data.username]
        )
        USER_ = cur.fetchone()
    
    if USER_:
        if not USER_['isactive']:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User Exists & Not Active: Please Verify Your Account!", headers=headers)
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Username Already Exists", headers=headers)
    
    verification_token = generate_verification_link(data=dict(user_data), Subject="Account Verification")
    
    hashed_password = do_password_hash(user_data.rePassword)

    new_user = {
        "name": user_data.name,
        "email": user_data.email,
        "password": hashed_password,
        "is_verified": False,
        "v_token": verification_token,
        "origin_ip": request.client.host,
        "v_endpoint": os.getenv("NEXT_PUBLIC_FRONTEND_ENDPOINT") + f"/verify?token={verification_token}",
        "from": os.getenv("SENDER_IDENTITY_SSO")
    }
    
    with conn.cursor() as cur:
        cur.execute(
            sql.SQL("""
                INSERT INTO {}.users (name, email, password, is_verified, v_token)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING *
            """).format(sql.Identifier(SCHEMA)),
            [new_user["name"], new_user["email"], new_user["password"], new_user["is_verified"], new_user["v_token"]]
        )
        isUserAddedToDb = cur.fetchone() is not None
        conn.commit()
    if isUserAddedToDb:
            new_user_for_task = copy.deepcopy(new_user)
            background_tasks.add_task(send_verification_email, new_user_for_task)
    
    new_user.pop("v_endpoint") #REMOVE THIS IN PRODUCTION ENV
    new_user.pop("v_token") 
    new_user.pop("password")
    new_user.pop("from")
    
    return JSONResponse(content=new_user, status_code=status.HTTP_200_OK, headers=headers)

@authRouter.get("/verify")
async def verify_user_via_token(token: str, request:Request, db = Depends(get_db)):
    # Verify the token
    try:
        user_data = decode_jwt_token(token)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")

    # Check if the user exists in the database
    conn = db
    with conn.cursor() as cur:
        cur.execute(
            sql.SQL("SELECT * FROM {}.users WHERE email=%s OR username=%s").format(sql.Identifier(SCHEMA)),
            [user_data['email'], user_data['username']]
        )
        user = cur.fetchone()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Check if the user is already verified
    if user['isactive'] and not user['is_verified']:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already verified")

    # Update the user's verification status
    with conn.cursor() as cur:
        cur.execute(
            sql.SQL("""
                UPDATE {}.users
                SET is_verified = NULL, isactive = TRUE, v_token = NULL
                WHERE email=%s OR username=%s
            """).format(sql.Identifier(SCHEMA)),
            [user_data['email'], user_data['username']]
        )
        conn.commit()

    content = {
        "email": user_data['email'],
        "username" : user_data['username'],
        "status" : "Verified"
    }
    
    return JSONResponse(content=content, status_code=status.HTTP_200_OK, headers=dict(request.headers))

@authRouter.post('/reset/password')
async def reset_password(user_data: UserReset, request : Request, background_tasks: BackgroundTasks, db =Depends(get_db)):
    if user_data.username:
        headers = dict(request.headers)
        if 'content-length' in headers:
            headers.pop('content-length')
        conn = db
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL(f"""SELECT * FROM {SCHEMA}.users WHERE email=%s or username=%s"""),
                [user_data.username, user_data.username]
            )
            USER_ = cur.fetchone()
        if not USER_:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Username Not Exists", headers=headers)
        if USER_['isactive'] == False:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User Not Active : Plese Verify Your Account!", headers=headers)
        
        content = {
            "status": "OK",
            "status_code" : status.HTTP_200_OK,
            "message": "If your email address exists in our database, you will receive a password recovery link at your email address in a few minutes.",
            "ip" : request.client.host
        }

        reset_token = generate_verification_link(data=dict({"email":  USER_['email'], "username": USER_['username']}), Subject="Password Reset")
        user_ = {
            "name":  USER_['name'],
            "email":  USER_['email'],
            "username": USER_['username'],
            "origin_ip": request.client.host,
            "reset_link_token": reset_token,
            "v_endpoint": os.getenv("NEXT_PUBLIC_RESET_ENDPOINT") + f"?token={reset_token}",
            "from": os.getenv("SENDER_IDENTITY_SSO")
        }
        conn.close()
        background_tasks.add_task(send_reset_link_email, user_)
        return JSONResponse(content=content, status_code=status.HTTP_200_OK, headers=headers)
    else:
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username Can't be Empty")

    
