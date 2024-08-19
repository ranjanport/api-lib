import os, jwt, smtplib, datetime, bcrypt
from typing import Optional
from jwt import PyJWTError
from fastapi.security import OAuth2PasswordBearer
from fastapi import status , Depends, HTTPException
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pytz 

IST = pytz.timezone('Asia/Kolkata') 


from dotenv import load_dotenv
load_dotenv()

sender_email = os.getenv('SENDER_EMAIL')
sender_password = os.getenv('SENDER_PASSWORD')
endPoint = os.getenv('NEXT_PUBLIC_API_SERVER_ENDPOINT')

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def do_password_hash(password:str):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode()

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)


def create_jwt(data: dict, Subject:str):
    payload = {
        "exp": datetime.datetime.now(IST) + datetime.timedelta(minutes=int(os.getenv("TOKEN_DEFAULT_EXPIRE_MINUTE"))),  # Token expiration
        # "iat": datetime.datetime.now(),  # Token creation time
        "identifier": Subject,  # Subject of the token (user ID)
        "username": data["username"],  # Additional data
        "email": data["email"]  # Additional data
    }
    token = jwt.encode(payload, os.getenv('JWT_SECRET_KEY'), algorithm=os.getenv('JWT_ALGORITHM'))
    return token

def decode_jwt_token(token: str):
    try:
        secret_key = os.getenv('JWT_SECRET_KEY')
        algorithm = os.getenv('JWT_ALGORITHM')
        if not secret_key or not algorithm:
            raise ValueError("JWT_SECRET_KEY or JWT_ALGORITHM environment variable is not set")
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(e),
            )
async def send_verification_email(data:dict):
    subject = "SingUp Verification ! - Verify Your Email"
    USER = data['name']
    TOKEN_VERIFICATION_LINK = data['v_endpoint']
    USER_MAIL = data['email']
    ORIGIN_IP = data['origin_ip']
    
    body = f"Hi, {USER} \n\n We have received a account creation request from {ORIGIN_IP} for {USER_MAIL}.\n\n Click the below link to verify your account \n\n {TOKEN_VERIFICATION_LINK} \n\n If this is not you please avoid clicking the link."
    
    msg = MIMEMultipart()
    msg['From'] = data["from"]
    msg['To'] = data['email']
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
    return True

async def send_reset_link_email(data:dict):
    subject = "Password Reset ! - Verify Your Email"
    USER = data['name']
    TOKEN_VERIFICATION_LINK = data['v_endpoint']
    USER_MAIL = data['email']
    ORIGIN_IP = data['origin_ip']
    
    body = f"Hi, {USER} \n\n We have received a Password Reset request from {ORIGIN_IP} for {USER_MAIL}.\n\n Click the below link which will redirect you to your account password recovery page \n\n {TOKEN_VERIFICATION_LINK} \n\n If this is not you please avoid clicking the link."
    
    msg = MIMEMultipart()
    msg['From'] = data["from"]
    msg['To'] = data['email']
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
    return True

def resend_verification_email(email_to: str, verification_token: str):
    subject = "Account Verification : Verify Account"
    body = f"Click the link to verify your email: \n\n {endPoint}/verify/user?token={verification_token}"
    
    msg = MIMEMultipart()
    msg['From'] = "PortalAuth"
    msg['To'] = email_to
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
    return True

def sendMail(email_to: str, subject: str, body : str ):

    msg = MIMEMultipart()
    msg['From'] = "PortalAuth"
    msg['To'] = email_to
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
    return True

def generate_verification_link(data:dict, Subject : str):
    payload = {
        "exp": datetime.datetime.now(IST) + datetime.timedelta(minutes=int(os.getenv("VERIFICATION_LINK_EXPIRE_MINUTE"))),  # Token expiration
        "identifier": Subject,  # Subject of the token (user ID)
        "username": data["username"],  # Additional data
        "email": data["email"]  # Additional data
    }
    token = jwt.encode(payload, os.getenv('JWT_SECRET_KEY'), algorithm=os.getenv('JWT_ALGORITHM'))
    return token
