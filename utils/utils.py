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


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def decode_jwt_token(token: str):
    try:
        payload = jwt.decode(token, os.getenv('JWT_SECRET_KEY'), algorithms=[os.getenv('JWT_ALGORITHM')])
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



def send_verification_email(email_to: str, verification_token: str, name : str):
    subject = "SingUp Verification ! - Verify Your Email"
    body = f"Hi {name} \n\n Click the link to verify your email: \n\n {endPoint}/verify/user?token={verification_token}"
    
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


