from pydantic import BaseModel
from typing import Optional


class returnMessage(BaseModel):
    message: str
    status : int 

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    password: str
    email: str

class UserIsActive(BaseModel):
    username: str
    password: str
    email: str
    is_active: bool = False

class UserRemove(BaseModel):
    username : str
    password : str
    token : str | bool

class UserCreate(BaseModel):
    name : str
    email : str
    username: str
    password: str
    rePassword : str


class UserVerify(BaseModel):
    token: str

class Token(BaseModel):
    token: str
