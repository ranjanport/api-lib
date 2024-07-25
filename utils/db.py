import psycopg2, sys
from psycopg2.extras import RealDictCursor
from psycopg2 import sql
from dotenv import load_dotenv
sys.path.append("..")

from fastapi import APIRouter, Request, status,  Depends, HTTPException
from models import *
import os

# Load environment variables from .env file


load_dotenv()
DATABASE_URL = os.getenv("POSTGRES_URL")
SCHEMA = os.getenv("POSTGRES_SCHEMA")


def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    try:
        yield conn
    finally:
        conn.close()
        

def get_user(conn, user_id: int):
    with conn.cursor() as cur:
        cur.execute(sql.SQL(f"SELECT * FROM {SCHEMA}.users WHERE id = %s"), [user_id])
        return cur.fetchone()

def create_user(conn, new_user:dict):
        return cur.fetchone()        

def create_tables():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {SCHEMA}.users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL GENERATED ALWAYS AS ((((name)::text || ' '::text) || (id)::text)) STORED,
                email VARCHAR(100) UNIQUE NOT NULL,
                name VARCHAR(100) NOT NULL,
                isactive BOOLEAN DEFAULT FALSE,
                password VARCHAR(256) NOT NULL
            )
            """)
            conn.commit()
    finally:
        conn.close()


initRouter = APIRouter(tags=["INIT"],prefix="/init_db")


@initRouter.on_event("startup")
def on_startup():
    create_tables()

@initRouter.post("/users/")
def create_user_endpoint(name: str, email: str, password:str, db = Depends(get_db)):
    user = create_user(db, name, email, password)
    return user

@initRouter.get("/users/{user_id}")
def read_user(user_id: int, db = Depends(get_db)):
    user = get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user