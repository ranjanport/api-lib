import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.auth import authRouter
from routes.dashboard import dashBoardRouter
from utils.db import initRouter

from dotenv import load_dotenv
load_dotenv()

app = FastAPI(title="OpenDevNetwork", summary="OpenDevNetwork is a Community for Open Source Developers",
              description='''OpenDevNetwork is a Community for Open Source Developers, Where People from around the world can collaborate and work on a shared projects.''',
                version='1.0.0')

app.include_router(authRouter)
app.include_router(dashBoardRouter)
app.include_router(initRouter)

origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
    f'{os.getenv("POSTGRES_URL")}',
    f'{os.getenv("NEXT_PUBLIC_API_SERVER_ENDPOINT")}',
    f'{os.getenv("NEXT_PUBLIC_API_SERVER_FALLBACK_ENDPOINT")}',   
    
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api")
def index():
    return {"Status" : "API Server is Active"}

@app.get("/api/python")
def hello_world():
    return {"message": "Hello World"}