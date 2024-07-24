from fastapi import APIRouter, Request, status

dashBoardRouter = APIRouter(tags=["Dashboard"], prefix='/api/dashboard')

@dashBoardRouter.get("/dash", status_code=status.HTTP_200_OK)
async def dashboard(request:Request):
    return {"status" : "allowed"}
