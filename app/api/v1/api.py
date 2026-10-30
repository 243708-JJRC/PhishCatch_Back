from fastapi import APIRouter

from app.api.v1.endpoints import auth, history, scan

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(scan.router, prefix="/scan", tags=["Scanning"])
api_router.include_router(history.router, prefix="/history", tags=["History"])
