from fastapi import APIRouter, UploadFile, File
from app.services.sonarqube_service import SonarQubeService
from app.schemas.scan_schema import ScanResult

router = APIRouter(prefix="/api/v1/scan", tags=["scan"])

@router.post("/code", response_model=ScanResult)
async def scan_code(file: UploadFile = File(...)):
    sonarqube_service = SonarQubeService()
    content = await file.read()
    return await sonarqube_service.scan_zip(content, file.filename)