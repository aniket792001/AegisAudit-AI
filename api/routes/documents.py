"""
Document management routes for AegisAudit AI.
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from pathlib import Path
import shutil
from typing import List, Dict, Any

from core.config import settings
from models.user_schema import UserResponse, UserRole
from api.deps import get_current_user, get_optional_user, require_roles
from typing import Optional

router = APIRouter(prefix="/api/documents", tags=["Documents"])

@router.post("/upload")
async def upload_document(
    file: UploadFile = File(...),
    current_user: UserResponse = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR]))
):
    """
    Uploads a PDF or text document to the server.
    Requires 'admin' or 'auditor' role.
    """
    safe_filename = Path(file.filename).name
    if not safe_filename.endswith((".pdf", ".txt", ".md")):
        raise HTTPException(status_code=400, detail="Only PDF, TXT, or MD files are supported.")

    target_path = settings.DATA_DIR / safe_filename
    with open(target_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {
        "filename": safe_filename,
        "size_bytes": target_path.stat().st_size,
        "uploaded_by": current_user.email,
        "message": "File uploaded successfully"
    }

@router.get("/list", response_model=List[Dict[str, Any]])
def list_documents(current_user: Optional[UserResponse] = Depends(get_optional_user)):
    """
    Lists all available documents in data directory.
    Requires authenticated user.
    """
    files = []
    for f in settings.DATA_DIR.glob("*.*"):
        if f.suffix in [".pdf", ".txt", ".md"]:
            files.append({
                "filename": f.name,
                "size_bytes": f.stat().st_size,
                "extension": f.suffix
            })
    return files
