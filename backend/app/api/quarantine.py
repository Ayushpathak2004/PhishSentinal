import os
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database.session import get_db
from backend.app.models.models import QuarantinedFile
from backend.app.schemas.schemas import RestoreFileRequest
from backend.app.agents.vault_keeper import VaultKeeper
from backend.app.utils.security import compute_sha256_file

router = APIRouter(prefix="/quarantine", tags=["Quarantine Vault"])

@router.get("")
def list_quarantined_files(status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(QuarantinedFile)
    if status:
        query = query.filter(QuarantinedFile.status == status.upper())
    files = query.order_by(desc(QuarantinedFile.created_at)).all()
    
    return [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "original_filename": f.original_filename,
            "stored_filename": f.stored_filename,
            "file_size": f.file_size,
            "file_hash": f.file_hash,
            "quarantine_reason": f.quarantine_reason,
            "status": f.status,
            "restored_at": f.restored_at,
            "restored_by": f.restored_by,
            "created_at": f.created_at
        }
        for f in files
    ]

@router.get("/{quarantine_id}/verify")
def verify_quarantined_file(quarantine_id: str, db: Session = Depends(get_db)):
    """
    Recalculates SHA-256 hash of quarantined file on disk and verifies integrity.
    """
    record = db.query(QuarantinedFile).filter(QuarantinedFile.id == quarantine_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Quarantined record not found")
        
    if not os.path.exists(record.file_path):
        return {
            "verified": False,
            "status": "FILE_MISSING",
            "message": "Physical file does not exist in storage"
        }
        
    current_hash = compute_sha256_file(record.file_path)
    file_size = os.path.getsize(record.file_path)

    matches = (current_hash == record.file_hash)
    return {
        "verified": matches,
        "status": "INTEGRITY_VERIFIED" if matches else "INTEGRITY_CORRUPTED",
        "baseline_hash": record.file_hash,
        "computed_hash": current_hash,
        "file_size_bytes": file_size
    }

@router.post("/{quarantine_id}/restore")
def restore_file(quarantine_id: str, req: RestoreFileRequest, db: Session = Depends(get_db)):
    """
    Safely restores a quarantined file after cryptographic integrity check and user authorization.
    """
    result = VaultKeeper.verify_and_restore_file(
        quarantine_id=quarantine_id,
        authorized_by=req.authorized_by,
        reason=req.reason,
        db=db,
        verify_integrity=req.verify_integrity
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("message"))
    return result
