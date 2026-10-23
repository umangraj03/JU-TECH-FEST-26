from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from backend.app.config import settings
from backend.app.database import get_db
from backend.seed import seed_database
from backend.models.db_models import DocumentModel, CustomerRecordModel

router = APIRouter(prefix="/api/demo", tags=["Demo"])


@router.post("/reset")
def reset_demo_state(db: Session = Depends(get_db)):
    if not settings.DEMO_MODE:
        raise HTTPException(
            status_code=403,
            detail="Demo reset is disabled in production environments."
        )

    seed_database(db=db, clear_existing=True)
    doc_count = db.query(DocumentModel).count()
    cust_count = db.query(CustomerRecordModel).count()

    return {
        "status": "SUCCESS",
        "message": "Demo state successfully reset to initial seed.",
        "documents_count": doc_count,
        "customers_count": cust_count
    }
